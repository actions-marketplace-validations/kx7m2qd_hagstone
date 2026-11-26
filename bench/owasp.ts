/**
 * OWASP Benchmark (Python or Java): score our rules per vulnerability category the way OWASP does
 * (score = true-positive rate − false-positive rate, per test file) and write
 * bench/results/owasp-<lang>.json. Exits 1 if a category drops below its threshold file.
 *
 *   tsx bench/owasp.ts [python|java] [--intrafile | --no-intrafile]   (compare the two modes)
 *
 * The suites are GPL, so they are not vendored: each is downloaded at a pinned commit, verified
 * by SHA-256 like our engine binaries, and cached under the Hagstone cache directory.
 */
import { access, mkdir, mkdtemp, readdir, readFile, rename, rm, writeFile } from "node:fs/promises";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import type { Finding } from "../src/core/finding.js";
import { DEFAULT_IGNORES } from "../src/core/ignore.js";
import { cacheRoot, resolveEngine } from "../src/engines/install.js";
import { runOpengrep } from "../src/engines/opengrep.js";
import { run } from "../src/engines/run.js";
import { downloadVerified } from "./fetch.js";

const BENCH_DIR = fileURLToPath(new URL(".", import.meta.url));

interface Suite {
  repo: string;
  commit: string;
  sha256: string;
  expected: string;
  /** Directory scanned, inside the suite (helpers included, so cross-file flows exist). */
  scan: string;
  ext: string;
  /** Run with `--taint-intrafile` by default (it is what the product does for this language). */
  intrafile: boolean;
}

export const SUITES = {
  python: {
    repo: "OWASP-Benchmark/BenchmarkPython",
    commit: "f1291485808b66e20ddb6b01b10dc71b3df8c8ba",
    sha256: "0defda4cce2ea7675fbeae5b059b4d7cca7d49232529367133feb1adfb529096",
    expected: "expectedresults-0.1.csv",
    scan: "testcode",
    ext: ".py",
    intrafile: false,
  },
  java: {
    repo: "OWASP-Benchmark/BenchmarkJava",
    commit: "10dfcc54ad02dcfcb358b0ba4a0fef8c919a6d17",
    sha256: "9bd7f125557e35c49af0040bed13eb19a9056c8f7a84719445826224227d022f",
    expected: "expectedresults-1.2.csv",
    scan: "src/main/java",
    ext: ".java",
    intrafile: true,
  },
} satisfies Record<string, Suite>;
export type SuiteLang = keyof typeof SUITES;

const suiteUrl = (s: Suite) => `https://codeload.github.com/${s.repo}/tar.gz/${s.commit}`;
const rulesDir = (lang: SuiteLang) => fileURLToPath(new URL(`../rules/${lang}`, import.meta.url));

interface Case {
  test: string;
  category: string;
  cwe: string;
  real: boolean;
}

interface CategoryScore {
  cwe: string;
  covered: boolean;
  tp: number;
  fp: number;
  fn: number;
  tn: number;
  tpr: number;
  fpr: number;
  score: number;
}

async function exists(path: string): Promise<boolean> {
  return access(path).then(
    () => true,
    () => false,
  );
}

/** Download, verify and extract the pinned suite once; later runs reuse the cache. */
async function fetchSuite(LANG: SuiteLang, SUITE: Suite): Promise<string> {
  const parent = join(cacheRoot(), "bench");
  const dir = join(parent, `owasp-${LANG}-${SUITE.commit.slice(0, 12)}`);
  if (await exists(join(dir, SUITE.expected))) return dir;

  const bytes = await downloadVerified(suiteUrl(SUITE), SUITE.sha256, `OWASP Benchmark (${LANG})`);
  await mkdir(parent, { recursive: true, mode: 0o700 });
  const work = await mkdtemp(join(parent, ".staging-"));
  try {
    await writeFile(join(work, "suite.tar.gz"), bytes);
    const { code, stderr } = await run("tar", ["-xzf", join(work, "suite.tar.gz"), "-C", work, "--strip-components=1"]);
    if (code !== 0) throw new Error(`tar failed: ${stderr.trim()}`);
    await rm(join(work, "suite.tar.gz"));
    await rm(dir, { recursive: true, force: true });
    await rename(work, dir);
  } catch (e) {
    await rm(work, { recursive: true, force: true });
    throw e;
  }
  return dir;
}

async function loadCases(dir: string, SUITE: Suite): Promise<Case[]> {
  const text = await readFile(join(dir, SUITE.expected), "utf8");
  return text
    .split("\n")
    .filter((line) => line.trim() && !line.startsWith("#"))
    .map((line) => {
      const [test = "", category = "", real = "", cwe = ""] = line.split(",").map((s) => s.trim());
      return { test, category, real: real === "true", cwe: `CWE-${cwe}` };
    });
}

/** CWEs our rules for this language claim, read from their metadata. */
async function coveredCwes(dir: string): Promise<Set<string>> {
  const cwes = new Set<string>();
  for (const name of await readdir(dir).catch(() => [] as string[])) {
    if (!name.endsWith(".yml")) continue;
    for (const m of (await readFile(join(dir, name), "utf8")).matchAll(/CWE-\d+/g)) cwes.add(m[0]);
  }
  return cwes;
}

const ratio = (num: number, den: number) => (den === 0 ? 0 : Math.round((num / den) * 1000) / 1000);

export function scoreCategories(cases: Case[], findings: Finding[], covered: Set<string>, ext = ".py"): Record<string, CategoryScore> {
  // A test file counts as flagged for its category if any finding in it carries that CWE.
  const flagged = new Set<string>();
  for (const f of findings) {
    const base = f.location.path.split("/").pop() ?? "";
    const test = base.endsWith(ext) ? base.slice(0, -ext.length).match(/^(BenchmarkTest\d+)$/)?.[1] : undefined;
    if (test) for (const cwe of f.cwe ?? []) flagged.add(`${test} ${cwe}`);
  }
  const out: Record<string, CategoryScore> = {};
  for (const c of cases) {
    const s = (out[c.category] ??= { cwe: c.cwe, covered: covered.has(c.cwe), tp: 0, fp: 0, fn: 0, tn: 0, tpr: 0, fpr: 0, score: 0 });
    const hit = flagged.has(`${c.test} ${c.cwe}`);
    if (c.real) s[hit ? "tp" : "fn"]++;
    else s[hit ? "fp" : "tn"]++;
  }
  for (const s of Object.values(out)) {
    s.tpr = ratio(s.tp, s.tp + s.fn);
    s.fpr = ratio(s.fp, s.fp + s.tn);
    s.score = Math.round((s.tpr - s.fpr) * 1000) / 1000;
  }
  return Object.fromEntries(Object.entries(out).sort(([a], [b]) => a.localeCompare(b)));
}

async function main(): Promise<number> {
  const LANG = (process.argv.slice(2).find((a) => !a.startsWith("--")) ?? "python") as SuiteLang;
  const SUITE: Suite = SUITES[LANG];
  if (!SUITE) throw new Error(`unknown suite "${LANG}" (python | java)`);
  const INTRAFILE = process.argv.includes("--no-intrafile") ? false : SUITE.intrafile || process.argv.includes("--intrafile");
  const RULES_DIR = rulesDir(LANG);
  const THRESHOLDS = LANG === "python" ? "owasp-thresholds.json" : `owasp-thresholds-${LANG}.json`;
  const URL_ = suiteUrl(SUITE);
  const thresholds = JSON.parse(await readFile(join(BENCH_DIR, THRESHOLDS), "utf8")) as Record<string, number>;
  const dir = await fetchSuite(LANG, SUITE);
  const cases = await loadCases(dir, SUITE);
  const bin = await resolveEngine("opengrep", { autoInstall: true });
  const { findings, warnings } = await runOpengrep(bin, join(dir, SUITE.scan), DEFAULT_IGNORES, {
    config: RULES_DIR,
    taintIntrafile: INTRAFILE,
    javaCrossFile: LANG === "java" && !process.argv.includes("--no-xfile"),
  });
  const categories = scoreCategories(cases, findings, await coveredCwes(RULES_DIR), SUITE.ext);

  const failures = Object.entries(thresholds)
    .filter(([cat, min]) => (categories[cat]?.score ?? 0) < min)
    .map(([cat, min]) => `${cat}: score ${categories[cat]?.score ?? 0} < gate ${min}`);
  const result = { pass: failures.length === 0, suite: { ...SUITE, url: URL_, intrafile: INTRAFILE }, thresholds, categories, failures, warnings };
  await mkdir(join(BENCH_DIR, "results"), { recursive: true });
  await writeFile(join(BENCH_DIR, "results", `owasp-${LANG}.json`), JSON.stringify(result, null, 2) + "\n");

  process.stdout.write(`${"category".padEnd(16)}${"cwe".padEnd(9)}  tp  fn  fp   tn    tpr    fpr  score\n`);
  for (const [cat, s] of Object.entries(categories)) {
    const row = [s.tp, s.fn, s.fp].map((n) => String(n).padStart(4)).join("") + String(s.tn).padStart(5);
    const rates = [s.tpr, s.fpr, s.score].map((n) => n.toFixed(3).padStart(7)).join("");
    process.stdout.write(`${cat.padEnd(16)}${s.cwe.padEnd(9)}${row}${rates}${s.covered ? "" : "  (no rule)"}\n`);
  }
  for (const f of failures) process.stdout.write(`  below gate: ${f}\n`);
  for (const w of warnings) process.stdout.write(`  warning: ${w}\n`);
  process.stdout.write(`\n→ ${result.pass ? "PASS" : "FAIL"}\n`);
  return result.pass ? 0 : 1;
}

if (process.argv[1] && fileURLToPath(import.meta.url) === process.argv[1]) {
  main().then(
    (code) => process.exit(code),
    (e: unknown) => {
      process.stderr.write(`bench:owasp: ${e instanceof Error ? e.message : String(e)}\n`);
      process.exit(2);
    },
  );
}
