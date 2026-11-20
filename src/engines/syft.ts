import { mkdir, mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fingerprint, type Finding, type Severity } from "../core/finding.js";
import { cacheRoot } from "./install.js";
import { run } from "./run.js";
import type { EngineOutput } from "./types.js";

// ---------- license policy ----------

export type LicenseClass = "network-copyleft" | "copyleft" | "non-commercial" | "denied";

/** `.hagstone/licenses.json`: SPDX ids or license names, matched case-insensitively. */
export interface LicensePolicy {
  /** Never reported, even if a default class matches (e.g. a company that is fine with GPL). */
  allow: string[];
  /** Always reported as `license-denied`. */
  deny: string[];
}

export const LICENSE_POLICY_FILE = ".hagstone/licenses.json";
export const EMPTY_POLICY: LicensePolicy = { allow: [], deny: [] };

/**
 * Read a license policy. A missing or empty file means the defaults only. A malformed one is an error
 * the caller reports (it fails toward reporting more, never less).
 */
export async function loadLicensePolicy(path: string): Promise<{ policy: LicensePolicy; error?: string }> {
  let text: string;
  try {
    text = await readFile(path, "utf8");
  } catch {
    return { policy: EMPTY_POLICY };
  }
  if (!text.trim()) return { policy: EMPTY_POLICY };
  try {
    const raw = JSON.parse(text) as Partial<LicensePolicy>;
    const list = (v: unknown) => (Array.isArray(v) ? v.filter((x): x is string => typeof x === "string") : []);
    return { policy: { allow: list(raw.allow), deny: list(raw.deny) } };
  } catch (e) {
    return { policy: EMPTY_POLICY, error: e instanceof Error ? e.message : String(e) };
  }
}

const CLASS_INFO: Record<LicenseClass, { severity: Severity; title: string; why: string }> = {
  "network-copyleft": {
    severity: "high",
    title: "Network copyleft license",
    why: "AGPL and SSPL require you to publish your own source code to anyone who uses the software over a network, which covers most web services.",
  },
  copyleft: {
    severity: "medium",
    title: "Copyleft license",
    why: "GPL requires software you distribute with this dependency to be released under the GPL too. Fine for internal or server-side use; a problem for anything you ship to customers.",
  },
  "non-commercial": {
    severity: "high",
    title: "Non-commercial or source-available license",
    why: "This license forbids or restricts commercial use (non-commercial Creative Commons, Business Source, Elastic, Commons Clause).",
  },
  denied: {
    severity: "high",
    title: "License denied by policy",
    why: `Your ${LICENSE_POLICY_FILE} denies this license.`,
  },
};

/** Exceptions that allow linking without the copyleft applying to your code. */
const LINKING_EXCEPTION = /classpath-exception|gcc-exception|llvm-exception|autoconf-exception|bison-exception|font-exception|openjdk-assembly-exception|universal-foss-exception/i;

/** Default classification of a single license id or name (no operators). Pure. */
export function classifyLicense(license: string): LicenseClass | undefined {
  const [base = "", exception] = license.split(/\s+WITH\s+/i);
  if (exception && LINKING_EXCEPTION.test(exception)) return undefined;
  if (/\bA-?GPL|Affero|\bSSPL\b|Server Side Public/i.test(base)) return "network-copyleft";
  if (/\bGPL|GNU General Public License|GNU GPL/i.test(base)) return "copyleft";
  if (/\bCC-BY(?:-SA)?-NC|NonCommercial|Non-Commercial|\bBUSL\b|Business Source License|\bElastic-2\.0\b|Elastic License|Commons Clause|PolyForm-Noncommercial/i.test(base))
    return "non-commercial";
  return undefined;
}

const SEVERITY_RANK: Severity[] = ["critical", "high", "medium", "low", "info"];
const rank = (c: LicenseClass) => SEVERITY_RANK.indexOf(CLASS_INFO[c].severity);
/** The more severe of two (first on ties): every part of an AND applies. */
const worse = (a: LicenseClass, b: LicenseClass) => (rank(a) <= rank(b) ? a : b);
/** The less severe of two (first on ties): with OR you pick the option that suits you. */
const milder = (a: LicenseClass, b: LicenseClass) => (rank(a) >= rank(b) ? a : b);

const matches = (license: string, list: string[]) => list.some((x) => x.toLowerCase() === license.trim().toLowerCase());

/** One license term (may carry WITH) under the policy: allow wins, then deny, then the defaults. */
function judgeTerm(term: string, policy: LicensePolicy): LicenseClass | undefined {
  const base = term.split(/\s+WITH\s+/i)[0] ?? term;
  if (matches(term, policy.allow) || matches(base, policy.allow)) return undefined;
  if (matches(term, policy.deny) || matches(base, policy.deny)) return "denied";
  return classifyLicense(term);
}

/**
 * Judge a package's licenses. Each entry may be an SPDX expression. `A OR B`: you pick the option that
 * suits you, so it is a problem only if every option is, and then the mildest. `A AND B`: every part
 * applies, so the worst. Several entries for one package
 * are treated as alternatives (npm's legacy `licenses` array meant dual licensing). Pure.
 */
export function judgeLicenses(expressions: string[], policy: LicensePolicy): LicenseClass | undefined {
  const judgeExpr = (expr: string): LicenseClass | undefined => {
    const flat = expr.replace(/[()]/g, " ").replace(/\s+/g, " ").trim();
    if (!flat) return undefined;
    const hasOr = /\sOR\s/i.test(flat);
    const hasAnd = /\sAND\s/i.test(flat);
    if (hasOr && !hasAnd) {
      const options = flat.split(/\s+OR\s+/i).map((t) => judgeTerm(t, policy));
      return options.some((o) => o === undefined) ? undefined : options.reduce((a, b) => milder(a!, b!));
    }
    // AND, or a mix we don't parse precedence for: be conservative and count every term.
    const terms = flat.split(/\s+(?:AND|OR)\s+/i).map((t) => judgeTerm(t, policy));
    const bad = terms.filter((t): t is LicenseClass => t !== undefined);
    return bad.length ? bad.reduce(worse) : undefined;
  };
  const verdicts = expressions.map(judgeExpr);
  if (!verdicts.length || verdicts.some((v) => v === undefined)) return undefined;
  return verdicts.reduce((a, b) => milder(a!, b!));
}

// ---------- syft JSON → findings ----------

export interface SyftPackage {
  name: string;
  version: string;
  type: string;
  purl?: string;
  licenses?: { value: string; spdxExpression?: string }[] | null;
  locations?: { path: string }[] | null;
}

export interface SyftDocument {
  artifacts?: SyftPackage[] | null;
}

const ECOSYSTEM: Record<string, string> = {
  npm: "npm",
  python: "PyPI",
  "go-module": "Go",
  "java-archive": "Maven",
  "rust-crate": "crates.io",
  gem: "RubyGems",
  "php-composer": "Packagist",
  dotnet: "NuGet",
  hex: "Hex",
  pub: "Pub",
  "swift-package-manager": "SwiftURL",
  cocoapods: "CocoaPods",
};

/** Types whose licenses don't ship with the product (CI actions run on the CI provider's machines). */
const NOT_SHIPPED = new Set(["github-action", "github-action-workflow"]);

export function normalizeSyftLicenses(doc: SyftDocument, policy: LicensePolicy): { findings: Finding[]; unknown: number } {
  const findings: Finding[] = [];
  let unknown = 0;
  for (const p of doc.artifacts ?? []) {
    if (NOT_SHIPPED.has(p.type)) continue;
    const expressions = (p.licenses ?? []).map((l) => (l.spdxExpression || l.value || "").trim()).filter(Boolean);
    if (!expressions.length) {
      unknown++;
      continue;
    }
    const verdict = judgeLicenses(expressions, policy);
    if (!verdict) continue;
    const info = CLASS_INFO[verdict];
    const ecosystem = ECOSYSTEM[p.type] ?? p.type;
    const license = [...new Set(expressions)].join(" OR ");
    const path = (p.locations?.[0]?.path ?? "").replace(/^\/+/, "") || ".";
    findings.push({
      id: fingerprint("syft", "license", ecosystem, p.name, p.version, license),
      category: "license",
      engine: "syft",
      ruleId: `license-${verdict}`,
      title: `${info.title}: ${p.name}@${p.version} (${license})`,
      message:
        `${p.name}@${p.version} is licensed ${license}. ${info.why} ` +
        `Replace it with a permissively licensed alternative, get legal sign-off, or record the decision: ` +
        `\`hagstone suppress <id> --as accepted-risk --reason "…"\`, or allow the license in ${LICENSE_POLICY_FILE}.`,
      severity: info.severity,
      confidence: "high",
      location: { path, startLine: 1 },
      cwe: [],
      owasp: [],
      dependency: { name: p.name, version: p.version, ecosystem, advisories: [], fixedVersions: [] },
    });
  }
  return { findings, unknown };
}

// ---------- running syft ----------

/**
 * Our own syft config. Syft runs from an empty directory with this file, so a scanned repo's
 * `.syft.yaml` is never read. Nothing executes project tooling, clones, or phones home; the only
 * network use is PyPI license metadata (package names only), and `offline` turns that off.
 */
export function syftConfig(opts: { offline: boolean; cacheDir: string }): string {
  return [
    "check-for-app-update: false",
    "cpp:",
    "  vcpkg-allow-git-clone: false",
    "golang:",
    "  search-local-mod-cache-licenses: true",
    "  search-remote-licenses: false",
    "  use-packages-lib: false",
    "java:",
    "  use-network: false",
    "  use-maven-local-repository: false",
    "  resolve-transitive-dependencies: false",
    "javascript:",
    "  search-remote-licenses: false",
    "  include-dev-dependencies: false",
    "python:",
    `  search-remote-licenses: ${opts.offline ? "false" : "true"}`,
    "  guess-unpinned-requirements: false",
    "cache:",
    `  dir: ${JSON.stringify(opts.cacheDir)}`,
    "",
  ].join("\n");
}

/** Our ignore patterns as syft `--exclude` globs. Findings are filtered again afterwards. */
export function syftExcludes(ignores: string[]): string[] {
  const out: string[] = [];
  for (const raw of ignores) {
    const p = raw.replace(/^\.\//, "");
    if (p.includes("/") && !/^[^/]+\/$/.test(p)) out.push(p.endsWith("/") ? `./${p}**` : `./${p}`);
    else {
      const name = p.replace(/\/$/, "");
      out.push(`**/${name}/**`, `**/${name}`);
    }
  }
  return out;
}

export type SbomFormat = "cyclonedx" | "spdx";
const SYFT_FORMAT: Record<SbomFormat | "syft", string> = { cyclonedx: "cyclonedx-json", spdx: "spdx-json", syft: "syft-json" };

/** Run syft on a directory and return its output in the given format. */
export async function runSyft(
  bin: string,
  root: string,
  ignores: string[],
  opts: { format: SbomFormat | "syft"; offline: boolean },
): Promise<string> {
  const work = await mkdtemp(join(tmpdir(), "hagstone-syft-"));
  try {
    const empty = join(work, "empty");
    await mkdir(empty);
    const config = join(work, "syft.yaml");
    await writeFile(config, syftConfig({ offline: opts.offline, cacheDir: join(cacheRoot(), "syft") }));
    const res = await run(
      bin,
      ["scan", `dir:${root}`, "--quiet", `--config=${config}`, ...syftExcludes(ignores).map((e) => `--exclude=${e}`), `--output=${SYFT_FORMAT[opts.format]}`],
      { cwd: empty },
    );
    if (res.code !== 0) throw new Error(`syft exited ${res.code}: ${res.stderr.trim().slice(-500)}`);
    return res.stdout;
  } finally {
    await rm(work, { recursive: true, force: true });
  }
}

export async function runSyftLicenses(
  bin: string,
  root: string,
  ignores: string[],
  opts: { offline: boolean; policy: LicensePolicy },
): Promise<EngineOutput> {
  const doc = JSON.parse((await runSyft(bin, root, ignores, { format: "syft", offline: opts.offline })) || "{}") as SyftDocument;
  const { findings, unknown } = normalizeSyftLicenses(doc, opts.policy);
  const warnings = unknown
    ? [`syft: ${unknown} package${unknown === 1 ? " has" : "s have"} no license data, so their licenses weren't checked`]
    : [];
  return { findings, warnings };
}
