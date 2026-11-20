import { copyFile, lstat, mkdir, mkdtemp, readdir, readFile, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { dirname, join, posix } from "node:path";
import { fileURLToPath } from "node:url";
import { fingerprint, type Finding, type Severity } from "../core/finding.js";
import { isIgnored } from "../core/ignore.js";
import { run } from "./run.js";
import type { EngineOutput } from "./types.js";

/** The parts of `trivy config --format json` we read. */
export interface TrivyMisconfig {
  ID: string;
  Title: string;
  Description?: string;
  Message?: string;
  Resolution?: string;
  Severity: string;
  PrimaryURL?: string;
  Status: string;
  CauseMetadata?: { Resource?: string; StartLine?: number; EndLine?: number };
}

export interface TrivyReport {
  Results?: { Target: string; Misconfigurations?: TrivyMisconfig[] | null }[] | null;
}

export interface HardeningPolicy {
  /** Check ID → why it is only hardening. */
  hardening: Record<string, string>;
}

const POLICY_FILE = fileURLToPath(new URL("../../config/iac-hardening.json", import.meta.url));

export async function loadHardeningPolicy(file = POLICY_FILE): Promise<HardeningPolicy> {
  const raw = JSON.parse(await readFile(file, "utf8")) as Partial<HardeningPolicy>;
  return { hardening: raw.hardening ?? {} };
}

const SEVERITY: Record<string, Severity> = { CRITICAL: "critical", HIGH: "high", MEDIUM: "medium", LOW: "low" };

export const MISCONFIG_OWASP = "A05:2021 - Security Misconfiguration";

function sentence(s: string | undefined): string {
  const t = (s ?? "").trim();
  return !t ? "" : /[.!?]$/.test(t) ? t : `${t}.`;
}

/**
 * Trivy JSON → findings. Only failed checks; LOW and policy-listed hardening checks are counted, not
 * returned, unless `includeHardening`. Pure.
 */
export function normalizeTrivy(
  report: TrivyReport,
  policy: HardeningPolicy,
  opts: { includeHardening?: boolean } = {},
): { findings: Finding[]; hiddenHardening: number } {
  const findings: Finding[] = [];
  let hiddenHardening = 0;

  for (const result of report.Results ?? []) {
    const path = result.Target.replace(/\\/g, "/").replace(/^\.\//, "");
    for (const m of result.Misconfigurations ?? []) {
      if (m.Status !== "FAIL") continue;
      const severity = SEVERITY[m.Severity] ?? "info";
      if (!opts.includeHardening && (severity === "low" || severity === "info" || m.ID in policy.hardening)) {
        hiddenHardening++;
        continue;
      }
      const resource = m.CauseMetadata?.Resource ?? "";
      const startLine = m.CauseMetadata?.StartLine || 1;
      const endLine = m.CauseMetadata?.EndLine || startLine;
      const message = [sentence(m.Message), sentence(m.Description), m.Resolution ? `Fix: ${sentence(m.Resolution)}` : "", m.PrimaryURL ?? ""]
        .filter(Boolean)
        .join(" ");
      findings.push({
        id: fingerprint("trivy", m.ID, path, resource, m.Message ?? ""),
        category: "iac",
        engine: "trivy",
        ruleId: m.ID,
        title: resource ? `${m.Title} (${resource})` : m.Title,
        message,
        severity,
        confidence: "high",
        location: { path, startLine, endLine },
        cwe: [],
        owasp: [MISCONFIG_OWASP],
      });
    }
  }

  return { findings, hiddenHardening };
}

// ---------- the sanitized copy ----------

const MAX_FILE_BYTES = 5 * 1024 * 1024;
const TERRAFORM = /\.tf(?:\.json)?$|\.tfvars(?:\.json)?$/;
const IAC_FILE =
  /\.tf(?:\.json)?$|\.tfvars(?:\.json)?$|^(?:Docker|Container)file(?:\..+)?$|\.(?:docker|container)file$|\.ya?ml$|\.json$|\.tpl$|^\.helmignore$/i;
/** JSON and YAML that is clearly not infrastructure: lockfiles and tool config. */
const NOT_IAC =
  /^(?:package(?:-lock)?|npm-shrinkwrap|composer|bower|lerna|nx|turbo|renovate|tsconfig.*|jsconfig.*|\.?eslintrc.*|\.?prettierrc.*|\.?babelrc.*|pnpm-lock|pnpm-workspace|yarn|\.?pre-commit-config|codecov|\.?markdownlint.*)\.(?:json|ya?ml)$|\.lock\.json$|\.min\.json$/i;

/** Directories Trivy never needs: downloaded Terraform modules and the default ignores. */
const SKIP_DIR = new Set([".terraform", ".terragrunt-cache"]);

export function isIacCandidate(name: string): boolean {
  return IAC_FILE.test(name) && !NOT_IAC.test(name);
}

/** A placeholder path that never exists, so Trivy skips the module instead of fetching it. */
export const REMOVED_MODULE = "./.hagstone-remote-module-not-fetched";

/** True when a module source is a relative path that stays inside the scan root. */
function isLocalSource(source: string, fileRel: string): boolean {
  if (!source.startsWith("./") && !source.startsWith("../")) return false;
  const resolved = posix.normalize(posix.join(posix.dirname(fileRel), source));
  return !resolved.startsWith("../") && resolved !== "..";
}

/** End of the `{ … }` block that opens at `open` (index of "{"), skipping strings and comments. */
function blockEnd(text: string, open: number): number {
  let depth = 0;
  for (let i = open; i < text.length; i++) {
    const c = text[i];
    if (c === '"') {
      for (i++; i < text.length && text[i] !== '"'; i++) if (text[i] === "\\") i++;
    } else if (c === "#" || (c === "/" && text[i + 1] === "/")) {
      while (i < text.length && text[i] !== "\n") i++;
    } else if (c === "/" && text[i + 1] === "*") {
      const end = text.indexOf("*/", i + 2);
      i = end < 0 ? text.length : end + 1;
    } else if (c === "{") depth++;
    else if (c === "}" && --depth === 0) return i;
  }
  return text.length;
}

/**
 * Make a file safe for Trivy without moving any line:
 * - inline `trivy:ignore` / `tfsec:ignore` markers stop working (the repo can't silence its own checks);
 * - Terraform module sources that aren't local paths inside the repo point at a path that doesn't
 *   exist, so Trivy doesn't download anything the repo names.
 * Pure.
 */
export function sanitizeIac(text: string, fileRel: string): string {
  let out = text.replace(/\b(trivy|tfsec)\s*:\s*ignore\b/gi, "hagstone-disabled-$1-ignore");
  const name = fileRel.split("/").pop() ?? "";
  if (!TERRAFORM.test(name)) return out;
  if (name.endsWith(".json")) {
    // JSON Terraform: rewrite every non-local "source" string (only modules have one that Trivy fetches).
    return out.replace(/("source"\s*:\s*")((?:\\.|[^"\\])*)(")/g, (all, a: string, src: string, b: string) =>
      isLocalSource(src, fileRel) ? all : `${a}${REMOVED_MODULE}${b}`,
    );
  }
  const header = /(^|\n)[ \t]*module[ \t]+"[^"\n]*"[ \t]*\{/g;
  let m: RegExpExecArray | null;
  while ((m = header.exec(out))) {
    const open = m.index + m[0].length - 1;
    const end = blockEnd(out, open);
    const body = out.slice(open, end).replace(/(\bsource\s*=\s*")((?:\\.|[^"\\\n])*)(")/g, (all, a: string, src: string, b: string) =>
      isLocalSource(src, fileRel) ? all : `${a}${REMOVED_MODULE}${b}`,
    );
    out = out.slice(0, open) + body + out.slice(end);
    header.lastIndex = open + body.length;
  }
  return out;
}

/**
 * Copy the files Trivy can scan into `dest`, sanitized. Skips symlinks (they could point outside the
 * repo), ignored paths, downloaded-module directories and files over 5 MB. Returns how many were copied.
 */
export async function prepareIacCopy(root: string, dest: string, ignores: string[]): Promise<number> {
  let copied = 0;
  async function walk(rel: string): Promise<void> {
    const dir = rel ? join(root, rel) : root;
    let entries;
    try {
      entries = await readdir(dir, { withFileTypes: true });
    } catch {
      return;
    }
    for (const e of entries) {
      const childRel = rel ? `${rel}/${e.name}` : e.name;
      if (e.isSymbolicLink()) continue;
      if (e.isDirectory()) {
        if (SKIP_DIR.has(e.name) || isIgnored(`${childRel}/`, ignores)) continue;
        await walk(childRel);
      } else if (e.isFile() && isIacCandidate(e.name) && !isIgnored(childRel, ignores)) {
        const src = join(root, childRel);
        const st = await lstat(src);
        if (st.size > MAX_FILE_BYTES) continue;
        const target = join(dest, childRel);
        await mkdir(dirname(target), { recursive: true });
        const text = await readFile(src, "utf8");
        const clean = sanitizeIac(text, childRel);
        if (clean === text) await copyFile(src, target);
        else await writeFile(target, clean);
        copied++;
      }
    }
  }
  await walk("");
  return copied;
}

export interface TrivyOptions {
  includeHardening?: boolean;
}

export async function runTrivy(bin: string, root: string, ignores: string[], opts: TrivyOptions = {}): Promise<EngineOutput> {
  const work = await mkdtemp(join(tmpdir(), "hagstone-trivy-"));
  try {
    const src = join(work, "src");
    const empty = join(work, "empty");
    const tmp = join(work, "tmp");
    await Promise.all([mkdir(src), mkdir(empty), mkdir(tmp)]);
    if ((await prepareIacCopy(root, src, ignores)) === 0) return { findings: [], warnings: [] };
    const res = await run(
      bin,
      [
        "config",
        "--format=json",
        "--quiet",
        "--exit-code=0",
        // Never read the repo's trivy.yaml / .trivyignore (cwd is an empty dir as well).
        "--config=",
        "--ignorefile=",
        // Built-in checks only; nothing fetched, nothing reported home.
        "--skip-check-update",
        "--skip-version-check",
        "--disable-telemetry",
        `--module-dir=${empty}`,
        `--cache-dir=${join(work, "cache")}`,
        src,
      ],
      // Trivy caches Terraform modules under $TMPDIR/.aqua: keep that private to this run.
      { cwd: empty, env: { TMPDIR: tmp } },
    );
    if (res.code !== 0) throw new Error(`trivy exited ${res.code}: ${res.stderr.trim().slice(-500)}`);
    const report = JSON.parse(res.stdout || "{}") as TrivyReport;
    const { findings, hiddenHardening } = normalizeTrivy(report, await loadHardeningPolicy(), opts);
    const warnings = hiddenHardening
      ? [`trivy: ${hiddenHardening} IaC hardening check${hiddenHardening === 1 ? "" : "s"} hidden (best practice, not an exposure); --include-hardening shows them`]
      : [];
    return { findings, warnings };
  } finally {
    await rm(work, { recursive: true, force: true });
  }
}
