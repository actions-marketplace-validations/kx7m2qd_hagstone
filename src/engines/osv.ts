import { fileURLToPath } from "node:url";
import { fingerprint, SEVERITY_ORDER, VULNERABLE_DEPENDENCY, type Finding, type Severity } from "../core/finding.js";
import { toRelative } from "./paths.js";
import { run } from "./run.js";
import type { EngineOutput } from "./types.js";

interface OsvVuln {
  id: string;
  summary?: string;
  details?: string;
  aliases?: string[];
  affected?: {
    package?: { name?: string; ecosystem?: string };
    ranges?: { events?: { introduced?: string; fixed?: string }[] }[];
  }[];
  database_specific?: { severity?: string; cwe_ids?: string[] };
}

interface OsvPackage {
  package: { name: string; version: string; ecosystem: string };
  vulnerabilities?: OsvVuln[];
  groups?: { ids: string[]; aliases?: string[]; max_severity?: string }[];
}

export interface OsvOutput {
  results?: { source: { path: string; type: string }; packages?: OsvPackage[] }[];
}

const CONFIG = fileURLToPath(new URL("../../config/osv-scanner.toml", import.meta.url));

export function severityFromScore(score: string | undefined, label: string | undefined): Severity {
  const n = score ? Number.parseFloat(score) : Number.NaN;
  if (!Number.isNaN(n) && n > 0) {
    if (n >= 9) return "critical";
    if (n >= 7) return "high";
    if (n >= 4) return "medium";
    return "low";
  }
  switch (label?.toUpperCase()) {
    case "CRITICAL":
      return "critical";
    case "HIGH":
      return "high";
    case "LOW":
      return "low";
    default:
      return "medium";
  }
}

/** Fixed versions this advisory lists for this package (one per affected release line). */
function fixesFor(v: OsvVuln, pkg: OsvPackage["package"]): string[] {
  const fixed = new Set<string>();
  for (const a of v.affected ?? []) {
    if (a.package?.name !== pkg.name) continue;
    for (const r of a.ranges ?? []) for (const e of r.events ?? []) if (e.fixed) fixed.add(e.fixed);
  }
  return [...fixed];
}

/**
 * Order two version strings by their numeric release part (`1.2.10` > `1.2.9`), with a
 * pre-release (`2.0.0-rc.1`, `2.0.0b1`) before its release. Good enough for npm and PyPI.
 */
export function compareVersions(a: string, b: string): number {
  const parse = (v: string) => {
    const m = /^v?(\d+(?:\.\d+)*)(.*)$/.exec(v.trim());
    return { nums: (m?.[1] ?? "0").split(".").map(Number), pre: !!m?.[2] && !/^\+/.test(m[2]) && !/^\.post/i.test(m[2]) };
  };
  const x = parse(a);
  const y = parse(b);
  for (let i = 0; i < Math.max(x.nums.length, y.nums.length); i++) {
    const d = (x.nums[i] ?? 0) - (y.nums[i] ?? 0);
    if (d) return d;
  }
  return Number(y.pre) - Number(x.pre);
}

/**
 * The lowest version that fixes every advisory: for each one, its first fix above the installed
 * version; then the highest of those. Advisories with no such fix are counted, not guessed.
 */
export function upgradeTarget(version: string, fixesPerAdvisory: string[][]): { target?: string; unfixed: number } {
  let target: string | undefined;
  let unfixed = 0;
  for (const fixes of fixesPerAdvisory) {
    const above = fixes.filter((f) => compareVersions(f, version) > 0).sort(compareVersions)[0];
    if (!above) {
      unfixed++;
      continue;
    }
    if (!target || compareVersions(above, target) > 0) target = above;
  }
  return { target, unfixed };
}

const MAX_LISTED = 5;

/**
 * One finding per package version, listing every advisory against it (osv already merges aliases
 * like GHSA + CVE into groups) and the single upgrade that fixes them all. One row per advisory
 * turned one outdated package into 10-30 findings nobody reads.
 */
export function normalizeOsv(root: string, out: OsvOutput): Finding[] {
  const findings: Finding[] = [];
  for (const result of out.results ?? []) {
    const path = toRelative(root, result.source.path);
    for (const pkg of result.packages ?? []) {
      const vulns = pkg.vulnerabilities ?? [];
      const groups = pkg.groups?.length ? pkg.groups : vulns.map((v) => ({ ids: [v.id], aliases: v.aliases }));
      const { name, version, ecosystem } = pkg.package;
      const advisories = [...new Set(groups.flatMap((g) => [...g.ids, ...(g.aliases ?? [])]))].sort();
      if (!groups.length) continue;
      // OpenSSF malicious-package advisories: the package itself is the attack, not a bug in it.
      const mal = advisories.filter((a) => a.startsWith("MAL-"));
      if (mal.length) {
        findings.push({
          id: fingerprint("osv-scanner", "pkg-known-malicious", path, ecosystem, name),
          category: "dependency",
          engine: "osv-scanner",
          ruleId: "pkg-known-malicious",
          title: `Known malicious package: ${name}`,
          message: `${name}@${version} (${ecosystem}) is listed as malicious (${mal.join(", ")}). It was published to steal data or run attacker code. Remove it, rotate any secrets that were reachable where it was installed, and install the legitimate package if you meant a different one.`,
          severity: "critical",
          confidence: "high",
          location: { path, startLine: 1 },
          cwe: ["CWE-506"],
          owasp: ["A08:2021 - Software and Data Integrity Failures"],
          dependency: { name, version, ecosystem, advisories, fixedVersions: [] },
        });
        continue;
      }
      const entries = groups
        .map((g) => {
          const members = vulns.filter((v) => g.ids.includes(v.id));
          const primary = members[0];
          return {
            id: g.ids[0] ?? "unknown",
            summary: primary?.summary,
            severity: severityFromScore("max_severity" in g ? g.max_severity : undefined, primary?.database_specific?.severity),
            fixes: [...new Set(members.flatMap((m) => fixesFor(m, pkg.package)))],
            cwes: members.flatMap((m) => m.database_specific?.cwe_ids ?? []),
          };
        })
        .sort((a, b) => SEVERITY_ORDER.indexOf(a.severity) - SEVERITY_ORDER.indexOf(b.severity) || a.id.localeCompare(b.id));
      const worst = entries[0]!;
      const { target, unfixed } = upgradeTarget(version, entries.map((e) => e.fixes));
      const n = entries.length;
      const fix = target
        ? ` Upgrade to ${target} or later to fix ${unfixed ? `${n - unfixed} of them; ${unfixed} ${unfixed === 1 ? "has" : "have"} no fixed version yet` : n === 1 ? "it" : `all ${n}`}.`
        : ` No fixed version published yet.`;
      const listed = entries.slice(0, MAX_LISTED).map((e) => `${e.id} (${e.severity}${e.summary ? `: ${e.summary}` : ""})`);
      const more = n > MAX_LISTED ? `; and ${n - MAX_LISTED} more` : "";
      findings.push({
        id: fingerprint("osv-scanner", VULNERABLE_DEPENDENCY, path, ecosystem, name, version),
        category: "dependency",
        engine: "osv-scanner",
        ruleId: VULNERABLE_DEPENDENCY,
        title: n === 1 ? `${name} ${version}: ${worst.summary ?? worst.id}` : `${name} ${version} has ${n} known vulnerabilities`,
        message: `${name}@${version} (${ecosystem}) is affected by ${n === 1 ? "" : `${n} advisories: `}${listed.join("; ")}${more}.${fix}`,
        severity: worst.severity,
        location: { path, startLine: 1 },
        cwe: [...new Set(entries.flatMap((e) => e.cwes))],
        owasp: ["A06:2021 - Vulnerable and Outdated Components"],
        dependency: { name, version, ecosystem, advisories, fixedVersions: target ? [target] : [] },
      });
    }
  }
  return findings;
}

export async function runOsv(bin: string, root: string): Promise<EngineOutput> {
  // Only package names and versions are sent to the OSV API, never source code.
  const res = await run(
    bin,
    [
      "scan",
      "source",
      "--format=json",
      // Our config, not the repo's osv-scanner.toml (which can ignore vulnerabilities).
      `--config=${CONFIG}`,
      // No call analysis: for some ecosystems it runs the repo's build scripts.
      "--no-call-analysis=all",
      // No transitive resolution: a manifest (e.g. pom.xml <repositories>) could
      // otherwise point the scanner at servers the repo chooses.
      "--no-resolve",
      "-r",
      "--",
      ".",
    ],
    { cwd: root },
  );
  // 0 = clean, 1 = vulnerabilities found, 128 = no packages/lockfiles found.
  if (res.code === 128) return { findings: [], warnings: [] };
  if (res.code !== 0 && res.code !== 1) {
    throw new Error(`osv-scanner exited ${res.code}: ${res.stderr.trim().slice(0, 500)}`);
  }
  return { findings: normalizeOsv(root, JSON.parse(res.stdout) as OsvOutput), warnings: [] };
}
