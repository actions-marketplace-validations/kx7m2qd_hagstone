import { mkdir, mkdtemp, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fingerprint, SEVERITY_ORDER, VULNERABLE_DEPENDENCY, type Finding, type Severity } from "../core/finding.js";
import { cacheRoot } from "./install.js";
import { run } from "./run.js";
import { ECOSYSTEM, syftConfig } from "./syft.js";
import type { EngineOutput } from "./types.js";

/** The parts of `grype -o json` we read. */
export interface GrypeMatch {
  vulnerability: {
    id: string;
    severity?: string;
    description?: string;
    fix?: { versions?: string[] | null; state?: string } | null;
    cvss?: { metrics?: { baseScore?: number } }[] | null;
  };
  relatedVulnerabilities?: { id: string; description?: string }[] | null;
  artifact: { name: string; version: string; type: string; purl?: string; locations?: { path: string }[] | null };
}

export interface GrypeOutput {
  matches?: GrypeMatch[] | null;
  distro?: { name?: string; version?: string } | null;
  descriptor?: { db?: { status?: { built?: string } } };
}

const DISTRO_ECOSYSTEM: Record<string, string> = { apk: "Alpine", deb: "Debian", rpm: "RPM" };

function severityOf(v: GrypeMatch["vulnerability"]): Severity {
  switch (v.severity?.toLowerCase()) {
    case "critical":
      return "critical";
    case "high":
      return "high";
    case "medium":
      return "medium";
    case "low":
      return "low";
    case "negligible":
      return "info";
  }
  const score = Math.max(0, ...(v.cvss ?? []).map((c) => c.metrics?.baseScore ?? 0));
  if (score >= 9) return "critical";
  if (score >= 7) return "high";
  if (score >= 4) return "medium";
  if (score > 0) return "low";
  return "medium";
}

/**
 * Compare distro and language package versions chunk by chunk (`3.1.7-r0` > `3.1.0-r4`,
 * `1.2.13-r1` > `1.2.13-r0`, `2:1.0` > `1:9.9`). A suffix after `-` is a revision, not a pre-release.
 * Good enough to pick the highest of a package's fix versions.
 */
export function compareDistroVersions(a: string, b: string): number {
  const epoch = (v: string): [number, string] => {
    const m = /^(\d+):(.*)$/.exec(v);
    return m ? [Number(m[1]), m[2]!] : [0, v];
  };
  const [ea, ra] = epoch(a);
  const [eb, rb] = epoch(b);
  if (ea !== eb) return ea - eb;
  const chunks = (v: string) => v.match(/\d+|[a-z]+/gi) ?? [];
  const x = chunks(ra);
  const y = chunks(rb);
  for (let i = 0; i < Math.max(x.length, y.length); i++) {
    const p = x[i];
    const q = y[i];
    if (p === undefined) return -1;
    if (q === undefined) return 1;
    const pn = /^\d+$/.test(p);
    const qn = /^\d+$/.test(q);
    if (pn && qn) {
      const d = Number(p) - Number(q);
      if (d) return d;
    } else if (pn !== qn) return pn ? 1 : -1;
    else if (p !== q) return p < q ? -1 : 1;
  }
  return 0;
}

/** The source package a binary package was built from (`libcrypto3` → `openssl`), from the purl. */
function sourcePackage(a: GrypeMatch["artifact"]): string {
  const m = /[?&]upstream=([^&#]+)/.exec(a.purl ?? "");
  return m ? decodeURIComponent(m[1]!).replace(/@.*$/, "") : a.name;
}

const MAX_LISTED = 5;

/**
 * One finding per source package version (a distro builds openssl into libcrypto3 + libssl3; you
 * upgrade them together), listing every advisory and the single upgrade that fixes them all.
 * Negligible advisories (e.g. Debian "unimportant") are counted, not reported. Pure.
 */
export function normalizeGrype(out: GrypeOutput): { findings: Finding[]; negligible: number } {
  const groups = new Map<string, { ecosystem: string; name: string; version: string; packages: Set<string>; path: string; matches: GrypeMatch[] }>();
  let negligible = 0;
  const distro = out.distro?.name ? `${out.distro.name} ${out.distro.version ?? ""}`.trim() : undefined;
  for (const m of out.matches ?? []) {
    if (severityOf(m.vulnerability) === "info") {
      negligible++;
      continue;
    }
    const a = m.artifact;
    const ecosystem = DISTRO_ECOSYSTEM[a.type] ?? ECOSYSTEM[a.type] ?? a.type;
    const name = sourcePackage(a);
    const key = `${ecosystem}\u0000${name}\u0000${a.version}`;
    const g = groups.get(key) ?? {
      ecosystem,
      name,
      version: a.version,
      packages: new Set<string>(),
      path: (a.locations?.[0]?.path ?? "").replace(/^\/+/, ""),
      matches: [],
    };
    g.packages.add(a.name);
    g.matches.push(m);
    groups.set(key, g);
  }

  const findings: Finding[] = [];
  for (const g of groups.values()) {
    const byId = new Map<string, GrypeMatch>();
    for (const m of g.matches) if (!byId.has(m.vulnerability.id)) byId.set(m.vulnerability.id, m);
    const entries = [...byId.values()]
      .map((m) => ({
        id: m.vulnerability.id,
        severity: severityOf(m.vulnerability),
        fixes: m.vulnerability.fix?.state === "fixed" ? (m.vulnerability.fix.versions ?? []) : [],
        state: m.vulnerability.fix?.state ?? "unknown",
      }))
      .sort((a, b) => SEVERITY_ORDER.indexOf(a.severity) - SEVERITY_ORDER.indexOf(b.severity) || a.id.localeCompare(b.id));
    const worst = entries[0]!;
    let target: string | undefined;
    let unfixed = 0;
    for (const e of entries) {
      const first = e.fixes.filter((f) => compareDistroVersions(f, g.version) > 0).sort(compareDistroVersions)[0];
      if (!first) unfixed++;
      else if (!target || compareDistroVersions(first, target) > 0) target = first;
    }
    const wontFix = entries.filter((e) => e.state === "wont-fix").length;
    const n = entries.length;
    const advisories = [...new Set(g.matches.flatMap((m) => [m.vulnerability.id, ...(m.relatedVulnerabilities ?? []).map((r) => r.id)]))].sort();
    const binaries = [...g.packages].sort();
    const label = binaries.length === 1 && binaries[0] === g.name ? g.name : `${g.name} (${binaries.join(", ")})`;
    const listed = entries.slice(0, MAX_LISTED).map((e) => `${e.id} (${e.severity})`);
    const more = n > MAX_LISTED ? `; and ${n - MAX_LISTED} more` : "";
    const fix = target
      ? ` Upgrade ${g.name} to ${target} or later${unfixed ? ` to fix ${n - unfixed} of them; ${unfixed} ${unfixed === 1 ? "has" : "have"} no fixed version yet` : n === 1 ? "" : " to fix all of them"}` +
        `${distro ? " (update the base image, or upgrade the package in your Dockerfile)" : ""}.`
      : ` No fixed version published yet${wontFix ? ` (${wontFix} marked won't-fix by the distribution)` : ""}; a different or newer base image may not ship it.`;
    findings.push({
      id: fingerprint("grype", VULNERABLE_DEPENDENCY, g.ecosystem, g.name, g.version),
      category: "dependency",
      engine: "grype",
      ruleId: VULNERABLE_DEPENDENCY,
      title: n === 1 ? `${g.name} ${g.version}: ${worst.id}` : `${g.name} ${g.version} has ${n} known vulnerabilities`,
      message: `${label} ${g.version} (${distro && DISTRO_ECOSYSTEM[g.matches[0]!.artifact.type] ? distro : g.ecosystem}) is affected by ${n === 1 ? "" : `${n} advisories: `}${listed.join("; ")}${more}.${fix}`,
      severity: worst.severity,
      location: { path: g.path || ".", startLine: 1 },
      cwe: [],
      owasp: ["A06:2021 - Vulnerable and Outdated Components"],
      dependency: { name: g.name, version: g.version, ecosystem: g.ecosystem, advisories, fixedVersions: target ? [target] : [] },
    });
  }
  return { findings, negligible };
}

/**
 * Our grype config: no update check, no external lookups, the vulnerability database under the
 * Hagstone cache. Grype verifies the database's checksum itself. `offline` uses the cached copy as is.
 */
export function grypeConfig(opts: { offline: boolean; dbDir: string }): string {
  return [
    "check-for-app-update: false",
    "external-sources:",
    "  enable: false",
    "db:",
    `  cache-dir: ${JSON.stringify(opts.dbDir)}`,
    `  auto-update: ${opts.offline ? "false" : "true"}`,
    "  validate-by-hash-on-start: true",
    `  validate-age: ${opts.offline ? "false" : "true"}`,
    "",
  ].join("\n");
}

/** Several GB: `HAGSTONE_GRYPE_DB_DIR` keeps it out of caches meant for engine binaries (the Action sets it). */
export const GRYPE_DB_DIR = () => process.env.HAGSTONE_GRYPE_DB_DIR || join(cacheRoot(), "grype-db");

/** Image sources syft understands; anything else is passed as is and syft picks (daemon, then registry). */
export const IMAGE_SCHEMES = ["registry:", "docker:", "podman:", "containerd:", "docker-archive:", "oci-archive:", "oci-dir:", "singularity:"];

/**
 * Catalog an image with syft, then match the catalog with grype. Only the vulnerability database is
 * downloaded (from Anchore, checksum-verified by grype); the image's package list never leaves the
 * machine. Pulling the image itself talks to its registry.
 */
export async function runImageScan(
  bins: { syft: string; grype: string },
  image: string,
  opts: { offline: boolean },
): Promise<EngineOutput> {
  const work = await mkdtemp(join(tmpdir(), "hagstone-image-"));
  try {
    const empty = join(work, "empty");
    await mkdir(empty);
    const syftCfg = join(work, "syft.yaml");
    const grypeCfg = join(work, "grype.yaml");
    const sbomPath = join(work, "sbom.syft.json");
    await writeFile(syftCfg, syftConfig({ offline: opts.offline, cacheDir: join(cacheRoot(), "syft") }));
    await writeFile(grypeCfg, grypeConfig({ offline: opts.offline, dbDir: GRYPE_DB_DIR() }));
    const s = await run(bins.syft, ["scan", image, "--quiet", `--config=${syftCfg}`, `--output=syft-json=${sbomPath}`], { cwd: empty });
    if (s.code !== 0) throw new Error(`syft could not read image ${image}: ${s.stderr.trim().slice(-500)}`);
    // The first run downloads grype's vulnerability database (several GB on disk): allow it time.
    const g = await run(bins.grype, [`sbom:${sbomPath}`, "--quiet", `--config=${grypeCfg}`, "--output=json"], { cwd: empty, timeoutMs: 60 * 60_000 });
    if (g.code !== 0) {
      const hint = opts.offline ? " (with --offline, run one image scan online first to download the vulnerability database)" : "";
      throw new Error(`grype exited ${g.code}: ${g.stderr.trim().slice(-500)}${hint}`);
    }
    const out = JSON.parse(g.stdout || "{}") as GrypeOutput;
    const { findings, negligible } = normalizeGrype(out);
    const warnings: string[] = [];
    if (negligible) warnings.push(`grype: ${negligible} negligible-severity advisor${negligible === 1 ? "y" : "ies"} not reported`);
    const built = out.descriptor?.db?.status?.built;
    if (opts.offline && built) warnings.push(`grype: --offline, so the cached vulnerability database (built ${built.slice(0, 10)}) was used`);
    return { findings, warnings };
  } finally {
    await rm(work, { recursive: true, force: true });
  }
}
