import { relative, resolve } from "node:path";
import { applyBaseline, BASELINE_FILE, defaultBaselinePath, loadBaseline, today, type BaselineSummary } from "./core/baseline.js";
import { dedupe, sortFindings, type EngineName, type Finding } from "./core/finding.js";
import { DEFAULT_IGNORES, isIgnored, loadIgnorePatterns } from "./core/ignore.js";
import { pathScope } from "./core/scope.js";
import { runGitleaks } from "./engines/gitleaks.js";
import { overrideVar, resolveEngine } from "./engines/install.js";
import type { BinaryEngine } from "./engines/manifest.js";
import { runOpengrep } from "./engines/opengrep.js";
import { runOsv } from "./engines/osv.js";
import { runPkgrisk } from "./engines/pkgrisk/index.js";
import { runTrivy } from "./engines/trivy.js";
import type { EngineOutput } from "./engines/types.js";
import { applyReachability } from "./reachability/index.js";

export const ALL_ENGINES: EngineName[] = ["opengrep", "osv-scanner", "gitleaks", "pkgrisk", "trivy"];

export interface ScanOptions {
  engines?: EngineName[];
  autoInstall?: boolean;
  /** Turn off pkgrisk's registry lookups (the only network use of that engine). */
  offline?: boolean;
  /** Import-level reachability for vulnerable npm/PyPI dependencies (default: on). */
  reachability?: boolean;
  /** Drop findings judged unreachable instead of only lowering their severity. */
  reachableOnly?: boolean;
  /** Ignore patterns from this file instead of `<root>/.hagstoneignore` (missing file → none). */
  ignoreFile?: string;
  /** Report code and dependency findings in test and example paths too (default: hidden and counted). */
  includeTests?: boolean;
  /** Report IaC hardening checks too (LOW and config/iac-hardening.json; default: hidden and counted). */
  includeHardening?: boolean;
  /** Baseline file to apply instead of `<root>/.hagstone/baseline.json` (missing file → none). */
  baseline?: string;
  /** Don't apply any baseline: report every finding. */
  noBaseline?: boolean;
  /**
   * The scan doesn't cover the whole tree (pre-commit hook, MCP `paths`), so baseline entries that
   * match nothing can't be called stale.
   */
  partial?: boolean;
}

export interface EngineStatus {
  engine: EngineName;
  ok: boolean;
  findings: number;
  ms: number;
  error?: string;
}

export interface ScanResult {
  root: string;
  findings: Finding[];
  /**
   * Patterns from the repo's own .hagstoneignore. Surfaced in every report: the repo
   * is untrusted, and a change here can hide findings.
   */
  ignores: string[];
  warnings: string[];
  engines: EngineStatus[];
  /** Findings left out because they are in test or example code (see `includeTests`). */
  hiddenInTests?: number;
  /** Findings a baseline entry hides, each with `suppression` set. Not in `findings`, not gated. */
  suppressed?: Finding[];
  /** Present when a baseline file was applied. */
  baseline?: BaselineSummary;
}

/**
 * Test and example code isn't deployed, so its code findings and its lockfiles' vulnerable packages
 * are noise by default. Secrets and malicious packages stay: a leaked key or an installed attack
 * package does harm wherever the file lives.
 */
export function hiddenByScope(f: Finding): boolean {
  if (!f.scope) return false;
  if (f.category === "code" || f.category === "iac") return true;
  return f.category === "dependency" && f.engine === "osv-scanner" && f.ruleId !== "pkg-known-malicious";
}

export async function scan(target: string, opts: ScanOptions = {}): Promise<ScanResult> {
  const root = resolve(target);
  const ignores = await loadIgnorePatterns(root, opts.ignoreFile);
  const engines = opts.engines ?? ALL_ENGINES;
  const autoInstall = opts.autoInstall ?? true;

  const runners: Partial<Record<BinaryEngine, (bin: string) => Promise<EngineOutput>>> = {
    opengrep: (bin) => runOpengrep(bin, root, ignores),
    "osv-scanner": (bin) => runOsv(bin, root),
    gitleaks: (bin) => runGitleaks(bin, root),
    trivy: (bin) => runTrivy(bin, root, ignores, { includeHardening: opts.includeHardening ?? false }),
  };

  const runnerFor = (engine: BinaryEngine) => {
    const r = runners[engine];
    if (!r) throw new Error(`${engine} doesn't scan a directory`);
    return r;
  };

  // Engines run in parallel; one failing engine must not hide the others' results.
  const outcomes = await Promise.all(
    engines.map(async (engine) => {
      const started = Date.now();
      try {
        // pkgrisk is built in: there is no binary to resolve.
        const out =
          engine === "pkgrisk"
            ? await runPkgrisk(root, ignores, { offline: opts.offline ?? false })
            : await runnerFor(engine)(await resolveEngine(engine, { autoInstall }));
        return { engine, out, ms: Date.now() - started };
      } catch (e) {
        return { engine, error: e instanceof Error ? e.message : String(e), ms: Date.now() - started };
      }
    }),
  );

  const findings: Finding[] = [];
  const warnings: string[] = [];
  for (const engine of engines) {
    if (engine === "pkgrisk") continue;
    const v = overrideVar(engine);
    if (process.env[v]) warnings.push(`${engine}: using ${v}=${process.env[v]}, which is not checksum-verified`);
  }
  const statuses: EngineStatus[] = [];
  for (const o of outcomes) {
    if ("error" in o) {
      statuses.push({ engine: o.engine, ok: false, findings: 0, ms: o.ms, error: o.error });
      warnings.push(`${o.engine} failed: ${o.error}`);
      continue;
    }
    const kept = o.out.findings.filter((f) => !isIgnored(f.location.path, ignores));
    findings.push(...kept);
    warnings.push(...o.out.warnings);
    statuses.push({ engine: o.engine, ok: true, findings: kept.length, ms: o.ms });
  }

  let kept = dedupe(findings);
  for (const f of kept) {
    const where = pathScope(f.location.path);
    if (where !== "prod") f.scope = where;
  }
  const visible = opts.includeTests ? kept : kept.filter((f) => !hiddenByScope(f));
  const hiddenScope = opts.includeTests ? [] : kept.filter((f) => hiddenByScope(f));
  const hiddenInTests = hiddenScope.length;
  kept = visible;
  if (opts.reachability ?? true) {
    try {
      await applyReachability(root, kept, ignores);
    } catch (e) {
      // Reachability only refines findings; a failure must never drop or block them.
      warnings.push(`reachability analysis failed: ${e instanceof Error ? e.message : String(e)}`);
    }
  }

  let suppressed: Finding[] | undefined;
  let baseline: BaselineSummary | undefined;
  if (!opts.noBaseline) {
    const path = opts.baseline ? resolve(opts.baseline) : defaultBaselinePath(root);
    const rel = relative(root, path);
    const shown = !opts.baseline ? BASELINE_FILE : rel && !rel.startsWith("..") ? rel : path;
    const { file, error } = await loadBaseline(path);
    if (error) warnings.push(`baseline ${shown} not applied (${error}), so every finding is shown`);
    else if (file) {
      const a = applyBaseline(kept, hiddenScope, file, today());
      kept = a.active;
      suppressed = sortFindings(a.suppressed);
      // Staleness needs every engine to have looked at the whole tree.
      const full = !opts.partial && ALL_ENGINES.every((e) => engines.includes(e)) && statuses.every((s) => s.ok);
      const stale = full
        ? a.unmatchedEntries.map((e) => ({ id: e.id, kind: e.kind, ruleId: e.ruleId, path: e.path }))
        : undefined;
      baseline = {
        file: shown,
        baselined: a.suppressed.filter((f) => f.suppression?.kind === "baseline").length,
        suppressed: a.suppressed.filter((f) => f.suppression?.kind !== "baseline").length,
        resurfaced: a.resurfaced,
        ...(stale ? { stale } : {}),
      };
      if (stale?.length)
        warnings.push(
          `${shown}: ${stale.length} entr${stale.length === 1 ? "y matches" : "ies match"} no finding (fixed, or the code changed); run \`hagstone baseline prune\``,
        );
    }
  }
  if (opts.reachableOnly) kept = kept.filter((f) => f.reachability?.status !== "unreachable");

  return {
    root,
    findings: sortFindings(kept),
    ignores: ignores.slice(DEFAULT_IGNORES.length),
    warnings,
    engines: statuses,
    hiddenInTests,
    ...(suppressed ? { suppressed } : {}),
    ...(baseline ? { baseline } : {}),
  };
}
