/**
 * `hagstone baseline create|prune` and `hagstone suppress` (docs/specs/baseline.md). Each runs a full
 * scan with no baseline applied, so it sees every finding, then edits `.hagstone/baseline.json`.
 */
import { resolve } from "node:path";
import {
  allowedKinds,
  BASELINE_FILE,
  BASELINE_SCHEMA,
  codeHash,
  defaultBaselinePath,
  entryFor,
  isDate,
  loadBaseline,
  matchEntries,
  saveBaseline,
  today,
  type BaselineEntry,
  type SuppressionKind,
} from "../core/baseline.js";
import type { Finding } from "../core/finding.js";
import { sanitizeForTerminal as safe } from "../core/sanitize.js";
import type { ScanOptions, ScanResult } from "../scan.js";

export interface CommandDeps {
  scan: (target: string, opts: ScanOptions) => Promise<ScanResult>;
  version: string;
  now?: Date;
}

export interface CommandResult {
  code: number;
  message: string;
}

const plural = (n: number, one: string, many = `${one}s`) => `${n} ${n === 1 ? one : many}`;

/** Every finding in the tree, test code included, no baseline applied. */
async function fullScan(root: string, deps: CommandDeps): Promise<{ result: ScanResult; failed: string[] }> {
  const result = await deps.scan(root, { includeTests: true, noBaseline: true });
  return { result, failed: result.engines.filter((e) => !e.ok).map((e) => `${e.engine}${e.error ? ` (${e.error})` : ""}`) };
}

const refusePartial = (failed: string[], what: string): CommandResult => ({
  code: 2,
  message: `not ${what}: ${failed.join(", ")} failed, so the scan is incomplete and findings would look new later. Fix the engine (\`hagstone engines install\`) and try again.`,
});

export async function baselineCreate(target: string, opts: { force: boolean }, deps: CommandDeps): Promise<CommandResult> {
  const root = resolve(target);
  const path = defaultBaselinePath(root);
  const existing = await loadBaseline(path);
  if ((existing.file || existing.error) && !opts.force)
    return { code: 2, message: `${BASELINE_FILE} already exists. Use \`hagstone suppress\` for single findings, or --force to snapshot again.` };

  const { result, failed } = await fullScan(root, deps);
  if (failed.length) return refusePartial(failed, "writing a baseline");
  const date = today(deps.now);

  const kept: BaselineEntry[] = existing.file ? existing.file.entries.filter((e) => e.kind !== "baseline") : [];
  const decided = new Set(matchEntries(result.findings, kept).matches.map((m) => m.finding));
  const known = existing.file ? new Set(matchEntries(result.findings, existing.file.entries).matches.map((m) => m.finding)) : undefined;

  const eligible = result.findings.filter((f) => allowedKinds(f).includes("baseline"));
  const left = result.findings.filter((f) => !allowedKinds(f).includes("baseline") && !decided.has(f));
  const added = eligible.filter((f) => !decided.has(f)).map((f) => entryFor(f, "baseline", { date }));
  await saveBaseline(path, { schema: BASELINE_SCHEMA, hagstoneVersion: deps.version, entries: [...kept, ...added] });

  const lines = [`Wrote ${BASELINE_FILE}: ${plural(added.length, "finding")} baselined${kept.length ? `, ${plural(kept.length, "decision")} kept` : ""}.`];
  if (known) {
    const swallowed = eligible.filter((f) => !known.has(f)).length;
    lines.push(swallowed ? `${plural(swallowed, "finding was", "findings were")} not in the old baseline and ${swallowed === 1 ? "is" : "are"} now hidden too.` : "No new findings were added.");
  }
  if (existing.error) lines.push(`The old file couldn't be read (${existing.error}), so no decisions were kept.`);
  if (left.length) {
    const secrets = left.filter((f) => f.category === "secret").length;
    const other = left.length - secrets;
    if (secrets)
      lines.push(`${plural(secrets, "secret")} not baselined: rotate ${secrets === 1 ? "it" : "them"}, or mark a test/dummy value with \`hagstone suppress <id> --as false-positive --reason "…"\`.`);
    if (other) lines.push(`${plural(other, "known-malicious package")} not baselined: remove ${other === 1 ? "it" : "them"}.`);
  }
  lines.push(`Commit ${BASELINE_FILE}. From now on only new findings are reported.`);
  return { code: 0, message: lines.join("\n") };
}

/** Find one finding by id, unique id prefix (≥6 chars), or `path:line`. */
export function locate(findings: Finding[], target: string): { finding?: Finding; error?: string } {
  const exact = findings.filter((f) => f.id === target);
  if (exact.length === 1) return { finding: exact[0] };
  if (/^[0-9a-f]{6,}$/i.test(target)) {
    const pre = findings.filter((f) => f.id.startsWith(target.toLowerCase()));
    if (pre.length === 1) return { finding: pre[0] };
    if (pre.length > 1) return { error: `id prefix ${target} matches ${pre.length} findings; use more characters.` };
  }
  const m = /^(.+):(\d+)$/.exec(target);
  if (m) {
    const path = m[1]!.replace(/\\/g, "/").replace(/^\.\//, "");
    const line = Number(m[2]);
    const hits = findings.filter((f) => f.location.path === path && line >= f.location.startLine && line <= (f.location.endLine ?? f.location.startLine));
    if (hits.length === 1) return { finding: hits[0] };
    if (hits.length > 1)
      return { error: `${target} has ${hits.length} findings; pick one by id:\n${hits.map((f) => `  ${f.id}  ${f.ruleId}  ${safe(f.title)}`).join("\n")}` };
  }
  return { error: `no finding matches ${target}. Use an id from \`hagstone scan --format json\`, or path:line.` };
}

export async function suppress(
  target: string,
  opts: { root: string; kind: string; reason?: string; expires?: string },
  deps: CommandDeps,
): Promise<CommandResult> {
  const kind = opts.kind as SuppressionKind;
  if (kind !== "false-positive" && kind !== "accepted-risk") return { code: 2, message: `--as must be false-positive or accepted-risk` };
  const reason = opts.reason?.trim();
  if (!reason) return { code: 2, message: `--reason is required: say why, for whoever reads this later.` };
  const date = today(deps.now);
  if (opts.expires !== undefined) {
    if (kind !== "accepted-risk") return { code: 2, message: `--expires only applies to accepted-risk (false positives don't expire).` };
    if (!isDate(opts.expires)) return { code: 2, message: `--expires must be a date like 2027-03-01.` };
    if (opts.expires <= date) return { code: 2, message: `--expires must be in the future.` };
  }

  const root = resolve(opts.root);
  const path = defaultBaselinePath(root);
  const existing = await loadBaseline(path);
  if (existing.error) return { code: 2, message: `${BASELINE_FILE} can't be read (${existing.error}). Fix or delete it first.` };

  const { result, failed } = await fullScan(root, deps);
  const { finding, error } = locate(result.findings, target);
  if (!finding) return { code: 2, message: `${error}${failed.length ? `\n(${failed.join(", ")} failed, so its findings are missing.)` : ""}` };

  const allowed = allowedKinds(finding);
  if (!allowed.includes(kind))
    return {
      code: 2,
      message: allowed.length
        ? `${finding.category === "secret" ? "Secrets" : "This finding"} can only be marked ${allowed.join(" or ")}. A real secret must be rotated.`
        : `Known-malicious packages can't be suppressed. Remove the package.`,
    };

  const entries = existing.file?.entries ?? [];
  const replaced = new Set(matchEntries([finding], entries).matches.map((m) => m.entry));
  const entry = entryFor(finding, kind, { date, reason, expires: opts.expires });
  await saveBaseline(path, { schema: BASELINE_SCHEMA, hagstoneVersion: deps.version, entries: [...entries.filter((e) => !replaced.has(e)), entry] });
  const what = `${finding.ruleId} at ${finding.location.path}:${finding.location.startLine}`;
  return {
    code: 0,
    message: `Marked ${safe(what)} as ${kind}${entry.expires ? ` until ${entry.expires}` : ""} in ${BASELINE_FILE}. Commit the file.`,
  };
}

export async function baselinePrune(target: string, deps: CommandDeps): Promise<CommandResult> {
  const root = resolve(target);
  const path = defaultBaselinePath(root);
  const existing = await loadBaseline(path);
  if (existing.error) return { code: 2, message: `${BASELINE_FILE} can't be read (${existing.error}).` };
  if (!existing.file) return { code: 2, message: `no ${BASELINE_FILE} here. Create one with \`hagstone baseline create\`.` };

  const { result, failed } = await fullScan(root, deps);
  if (failed.length) return refusePartial(failed, "pruning");

  const { matches, unmatchedEntries } = matchEntries(result.findings, existing.file.entries);
  let updated = 0;
  const entries = matches.map(({ finding: f, entry: e, fallback }) => {
    if (!fallback) return e;
    // Re-attach to the finding's current fingerprint and place. Advisories, severity and the
    // decision stay as recorded, so anything new still resurfaces.
    updated++;
    const next: BaselineEntry = { ...e, id: f.id, path: f.location.path, ruleId: f.ruleId };
    const ch = codeHash(f);
    if (ch) next.codeHash = ch;
    return next;
  });
  await saveBaseline(path, { schema: BASELINE_SCHEMA, hagstoneVersion: deps.version, entries });
  const lines = [`${BASELINE_FILE}: removed ${plural(unmatchedEntries.length, "stale entry", "stale entries")}, updated ${plural(updated, "moved entry", "moved entries")}, kept ${entries.length}.`];
  for (const e of unmatchedEntries.slice(0, 20)) lines.push(`  removed ${e.kind.padEnd(14)} ${e.ruleId}  ${safe(e.path)}`);
  if (unmatchedEntries.length > 20) lines.push(`  …and ${unmatchedEntries.length - 20} more`);
  return { code: 0, message: lines.join("\n") };
}
