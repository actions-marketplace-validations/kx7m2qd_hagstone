/**
 * Baseline + suppressions (docs/specs/baseline.md): a committed file of findings a team has already
 * seen (`baseline`) or decided about (`false-positive`, `accepted-risk`). Matched findings are left out
 * of the gate and the reports, unless they got worse. Everything here is pure except load/save.
 */
import { readFile, mkdir, writeFile } from "node:fs/promises";
import { dirname, join } from "node:path";
import { fingerprint, gateSeverity, normalizeCode, SEVERITY_ORDER, type Finding, type ReachabilityStatus, type Severity } from "./finding.js";

export const BASELINE_FILE = ".hagstone/baseline.json";
export const BASELINE_SCHEMA = 1;
/** Default lifetime of an `accepted-risk` decision. */
export const ACCEPTED_RISK_DAYS = 90;
const EXCERPT_MAX = 120;

export type SuppressionKind = "baseline" | "false-positive" | "accepted-risk";
export const SUPPRESSION_KINDS: readonly SuppressionKind[] = ["baseline", "false-positive", "accepted-risk"];

export interface BaselineEntry {
  id: string;
  kind: SuppressionKind;
  engine: string;
  category: string;
  ruleId: string;
  path: string;
  /** Severity before reachability lowered it, when recorded; a higher one later resurfaces the finding. */
  severity: Severity;
  /** Reachability when recorded (dependencies); unreachable/dev-only → reachable resurfaces it. */
  reachability?: ReachabilityStatus;
  /** YYYY-MM-DD */
  date: string;
  reason?: string;
  /** YYYY-MM-DD, accepted-risk only. */
  expires?: string;
  /** Redacted code excerpt for humans (code findings only). */
  excerpt?: string;
  /** engine + rule + normalized code, without the path: survives renames (code findings only). */
  codeHash?: string;
  dependency?: { ecosystem: string; name: string; version: string; advisories: string[] };
}

export interface BaselineFile {
  schema: number;
  hagstoneVersion: string;
  entries: BaselineEntry[];
}

/** What a matched finding carries in JSON output. */
export type Suppression = NonNullable<Finding["suppression"]>;

export interface StaleEntry {
  id: string;
  kind: SuppressionKind;
  ruleId: string;
  path: string;
}

export interface BaselineSummary {
  file: string;
  baselined: number;
  suppressed: number;
  resurfaced: number;
  /** Undefined when the scan was partial, so staleness couldn't be judged. */
  stale?: StaleEntry[];
}

/** Known-malicious packages are never acceptable, so no entry can hide one. */
export const neverSuppressible = (f: Pick<Finding, "ruleId">): boolean => f.ruleId === "pkg-known-malicious";

/** Kinds allowed for a finding: secrets only as false positives; malicious packages none. */
export function allowedKinds(f: Pick<Finding, "ruleId" | "category">): SuppressionKind[] {
  if (neverSuppressible(f)) return [];
  if (f.category === "secret") return ["false-positive"];
  return [...SUPPRESSION_KINDS];
}

export function codeHash(f: Finding): string | undefined {
  if (f.category !== "code" || !f.location.snippet) return undefined;
  return fingerprint("baseline-code", f.engine, f.ruleId, normalizeCode(f.location.snippet));
}

const depKey = (engine: string, d: { ecosystem: string; name: string; version: string }) =>
  `${engine}\u0000${d.ecosystem}\u0000${d.name}\u0000${d.version}`;

export const today = (now = new Date()): string => now.toISOString().slice(0, 10);

export function addDays(date: string, days: number): string {
  const d = new Date(`${date}T00:00:00Z`);
  d.setUTCDate(d.getUTCDate() + days);
  return today(d);
}

export const isDate = (s: string): boolean => /^\d{4}-\d{2}-\d{2}$/.test(s) && !Number.isNaN(Date.parse(`${s}T00:00:00Z`));

/** Build the entry for a finding. Never stores a raw secret: secret entries keep no excerpt. */
export function entryFor(
  f: Finding,
  kind: SuppressionKind,
  opts: { date: string; reason?: string; expires?: string },
): BaselineEntry {
  const e: BaselineEntry = {
    id: f.id,
    kind,
    engine: f.engine,
    category: f.category,
    ruleId: f.ruleId,
    path: f.location.path,
    severity: gateSeverity(f),
    date: opts.date,
  };
  if (f.reachability) e.reachability = f.reachability.status;
  if (opts.reason) e.reason = opts.reason;
  if (kind === "accepted-risk") e.expires = opts.expires ?? addDays(opts.date, ACCEPTED_RISK_DAYS);
  if (f.category === "code" && f.location.snippet) {
    e.excerpt = f.location.snippet.split("\n")[0]!.trim().slice(0, EXCERPT_MAX);
    e.codeHash = codeHash(f);
  }
  if (f.dependency) {
    const { ecosystem, name, version, advisories } = f.dependency;
    e.dependency = { ecosystem, name, version, advisories: [...advisories].sort() };
  }
  return e;
}

/** Whether an entry may hide this finding at all. */
function usable(e: BaselineEntry, f: Finding): boolean {
  if (neverSuppressible(f)) return false;
  if (f.category === "secret" && e.kind !== "false-positive") return false;
  return true;
}

export interface Match {
  finding: Finding;
  entry: BaselineEntry;
  /** True when found by a fallback key rather than the exact fingerprint. */
  fallback: boolean;
}

/**
 * Pair findings with entries, each entry used at most once: exact fingerprints first, then the
 * fallbacks (code: engine + rule + normalized code; dependency: engine + package coordinates).
 * Secrets match exactly only.
 */
export function matchEntries(findings: Finding[], entries: BaselineEntry[]): { matches: Match[]; unmatchedEntries: BaselineEntry[] } {
  const free = new Set(entries);
  const byId = new Map<string, BaselineEntry[]>();
  for (const e of entries) byId.set(e.id, [...(byId.get(e.id) ?? []), e]);
  const matches: Match[] = [];
  const pending: Finding[] = [];

  for (const f of findings) {
    const e = (byId.get(f.id) ?? []).find((x) => free.has(x) && usable(x, f));
    if (e) {
      free.delete(e);
      matches.push({ finding: f, entry: e, fallback: false });
    } else pending.push(f);
  }

  // Fallback keys, indexed so large repos stay linear. Values keep file order.
  const byFallback = new Map<string, BaselineEntry[]>();
  for (const e of free) {
    const keys = [e.codeHash ? `c\u0000${e.category}\u0000${e.codeHash}` : "", e.dependency ? `d\u0000${e.category}\u0000${depKey(e.engine, e.dependency)}` : ""];
    for (const k of keys) if (k) byFallback.set(k, [...(byFallback.get(k) ?? []), e]);
  }
  for (const f of pending) {
    if (f.category === "secret" || neverSuppressible(f)) continue;
    const ch = codeHash(f);
    const keys = [ch ? `c\u0000${f.category}\u0000${ch}` : "", f.dependency ? `d\u0000${f.category}\u0000${depKey(f.engine, f.dependency)}` : ""];
    let e: BaselineEntry | undefined;
    for (const k of keys) {
      if (!k || e) continue;
      e = (byFallback.get(k) ?? []).find((x) => free.has(x) && usable(x, f));
    }
    if (e) {
      free.delete(e);
      matches.push({ finding: f, entry: e, fallback: true });
    }
  }
  return { matches, unmatchedEntries: [...free] };
}

/** Why a matched finding should be reported again, or undefined if it stays hidden. */
export function resurfaceReason(f: Finding, e: BaselineEntry, date: string): string | undefined {
  if (e.kind === "accepted-risk" && e.expires && e.expires < date) return `accepted risk expired on ${e.expires}`;
  if (f.dependency && e.dependency) {
    const known = new Set(e.dependency.advisories);
    const added = f.dependency.advisories.filter((a) => !known.has(a));
    if (added.length) return `new advisor${added.length === 1 ? "y" : "ies"} since it was ${label(e.kind)}: ${added.slice(0, 5).join(", ")}${added.length > 5 ? ", …" : ""}`;
  }
  const now = gateSeverity(f);
  if (SEVERITY_ORDER.indexOf(now) < SEVERITY_ORDER.indexOf(e.severity))
    return `severity rose from ${e.severity} to ${now} since it was ${label(e.kind)}`;
  if ((e.reachability === "unreachable" || e.reachability === "dev-only") && f.reachability?.status === "reachable")
    return `now reachable (was ${e.reachability} when it was ${label(e.kind)})`;
  return undefined;
}

const label = (k: SuppressionKind) => (k === "baseline" ? "baselined" : k === "false-positive" ? "marked a false positive" : "accepted as a risk");

export interface Applied {
  /** Findings to report: unmatched ones, plus matched ones that resurfaced (with `resurfaced` set). */
  active: Finding[];
  /** Matched findings that stay hidden, with `suppression` set. */
  suppressed: Finding[];
  matches: Match[];
  unmatchedEntries: BaselineEntry[];
  resurfaced: number;
}

/**
 * Apply a baseline to the findings that will be reported (`visible`). `hidden` findings (e.g. test code
 * hidden by scope) are matched too, only so their entries don't look stale.
 */
export function applyBaseline(visible: Finding[], hidden: Finding[], file: BaselineFile, date: string): Applied {
  const { matches, unmatchedEntries } = matchEntries([...visible, ...hidden], file.entries);
  const byFinding = new Map(matches.map((m) => [m.finding, m]));
  const active: Finding[] = [];
  const suppressed: Finding[] = [];
  let resurfaced = 0;
  for (const f of visible) {
    const m = byFinding.get(f);
    if (!m) {
      active.push(f);
      continue;
    }
    const why = resurfaceReason(f, m.entry, date);
    if (why) {
      f.resurfaced = why;
      resurfaced++;
      active.push(f);
      continue;
    }
    const s: Suppression = { kind: m.entry.kind, date: m.entry.date };
    if (m.entry.reason) s.reason = m.entry.reason;
    if (m.entry.expires) s.expires = m.entry.expires;
    f.suppression = s;
    suppressed.push(f);
  }
  return { active, suppressed, matches, unmatchedEntries, resurfaced };
}

export const sortEntries = (entries: BaselineEntry[]): BaselineEntry[] =>
  [...entries].sort((a, b) => (a.id < b.id ? -1 : a.id > b.id ? 1 : a.kind.localeCompare(b.kind)));

export function serialize(file: BaselineFile): string {
  const ordered = { schema: file.schema, hagstoneVersion: file.hagstoneVersion, entries: sortEntries(file.entries) };
  return JSON.stringify(ordered, null, 2) + "\n";
}

/** Parse and validate. Throws with a readable message on anything unexpected. */
export function parseBaseline(text: string): BaselineFile {
  const raw = JSON.parse(text) as Partial<BaselineFile>;
  if (!raw || typeof raw !== "object") throw new Error("not a JSON object");
  if (raw.schema !== BASELINE_SCHEMA) throw new Error(`unsupported schema ${String(raw.schema)} (this version reads ${BASELINE_SCHEMA}); upgrade hagstone`);
  if (!Array.isArray(raw.entries)) throw new Error("`entries` must be an array");
  const sev = new Set<string>(SEVERITY_ORDER);
  raw.entries.forEach((e, i) => {
    const bad = (what: string) => new Error(`entry ${i}: ${what}`);
    if (!e || typeof e !== "object") throw bad("not an object");
    for (const k of ["id", "engine", "category", "ruleId", "path", "date"] as const)
      if (typeof e[k] !== "string" || !e[k]) throw bad(`missing \`${k}\``);
    if (!SUPPRESSION_KINDS.includes(e.kind)) throw bad(`unknown kind "${String(e.kind)}"`);
    if (!sev.has(e.severity)) throw bad(`unknown severity "${String(e.severity)}"`);
    if (e.kind !== "baseline" && !e.reason?.trim()) throw bad(`${e.kind} needs a \`reason\``);
    if (e.kind === "accepted-risk" && (!e.expires || !isDate(e.expires))) throw bad("accepted-risk needs an `expires` date (YYYY-MM-DD)");
  });
  return { schema: raw.schema, hagstoneVersion: String(raw.hagstoneVersion ?? ""), entries: raw.entries };
}

export const defaultBaselinePath = (root: string): string => join(root, BASELINE_FILE);

/** Read a baseline file. Missing → undefined; unreadable or invalid → `error`. */
export async function loadBaseline(path: string): Promise<{ file?: BaselineFile; error?: string }> {
  let text: string;
  try {
    text = await readFile(path, "utf8");
  } catch {
    return {};
  }
  try {
    return { file: parseBaseline(text) };
  } catch (e) {
    return { error: e instanceof Error ? e.message : String(e) };
  }
}

export async function saveBaseline(path: string, file: BaselineFile): Promise<void> {
  await mkdir(dirname(path), { recursive: true });
  await writeFile(path, serialize(file));
}
