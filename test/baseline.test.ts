import { mkdtemp, readFile, rm, writeFile, mkdir } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, describe, expect, it } from "vitest";
import {
  applyBaseline,
  BASELINE_FILE,
  BASELINE_SCHEMA,
  entryFor,
  loadBaseline,
  matchEntries,
  parseBaseline,
  resurfaceReason,
  serialize,
  type BaselineEntry,
  type BaselineFile,
} from "../src/core/baseline.js";
import { baselineCreate, baselinePrune, locate, suppress, type CommandDeps } from "../src/commands/baseline.js";
import { fingerprint, type Finding } from "../src/core/finding.js";
import { toSarif } from "../src/report/sarif.js";
import { toText } from "../src/report/text.js";
import type { ScanOptions, ScanResult } from "../src/scan.js";

const DATE = "2026-11-19";
const NOW = new Date(`${DATE}T12:00:00Z`);

let n = 0;
function code(over: Partial<Finding> & { path?: string; line?: number; snippet?: string } = {}): Finding {
  const { path = "src/a.js", line = 10, snippet = `res.send(x${n++})`, ...rest } = over;
  return {
    id: fingerprint("code", path, snippet),
    category: "code",
    engine: "opengrep",
    ruleId: "js-xss",
    title: "XSS",
    message: "m",
    severity: "high",
    location: { path, startLine: line, snippet },
    cwe: ["CWE-79"],
    owasp: [],
    ...rest,
  };
}

function dep(over: Partial<Finding> & { advisories?: string[]; version?: string } = {}): Finding {
  const { advisories = ["GHSA-1"], version = "1.0.0", ...rest } = over;
  return {
    id: fingerprint("dep", "lodash", version),
    category: "dependency",
    engine: "osv-scanner",
    ruleId: "vulnerable-dependency",
    title: "lodash",
    message: "m",
    severity: "high",
    location: { path: "package-lock.json", startLine: 1 },
    cwe: [],
    owasp: [],
    dependency: { name: "lodash", version, ecosystem: "npm", advisories, fixedVersions: [] },
    ...rest,
  };
}

function secret(over: Partial<Finding> = {}): Finding {
  return {
    id: fingerprint("secret", String(n++)),
    category: "secret",
    engine: "gitleaks",
    ruleId: "aws-access-token",
    title: "AWS key",
    message: "m",
    severity: "critical",
    location: { path: "config.js", startLine: 3, snippet: 'key = "AKIA************"' },
    cwe: [],
    owasp: [],
    ...over,
  };
}

const malicious = (): Finding => ({ ...dep(), id: fingerprint("mal"), ruleId: "pkg-known-malicious", severity: "critical" });

const file = (entries: BaselineEntry[]): BaselineFile => ({ schema: BASELINE_SCHEMA, hagstoneVersion: "test", entries });
const base = (f: Finding) => entryFor(f, "baseline", { date: DATE });

describe("matchEntries", () => {
  it("matches by exact fingerprint", () => {
    const f = code();
    const { matches, unmatchedEntries } = matchEntries([f], [base(f)]);
    expect(matches).toHaveLength(1);
    expect(matches[0]!.fallback).toBe(false);
    expect(unmatchedEntries).toEqual([]);
  });

  it("falls back to rule + normalized code when the file was renamed", () => {
    const before = code({ path: "src/old.js", snippet: "res.send( name )" });
    const after = code({ path: "src/new.js", snippet: "res.send(name)" });
    expect(after.id).not.toBe(before.id);
    const { matches } = matchEntries([after], [base(before)]);
    expect(matches).toHaveLength(1);
    expect(matches[0]!.fallback).toBe(true);
  });

  it("does not fall back across rules", () => {
    const before = code({ snippet: "res.send(name)" });
    const other = { ...code({ snippet: "res.send(name)", path: "b.js" }), ruleId: "js-other" };
    expect(matchEntries([other], [base(before)]).matches).toHaveLength(0);
  });

  it("falls back to package coordinates for dependencies (fingerprint scheme changed)", () => {
    const f = dep();
    const old = { ...base(f), id: "old-scheme-id", ruleId: "GHSA-1" };
    const { matches } = matchEntries([f], [old]);
    expect(matches).toHaveLength(1);
    expect(matches[0]!.fallback).toBe(true);
  });

  it("uses each entry at most once", () => {
    const a = code({ snippet: "res.send(name)", path: "a.js" });
    const b = code({ snippet: "res.send(name)", path: "b.js" });
    const { matches } = matchEntries([a, b], [base(a)]);
    expect(matches).toHaveLength(1);
    expect(matches[0]!.finding).toBe(a);
  });

  it("matches secrets by exact fingerprint only, and only false-positive entries", () => {
    const s = secret();
    const moved = { ...s, id: "different", location: { ...s.location, path: "other.js" } };
    const fp = entryFor(s, "false-positive", { date: DATE, reason: "test key" });
    expect(matchEntries([moved], [fp]).matches).toHaveLength(0);
    expect(matchEntries([s], [fp]).matches).toHaveLength(1);
    expect(matchEntries([s], [{ ...fp, kind: "baseline" }]).matches).toHaveLength(0);
    expect(matchEntries([s], [{ ...fp, kind: "accepted-risk", expires: "2099-01-01" }]).matches).toHaveLength(0);
  });

  it("never matches known-malicious packages", () => {
    const m = malicious();
    expect(matchEntries([m], [entryFor(m, "false-positive", { date: DATE, reason: "x" })]).matches).toHaveLength(0);
  });
});

describe("resurfaceReason", () => {
  it("brings back an expired accepted risk", () => {
    const f = code();
    const e = entryFor(f, "accepted-risk", { date: "2026-01-01", reason: "r", expires: "2026-03-01" });
    expect(resurfaceReason(f, e, DATE)).toMatch(/expired on 2026-03-01/);
    expect(resurfaceReason(f, e, "2026-02-01")).toBeUndefined();
  });

  it("defaults accepted-risk to 90 days", () => {
    expect(entryFor(code(), "accepted-risk", { date: DATE, reason: "r" }).expires).toBe("2027-02-17");
  });

  it("brings back a dependency with a new advisory", () => {
    const e = base(dep({ advisories: ["GHSA-1"] }));
    expect(resurfaceReason(dep({ advisories: ["GHSA-1", "GHSA-2"] }), e, DATE)).toMatch(/new advisory.*GHSA-2/);
    expect(resurfaceReason(dep({ advisories: ["GHSA-1"] }), e, DATE)).toBeUndefined();
  });

  it("brings back a finding whose severity rose", () => {
    const e = base(code({ severity: "medium" }));
    expect(resurfaceReason(code({ severity: "critical" }), e, DATE)).toMatch(/medium to critical/);
  });

  it("brings back a dependency that became reachable, but not when reachability is off", () => {
    const lowered = dep({ severity: "medium", reachability: { status: "unreachable", reason: "r", originalSeverity: "high" } });
    const e = base(lowered);
    expect(e.severity).toBe("high");
    expect(e.reachability).toBe("unreachable");
    const now = dep({ reachability: { status: "reachable", reason: "imported" } });
    expect(resurfaceReason(now, e, DATE)).toMatch(/now reachable/);
    // --no-reachability: shown at the original severity, no status. Not "worse".
    expect(resurfaceReason(dep(), e, DATE)).toBeUndefined();
  });
});

describe("applyBaseline", () => {
  it("splits active, suppressed and resurfaced, and counts hidden findings as matched", () => {
    const keep = code();
    const hide = code();
    const back = dep({ advisories: ["GHSA-1", "GHSA-9"] });
    const testOnly = code({ path: "test/x.js" });
    const fp = entryFor(hide, "false-positive", { date: DATE, reason: "sanitized upstream" });
    const a = applyBaseline([keep, hide, back], [testOnly], file([fp, base(dep()), base(testOnly)]), DATE);
    expect(a.active).toEqual([keep, back]);
    expect(back.resurfaced).toMatch(/GHSA-9/);
    expect(a.suppressed).toEqual([hide]);
    expect(hide.suppression).toEqual({ kind: "false-positive", reason: "sanitized upstream", date: DATE });
    expect(a.unmatchedEntries).toEqual([]);
  });
});

describe("file format", () => {
  it("serializes sorted, pretty and with a trailing newline, and round-trips", () => {
    const a = base(code());
    const b = base(code());
    const text = serialize(file([b, a].sort((x, y) => (x.id < y.id ? 1 : -1))));
    expect(text.endsWith("}\n")).toBe(true);
    expect(text).toContain('\n  "schema": 1');
    const parsed = parseBaseline(text);
    expect(parsed.entries.map((e) => e.id)).toEqual([a.id, b.id].sort());
  });

  it("rejects unknown schemas, bad kinds, decisions without a reason, accepted-risk without expires", () => {
    const ok = base(code());
    expect(() => parseBaseline(JSON.stringify({ schema: 2, entries: [] }))).toThrow(/schema 2/);
    expect(() => parseBaseline(JSON.stringify(file([{ ...ok, kind: "ignore" as never }])))).toThrow(/unknown kind/);
    expect(() => parseBaseline(JSON.stringify(file([{ ...ok, kind: "false-positive" }])))).toThrow(/reason/);
    expect(() => parseBaseline(JSON.stringify(file([{ ...ok, kind: "accepted-risk", reason: "r" }])))).toThrow(/expires/);
    expect(() => parseBaseline("{not json")).toThrow();
  });

  it("never stores a secret excerpt", () => {
    const e = entryFor(secret(), "false-positive", { date: DATE, reason: "dummy" });
    expect(e.excerpt).toBeUndefined();
    expect(e.codeHash).toBeUndefined();
  });

  it("loadBaseline: missing is fine, broken is an error", async () => {
    const dir = await mkdtemp(join(tmpdir(), "hagstone-bl-"));
    try {
      expect(await loadBaseline(join(dir, "nope.json"))).toEqual({});
      await writeFile(join(dir, "bad.json"), "{");
      expect((await loadBaseline(join(dir, "bad.json"))).error).toBeTruthy();
    } finally {
      await rm(dir, { recursive: true, force: true });
    }
  });
});

describe("reports", () => {
  const result = (findings: Finding[], suppressed: Finding[]): ScanResult => ({
    root: "/r",
    findings,
    ignores: [],
    warnings: [],
    engines: [],
    suppressed,
    baseline: { file: BASELINE_FILE, baselined: 2, suppressed: 1, resurfaced: 1, stale: [] },
  });

  it("SARIF leaves suppressed findings out and carries the counts", () => {
    const shown = { ...code(), resurfaced: "new advisory" };
    const sarif = toSarif(result([shown], [code()])) as { runs: { results: unknown[]; properties: unknown }[] };
    expect(sarif.runs[0]!.results).toHaveLength(1);
    expect(sarif.runs[0]!.properties).toEqual({ hagstone: { baselined: 2, suppressed: 1, resurfaced: 1, stale: 0 } });
  });

  it("text shows the count line and why a finding came back", () => {
    const text = toText(result([{ ...code(), resurfaced: "accepted risk expired on 2026-01-01" }], []), { color: false });
    expect(text).toContain("back: accepted risk expired on 2026-01-01");
    expect(text).toContain("2 baselined, 1 suppressed (false positive / accepted risk) not shown");
    expect(text).toContain("--no-baseline");
  });
});

describe("commands", () => {
  let dir: string;
  let findings: Finding[];
  let failed = false;
  const calls: ScanOptions[] = [];
  const deps: CommandDeps = {
    version: "9.9.9",
    now: NOW,
    scan: async (root: string, opts: ScanOptions) => {
      calls.push(opts);
      return {
        root,
        findings,
        ignores: [],
        warnings: [],
        engines: [{ engine: "opengrep", ok: !failed, findings: findings.length, ms: 1, ...(failed ? { error: "boom" } : {}) }],
      };
    },
  };
  const read = async () => parseBaseline(await readFile(join(dir, BASELINE_FILE), "utf8"));

  async function setup(list: Finding[]) {
    dir = await mkdtemp(join(tmpdir(), "hagstone-cmd-"));
    findings = list;
    failed = false;
    calls.length = 0;
  }
  afterEach(async () => rm(dir, { recursive: true, force: true }));

  it("create: snapshots everything but secrets and malicious packages, with a full scan", async () => {
    await setup([code(), dep(), secret(), malicious()]);
    const res = await baselineCreate(dir, { force: false }, deps);
    expect(res.code).toBe(0);
    expect(res.message).toMatch(/2 findings baselined/);
    expect(res.message).toMatch(/1 secret not baselined/);
    expect(res.message).toMatch(/1 known-malicious package not baselined/);
    expect(calls[0]).toEqual({ includeTests: true, noBaseline: true });
    const f = await read();
    expect(f.hagstoneVersion).toBe("9.9.9");
    expect(f.entries.map((e) => e.kind)).toEqual(["baseline", "baseline"]);
  });

  it("create: refuses to overwrite, and refuses a partial scan", async () => {
    await setup([code()]);
    await baselineCreate(dir, { force: false }, deps);
    expect((await baselineCreate(dir, { force: false }, deps)).code).toBe(2);
    failed = true;
    const res = await baselineCreate(dir, { force: true }, deps);
    expect(res.code).toBe(2);
    expect(res.message).toMatch(/opengrep \(boom\) failed/);
  });

  it("create --force: keeps decisions and says how many new findings it swallows", async () => {
    const old = code();
    const decided = code();
    await setup([old, decided]);
    await baselineCreate(dir, { force: false }, deps);
    await suppress(decided.id, { root: dir, kind: "false-positive", reason: "escaped by the template" }, deps);
    findings = [old, decided, code(), code()];
    const res = await baselineCreate(dir, { force: true }, deps);
    expect(res.message).toMatch(/3 findings baselined, 1 decision kept/);
    expect(res.message).toMatch(/2 findings were not in the old baseline/);
    const kinds = (await read()).entries.map((e) => e.kind).sort();
    expect(kinds).toEqual(["baseline", "baseline", "baseline", "false-positive"]);
  });

  it("suppress: by id prefix, replacing the baseline entry; accepted-risk gets an expiry", async () => {
    const f = code();
    await setup([f, code()]);
    await baselineCreate(dir, { force: false }, deps);
    const res = await suppress(f.id.slice(0, 8), { root: dir, kind: "accepted-risk", reason: "internal admin tool" }, deps);
    expect(res.code).toBe(0);
    expect(res.message).toMatch(/until 2027-02-17/);
    const entries = (await read()).entries.filter((e) => e.id === f.id);
    expect(entries).toHaveLength(1);
    expect(entries[0]).toMatchObject({ kind: "accepted-risk", reason: "internal admin tool", expires: "2027-02-17" });
  });

  it("suppress: path:line, ambiguity, and input checks", async () => {
    const a = code({ path: "src/x.js", line: 5 });
    const b = code({ path: "src/x.js", line: 5 });
    await setup([a, b, code({ path: "src/y.js", line: 7 })]);
    const amb = await suppress("src/x.js:5", { root: dir, kind: "false-positive", reason: "r" }, deps);
    expect(amb.code).toBe(2);
    expect(amb.message).toContain(a.id);
    expect((await suppress("./src/y.js:7", { root: dir, kind: "false-positive", reason: "r" }, deps)).code).toBe(0);
    expect((await suppress("src/y.js:7", { root: dir, kind: "false-positive", reason: " " }, deps)).message).toMatch(/--reason/);
    expect((await suppress("src/y.js:7", { root: dir, kind: "baseline", reason: "r" }, deps)).code).toBe(2);
    expect((await suppress("src/y.js:7", { root: dir, kind: "false-positive", reason: "r", expires: "2027-01-01" }, deps)).message).toMatch(/only applies/);
    expect((await suppress("src/y.js:7", { root: dir, kind: "accepted-risk", reason: "r", expires: "2026-01-01" }, deps)).message).toMatch(/future/);
    expect((await suppress("nothing:1", { root: dir, kind: "false-positive", reason: "r" }, deps)).message).toMatch(/no finding/);
  });

  it("suppress: secrets only as false positives, malicious packages never", async () => {
    const s = secret();
    const m = malicious();
    await setup([s, m]);
    expect((await suppress(s.id, { root: dir, kind: "accepted-risk", reason: "r" }, deps)).message).toMatch(/rotated/);
    expect((await suppress(s.id, { root: dir, kind: "false-positive", reason: "dummy key in docs" }, deps)).code).toBe(0);
    expect((await suppress(m.id, { root: dir, kind: "false-positive", reason: "r" }, deps)).message).toMatch(/can't be suppressed/);
  });

  it("prune: removes stale entries and re-attaches moved ones without refreshing advisories", async () => {
    const fixed = code();
    const moved = code({ path: "src/old.js", snippet: "res.send(q)" });
    const d = dep({ advisories: ["GHSA-1"] });
    await setup([fixed, moved, d]);
    await baselineCreate(dir, { force: false }, deps);
    const now = code({ path: "src/new.js", snippet: "res.send(q)" });
    findings = [now, dep({ advisories: ["GHSA-1", "GHSA-2"] })];
    const res = await baselinePrune(dir, deps);
    expect(res.message).toMatch(/removed 1 stale entry, updated 1 moved entry, kept 2/);
    const entries = (await read()).entries;
    expect(entries.find((e) => e.path === "src/new.js")?.id).toBe(now.id);
    expect(entries.find((e) => e.dependency)?.dependency?.advisories).toEqual(["GHSA-1"]);
  });

  it("prune: refuses without a file, with a broken file, or after a failed engine", async () => {
    await setup([code()]);
    expect((await baselinePrune(dir, deps)).message).toMatch(/no \.hagstone/);
    await mkdir(join(dir, ".hagstone"));
    await writeFile(join(dir, BASELINE_FILE), "{}");
    expect((await baselinePrune(dir, deps)).message).toMatch(/can't be read/);
    await rm(join(dir, BASELINE_FILE));
    await baselineCreate(dir, { force: false }, deps);
    failed = true;
    expect((await baselinePrune(dir, deps)).code).toBe(2);
  });

  it("locate: exact id beats prefix; short prefixes are not ids", () => {
    const a = code();
    expect(locate([a], a.id).finding).toBe(a);
    expect(locate([a], a.id.slice(0, 5)).error).toMatch(/no finding/);
  });
});

describe("scan() with a baseline (real pipeline, offline pkgrisk only)", () => {
  let dir: string;
  afterEach(async () => rm(dir, { recursive: true, force: true }));

  it("hides baselined findings, honours --no-baseline and --baseline, warns on a broken file", async () => {
    const { scan } = await import("../src/scan.js");
    dir = await mkdtemp(join(tmpdir(), "hagstone-scan-"));
    await writeFile(join(dir, "requirements.txt"), "reqeusts==1.0\n");
    const opts: ScanOptions = { engines: ["pkgrisk"], offline: true };

    const first = await scan(dir, opts);
    expect(first.findings.map((f) => f.ruleId)).toEqual(["pkg-typosquat"]);
    expect(first.baseline).toBeUndefined();

    await mkdir(join(dir, ".hagstone"));
    await writeFile(join(dir, BASELINE_FILE), serialize(file([base(first.findings[0]!)])));
    const second = await scan(dir, opts);
    expect(second.findings).toEqual([]);
    expect(second.suppressed?.map((f) => f.suppression?.kind)).toEqual(["baseline"]);
    // Only one engine ran, so unmatched entries can't be judged stale.
    expect(second.baseline).toMatchObject({ file: BASELINE_FILE, baselined: 1, suppressed: 0, resurfaced: 0 });
    expect(second.baseline?.stale).toBeUndefined();

    expect((await scan(dir, { ...opts, noBaseline: true })).findings).toHaveLength(1);
    expect((await scan(dir, { ...opts, baseline: join(dir, "missing.json") })).findings).toHaveLength(1);

    await writeFile(join(dir, BASELINE_FILE), "{");
    const broken = await scan(dir, opts);
    expect(broken.findings).toHaveLength(1);
    expect(broken.warnings.join("\n")).toMatch(/\.hagstone\/baseline\.json not applied/);
  });
});
