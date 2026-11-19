# Spec: baseline + suppressions

Roadmap step 1 (`docs/APPROACH.md` §4). Design agreed 2026-11-18.

## Goal
A team can adopt Hagstone on an existing repo without fixing everything first, and can record
decisions about single findings (`false-positive`, `accepted-risk`) with a reason. After that, only
new findings, or old ones that got worse, are reported and fail the gate.

## The file: `.hagstone/baseline.json`
Committed to the repo. Pretty JSON (2 spaces), entries sorted by `id`, trailing newline.

```json
{
  "schema": 1,
  "hagstoneVersion": "0.4.0",
  "entries": [
    {
      "id": "<fingerprint>",
      "kind": "baseline | false-positive | accepted-risk",
      "engine": "opengrep",
      "category": "code",
      "ruleId": "js-xss",
      "path": "src/app.js",
      "severity": "high",
      "reachability": "unreachable (dependencies only)",
      "date": "2026-11-19",
      "reason": "required for false-positive / accepted-risk",
      "expires": "2027-02-17 (accepted-risk only)",
      "excerpt": "res.send(`<p>${name}</p>`)  (redacted, ≤120 chars, code findings only)",
      "codeHash": "<hash of engine + rule + normalized code> (code findings only)",
      "dependency": { "ecosystem": "npm", "name": "lodash", "version": "4.17.20", "advisories": ["GHSA-…"] }
    }
  ]
}
```

- `severity` is the finding's severity before reachability lowered it; `reachability` (dependencies)
  is the reachability status when recorded.
- No author field: `git blame` on the file has it, and it keeps personal data out.
- Never contains a raw secret: excerpts come from `Location.snippet`, which engines already redact
  for secrets and credential rules; secret entries store no excerpt at all.
- `.hagstone/` is in `DEFAULT_IGNORES`, so Hagstone never scans its own baseline.

## Matching (pure: `src/core/baseline.ts`)
Each entry matches at most one finding.
1. **Exact:** same `id`.
2. **Fallback, code findings:** same `codeHash` (engine + rule + normalized code, path not included),
   so a renamed file or moved code still matches.
3. **Fallback, dependency findings:** same engine + ecosystem + name + version (survives fingerprint
   changes such as 0.3.0's move to the `vulnerable-dependency` rule id).
4. **Secrets:** exact `id` only. A redacted snippet could match a different secret.

Never suppressible (entry ignored, finding stays): `pkg-known-malicious`. Secret entries only count
when `kind` is `false-positive`.

## When a matched finding comes back (resurfaces)
Shown as a normal finding, with `resurfaced` set to the reason, and counted by the gate:
- `accepted-risk` whose `expires` date has passed;
- dependency finding with an advisory not in the entry's `advisories`;
- severity (before reachability) higher than the entry's `severity`;
- recorded as `unreachable` or `dev-only` and now `reachable`. (Comparing reachability status rather
  than the lowered severity keeps `--no-reachability` from resurfacing everything.)

## Stale entries
Entries that match no finding. Reported as a warning (and a `::warning` annotation in GitHub Actions),
never a gate failure. Only computed on a full scan (all engines ran and succeeded, whole tree, not the
hook or MCP `paths` mode); otherwise an entry for a finding the partial scan didn't look for would look
stale. Matching runs on findings hidden by test scope too, so their entries aren't stale.

## Reports
- **ScanResult:** `findings` = active findings only; `suppressed` = matched findings with a
  `suppression` field (`kind`, `reason`, `date`, `expires`); `baseline` = summary
  (`file`, `baselined`, `suppressed`, `resurfaced`, `stale`).
- **Text:** suppressed findings hidden; one count line ("N baselined, M suppressed not shown;
  --no-baseline to show"); resurfaced findings show the reason; stale entries as a warning.
- **JSON:** the whole ScanResult, including `suppressed`.
- **SARIF:** suppressed findings left out (GitHub doesn't document SARIF `suppressions`), so their
  alerts close. Counts go in `runs[0].properties` for the job summary.
- **PR comments / check run:** built from SARIF, so they never include suppressed findings.
- **MCP `scan`:** counts only (`baselined`, `suppressed`). MCP has no tool that writes the file.

## When it applies
Automatically when `<root>/.hagstone/baseline.json` exists: `scan`, the Action, the pre-commit hook,
MCP. `--no-baseline` turns it off; `--baseline <file>` reads another file (missing → none). A file that
can't be parsed, or has an unknown `schema`, is a warning and is not applied (fail toward showing more).

**Action:** on pull requests it passes the base branch's copy with `--baseline` (like `.hagstoneignore`),
and warns when the PR changes the file. No copy on the base branch → `--no-baseline`.

## CLI
- `hagstone baseline create [path] [--force]`: full scan including test code, no baseline applied.
  Records every finding as `kind: baseline`, except secrets and known-malicious packages (they stay
  visible; the command says how many and how to mark secrets that are false positives). Refuses if any
  engine failed (a partial snapshot would make findings look new later). Refuses if the file exists,
  unless `--force`: then explicit decisions are kept, `baseline` entries are replaced, and it prints how
  many findings are new (swallowed into the baseline).
- `hagstone suppress <id|path:line> --as false-positive|accepted-risk --reason "…" [--expires YYYY-MM-DD] [--path <root>]`:
  full scan, finds the finding by id (or unique id prefix) or by `path:line`, writes or replaces its
  entry. `accepted-risk` defaults to 90 days. Secrets: only `false-positive`. Malicious packages: refused.
  `path:line` matching several findings: refused, lists their ids.
- `hagstone baseline prune [path]`: full scan; removes stale entries; rewrites entries matched by a
  fallback with the finding's current id/path/codeHash (this is the migration path when fingerprints
  change). Refuses if any engine failed.
- Every write records the current `schema` and `hagstoneVersion`.

## Done when
- Unit tests for matching (exact, code fallback, dependency fallback, secrets exact-only, malicious
  never, one-to-one), resurfacing (expiry, new advisory, higher severity), staleness, file read/write
  (sorted, schema check, malformed file), and the CLI commands end to end on a fixture.
- `npm run check` and `npm run bench` pass.
- On a real repo: `baseline create` → scan shows 0 findings and passes; add a vulnerable line → only it
  shows; `suppress` it → gone; remove the code → `prune` removes the entry.
