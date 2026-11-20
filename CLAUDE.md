# Hagstone — notes for Claude Code

Read `docs/APPROACH.md` before planning any feature. It defines the principles, roadmap and loops.

## Commands
- `npm run dev -- scan <path>` — run the CLI from source
- `npm run check` — typecheck + unit tests + rule tests (must pass before you say "done")
- `npm run test:rules` — `opengrep test rules/`
- `npm run bench` — benchmark gate; fails if precision/recall drop below `bench/thresholds.json`
- `npm run bench:owasp` / `npm run bench:owasp:java` — OWASP Benchmark per-category gates (CI runs both)
- `npm run build` — compile to `dist/`

## Rules of the codebase
- All engine output is normalized into `Finding` (`src/core/finding.ts`). Do not let engine-specific
  shapes leak past `src/engines/`.
- Never put a raw secret value into a `Finding`, a log line, a report, or an AI prompt. Use
  `redactSecret()`.
- Engine binaries are pinned in `src/engines/manifest.ts` by version + SHA-256. Never download
  unverified binaries or use `latest` URLs.
- Every rule in `rules/<lang>/<id>.yml` needs a same-named test file with `ruleid:` and `ok:` cases.
  Rule IDs are kebab-case, prefixed with the language (`js-`, `py-`, `java-`), and contain no dots.
- Java rules run with `--taint-intrafile` (`INTRAFILE_RULE_DIRS` in `src/engines/opengrep.ts`); JS and
  Python don't (it lowers their OWASP score). `java.lang` types (`Runtime`, `ProcessBuilder`) must be
  matched by simple name in typed patterns.
- Rules need `metadata.cwe`, `metadata.owasp`, `metadata.confidence`, and a `message` that says
  what is wrong, why it matters, and how to fix it.
- `rules/` test files and `bench/cases/` are intentionally vulnerable. They are excluded via
  `.hagstoneignore`; keep it that way.
- Source code never leaves the user's machine. Only `Finding` objects may be sent anywhere.
- ESM + TypeScript, NodeNext resolution: relative imports end in `.js`.
- Prefer Node built-ins over new dependencies.
