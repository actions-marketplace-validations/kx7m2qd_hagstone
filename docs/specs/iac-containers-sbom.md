# Spec: IaC, container images, SBOM + licenses

Roadmap step 2 (`docs/APPROACH.md` §4). Written 2026-11-20.

## Goal
One `hagstone scan` also covers infrastructure as code (Terraform, Kubernetes, Dockerfile, Helm,
CloudFormation, ARM, Ansible) and license compliance; `hagstone sbom` writes a CycloneDX or SPDX
SBOM; `hagstone scan --image <ref>` scans a container image. Same bar as today: pinned, normalized
into `Finding`, benchmarked, quiet.

## Engine choice (checked 2026-11-20)

| Job | Engine | License | Why |
|---|---|---|---|
| IaC | **Trivy** 0.76.2 (`trivy config`) | Apache-2.0 | KICS stopped publishing binaries (Docker only); Checkov ships x86_64 zips only, no darwin-arm64, no checksum file. Neither can be pinned the way §2.4 requires. |
| SBOM + licenses | **Syft** 1.57.2 | Apache-2.0 | The standard cataloger; CycloneDX + SPDX; checksums + Sigstore. |
| Container image vulnerabilities | **Grype** 0.122.1 | Apache-2.0 | Matches vulnerabilities from Syft's SBOM, so an image is catalogued once and the SBOM and the findings agree. |

All three: archives pinned by SHA-256 (matching the published checksum files) and the extracted
binary re-checked before every run. Each checksum file's Sigstore bundle signs that digest and has a
transparency-log entry; full `cosign verify-blob` is still a TODO (as for Opengrep).

**Trivy's March 2026 compromise** (CVE-2026-33634 / GHSA-69fq-xp46-6x23: a stolen bot token published a
malicious v0.69.4 and force-pushed the `trivy-action` tags). Pinning by hash is the defense: we never
use `latest`, never use `trivy-action`, and every bump is checked against Trivy's advisories first.

## Untrusted repo: what each engine must not read or do
The scanned repo is untrusted (same rule as `.gitleaksignore` and the baseline).

Trivy (verified by running it):
- `trivy.yaml` in the working directory and `.trivyignore` are loaded by default → `--config ""`,
  `--ignorefile ""`, and the working directory is an empty temp dir.
- Inline `#trivy:ignore:<id>` / `#tfsec:ignore:<id>` comments silence checks (confirmed on
  AVD-AWS-0057) and there's no flag to turn them off → Trivy scans a **copy** of the IaC files in which
  those markers are rewritten (same line count, so line numbers hold).
- Terraform `module` blocks with a remote `source` (registry, `git::`, `http`, `s3::`, …) are
  **downloaded**, and `TRIVY_OFFLINE_SCAN` doesn't stop it → in the copy, every module `source` that
  isn't a relative path inside the repo is replaced with a path that doesn't exist. Trivy then skips
  that module. Third-party module code isn't the repo's code anyway, and the scan stays offline.
- Downloaded modules are cached in `$TMPDIR/.aqua/cache`, shared across runs → each run gets a fresh
  `TMPDIR`.
- `--skip-check-update` (built-in checks only, nothing fetched), `--skip-version-check`,
  `--disable-telemetry`, `--module-dir <empty dir>` (no WASM modules from `~/.trivy`).
- The copy skips symlinks, `.terraform/`, ignored paths (`.hagstoneignore` + defaults), files over 5 MB,
  and JSON files that are clearly not IaC (`package.json`, lockfiles, `tsconfig*.json`).

Syft and Grype read `.syft.yaml` / `.grype.yaml` from the working directory → run them from an empty
temp dir with `--config` pointing at our own files.

## 1. IaC findings (`engine: "trivy"`, `category: "iac"`)
- One finding per failed check per resource (`Status: FAIL`; successes are never requested).
- `ruleId`: Trivy's check ID as given (`AWS-0107`, `KSV-0017`, `DS-0002`).
- `id` = fingerprint(`trivy`, check ID, path, `CauseMetadata.Resource` or "", Trivy's `Message`).
  Not the line: findings survive edits elsewhere in the file. The message names the resource for
  Kubernetes ("Container 'web' of Pod 'web' …"), so two pods in one file stay apart.
- Severity: Trivy's, one to one (`UNKNOWN` → `info`). Confidence `high` (deterministic checks).
- `cwe: []` (Trivy doesn't map checks to CWEs), `owasp: ["A05:2021 - Security Misconfiguration"]`.
- Message: what is wrong (Trivy `Message`), why it matters (`Description`), how to fix (`Resolution`),
  plus the reference URL.
- Location: path + `CauseMetadata.StartLine`/`EndLine` (line 1 when absent). **No snippet**: IaC files
  often hold credentials, and Gitleaks already reports those with redaction.
- Test and example paths: hidden by default, like code findings (Terraform `examples/` folders are
  common and aren't deployed).

### Quiet by default: the hardening tier
Trivy reports every best-practice gap: three tiny files gave 31 findings, 18 for one pod. Hagstone
reports the things that expose something and hides **hardening** checks by default, counted in one
warning line, shown with `--include-hardening`:
- every `LOW` check;
- the checks listed in `config/iac-hardening.json`, each with a one-line reason (e.g. AWS-0132
  "customer-managed KMS key instead of the AWS-managed one": HIGH in Trivy, but not an exposure).

Hidden hardening findings are not baselined and not gated. The list is reviewed like a rule: a change
must keep the IaC bench gate.

### Benchmark
`bench/cases/iac/`: realistic Terraform, Kubernetes, Dockerfile and Helm files with
`# expect: <check-id>` labels (lowercase) on real exposures, safe variants next to them, and
hardening-only resources that must report nothing. Scored by `npm run bench` together with the code
cases (precision / recall gate). Also tests the untrusted-repo defenses: an inline `trivy:ignore` on
a labeled line must not hide it, and a remote module must not be fetched.

## 2. SBOM + licenses (Syft) — built 2026-11-20
- `hagstone sbom [path] [--format cyclonedx|spdx] [--output <file>] [--offline]`: Syft's SBOM of the
  directory, unchanged. Image SBOMs come with the container milestone.
- Syft's own config (written per run, `--config`; cwd is an empty dir): no update check, no Go
  tooling (`use-packages-lib` would run `go` on the repo), no Maven / Go-proxy / git-clone lookups, no
  dev dependencies (they don't ship). Only PyPI license metadata is fetched (names only, like
  pkgrisk); `--offline` turns that off. npm licenses come from `package-lock.json`.
- License findings (`category: "license"`, `engine: "syft"`, one per package version; fingerprint
  `syft`, ecosystem, name, version, license):
  | rule | licenses | severity |
  |---|---|---|
  | `license-network-copyleft` | AGPL, SSPL | high |
  | `license-copyleft` | GPL (not LGPL; not GPL WITH a linking exception such as Classpath) | medium |
  | `license-non-commercial` | CC-BY-NC, BUSL, Elastic-2.0, Commons Clause, PolyForm-Noncommercial | high |
  | `license-denied` | anything in the policy's `deny` list | high |
- Names are matched by pattern, not only SPDX ids: PyPI reports "GPL", "BSD", "GNU General Public
  License v2 (GPLv2)". `A OR B` → you choose, so only a problem if every option is (then the mildest);
  `A AND B` → the worst part. Several license entries on one package are alternatives.
- `.hagstone/licenses.json` `{"allow": [...], "deny": [...]}`, case-insensitive: allow beats the
  defaults, deny adds `license-denied`. `--license-policy <file>` reads another file; the Action passes
  the base branch's copy and warns when a PR changes it. Malformed file → warning, defaults apply.
- Packages without license data are counted in one warning, not reported. GitHub Actions found in
  workflows are skipped (they don't ship). Test and example lockfiles are hidden by default.
- Bench: `bench/cases/licenses/` (offline; expected.json), scored with the supply-chain cases.

## 3. Container images (Syft → Grype) — milestone after SBOM
- `hagstone scan --image <ref>` (registry or `docker:` / `oci-archive:` / tar): Syft catalogs the
  image, Grype matches that SBOM, findings are `category: "dependency"`, `engine: "grype"`, one per
  package version (same `vulnerable-dependency` rule id and grouping as osv-scanner), location = the
  image layer path of the package.
- Grype's vulnerability database is downloaded at run time from Anchore (Grype checks its checksum);
  it lives under the Hagstone cache directory. The image name and package list never leave the machine;
  the database download is the only network use (`--offline` uses the cached database).

## Done criteria (each milestone)
- `npm run check` and `npm run bench` pass; unit tests for the normalizer, the copy/sanitize step and
  the hardening filter.
- `hagstone scan` on a repo with no IaC: no new findings, no new warnings, small time cost.
- README, `--help`, `docs/github-action.md` and APPROACH coverage table updated.
