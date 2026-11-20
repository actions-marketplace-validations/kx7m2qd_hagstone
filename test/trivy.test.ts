import { mkdir, mkdtemp, readFile, rm, symlink, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, describe, expect, it } from "vitest";
import { DEFAULT_IGNORES } from "../src/core/ignore.js";
import { hiddenByScope } from "../src/scan.js";
import {
  isIacCandidate,
  loadHardeningPolicy,
  normalizeTrivy,
  prepareIacCopy,
  REMOVED_MODULE,
  sanitizeIac,
  type TrivyMisconfig,
  type TrivyReport,
} from "../src/engines/trivy.js";

const misconfig = (over: Partial<TrivyMisconfig> = {}): TrivyMisconfig => ({
  ID: "AWS-0107",
  Title: "Security groups should not allow unrestricted ingress to SSH or RDP from any IP address.",
  Description: "Security groups provide stateful filtering",
  Message: "Security group rule allows unrestricted ingress from any IP address.",
  Resolution: "Set a more restrictive cidr range",
  Severity: "HIGH",
  PrimaryURL: "https://avd.aquasec.com/misconfig/aws-0107",
  Status: "FAIL",
  CauseMetadata: { Resource: "aws_security_group.web", StartLine: 10, EndLine: 10 },
  ...over,
});
const report = (...m: TrivyMisconfig[]): TrivyReport => ({ Results: [{ Target: "tf/main.tf", Misconfigurations: m }] });
const policy = { hardening: { "AWS-0132": "CMK vs AWS-managed key" } };

describe("trivy normalizer", () => {
  it("maps a failed check into an iac Finding with what / why / fix", () => {
    const { findings } = normalizeTrivy(report(misconfig()), policy);
    expect(findings).toHaveLength(1);
    const f = findings[0]!;
    expect(f).toMatchObject({
      category: "iac",
      engine: "trivy",
      ruleId: "AWS-0107",
      severity: "high",
      confidence: "high",
      location: { path: "tf/main.tf", startLine: 10, endLine: 10 },
      cwe: [],
      owasp: ["A05:2021 - Security Misconfiguration"],
    });
    expect(f.title).toContain("(aws_security_group.web)");
    expect(f.message).toMatch(/unrestricted ingress.*stateful filtering.*Fix: Set a more restrictive cidr range\..*aws-0107/);
    expect(f.location.snippet).toBeUndefined();
  });

  it("ignores passed checks", () => {
    expect(normalizeTrivy(report(misconfig({ Status: "PASS" })), policy).findings).toEqual([]);
  });

  it("hides LOW and listed hardening checks by default, and counts them", () => {
    const r = report(misconfig({ ID: "AWS-0089", Severity: "LOW" }), misconfig({ ID: "AWS-0132" }), misconfig());
    const quiet = normalizeTrivy(r, policy);
    expect(quiet.findings.map((f) => f.ruleId)).toEqual(["AWS-0107"]);
    expect(quiet.hiddenHardening).toBe(2);
    const all = normalizeTrivy(r, policy, { includeHardening: true });
    expect(all.findings.map((f) => f.ruleId)).toEqual(["AWS-0089", "AWS-0132", "AWS-0107"]);
    expect(all.hiddenHardening).toBe(0);
  });

  it("fingerprints on check + path + resource + message, not the line", () => {
    const a = normalizeTrivy(report(misconfig()), policy).findings[0]!;
    const moved = normalizeTrivy(report(misconfig({ CauseMetadata: { Resource: "aws_security_group.web", StartLine: 40 } })), policy).findings[0]!;
    const other = normalizeTrivy(report(misconfig({ CauseMetadata: { Resource: "aws_security_group.db", StartLine: 10 } })), policy).findings[0]!;
    expect(moved.id).toBe(a.id);
    expect(other.id).not.toBe(a.id);
  });

  it("keeps two Kubernetes workloads in one file apart (no resource; the message names them)", () => {
    const k = (name: string) =>
      misconfig({ ID: "KSV-0017", Message: `Container 'c' of Deployment '${name}' should set 'securityContext.privileged' to false`, CauseMetadata: { StartLine: 7 } });
    const { findings } = normalizeTrivy({ Results: [{ Target: "k8s/all.yaml", Misconfigurations: [k("a"), k("b")] }] }, policy);
    expect(new Set(findings.map((f) => f.id)).size).toBe(2);
  });

  it("defaults the line to 1 when Trivy gives none, and tolerates null results", () => {
    const { findings } = normalizeTrivy(report(misconfig({ ID: "DS-0002", CauseMetadata: undefined })), policy);
    expect(findings[0]!.location).toEqual({ path: "tf/main.tf", startLine: 1, endLine: 1 });
    expect(normalizeTrivy({ Results: null }, policy).findings).toEqual([]);
    expect(normalizeTrivy({ Results: [{ Target: "x", Misconfigurations: null }] }, policy).findings).toEqual([]);
  });

  it("ships a hardening list where every entry says why", async () => {
    const p = await loadHardeningPolicy();
    expect(Object.keys(p.hardening).length).toBeGreaterThan(0);
    for (const [id, why] of Object.entries(p.hardening)) {
      expect(id).toMatch(/^[A-Z]+-\d{4}$/);
      expect(why.length).toBeGreaterThan(10);
    }
  });

  it("hides IaC in test and example paths by default", () => {
    const f = { ...normalizeTrivy(report(misconfig()), policy).findings[0]!, scope: "example" as const };
    expect(hiddenByScope(f)).toBe(true);
  });
});

describe("sanitizeIac (the scanned repo is untrusted)", () => {
  it("disables inline trivy / tfsec ignore markers without moving lines", () => {
    const src = '#trivy:ignore:AVD-AWS-0107\nresource "a" "b" {}\n# tfsec:ignore:aws-vpc-no-public-ingress-sgr\n// TRIVY : IGNORE:*\n';
    const out = sanitizeIac(src, "main.tf");
    expect(out).not.toMatch(/(trivy|tfsec)\s*:\s*ignore/i);
    expect(out.split("\n")).toHaveLength(src.split("\n").length);
    // Kubernetes / Dockerfile comments too.
    expect(sanitizeIac("# trivy:ignore:KSV-0017\nkind: Pod\n", "pod.yaml")).not.toMatch(/trivy:ignore/);
  });

  it("points remote module sources at a path that doesn't exist, keeps local ones", () => {
    const src = [
      'module "vpc" {',
      '  source  = "terraform-aws-modules/vpc/aws"',
      '  version = "5.0.0"',
      "}",
      'module "git" {',
      '  source = "git::https://example.com/m.git?ref=v1" # pinned',
      "  tags = { a = \"}\" }",
      "}",
      'module "local" {',
      '  source = "./modules/net"',
      "}",
      'module "escape" {',
      '  source = "../../../../etc"',
      "}",
      'module "abs" { source = "/opt/modules/x" }',
      'resource "aws_s3_object" "o" {',
      '  source = "https://not-a-module.example.com/file"',
      "}",
    ].join("\n");
    const out = sanitizeIac(src, "infra/main.tf");
    const lines = out.split("\n");
    expect(lines).toHaveLength(src.split("\n").length);
    expect(lines[1]).toContain(REMOVED_MODULE);
    expect(lines[5]).toContain(REMOVED_MODULE);
    expect(lines[9]).toContain('"./modules/net"');
    expect(lines[12]).toContain(REMOVED_MODULE);
    expect(lines[14]).toContain(REMOVED_MODULE);
    // `source` outside a module block is resource data, not something Trivy fetches.
    expect(lines[16]).toContain("https://not-a-module.example.com/file");
  });

  it("rewrites remote sources in JSON Terraform", () => {
    const src = '{"module": {"vpc": {"source": "terraform-aws-modules/vpc/aws"}, "l": {"source": "./x"}}}';
    const out = sanitizeIac(src, "main.tf.json");
    expect(out).toContain(REMOVED_MODULE);
    expect(out).toContain('"./x"');
    expect(JSON.parse(out)).toBeTruthy();
  });

  it("leaves files without markers or modules byte-identical", () => {
    const src = 'resource "aws_s3_bucket" "b" {\n  bucket = "x"\n}\n';
    expect(sanitizeIac(src, "main.tf")).toBe(src);
  });
});

describe("prepareIacCopy", () => {
  let dir: string | undefined;
  afterEach(async () => {
    if (dir) await rm(dir, { recursive: true, force: true });
  });

  it("copies IaC files only, sanitized, skipping symlinks, ignores and downloaded modules", async () => {
    dir = await mkdtemp(join(tmpdir(), "hagstone-iac-test-"));
    const root = join(dir, "repo");
    const dest = join(dir, "copy");
    await mkdir(join(root, "infra/.terraform/modules/x"), { recursive: true });
    await mkdir(join(root, "node_modules/pkg"), { recursive: true });
    await mkdir(join(root, "k8s"), { recursive: true });
    await mkdir(dest);
    await writeFile(join(root, "infra/main.tf"), '#trivy:ignore:AVD-AWS-0107\nresource "a" "b" {}\n');
    await writeFile(join(root, "infra/.terraform/modules/x/main.tf"), "x");
    await writeFile(join(root, "node_modules/pkg/deploy.yaml"), "kind: Pod");
    await writeFile(join(root, "k8s/pod.yaml"), "kind: Pod");
    await writeFile(join(root, "Dockerfile"), "FROM scratch");
    await writeFile(join(root, "package.json"), "{}");
    await writeFile(join(root, "app.js"), "x");
    await writeFile(join(dir, "outside.tf"), "secret");
    await symlink(join(dir, "outside.tf"), join(root, "link.tf"));

    expect(await prepareIacCopy(root, dest, DEFAULT_IGNORES)).toBe(3);
    expect(await readFile(join(dest, "infra/main.tf"), "utf8")).not.toMatch(/trivy:ignore/);
    expect(await readFile(join(dest, "k8s/pod.yaml"), "utf8")).toBe("kind: Pod");
    await expect(readFile(join(dest, "link.tf"))).rejects.toThrow();
    await expect(readFile(join(dest, "infra/.terraform/modules/x/main.tf"))).rejects.toThrow();
    await expect(readFile(join(dest, "package.json"))).rejects.toThrow();
  });

  it("recognises IaC file names", () => {
    for (const n of ["main.tf", "x.tf.json", "prod.tfvars", "Dockerfile", "Dockerfile.prod", "api.dockerfile", "Containerfile", "pod.yaml", "chart.yml", "template.json", "_helpers.tpl"])
      expect(isIacCandidate(n), n).toBe(true);
    for (const n of ["package.json", "package-lock.json", "tsconfig.base.json", "pnpm-lock.yaml", "app.js", "README.md"])
      expect(isIacCandidate(n), n).toBe(false);
  });
});
