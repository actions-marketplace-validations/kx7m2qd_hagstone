import { readFile } from "node:fs/promises";
import { describe, expect, it } from "vitest";
import { compareDistroVersions, grypeConfig, normalizeGrype, type GrypeMatch, type GrypeOutput } from "../src/engines/grype.js";

const fixture = async () => JSON.parse(await readFile(new URL("./fixtures/grype-alpine-3.18.0.json", import.meta.url), "utf8")) as GrypeOutput;

const match = (over: { id?: string; severity?: string; fix?: GrypeMatch["vulnerability"]["fix"]; name?: string; version?: string; purl?: string; type?: string; cvss?: number }): GrypeMatch => ({
  vulnerability: {
    id: over.id ?? "CVE-2024-0001",
    severity: over.severity ?? "High",
    fix: over.fix ?? { versions: ["1.0.1-r0"], state: "fixed" },
    ...(over.cvss !== undefined ? { cvss: [{ metrics: { baseScore: over.cvss } }] } : {}),
  },
  artifact: {
    name: over.name ?? "zlib",
    version: over.version ?? "1.0.0-r0",
    type: over.type ?? "apk",
    purl: over.purl ?? `pkg:apk/alpine/${over.name ?? "zlib"}@${over.version ?? "1.0.0-r0"}`,
    locations: [{ path: "/lib/apk/db/installed" }],
  },
});

describe("grype normalizer (real alpine:3.18.0 output)", () => {
  it("groups 63 matches into one finding per source package", async () => {
    const { findings, negligible } = normalizeGrype(await fixture());
    expect(negligible).toBe(0);
    expect(findings.map((f) => `${f.dependency?.name} ${f.dependency?.version} ${f.severity}`).sort()).toEqual([
      "busybox 1.36.0-r9 critical",
      "musl 1.2.4-r0 high",
      "openssl 3.1.0-r4 critical",
      "zlib 1.2.13-r1 medium",
    ]);
    const openssl = findings.find((f) => f.dependency?.name === "openssl")!;
    expect(openssl).toMatchObject({
      category: "dependency",
      engine: "grype",
      ruleId: "vulnerable-dependency",
      location: { path: "lib/apk/db/installed", startLine: 1 },
      owasp: ["A06:2021 - Vulnerable and Outdated Components"],
      dependency: { ecosystem: "Alpine", fixedVersions: ["3.1.8-r0"] },
    });
    expect(openssl.dependency!.advisories).toContain("CVE-2024-6119");
    expect(openssl.message).toMatch(/^openssl \(libcrypto3, libssl3\) 3\.1\.0-r4 \(alpine 3\.18\.0\) is affected by 16 advisories/);
    expect(openssl.message).toContain("Upgrade openssl to 3.1.8-r0 or later");
  });
});

describe("grype normalizer", () => {
  it("one advisory shared by two binary packages counts once", () => {
    const up = "pkg:apk/alpine/libssl3@3.1.0-r4?upstream=openssl";
    const { findings } = normalizeGrype({
      matches: [match({ name: "libssl3", version: "3.1.0-r4", purl: up }), match({ name: "libcrypto3", version: "3.1.0-r4", purl: up.replace("libssl3", "libcrypto3") })],
    });
    expect(findings).toHaveLength(1);
    expect(findings[0]!.title).toBe("openssl 3.1.0-r4: CVE-2024-0001");
  });

  it("drops negligible advisories and counts them", () => {
    const { findings, negligible } = normalizeGrype({ matches: [match({ severity: "Negligible" }), match({ id: "CVE-2", severity: "Low" })] });
    expect(negligible).toBe(1);
    expect(findings[0]!.dependency!.advisories).toEqual(["CVE-2"]);
  });

  it("falls back to CVSS, then medium, when grype has no severity label", () => {
    expect(normalizeGrype({ matches: [match({ severity: "Unknown", cvss: 9.8 })] }).findings[0]!.severity).toBe("critical");
    expect(normalizeGrype({ matches: [match({ severity: "Unknown" })] }).findings[0]!.severity).toBe("medium");
  });

  it("says when there is no fix and when the distro won't fix it", () => {
    const f = normalizeGrype({ matches: [match({ fix: { versions: [], state: "wont-fix" } })] }).findings[0]!;
    expect(f.dependency!.fixedVersions).toEqual([]);
    expect(f.message).toMatch(/No fixed version published yet \(1 marked won't-fix/);
  });

  it("fingerprints without the image name or path, so decisions carry across image tags", () => {
    const a = normalizeGrype({ matches: [match({})] }).findings[0]!;
    const b = normalizeGrype({ matches: [{ ...match({}), artifact: { ...match({}).artifact, locations: [{ path: "/other" }] } }] }).findings[0]!;
    const c = normalizeGrype({ matches: [match({ version: "1.0.0-r1" })] }).findings[0]!;
    expect(b.id).toBe(a.id);
    expect(c.id).not.toBe(a.id);
  });

  it("language packages in an image use the ecosystem names", () => {
    const f = normalizeGrype({ matches: [match({ type: "npm", name: "lodash", version: "4.17.20", purl: "pkg:npm/lodash@4.17.20", fix: { versions: ["4.17.21"], state: "fixed" } })] }).findings[0]!;
    expect(f.dependency).toMatchObject({ ecosystem: "npm", name: "lodash", fixedVersions: ["4.17.21"] });
  });
});

describe("compareDistroVersions", () => {
  it.each([
    ["3.1.7-r0", "3.1.0-r4", 1],
    ["1.2.13-r1", "1.2.13-r0", 1],
    ["1.2.13", "1.2.13-r0", -1],
    ["2:1.0", "1:9.9", 1],
    ["1.36.1-r2", "1.36.1-r10", -1],
    ["1.1.1w-r1", "1.1.1t-r0", 1],
    ["5.2.15-2+deb12u1", "5.2.15-2", 1],
    ["1.0.0", "1.0.0", 0],
  ])("%s vs %s", (a, b, sign) => expect(Math.sign(compareDistroVersions(a, b))).toBe(sign));
});

describe("grype config", () => {
  it("no update check, no external sources, our database dir; offline neither updates nor rejects an old database", () => {
    const online = grypeConfig({ offline: false, dbDir: "/c/grype-db" });
    expect(online).toContain("check-for-app-update: false");
    expect(online).toMatch(/external-sources:\n  enable: false/);
    expect(online).toContain('cache-dir: "/c/grype-db"');
    expect(online).toContain("auto-update: true");
    expect(online).toContain("validate-by-hash-on-start: true");
    const offline = grypeConfig({ offline: true, dbDir: "/c" });
    expect(offline).toContain("auto-update: false");
    expect(offline).toContain("validate-age: false");
  });
});
