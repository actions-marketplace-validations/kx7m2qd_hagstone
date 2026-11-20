import { mkdtemp, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, describe, expect, it } from "vitest";
import {
  classifyLicense,
  EMPTY_POLICY,
  judgeLicenses,
  loadLicensePolicy,
  normalizeSyftLicenses,
  syftConfig,
  syftExcludes,
  type SyftPackage,
} from "../src/engines/syft.js";
import { hiddenByScope } from "../src/scan.js";

describe("classifyLicense", () => {
  it.each([
    ["AGPL-3.0-only", "network-copyleft"],
    ["AGPL-3.0-or-later", "network-copyleft"],
    ["GNU Affero General Public License v3", "network-copyleft"],
    ["SSPL-1.0", "network-copyleft"],
    ["GPL-3.0", "copyleft"],
    ["GPL-2.0-or-later", "copyleft"],
    ["GNU General Public License v2 (GPLv2)", "copyleft"],
    ["GPL", "copyleft"],
    ["BUSL-1.1", "non-commercial"],
    ["CC-BY-NC-4.0", "non-commercial"],
    ["CC-BY-NC-SA-4.0", "non-commercial"],
    ["Elastic-2.0", "non-commercial"],
  ])("%s → %s", (license, cls) => expect(classifyLicense(license)).toBe(cls));

  it.each(["MIT", "Apache-2.0", "BSD-3-Clause", "ISC", "MPL-2.0", "LGPL-3.0", "LGPL-2.1-or-later", "GNU Lesser General Public License v3 (LGPLv3)", "BSD", "BSD-like", "CC-BY-4.0", "Unlicense", "UNLICENSED"])(
    "%s is allowed",
    (license) => expect(classifyLicense(license)).toBeUndefined(),
  );

  it("treats linking exceptions as allowed, other exceptions as the base license", () => {
    expect(classifyLicense("GPL-2.0-only WITH Classpath-exception-2.0")).toBeUndefined();
    expect(classifyLicense("GPL-3.0-or-later WITH GCC-exception-3.1")).toBeUndefined();
    expect(classifyLicense("GPL-2.0-only WITH Some-other-exception")).toBe("copyleft");
  });
});

describe("judgeLicenses", () => {
  it("OR: fine if any option is fine; otherwise the mildest option", () => {
    expect(judgeLicenses(["(MIT OR GPL-3.0)"], EMPTY_POLICY)).toBeUndefined();
    expect(judgeLicenses(["(GPL-3.0 OR AGPL-3.0)"], EMPTY_POLICY)).toBe("copyleft");
  });

  it("AND: every part applies", () => {
    expect(judgeLicenses(["(Apache-2.0 AND GPL-2.0-only)"], EMPTY_POLICY)).toBe("copyleft");
    expect(judgeLicenses(["MIT AND (BSD-3-Clause OR AGPL-3.0)"], EMPTY_POLICY)).toBe("network-copyleft");
  });

  it("several license entries are alternatives", () => {
    expect(judgeLicenses(["GPL-3.0", "MIT"], EMPTY_POLICY)).toBeUndefined();
    expect(judgeLicenses(["GPL-3.0", "AGPL-3.0"], EMPTY_POLICY)).toBe("copyleft");
  });

  it("policy: allow wins over the defaults, deny reports anything", () => {
    expect(judgeLicenses(["GPL-3.0-only"], { allow: ["gpl-3.0-only"], deny: [] })).toBeUndefined();
    expect(judgeLicenses(["GPL-2.0-only WITH Foo-exception"], { allow: ["GPL-2.0-only"], deny: [] })).toBeUndefined();
    expect(judgeLicenses(["MPL-2.0"], { allow: [], deny: ["MPL-2.0"] })).toBe("denied");
  });
});

describe("normalizeSyftLicenses", () => {
  const pkg = (over: Partial<SyftPackage>): SyftPackage => ({
    name: "pdf-stamp",
    version: "2.1.0",
    type: "npm",
    licenses: [{ value: "AGPL-3.0-only", spdxExpression: "AGPL-3.0-only" }],
    locations: [{ path: "/app/package-lock.json" }],
    ...over,
  });

  it("one finding per package with a problem license; counts packages with none", () => {
    const { findings, unknown } = normalizeSyftLicenses(
      {
        artifacts: [
          pkg({}),
          pkg({ name: "express", licenses: [{ value: "MIT", spdxExpression: "MIT" }] }),
          pkg({ name: "nolicense", licenses: [] }),
          pkg({ name: "actions/checkout", type: "github-action", licenses: [] }),
          pkg({ name: "agpl-action", type: "github-action" }),
        ],
      },
      EMPTY_POLICY,
    );
    expect(unknown).toBe(1);
    expect(findings).toHaveLength(1);
    expect(findings[0]).toMatchObject({
      category: "license",
      engine: "syft",
      ruleId: "license-network-copyleft",
      severity: "high",
      location: { path: "app/package-lock.json", startLine: 1 },
      dependency: { name: "pdf-stamp", version: "2.1.0", ecosystem: "npm", advisories: [], fixedVersions: [] },
    });
    expect(findings[0]!.message).toMatch(/AGPL-3\.0-only.*publish your own source.*hagstone suppress/s);
  });

  it("maps syft package types to ecosystem names and uses value when there's no SPDX expression", () => {
    const { findings } = normalizeSyftLicenses({ artifacts: [pkg({ type: "python", licenses: [{ value: "GPL" }] })] }, EMPTY_POLICY);
    expect(findings[0]!.dependency?.ecosystem).toBe("PyPI");
    expect(findings[0]!.ruleId).toBe("license-copyleft");
  });

  it("fingerprints on package + license, so a relicense is a new finding", () => {
    const a = normalizeSyftLicenses({ artifacts: [pkg({})] }, EMPTY_POLICY).findings[0]!;
    const moved = normalizeSyftLicenses({ artifacts: [pkg({ locations: [{ path: "/other/package-lock.json" }] })] }, EMPTY_POLICY).findings[0]!;
    const relicensed = normalizeSyftLicenses({ artifacts: [pkg({ licenses: [{ value: "SSPL-1.0" }] })] }, EMPTY_POLICY).findings[0]!;
    expect(moved.id).toBe(a.id);
    expect(relicensed.id).not.toBe(a.id);
  });

  it("license findings in test and example lockfiles are hidden by default", () => {
    const f = { ...normalizeSyftLicenses({ artifacts: [pkg({})] }, EMPTY_POLICY).findings[0]!, scope: "test" as const };
    expect(hiddenByScope(f)).toBe(true);
  });
});

describe("syft config (the scanned repo is untrusted)", () => {
  it("turns off update checks, project tooling, clones and network lookups except PyPI licenses", () => {
    const online = syftConfig({ offline: false, cacheDir: "/c" });
    for (const line of ["check-for-app-update: false", "vcpkg-allow-git-clone: false", "use-packages-lib: false", "use-network: false", "include-dev-dependencies: false"])
      expect(online).toContain(line);
    expect(online).toMatch(/golang:\n(?:  .*\n)*  search-remote-licenses: false/);
    expect(online).toMatch(/python:\n  search-remote-licenses: true/);
    expect(syftConfig({ offline: true, cacheDir: "/c" })).toMatch(/python:\n  search-remote-licenses: false/);
  });

  it("turns ignore patterns into syft globs", () => {
    expect(syftExcludes(["node_modules/", "bench/cases/", "fixtures", "src/gen.js"])).toEqual([
      "**/node_modules/**",
      "**/node_modules",
      "./bench/cases/**",
      "**/fixtures/**",
      "**/fixtures",
      "./src/gen.js",
    ]);
  });
});

describe("loadLicensePolicy", () => {
  let dir: string | undefined;
  afterEach(async () => {
    if (dir) await rm(dir, { recursive: true, force: true });
  });

  it("missing or empty → defaults; malformed → defaults plus an error; valid → lists", async () => {
    dir = await mkdtemp(join(tmpdir(), "hagstone-lic-"));
    expect(await loadLicensePolicy(join(dir, "none.json"))).toEqual({ policy: EMPTY_POLICY });
    await writeFile(join(dir, "empty.json"), "");
    expect(await loadLicensePolicy(join(dir, "empty.json"))).toEqual({ policy: EMPTY_POLICY });
    await writeFile(join(dir, "bad.json"), "{");
    const bad = await loadLicensePolicy(join(dir, "bad.json"));
    expect(bad.policy).toEqual(EMPTY_POLICY);
    expect(bad.error).toBeTruthy();
    await writeFile(join(dir, "ok.json"), JSON.stringify({ allow: ["GPL-3.0-only", 7], deny: ["MPL-2.0"] }));
    expect((await loadLicensePolicy(join(dir, "ok.json"))).policy).toEqual({ allow: ["GPL-3.0-only"], deny: ["MPL-2.0"] });
  });
});
