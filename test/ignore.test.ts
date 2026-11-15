import { mkdtemp, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { describe, expect, it } from "vitest";
import { DEFAULT_IGNORES, isIgnored, loadIgnorePatterns } from "../src/core/ignore.js";

describe("isIgnored", () => {
  const patterns = [...DEFAULT_IGNORES, "bench/cases/", "fixtures", "src/generated/api.ts"];

  it("matches bare directory names at any depth", () => {
    expect(isIgnored("node_modules/x/index.js", patterns)).toBe(true);
    expect(isIgnored("packages/web/node_modules/x/index.js", patterns)).toBe(true);
    expect(isIgnored("test/fixtures/vuln.js", patterns)).toBe(true);
  });

  it("matches multi-segment patterns only as a root prefix", () => {
    expect(isIgnored("bench/cases/app.js", patterns)).toBe(true);
    expect(isIgnored("other/bench/cases/app.js", patterns)).toBe(false);
    expect(isIgnored("src/generated/api.ts", patterns)).toBe(true);
  });

  it("does not match partial names", () => {
    expect(isIgnored("src/distance.js", patterns)).toBe(false);
    expect(isIgnored("src/builder/index.js", patterns)).toBe(false);
  });

  it("normalizes ./ and backslashes", () => {
    expect(isIgnored("./dist/cli.js", patterns)).toBe(true);
    expect(isIgnored("bench\\cases\\app.js", patterns)).toBe(true);
  });
});

describe("loadIgnorePatterns", () => {
  it("reads .hagstoneignore, skipping comments and blanks", async () => {
    const dir = await mkdtemp(join(tmpdir(), "hagstone-ignore-"));
    await writeFile(join(dir, ".hagstoneignore"), "# comment\n\nrules/\n  fixtures  \n");
    const patterns = await loadIgnorePatterns(dir);
    expect(patterns).toEqual([...DEFAULT_IGNORES, "rules/", "fixtures"]);
  });

  it("falls back to defaults without a file", async () => {
    const dir = await mkdtemp(join(tmpdir(), "hagstone-ignore-"));
    expect(await loadIgnorePatterns(dir)).toEqual(DEFAULT_IGNORES);
  });

  it("the repo's own .hagstoneignore excludes the intentionally vulnerable folders", async () => {
    const patterns = await loadIgnorePatterns(process.cwd());
    for (const p of ["rules/x.js", "bench/cases/x.js", "test/fixtures/x.js"]) {
      expect(isIgnored(p, patterns)).toBe(true);
    }
  });
});

describe("legacy ignore file", () => {
  it("reads .vigilignore only when .hagstoneignore is absent", async () => {
    const dir = await mkdtemp(join(tmpdir(), "hagstone-ignore-"));
    await writeFile(join(dir, ".vigilignore"), "old/\n");
    expect(await loadIgnorePatterns(dir)).toContain("old/");
    await writeFile(join(dir, ".hagstoneignore"), "new/\n");
    const both = await loadIgnorePatterns(dir);
    expect(both).toContain("new/");
    expect(both).not.toContain("old/");
  });
});
