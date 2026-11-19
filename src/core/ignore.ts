import { readFile } from "node:fs/promises";
import { join } from "node:path";

/** Always skipped, regardless of .hagstoneignore / .vigilignore. */
export const DEFAULT_IGNORES = ["node_modules/", ".git/", "dist/", "build/", "vendor/", ".venv/", "venv/", "__pycache__/", ".hagstone/"];

/**
 * Load .hagstoneignore from the scan root, or from `file` when given (CI passes the base branch's copy,
 * so a pull request can't hide its own code by editing the ignore file). Each non-comment line is
 * either a path prefix ("bench/cases/") or a bare directory/file name ("fixtures") that matches at
 * any depth. A missing file means no patterns.
 */
export const IGNORE_FILE = ".hagstoneignore";
/** Read when .hagstoneignore is absent (the tool was called Vigil before 0.2.0). */
export const LEGACY_IGNORE_FILE = ".vigilignore";

export async function loadIgnorePatterns(root: string, file?: string): Promise<string[]> {
  let text = "";
  for (const candidate of file ? [file] : [join(root, IGNORE_FILE), join(root, LEGACY_IGNORE_FILE)]) {
    try {
      text = await readFile(candidate, "utf8");
      break;
    } catch {
      // No ignore file is fine.
    }
  }
  const own = text
    .split("\n")
    .map((l) => l.trim())
    .filter((l) => l && !l.startsWith("#"));
  return [...DEFAULT_IGNORES, ...own];
}

export function isIgnored(relPath: string, patterns: string[]): boolean {
  const path = relPath.replace(/\\/g, "/").replace(/^\.\//, "");
  const segments = path.split("/");
  return patterns.some((raw) => {
    const p = raw.replace(/^\.\//, "");
    if (p.includes("/") && !/^[^/]+\/$/.test(p)) return path.startsWith(p);
    const name = p.replace(/\/$/, "");
    return segments.includes(name);
  });
}
