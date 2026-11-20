/**
 * Verify every pinned engine against its upstream signature or provenance (src/engines/manifest.ts
 * `provenance`). Needs `cosign` (v2+) and, for SLSA, `slsa-verifier` on PATH. Run in CI by
 * .github/workflows/engine-signatures.yml whenever the manifest changes: `npm run verify:engines`.
 *
 * For each engine and platform: download the pinned artifact, check its SHA-256 against the manifest,
 * then check the signature, requiring the signing certificate to come from the release workflow at the
 * release tag's commit. Exit 1 if anything doesn't verify. Unsigned engines are a warning.
 */
import { spawnSync } from "node:child_process";
import { createHash } from "node:crypto";
import { mkdtemp, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { basename, join } from "node:path";
import { ENGINES, type BinaryEngine, type Provenance } from "../src/engines/manifest.js";

const ISSUER = "https://token.actions.githubusercontent.com";
const inCi = process.env.GITHUB_ACTIONS === "true";

let failures = 0;
const fail = (engine: string, msg: string): void => {
  failures++;
  process.stdout.write(inCi ? `::error title=${engine}::${msg}\n` : `✗ ${engine}: ${msg}\n`);
};
const warn = (engine: string, msg: string): void => {
  process.stdout.write(inCi ? `::warning title=${engine}::${msg}\n` : `! ${engine}: ${msg}\n`);
};
const ok = (engine: string, msg: string): void => {
  process.stdout.write(`✓ ${engine}: ${msg}\n`);
};

async function fetchTo(url: string, dir: string, name = basename(new URL(url).pathname)): Promise<{ path: string; bytes: Buffer }> {
  const res = await fetch(url, { signal: AbortSignal.timeout(10 * 60_000) });
  if (!res.ok) throw new Error(`HTTP ${res.status} for ${url}`);
  const bytes = Buffer.from(await res.arrayBuffer());
  const path = join(dir, name);
  await writeFile(path, bytes);
  return { path, bytes };
}

const sha256 = (b: Buffer) => createHash("sha256").update(b).digest("hex");

function tool(cmd: string, args: string[]): { ok: boolean; out: string } {
  const r = spawnSync(cmd, args, { encoding: "utf8" });
  if (r.error) return { ok: false, out: `${cmd}: ${r.error.message}` };
  return { ok: r.status === 0, out: `${r.stdout}${r.stderr}`.trim().split("\n").slice(-3).join(" | ") };
}

const certFlags = (identity: string, commit: string) => [
  `--certificate-identity=${identity}`,
  `--certificate-oidc-issuer=${ISSUER}`,
  `--certificate-github-workflow-sha=${commit}`,
];

async function verifyEngine(name: BinaryEngine, dir: string): Promise<void> {
  const spec = ENGINES[name];
  const before = failures;
  const done = (msg: string): void => {
    if (failures === before) ok(name, msg);
  };
  const p: Provenance = spec.provenance;
  const artifacts = Object.entries(spec.artifacts);
  const files: { platform: string; url: string; path: string; sha: string }[] = [];
  for (const [platform, a] of artifacts) {
    if (!a) continue;
    const { path, bytes } = await fetchTo(a.url, dir, `${name}-${platform}-${basename(new URL(a.url).pathname)}`);
    const sha = sha256(bytes);
    if (sha !== a.sha256) fail(name, `${platform}: downloaded ${sha}, manifest pins ${a.sha256}`);
    files.push({ platform, url: a.url, path, sha });
  }

  const listedIn = (checksums: string) => {
    for (const f of files) {
      const file = basename(new URL(f.url).pathname);
      const line = checksums.split("\n").find((l) => l.trim().endsWith(` ${file}`) || l.trim().endsWith(`*${file}`));
      if (!line?.startsWith(f.sha)) fail(name, `${f.platform}: ${file} is not listed with the pinned hash in the checksums file`);
    }
  };

  switch (p.kind) {
    case "sigstore-checksums": {
      const sums = await fetchTo(p.checksums, dir, `${name}-checksums.txt`);
      const bundle = await fetchTo(p.bundle, dir, `${name}-checksums.sigstore.json`);
      const r = tool("cosign", ["verify-blob", `--bundle=${bundle.path}`, ...certFlags(p.identity, p.commit), sums.path]);
      if (!r.ok) return fail(name, `checksums signature did not verify: ${r.out}`);
      listedIn(sums.bytes.toString("utf8"));
      return done(`checksums file signed by ${p.identity} at ${p.commit.slice(0, 7)}; pinned hashes listed`);
    }
    case "sigstore-blob": {
      for (const f of files) {
        const sig = await fetchTo(`${f.url}.sig`, dir, `${basename(f.path)}.sig`);
        const cert = await fetchTo(`${f.url}.cert`, dir, `${basename(f.path)}.cert`);
        const r = tool("cosign", ["verify-blob", `--signature=${sig.path}`, `--certificate=${cert.path}`, ...certFlags(p.identity, p.commit), f.path]);
        if (!r.ok) fail(name, `${f.platform}: signature did not verify: ${r.out}`);
      }
      return done(`each artifact signed by ${p.identity} at ${p.commit.slice(0, 7)}`);
    }
    case "slsa": {
      const prov = await fetchTo(p.provenance, dir, `${name}.intoto.jsonl`);
      for (const f of files) {
        const r = tool("slsa-verifier", ["verify-artifact", f.path, `--provenance-path=${prov.path}`, `--source-uri=${p.source}`, `--source-tag=${p.tag}`]);
        if (!r.ok) fail(name, `${f.platform}: SLSA provenance did not verify: ${r.out}`);
      }
      return done(`SLSA provenance from ${p.source}@${p.tag}`);
    }
    case "unsigned": {
      const sums = await fetchTo(p.checksums, dir, `${name}-checksums.txt`);
      listedIn(sums.bytes.toString("utf8"));
      return warn(name, "upstream publishes no signature; pinned hashes match its (unsigned) checksums file");
    }
  }
}

async function main(): Promise<number> {
  const dir = await mkdtemp(join(tmpdir(), "hagstone-verify-"));
  try {
    for (const name of Object.keys(ENGINES) as BinaryEngine[]) {
      try {
        await verifyEngine(name, dir);
      } catch (e) {
        fail(name, e instanceof Error ? e.message : String(e));
      }
    }
  } finally {
    await rm(dir, { recursive: true, force: true });
  }
  process.stdout.write(failures ? `\n${failures} problem(s)\n` : "\nall engines verified\n");
  return failures ? 1 : 0;
}

main().then((code) => process.exit(code));
