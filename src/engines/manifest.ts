import type { EngineName } from "../core/finding.js";

/** Engines that run as a downloaded binary. `pkgrisk` is built in (no binary to resolve). */
export type BinaryEngine = Exclude<EngineName, "pkgrisk">;

export type Platform = "darwin-arm64" | "linux-x64";

export interface Artifact {
  url: string;
  sha256: string;
  /**
   * Present when the download is an archive; `member` is the file to extract and
   * `sha256` is the hash of that extracted binary (re-checked before every run).
   */
  archive?: { type: "tar.gz"; member: string; sha256: string };
}

/**
 * How the upstream release proves where its files came from. Checked by `npm run verify:engines`
 * (scripts/verify-signatures.ts, CI workflow engine-signatures.yml) whenever this file changes, not at
 * run time: the pinned SHA-256 is what every run enforces. `commit` is the release tag's commit; the
 * signing certificate must name it, so a signature made from any other source is rejected.
 */
export type Provenance =
  /** A checksums file signed with a Sigstore bundle; every artifact's hash must be listed in it. */
  | { kind: "sigstore-checksums"; checksums: string; bundle: string; identity: string; commit: string }
  /** Each artifact signed on its own: `<url>.sig` + `<url>.cert` (cosign sign-blob). */
  | { kind: "sigstore-blob"; identity: string; commit: string }
  /** SLSA provenance from slsa-github-generator, checked with slsa-verifier. */
  | { kind: "slsa"; provenance: string; source: string; tag: string }
  /** Nothing signed upstream: only the (unsigned) published checksums are compared. */
  | { kind: "unsigned"; checksums: string };

export interface EngineSpec {
  version: string;
  binary: string;
  artifacts: Partial<Record<Platform, Artifact>>;
  provenance: Provenance;
}

/**
 * Pinned engine binaries. Bumping a version means: download, verify against the
 * upstream checksum/signature, then update both the version and the sha256 here.
 *
 * osv-scanner and gitleaks hashes match their published checksum files.
 * Signatures and provenance (`provenance` below) are verified by `npm run verify:engines` in CI
 * (.github/workflows/engine-signatures.yml) on every change to this file. Gitleaks publishes no
 * signature, only a checksums file.
 *
 * Trivy's release pipeline was compromised in March 2026 (CVE-2026-33634, malicious v0.69.4):
 * never bump trivy without checking the release against its advisories.
 */
export const ENGINES: Record<BinaryEngine, EngineSpec> = {
  opengrep: {
    version: "1.30.1",
    binary: "opengrep",
    provenance: {
      kind: "sigstore-blob",
      identity: "https://github.com/opengrep/opengrep/.github/workflows/rolling-release.yml@refs/heads/release-v1.30.1",
      commit: "525e67142af506e2f3ea1728d18c5824813f0248",
    },
    artifacts: {
      "darwin-arm64": {
        url: "https://github.com/opengrep/opengrep/releases/download/v1.30.1/opengrep_osx_arm64",
        sha256: "7b788794e111ce3fb83f0aa52c100a3b85d37d8b59482262109031f50d4a8d91",
      },
      "linux-x64": {
        url: "https://github.com/opengrep/opengrep/releases/download/v1.30.1/opengrep_manylinux_x86",
        sha256: "d3195b9d8d5ae93179f6aa5f5daaba6a920a5a09d38c5d5ae5e60924050210c4",
      },
    },
  },
  "osv-scanner": {
    version: "2.6.0",
    binary: "osv-scanner",
    provenance: {
      kind: "slsa",
      provenance: "https://github.com/google/osv-scanner/releases/download/v2.6.0/multiple.intoto.jsonl",
      source: "github.com/google/osv-scanner",
      tag: "v2.6.0",
    },
    artifacts: {
      "darwin-arm64": {
        url: "https://github.com/google/osv-scanner/releases/download/v2.6.0/osv-scanner_darwin_arm64",
        sha256: "98c460dcd37de25819babd757d04542045b6243113e209edcd4d89fedb0256b4",
      },
      "linux-x64": {
        url: "https://github.com/google/osv-scanner/releases/download/v2.6.0/osv-scanner_linux_amd64",
        sha256: "ca69b3d3cd08f889a49dc0a383122f71cc528b83803671df5fd874d97485b108",
      },
    },
  },
  gitleaks: {
    version: "8.30.1",
    binary: "gitleaks",
    provenance: { kind: "unsigned", checksums: "https://github.com/gitleaks/gitleaks/releases/download/v8.30.1/gitleaks_8.30.1_checksums.txt" },
    artifacts: {
      "darwin-arm64": {
        url: "https://github.com/gitleaks/gitleaks/releases/download/v8.30.1/gitleaks_8.30.1_darwin_arm64.tar.gz",
        sha256: "b40ab0ae55c505963e365f271a8d3846efbc170aa17f2607f13df610a9aeb6a5",
        archive: {
          type: "tar.gz",
          member: "gitleaks",
          sha256: "ba52fb1bfabbcde42f032afad3d6e0b19dff8ed105229a16e7caa338bbc0e84f",
        },
      },
      "linux-x64": {
        url: "https://github.com/gitleaks/gitleaks/releases/download/v8.30.1/gitleaks_8.30.1_linux_x64.tar.gz",
        sha256: "551f6fc83ea457d62a0d98237cbad105af8d557003051f41f3e7ca7b3f2470eb",
        archive: {
          type: "tar.gz",
          member: "gitleaks",
          sha256: "88f91962aa2f93ac6ab281d553b9e125f5197bbbce38f9f2437f7299c32e5509",
        },
      },
    },
  },
  trivy: {
    version: "0.76.2",
    binary: "trivy",
    provenance: {
      kind: "sigstore-checksums",
      checksums: "https://github.com/aquasecurity/trivy/releases/download/v0.76.2/trivy_0.76.2_checksums.txt",
      bundle: "https://github.com/aquasecurity/trivy/releases/download/v0.76.2/trivy_0.76.2_checksums.txt.sigstore.json",
      identity: "https://github.com/aquasecurity/trivy/.github/workflows/reusable-release.yaml@refs/tags/v0.76.2",
      commit: "3f6334d223b52188324af3b9923b4249cd206652",
    },
    artifacts: {
      "darwin-arm64": {
        url: "https://github.com/aquasecurity/trivy/releases/download/v0.76.2/trivy_0.76.2_macOS-ARM64.tar.gz",
        sha256: "ae7ea358326960406b703c77b2ac490190797d80b306b5b50c2a27221da0a5b8",
        archive: { type: "tar.gz", member: "trivy", sha256: "7a15c426f963473a485a4f315e21f8e2c881269d500bf0de35da13a4421fa108" },
      },
      "linux-x64": {
        url: "https://github.com/aquasecurity/trivy/releases/download/v0.76.2/trivy_0.76.2_Linux-64bit.tar.gz",
        sha256: "bc0fc726e017b8927a62b2d3531d7a84ee01769daf5c99ed866dced54089fdbf",
        archive: { type: "tar.gz", member: "trivy", sha256: "6a972c69606c7b3ea4c6bdcc6fc9332ea9ad38381624310c1e85cc77345909f3" },
      },
    },
  },
  syft: {
    version: "1.57.2",
    binary: "syft",
    provenance: {
      kind: "sigstore-checksums",
      checksums: "https://github.com/anchore/syft/releases/download/v1.57.2/syft_1.57.2_checksums.txt",
      bundle: "https://github.com/anchore/syft/releases/download/v1.57.2/syft_1.57.2_checksums.txt.sigstore.json",
      // Anchore releases from a manual run on main; the commit pins it to the v1.57.2 tag.
      identity: "https://github.com/anchore/syft/.github/workflows/release.yaml@refs/heads/main",
      commit: "1a72047fd46c72e0a12ee77e24b23d2316753d08",
    },
    artifacts: {
      "darwin-arm64": {
        url: "https://github.com/anchore/syft/releases/download/v1.57.2/syft_1.57.2_darwin_arm64.tar.gz",
        sha256: "38afbcc03a9d9afac2d7572432fd2c435e051e03930582ea90f4710ffb515224",
        archive: { type: "tar.gz", member: "syft", sha256: "a55d46242c69903c31c10fdceb4579a9f712280b6994001949f8ef634558a99f" },
      },
      "linux-x64": {
        url: "https://github.com/anchore/syft/releases/download/v1.57.2/syft_1.57.2_linux_amd64.tar.gz",
        sha256: "ad92bd3ec1b94a3df01d4d0aec199afa9c42b72e86da436ff5f837914d32706b",
        archive: { type: "tar.gz", member: "syft", sha256: "17cc40c1e40dbfdeb8c84b6d9928909bceb793f22e8a8023ef408625f1d96ec5" },
      },
    },
  },
  grype: {
    version: "0.122.1",
    binary: "grype",
    provenance: {
      kind: "sigstore-checksums",
      checksums: "https://github.com/anchore/grype/releases/download/v0.122.1/grype_0.122.1_checksums.txt",
      bundle: "https://github.com/anchore/grype/releases/download/v0.122.1/grype_0.122.1_checksums.txt.sigstore.json",
      identity: "https://github.com/anchore/grype/.github/workflows/release.yaml@refs/heads/main",
      commit: "8f3ddeddc4a4ed6314248aaf0a7c510f98db8882",
    },
    artifacts: {
      "darwin-arm64": {
        url: "https://github.com/anchore/grype/releases/download/v0.122.1/grype_0.122.1_darwin_arm64.tar.gz",
        sha256: "8bbb3c01695d1e954875cf9f7403c5d3cdb652caf763867955fad520e3cd6c00",
        archive: { type: "tar.gz", member: "grype", sha256: "df8effdd7d4069cfd8762516aa37ddc9e5bf026469f4f509daae2ef730c517f1" },
      },
      "linux-x64": {
        url: "https://github.com/anchore/grype/releases/download/v0.122.1/grype_0.122.1_linux_amd64.tar.gz",
        sha256: "f1ba7e2917ee1395618de20a98da0aa7c0fb1788927797651047c50502a37538",
        archive: { type: "tar.gz", member: "grype", sha256: "322a7839c1c9f6c1b6ac0aa6b61a7d94139b7f24780b82a05b63caab56d4286b" },
      },
    },
  },
};

export function currentPlatform(): Platform | undefined {
  const key = `${process.platform}-${process.arch}`;
  if (key === "darwin-arm64") return "darwin-arm64";
  if (key === "linux-x64") return "linux-x64";
  return undefined;
}

export const BINARY_ENGINES = Object.keys(ENGINES) as BinaryEngine[];
