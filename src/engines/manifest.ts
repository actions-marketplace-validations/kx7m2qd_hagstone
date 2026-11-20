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

export interface EngineSpec {
  version: string;
  binary: string;
  artifacts: Partial<Record<Platform, Artifact>>;
}

/**
 * Pinned engine binaries. Bumping a version means: download, verify against the
 * upstream checksum/signature, then update both the version and the sha256 here.
 *
 * osv-scanner and gitleaks hashes match their published checksum files.
 * Opengrep publishes Sigstore signatures (.sig/.cert) instead of checksums; its
 * hashes match the asset digests GitHub reports for the release (checked
 * 2026-10-22). TODO: also verify with `cosign verify-blob` before the first
 * public release (docs/SECURITY.md).
 *
 * trivy, syft and grype hashes match their published checksum files; each checksum file's
 * Sigstore bundle signs that same digest and has a transparency-log entry (checked 2026-11-20;
 * trivy's certificate names its own release workflow at the pinned tag). Trivy's release
 * pipeline was compromised in March 2026 (CVE-2026-33634, malicious v0.69.4): never bump trivy
 * without checking the release against its advisories. TODO: `cosign verify-blob` all three.
 */
export const ENGINES: Record<BinaryEngine, EngineSpec> = {
  opengrep: {
    version: "1.30.1",
    binary: "opengrep",
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
