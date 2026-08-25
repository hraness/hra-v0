import { afterEach, describe, expect, test } from "bun:test";
import { createHash } from "node:crypto";
import { mkdtemp, readFile, realpath, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath } from "node:url";

import {
  applyReleaseGitHubReadAuthorization,
  parseHistoricalReleaseCandidateContract,
  parseReleaseDownloadContract,
  readReleaseDownloadContract,
  releaseGitHubReadTokenEnvironmentVariable,
  requirePublishedReleaseSource,
  verifyReleaseDownloadContract,
  verifyLocalReleaseCandidate,
  verifyPublishedReleaseArtifacts,
  verifyArchivedReleaseSourceEvidence,
  verifyPublishedReleaseSurfaceEvidence,
  verifyPublishedReleaseSourceEvidence,
  verifyReleaseSourceGate,
  verifyReleaseSourceState,
  verifyRemoteReleaseState,
  releasePublicationCommitAllowlistEnvironmentVariable,
  releaseSurfaceCommitAllowlistEnvironmentVariable,
  verifyVercelReleaseSourceState,
  type PublishedReleaseDownloadContract,
  type ReleaseDownloadContract,
  type ReleaseHttpFetcher,
} from "../release-download-contract";
import { correspondingSourceSpecs } from "../corresponding-sources";
import {
  inspectReleasePublicationObjectStore,
  inspectReleaseSourceRepository,
} from "../release-provenance";
import { productionReleaseSigning } from "../release-signing-authority";
import {
  parseReleaseHistoryContract,
  readReleaseHistoryContract,
  type ReleaseHistoryContract,
} from "../release-history-contract";

const temporaryRoots: string[] = [];
const setupEnvironment = Object.freeze({
  GIT_CONFIG_GLOBAL: "/dev/null",
  GIT_CONFIG_NOSYSTEM: "1",
  HOME: "/var/empty",
  LANG: "C",
  LC_ALL: "C",
  PATH: "/usr/bin:/bin",
});
const currentRepository = "https://github.com/hraness/hra-v0" as const;
const historicalPublicationRepository =
  "https://github.com/hraness/hra" as const;
const parsedCandidateContractFixture = parseReleaseDownloadContract({
  release: {
    architecture: "Apple Silicon",
    artifacts: {
      checksum: {
        bytes: null,
        name: "HRA-0.1.16-17-macos-arm64.dmg.sha256",
        sha256: null,
      },
      dmg: {
        bytes: null,
        name: "HRA-0.1.16-17-macos-arm64.dmg",
        sha256: null,
      },
      manifest: {
        bytes: null,
        name: "HRA-0.1.16-17-release-manifest.json",
        sha256: null,
      },
    },
    availability: "candidate",
    build: 17,
    minimumMacOS: "13",
    source: {
      commit: null,
      runtimeTreeSha256: null,
      tagObject: null,
    },
    tag: "v0.1.16",
    version: "0.1.16",
  },
  repository: currentRepository,
  schemaVersion: 1,
});
if (parsedCandidateContractFixture.release.availability !== "candidate") {
  throw new Error("Expected candidate fixture.");
}
const candidateContractFixture = parsedCandidateContractFixture;
const parsedV15CandidateContractFixture = parseReleaseDownloadContract({
  release: {
    architecture: "Apple Silicon",
    artifacts: {
      checksum: {
        bytes: null,
        name: "HRA-0.1.15-16-macos-arm64.dmg.sha256",
        sha256: null,
      },
      dmg: {
        bytes: null,
        name: "HRA-0.1.15-16-macos-arm64.dmg",
        sha256: null,
      },
      manifest: {
        bytes: null,
        name: "HRA-0.1.15-16-release-manifest.json",
        sha256: null,
      },
    },
    availability: "candidate",
    build: 16,
    minimumMacOS: "13",
    source: { commit: null, runtimeTreeSha256: null, tagObject: null },
    tag: "v0.1.15",
    version: "0.1.15",
  },
  repository: currentRepository,
  schemaVersion: 1,
});
if (parsedV15CandidateContractFixture.release.availability !== "candidate") {
  throw new Error("Expected v0.1.15 candidate fixture.");
}
const v15CandidateContractFixture = parsedV15CandidateContractFixture;
const historicalCandidateContractFixture = parseHistoricalReleaseCandidateContract({
  release: {
    architecture: "Apple Silicon",
    artifacts: {
      checksum: {
        bytes: null,
        name: "HRA-0.1.14-15-macos-arm64.dmg.sha256",
        sha256: null,
      },
      dmg: {
        bytes: null,
        name: "HRA-0.1.14-15-macos-arm64.dmg",
        sha256: null,
      },
      manifest: {
        bytes: null,
        name: "HRA-0.1.14-15-release-manifest.json",
        sha256: null,
      },
    },
    availability: "candidate",
    build: 15,
    minimumMacOS: "13",
    source: { commit: null, runtimeTreeSha256: null, tagObject: null },
    tag: "v0.1.14",
    version: "0.1.14",
  },
  repository: historicalPublicationRepository,
  schemaVersion: 1,
});

afterEach(async () => {
  await Promise.all(
    temporaryRoots.splice(0).map(root =>
      rm(root, { force: true, recursive: true })
    ),
  );
});

describe("GitHub Actions release read authorization", () => {
  const token =
    `ghs_12345_${"a".repeat(48)}.${"b".repeat(48)}.${"c".repeat(48)}`;
  const actionsEnvironment = Object.freeze({
    GITHUB_ACTIONS: "true",
    GITHUB_API_URL: "https://api.github.com",
    GITHUB_REPOSITORY: "hraness/hra-v0",
    [releaseGitHubReadTokenEnvironmentVariable]: token,
  });

  test("authorizes only the fixed HRA v0 GitHub API boundary", () => {
    for (const url of [
      "https://api.github.com/repos/hraness/hra-v0/releases?per_page=100",
      "https://api.github.com/repos/hraness/hra-v0/git/matching-refs/tags/v0.1",
      "https://api.github.com/repos/hraness/hra-v0/releases/tags/v0.1.15",
      "https://api.github.com/repos/hraness/hra-v0/releases/tags/v0.1.16",
    ]) {
      const apiRequest = applyReleaseGitHubReadAuthorization(
        url,
        {
          headers: { Accept: "application/vnd.github+json" },
          redirect: "error",
        },
        actionsEnvironment,
      );
      expect(new Headers(apiRequest.headers).get("authorization"))
        .toBe(`Bearer ${token}`);
      expect(new Headers(apiRequest.headers).get("accept"))
        .toBe("application/vnd.github+json");
    }

    for (const name of [
      "HRA-0.1.16-17-macos-arm64.dmg.sha256",
      "HRA-0.1.16-17-release-manifest.json",
    ]) {
      const browserRequest = applyReleaseGitHubReadAuthorization(
        `${currentRepository}/releases/download/v0.1.16/${name}`,
        { headers: { Accept: "application/octet-stream" }, redirect: "follow" },
        actionsEnvironment,
      );
      expect(new Headers(browserRequest.headers).has("authorization")).toBe(false);
    }
  });

  test("stays credential-free by default and rejects every other credential shape", () => {
    const credentialFree = applyReleaseGitHubReadAuthorization(
      "https://api.github.com/repos/hraness/hra-v0/releases?per_page=100",
      { redirect: "error" },
      {},
    );
    expect(new Headers(credentialFree.headers).has("authorization")).toBe(false);

    for (const environment of [
      { [releaseGitHubReadTokenEnvironmentVariable]: token },
      {
        GITHUB_ACTIONS: "true",
        GITHUB_API_URL: "https://api.github.com",
        GITHUB_REPOSITORY: "hraness/hra-v0",
        [releaseGitHubReadTokenEnvironmentVariable]: "ghp_personal-token",
      },
      {
        GITHUB_ACTIONS: "true",
        GITHUB_API_URL: "https://api.github.com",
        GITHUB_REPOSITORY: "hraness/hra-v0",
        [releaseGitHubReadTokenEnvironmentVariable]: "ghs_contains whitespace",
      },
      {
        GITHUB_ACTIONS: "true",
        GITHUB_API_URL: "https://api.github.com",
        GITHUB_REPOSITORY: "hraness/hra-v0",
        [releaseGitHubReadTokenEnvironmentVariable]: `ghs_${"a".repeat(4_096)}`,
      },
      { ...actionsEnvironment, GITHUB_REPOSITORY: "hraness/hra" },
      { ...actionsEnvironment, GITHUB_API_URL: "https://github.example/api" },
    ]) {
      let message = "";
      try {
        applyReleaseGitHubReadAuthorization(
          "https://api.github.com/repos/hraness/hra-v0/releases?per_page=100",
          { redirect: "error" },
          environment,
        );
      } catch (error) {
        message = error instanceof Error ? error.message : String(error);
      }
      expect(message).toContain("GitHub Actions release read token is invalid");
      expect(message).not.toContain(token);
    }
    expect(() => applyReleaseGitHubReadAuthorization(
      "https://api.github.com/repos/hraness/hra-v0/releases?per_page=100",
      { redirect: "error" },
      {
        GITHUB_ACTIONS: "true",
        GITHUB_API_URL: "https://api.github.com",
        GITHUB_REPOSITORY: "hraness/hra-v0",
      },
    )).toThrow("requires its read token");
    expect(() => applyReleaseGitHubReadAuthorization(
      "https://api.github.com/repos/hraness/hra-v0/releases?per_page=100",
      { headers: { Authorization: "Bearer ambient" }, redirect: "error" },
      {},
    )).toThrow("must not supply ambient authorization");
  });

  test("rejects every request outside the exact read-only transport", () => {
    for (const [url, init] of [
      [
        "https://api.github.com/repos/hraness/hra-v0/releases?per_page=99",
        { redirect: "error" },
      ],
      [
        "https://api.github.com/repos/hraness/hra-v0/issues",
        { redirect: "error" },
      ],
      [
        "https://api.github.com/repos/hraness/hra/releases?per_page=100",
        { redirect: "error" },
      ],
      [
        "https://api.github.com.evil.example/repos/hraness/hra-v0/releases?per_page=100",
        { redirect: "error" },
      ],
      [
        "https://api.github.com/repos/hraness/hra-v0/releases?per_page=100",
        { method: "POST", redirect: "error" },
      ],
      [
        "https://api.github.com/repos/hraness/hra-v0/releases?per_page=100",
        { body: "unexpected", method: "GET", redirect: "error" },
      ],
      [
        "https://api.github.com/repos/hraness/hra-v0/releases?per_page=100",
        { redirect: "follow" },
      ],
      [
        `${currentRepository}/releases/download/v0.1.15/HRA-0.1.15-16-macos-arm64.dmg`,
        { redirect: "follow" },
      ],
      [
        `${currentRepository}/releases/download/v0.1.15/${correspondingSourceSpecs[0]?.archiveName ?? "missing"}`,
        { redirect: "follow" },
      ],
      [
        `${currentRepository}/releases/download/v0.1.15/HRA-0.1.15-16-macos-arm64.dmg.sha256`,
        { redirect: "error" },
      ],
    ] as const) {
      expect(() => applyReleaseGitHubReadAuthorization(
        url,
        init,
        actionsEnvironment,
      )).toThrow(/not allowlisted|request shape/u);
    }
  });
});

describe("release and download convergence", () => {
  test("verifies the v0.1.16 build 17 repository contract in either protocol state", async () => {
    const contract = await readReleaseDownloadContract();
    expectReleaseIdentity(contract);
    expect(await verifyReleaseDownloadContract()).toEqual(contract);
    if (contract.release.availability === "candidate") {
      expect(contract).toEqual(candidateContractFixture);
      await expectRejection(requirePublishedReleaseSource(), "not published");
    } else {
      const source = await verifyReleaseSourceGate();
      expect(source).toMatchObject({
        availability: "published",
        contract,
        status: "verified_published_source",
      });
      expect(await requirePublishedReleaseSource()).toMatchObject({ contract });
    }
  });

  test("keeps maintained candidate state at hra-v0 and P14 compatibility historical", async () => {
    const maintainedCandidate = candidateContractFixture;
    const historicalCandidate = historicalCandidateContractFixture;
    expect(parseReleaseDownloadContract(maintainedCandidate)).toEqual(
      maintainedCandidate,
    );
    expect(
      parseHistoricalReleaseCandidateContract(historicalCandidate),
    ).toEqual(historicalCandidate);
    expect(() =>
      parseHistoricalReleaseCandidateContract(maintainedCandidate)
    ).toThrow();

    const history = createRemoteHistoryFixture();
    expect(await verifyRemoteReleaseState(
      maintainedCandidate,
      history.fetcher,
      undefined,
      history.contract,
    )).toMatchObject({
      availability: "candidate",
      history: {
        assetCount: 56,
        releaseCount: 8,
        tagCount: 9,
      },
      status: "verified_candidate_remote_collision_absence",
    });
    expect(history.requests).toHaveLength(11);
    const candidateVercelEnvironment = {
      VERCEL: "1",
      VERCEL_ENV: "preview",
      VERCEL_GIT_COMMIT_REF: "candidate-preview",
      VERCEL_GIT_COMMIT_SHA: "a".repeat(40),
      VERCEL_GIT_PROVIDER: "github",
      VERCEL_GIT_REPO_OWNER: "hraness",
      VERCEL_GIT_REPO_SLUG: "hra-v0",
      VERCEL_TARGET_ENV: "preview",
    } as const;
    expect(await verifyVercelReleaseSourceState(
      maintainedCandidate,
      candidateVercelEnvironment,
    )).toMatchObject({
      availability: "candidate",
      status: "valid_candidate_contract",
    });
  });

  test("models publication as one strict evidence-bearing state", () => {
    const candidate = candidateContractFixture;
    const published = {
      ...candidate,
      repository: currentRepository,
      release: {
        ...candidate.release,
        artifacts: {
          checksum: { bytes: 81, name: candidate.release.artifacts.checksum.name, sha256: "a".repeat(64) },
          dmg: { bytes: 1_000, name: candidate.release.artifacts.dmg.name, sha256: "b".repeat(64) },
          manifest: { bytes: 2_000, name: candidate.release.artifacts.manifest.name, sha256: "c".repeat(64) },
        },
        availability: "published",
        source: {
          commit: "d".repeat(40),
          runtimeTreeSha256: "e".repeat(64),
          tagObject: "f".repeat(40),
        },
      },
    };
    expect(parseReleaseDownloadContract(published).release.availability).toBe("published");

    expect(parseReleaseDownloadContract(candidate)).toEqual(candidate);

    expect(() => parseReleaseDownloadContract({
      ...published,
      release: {
        ...published.release,
        source: { ...published.release.source, commit: null },
      },
    })).toThrow();
    expect(() => parseReleaseDownloadContract({
      ...candidate,
      release: {
        ...candidate.release,
        artifacts: {
          ...candidate.release.artifacts,
          dmg: { ...candidate.release.artifacts.dmg, sha256: "0".repeat(64) },
        },
      },
    })).toThrow();
  });

  test("verifies the immutable seven-asset GitHub prerelease without fetching the DMG", async () => {
    const fixture = createRemoteReleaseFixture(
      candidateContractFixture,
    );
    expect(await verifyRemoteReleaseState(
      fixture.contract,
      fixture.fetcher,
      undefined,
      fixture.historyContract,
    )).toMatchObject({
      availability: "published",
      history: {
        assetCount: 63,
        releaseCount: 9,
        tagCount: 10,
      },
      immutable: true,
      releaseId: 18,
      status: "verified_immutable_remote_release",
    });
    expect(fixture.requests).toContain(fixture.metadataUrl);
    expect(fixture.requests).toContain(fixture.checksumUrl);
    expect(fixture.requests).toContain(fixture.manifestUrl);
    expect(fixture.requests).not.toContain(fixture.dmgUrl);

    const frozen = createRemoteReleaseFixture(candidateContractFixture, {
      frozenGenerationTwo: true,
    });
    expect(await verifyRemoteReleaseState(
      frozen.contract,
      frozen.fetcher,
      undefined,
      frozen.historyContract,
    )).toMatchObject({
      availability: "published",
      history: {
        assetCount: 63,
        releaseCount: 9,
        tagCount: 10,
      },
      status: "verified_immutable_remote_release",
    });
  });

  test("rejects mutable metadata, digest drift, and a manifest bound to another commit", async () => {
    const candidate = candidateContractFixture;
    const mutable = createRemoteReleaseFixture(candidate);
    mutable.metadata.immutable = false;
    await expectRejection(
      verifyRemoteReleaseState(mutable.contract, mutable.fetcher),
      "published immutable HRA prerelease",
    );

    const digestDrift = createRemoteReleaseFixture(candidate);
    const dmg = digestDrift.metadata.assets.find((asset) =>
      asset.name === digestDrift.contract.release.artifacts.dmg.name
    );
    if (dmg === undefined) throw new Error("Expected fixture DMG metadata.");
    dmg.digest = `sha256:${"0".repeat(64)}`;
    await expectRejection(
      verifyRemoteReleaseState(digestDrift.contract, digestDrift.fetcher),
      "metadata differs from published evidence",
    );

    const wrongManifest = createRemoteReleaseFixture(candidate, {
      manifestCommit: "f".repeat(40),
    });
    await expectRejection(
      verifyRemoteReleaseState(wrongManifest.contract, wrongManifest.fetcher),
      "manifest does not bind the published HRA evidence",
    );

    const ledgerDrift = createRemoteReleaseFixture(candidate, {
      frozenGenerationTwo: true,
    });
    ledgerDrift.metadata.id += 1;
    await expectRejection(
      verifyRemoteReleaseState(
        ledgerDrift.contract,
        ledgerDrift.fetcher,
        undefined,
        ledgerDrift.historyContract,
      ),
      "generation-2 release ledger differs",
    );
  });

  test("rejects alternate repositories, extra fields, and mismatched tags", () => {
    const contract = createRemoteReleaseFixture(candidateContractFixture).contract;
    for (const repository of [
      historicalPublicationRepository,
      "https://github.com/attacker/hra",
    ] as const) {
      expect(() => parseReleaseDownloadContract({
        ...contract,
        repository,
      })).toThrow();
    }
    expect(() => parseReleaseDownloadContract({
      ...contract,
      callerCommit: "0".repeat(40),
    })).toThrow();
    expect(() => parseReleaseDownloadContract({
      ...contract,
      release: { ...contract.release, tag: "v0.1.7" },
    })).toThrow();
  });

  test("makes the conditional source gate a required CI and build boundary", async () => {
    const [workflow, rootManifestText, desktopManifestText] = await Promise.all([
      readFile(
        new URL("../../../../.github/workflows/ci.yml", import.meta.url),
        "utf8",
      ),
      readFile(new URL("../../../../package.json", import.meta.url), "utf8"),
      readFile(new URL("../../package.json", import.meta.url), "utf8"),
    ]);
    const rootManifest = JSON.parse(rootManifestText) as {
      scripts?: Record<string, unknown>;
    };
    const desktopManifest = JSON.parse(desktopManifestText) as {
      scripts?: Record<string, unknown>;
    };
    expect(rootManifest.scripts?.["check:release-source"]).toBe(
      "bun run --cwd apps/desktop check:release-source",
    );
    expect(desktopManifest.scripts?.["check:release-source"]).toBe(
      "bun run runtime/release-download-contract.ts source",
    );
    expect(rootManifest.scripts?.["verify:remote-release"]).toBe(
      "bun run --cwd apps/desktop verify:remote-release",
    );
    expect(desktopManifest.scripts?.["verify:remote-release"]).toBe(
      "bun run runtime/release-download-contract.ts remote",
    );
    expect(desktopManifest.scripts?.["verify:release-candidate"]).toBe(
      "bun run runtime/release-download-contract.ts candidate",
    );
    expect(desktopManifest.scripts?.["verify:published-release"]).toBe(
      "bun run runtime/release-download-contract.ts published",
    );
    expect(rootManifest.scripts?.["package:macos:structural"]).toBe(
      "bun run --cwd apps/desktop package:macos:structural",
    );
    expect(rootManifest.scripts?.["verify:package:macos:structural"]).toBe(
      "bun run --cwd apps/desktop verify:package:macos:structural",
    );
    expect(rootManifest.scripts?.["package:macos:adhoc"]).toBeUndefined();
    expect(rootManifest.scripts?.["verify:package:macos:adhoc"]).toBeUndefined();
    expect(rootManifest.scripts?.["installation:forward-recovery"]).toBe(
      "bun run --cwd apps/desktop installation:forward-recovery --",
    );
    expect(rootManifest.scripts?.["installation:forward-status"]).toBe(
      "bun run --cwd apps/desktop installation:forward-status --",
    );
    expect(rootManifest.scripts?.["installation:forward-resume"]).toBe(
      "bun run --cwd apps/desktop installation:forward-resume --",
    );
    expect(rootManifest.scripts?.["installation:forward-cleanup"]).toBe(
      "bun run --cwd apps/desktop installation:forward-cleanup --",
    );
    expect(desktopManifest.scripts?.build).toStartWith(
      "bun run check:release-source &&",
    );
    expect(workflow).toContain(
      [
        "ref: $",
        "{{ github.event_name == 'pull_request' && github.event.pull_request.head.sha || github.sha }}",
      ].join(""),
    );
    expect(workflow).toContain("run: bun run check:release-source");
    const releaseEvidenceStep = [
      "      - name: Verify immutable remote release evidence",
      "        env:",
      ["          HRA_RELEASE_GITHUB_READ_TOKEN: $", "{{ github.token }}"].join(""),
      "        run: bun run verify:remote-release",
    ].join("\n");
    expect(workflow).toContain(releaseEvidenceStep);
    expect(workflow).toContain("permissions:\n  contents: read");
    expect(workflow.split(releaseGitHubReadTokenEnvironmentVariable))
      .toHaveLength(2);
    expect(workflow.split(["$", "{{ github.token }}"].join("")))
      .toHaveLength(2);
    expect(workflow).not.toContain(["secrets", "GITHUB_TOKEN"].join("."));
    expect(workflow).toContain(
      "run: bun run --cwd apps/desktop package:macos:structural",
    );
    expect(workflow).not.toContain("package:macos:adhoc");
  });

  test("keeps caller-supplied release directories absolute and normalized", async () => {
    await expectRejection(
      verifyLocalReleaseCandidate("zig-out/release/macos/arm64"),
      "absolute normalized path",
    );
    await expectRejection(
      verifyPublishedReleaseArtifacts("zig-out/release/macos/arm64"),
      "absolute normalized path",
    );
  });

  test("routes no-argument local release commands and rejects every extra argument", async () => {
    for (const command of ["candidate", "published"] as const) {
      const local = await runReleaseContractCli([command]);
      expect(local.stderr).not.toContain("Usage: release-download-contract.ts");
      expect(local.stderr.split("\n")).not.toContain(
        "error: Release directory must be an absolute normalized path.",
      );

      for (const arguments_ of [
        [command, "unexpected"],
        [command, "--release-directory", "/tmp", "unexpected"],
      ]) {
        const extra = await runReleaseContractCli(arguments_);
        expect(extra.exitCode).not.toBe(0);
        expect(extra.stderr).toContain("Usage: release-download-contract.ts");
      }
    }
  });

  test("keeps candidate source valid on a descendant of the exact Q14-to-base-to-surface-to-custody-to-host-trust-to-bundle-code-authority-to-signed-release-probe-repair-to-final-C15 chain", async () => {
    const repositoryRoot = await realpath(
      await mkdtemp(join(tmpdir(), "hra-v015-candidate-descendant-")),
    );
    temporaryRoots.push(repositoryRoot);
    await runSetupGit(repositoryRoot, ["init", "--initial-branch=main"]);
    await runSetupGit(repositoryRoot, [
      "config",
      "user.email",
      "release-test@hraness.com",
    ]);
    await runSetupGit(repositoryRoot, [
      "config",
      "user.name",
      "HRA release test",
    ]);
    await writeFile(join(repositoryRoot, "q14.txt"), "reviewed Q14 surface\n");
    await runSetupGit(repositoryRoot, ["add", "q14.txt"]);
    await runSetupGit(repositoryRoot, ["commit", "-m", "reviewed Q14"]);
    const q14Commit = (
      await runSetupGit(repositoryRoot, ["rev-parse", "HEAD"])
    ).trim();
    await writeFile(
      join(repositoryRoot, "release-download.json"),
      `${JSON.stringify(v15CandidateContractFixture, null, 2)}\n`,
    );
    await writeFile(join(repositoryRoot, "source.txt"), "base C15\n");
    await runSetupGit(repositoryRoot, [
      "add",
      "release-download.json",
      "source.txt",
    ]);
    await runSetupGit(repositoryRoot, ["commit", "-m", "base C15"]);
    const baseCommit = (
      await runSetupGit(repositoryRoot, ["rev-parse", "HEAD"])
    ).trim();
    await writeFile(join(repositoryRoot, "surface.txt"), "reviewed public surface\n");
    await runSetupGit(repositoryRoot, ["add", "surface.txt"]);
    await runSetupGit(repositoryRoot, ["commit", "-m", "reviewed public surface"]);
    const surfaceCommit = (
      await runSetupGit(repositoryRoot, ["rev-parse", "HEAD"])
    ).trim();
    await writeFile(join(repositoryRoot, "repair.txt"), "repaired C15\n");
    await runSetupGit(repositoryRoot, ["add", "repair.txt"]);
    await runSetupGit(repositoryRoot, ["commit", "-m", "custody repair"]);
    const custodyRepairCommit = (
      await runSetupGit(repositoryRoot, ["rev-parse", "HEAD"])
    ).trim();
    await writeFile(join(repositoryRoot, "host-trust.txt"), "host trust repair\n");
    await runSetupGit(repositoryRoot, ["add", "host-trust.txt"]);
    await runSetupGit(repositoryRoot, ["commit", "-m", "host-trust repair"]);
    const hostTrustCommit = (
      await runSetupGit(repositoryRoot, ["rev-parse", "HEAD"])
    ).trim();
    await writeFile(
      join(repositoryRoot, "bundle-code-authority.txt"),
      "bundle code authority\n",
    );
    await runSetupGit(repositoryRoot, ["add", "bundle-code-authority.txt"]);
    await runSetupGit(repositoryRoot, [
      "commit",
      "-m",
      "bundle-code-authority repair",
    ]);
    const bundleCodeAuthorityCommit = (
      await runSetupGit(repositoryRoot, ["rev-parse", "HEAD"])
    ).trim();
    await writeFile(
      join(repositoryRoot, "signed-release-probe-repair.txt"),
      "signed release-probe repair\n",
    );
    await runSetupGit(repositoryRoot, ["add", "signed-release-probe-repair.txt"]);
    await runSetupGit(repositoryRoot, [
      "commit",
      "-m",
      "signed-release-probe repair",
    ]);
    const signedReleaseProbeRepairCommit = (
      await runSetupGit(repositoryRoot, ["rev-parse", "HEAD"])
    ).trim();
    await writeFile(join(repositoryRoot, "candidate.txt"), "final C15\n");
    await runSetupGit(repositoryRoot, ["add", "candidate.txt"]);
    await runSetupGit(repositoryRoot, ["commit", "-m", "final C15"]);
    expect(await verifyReleaseSourceState(v15CandidateContractFixture, {
      candidateBaseCommit: baseCommit,
      candidateBundleCodeAuthorityCommit: bundleCodeAuthorityCommit,
      candidateCustodyRepairCommit: custodyRepairCommit,
      candidateHostTrustCommit: hostTrustCommit,
      candidateQ14Commit: q14Commit,
      candidateSignedReleaseProbeRepairCommit: signedReleaseProbeRepairCommit,
      candidateSurfaceCommit: surfaceCommit,
      environment: {},
      repositoryRoot,
    })).toMatchObject({
      availability: "candidate",
      status: "valid_candidate_contract",
    });
    await writeFile(join(repositoryRoot, "follow-up.txt"), "archive follow-up\n");
    await runSetupGit(repositoryRoot, ["add", "follow-up.txt"]);
    await runSetupGit(repositoryRoot, ["commit", "-m", "archive follow-up"]);
    expect(await verifyReleaseSourceState(v15CandidateContractFixture, {
      candidateBaseCommit: baseCommit,
      candidateBundleCodeAuthorityCommit: bundleCodeAuthorityCommit,
      candidateCustodyRepairCommit: custodyRepairCommit,
      candidateHostTrustCommit: hostTrustCommit,
      candidateQ14Commit: q14Commit,
      candidateSignedReleaseProbeRepairCommit: signedReleaseProbeRepairCommit,
      candidateSurfaceCommit: surfaceCommit,
      environment: {},
      repositoryRoot,
    })).toMatchObject({
      availability: "candidate",
      status: "valid_candidate_contract",
    });
  });

  test("binds v0.1.16 to the linear Q15-to-C16-to-P16 candidate and publication path", async () => {
    const repositoryRoot = await realpath(
      await mkdtemp(join(tmpdir(), "hra-v016-publication-")),
    );
    temporaryRoots.push(repositoryRoot);
    await runSetupGit(repositoryRoot, ["init", "--initial-branch=main"]);
    await runSetupGit(repositoryRoot, [
      "config",
      "user.email",
      "release-test@hraness.com",
    ]);
    await runSetupGit(repositoryRoot, [
      "config",
      "user.name",
      "HRA release test",
    ]);
    await writeFile(join(repositoryRoot, "q15.txt"), "reviewed Q15 surface\n");
    await runSetupGit(repositoryRoot, ["add", "q15.txt"]);
    await runSetupGit(repositoryRoot, ["commit", "-m", "reviewed Q15"]);
    const q15Commit = (
      await runSetupGit(repositoryRoot, ["rev-parse", "HEAD"])
    ).trim();

    await Promise.all([
      writeFile(
        join(repositoryRoot, "release-download.json"),
        `${JSON.stringify(candidateContractFixture, null, 2)}\n`,
      ),
      writeFile(join(repositoryRoot, "hotfix.txt"), "macOS ACL hotfix\n"),
    ]);
    await runSetupGit(repositoryRoot, [
      "add",
      "hotfix.txt",
      "release-download.json",
    ]);
    await runSetupGit(repositoryRoot, ["commit", "-m", "candidate C16"]);
    const candidateCommit = (
      await runSetupGit(repositoryRoot, ["rev-parse", "HEAD"])
    ).trim();
    expect(await verifyReleaseSourceState(candidateContractFixture, {
      candidateQ15Commit: q15Commit,
      environment: {},
      repositoryRoot,
    })).toMatchObject({
      availability: "candidate",
      status: "valid_candidate_contract",
    });

    await runSetupGit(repositoryRoot, [
      "tag",
      "-a",
      candidateContractFixture.release.tag,
      "-m",
      "HRA v0.1.16 candidate",
    ]);
    const tagObject = (
      await runSetupGit(repositoryRoot, [
        "rev-parse",
        `refs/tags/${candidateContractFixture.release.tag}`,
      ])
    ).trim();
    const published = asPublishedFixture(parseReleaseDownloadContract({
      ...candidateContractFixture,
      release: {
        ...candidateContractFixture.release,
        artifacts: {
          checksum: {
            bytes: 96,
            name: candidateContractFixture.release.artifacts.checksum.name,
            sha256: "a".repeat(64),
          },
          dmg: {
            bytes: 1_000,
            name: candidateContractFixture.release.artifacts.dmg.name,
            sha256: "b".repeat(64),
          },
          manifest: {
            bytes: 2_000,
            name: candidateContractFixture.release.artifacts.manifest.name,
            sha256: "c".repeat(64),
          },
        },
        availability: "published",
        source: {
          commit: candidateCommit,
          runtimeTreeSha256: "d".repeat(64),
          tagObject,
        },
      },
    }));
    await writeFile(
      join(repositoryRoot, "release-download.json"),
      `${JSON.stringify(published, null, 2)}\n`,
    );
    await runSetupGit(repositoryRoot, ["add", "release-download.json"]);
    await runSetupGit(repositoryRoot, ["commit", "-m", "publication P16"]);
    const publicationCommit = (
      await runSetupGit(repositoryRoot, ["rev-parse", "HEAD"])
    ).trim();
    const repository = await inspectReleaseSourceRepository({
      environment: {},
      repositoryRoot,
    });
    const verified = await verifyPublishedReleaseSourceEvidence(
      published,
      repository,
      { expectedQ15Commit: q15Commit },
    );
    expect(verified.publication).toMatchObject({
      candidateCommit,
      changedPath: "release-download.json",
      publicationCommit,
      status: "exact_candidate_publication_transition",
    });
    expect(await verifyReleaseSourceState(published, {
      candidateQ15Commit: q15Commit,
      environment: {},
      repositoryRoot,
    })).toMatchObject({
      availability: "published",
      status: "verified_published_source",
    });

    const generationTwo = generationTwoHistoryContract(
      published,
      publicationCommit,
    );
    await writeFile(
      join(repositoryRoot, "release-history.json"),
      `${JSON.stringify(generationTwo, null, 2)}\n`,
    );
    await runSetupGit(repositoryRoot, ["add", "release-history.json"]);
    await runSetupGit(repositoryRoot, ["commit", "-m", "archive surface Q16"]);
    const surfaceCommit = (
      await runSetupGit(repositoryRoot, ["rev-parse", "HEAD"])
    ).trim();
    const surfaceRepository = await inspectReleaseSourceRepository({
      environment: {},
      repositoryRoot,
    });
    const surface = await verifyPublishedReleaseSurfaceEvidence(
      published,
      surfaceRepository,
      {
        expectedQ15Commit: q15Commit,
        historyContract: generationTwo,
        publicationCommit,
      },
    );
    expect(surface.surface).toMatchObject({
      publication: { candidateCommit, publicationCommit },
      status: "verified_linear_publication_surface",
      surfaceCommit,
    });
    expect(await verifyReleaseSourceState(published, {
      candidateQ15Commit: q15Commit,
      environment: {},
      historyContract: generationTwo,
      repositoryRoot,
    })).toMatchObject({
      availability: "published",
      status: "verified_published_source",
      surface: { surfaceCommit },
    });
    await expectRejection(
      verifyReleaseSourceState(published, {
        candidateQ15Commit: q15Commit,
        environment: {},
        historyContract: readReleaseHistoryContract(),
        repositoryRoot,
      }),
      "only direct parent",
    );

    const providerEnvironment = {
      VERCEL: "1",
      VERCEL_ENV: "production",
      VERCEL_GIT_COMMIT_REF: "main",
      VERCEL_GIT_COMMIT_SHA: surfaceCommit,
      VERCEL_GIT_PROVIDER: "github",
      VERCEL_GIT_REPO_OWNER: "hraness",
      VERCEL_GIT_REPO_SLUG: "hra-v0",
      VERCEL_TARGET_ENV: "production",
      [releasePublicationCommitAllowlistEnvironmentVariable]: publicationCommit,
      [releaseSurfaceCommitAllowlistEnvironmentVariable]: surfaceCommit,
    } as const;
    const inspectCanonicalSurface = (options: Readonly<{
      candidateCommit: string;
      publicationCommit: string;
      surfaceCommit: string;
      tag: string;
    }>) => {
      expect(options).toEqual({
        candidateCommit,
        publicationCommit,
        surfaceCommit,
        tag: published.release.tag,
      });
      return Promise.resolve({
        publication: surface.publication,
        surface: surface.surface,
        tag: surface.tag,
      });
    };
    expect(await verifyVercelReleaseSourceState(
      published,
      providerEnvironment,
      undefined,
      undefined,
      undefined,
      inspectCanonicalSurface,
      generationTwo,
    )).toMatchObject({
      availability: "published",
      publicationCommit,
      status: "verified_vercel_publication_surface_binding",
      surfaceCommit,
    });
    await expectRejection(
      verifyVercelReleaseSourceState(
        published,
        providerEnvironment,
        undefined,
        undefined,
        undefined,
        () => Promise.resolve({
          publication: surface.publication,
          surface: {
            ...surface.surface,
            surfaceCommit: "f".repeat(40),
          },
          tag: surface.tag,
        }),
        generationTwo,
      ),
      "differs from provider source",
    );
    await expectRejection(
      verifyVercelReleaseSourceState(
        published,
        {
          ...providerEnvironment,
          [releaseSurfaceCommitAllowlistEnvironmentVariable]:
            `${surfaceCommit},${"f".repeat(40)}`,
        },
        undefined,
        undefined,
        undefined,
        inspectCanonicalSurface,
        generationTwo,
      ),
      "singleton allowlisted",
    );
    await expectRejection(
      verifyVercelReleaseSourceState(
        published,
        providerEnvironment,
        undefined,
        undefined,
        undefined,
        inspectCanonicalSurface,
        readReleaseHistoryContract(),
      ),
      "generation-2 P16 release ledger",
    );
  });

  test("binds published v0.1.15 to the exact Q14-to-base-to-surface-to-custody-to-host-trust-to-bundle-code-authority-to-signed-release-probe-repair-to-final-C15-to-P15 chain", async () => {
    const repositoryRoot = await realpath(
      await mkdtemp(join(tmpdir(), "hra-v015-publication-")),
    );
    temporaryRoots.push(repositoryRoot);
    await runSetupGit(repositoryRoot, ["init", "--initial-branch=main"]);
    await runSetupGit(repositoryRoot, [
      "config",
      "user.email",
      "release-test@hraness.com",
    ]);
    await runSetupGit(repositoryRoot, [
      "config",
      "user.name",
      "HRA release test",
    ]);
    await writeFile(join(repositoryRoot, "q14.txt"), "reviewed Q14 surface\n");
    await runSetupGit(repositoryRoot, ["add", "q14.txt"]);
    await runSetupGit(repositoryRoot, ["commit", "-m", "reviewed Q14"]);
    const q14Commit = (
      await runSetupGit(repositoryRoot, ["rev-parse", "HEAD"])
    ).trim();
    await writeFile(
      join(repositoryRoot, "release-download.json"),
      `${JSON.stringify(v15CandidateContractFixture, null, 2)}\n`,
    );
    await writeFile(join(repositoryRoot, "source.txt"), "base C15\n");
    await runSetupGit(repositoryRoot, [
      "add",
      "release-download.json",
      "source.txt",
    ]);
    await runSetupGit(repositoryRoot, ["commit", "-m", "base C15"]);
    const baseCommit = (
      await runSetupGit(repositoryRoot, ["rev-parse", "HEAD"])
    ).trim();
    await writeFile(join(repositoryRoot, "surface.txt"), "reviewed public surface\n");
    await runSetupGit(repositoryRoot, ["add", "surface.txt"]);
    await runSetupGit(repositoryRoot, ["commit", "-m", "reviewed public surface"]);
    const surfaceCommit = (
      await runSetupGit(repositoryRoot, ["rev-parse", "HEAD"])
    ).trim();
    await writeFile(join(repositoryRoot, "repair.txt"), "repaired C15\n");
    await runSetupGit(repositoryRoot, ["add", "repair.txt"]);
    await runSetupGit(repositoryRoot, ["commit", "-m", "custody repair"]);
    const custodyRepairCommit = (
      await runSetupGit(repositoryRoot, ["rev-parse", "HEAD"])
    ).trim();
    await writeFile(join(repositoryRoot, "host-trust.txt"), "host trust repair\n");
    await runSetupGit(repositoryRoot, ["add", "host-trust.txt"]);
    await runSetupGit(repositoryRoot, ["commit", "-m", "host-trust repair"]);
    const hostTrustCommit = (
      await runSetupGit(repositoryRoot, ["rev-parse", "HEAD"])
    ).trim();
    await writeFile(
      join(repositoryRoot, "bundle-code-authority.txt"),
      "bundle code authority\n",
    );
    await runSetupGit(repositoryRoot, ["add", "bundle-code-authority.txt"]);
    await runSetupGit(repositoryRoot, [
      "commit",
      "-m",
      "bundle-code-authority repair",
    ]);
    const bundleCodeAuthorityCommit = (
      await runSetupGit(repositoryRoot, ["rev-parse", "HEAD"])
    ).trim();
    await writeFile(
      join(repositoryRoot, "signed-release-probe-repair.txt"),
      "signed release-probe repair\n",
    );
    await runSetupGit(repositoryRoot, ["add", "signed-release-probe-repair.txt"]);
    await runSetupGit(repositoryRoot, [
      "commit",
      "-m",
      "signed-release-probe repair",
    ]);
    const signedReleaseProbeRepairCommit = (
      await runSetupGit(repositoryRoot, ["rev-parse", "HEAD"])
    ).trim();
    await writeFile(join(repositoryRoot, "candidate.txt"), "final C15\n");
    await runSetupGit(repositoryRoot, ["add", "candidate.txt"]);
    await runSetupGit(repositoryRoot, ["commit", "-m", "final C15"]);
    const candidateCommit = (
      await runSetupGit(repositoryRoot, ["rev-parse", "HEAD"])
    ).trim();
    expect(await verifyReleaseSourceState(v15CandidateContractFixture, {
      candidateBaseCommit: baseCommit,
      candidateBundleCodeAuthorityCommit: bundleCodeAuthorityCommit,
      candidateCustodyRepairCommit: custodyRepairCommit,
      candidateHostTrustCommit: hostTrustCommit,
      candidateQ14Commit: q14Commit,
      candidateSignedReleaseProbeRepairCommit: signedReleaseProbeRepairCommit,
      candidateSurfaceCommit: surfaceCommit,
      environment: {},
      repositoryRoot,
    })).toMatchObject({
      availability: "candidate",
      status: "valid_candidate_contract",
    });
    await runSetupGit(repositoryRoot, [
      "tag",
      "-a",
      v15CandidateContractFixture.release.tag,
      "-m",
      "HRA v0.1.15 candidate",
    ]);
    const tagObject = (
      await runSetupGit(repositoryRoot, [
        "rev-parse",
        `refs/tags/${v15CandidateContractFixture.release.tag}`,
      ])
    ).trim();
    const published = asPublishedFixture(parseReleaseDownloadContract({
      ...v15CandidateContractFixture,
      release: {
        ...v15CandidateContractFixture.release,
        artifacts: {
          checksum: {
            bytes: 81,
            name: v15CandidateContractFixture.release.artifacts.checksum.name,
            sha256: "a".repeat(64),
          },
          dmg: {
            bytes: 1_000,
            name: v15CandidateContractFixture.release.artifacts.dmg.name,
            sha256: "b".repeat(64),
          },
          manifest: {
            bytes: 2_000,
            name: v15CandidateContractFixture.release.artifacts.manifest.name,
            sha256: "c".repeat(64),
          },
        },
        availability: "published",
        source: {
          commit: candidateCommit,
          runtimeTreeSha256: "d".repeat(64),
          tagObject,
        },
      },
    }));
    await writeFile(
      join(repositoryRoot, "release-download.json"),
      `${JSON.stringify(published, null, 2)}\n`,
    );
    await runSetupGit(repositoryRoot, ["add", "release-download.json"]);
    await runSetupGit(repositoryRoot, ["commit", "-m", "publication P15"]);
    const publicationCommit = (
      await runSetupGit(repositoryRoot, ["rev-parse", "HEAD"])
    ).trim();
    const repository = await inspectReleaseSourceRepository({
      environment: {},
      repositoryRoot,
    });
    const verified = await verifyPublishedReleaseSourceEvidence(
      published,
      repository,
      {
        expectedBaseCommit: baseCommit,
        expectedBundleCodeAuthorityCommit: bundleCodeAuthorityCommit,
        expectedCustodyRepairCommit: custodyRepairCommit,
        expectedHostTrustCommit: hostTrustCommit,
        expectedQ14Commit: q14Commit,
        expectedSignedReleaseProbeRepairCommit: signedReleaseProbeRepairCommit,
        expectedSurfaceCommit: surfaceCommit,
      },
    );
    expect(verified.publication).toMatchObject({
      candidateCommit,
      changedPath: "release-download.json",
      publicationCommit,
      status: "exact_candidate_publication_transition",
    });
    expect(await verifyVercelReleaseSourceState(published, {
      VERCEL: "1",
      VERCEL_ENV: "production",
      VERCEL_GIT_COMMIT_REF: "main",
      VERCEL_GIT_COMMIT_SHA: publicationCommit,
      VERCEL_GIT_PROVIDER: "github",
      VERCEL_GIT_REPO_OWNER: "hraness",
      VERCEL_GIT_REPO_SLUG: "hra-v0",
      VERCEL_TARGET_ENV: "production",
      [releasePublicationCommitAllowlistEnvironmentVariable]:
        publicationCommit,
    }, () => Promise.resolve({
      publication: verified.publication,
      tag: verified.tag,
    }))).toMatchObject({
      availability: "published",
      publicationCommit,
      status: "verified_vercel_publication_binding",
    });
    await expectRejection(
      verifyVercelReleaseSourceState(published, {
        VERCEL: "1",
        VERCEL_ENV: "production",
        VERCEL_GIT_COMMIT_REF: "main",
        VERCEL_GIT_COMMIT_SHA: "f".repeat(40),
        VERCEL_GIT_PROVIDER: "github",
        VERCEL_GIT_REPO_OWNER: "hraness",
        VERCEL_GIT_REPO_SLUG: "hra-v0",
        VERCEL_TARGET_ENV: "production",
        [releasePublicationCommitAllowlistEnvironmentVariable]:
          publicationCommit,
      }),
      "surface commit allowlist",
    );
    await writeFile(join(repositoryRoot, "source.txt"), "post-P15 Q15\n");
    await runSetupGit(repositoryRoot, ["add", "source.txt"]);
    await runSetupGit(repositoryRoot, ["commit", "-m", "future Q15"]);
    const descendant = await inspectReleaseSourceRepository({
      environment: {},
      repositoryRoot,
    });
    await expectRejection(
      verifyPublishedReleaseSourceEvidence(published, descendant, {
        expectedBaseCommit: baseCommit,
        expectedBundleCodeAuthorityCommit: bundleCodeAuthorityCommit,
        expectedCustodyRepairCommit: custodyRepairCommit,
        expectedHostTrustCommit: hostTrustCommit,
        expectedQ14Commit: q14Commit,
        expectedSignedReleaseProbeRepairCommit: signedReleaseProbeRepairCommit,
        expectedSurfaceCommit: surfaceCommit,
      }),
      "only direct parent",
    );
  });

  test("binds a Q15 provider build to the singleton surface and fixed ordered integration bridge", async () => {
    const contract = frozenPublishedV15Contract();
    const publicationCommit =
      "d96173c3556799cb203a4d659f29856180838029";
    const concurrentMainCommit =
      "559c272f1bd7a2f1195f1af3c493b4f73a8fb3d2";
    const integrationBridgeCommit =
      "af3296e59e2173e1e7737dee7a3194592de1105e";
    const surfaceCommit = "a".repeat(40);
    const publication = Object.freeze({
      candidateCommit: contract.release.source.commit,
      candidateContract: `${JSON.stringify(v15CandidateContractFixture, null, 2)}\n`,
      changedPath: "release-download.json" as const,
      publicationCommit,
      publicationContract: `${JSON.stringify(contract, null, 2)}\n`,
      status: "exact_candidate_publication_transition" as const,
    });
    const bridge = Object.freeze({
      concurrentMainCommit,
      integrationBridgeCommit,
      publication,
      status:
        "exact_candidate_publication_concurrent_main_integration_bridge" as const,
    });
    const surface = Object.freeze({
      bridge,
      status: "verified_publication_integration_bridge_surface" as const,
      surfaceCommit,
    });
    let inspected: Readonly<Record<string, string>> | undefined;
    expect(await verifyVercelReleaseSourceState(contract, {
      VERCEL: "1",
      VERCEL_ENV: "production",
      VERCEL_GIT_COMMIT_REF: "main",
      VERCEL_GIT_COMMIT_SHA: surfaceCommit,
      VERCEL_GIT_PROVIDER: "github",
      VERCEL_GIT_REPO_OWNER: "hraness",
      VERCEL_GIT_REPO_SLUG: "hra-v0",
      VERCEL_TARGET_ENV: "production",
      [releasePublicationCommitAllowlistEnvironmentVariable]: publicationCommit,
      [releaseSurfaceCommitAllowlistEnvironmentVariable]: surfaceCommit,
    }, undefined, undefined, (options) => {
      inspected = options;
      return Promise.resolve({
        bridge,
        publication,
        surface,
        tag: {
          commit: contract.release.source.commit,
          object: contract.release.source.tagObject,
          objectType: "tag",
          tag: contract.release.tag,
        },
      });
    })).toMatchObject({
      availability: "published",
      integrationBridgeCommit,
      publicationCommit,
      status: "verified_vercel_publication_integration_surface_binding",
      surfaceCommit,
    });
    expect(inspected).toEqual({
      candidateCommit: contract.release.source.commit,
      concurrentMainCommit,
      integrationBridgeCommit,
      publicationCommit,
      surfaceCommit,
      tag: contract.release.tag,
    });

    await expectRejection(
      verifyVercelReleaseSourceState(contract, {
        VERCEL: "1",
        VERCEL_ENV: "production",
        VERCEL_GIT_COMMIT_REF: "main",
        VERCEL_GIT_COMMIT_SHA: surfaceCommit,
        VERCEL_GIT_PROVIDER: "github",
        VERCEL_GIT_REPO_OWNER: "hraness",
        VERCEL_GIT_REPO_SLUG: "hra-v0",
        VERCEL_TARGET_ENV: "production",
        [releasePublicationCommitAllowlistEnvironmentVariable]: publicationCommit,
        [releaseSurfaceCommitAllowlistEnvironmentVariable]:
          `${surfaceCommit},${"b".repeat(40)}`,
      }),
      "singleton allowlisted",
    );
  });

  test("keeps the full release suite valid across a synthetic contract-only publication P", async () => {
    const candidate = historicalCandidateContractFixture;
    const historicalCandidate = candidate;
    const repositoryRoot = await realpath(
      await mkdtemp(join(tmpdir(), "hra-publication-protocol-")),
    );
    temporaryRoots.push(repositoryRoot);
    await runSetupGit(repositoryRoot, ["init", "--initial-branch=main"]);
    await runSetupGit(repositoryRoot, [
      "config",
      "user.email",
      "release-test@hraness.com",
    ]);
    await runSetupGit(repositoryRoot, [
      "config",
      "user.name",
      "HRA release test",
    ]);
    await writeFile(
      join(repositoryRoot, "release-download.json"),
      `${JSON.stringify(historicalCandidate, null, 2)}\n`,
    );
    await writeFile(join(repositoryRoot, "source.txt"), "candidate\n");
    await runSetupGit(repositoryRoot, ["add", "release-download.json", "source.txt"]);
    await runSetupGit(repositoryRoot, ["commit", "-m", "candidate C"]);
    const candidateCommit = (
      await runSetupGit(repositoryRoot, ["rev-parse", "HEAD"])
    ).trim();
    await runSetupGit(repositoryRoot, [
      "tag",
      "-a",
      candidate.release.tag,
      "-m",
      `HRA ${candidate.release.version} candidate`,
    ]);
    const tagObject = (
      await runSetupGit(repositoryRoot, [
        "rev-parse",
        `refs/tags/${candidate.release.tag}`,
      ])
    ).trim();
    const published = parseReleaseDownloadContract({
      ...candidate,
      repository: currentRepository,
      release: {
        ...candidate.release,
        artifacts: {
          checksum: {
            bytes: 81,
            name: candidate.release.artifacts.checksum.name,
            sha256: "a".repeat(64),
          },
          dmg: {
            bytes: 1_000,
            name: candidate.release.artifacts.dmg.name,
            sha256: "b".repeat(64),
          },
          manifest: {
            bytes: 2_000,
            name: candidate.release.artifacts.manifest.name,
            sha256: "c".repeat(64),
          },
        },
        availability: "published",
        source: {
          commit: candidateCommit,
          runtimeTreeSha256: "d".repeat(64),
          tagObject,
        },
      },
    });
    const publishedContract = asPublishedFixture(published);
    expect(publishedContract).toMatchObject({
      release: { build: 15, tag: "v0.1.14", version: "0.1.14" },
      repository: currentRepository,
    });
    await writeFile(
      join(repositoryRoot, "release-download.json"),
      `${JSON.stringify(historicalContract(publishedContract), null, 2)}\n`,
    );
    await runSetupGit(repositoryRoot, ["add", "release-download.json"]);
    await runSetupGit(repositoryRoot, ["commit", "-m", "publication P"]);
    const publicationCommit = (
      await runSetupGit(repositoryRoot, ["rev-parse", "HEAD"])
    ).trim();
    await Promise.all([
      writeFile(join(repositoryRoot, "archive.md"), "HRA v0 archive\n"),
      writeFile(
        join(repositoryRoot, "release-download.json"),
        `${JSON.stringify(publishedContract, null, 2)}\n`,
      ),
    ]);
    await runSetupGit(repositoryRoot, ["add", "archive.md", "release-download.json"]);
    await runSetupGit(repositoryRoot, ["commit", "-m", "archive surface Q"]);
    const surfaceCommit = (
      await runSetupGit(repositoryRoot, ["rev-parse", "HEAD"])
    ).trim();

    const source = await verifyReleaseSourceState(
      publishedContract,
      { environment: {}, publicationCommit, repositoryRoot },
    );
    if (source.availability !== "published") {
      throw new Error("Expected historical published source evidence.");
    }
    expect(source.status).toBe("verified_published_source");
    const verified = await verifyArchivedReleaseSourceEvidence(
      publishedContract,
      source.repository,
      publicationCommit,
    );
    expect(verified.publication).toMatchObject({
      candidateCommit,
      changedPath: "release-download.json",
      publicationCommit,
      status: "exact_candidate_publication_transition",
    });
    expect(verified.surface).toEqual({
      publicationCommit,
      repositoryMigrationCommit: surfaceCommit,
      status: "verified_descendant_archive_surface",
      surfaceCommit,
    });
    expect(verified.tag.commit).toBe(candidateCommit);
    expect(verified.repository.commit).not.toBe(candidateCommit);
    const objectStore = await inspectReleasePublicationObjectStore({
      candidateCommit,
      gitDirectory: join(repositoryRoot, ".git"),
      publicationCommit,
      tag: publishedContract.release.tag,
    });
    expect(objectStore.publication).toMatchObject({
      candidateCommit,
      publicationCommit,
      status: "exact_candidate_publication_transition",
    });
    expect(objectStore.tag).toEqual(verified.tag);
    expect(await verifyVercelReleaseSourceState(publishedContract, {
      VERCEL: "1",
      VERCEL_ENV: "production",
      VERCEL_GIT_COMMIT_REF: "main",
      VERCEL_GIT_COMMIT_SHA: surfaceCommit,
      VERCEL_GIT_PROVIDER: "github",
      VERCEL_GIT_REPO_OWNER: "hraness",
      VERCEL_GIT_REPO_SLUG: "hra-v0",
      VERCEL_TARGET_ENV: "production",
      [releasePublicationCommitAllowlistEnvironmentVariable]:
        publicationCommit,
      [releaseSurfaceCommitAllowlistEnvironmentVariable]:
        `${"f".repeat(40)},${surfaceCommit}`,
    }, undefined, () => Promise.resolve({
      publication: verified.publication,
      surface: verified.surface,
      tag: verified.tag,
    }))).toMatchObject({
      availability: "published",
      publicationCommit,
      repositoryMigrationCommit: surfaceCommit,
      status: "verified_vercel_archive_surface_binding",
      surfaceCommit,
    });

    await runSetupGit(repositoryRoot, [
      "switch",
      "-c",
      "invalid-current-coordinate-publication",
      candidateCommit,
    ]);
    await writeFile(
      join(repositoryRoot, "release-download.json"),
      `${JSON.stringify(publishedContract, null, 2)}\n`,
    );
    await runSetupGit(repositoryRoot, ["add", "release-download.json"]);
    await runSetupGit(repositoryRoot, ["commit", "-m", "invalid publication coordinate"]);
    const invalidPublicationRepository = await inspectReleaseSourceRepository({
      environment: {},
      repositoryRoot,
    });
    await expectRejection(
      verifyPublishedReleaseSourceEvidence(
        publishedContract,
        invalidPublicationRepository,
      ),
      historicalPublicationRepository,
    );
    await runSetupGit(repositoryRoot, ["switch", "main"]);

    await writeFile(join(repositoryRoot, "source.txt"), "follow-up\n");
    await runSetupGit(repositoryRoot, ["add", "source.txt"]);
    await runSetupGit(repositoryRoot, ["commit", "-m", "follow-up Q"]);
    const followUpRepository = await inspectReleaseSourceRepository({
      environment: {},
      repositoryRoot,
    });
    expect(await verifyArchivedReleaseSourceEvidence(
      publishedContract,
      followUpRepository,
      publicationCommit,
    )).toMatchObject({
      surface: { publicationCommit, surfaceCommit: followUpRepository.commit },
    });
    await expectRejection(
      verifyPublishedReleaseSourceEvidence(publishedContract, followUpRepository),
      "only direct parent",
    );

    await writeFile(
      join(repositoryRoot, "release-download.json"),
      `${JSON.stringify(candidate, null, 2)}\n`,
    );
    await runSetupGit(repositoryRoot, ["add", "release-download.json"]);
    await runSetupGit(repositoryRoot, ["commit", "-m", "rewrite release contract"]);
    const rewrittenRepository = await inspectReleaseSourceRepository({
      environment: {},
      repositoryRoot,
    });
    await expectRejection(
      verifyArchivedReleaseSourceEvidence(
        publishedContract,
        rewrittenRepository,
        publicationCommit,
      ),
      "may change only the reviewed release repository coordinate",
    );

    await writeFile(
      join(repositoryRoot, "release-download.json"),
      `${JSON.stringify(publishedContract, null, 2)}\n`,
    );
    await runSetupGit(repositoryRoot, ["add", "release-download.json"]);
    await runSetupGit(repositoryRoot, ["commit", "-m", "hide contract rewrite"]);
    const restoredRepository = await inspectReleaseSourceRepository({
      environment: {},
      repositoryRoot,
    });
    await expectRejection(
      verifyArchivedReleaseSourceEvidence(
        publishedContract,
        restoredRepository,
        publicationCommit,
      ),
      "must preserve exact historical H or archive A release contract bytes",
    );
  });

  test("rejects a schema-valid publication with forged tag evidence", async () => {
    const candidate = historicalCandidateContractFixture;
    const historicalCandidate = candidate;
    const repositoryRoot = await realpath(
      await mkdtemp(join(tmpdir(), "hra-bogus-publication-")),
    );
    temporaryRoots.push(repositoryRoot);
    await runSetupGit(repositoryRoot, ["init", "--initial-branch=main"]);
    await runSetupGit(repositoryRoot, [
      "config",
      "user.email",
      "release-test@hraness.com",
    ]);
    await runSetupGit(repositoryRoot, [
      "config",
      "user.name",
      "HRA release test",
    ]);
    await writeFile(
      join(repositoryRoot, "release-download.json"),
      `${JSON.stringify(historicalCandidate, null, 2)}\n`,
    );
    await writeFile(join(repositoryRoot, "source.txt"), "candidate\n");
    await runSetupGit(repositoryRoot, ["add", "release-download.json", "source.txt"]);
    await runSetupGit(repositoryRoot, ["commit", "-m", "candidate C"]);
    const candidateCommit = (
      await runSetupGit(repositoryRoot, ["rev-parse", "HEAD"])
    ).trim();
    await runSetupGit(repositoryRoot, [
      "tag",
      "-a",
      candidate.release.tag,
      "-m",
      `HRA ${candidate.release.version} candidate`,
    ]);
    const actualTagObject = (
      await runSetupGit(repositoryRoot, [
        "rev-parse",
        `refs/tags/${candidate.release.tag}`,
      ])
    ).trim();
    const forgedTagObject = actualTagObject === "f".repeat(40)
      ? "e".repeat(40)
      : "f".repeat(40);
    const bogusPublished = asPublishedFixture(parseReleaseDownloadContract({
      ...candidate,
      repository: currentRepository,
      release: {
        ...candidate.release,
        artifacts: {
          checksum: {
            bytes: 81,
            name: candidate.release.artifacts.checksum.name,
            sha256: "a".repeat(64),
          },
          dmg: {
            bytes: 1_000,
            name: candidate.release.artifacts.dmg.name,
            sha256: "b".repeat(64),
          },
          manifest: {
            bytes: 2_000,
            name: candidate.release.artifacts.manifest.name,
            sha256: "c".repeat(64),
          },
        },
        availability: "published",
        source: {
          commit: candidateCommit,
          runtimeTreeSha256: "d".repeat(64),
          tagObject: forgedTagObject,
        },
      },
    }));
    await writeFile(
      join(repositoryRoot, "release-download.json"),
      `${JSON.stringify(historicalContract(bogusPublished), null, 2)}\n`,
    );
    await runSetupGit(repositoryRoot, ["add", "release-download.json"]);
    await runSetupGit(repositoryRoot, ["commit", "-m", "bogus publication P"]);
    const bogusPublicationCommit = (
      await runSetupGit(repositoryRoot, ["rev-parse", "HEAD"])
    ).trim();
    await Promise.all([
      writeFile(join(repositoryRoot, "archive.md"), "HRA v0 archive\n"),
      writeFile(
        join(repositoryRoot, "release-download.json"),
        `${JSON.stringify(bogusPublished, null, 2)}\n`,
      ),
    ]);
    await runSetupGit(repositoryRoot, ["add", "archive.md", "release-download.json"]);
    await runSetupGit(repositoryRoot, ["commit", "-m", "archive surface Q"]);
    const surfaceCommit = (
      await runSetupGit(repositoryRoot, ["rev-parse", "HEAD"])
    ).trim();

    await expectRejection(
      verifyVercelReleaseSourceState(bogusPublished, {
        VERCEL: "1",
        VERCEL_ENV: "production",
        VERCEL_GIT_COMMIT_REF: "main",
        VERCEL_GIT_COMMIT_SHA: surfaceCommit,
        VERCEL_GIT_PROVIDER: "github",
        VERCEL_GIT_REPO_OWNER: "hraness",
        VERCEL_GIT_REPO_SLUG: "hra-v0",
        VERCEL_TARGET_ENV: "production",
        [releasePublicationCommitAllowlistEnvironmentVariable]: "a".repeat(40),
        [releaseSurfaceCommitAllowlistEnvironmentVariable]: "b".repeat(40),
      }),
      "not an allowlisted HRA v0 archive surface",
    );

    const bogusObjectStore = await inspectReleasePublicationObjectStore({
      candidateCommit,
      gitDirectory: join(repositoryRoot, ".git"),
      publicationCommit: bogusPublicationCommit,
      tag: bogusPublished.release.tag,
    });
    await expectRejection(
      verifyVercelReleaseSourceState(bogusPublished, {
        VERCEL: "1",
        VERCEL_ENV: "production",
        VERCEL_GIT_COMMIT_REF: "main",
        VERCEL_GIT_COMMIT_SHA: surfaceCommit,
        VERCEL_GIT_PROVIDER: "github",
        VERCEL_GIT_REPO_OWNER: "hraness",
        VERCEL_GIT_REPO_SLUG: "hra-v0",
        VERCEL_TARGET_ENV: "production",
        [releasePublicationCommitAllowlistEnvironmentVariable]:
          bogusPublicationCommit,
        [releaseSurfaceCommitAllowlistEnvironmentVariable]: surfaceCommit,
      }, undefined, () => Promise.resolve({
        ...bogusObjectStore,
        surface: {
          publicationCommit: bogusPublicationCommit,
          repositoryMigrationCommit: surfaceCommit,
          status: "verified_descendant_archive_surface" as const,
          surfaceCommit,
        },
      })),
      "canonical annotated release tag differs",
    );

    await expectRejection(
      verifyReleaseSourceState(
        bogusPublished,
        {
          environment: {},
          publicationCommit: bogusPublicationCommit,
          repositoryRoot,
        },
      ),
      "annotated release tag differs",
    );
  });
});

function historicalContract(
  contract: ReleaseDownloadContract,
): Omit<ReleaseDownloadContract, "repository"> & Readonly<{
  repository: typeof historicalPublicationRepository;
}> {
  return {
    ...contract,
    repository: historicalPublicationRepository,
  };
}

function asPublishedFixture(
  contract: ReleaseDownloadContract,
): PublishedReleaseDownloadContract {
  if (contract.release.availability !== "published") {
    throw new Error("Expected published fixture.");
  }
  return Object.freeze({
    release: contract.release,
    repository: contract.repository,
    schemaVersion: contract.schemaVersion,
  });
}

function frozenPublishedV15Contract(): PublishedReleaseDownloadContract {
  const history = readReleaseHistoryContract();
  const entry = history.tags.at(-1);
  if (entry?.tag !== "v0.1.15" || entry.release === null) {
    throw new Error("Expected frozen v0.1.15 history evidence.");
  }
  const artifact = (name: string) => {
    const value = entry.release?.assets.find((asset) => asset.name === name);
    if (value === undefined) throw new Error(`Missing frozen asset: ${name}`);
    return { bytes: value.bytes, name: value.name, sha256: value.sha256 };
  };
  return asPublishedFixture(parseReleaseDownloadContract({
    ...v15CandidateContractFixture,
    release: {
      ...v15CandidateContractFixture.release,
      artifacts: {
        checksum: artifact("HRA-0.1.15-16-macos-arm64.dmg.sha256"),
        dmg: artifact("HRA-0.1.15-16-macos-arm64.dmg"),
        manifest: artifact("HRA-0.1.15-16-release-manifest.json"),
      },
      availability: "published",
      source: {
        commit: entry.commit,
        runtimeTreeSha256:
          "18cf47ca1120cfa95d39b081a534717c8722fe346272c022f42e723700d83a8d",
        tagObject: entry.tagObject,
      },
    },
  }));
}

function generationTwoHistoryContract(
  contract: PublishedReleaseDownloadContract,
  publicationCommit: string,
): ReleaseHistoryContract {
  const generationOne = readReleaseHistoryContract();
  const releaseAssets = [
    contract.release.artifacts.checksum,
    contract.release.artifacts.dmg,
    contract.release.artifacts.manifest,
    ...correspondingSourceSpecs.map((spec, index) => ({
      bytes: 3_000 + index,
      name: spec.archiveName,
      sha256: String(index + 4).repeat(64),
    })),
  ].toSorted((left, right) =>
    left.name < right.name ? -1 : left.name > right.name ? 1 : 0
  ).map((asset, index) => ({
    ...asset,
    id: 910_000 + index,
  }));
  return parseReleaseHistoryContract({
    ...generationOne,
    generation: 2,
    publicationCommit,
    tags: [
      ...generationOne.tags,
      {
        build: contract.release.build,
        commit: contract.release.source.commit,
        objectKind: "annotated",
        release: {
          assets: releaseAssets,
          id: 910_100,
          immutable: true,
          prerelease: true,
          publishedAt: "2026-08-25T00:00:00Z",
        },
        tag: contract.release.tag,
        tagObject: contract.release.source.tagObject,
        version: contract.release.version,
      },
    ],
  });
}

function expectReleaseIdentity(contract: ReleaseDownloadContract): void {
  expect(contract).toMatchObject({
    release: {
      architecture: "Apple Silicon",
      artifacts: {
        checksum: { name: "HRA-0.1.16-17-macos-arm64.dmg.sha256" },
        dmg: { name: "HRA-0.1.16-17-macos-arm64.dmg" },
        manifest: { name: "HRA-0.1.16-17-release-manifest.json" },
      },
      build: 17,
      minimumMacOS: "13",
      tag: "v0.1.16",
      version: "0.1.16",
    },
    repository: currentRepository,
    schemaVersion: 1,
  });
  const artifacts = [
    contract.release.artifacts.checksum,
    contract.release.artifacts.dmg,
    contract.release.artifacts.manifest,
  ] as const;
  for (const artifact of artifacts) {
    if (contract.release.availability === "candidate") {
      expect(artifact.bytes).toBeNull();
      expect(artifact.sha256).toBeNull();
    } else {
      expect(artifact.bytes).toBeGreaterThan(0);
      expect(artifact.sha256).toMatch(/^[0-9a-f]{64}$/u);
    }
  }
  if (contract.release.availability === "candidate") {
    expect(contract.release.source).toEqual({
      commit: null,
      runtimeTreeSha256: null,
      tagObject: null,
    });
  } else {
    expect(contract.release.source.commit).toMatch(/^[0-9a-f]{40}$/u);
    expect(contract.release.source.runtimeTreeSha256).toMatch(/^[0-9a-f]{64}$/u);
    expect(contract.release.source.tagObject).toMatch(/^[0-9a-f]{40}$/u);
  }
}

function createRemoteReleaseFixture(
  candidate: typeof candidateContractFixture,
  options: Readonly<{
    frozenGenerationTwo?: boolean;
    manifestCommit?: string;
  }> = {},
) {
  const encoder = new TextEncoder();
  const commit = "c".repeat(40);
  const runtimeTreeSha256 = "d".repeat(64);
  const dmgBytes = encoder.encode("deterministic fixture DMG");
  const dmgSha256 = sha256Bytes(dmgBytes);
  const checksumBytes = encoder.encode(
    `${dmgSha256}  ${candidate.release.artifacts.dmg.name}\n`,
  );
  const correspondingSources = correspondingSourceSpecs.map((spec, index) => ({
    archiveName: spec.archiveName,
    bytes: 100 + index,
    commit: spec.commit,
    externalSources: spec.externalSources,
    project: spec.project,
    repository: spec.repository,
    sha256: sha256Bytes(encoder.encode(spec.archiveName)),
    submodules: spec.submodules,
  }));
  const releaseIdentity = {
    architecture: "arm64",
    build: candidate.release.build,
    commit: options.manifestCommit ?? commit,
    minimumMacOS: `${candidate.release.minimumMacOS}.0`,
    signing: productionReleaseSigning,
    version: candidate.release.version,
  } as const;
  const manifestBytes = encoder.encode(`${JSON.stringify({
    artifact: {
      bytes: dmgBytes.byteLength,
      name: candidate.release.artifacts.dmg.name,
      sha256: dmgSha256,
    },
    correspondingSources,
    release: { ...releaseIdentity, notarized: false },
    runtimeManifest: {
      release: releaseIdentity,
      runtime: { treeSha256: runtimeTreeSha256 },
      schemaVersion: 1,
    },
    runtimeTreeSha256,
    schemaVersion: 1,
    sourceTreeCleanAtPackaging: true,
  }, null, 2)}\n`);
  const contract = asPublishedFixture(parseReleaseDownloadContract({
    ...candidate,
    repository: currentRepository,
    release: {
      ...candidate.release,
      artifacts: {
        checksum: {
          bytes: checksumBytes.byteLength,
          name: candidate.release.artifacts.checksum.name,
          sha256: sha256Bytes(checksumBytes),
        },
        dmg: {
          bytes: dmgBytes.byteLength,
          name: candidate.release.artifacts.dmg.name,
          sha256: dmgSha256,
        },
        manifest: {
          bytes: manifestBytes.byteLength,
          name: candidate.release.artifacts.manifest.name,
          sha256: sha256Bytes(manifestBytes),
        },
      },
      availability: "published",
      source: {
        commit,
        runtimeTreeSha256,
        tagObject: "e".repeat(40),
      },
    },
  }));
  const metadataUrl =
    `https://api.github.com/repos/hraness/hra-v0/releases/tags/${contract.release.tag}`;
  const metadataAssets = [
    contract.release.artifacts.checksum,
    contract.release.artifacts.dmg,
    contract.release.artifacts.manifest,
    ...correspondingSources.map((source) => ({
      bytes: source.bytes,
      name: source.archiveName,
      sha256: source.sha256,
    })),
  ].map((artifact, index) => ({
    browser_download_url:
      `https://github.com/hraness/hra-v0/releases/download/${contract.release.tag}/${artifact.name}`,
    digest: `sha256:${artifact.sha256}`,
    id: 100 + index,
    name: artifact.name,
    size: artifact.bytes,
    state: "uploaded",
    url: `https://api.github.com/repos/hraness/hra-v0/releases/assets/${100 + index}`,
  }));
  const metadata = {
    assets: metadataAssets,
    draft: false,
    html_url:
      `${currentRepository}/releases/tag/${contract.release.tag}`,
    id: 18,
    immutable: true,
    prerelease: true,
    published_at: "2026-08-23T00:00:00Z",
    tag_name: contract.release.tag,
  };
  const checksumUrl = metadataAssets[0]?.browser_download_url ?? "";
  const dmgUrl = metadataAssets[1]?.browser_download_url ?? "";
  const manifestUrl = metadataAssets[2]?.browser_download_url ?? "";
  const requests: string[] = [];
  const generationOne = readReleaseHistoryContract();
  const frozenHistoryContract = options.frozenGenerationTwo === true
    ? parseReleaseHistoryContract({
        ...generationOne,
        generation: 2,
        publicationCommit: "f".repeat(40),
        tags: [
          ...generationOne.tags,
          {
            build: contract.release.build,
            commit: contract.release.source.commit,
            objectKind: "annotated",
            release: {
              assets: metadataAssets.map((asset) => ({
                bytes: asset.size,
                id: asset.id,
                name: asset.name,
                sha256: asset.digest.slice("sha256:".length),
              })).toSorted((left, right) =>
                left.name < right.name ? -1 : left.name > right.name ? 1 : 0
              ),
              id: metadata.id,
              immutable: true,
              prerelease: true,
              publishedAt: metadata.published_at,
            },
            tag: contract.release.tag,
            tagObject: contract.release.source.tagObject,
            version: contract.release.version,
          },
        ],
      })
    : undefined;
  const history = createRemoteHistoryFixture(
    frozenHistoryContract === undefined ? { contract, metadata } : undefined,
    requests,
    frozenHistoryContract,
  );
  const bodies = new Map<string, Uint8Array>([
    [checksumUrl, checksumBytes],
    [manifestUrl, manifestBytes],
  ]);
  const fetcher: ReleaseHttpFetcher = (url, init) => {
    if (new Headers(init.headers).has("authorization")) {
      return Promise.reject(new Error("Remote release gate must be credential-free."));
    }
    if (url === metadataUrl) {
      requests.push(url);
      const bytes = encoder.encode(JSON.stringify(metadata));
      return Promise.resolve(new Response(arrayBufferCopy(bytes), {
        headers: { "content-length": String(bytes.byteLength) },
        status: 200,
      }));
    }
    const bytes = bodies.get(url);
    if (bytes === undefined) {
      return history.fetcher(url, init);
    }
    requests.push(url);
    return Promise.resolve(new Response(arrayBufferCopy(bytes), {
      headers: { "content-length": String(bytes.byteLength) },
      status: 200,
    }));
  };
  return {
    checksumUrl,
    contract,
    dmgUrl,
    fetcher,
    manifestUrl,
    metadata,
    metadataUrl,
    requests,
    historyContract: history.contract,
  };
}

function createRemoteHistoryFixture(
  current?: Readonly<{
    contract: PublishedReleaseDownloadContract;
    metadata: Record<string, unknown>;
  }>,
  requests: string[] = [],
  contractOverride?: ReleaseHistoryContract,
) {
  const currentContract = readReleaseHistoryContract();
  const contract = contractOverride
    ?? (current?.contract.release.version === "0.1.15"
      ? parseReleaseHistoryContract({
          ...currentContract,
          generation: 0,
          publicationCommit: "6221f79b745f154882080936b961ff431569f33e",
          tags: currentContract.tags.slice(0, 8),
        })
      : currentContract);
  const apiRepository = "https://api.github.com/repos/hraness/hra-v0";
  const releases: Record<string, unknown>[] = contract.tags.flatMap((entry) =>
    entry.release === null
      ? []
      : [{
          assets: entry.release.assets.map((asset) => ({
            browser_download_url:
              `${currentRepository}/releases/download/${entry.tag}/${asset.name}`,
            digest: `sha256:${asset.sha256}`,
            id: asset.id,
            name: asset.name,
            size: asset.bytes,
            state: "uploaded",
            url: `${apiRepository}/releases/assets/${asset.id}`,
          })),
          draft: false,
          html_url: `${currentRepository}/releases/tag/${entry.tag}`,
          id: entry.release.id,
          immutable: true,
          prerelease: true,
          published_at: entry.release.publishedAt,
          tag_name: entry.tag,
        }]
  );
  const refs: Record<string, unknown>[] = contract.tags.map((entry) => ({
    object: {
      sha: entry.tagObject,
      type: "tag",
      url: `${apiRepository}/git/tags/${entry.tagObject}`,
    },
    ref: `refs/tags/${entry.tag}`,
  }));
  const tagObjects = new Map(contract.tags.map((entry) => [entry.tagObject, {
    object: {
      sha: entry.commit,
      type: "commit",
      url: `${apiRepository}/git/commits/${entry.commit}`,
    },
    sha: entry.tagObject,
    tag: entry.tag,
  }]));
  if (current !== undefined) {
    releases.push(current.metadata);
    refs.push({
      object: {
        sha: current.contract.release.source.tagObject,
        type: "tag",
        url:
          `${apiRepository}/git/tags/${current.contract.release.source.tagObject}`,
      },
      ref: `refs/tags/${current.contract.release.tag}`,
    });
    tagObjects.set(current.contract.release.source.tagObject, {
      object: {
        sha: current.contract.release.source.commit,
        type: "commit",
        url:
          `${apiRepository}/git/commits/${current.contract.release.source.commit}`,
      },
      sha: current.contract.release.source.tagObject,
      tag: current.contract.release.tag,
    });
  }
  const fetcher: ReleaseHttpFetcher = (url, init) => {
    requests.push(url);
    if (new Headers(init.headers).has("authorization")) {
      return Promise.reject(new Error("Remote history must be credential-free."));
    }
    if (url === `${apiRepository}/releases?per_page=100`) {
      return Promise.resolve(jsonResponse(releases));
    }
    if (url === `${apiRepository}/git/matching-refs/tags/v0.1`) {
      return Promise.resolve(jsonResponse(refs));
    }
    const tagPrefix = `${apiRepository}/git/tags/`;
    if (url.startsWith(tagPrefix)) {
      const object = tagObjects.get(url.slice(tagPrefix.length));
      if (object !== undefined) return Promise.resolve(jsonResponse(object));
    }
    return Promise.reject(new Error(`Unexpected history request: ${url}`));
  };
  return { contract, fetcher, requests };
}

function jsonResponse(value: unknown): Response {
  const body = JSON.stringify(value);
  return new Response(body, {
    headers: {
      "content-length": String(new TextEncoder().encode(body).byteLength),
    },
    status: 200,
  });
}

function sha256Bytes(bytes: Uint8Array): string {
  return createHash("sha256").update(bytes).digest("hex");
}

function arrayBufferCopy(bytes: Uint8Array): ArrayBuffer {
  const copy = new Uint8Array(bytes.byteLength);
  copy.set(bytes);
  return copy.buffer;
}

async function runSetupGit(
  repositoryRoot: string,
  args: readonly string[],
): Promise<string> {
  const child = Bun.spawn(["/usr/bin/git", ...args], {
    cwd: repositoryRoot,
    env: setupEnvironment,
    stdin: "ignore",
    stderr: "pipe",
    stdout: "pipe",
  });
  const [stdout, stderr, exitCode] = await Promise.all([
    new Response(child.stdout).text(),
    new Response(child.stderr).text(),
    child.exited,
  ]);
  if (exitCode !== 0) {
    throw new Error(`git ${args[0] ?? "command"} failed: ${stderr.trim()}`);
  }
  return stdout;
}

async function runReleaseContractCli(
  arguments_: readonly string[],
): Promise<Readonly<{ exitCode: number; stderr: string }>> {
  const child = Bun.spawn([
    process.execPath,
    fileURLToPath(new URL("../release-download-contract.ts", import.meta.url)),
    ...arguments_,
  ], {
    stdin: "ignore",
    stderr: "pipe",
    stdout: "ignore",
  });
  const [stderr, exitCode] = await Promise.all([
    new Response(child.stderr).text(),
    child.exited,
  ]);
  return { exitCode, stderr };
}

async function expectRejection(
  promise: Promise<unknown>,
  expectedMessage: string,
): Promise<void> {
  let rejection: unknown;
  try {
    await promise;
  } catch (error) {
    rejection = error;
  }
  expect(rejection).toBeInstanceOf(Error);
  expect((rejection as Error).message).toContain(expectedMessage);
}
