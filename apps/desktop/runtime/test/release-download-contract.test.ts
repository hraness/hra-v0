import { afterEach, describe, expect, test } from "bun:test";
import { createHash } from "node:crypto";
import { mkdtemp, readFile, realpath, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath } from "node:url";

import {
  parseHistoricalReleaseCandidateContract,
  parseReleaseDownloadContract,
  readReleaseDownloadContract,
  requirePublishedReleaseSource,
  verifyReleaseDownloadContract,
  verifyLocalReleaseCandidate,
  verifyPublishedReleaseArtifacts,
  verifyArchivedReleaseSourceEvidence,
  verifyPublishedReleaseSourceEvidence,
  verifyReleaseSourceGate,
  verifyReleaseSourceState,
  verifyRemoteReleaseState,
  releasePublicationCommitAllowlistEnvironmentVariable,
  releaseSurfaceCommitAllowlistEnvironmentVariable,
  verifyVercelReleaseSourceState,
  type HistoricalCandidateReleaseDownloadContract,
  type PublishedReleaseDownloadContract,
  type ReleaseDownloadContract,
  type ReleaseHttpFetcher,
} from "../release-download-contract";
import { correspondingSourceSpecs } from "../corresponding-sources";
import {
  inspectReleasePublicationObjectStore,
  inspectReleaseSourceRepository,
} from "../release-provenance";

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
const candidateContractFixture = parseHistoricalReleaseCandidateContract({
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
    source: {
      commit: null,
      runtimeTreeSha256: null,
      tagObject: null,
    },
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

describe("release and download convergence", () => {
  test("verifies the published-only v0.1.14 build 15 archive contract", async () => {
    const contract = await readReleaseDownloadContract();
    expectReleaseIdentity(contract);
    expect(await verifyReleaseDownloadContract()).toEqual(contract);
    const source = await verifyReleaseSourceGate();
    expect(source).toMatchObject({
      availability: "published",
      contract,
      status: "verified_published_source",
    });
    expect(await requirePublishedReleaseSource()).toMatchObject({ contract });
  });

  test("keeps candidate parsing historical and rejects it at every maintained gate", async () => {
    const historicalCandidate = candidateContractFixture;
    const maintainedCandidate = {
      ...historicalCandidate,
      repository: currentRepository,
    };
    expect(() => parseReleaseDownloadContract(maintainedCandidate)).toThrow();
    expect(
      parseHistoricalReleaseCandidateContract(historicalCandidate),
    ).toEqual(historicalCandidate);
    expect(() =>
      parseHistoricalReleaseCandidateContract(maintainedCandidate)
    ).toThrow();

    const unsafeCandidate = maintainedCandidate as unknown as ReleaseDownloadContract;
    let remoteRequests = 0;
    await expectRejection(
      verifyRemoteReleaseState(unsafeCandidate, () => {
        remoteRequests += 1;
        return Promise.reject(new Error("candidate must not use the network"));
      }),
      "must be published",
    );
    expect(remoteRequests).toBe(0);
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
    await expectRejection(
      verifyVercelReleaseSourceState(
        unsafeCandidate,
        candidateVercelEnvironment,
      ),
      "must be published",
    );
    await expectRejection(
      verifyReleaseSourceState(unsafeCandidate),
      "must be published",
    );
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

    expect(() => parseReleaseDownloadContract({
      ...candidate,
      repository: currentRepository,
    })).toThrow();

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
    )).toMatchObject({
      availability: "published",
      immutable: true,
      releaseId: 18,
      status: "verified_immutable_remote_release",
    });
    expect(fixture.requests).toEqual([
      fixture.metadataUrl,
      fixture.checksumUrl,
      fixture.manifestUrl,
    ]);
    expect(fixture.requests).not.toContain(fixture.dmgUrl);
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
    expect(workflow).toContain("run: bun run verify:remote-release");
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

  test("keeps the full release suite valid across a synthetic contract-only publication P", async () => {
    const candidate = candidateContractFixture;
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
    const publishedContract: PublishedReleaseDownloadContract = {
      release: published.release,
      repository: published.repository,
      schemaVersion: published.schemaVersion,
    };
    expectReleaseIdentity(publishedContract);
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

    const verified = await verifyReleaseSourceState(
      publishedContract,
      { environment: {}, publicationCommit, repositoryRoot },
    );
    if (verified.availability !== "published") {
      throw new Error("Expected published source evidence.");
    }
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
    expect(verified.status).toBe("verified_published_source");
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
    }, () => Promise.resolve({
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
    const candidate = candidateContractFixture;
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
    const bogusPublished = parseReleaseDownloadContract({
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
    });
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
      }, () => Promise.resolve({
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

function expectReleaseIdentity(contract: ReleaseDownloadContract): void {
  expect(contract).toMatchObject({
    release: {
      architecture: "Apple Silicon",
      artifacts: {
        checksum: { name: "HRA-0.1.14-15-macos-arm64.dmg.sha256" },
        dmg: { name: "HRA-0.1.14-15-macos-arm64.dmg" },
        manifest: { name: "HRA-0.1.14-15-release-manifest.json" },
      },
      build: 15,
      minimumMacOS: "13",
      tag: "v0.1.14",
      version: "0.1.14",
    },
    repository: currentRepository,
    schemaVersion: 1,
  });
  for (const artifact of Object.values(contract.release.artifacts)) {
    expect(artifact.bytes).toBeGreaterThan(0);
    expect(artifact.sha256).toMatch(/^[0-9a-f]{64}$/u);
  }
  expect(contract.release.source.commit).toMatch(/^[0-9a-f]{40}$/u);
  expect(contract.release.source.runtimeTreeSha256).toMatch(/^[0-9a-f]{64}$/u);
  expect(contract.release.source.tagObject).toMatch(/^[0-9a-f]{40}$/u);
}

function createRemoteReleaseFixture(
  candidate: HistoricalCandidateReleaseDownloadContract,
  options: Readonly<{ manifestCommit?: string }> = {},
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
    signing: "adhoc",
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
  const contract = parseReleaseDownloadContract({
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
  });
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
    id: 18,
    immutable: true,
    prerelease: true,
    tag_name: contract.release.tag,
  };
  const checksumUrl = metadataAssets[0]?.browser_download_url ?? "";
  const dmgUrl = metadataAssets[1]?.browser_download_url ?? "";
  const manifestUrl = metadataAssets[2]?.browser_download_url ?? "";
  const requests: string[] = [];
  const bodies = new Map<string, Uint8Array>([
    [checksumUrl, checksumBytes],
    [manifestUrl, manifestBytes],
  ]);
  const fetcher: ReleaseHttpFetcher = (url, init) => {
    requests.push(url);
    if (new Headers(init.headers).has("authorization")) {
      return Promise.reject(new Error("Remote release gate must be credential-free."));
    }
    if (url === metadataUrl) {
      const bytes = encoder.encode(JSON.stringify(metadata));
      return Promise.resolve(new Response(arrayBufferCopy(bytes), {
        headers: { "content-length": String(bytes.byteLength) },
        status: 200,
      }));
    }
    const bytes = bodies.get(url);
    if (bytes === undefined) {
      return Promise.reject(new Error(`Unexpected remote fixture request: ${url}`));
    }
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
  };
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
