import { createHash } from "node:crypto";
import { constants, type BigIntStats } from "node:fs";
import {
  chmod,
  lstat,
  mkdtemp,
  open,
  readFile,
  readdir,
  realpath,
  rm,
} from "node:fs/promises";
import { tmpdir } from "node:os";
import { isAbsolute, join, resolve } from "node:path";
import { isDeepStrictEqual } from "node:util";

import { dlopen, FFIType } from "bun:ffi";

import { z } from "@hra-internal/schema";

import { correspondingSourceSpecs } from "./corresponding-sources";
import { macosPackage } from "./macos-package-config";
import {
  readReleaseHistoryContract,
  verifyCanonicalRemoteReleaseTags,
  verifyRemoteReleaseHistoryState,
  type CurrentRemoteReleaseHistoryEntry,
  type ReleaseHistoryContract,
  type RemoteReleaseHistoryEvidence,
  type ReleaseHistoryTagVerifier,
} from "./release-history-contract";
import {
  HRA_CANONICAL_REPOSITORY,
  HRA_HISTORICAL_PUBLICATION_REPOSITORY,
  HRA_V0_C15_BASE_COMMIT,
  HRA_V0_C15_BUNDLE_CODE_AUTHORITY_COMMIT,
  HRA_V0_C15_CUSTODY_REPAIR_COMMIT,
  HRA_V0_C15_HOST_TRUST_COMMIT,
  HRA_V0_C15_REVIEWED_SURFACE_COMMIT,
  HRA_V0_C15_SIGNED_RELEASE_PROBE_REPAIR_COMMIT,
  HRA_V0_C16_COMPATIBILITY_COMMIT,
  HRA_V0_C17_TIMEOUT_CAP_COMMIT,
  HRA_V0_C18_COLD_CUSTODY_TIMEOUT_COMMIT,
  HRA_V0_C19_CUSTODY_TRANSITION_COMMIT,
  HRA_V0_C20_ZOMBIE_FENCE_COMMIT,
  HRA_V0_CURRENT_REPOSITORY,
  HRA_V0_P15_CONCURRENT_MAIN_COMMIT,
  HRA_V0_P15_INTEGRATION_BRIDGE_COMMIT,
  HRA_V0_P15_PUBLICATION_COMMIT,
  HRA_V0_Q14_SURFACE_COMMIT,
  HRA_V0_Q15_SURFACE_COMMIT,
  HRA_V0_R20_HEADLONG_READING_COMMIT,
  HRA_V0_R20_NOT_A_CODEX_TUI_READING_COMMIT,
  inspectArchiveReleaseSurface,
  inspectCanonicalArchiveRelease,
  inspectCanonicalReleasePublication,
  inspectCanonicalReleasePublicationIntegrationSurface,
  inspectCanonicalReleasePublicationSurface,
  inspectReleaseCandidateLineage,
  inspectReleaseHotfixCandidateLineage,
  inspectReleasePublicationAtCommit,
  inspectReleasePublicationIntegrationSurface,
  inspectReleasePublicationSurface,
  inspectReleasePublicationTransition,
  inspectReleaseSourceRepository,
  inspectReleaseTag,
  resolveReleaseCandidateCommit,
  resolveReleaseHotfixCandidateCommit,
  type ArchiveReleaseSurfaceEvidence,
  type CanonicalArchiveReleaseEvidence,
  type CanonicalReleasePublicationEvidence,
  type CanonicalReleasePublicationIntegrationSurfaceEvidence,
  type CanonicalReleasePublicationSurfaceEvidence,
  type ReleasePublicationIntegrationBridgeEvidence,
  type ReleasePublicationIntegrationSurfaceEvidence,
  type ReleasePublicationSurfaceEvidence,
  type ReleasePublicationEvidence,
  type ReleaseRepositoryEvidence,
  type ReleaseTagEvidence,
} from "./release-provenance";
import { hraReleaseIdentity } from "./release-identity";
import { productionReleaseSigning } from "./release-signing-authority";
import {
  verifyMacOSApp,
  verifyMacOSReleaseArtifacts,
  type CustodyProbeSupervisorAuthorityEvidence,
} from "./verify-macos-package";

const repositoryRoot = resolve(import.meta.dir, "../../..");
const releaseDownloadPath = join(repositoryRoot, "release-download.json");
const digestSchema = z.string().regex(/^[0-9a-f]{64}$/u);
const objectIdSchema = z.string().regex(/^[0-9a-f]{40}$/u);
const releaseCloneLibrary = process.platform === "darwin"
  ? dlopen("/usr/lib/libSystem.B.dylib", {
      fclonefileat: {
        args: [FFIType.i32, FFIType.i32, FFIType.cstring, FFIType.u32],
        returns: FFIType.i32,
      },
    })
  : null;
const emptyArtifactSchema = z.object({
  bytes: z.null(),
  name: z.string().min(1).max(200),
  sha256: z.null(),
}).strict();
const publishedArtifactSchema = z.object({
  bytes: z.number().int().positive().safe(),
  name: z.string().min(1).max(200),
  sha256: digestSchema,
}).strict();
const commonReleaseShape = {
  architecture: z.literal("Apple Silicon"),
  build: z.number().int().positive().safe(),
  minimumMacOS: z.string().regex(/^[1-9][0-9]*(?:\.[0-9]+)?$/u),
  tag: z.string().regex(/^v[0-9]+\.[0-9]+\.[0-9]+$/u),
  version: z.string().regex(/^[0-9]+\.[0-9]+\.[0-9]+$/u),
} as const;
const candidateReleaseSchema = z.object({
  ...commonReleaseShape,
  artifacts: z.object({
    checksum: emptyArtifactSchema,
    dmg: emptyArtifactSchema,
    manifest: emptyArtifactSchema,
  }).strict(),
  availability: z.literal("candidate"),
  source: z.object({
    commit: z.null(),
    runtimeTreeSha256: z.null(),
    tagObject: z.null(),
  }).strict(),
}).strict();
const publishedReleaseSchema = z.object({
  ...commonReleaseShape,
  artifacts: z.object({
    checksum: publishedArtifactSchema,
    dmg: publishedArtifactSchema,
    manifest: publishedArtifactSchema,
  }).strict(),
  availability: z.literal("published"),
  source: z.object({
    commit: objectIdSchema,
    runtimeTreeSha256: digestSchema,
    tagObject: objectIdSchema,
  }).strict(),
}).strict();
function refineReleaseDownloadContract(
  contract: Readonly<{
    release: z.infer<typeof candidateReleaseSchema>
      | z.infer<typeof publishedReleaseSchema>;
  }>,
  context: z.RefinementCtx,
): void {
  const { release } = contract;
  const dmg = `HRA-${release.version}-${release.build}-macos-arm64.dmg`;
  if (
    release.tag !== `v${release.version}`
    || release.artifacts.dmg.name !== dmg
    || release.artifacts.checksum.name !== `${dmg}.sha256`
    || release.artifacts.manifest.name
      !== `HRA-${release.version}-${release.build}-release-manifest.json`
  ) {
    context.addIssue({
      code: "custom",
      message: "Release tag and artifact names must derive from version and build.",
    });
  }
}

const releaseDownloadContractSchema = z.object({
  release: z.discriminatedUnion("availability", [
    candidateReleaseSchema,
    publishedReleaseSchema,
  ]),
  repository: z.literal(HRA_CANONICAL_REPOSITORY),
  schemaVersion: z.literal(1),
}).strict().superRefine(refineReleaseDownloadContract);

const historicalCandidateReleaseDownloadContractSchema = z.object({
  release: candidateReleaseSchema,
  repository: z.literal(HRA_HISTORICAL_PUBLICATION_REPOSITORY),
  schemaVersion: z.literal(1),
}).strict().superRefine(refineReleaseDownloadContract);

const historicalPublishedReleaseDownloadContractSchema = z.object({
  release: publishedReleaseSchema,
  repository: z.literal(HRA_HISTORICAL_PUBLICATION_REPOSITORY),
  schemaVersion: z.literal(1),
}).strict().superRefine(refineReleaseDownloadContract);

export type ReleaseDownloadContract = z.infer<typeof releaseDownloadContractSchema>;
export type HistoricalCandidateReleaseDownloadContract = z.infer<
  typeof historicalCandidateReleaseDownloadContractSchema
>;
export type PublishedReleaseDownloadContract = Readonly<{
  release: z.infer<typeof publishedReleaseSchema>;
  repository: typeof HRA_CANONICAL_REPOSITORY;
  schemaVersion: 1;
}>;

export interface LocalReleaseCandidateEvidence {
  readonly artifacts: Readonly<{
    checksum: ReleaseArtifactEvidence;
    dmg: ReleaseArtifactEvidence;
    manifest: ReleaseArtifactEvidence;
  }>;
  readonly commit: string;
  readonly releaseDirectory: string;
  readonly repository: typeof HRA_CANONICAL_REPOSITORY;
  readonly runtimeTreeSha256: string;
  readonly status: "verified_local_candidate";
  readonly tag: "absent" | ReleaseTagEvidence;
}

export interface PublishedReleaseCandidateEvidence {
  readonly commit: string;
  readonly contract: PublishedReleaseDownloadContract;
  readonly custodyProbeSupervisor: CustodyProbeSupervisorAuthorityEvidence;
  readonly repository: ReleaseRepositoryEvidence;
  readonly runtimeTreeSha256: string;
  readonly tag: ReleaseTagEvidence;
}

export interface PublishedReleaseSourceEvidence {
  readonly contract: PublishedReleaseDownloadContract;
  readonly publication: ReleasePublicationEvidence;
  readonly repository: ReleaseRepositoryEvidence;
  readonly tag: ReleaseTagEvidence;
}

export interface HistoricalPublishedReleaseSourceEvidence
  extends PublishedReleaseSourceEvidence {
  readonly surface: ArchiveReleaseSurfaceEvidence;
}

export interface PublishedReleaseIntegrationSurfaceSourceEvidence
  extends PublishedReleaseSourceEvidence {
  readonly bridge: ReleasePublicationIntegrationBridgeEvidence;
  readonly surface: ReleasePublicationIntegrationSurfaceEvidence;
}

export interface PublishedReleaseSurfaceSourceEvidence
  extends PublishedReleaseSourceEvidence {
  readonly surface: ReleasePublicationSurfaceEvidence;
}

export type ReleaseSourceGateEvidence =
  | Readonly<{
      availability: "candidate";
      contract: ReleaseDownloadContract;
      status: "valid_candidate_contract";
    }>
  | Readonly<PublishedReleaseSourceEvidence & {
      availability: "published";
      status: "verified_published_source";
    }>;

export const releasePublicationCommitAllowlistEnvironmentVariable =
  "HRA_RELEASE_PUBLICATION_COMMIT_ALLOWLIST" as const;
export const releaseSurfaceCommitAllowlistEnvironmentVariable =
  "HRA_V0_SURFACE_COMMIT_ALLOWLIST" as const;
export const releaseGitHubReadTokenEnvironmentVariable =
  "HRA_RELEASE_GITHUB_READ_TOKEN" as const;
export const HRA_V0_RELEASE_PUBLICATION_COMMIT =
  "6221f79b745f154882080936b961ff431569f33e" as const;
const releaseGitHubApiReadUrls = new Set([
  "https://api.github.com/repos/hraness/hra-v0/git/matching-refs/tags/v0.1",
  "https://api.github.com/repos/hraness/hra-v0/releases?per_page=100",
  "https://api.github.com/repos/hraness/hra-v0/releases/tags/v0.1.15",
  "https://api.github.com/repos/hraness/hra-v0/releases/tags/v0.1.16",
]);

export type VercelReleaseSourceGateEvidence =
  | Extract<ReleaseSourceGateEvidence, { availability: "candidate" }>
  | Readonly<{
      availability: "published";
      contract: PublishedReleaseDownloadContract;
      publicationCommit: string;
      status: "verified_vercel_publication_binding";
    }>
  | Readonly<{
      availability: "published";
      contract: PublishedReleaseDownloadContract;
      integrationBridgeCommit: string;
      publicationCommit: string;
      status: "verified_vercel_publication_integration_surface_binding";
      surfaceCommit: string;
    }>
  | Readonly<{
      availability: "published";
      contract: PublishedReleaseDownloadContract;
      publicationCommit: string;
      status: "verified_vercel_publication_surface_binding";
      surfaceCommit: string;
    }>
  | Readonly<{
      availability: "published";
      contract: PublishedReleaseDownloadContract;
      publicationCommit: string;
      repositoryMigrationCommit: string;
      status: "verified_vercel_archive_surface_binding";
      surfaceCommit: string;
    }>;

export type ReleaseHttpFetcher = (
  url: string,
  init: RequestInit,
) => Promise<Response>;

export type RemoteReleaseStateEvidence =
  | Readonly<{
      availability: "candidate";
      contract: ReleaseDownloadContract;
      history: Extract<
        RemoteReleaseHistoryEvidence,
        { assetCount: 49 | 56 }
      >;
      status: "verified_candidate_remote_collision_absence";
    }>
  | Readonly<{
      assets: LocalReleaseCandidateEvidence["artifacts"];
      availability: "published";
      contract: PublishedReleaseDownloadContract;
      history: Extract<
        RemoteReleaseHistoryEvidence,
        { assetCount: 56 | 63 }
      >;
      immutable: true;
      releaseId: number;
      status: "verified_immutable_remote_release";
    }>;
export type RemoteReleaseGateEvidence = RemoteReleaseStateEvidence;

type ReleaseSourceStateOptions = Readonly<{
  candidateBaseCommit?: string;
  candidateBundleCodeAuthorityCommit?: string;
  candidateC16Commit?: string;
  candidateC17Commit?: string;
  candidateC18Commit?: string;
  candidateC19Commit?: string;
  candidateC20Commit?: string;
  candidateHeadlongReadingCommit?: string;
  candidateNotACodexTuiReadingCommit?: string;
  candidateCustodyRepairCommit?: string;
  candidateHostTrustCommit?: string;
  candidateQ14Commit?: string;
  candidateQ15Commit?: string;
  candidateSignedReleaseProbeRepairCommit?: string;
  candidateSurfaceCommit?: string;
  concurrentMainCommit?: string;
  environment?: Readonly<Record<string, string | undefined>>;
  historyContract?: ReleaseHistoryContract;
  integrationBridgeCommit?: string;
  publicationCommit?: string;
  repositoryRoot?: string;
}>;

interface ReleaseArtifactEvidence {
  readonly bytes: number;
  readonly name: string;
  readonly sha256: string;
}

interface RemoteReleaseArtifactEvidence extends ReleaseArtifactEvidence {
  readonly downloadUrl: string;
  readonly id: number;
}

interface RemoteCorrespondingSourceEvidence {
  readonly archiveName: string;
  readonly bytes: number;
  readonly sha256: string;
}

interface ReleaseArtifactSetEvidence {
  readonly artifacts: LocalReleaseCandidateEvidence["artifacts"];
  readonly commit: string;
  readonly runtimeTreeSha256: string;
}

export function parseReleaseDownloadContract(value: unknown): ReleaseDownloadContract {
  return releaseDownloadContractSchema.parse(value);
}

export function parseHistoricalReleaseCandidateContract(
  value: unknown,
): HistoricalCandidateReleaseDownloadContract {
  return historicalCandidateReleaseDownloadContractSchema.parse(value);
}

export async function readReleaseDownloadContract(): Promise<ReleaseDownloadContract> {
  return parseReleaseDownloadContract(
    JSON.parse(await readFile(releaseDownloadPath, "utf8")) as unknown,
  );
}

export async function verifyReleaseDownloadContract(): Promise<ReleaseDownloadContract> {
  const contract = await readReleaseDownloadContract();
  const expectedNames = releaseArtifactNames();
  const release = contract.release;
  if (
    release.version !== macosPackage.version
    || release.build !== macosPackage.build
    || release.tag !== `v${macosPackage.version}`
    || release.minimumMacOS !== macosPackage.minimumMacOS.replace(/\.0$/u, "")
    || release.artifacts.dmg.name !== expectedNames.dmg
    || release.artifacts.checksum.name !== expectedNames.checksum
    || release.artifacts.manifest.name !== expectedNames.manifest
    || hraReleaseIdentity.version !== macosPackage.version
    || hraReleaseIdentity.build !== macosPackage.build
  ) {
    throw new Error("The download contract differs from the packaged HRA identity.");
  }
  await verifyVersionSurfaces();
  return contract;
}

/**
 * The maintained archive contract is published-only. It has authority to
 * expose downloads only after proving immutable C-to-P publication, the direct
 * annotated tag, and the exact repository-coordinate migration on a clean
 * descendant surface. This gate does not read or require packaged artifacts.
 */
export async function verifyReleaseSourceGate(): Promise<ReleaseSourceGateEvidence> {
  return await verifyReleaseSourceState(await verifyReleaseDownloadContract());
}

/**
 * Candidate state proves the frozen generation-1 9/8/56 history and the
 * absence of a v0.1.16 collision. Published state overlays its exact current
 * release on that frozen ledger and proves the combined 10/9/63 remote set.
 */
export async function verifyRemoteReleaseGate(
  fetcher: ReleaseHttpFetcher = defaultReleaseFetcher,
  tagVerifier: ReleaseHistoryTagVerifier = verifyCanonicalRemoteReleaseTags,
): Promise<RemoteReleaseGateEvidence> {
  return await verifyRemoteReleaseState(
    await verifyReleaseDownloadContract(),
    fetcher,
    tagVerifier,
  );
}

export async function verifyRemoteReleaseState(
  contract: ReleaseDownloadContract,
  fetcher: ReleaseHttpFetcher,
  tagVerifier?: ReleaseHistoryTagVerifier,
  historyContract: ReleaseHistoryContract = readReleaseHistoryContract(),
): Promise<RemoteReleaseStateEvidence> {
  if (contract.release.availability === "candidate") {
    const history = await verifyRemoteReleaseHistoryState(
      historyContract,
      fetcher,
      undefined,
      tagVerifier,
    );
    const expectedAssetCount = contract.release.version === "0.1.16" ? 56 : 49;
    if (history.assetCount !== expectedAssetCount) {
      throw new Error(
        `Candidate history differs from the frozen predecessor for ${contract.release.tag}.`,
      );
    }
    return Object.freeze({
      availability: "candidate",
      contract,
      history,
      status: "verified_candidate_remote_collision_absence",
    });
  }
  const publishedContract = asPublishedContract(contract);
  const metadataUrl =
    `https://api.github.com/repos/hraness/hra-v0/releases/tags/${publishedContract.release.tag}`;
  const metadataResponse = await fetcher(metadataUrl, {
    headers: githubJsonHeaders(),
    redirect: "error",
    signal: AbortSignal.timeout(30_000),
  });
  requireSuccessfulResponse(metadataResponse, "GitHub release metadata");
  const metadataBytes = await readBoundedResponse(
    metadataResponse,
    1_048_576,
    "GitHub release metadata",
  );
  const metadata = parseJsonRecord(metadataBytes, "GitHub release metadata");
  const releaseId = requirePositiveSafeInteger(
    metadata["id"],
    "GitHub release ID",
  );
  const publishedAt = requireReleaseTimestamp(
    metadata["published_at"],
    "GitHub release publication timestamp",
  );
  if (
    metadata["tag_name"] !== publishedContract.release.tag
    || metadata["draft"] !== false
    || metadata["prerelease"] !== true
    || metadata["immutable"] !== true
    || metadata["html_url"]
      !== `${HRA_V0_CURRENT_REPOSITORY}/releases/tag/${publishedContract.release.tag}`
  ) {
    throw new Error(
      "The GitHub release must be the exact published immutable HRA prerelease.",
    );
  }
  const rawAssets = metadata["assets"];
  if (!Array.isArray(rawAssets) || rawAssets.length > 64) {
    throw new Error("GitHub release assets must be one bounded array.");
  }
  const assetsByName = new Map<string, Record<string, unknown>>();
  for (const [index, value] of rawAssets.entries()) {
    const asset = requireRecord(value, `GitHub release asset ${index}`);
    const name = requireString(asset["name"], `GitHub release asset ${index} name`);
    if (assetsByName.has(name)) {
      throw new Error(`GitHub release asset name is duplicated: ${name}.`);
    }
    assetsByName.set(name, asset);
  }

  const expected = publishedContract.release.artifacts;
  const actualNames = [...assetsByName.keys()].sort();
  const expectedNames = [
    expected.checksum.name,
    expected.dmg.name,
    expected.manifest.name,
    ...correspondingSourceSpecs.map((spec) => spec.archiveName),
  ].sort();
  if (!isDeepStrictEqual(actualNames, expectedNames)) {
    throw new Error("The immutable GitHub release has the wrong exact asset set.");
  }
  const checksum = inspectRemoteReleaseAssetMetadata(
    publishedContract.release.tag,
    expected.checksum,
    assetsByName,
  );
  const dmg = inspectRemoteReleaseAssetMetadata(
    publishedContract.release.tag,
    expected.dmg,
    assetsByName,
  );
  const manifest = inspectRemoteReleaseAssetMetadata(
    publishedContract.release.tag,
    expected.manifest,
    assetsByName,
  );
  if (checksum.bytes > 4_096 || manifest.bytes > 16 * 1_024 * 1_024) {
    throw new Error("Remote release evidence files exceed their bounded sizes.");
  }
  const checksumBytes = await downloadSmallReleaseAsset(
    fetcher,
    checksum,
    "Remote checksum",
  );
  const manifestBytes = await downloadSmallReleaseAsset(
    fetcher,
    manifest,
    "Remote release manifest",
  );
  const expectedChecksum = `${dmg.sha256}  ${dmg.name}\n`;
  if (decodeUtf8(checksumBytes, "Remote checksum") !== expectedChecksum) {
    throw new Error("The remote checksum does not bind the published DMG.");
  }
  const correspondingSources = verifyRemoteReleaseManifest(
    manifestBytes,
    publishedContract,
  );
  const correspondingSourceAssets = correspondingSources.map((source) =>
    inspectRemoteReleaseAssetMetadata(
      publishedContract.release.tag,
      {
        bytes: source.bytes,
        name: source.archiveName,
        sha256: source.sha256,
      },
      assetsByName,
    )
  );
  const historyTag = publishedContract.release.tag;
  if (historyTag !== "v0.1.15" && historyTag !== "v0.1.16") {
    throw new Error("Published remote history requires a supported HRA v0 tag.");
  }
  const historyEntry: CurrentRemoteReleaseHistoryEntry = Object.freeze({
    assets: Object.freeze([
      checksum,
      dmg,
      manifest,
      ...correspondingSourceAssets,
    ].map(({ bytes, id, name, sha256 }) =>
      Object.freeze({ bytes, id, name, sha256 })
    ).toSorted((left, right) =>
      left.name < right.name ? -1 : left.name > right.name ? 1 : 0
    )),
    commit: publishedContract.release.source.commit,
    publishedAt,
    releaseId,
    tag: historyTag,
    tagObject: publishedContract.release.source.tagObject,
  });
  const currentEntry = publishedContract.release.version === "0.1.16"
    && historyContract.generation === 1
    ? historyEntry
    : publishedContract.release.version === "0.1.15"
      && historyContract.generation === 0
      ? historyEntry
      : undefined;
  if (
    (publishedContract.release.version === "0.1.15"
      && historyContract.generation === 1)
    || (publishedContract.release.version === "0.1.16"
      && historyContract.generation === 2)
  ) {
    verifyPublishedReleaseHistoryBinding(
      publishedContract,
      historyEntry,
      historyContract,
    );
  }
  const history = await verifyRemoteReleaseHistoryState(
    historyContract,
    fetcher,
    currentEntry,
    tagVerifier,
  );
  const expectedAssetCount = publishedContract.release.version === "0.1.16"
    ? 63
    : 56;
  if (history.assetCount !== expectedAssetCount) {
    throw new Error(
      `Published history is missing the exact ${publishedContract.release.tag} overlay.`,
    );
  }
  return Object.freeze({
    assets: Object.freeze({
      checksum: releaseArtifactEvidence(checksum),
      dmg: releaseArtifactEvidence(dmg),
      manifest: releaseArtifactEvidence(manifest),
    }),
    availability: "published",
    contract: publishedContract,
    history,
    immutable: true,
    releaseId,
    status: "verified_immutable_remote_release",
  });
}

/**
 * Vercel Git builds are intentionally shallow. The provider binds immutable P
 * and one allowlisted surface, then fetches canonical history to prove the
 * exact linear Q16 surface, the fixed P15 integration bridge, or the earlier
 * archive migration without trusting the ambient shallow .git directory.
 */
export async function verifyVercelReleaseSourceGate(
  environment: Readonly<Record<string, string | undefined>> = process.env,
): Promise<VercelReleaseSourceGateEvidence> {
  return await verifyVercelReleaseSourceState(
    await verifyReleaseDownloadContract(),
    environment,
  );
}

export async function verifyVercelReleaseSourceState(
  contract: ReleaseDownloadContract,
  environment: Readonly<Record<string, string | undefined>>,
  inspectCanonicalPublication: (options: Readonly<{
    candidateCommit: string;
    publicationCommit: string;
    tag: string;
  }>) => Promise<CanonicalReleasePublicationEvidence> =
    inspectCanonicalReleasePublication,
  inspectCanonicalArchive: (options: Readonly<{
    candidateCommit: string;
    publicationCommit: string;
    surfaceCommit: string;
    tag: string;
  }>) => Promise<CanonicalArchiveReleaseEvidence> =
    inspectCanonicalArchiveRelease,
  inspectCanonicalIntegration: (options: Readonly<{
    candidateCommit: string;
    concurrentMainCommit: string;
    integrationBridgeCommit: string;
    publicationCommit: string;
    surfaceCommit: string;
    tag: string;
  }>) => Promise<CanonicalReleasePublicationIntegrationSurfaceEvidence> =
    inspectCanonicalReleasePublicationIntegrationSurface,
  inspectCanonicalSurface: (options: Readonly<{
    candidateCommit: string;
    expectedC20Commit: string;
    expectedHeadlongReadingCommit: string;
    expectedNotACodexTuiReadingCommit: string;
    publicationCommit: string;
    surfaceCommit: string;
    tag: string;
  }>) => Promise<CanonicalReleasePublicationSurfaceEvidence> =
    inspectCanonicalReleasePublicationSurface,
  historyContract: ReleaseHistoryContract = readReleaseHistoryContract(),
): Promise<VercelReleaseSourceGateEvidence> {
  if (
    environment.VERCEL !== "1"
    || environment.VERCEL_GIT_PROVIDER !== "github"
    || environment.VERCEL_GIT_REPO_OWNER !== "hraness"
    || environment.VERCEL_GIT_REPO_SLUG !== "hra-v0"
  ) {
    throw new Error(
      "HRA provider source requires the canonical Vercel Git repository identity.",
    );
  }
  const target = environment.VERCEL_TARGET_ENV;
  if (
    (target !== "production" && target !== "preview")
    || environment.VERCEL_ENV !== target
  ) {
    throw new Error(
      "HRA provider source requires one exact Production or Preview Vercel target.",
    );
  }
  if (
    target === "production"
    && environment.VERCEL_GIT_COMMIT_REF !== "main"
  ) {
    throw new Error("HRA Production source must be deployed from main.");
  }
  const surfaceCommit = requireObjectId(
    environment.VERCEL_GIT_COMMIT_SHA,
    "Vercel source commit",
  );
  if (contract.release.availability === "candidate") {
    return Object.freeze({
      availability: "candidate",
      contract,
      status: "valid_candidate_contract",
    });
  }
  const publicationCommit = requireObjectId(
    environment[releasePublicationCommitAllowlistEnvironmentVariable],
    "Trusted Vercel publication commit allowlist",
  );
  const publishedContract = asPublishedContract(contract);
  if (publishedContract.release.version === "0.1.16") {
    if (
      historyContract.generation !== 2
      || historyContract.publicationCommit !== publicationCommit
    ) {
      throw new Error(
        "The v0.1.16 provider surface requires the exact generation-2 P16 release ledger.",
      );
    }
    const allowedSurfaceCommits = parseCommitAllowlist(
      environment[releaseSurfaceCommitAllowlistEnvironmentVariable],
      "Trusted HRA v0 surface commit allowlist",
    );
    if (
      allowedSurfaceCommits.size !== 1
      || !allowedSurfaceCommits.has(surfaceCommit)
    ) {
      throw new Error(
        "The Q16 provider source must be the singleton allowlisted HRA v0 surface commit.",
      );
    }
    verifyPublishedContractGenerationTwoHistoryBinding(
      publishedContract,
      historyContract,
    );
    const canonical = await inspectCanonicalSurface({
      candidateCommit: publishedContract.release.source.commit,
      expectedC20Commit: HRA_V0_C20_ZOMBIE_FENCE_COMMIT,
      expectedHeadlongReadingCommit: HRA_V0_R20_HEADLONG_READING_COMMIT,
      expectedNotACodexTuiReadingCommit:
        HRA_V0_R20_NOT_A_CODEX_TUI_READING_COMMIT,
      publicationCommit,
      surfaceCommit,
      tag: publishedContract.release.tag,
    });
    verifyPublicationContractTransition(
      publishedContract,
      canonical.publication,
    );
    verifyPublishedTagBinding(publishedContract, canonical.tag);
    if (
      canonical.surface.publication.publicationCommit !== publicationCommit
      || canonical.surface.surfaceCommit !== surfaceCommit
      || canonical.surface.status !== "verified_linear_publication_surface"
    ) {
      throw new Error(
        "The canonical Q16 publication surface differs from provider source.",
      );
    }
    return Object.freeze({
      availability: "published",
      contract: publishedContract,
      publicationCommit,
      status: "verified_vercel_publication_surface_binding",
      surfaceCommit,
    });
  }
  if (publishedContract.release.version === "0.1.15") {
    if (surfaceCommit === publicationCommit) {
      const canonical = await inspectCanonicalPublication({
        candidateCommit: publishedContract.release.source.commit,
        publicationCommit,
        tag: publishedContract.release.tag,
      });
      verifyPublicationContractTransition(
        publishedContract,
        canonical.publication,
      );
      verifyPublishedTagBinding(publishedContract, canonical.tag);
      return Object.freeze({
        availability: "published",
        contract: publishedContract,
        publicationCommit,
        status: "verified_vercel_publication_binding",
      });
    }
    const allowedSurfaceCommits = parseCommitAllowlist(
      environment[releaseSurfaceCommitAllowlistEnvironmentVariable],
      "Trusted HRA v0 surface commit allowlist",
    );
    if (
      allowedSurfaceCommits.size !== 1
      || !allowedSurfaceCommits.has(surfaceCommit)
    ) {
      throw new Error(
        "The Q15 provider source must be the singleton allowlisted HRA v0 surface commit.",
      );
    }
    verifyPublishedContractGenerationOneHistoryBinding(publishedContract);
    const canonical = await inspectCanonicalIntegration({
      candidateCommit: publishedContract.release.source.commit,
      concurrentMainCommit: HRA_V0_P15_CONCURRENT_MAIN_COMMIT,
      integrationBridgeCommit: HRA_V0_P15_INTEGRATION_BRIDGE_COMMIT,
      publicationCommit,
      surfaceCommit,
      tag: publishedContract.release.tag,
    });
    verifyPublicationContractTransition(
      publishedContract,
      canonical.publication,
    );
    verifyPublishedTagBinding(publishedContract, canonical.tag);
    if (
      canonical.bridge.concurrentMainCommit !== HRA_V0_P15_CONCURRENT_MAIN_COMMIT
      || canonical.bridge.integrationBridgeCommit
        !== HRA_V0_P15_INTEGRATION_BRIDGE_COMMIT
      || canonical.bridge.publication.publicationCommit !== publicationCommit
      || canonical.surface.surfaceCommit !== surfaceCommit
      || canonical.surface.status
        !== "verified_publication_integration_bridge_surface"
    ) {
      throw new Error(
        "The canonical Q15 integration surface differs from provider source.",
      );
    }
    return Object.freeze({
      availability: "published",
      contract: publishedContract,
      integrationBridgeCommit: HRA_V0_P15_INTEGRATION_BRIDGE_COMMIT,
      publicationCommit,
      status: "verified_vercel_publication_integration_surface_binding",
      surfaceCommit,
    });
  }
  const allowedSurfaceCommits = parseCommitAllowlist(
    environment[releaseSurfaceCommitAllowlistEnvironmentVariable],
    "Trusted HRA v0 surface commit allowlist",
  );
  if (!allowedSurfaceCommits.has(surfaceCommit)) {
    throw new Error(
      "The Vercel Git commit is not an allowlisted HRA v0 archive surface.",
    );
  }
  const canonical = await inspectCanonicalArchive({
    candidateCommit: publishedContract.release.source.commit,
    publicationCommit,
    surfaceCommit,
    tag: publishedContract.release.tag,
  });
  verifyHistoricalPublicationContractTransition(
    publishedContract,
    canonical.publication,
  );
  if (
    canonical.tag.commit !== publishedContract.release.source.commit
    || canonical.tag.object !== publishedContract.release.source.tagObject
  ) {
    throw new Error(
      "The canonical annotated release tag differs from the published contract.",
    );
  }
  if (
    canonical.surface.publicationCommit !== publicationCommit
    || canonical.surface.surfaceCommit !== surfaceCommit
    || canonical.surface.status !== "verified_descendant_archive_surface"
  ) {
    throw new Error(
      "The canonical HRA v0 archive surface differs from provider source.",
    );
  }
  const repositoryMigrationCommit = requireObjectId(
    canonical.surface.repositoryMigrationCommit,
    "Canonical archive repository migration commit",
  );
  return Object.freeze({
    availability: "published",
    contract: publishedContract,
    publicationCommit,
    repositoryMigrationCommit,
    status: "verified_vercel_archive_surface_binding",
    surfaceCommit,
  });
}

/**
 * Apply the conditional source rule to an already parsed and version-checked
 * contract. Repository options exist so focused tests can exercise the same
 * hermetic Git boundary in isolated repositories.
 */
export async function verifyReleaseSourceState(
  contract: ReleaseDownloadContract,
  options: ReleaseSourceStateOptions = {},
): Promise<ReleaseSourceGateEvidence> {
  if (contract.release.availability === "candidate") {
    const repository = await inspectReleaseSourceRepository(options);
    if (contract.release.version === "0.1.16") {
      const expectedC16Commit = options.candidateC16Commit
        ?? HRA_V0_C16_COMPATIBILITY_COMMIT;
      const expectedC17Commit = options.candidateC17Commit
        ?? HRA_V0_C17_TIMEOUT_CAP_COMMIT;
      const expectedC18Commit = options.candidateC18Commit
        ?? HRA_V0_C18_COLD_CUSTODY_TIMEOUT_COMMIT;
      const expectedC19Commit = options.candidateC19Commit
        ?? HRA_V0_C19_CUSTODY_TRANSITION_COMMIT;
      const expectedC20Commit = options.candidateC20Commit
        ?? HRA_V0_C20_ZOMBIE_FENCE_COMMIT;
      const expectedHeadlongReadingCommit =
        options.candidateHeadlongReadingCommit
        ?? HRA_V0_R20_HEADLONG_READING_COMMIT;
      const expectedNotACodexTuiReadingCommit =
        options.candidateNotACodexTuiReadingCommit
        ?? HRA_V0_R20_NOT_A_CODEX_TUI_READING_COMMIT;
      const expectedQ15Commit = options.candidateQ15Commit
        ?? HRA_V0_Q15_SURFACE_COMMIT;
      const candidateCommit = await resolveReleaseHotfixCandidateCommit(
        repository,
        {
          expectedC16Commit,
          expectedC17Commit,
          expectedC18Commit,
          expectedC19Commit,
          expectedC20Commit,
          expectedHeadlongReadingCommit,
          expectedNotACodexTuiReadingCommit,
          expectedQ15Commit,
        },
      );
      await inspectReleaseHotfixCandidateLineage(repository, {
        candidateCommit,
        expectedC16Commit,
        expectedC17Commit,
        expectedC18Commit,
        expectedC19Commit,
        expectedC20Commit,
        expectedHeadlongReadingCommit,
        expectedNotACodexTuiReadingCommit,
        expectedQ15Commit,
      });
      return Object.freeze({
        availability: "candidate",
        contract,
        status: "valid_candidate_contract",
      });
    }
    const expectedBundleCodeAuthorityCommit =
      options.candidateBundleCodeAuthorityCommit ??
      HRA_V0_C15_BUNDLE_CODE_AUTHORITY_COMMIT;
    const expectedCustodyRepairCommit =
      options.candidateCustodyRepairCommit ?? HRA_V0_C15_CUSTODY_REPAIR_COMMIT;
    const expectedHostTrustCommit =
      options.candidateHostTrustCommit ?? HRA_V0_C15_HOST_TRUST_COMMIT;
    const expectedSignedReleaseProbeRepairCommit =
      options.candidateSignedReleaseProbeRepairCommit ??
      HRA_V0_C15_SIGNED_RELEASE_PROBE_REPAIR_COMMIT;
    const expectedSurfaceCommit =
      options.candidateSurfaceCommit ?? HRA_V0_C15_REVIEWED_SURFACE_COMMIT;
    const candidateCommit = await resolveReleaseCandidateCommit(repository, {
      expectedSignedReleaseProbeRepairCommit,
    });
    await inspectReleaseCandidateLineage(repository, {
      candidateCommit,
      expectedBaseCommit:
        options.candidateBaseCommit ?? HRA_V0_C15_BASE_COMMIT,
      expectedBundleCodeAuthorityCommit,
      expectedCustodyRepairCommit,
      expectedHostTrustCommit,
      expectedQ14Commit:
        options.candidateQ14Commit ?? HRA_V0_Q14_SURFACE_COMMIT,
      expectedSignedReleaseProbeRepairCommit,
      expectedSurfaceCommit,
    });
    return Object.freeze({
      availability: "candidate",
      contract,
      status: "valid_candidate_contract",
    });
  }
  const publishedContract = asPublishedContract(contract);
  const repository = await inspectReleaseSourceRepository(options);
  const historyContract = options.historyContract ?? readReleaseHistoryContract();
  const v16SurfacePublicationCommit = publishedContract.release.version === "0.1.16"
    ? options.publicationCommit
      ?? (historyContract.generation === 2
        ? historyContract.publicationCommit
        : undefined)
    : undefined;
  const lineageExpectations = {
    expectedBaseCommit:
      options.candidateBaseCommit ?? HRA_V0_C15_BASE_COMMIT,
    expectedBundleCodeAuthorityCommit:
      options.candidateBundleCodeAuthorityCommit ??
      HRA_V0_C15_BUNDLE_CODE_AUTHORITY_COMMIT,
    expectedCustodyRepairCommit:
      options.candidateCustodyRepairCommit ?? HRA_V0_C15_CUSTODY_REPAIR_COMMIT,
    expectedHostTrustCommit:
      options.candidateHostTrustCommit ?? HRA_V0_C15_HOST_TRUST_COMMIT,
    expectedQ14Commit:
      options.candidateQ14Commit ?? HRA_V0_Q14_SURFACE_COMMIT,
    expectedSignedReleaseProbeRepairCommit:
      options.candidateSignedReleaseProbeRepairCommit ??
      HRA_V0_C15_SIGNED_RELEASE_PROBE_REPAIR_COMMIT,
    expectedSurfaceCommit:
      options.candidateSurfaceCommit ?? HRA_V0_C15_REVIEWED_SURFACE_COMMIT,
  } as const;
  const publicationCommit = options.publicationCommit
    ?? (publishedContract.release.version === "0.1.14"
      ? HRA_V0_RELEASE_PUBLICATION_COMMIT
      : HRA_V0_P15_PUBLICATION_COMMIT);
  const published = publishedContract.release.version === "0.1.14"
    ? await verifyArchivedReleaseSourceEvidence(
        publishedContract,
        repository,
        publicationCommit,
      )
    : publishedContract.release.version === "0.1.16"
      ? v16SurfacePublicationCommit !== undefined
          && repository.commit !== v16SurfacePublicationCommit
        ? await verifyPublishedReleaseSurfaceEvidence(
            publishedContract,
            repository,
            {
              expectedC16Commit:
                options.candidateC16Commit ?? HRA_V0_C16_COMPATIBILITY_COMMIT,
              expectedC17Commit:
                options.candidateC17Commit ?? HRA_V0_C17_TIMEOUT_CAP_COMMIT,
              expectedC18Commit:
                options.candidateC18Commit ??
                HRA_V0_C18_COLD_CUSTODY_TIMEOUT_COMMIT,
              expectedC19Commit:
                options.candidateC19Commit ??
                HRA_V0_C19_CUSTODY_TRANSITION_COMMIT,
              expectedC20Commit:
                options.candidateC20Commit ??
                HRA_V0_C20_ZOMBIE_FENCE_COMMIT,
              expectedHeadlongReadingCommit:
                options.candidateHeadlongReadingCommit ??
                HRA_V0_R20_HEADLONG_READING_COMMIT,
              expectedNotACodexTuiReadingCommit:
                options.candidateNotACodexTuiReadingCommit ??
                HRA_V0_R20_NOT_A_CODEX_TUI_READING_COMMIT,
              expectedQ15Commit:
                options.candidateQ15Commit ?? HRA_V0_Q15_SURFACE_COMMIT,
              historyContract,
              publicationCommit: v16SurfacePublicationCommit,
            },
          )
        : await verifyPublishedReleaseSourceEvidence(
            publishedContract,
            repository,
            {
              expectedC16Commit:
                options.candidateC16Commit ?? HRA_V0_C16_COMPATIBILITY_COMMIT,
              expectedC17Commit:
                options.candidateC17Commit ?? HRA_V0_C17_TIMEOUT_CAP_COMMIT,
              expectedC18Commit:
                options.candidateC18Commit ??
                HRA_V0_C18_COLD_CUSTODY_TIMEOUT_COMMIT,
              expectedC19Commit:
                options.candidateC19Commit ??
                HRA_V0_C19_CUSTODY_TRANSITION_COMMIT,
              expectedC20Commit:
                options.candidateC20Commit ??
                HRA_V0_C20_ZOMBIE_FENCE_COMMIT,
              expectedHeadlongReadingCommit:
                options.candidateHeadlongReadingCommit ??
                HRA_V0_R20_HEADLONG_READING_COMMIT,
              expectedNotACodexTuiReadingCommit:
                options.candidateNotACodexTuiReadingCommit ??
                HRA_V0_R20_NOT_A_CODEX_TUI_READING_COMMIT,
              expectedQ15Commit:
                options.candidateQ15Commit ?? HRA_V0_Q15_SURFACE_COMMIT,
            },
          )
      : repository.commit === publicationCommit
        ? await verifyPublishedReleaseSourceEvidence(
            publishedContract,
            repository,
            lineageExpectations,
          )
        : await verifyPublishedReleaseIntegrationSurfaceEvidence(
            publishedContract,
            repository,
            {
              ...lineageExpectations,
              concurrentMainCommit:
                options.concurrentMainCommit ?? HRA_V0_P15_CONCURRENT_MAIN_COMMIT,
              integrationBridgeCommit:
                options.integrationBridgeCommit
                ?? HRA_V0_P15_INTEGRATION_BRIDGE_COMMIT,
              publicationCommit,
            },
          );
  return Object.freeze({
    ...published,
    availability: "published",
    status: "verified_published_source",
  });
}

export async function verifyLocalReleaseCandidate(
  releaseDirectoryValue: string,
): Promise<LocalReleaseCandidateEvidence> {
  const releaseDirectory = await requireCanonicalReleaseDirectory(
    releaseDirectoryValue,
  );
  const contract = await verifyReleaseDownloadContract();
  if (contract.release.availability !== "candidate") {
    throw new Error("Local candidate verification requires a candidate download contract.");
  }
  const repository = await inspectReleaseSourceRepository();
  if (contract.release.version === "0.1.16") {
    await inspectReleaseHotfixCandidateLineage(repository);
  } else {
    await inspectReleaseCandidateLineage(repository);
  }
  const evidence = await inspectReleaseArtifactSet(releaseDirectory, contract);
  if (evidence.commit !== repository.commit) {
    throw new Error("The release manifest commit differs from the clean source commit.");
  }
  const tag = await inspectReleaseTag(repository, contract.release.tag);
  if (tag !== null && tag.commit !== repository.commit) {
    throw new Error("The release tag already points to another commit.");
  }
  return Object.freeze({
    artifacts: evidence.artifacts,
    commit: repository.commit,
    releaseDirectory,
    repository: HRA_CANONICAL_REPOSITORY,
    runtimeTreeSha256: evidence.runtimeTreeSha256,
    status: "verified_local_candidate",
    tag: tag ?? "absent",
  });
}

export async function requirePublishedReleaseSource(): Promise<
  PublishedReleaseSourceEvidence
> {
  const contract = await requirePublishedContract();
  const source = await verifyReleaseSourceState(contract);
  if (source.availability !== "published") {
    throw new Error("The HRA release source is not published.");
  }
  return source;
}

export async function verifyArchivedReleaseSourceEvidence(
  contract: PublishedReleaseDownloadContract,
  repository: ReleaseRepositoryEvidence,
  publicationCommit: string,
): Promise<HistoricalPublishedReleaseSourceEvidence> {
  const publication = await inspectReleasePublicationAtCommit(
    repository,
    contract.release.source.commit,
    publicationCommit,
  );
  verifyHistoricalPublicationContractTransition(contract, publication);
  const [surface, tag] = await Promise.all([
    inspectArchiveReleaseSurface(repository, publicationCommit),
    inspectReleaseTag(repository, contract.release.tag),
  ]);
  if (
    tag === null
    || tag.commit !== contract.release.source.commit
    || tag.object !== contract.release.source.tagObject
  ) {
    throw new Error("The local annotated release tag differs from the published contract.");
  }
  return Object.freeze({ contract, publication, repository, surface, tag });
}

export async function verifyPublishedReleaseIntegrationSurfaceEvidence(
  contract: PublishedReleaseDownloadContract,
  repository: ReleaseRepositoryEvidence,
  expectations: Readonly<{
    concurrentMainCommit: string;
    expectedBaseCommit?: string;
    expectedBundleCodeAuthorityCommit?: string;
    expectedCustodyRepairCommit?: string;
    expectedHostTrustCommit?: string;
    expectedQ14Commit?: string;
    expectedSignedReleaseProbeRepairCommit?: string;
    expectedSurfaceCommit?: string;
    integrationBridgeCommit: string;
    publicationCommit: string;
  }>,
): Promise<PublishedReleaseIntegrationSurfaceSourceEvidence> {
  const surface = await inspectReleasePublicationIntegrationSurface(
    repository,
    {
      candidateCommit: contract.release.source.commit,
      concurrentMainCommit: expectations.concurrentMainCommit,
      integrationBridgeCommit: expectations.integrationBridgeCommit,
      publicationCommit: expectations.publicationCommit,
    },
  );
  const publication = surface.bridge.publication;
  verifyPublicationContractTransition(contract, publication);
  await inspectReleaseCandidateLineage(repository, {
    candidateCommit: contract.release.source.commit,
    expectedBaseCommit:
      expectations.expectedBaseCommit ?? HRA_V0_C15_BASE_COMMIT,
    expectedBundleCodeAuthorityCommit:
      expectations.expectedBundleCodeAuthorityCommit ??
      HRA_V0_C15_BUNDLE_CODE_AUTHORITY_COMMIT,
    expectedCustodyRepairCommit:
      expectations.expectedCustodyRepairCommit ?? HRA_V0_C15_CUSTODY_REPAIR_COMMIT,
    expectedHostTrustCommit:
      expectations.expectedHostTrustCommit ?? HRA_V0_C15_HOST_TRUST_COMMIT,
    expectedQ14Commit:
      expectations.expectedQ14Commit ?? HRA_V0_Q14_SURFACE_COMMIT,
    expectedSignedReleaseProbeRepairCommit:
      expectations.expectedSignedReleaseProbeRepairCommit ??
      HRA_V0_C15_SIGNED_RELEASE_PROBE_REPAIR_COMMIT,
    expectedSurfaceCommit:
      expectations.expectedSurfaceCommit ?? HRA_V0_C15_REVIEWED_SURFACE_COMMIT,
  });
  const tag = await inspectReleaseTag(repository, contract.release.tag);
  if (tag === null) {
    throw new Error("The local annotated release tag is missing.");
  }
  verifyPublishedTagBinding(contract, tag);
  verifyPublishedContractGenerationOneHistoryBinding(contract);
  return Object.freeze({
    bridge: surface.bridge,
    contract,
    publication,
    repository,
    surface,
    tag,
  });
}

export async function verifyPublishedReleaseSurfaceEvidence(
  contract: PublishedReleaseDownloadContract,
  repository: ReleaseRepositoryEvidence,
  expectations: Readonly<{
    expectedC16Commit?: string;
    expectedC17Commit?: string;
    expectedC18Commit?: string;
    expectedC19Commit?: string;
    expectedC20Commit?: string;
    expectedHeadlongReadingCommit?: string;
    expectedNotACodexTuiReadingCommit?: string;
    expectedQ15Commit?: string;
    historyContract?: ReleaseHistoryContract;
    publicationCommit: string;
  }>,
): Promise<PublishedReleaseSurfaceSourceEvidence> {
  const historyContract = expectations.historyContract
    ?? readReleaseHistoryContract();
  if (
    historyContract.generation !== 2
    || historyContract.publicationCommit !== expectations.publicationCommit
  ) {
    throw new Error(
      "The v0.1.16 publication surface requires the exact generation-2 P16 release ledger.",
    );
  }
  const surface = await inspectReleasePublicationSurface(repository, {
    candidateCommit: contract.release.source.commit,
    publicationCommit: expectations.publicationCommit,
  });
  const publication = surface.publication;
  verifyPublicationContractTransition(contract, publication);
  await inspectReleaseHotfixCandidateLineage(repository, {
    candidateCommit: contract.release.source.commit,
    expectedC16Commit:
      expectations.expectedC16Commit ?? HRA_V0_C16_COMPATIBILITY_COMMIT,
    expectedC17Commit:
      expectations.expectedC17Commit ?? HRA_V0_C17_TIMEOUT_CAP_COMMIT,
    expectedC18Commit:
      expectations.expectedC18Commit ?? HRA_V0_C18_COLD_CUSTODY_TIMEOUT_COMMIT,
    expectedC19Commit:
      expectations.expectedC19Commit ?? HRA_V0_C19_CUSTODY_TRANSITION_COMMIT,
    expectedC20Commit:
      expectations.expectedC20Commit ?? HRA_V0_C20_ZOMBIE_FENCE_COMMIT,
    expectedHeadlongReadingCommit:
      expectations.expectedHeadlongReadingCommit ??
      HRA_V0_R20_HEADLONG_READING_COMMIT,
    expectedNotACodexTuiReadingCommit:
      expectations.expectedNotACodexTuiReadingCommit ??
      HRA_V0_R20_NOT_A_CODEX_TUI_READING_COMMIT,
    expectedQ15Commit:
      expectations.expectedQ15Commit ?? HRA_V0_Q15_SURFACE_COMMIT,
  });
  const tag = await inspectReleaseTag(repository, contract.release.tag);
  if (tag === null) {
    throw new Error("The local annotated release tag is missing.");
  }
  verifyPublishedTagBinding(contract, tag);
  verifyPublishedContractGenerationTwoHistoryBinding(contract, historyContract);
  return Object.freeze({
    contract,
    publication,
    repository,
    surface,
    tag,
  });
}

export async function verifyPublishedReleaseSourceEvidence(
  contract: PublishedReleaseDownloadContract,
  repository: ReleaseRepositoryEvidence,
  expectations: Readonly<{
    expectedBaseCommit?: string;
    expectedBundleCodeAuthorityCommit?: string;
    expectedCustodyRepairCommit?: string;
    expectedHostTrustCommit?: string;
    expectedQ14Commit?: string;
    expectedSignedReleaseProbeRepairCommit?: string;
    expectedSurfaceCommit?: string;
    expectedC16Commit?: string;
    expectedC17Commit?: string;
    expectedC18Commit?: string;
    expectedC19Commit?: string;
    expectedC20Commit?: string;
    expectedHeadlongReadingCommit?: string;
    expectedNotACodexTuiReadingCommit?: string;
    expectedQ15Commit?: string;
  }> = {},
): Promise<PublishedReleaseSourceEvidence> {
  const publication = await inspectReleasePublicationTransition(
    repository,
    contract.release.source.commit,
  );
  verifyPublicationContractTransition(contract, publication);
  if (contract.release.version === "0.1.15") {
    await inspectReleaseCandidateLineage(repository, {
      candidateCommit: contract.release.source.commit,
      expectedBaseCommit:
        expectations.expectedBaseCommit ?? HRA_V0_C15_BASE_COMMIT,
      expectedBundleCodeAuthorityCommit:
        expectations.expectedBundleCodeAuthorityCommit ??
        HRA_V0_C15_BUNDLE_CODE_AUTHORITY_COMMIT,
      expectedCustodyRepairCommit:
        expectations.expectedCustodyRepairCommit ??
        HRA_V0_C15_CUSTODY_REPAIR_COMMIT,
      expectedHostTrustCommit:
        expectations.expectedHostTrustCommit ?? HRA_V0_C15_HOST_TRUST_COMMIT,
      expectedQ14Commit:
        expectations.expectedQ14Commit ?? HRA_V0_Q14_SURFACE_COMMIT,
      expectedSignedReleaseProbeRepairCommit:
        expectations.expectedSignedReleaseProbeRepairCommit ??
        HRA_V0_C15_SIGNED_RELEASE_PROBE_REPAIR_COMMIT,
      expectedSurfaceCommit:
        expectations.expectedSurfaceCommit ??
        HRA_V0_C15_REVIEWED_SURFACE_COMMIT,
    });
  } else if (contract.release.version === "0.1.16") {
    await inspectReleaseHotfixCandidateLineage(repository, {
      candidateCommit: contract.release.source.commit,
      expectedC16Commit:
        expectations.expectedC16Commit ?? HRA_V0_C16_COMPATIBILITY_COMMIT,
      expectedC17Commit:
        expectations.expectedC17Commit ?? HRA_V0_C17_TIMEOUT_CAP_COMMIT,
      expectedC18Commit:
        expectations.expectedC18Commit ??
        HRA_V0_C18_COLD_CUSTODY_TIMEOUT_COMMIT,
      expectedC19Commit:
        expectations.expectedC19Commit ??
        HRA_V0_C19_CUSTODY_TRANSITION_COMMIT,
      expectedC20Commit:
        expectations.expectedC20Commit ??
        HRA_V0_C20_ZOMBIE_FENCE_COMMIT,
      expectedHeadlongReadingCommit:
        expectations.expectedHeadlongReadingCommit ??
        HRA_V0_R20_HEADLONG_READING_COMMIT,
      expectedNotACodexTuiReadingCommit:
        expectations.expectedNotACodexTuiReadingCommit ??
        HRA_V0_R20_NOT_A_CODEX_TUI_READING_COMMIT,
      expectedQ15Commit:
        expectations.expectedQ15Commit ?? HRA_V0_Q15_SURFACE_COMMIT,
    });
  }
  const tag = await inspectReleaseTag(repository, contract.release.tag);
  if (
    tag === null
    || tag.commit !== contract.release.source.commit
    || tag.object !== contract.release.source.tagObject
  ) {
    throw new Error("The local annotated release tag differs from the published contract.");
  }
  return Object.freeze({ contract, publication, repository, tag });
}

function verifyPublicationContractTransition(
  contract: PublishedReleaseDownloadContract,
  publication: ReleasePublicationEvidence,
): void {
  const published = parseContractText(
    publication.publicationContract,
    "The publication release contract is not JSON.",
  );
  if (!isDeepStrictEqual(published, contract)) {
    throw new Error(
      "The canonical publication contract differs from the provider source.",
    );
  }
  const candidate = parseContractText(
    publication.candidateContract,
    "The tagged candidate release contract is not JSON.",
  );
  if (candidate.release.availability !== "candidate") {
    throw new Error("The tagged source must contain the candidate release contract.");
  }
  const expectedCandidate: ReleaseDownloadContract = {
    release: {
      architecture: contract.release.architecture,
      artifacts: {
        checksum: {
          bytes: null,
          name: contract.release.artifacts.checksum.name,
          sha256: null,
        },
        dmg: {
          bytes: null,
          name: contract.release.artifacts.dmg.name,
          sha256: null,
        },
        manifest: {
          bytes: null,
          name: contract.release.artifacts.manifest.name,
          sha256: null,
        },
      },
      availability: "candidate",
      build: contract.release.build,
      minimumMacOS: contract.release.minimumMacOS,
      source: {
        commit: null,
        runtimeTreeSha256: null,
        tagObject: null,
      },
      tag: contract.release.tag,
      version: contract.release.version,
    },
    repository: contract.repository,
    schemaVersion: contract.schemaVersion,
  };
  if (!isDeepStrictEqual(candidate, expectedCandidate)) {
    throw new Error(
      "The publication contract is not the exact evidence-only transition from its candidate.",
    );
  }
}

function verifyPublishedReleaseHistoryBinding(
  contract: PublishedReleaseDownloadContract,
  currentEntry: CurrentRemoteReleaseHistoryEntry,
  history: ReleaseHistoryContract,
): void {
  const finalEntry = history.tags.at(-1);
  const finalRelease = finalEntry?.release;
  const expectedGeneration = contract.release.version === "0.1.15"
    ? 1
    : contract.release.version === "0.1.16"
      ? 2
      : null;
  if (
    expectedGeneration === null
    || history.generation !== expectedGeneration
    || finalEntry === undefined
    || finalRelease === null
    || finalRelease === undefined
    || finalEntry.tag !== contract.release.tag
    || finalEntry.version !== contract.release.version
    || finalEntry.build !== contract.release.build
    || finalEntry.commit !== contract.release.source.commit
    || finalEntry.tagObject !== contract.release.source.tagObject
    || finalRelease.id !== currentEntry.releaseId
    || finalRelease.publishedAt !== currentEntry.publishedAt
    || !isDeepStrictEqual(finalRelease.assets, currentEntry.assets)
  ) {
    throw new Error(
      `The generation-${String(expectedGeneration ?? "unsupported")} release ledger differs from the published ${contract.release.tag} evidence.`,
    );
  }
  const contractAssets = [
    contract.release.artifacts.checksum,
    contract.release.artifacts.dmg,
    contract.release.artifacts.manifest,
  ].toSorted((left, right) =>
    left.name < right.name ? -1 : left.name > right.name ? 1 : 0
  );
  const contractNames = new Set(contractAssets.map(({ name }) => name));
  const ledgerContractAssets = finalRelease.assets
    .filter(({ name }) => contractNames.has(name))
    .map(({ bytes, name, sha256 }) => ({ bytes, name, sha256 }));
  if (!isDeepStrictEqual(ledgerContractAssets, contractAssets)) {
    throw new Error(
      `The generation-${String(expectedGeneration)} release ledger does not bind the published download artifacts.`,
    );
  }
}

function verifyPublishedContractGenerationOneHistoryBinding(
  contract: PublishedReleaseDownloadContract,
): void {
  const history = readReleaseHistoryContract();
  const finalEntry = history.tags.at(-1);
  const finalRelease = finalEntry?.release;
  if (finalEntry === undefined || finalRelease === null || finalRelease === undefined) {
    throw new Error("The generation-1 release ledger has no final published release.");
  }
  verifyPublishedReleaseHistoryBinding(
    contract,
    Object.freeze({
      assets: finalRelease.assets,
      commit: finalEntry.commit,
      publishedAt: finalRelease.publishedAt,
      releaseId: finalRelease.id,
      tag: "v0.1.15",
      tagObject: finalEntry.tagObject,
    }),
    history,
  );
}

function verifyPublishedContractGenerationTwoHistoryBinding(
  contract: PublishedReleaseDownloadContract,
  history: ReleaseHistoryContract = readReleaseHistoryContract(),
): void {
  const finalEntry = history.tags.at(-1);
  const finalRelease = finalEntry?.release;
  if (
    history.generation !== 2
    || finalEntry === undefined
    || finalRelease === null
    || finalRelease === undefined
    || finalEntry.tag !== "v0.1.16"
  ) {
    throw new Error("The generation-2 release ledger has no final v0.1.16 release.");
  }
  verifyPublishedReleaseHistoryBinding(
    contract,
    Object.freeze({
      assets: finalRelease.assets,
      commit: finalEntry.commit,
      publishedAt: finalRelease.publishedAt,
      releaseId: finalRelease.id,
      tag: "v0.1.16",
      tagObject: finalEntry.tagObject,
    }),
    history,
  );
}

function verifyPublishedTagBinding(
  contract: PublishedReleaseDownloadContract,
  tag: ReleaseTagEvidence,
): void {
  if (
    tag.commit !== contract.release.source.commit
    || tag.object !== contract.release.source.tagObject
    || tag.tag !== contract.release.tag
  ) {
    throw new Error(
      "The canonical annotated release tag differs from the published contract.",
    );
  }
}

function verifyHistoricalPublicationContractTransition(
  contract: PublishedReleaseDownloadContract,
  publication: ReleasePublicationEvidence,
): void {
  const published = parseHistoricalPublishedContractText(
    publication.publicationContract,
    "The publication release contract is not JSON.",
  );
  const expectedArchiveContract: PublishedReleaseDownloadContract = {
    release: published.release,
    repository: HRA_CANONICAL_REPOSITORY,
    schemaVersion: published.schemaVersion,
  };
  if (!isDeepStrictEqual(expectedArchiveContract, contract)) {
    throw new Error(
      "The archive contract is not the exact repository-coordinate migration from publication P.",
    );
  }
  const candidate = parseHistoricalCandidateContractText(
    publication.candidateContract,
    "The tagged candidate release contract is not JSON.",
  );
  const expectedCandidate: HistoricalCandidateReleaseDownloadContract = {
    release: {
      architecture: contract.release.architecture,
      artifacts: {
        checksum: {
          bytes: null,
          name: contract.release.artifacts.checksum.name,
          sha256: null,
        },
        dmg: {
          bytes: null,
          name: contract.release.artifacts.dmg.name,
          sha256: null,
        },
        manifest: {
          bytes: null,
          name: contract.release.artifacts.manifest.name,
          sha256: null,
        },
      },
      availability: "candidate",
      build: contract.release.build,
      minimumMacOS: contract.release.minimumMacOS,
      source: {
        commit: null,
        runtimeTreeSha256: null,
        tagObject: null,
      },
      tag: contract.release.tag,
      version: contract.release.version,
    },
    repository: HRA_HISTORICAL_PUBLICATION_REPOSITORY,
    schemaVersion: published.schemaVersion,
  };
  if (!isDeepStrictEqual(candidate, expectedCandidate)) {
    throw new Error(
      "The publication contract is not the exact evidence-only transition from its candidate.",
    );
  }
}

function parseContractText(
  value: string,
  invalidJsonMessage: string,
): ReleaseDownloadContract {
  let parsed: unknown;
  try {
    parsed = JSON.parse(value) as unknown;
  } catch {
    throw new Error(invalidJsonMessage);
  }
  return parseReleaseDownloadContract(parsed);
}

function parseHistoricalCandidateContractText(
  value: string,
  invalidJsonMessage: string,
): HistoricalCandidateReleaseDownloadContract {
  let parsed: unknown;
  try {
    parsed = JSON.parse(value) as unknown;
  } catch {
    throw new Error(invalidJsonMessage);
  }
  return parseHistoricalReleaseCandidateContract(parsed);
}

function parseHistoricalPublishedContractText(
  value: string,
  invalidJsonMessage: string,
): z.infer<typeof historicalPublishedReleaseDownloadContractSchema> {
  let parsed: unknown;
  try {
    parsed = JSON.parse(value) as unknown;
  } catch {
    throw new Error(invalidJsonMessage);
  }
  return historicalPublishedReleaseDownloadContractSchema.parse(parsed);
}

export async function verifyPublishedReleaseCandidate(
  candidateAppPath: string,
): Promise<PublishedReleaseCandidateEvidence> {
  const published = await requirePublishedReleaseSource();
  const app = await verifyMacOSApp(candidateAppPath);
  if (
    app.commit !== published.contract.release.source.commit
    || app.treeSha256 !== published.contract.release.source.runtimeTreeSha256
  ) {
    throw new Error("The HRA candidate app differs from the published release provenance.");
  }
  return Object.freeze({
    commit: app.commit,
    contract: published.contract,
    custodyProbeSupervisor: app.custodyProbeSupervisor,
    repository: published.repository,
    runtimeTreeSha256: app.treeSha256,
    tag: published.tag,
  });
}

export async function verifyPublishedReleaseArtifacts(
  releaseDirectoryValue: string,
): Promise<ReleaseArtifactSetEvidence> {
  const releaseDirectory = await requireCanonicalReleaseDirectory(
    releaseDirectoryValue,
  );
  const published = await requirePublishedReleaseSource();
  const evidence = await inspectReleaseArtifactSet(
    releaseDirectory,
    published.contract,
  );
  if (
    evidence.commit !== published.contract.release.source.commit
    || evidence.runtimeTreeSha256
      !== published.contract.release.source.runtimeTreeSha256
    || JSON.stringify(evidence.artifacts)
      !== JSON.stringify(published.contract.release.artifacts)
  ) {
    throw new Error("Local release assets differ from the published release contract.");
  }
  return evidence;
}

async function requirePublishedContract(): Promise<PublishedReleaseDownloadContract> {
  return asPublishedContract(await verifyReleaseDownloadContract());
}

function asPublishedContract(
  contract: ReleaseDownloadContract,
): PublishedReleaseDownloadContract {
  if (contract.release.availability !== "published") {
    throw new Error(
      "The HRA release-download contract is not published.",
    );
  }
  return Object.freeze({
    release: contract.release,
    repository: contract.repository,
    schemaVersion: contract.schemaVersion,
  });
}

async function inspectReleaseArtifactSet(
  releaseDirectory: string,
  contract: ReleaseDownloadContract,
): Promise<ReleaseArtifactSetEvidence> {
  const snapshot = await snapshotReleaseArtifactSet(releaseDirectory);
  try {
    return await inspectReleaseArtifactSnapshot(snapshot, contract);
  } finally {
    await snapshot.remove();
  }
}

type ReleaseArtifactSetSnapshot = Readonly<{
  path: string;
  remove: () => Promise<void>;
}>;

function sameArtifactAuthority(
  expected: BigIntStats,
  actual: BigIntStats,
): boolean {
  return expected.dev === actual.dev
    && expected.ino === actual.ino
    && expected.mode === actual.mode
    && expected.nlink === actual.nlink
    && expected.uid === actual.uid
    && expected.gid === actual.gid
    && expected.size === actual.size
    && expected.mtimeNs === actual.mtimeNs
    && expected.ctimeNs === actual.ctimeNs
    && actual.isFile()
    && !actual.isSymbolicLink();
}

async function snapshotReleaseArtifactSet(
  releaseDirectory: string,
): Promise<ReleaseArtifactSetSnapshot> {
  if (releaseCloneLibrary === null) {
    throw new Error("Release artifact snapshots require macOS clonefile support.");
  }
  const names = (await readdir(releaseDirectory)).sort();
  if (
    names.length === 0
    || names.length > 16
    || names.some(name => (
      name.length === 0
      || name.length > 200
      || name.includes("/")
      || name.includes("\0")
      || name.includes("\n")
      || name.includes("\r")
    ))
  ) throw new Error("Release artifact snapshot inventory is unsafe.");
  const root = await realpath(await mkdtemp(join(
    tmpdir(),
    "hra-release-artifact-snapshot-",
  )));
  await chmod(root, 0o700);
  const destinationDirectory = await open(
    root,
    constants.O_RDONLY | constants.O_DIRECTORY,
  );
  const effectiveUserId = process.geteuid?.();
  try {
    if (effectiveUserId === undefined) {
      throw new Error("Release artifact snapshot custody is unavailable.");
    }
    for (const name of names) {
      const sourcePath = join(releaseDirectory, name);
      const before = await lstat(sourcePath, { bigint: true });
      const source = await open(
        sourcePath,
        constants.O_RDONLY | constants.O_NOFOLLOW,
      );
      try {
        const held = await source.stat({ bigint: true });
        if (
          !sameArtifactAuthority(before, held)
          || held.uid !== BigInt(effectiveUserId)
          || held.nlink !== 1n
          || held.size <= 0n
          || (held.mode & 0o022n) !== 0n
        ) throw new Error(`Release artifact authority is unsafe: ${name}`);
        const cloneResult = releaseCloneLibrary.symbols.fclonefileat(
          source.fd,
          destinationDirectory.fd,
          Buffer.from(`${name}\0`),
          0,
        );
        if (cloneResult !== 0) {
          throw new Error(`Release artifact clone failed: ${name}`);
        }
        const [heldAfter, namedAfter, cloned] = await Promise.all([
          source.stat({ bigint: true }),
          lstat(sourcePath, { bigint: true }),
          lstat(join(root, name), { bigint: true }),
        ]);
        if (
          !sameArtifactAuthority(held, heldAfter)
          || !sameArtifactAuthority(held, namedAfter)
          || !cloned.isFile()
          || cloned.isSymbolicLink()
          || cloned.uid !== BigInt(effectiveUserId)
          || cloned.nlink !== 1n
          || cloned.size !== held.size
        ) throw new Error(`Release artifact changed during snapshot: ${name}`);
      } finally {
        await source.close();
      }
    }
    if (JSON.stringify((await readdir(root)).sort()) !== JSON.stringify(names)) {
      throw new Error("Release artifact snapshot inventory differs.");
    }
    return Object.freeze({
      path: root,
      remove: () => rm(root, { force: true, recursive: true }),
    });
  } catch (error: unknown) {
    await destinationDirectory.close();
    await rm(root, { force: true, recursive: true });
    throw error;
  } finally {
    await destinationDirectory.close().catch(() => undefined);
  }
}

async function inspectReleaseArtifactSnapshot(
  snapshot: ReleaseArtifactSetSnapshot,
  contract: ReleaseDownloadContract,
): Promise<ReleaseArtifactSetEvidence> {
  const releaseDirectory = snapshot.path;
  await verifyMacOSReleaseArtifacts(releaseDirectory);
  const { checksum, dmg, manifest } = contract.release.artifacts;
  const [checksumEvidence, dmgEvidence, manifestEvidence] = await Promise.all([
    inspectRegularArtifact(releaseDirectory, checksum.name),
    inspectRegularArtifact(releaseDirectory, dmg.name),
    inspectRegularArtifact(releaseDirectory, manifest.name),
  ]);
  const checksumText = await readFile(join(releaseDirectory, checksum.name), "utf8");
  if (checksumText !== `${dmgEvidence.sha256}  ${dmg.name}\n`) {
    throw new Error("The release checksum file does not name the exact DMG hash.");
  }
  const manifestValue: unknown = JSON.parse(
    await readFile(join(releaseDirectory, manifest.name), "utf8"),
  );
  const manifestRecord = requireRecord(manifestValue, "Release manifest");
  const releaseRecord = requireRecord(manifestRecord["release"], "Release identity");
  const commit = requireObjectId(releaseRecord["commit"], "Release manifest commit");
  const runtimeTreeSha256 = requireDigest(
    manifestRecord["runtimeTreeSha256"],
    "Release runtime tree SHA-256",
  );
  return Object.freeze({
    artifacts: Object.freeze({
      checksum: checksumEvidence,
      dmg: dmgEvidence,
      manifest: manifestEvidence,
    }),
    commit,
    runtimeTreeSha256,
  });
}

async function inspectRegularArtifact(
  releaseDirectory: string,
  name: string,
): Promise<ReleaseArtifactEvidence> {
  const path = join(releaseDirectory, name);
  const status = await lstat(path);
  if (!status.isFile() || status.isSymbolicLink()) {
    throw new Error(`Release artifact must be a regular file: ${name}`);
  }
  return Object.freeze({
    bytes: status.size,
    name,
    sha256: await sha256File(path),
  });
}

async function verifyVersionSurfaces(): Promise<void> {
  const [appManifest, packageText, buildManifest, buildSource, lockText] =
    await Promise.all([
      readFile(join(repositoryRoot, "apps/desktop/app.zon"), "utf8"),
      readFile(join(repositoryRoot, "apps/desktop/package.json"), "utf8"),
      readFile(join(repositoryRoot, "apps/desktop/build.zig.zon"), "utf8"),
      readFile(join(repositoryRoot, "apps/desktop/build.zig"), "utf8"),
      readFile(join(repositoryRoot, "bun.lock"), "utf8"),
    ]);
  const packageValue = requireRecord(
    JSON.parse(packageText) as unknown,
    "Desktop package manifest",
  );
  const lockVersion = /"apps\/desktop":\s*\{[\s\S]*?"version":\s*"([^"]+)"/u
    .exec(lockText)?.[1];
  const buildNumber = /const release_build_number = ([0-9]+);/u
    .exec(buildSource)?.[1];
  if (
    zonLiteral(appManifest, "version") !== macosPackage.version
    || zonLiteral(appManifest, "id") !== macosPackage.bundleIdentifier
    || zonLiteral(appManifest, "display_name") !== macosPackage.displayName
    || zonLiteral(buildManifest, "version") !== macosPackage.version
    || packageValue["version"] !== macosPackage.version
    || lockVersion !== macosPackage.version
    || buildNumber !== String(macosPackage.build)
  ) {
    throw new Error("A checked desktop version surface differs from the HRA release identity.");
  }
}

function releaseArtifactNames() {
  const dmg = `${macosPackage.artifactBaseName}.dmg`;
  return Object.freeze({
    checksum: `${dmg}.sha256`,
    dmg,
    manifest:
      `HRA-${macosPackage.version}-${macosPackage.build}-release-manifest.json`,
  });
}

function zonLiteral(source: string, key: string): string {
  const value = new RegExp(`\\.${key}\\s*=\\s*"([^"]+)"`, "u").exec(source)?.[1];
  if (value === undefined) throw new Error(`A Zig manifest is missing ${key}.`);
  return value;
}

async function requireCanonicalReleaseDirectory(value: string): Promise<string> {
  if (!isAbsolute(value) || resolve(value) !== value) {
    throw new Error("Release directory must be an absolute normalized path.");
  }
  const status = await lstat(value);
  if (!status.isDirectory() || status.isSymbolicLink() || await realpath(value) !== value) {
    throw new Error("Release directory must be a real canonical directory.");
  }
  return value;
}

async function sha256File(path: string): Promise<string> {
  const handle = await open(path, "r");
  const hasher = createHash("sha256");
  try {
    for await (const chunk of handle.readableWebStream()) {
      hasher.update(chunk as Uint8Array);
    }
  } finally {
    await handle.close();
  }
  return hasher.digest("hex");
}

export function applyReleaseGitHubReadAuthorization(
  url: string,
  init: RequestInit,
  environment: Readonly<Record<string, string | undefined>>,
): RequestInit {
  const headers = new Headers(init.headers);
  if (headers.has("authorization")) {
    throw new Error("Release HTTP requests must not supply ambient authorization.");
  }
  const apiRead = releaseGitHubApiReadUrls.has(url);
  const assetRead = isExactReleaseAssetDownloadUrl(url);
  if (!apiRead && !assetRead) {
    throw new Error("The release HTTP request target is not allowlisted.");
  }
  if (
    (init.method !== undefined && init.method !== "GET")
    || (init.body !== undefined && init.body !== null)
    || init.redirect !== (apiRead ? "error" : "follow")
  ) {
    throw new Error("The release HTTP request shape is invalid.");
  }
  const configured = environment[releaseGitHubReadTokenEnvironmentVariable];
  const inGitHubActions = environment["GITHUB_ACTIONS"] === "true";
  if (configured === undefined) {
    if (inGitHubActions) {
      throw new Error("GitHub Actions release verification requires its read token.");
    }
    return { ...init, headers };
  }
  if (
    !inGitHubActions
    || environment["GITHUB_REPOSITORY"] !== "hraness/hra-v0"
    || environment["GITHUB_API_URL"] !== "https://api.github.com"
    || configured.length < 20
    || configured.length > 4_096
    || !/^ghs_[A-Za-z0-9._-]+$/u.test(configured)
  ) {
    throw new Error("The GitHub Actions release read token is invalid.");
  }
  if (apiRead) headers.set("Authorization", `Bearer ${configured}`);
  return { ...init, headers };
}

function isExactReleaseAssetDownloadUrl(url: string): boolean {
  const artifacts = releaseArtifactNames();
  const names = [
    artifacts.checksum,
    artifacts.manifest,
  ];
  return names.some((name) =>
    url
      === `${HRA_V0_CURRENT_REPOSITORY}/releases/download/v${macosPackage.version}/${name}`
  );
}

function defaultReleaseFetcher(url: string, init: RequestInit): Promise<Response> {
  return fetch(
    url,
    applyReleaseGitHubReadAuthorization(url, init, process.env),
  );
}

function githubJsonHeaders(): HeadersInit {
  return {
    Accept: "application/vnd.github+json",
    "User-Agent": "hraness-hra-release-verifier",
    "X-GitHub-Api-Version": "2026-03-10",
  };
}

function requireSuccessfulResponse(response: Response, label: string): void {
  if (!response.ok || response.status !== 200) {
    throw new Error(`${label} returned HTTP ${response.status}.`);
  }
}

async function readBoundedResponse(
  response: Response,
  maximumBytes: number,
  label: string,
): Promise<Uint8Array> {
  if (response.body === null) throw new Error(`${label} has no response body.`);
  const declaredLength = response.headers.get("content-length");
  if (declaredLength !== null) {
    const parsedLength = Number(declaredLength);
    if (
      !Number.isSafeInteger(parsedLength)
      || parsedLength < 0
      || parsedLength > maximumBytes
    ) {
      throw new Error(`${label} has an invalid or oversized Content-Length.`);
    }
  }
  const chunks: Uint8Array[] = [];
  let total = 0;
  const reader = response.body.getReader();
  try {
    while (true) {
      const result = await reader.read();
      if (result.done) break;
      total += result.value.byteLength;
      if (total > maximumBytes) {
        throw new Error(`${label} exceeds its byte limit.`);
      }
      chunks.push(result.value);
    }
  } finally {
    reader.releaseLock();
  }
  const bytes = new Uint8Array(total);
  let offset = 0;
  for (const chunk of chunks) {
    bytes.set(chunk, offset);
    offset += chunk.byteLength;
  }
  return bytes;
}

function parseJsonRecord(bytes: Uint8Array, label: string): Record<string, unknown> {
  let value: unknown;
  try {
    value = JSON.parse(decodeUtf8(bytes, label)) as unknown;
  } catch (error) {
    if (error instanceof Error && error.message.includes("UTF-8")) throw error;
    throw new Error(`${label} is not valid JSON.`);
  }
  return requireRecord(value, label);
}

function decodeUtf8(bytes: Uint8Array, label: string): string {
  try {
    return new TextDecoder("utf-8", { fatal: true }).decode(bytes);
  } catch {
    throw new Error(`${label} is not valid UTF-8.`);
  }
}

function inspectRemoteReleaseAssetMetadata(
  tag: string,
  expected: PublishedReleaseDownloadContract["release"]["artifacts"]["dmg"],
  assetsByName: ReadonlyMap<string, Record<string, unknown>>,
): RemoteReleaseArtifactEvidence {
  const metadata = assetsByName.get(expected.name);
  if (metadata === undefined) {
    throw new Error(`The GitHub release is missing ${expected.name}.`);
  }
  const id = requirePositiveSafeInteger(
    metadata["id"],
    `GitHub release asset ${expected.name} ID`,
  );
  const expectedDownloadUrl =
    `${HRA_V0_CURRENT_REPOSITORY}/releases/download/${tag}/${expected.name}`;
  const expectedApiUrl =
    `https://api.github.com/repos/hraness/hra-v0/releases/assets/${id}`;
  if (
    metadata["state"] !== "uploaded"
    || metadata["size"] !== expected.bytes
    || metadata["digest"] !== `sha256:${expected.sha256}`
    || metadata["browser_download_url"] !== expectedDownloadUrl
    || metadata["url"] !== expectedApiUrl
  ) {
    throw new Error(
      `GitHub release metadata differs from published evidence for ${expected.name}.`,
    );
  }
  return Object.freeze({
    bytes: expected.bytes,
    downloadUrl: expectedDownloadUrl,
    id,
    name: expected.name,
    sha256: expected.sha256,
  });
}

async function downloadSmallReleaseAsset(
  fetcher: ReleaseHttpFetcher,
  artifact: RemoteReleaseArtifactEvidence,
  label: string,
): Promise<Uint8Array> {
  const response = await fetcher(artifact.downloadUrl, {
    headers: {
      Accept: "application/octet-stream",
      "User-Agent": "hraness-hra-release-verifier",
    },
    redirect: "follow",
    signal: AbortSignal.timeout(60_000),
  });
  requireSuccessfulResponse(response, label);
  const bytes = await readBoundedResponse(response, artifact.bytes, label);
  if (bytes.byteLength !== artifact.bytes) {
    throw new Error(`${label} has the wrong byte count.`);
  }
  const sha256 = createHash("sha256").update(bytes).digest("hex");
  if (sha256 !== artifact.sha256) {
    throw new Error(`${label} has the wrong SHA-256 digest.`);
  }
  return bytes;
}

function releaseArtifactEvidence(
  artifact: RemoteReleaseArtifactEvidence,
): ReleaseArtifactEvidence {
  return Object.freeze({
    bytes: artifact.bytes,
    name: artifact.name,
    sha256: artifact.sha256,
  });
}

function verifyRemoteReleaseManifest(
  bytes: Uint8Array,
  contract: PublishedReleaseDownloadContract,
): readonly RemoteCorrespondingSourceEvidence[] {
  const manifest = parseJsonRecord(bytes, "Remote release manifest");
  const artifact = requireRecord(
    manifest["artifact"],
    "Remote release manifest artifact",
  );
  const release = requireRecord(
    manifest["release"],
    "Remote release manifest identity",
  );
  const runtimeManifest = requireRecord(
    manifest["runtimeManifest"],
    "Remote runtime manifest",
  );
  const runtimeRelease = requireRecord(
    runtimeManifest["release"],
    "Remote runtime manifest release",
  );
  const runtime = requireRecord(
    runtimeManifest["runtime"],
    "Remote runtime manifest runtime",
  );
  const rawSources = manifest["correspondingSources"];
  if (
    !Array.isArray(rawSources)
    || rawSources.length !== correspondingSourceSpecs.length
  ) {
    throw new Error(
      "The remote release manifest has the wrong corresponding-source set.",
    );
  }
  const expected = contract.release;
  if (
    manifest["schemaVersion"] !== 1
    || artifact["bytes"] !== expected.artifacts.dmg.bytes
    || artifact["name"] !== expected.artifacts.dmg.name
    || artifact["sha256"] !== expected.artifacts.dmg.sha256
    || release["architecture"] !== "arm64"
    || release["build"] !== expected.build
    || release["commit"] !== expected.source.commit
    || normalizeMinimumMacOS(release["minimumMacOS"]) !== expected.minimumMacOS
    || release["notarized"] !== false
    || !isDeepStrictEqual(release["signing"], productionReleaseSigning)
    || release["version"] !== expected.version
    || manifest["runtimeTreeSha256"] !== expected.source.runtimeTreeSha256
    || manifest["sourceTreeCleanAtPackaging"] !== true
    || runtimeManifest["schemaVersion"] !== 1
    || runtimeRelease["commit"] !== expected.source.commit
    || runtimeRelease["version"] !== expected.version
    || runtimeRelease["build"] !== expected.build
    || !isDeepStrictEqual(runtimeRelease["signing"], productionReleaseSigning)
    || runtime["treeSha256"] !== expected.source.runtimeTreeSha256
  ) {
    throw new Error(
      "The remote release manifest does not bind the published HRA evidence.",
    );
  }
  const sources: RemoteCorrespondingSourceEvidence[] = [];
  for (const [index, spec] of correspondingSourceSpecs.entries()) {
    const source = requireRecord(
      rawSources[index],
      `Remote corresponding source ${index}`,
    );
    const bytes = requirePositiveSafeInteger(
      source["bytes"],
      `Remote corresponding source ${index} bytes`,
    );
    const sha256 = requireDigest(
      source["sha256"],
      `Remote corresponding source ${index} SHA-256`,
    );
    if (
      source["archiveName"] !== spec.archiveName
      || source["commit"] !== spec.commit
      || source["project"] !== spec.project
      || source["repository"] !== spec.repository
      || !isDeepStrictEqual(source["externalSources"], spec.externalSources)
      || !isDeepStrictEqual(source["submodules"], spec.submodules)
    ) {
      throw new Error(
        `Remote corresponding-source evidence differs for ${spec.project}.`,
      );
    }
    sources.push(Object.freeze({
      archiveName: spec.archiveName,
      bytes,
      sha256,
    }));
  }
  return Object.freeze(sources);
}

function normalizeMinimumMacOS(value: unknown): string | null {
  return typeof value === "string" && /^[1-9][0-9]*(?:\.[0-9]+)?$/u.test(value)
    ? value.replace(/\.0$/u, "")
    : null;
}

function requireString(value: unknown, label: string): string {
  if (typeof value !== "string" || value.length === 0) {
    throw new Error(`${label} must be a nonempty string.`);
  }
  return value;
}

function requirePositiveSafeInteger(value: unknown, label: string): number {
  if (typeof value !== "number" || !Number.isSafeInteger(value) || value <= 0) {
    throw new Error(`${label} must be one positive safe integer.`);
  }
  return value;
}

function requireReleaseTimestamp(value: unknown, label: string): string {
  if (
    typeof value !== "string"
    || !/^2026-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z$/u.test(value)
  ) {
    throw new Error(`${label} must be one exact UTC timestamp.`);
  }
  return value;
}

function requireRecord(value: unknown, label: string): Record<string, unknown> {
  if (typeof value !== "object" || value === null || Array.isArray(value)) {
    throw new Error(`${label} must be an object.`);
  }
  return value as Record<string, unknown>;
}

function requireObjectId(value: unknown, label: string): string {
  if (typeof value !== "string" || !/^[0-9a-f]{40}$/u.test(value)) {
    throw new Error(`${label} must be one full SHA-1 object ID.`);
  }
  return value;
}

function parseCommitAllowlist(
  value: unknown,
  label: string,
): ReadonlySet<string> {
  if (typeof value !== "string" || value.length === 0 || value.length > 1_312) {
    throw new Error(`${label} must contain 1 to 32 full SHA-1 object IDs.`);
  }
  const commits = value.split(",");
  if (
    commits.length === 0
    || commits.length > 32
    || commits.some((commit) => !/^[0-9a-f]{40}$/u.test(commit))
  ) {
    throw new Error(`${label} must contain 1 to 32 full SHA-1 object IDs.`);
  }
  const unique = new Set(commits);
  if (unique.size !== commits.length) {
    throw new Error(`${label} may not contain duplicate commits.`);
  }
  return unique;
}

function requireDigest(value: unknown, label: string): string {
  if (typeof value !== "string" || !/^[0-9a-f]{64}$/u.test(value)) {
    throw new Error(`${label} must be one SHA-256 digest.`);
  }
  return value;
}

async function main(): Promise<void> {
  const arguments_ = process.argv.slice(2);
  const [command, flag, value] = arguments_;
  if (command === "contract" && arguments_.length === 1) {
    const contract = await verifyReleaseDownloadContract();
    process.stdout.write(`${JSON.stringify({ contract, status: "valid" })}\n`);
    return;
  }
  if (command === "source" && arguments_.length === 1) {
    process.stdout.write(`${JSON.stringify(await verifyReleaseSourceGate())}\n`);
    return;
  }
  if (command === "remote" && arguments_.length === 1) {
    process.stdout.write(`${JSON.stringify(await verifyRemoteReleaseGate())}\n`);
    return;
  }
  const releaseDirectory = arguments_.length === 1
    ? macosPackage.releaseDirectory
    : arguments_.length === 3 && flag === "--release-directory"
      ? value
      : undefined;
  if (command === "candidate" && releaseDirectory !== undefined) {
    process.stdout.write(
      `${JSON.stringify(await verifyLocalReleaseCandidate(releaseDirectory))}\n`,
    );
    return;
  }
  if (command === "published" && releaseDirectory !== undefined) {
    process.stdout.write(
      `${JSON.stringify(await verifyPublishedReleaseArtifacts(
        releaseDirectory,
      ))}\n`,
    );
    return;
  }
  throw new Error(
    "Usage: release-download-contract.ts contract | source | remote | candidate [--release-directory ABS] | published [--release-directory ABS]",
  );
}

if (import.meta.main) await main();
