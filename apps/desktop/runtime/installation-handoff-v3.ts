import { createHash, randomBytes } from "node:crypto";
import { constants } from "node:fs";
import {
  lstat,
  open,
  readdir,
  realpath,
  unlink,
} from "node:fs/promises";
import { basename, dirname, isAbsolute, join, resolve, sep } from "node:path";
import { isDeepStrictEqual } from "node:util";

import { z } from "@hra-internal/schema";

import {
  productionCustodyProbeSupervisorAuthoritySchema,
  type CustodyProbeSupervisorAuthorityEvidence,
} from "./custody-probe-supervisor-authority";
import {
  expectedHistoricalOprtePreviewIdentity,
  expectedHistoricalOprtePreviewSignature,
  expectedHistoricalOprtePreviewTree,
  strictBundleSignaturePolicy,
} from "./historical-oprte-preview";
import {
  defaultInstallationHandoffDependencies,
  inspectInstallationBundle,
  type BundleContinuityEvidence,
  type InstallationHandoffDependencies,
  type InstallationHandoffPaths,
  type StateContinuityEvidence,
} from "./installation-handoff";
import {
  inspectProspectivePathAuthority,
  renameWithPathAuthority,
  renameSwapForwardOnly,
} from "./installation-path-authority";
import { verifyPublishedReleaseCandidate } from "./release-download-contract";
import {
  digestHarnessKeyEnrollmentPreState,
  type HarnessKeyEnrollmentFileEvidence,
} from "./src/state/harness-key-enrollment";

export const installationHandoffV3CoreFileName =
  "handoff-enrollment-authorization-v3.json" as const;
export const installationHandoffV3ProgressFileName =
  "handoff-progress-v3.json" as const;

const maximumCoreBytes = 2 * 1_024 * 1_024;
const maximumProgressBytes = 256 * 1_024;
const maximumManifestBytes = 4 * 1_024 * 1_024;
const maximumTreeEntries = 2_000_000;
const maximumTreeBytes = 128 * 1_024 * 1_024 * 1_024;
const privateDirectoryModeMask = 0o077n;
const forbiddenKeys = new Set(["__proto__", "constructor", "prototype"]);
const operationIdPattern = /^handoff_[0-9a-f]{24}$/u;
const sha256Pattern = /^[0-9a-f]{64}$/u;
const commitPattern = /^[0-9a-f]{40}$/u;
const decimalBigIntPattern = /^(?:0|[1-9][0-9]*)$/u;
const corePendingPattern =
  /^\.handoff-enrollment-authorization-v3\.json\.pending\.[1-9][0-9]{0,19}\.[0-9a-f]{24}$/u;
const maximumRecoverableCorePendingFiles = 8;
const closeOnExecValue: unknown = Reflect.get(constants, "O_CLOEXEC");
const closeOnExec = typeof closeOnExecValue === "number"
  ? closeOnExecValue
  : 0;

const exactCandidateIdentity = Object.freeze({
  build: "16",
  bundleIdentifier: "kitchen.hraness",
  executable: "hra",
  version: "0.1.15",
} as const);

const priorHraIdentities = Object.freeze([
  { build: "8", version: "0.1.7" },
  { build: "9", version: "0.1.8" },
  { build: "10", version: "0.1.9" },
  { build: "11", version: "0.1.10" },
  { build: "13", version: "0.1.12" },
  { build: "14", version: "0.1.13" },
  { build: "15", version: "0.1.14" },
] as const);

export interface InstallationHandoffV3NodeEvidence {
  readonly device: string;
  readonly inode: string;
}

export interface InstallationHandoffV3ManifestEvidence
  extends InstallationHandoffV3NodeEvidence {
  readonly bytes: number;
  readonly commit: string;
  readonly runtimeTreeSha256: string;
  readonly sha256: string;
}

export interface InstallationHandoffV3CandidateEvidence {
  readonly bundle: BundleContinuityEvidence;
  readonly custodyProbeSupervisor: CustodyProbeSupervisorAuthorityEvidence;
  readonly manifest: InstallationHandoffV3ManifestEvidence;
  readonly root: InstallationHandoffV3NodeEvidence;
}

export interface InstallationHandoffV3Paths extends InstallationHandoffPaths {
  readonly backupDirectory: string;
  readonly candidateStage: string;
  readonly predecessorRetirementStage: string;
}

export interface InstallationHandoffV3Core {
  readonly candidate: InstallationHandoffV3CandidateEvidence;
  readonly createdAt: number;
  readonly keychainDescriptors: readonly string[];
  readonly kind: "hra-installation-handoff-authorization";
  readonly operationId: string;
  readonly paths: InstallationHandoffV3Paths;
  readonly predecessor: BundleContinuityEvidence;
  readonly preState: StateContinuityEvidence;
  readonly preStateSha256: string;
  readonly priorHra: BundleContinuityEvidence | null;
  readonly schemaVersion: 3;
}

export interface InstallationHandoffV3CoreEvidence
  extends InstallationHandoffV3NodeEvidence {
  readonly bytes: number;
  readonly path: string;
  readonly schemaVersion: 3;
  readonly sha256: string;
}

export type InstallationHandoffV3Phase =
  | "created"
  | "backed_up"
  | "smoked"
  | "bundles_archived"
  | "candidate_staged"
  | "enrollment_authorizing"
  | "enrollment_authorized"
  | "candidate_publish_prepared"
  | "candidate_installed"
  | "predecessor_retired"
  | "verified"
  | "committed"
  | "rolled_back";

export interface InstallationHandoffV3Progress {
  readonly authorizedSidecar: HarnessKeyEnrollmentFileEvidence | null;
  readonly candidateStage: InstallationHandoffV3CandidateEvidence | null;
  readonly core: InstallationHandoffV3CoreEvidence;
  readonly keychainContinuity:
    | "pending_same_process"
    | "verified_same_process"
    | "unavailable_after_process_restart"
    | "not_applicable";
  readonly phase: InstallationHandoffV3Phase;
  readonly schemaVersion: 3;
}

export interface InstallationHandoffV3ProgressFile {
  readonly evidence: Readonly<{
    readonly bytes: number;
    readonly device: string;
    readonly inode: string;
    readonly sha256: string;
  }>;
  readonly progress: InstallationHandoffV3Progress;
}

type InstallationHandoffV3PrivateFileEvidence = Readonly<{
  readonly bytes: number;
  readonly device: string;
  readonly inode: string;
  readonly sha256: string;
}>;

type HeldPrivateDirectory = Readonly<{
  readonly device: bigint;
  readonly handle: Awaited<ReturnType<typeof open>>;
  readonly inode: bigint;
  readonly mode: bigint;
  readonly owner: bigint;
  readonly path: string;
}>;

export interface InstallationHandoffV3PublicationTestOptions {
  /** Test-only crash seam after the private candidate and parent are durable. */
  readonly afterCandidateSyncForTest?: () => Promise<void> | void;
  /** Test-only race seam immediately before the create-only rename. */
  readonly beforeRenameForTest?: () => Promise<void> | void;
  /** Test-only crash seam after rename returns and before the parent fsync. */
  readonly afterRenameForTest?: () => Promise<void> | void;
}

export type InstallationHandoffV3CustodyObservation =
  | Readonly<{ state: "absent" }>
  | Readonly<{
      envelopeSha256: string;
      state: "present";
      strictAcl: true;
    }>;

export interface InstallationHandoffV3Dependencies
  extends InstallationHandoffDependencies {
  readonly inspectCandidateV3: (
    path: string,
  ) => Promise<InstallationHandoffV3CandidateEvidence>;
  readonly inspectEnrollmentKeychainNoUi: (
    candidateApp: string,
    authority: CustodyProbeSupervisorAuthorityEvidence,
  ) => Promise<InstallationHandoffV3CustodyObservation>;
  readonly beforeProgressPublishForTest?: (
    next: InstallationHandoffV3Progress,
  ) => Promise<void> | void;
  readonly afterProgressPublishForTest?: (
    next: InstallationHandoffV3Progress,
  ) => Promise<void> | void;
  readonly afterProgressSwapBeforeSyncForTest?: (
    next: InstallationHandoffV3Progress,
  ) => Promise<void> | void;
}

export interface InstallationHandoffV3ProgressAdvanceOptions
  extends Pick<
    InstallationHandoffV3Dependencies,
    | "beforeProgressPublishForTest"
    | "afterProgressPublishForTest"
    | "afterProgressSwapBeforeSyncForTest"
  > {
  /** Revalidates live invariants immediately before the first durable next leaf. */
  readonly beforeProgressCandidate?: (
    next: InstallationHandoffV3Progress,
  ) => Promise<void> | void;
  /** Marks the fixed next-history leaf durable before the canonical CAS. */
  readonly afterProgressCandidateDurable?: (
    next: InstallationHandoffV3Progress,
  ) => Promise<void> | void;
  /** Revalidates live invariants with both CAS parents held before rename. */
  readonly beforeProgressSwap?: (
    next: InstallationHandoffV3Progress,
  ) => Promise<void> | void;
}

export interface InstallationHandoffV3EffectiveProgressRead {
  readonly canonical: InstallationHandoffV3ProgressFile;
  readonly effective: InstallationHandoffV3ProgressFile;
  readonly source: "canonical" | "durable_next_history";
}

export interface InstallationHandoffV3CandidateInspectionTestOptions {
  /** Test-only logical bundle seam used to prove the two full scans agree. */
  readonly inspectBundleForTest?: typeof inspectInstallationBundle;
  /** Test-only package-verifier seam between the two full bundle scans. */
  readonly verifyCandidateForTest?: typeof verifyPublishedReleaseCandidate;
}

export class InstallationHandoffV3Error extends Error {
  readonly code:
    | "backup_invalid"
    | "candidate_invalid"
    | "continuity_failed"
    | "custody_unavailable"
    | "filesystem_unsafe"
    | "recovery_conflict";

  constructor(code: InstallationHandoffV3Error["code"], message: string) {
    super(message);
    this.name = "InstallationHandoffV3Error";
    this.code = code;
  }
}

export const defaultInstallationHandoffV3Dependencies:
  InstallationHandoffV3Dependencies = {
    ...defaultInstallationHandoffDependencies,
    inspectCandidateV3: inspectExactCandidateV3,
    inspectEnrollmentKeychainNoUi: () => Promise.reject(
      new InstallationHandoffV3Error(
        "custody_unavailable",
        "The resident no-UI custody adapter is unavailable.",
      ),
    ),
  };

const nonNegativeSafeIntegerSchema = z.number().int().nonnegative()
  .max(Number.MAX_SAFE_INTEGER);
const sha256Schema = z.string().regex(sha256Pattern);
const nodeEvidenceSchema = z.object({
  device: z.string().regex(decimalBigIntPattern),
  inode: z.string().regex(decimalBigIntPattern),
}).strict();
const treeEvidenceSchema = z.object({
  bytes: nonNegativeSafeIntegerSchema.max(maximumTreeBytes),
  directories: nonNegativeSafeIntegerSchema.max(maximumTreeEntries),
  digest: sha256Schema,
  entries: nonNegativeSafeIntegerSchema.max(maximumTreeEntries),
  files: nonNegativeSafeIntegerSchema.max(maximumTreeEntries),
  symlinks: nonNegativeSafeIntegerSchema.max(maximumTreeEntries),
}).strict().superRefine((value, context) => {
  if (value.entries !== value.directories + value.files + value.symlinks) {
    context.addIssue({ code: "custom", message: "tree entry counts differ" });
  }
});
const stateEvidenceSchema = z.object({
  accountHomes: nonNegativeSafeIntegerSchema,
  chatWorktreeLanes: nonNegativeSafeIntegerSchema,
  database: z.object({
    databaseSha256: sha256Schema,
    migrationVersion: nonNegativeSafeIntegerSchema,
    quickCheck: z.literal("ok"),
    rows: z.record(
      z.string().regex(/^[A-Za-z_][A-Za-z0-9_]{0,127}$/u),
      nonNegativeSafeIntegerSchema,
    ).refine(value => Object.keys(value).length <= 4_096, "too many rows"),
  }).strict(),
  dispatchWorktreeLanes: nonNegativeSafeIntegerSchema,
  harnessWorktreeLanes: nonNegativeSafeIntegerSchema,
  localTaskWorktreeLanes: nonNegativeSafeIntegerSchema,
  sessionEntries: nonNegativeSafeIntegerSchema,
  tree: treeEvidenceSchema,
}).strict();
const strictSignatureSchema = z.object({
  policy: z.literal(strictBundleSignaturePolicy),
}).strict();
const identitySchema = (identity: Readonly<{
  build: string;
  bundleIdentifier?: string;
  executable?: string;
  version: string;
}>) => z.object({
  build: z.literal(identity.build),
  bundleIdentifier: z.literal(identity.bundleIdentifier ?? "kitchen.hraness"),
  executable: z.literal(identity.executable ?? "hra"),
  version: z.literal(identity.version),
}).strict();
const bundleSchema = (identity: Parameters<typeof identitySchema>[0]) => z.object({
  identity: identitySchema(identity),
  signature: strictSignatureSchema,
  tree: treeEvidenceSchema,
}).strict();
const predecessorSchema = z.custom<BundleContinuityEvidence>(value =>
  isRecord(value)
  && Object.keys(value).length === 3
  && Object.keys(value).every(key =>
    key === "identity" || key === "signature" || key === "tree"
  )
  && isDeepStrictEqual(value["identity"], expectedHistoricalOprtePreviewIdentity)
  && isDeepStrictEqual(value["signature"], expectedHistoricalOprtePreviewSignature)
  && isDeepStrictEqual(value["tree"], expectedHistoricalOprtePreviewTree),
"historical predecessor evidence differs");
const priorHraSchema = z.union(priorHraIdentities.map(identity =>
  bundleSchema(identity)
) as [
  ReturnType<typeof bundleSchema>,
  ReturnType<typeof bundleSchema>,
  ...ReturnType<typeof bundleSchema>[],
]);
const candidateSchema = z.object({
  bundle: bundleSchema(exactCandidateIdentity),
  custodyProbeSupervisor: productionCustodyProbeSupervisorAuthoritySchema,
  manifest: nodeEvidenceSchema.extend({
    bytes: nonNegativeSafeIntegerSchema.max(maximumManifestBytes),
    commit: z.string().regex(commitPattern),
    runtimeTreeSha256: sha256Schema,
    sha256: sha256Schema,
  }).strict(),
  root: nodeEvidenceSchema,
}).strict();
const normalizedPathSchema = z.string().min(2).max(4_096).refine(
  isAbsoluteNormalizedNonRoot,
  "path must be absolute, normalized, and non-root",
);
const pathsSchema = z.object({
  applicationsDirectory: normalizedPathSchema,
  backupDirectory: normalizedPathSchema,
  candidateApp: normalizedPathSchema,
  candidateStage: normalizedPathSchema,
  canonicalApp: normalizedPathSchema,
  controlPlanePath: normalizedPathSchema,
  nativeInstanceLockPath: normalizedPathSchema,
  predecessorApp: normalizedPathSchema,
  predecessorRetirementStage: normalizedPathSchema,
  sparkleCacheRoots: z.array(normalizedPathSchema).min(1).max(16),
  stateRoot: normalizedPathSchema,
  updateHazardPath: normalizedPathSchema,
  updateHazardTemporaryPath: normalizedPathSchema,
}).strict();
const descriptorSchema = z.string().max(2_048).refine(value => {
  const separator = value.indexOf("\0");
  return separator > 0
    && separator === value.lastIndexOf("\0")
    && separator < value.length - 1;
}, "invalid Keychain descriptor");
const coreEvidenceSchema = nodeEvidenceSchema.extend({
  bytes: nonNegativeSafeIntegerSchema.max(maximumCoreBytes),
  path: normalizedPathSchema,
  schemaVersion: z.literal(3),
  sha256: sha256Schema,
}).strict();
const enrollmentFileEvidenceSchema = nodeEvidenceSchema.extend({
  bytes: nonNegativeSafeIntegerSchema.max(64 * 1_024),
  sha256: sha256Schema,
}).strict();

const coreSchema = z.object({
  candidate: candidateSchema,
  createdAt: nonNegativeSafeIntegerSchema,
  keychainDescriptors: z.array(descriptorSchema).max(4_096),
  kind: z.literal("hra-installation-handoff-authorization"),
  operationId: z.string().regex(operationIdPattern),
  paths: pathsSchema,
  predecessor: predecessorSchema,
  preState: stateEvidenceSchema,
  preStateSha256: sha256Schema,
  priorHra: priorHraSchema.nullable(),
  schemaVersion: z.literal(3),
}).strict().superRefine((value, context) => {
  const descriptors = value.keychainDescriptors;
  if (
    new Set(descriptors).size !== descriptors.length
    || [...descriptors].sort().some((item, index) => item !== descriptors[index])
  ) {
    context.addIssue({ code: "custom", message: "descriptor inventory differs" });
  }
  if (
    value.preStateSha256
      !== digestHarnessKeyEnrollmentPreState(value.preState)
  ) {
    context.addIssue({ code: "custom", message: "pre-state digest differs" });
  }
  if (
    value.paths.candidateStage
      !== candidateStagePath(value.paths.applicationsDirectory, value.operationId)
    || value.paths.predecessorRetirementStage
      !== predecessorRetirementStagePath(
        value.paths.applicationsDirectory,
        value.operationId,
      )
  ) {
    context.addIssue({ code: "custom", message: "staging paths differ" });
  }
});

const progressSchema = z.object({
  authorizedSidecar: enrollmentFileEvidenceSchema.nullable(),
  candidateStage: candidateSchema.nullable(),
  core: coreEvidenceSchema,
  keychainContinuity: z.enum([
    "pending_same_process",
    "verified_same_process",
    "unavailable_after_process_restart",
    "not_applicable",
  ]),
  phase: z.enum([
    "created",
    "backed_up",
    "smoked",
    "bundles_archived",
    "candidate_staged",
    "enrollment_authorizing",
    "enrollment_authorized",
    "candidate_publish_prepared",
    "candidate_installed",
    "predecessor_retired",
    "verified",
    "committed",
    "rolled_back",
  ]),
  schemaVersion: z.literal(3),
}).strict().superRefine((value, context) => {
  const requiresSidecar = phaseIndex(value.phase) >= phaseIndex(
    "enrollment_authorized",
  ) && value.phase !== "rolled_back";
  if (requiresSidecar !== (value.authorizedSidecar !== null)) {
    context.addIssue({ code: "custom", message: "sidecar evidence differs" });
  }
  const requiresCandidateStage = phaseIndex(value.phase) >= phaseIndex(
    "candidate_staged",
  ) && value.phase !== "rolled_back";
  if (requiresCandidateStage !== (value.candidateStage !== null)) {
    context.addIssue({ code: "custom", message: "candidate stage evidence differs" });
  }
  const validContinuity = value.phase === "rolled_back"
    ? value.keychainContinuity === "not_applicable"
    : value.phase === "verified" || value.phase === "committed"
      ? value.keychainContinuity === "verified_same_process"
        || value.keychainContinuity === "unavailable_after_process_restart"
      : value.keychainContinuity === "pending_same_process"
        || value.keychainContinuity === "unavailable_after_process_restart";
  if (!validContinuity) {
    context.addIssue({ code: "custom", message: "Keychain continuity differs" });
  }
});

const phaseOrder: readonly InstallationHandoffV3Phase[] = [
  "created",
  "backed_up",
  "smoked",
  "bundles_archived",
  "candidate_staged",
  "enrollment_authorizing",
  "enrollment_authorized",
  "candidate_publish_prepared",
  "candidate_installed",
  "predecessor_retired",
  "verified",
  "committed",
];

export function parseInstallationHandoffV3Core(
  value: unknown,
): InstallationHandoffV3Core {
  if (containsForbiddenKey(value, new WeakSet<object>())) throw invalidCore();
  const parsed = coreSchema.safeParse(value);
  if (!parsed.success) throw invalidCore();
  return parsed.data;
}

export function parseInstallationHandoffV3Progress(
  value: unknown,
): InstallationHandoffV3Progress {
  if (containsForbiddenKey(value, new WeakSet<object>())) throw invalidProgress();
  const parsed = progressSchema.safeParse(value);
  if (!parsed.success) throw invalidProgress();
  return parsed.data;
}

/**
 * Recovers only the bounded create-only publication residue owned by the
 * immutable v3 core writer. It never guesses at unrelated backup content.
 */
export async function recoverInstallationHandoffV3CorePublication(
  backupDirectoryValue: string,
): Promise<Readonly<{
  core: InstallationHandoffV3Core;
  evidence: InstallationHandoffV3CoreEvidence;
}> | null> {
  const backupDirectory = requireAbsoluteNormalized(
    backupDirectoryValue,
    "handoff backup directory",
  );
  const directory = await openHeldPrivateDirectory(backupDirectory);
  try {
    const names = await readdir(backupDirectory);
    const pendingNames = names.filter(name => corePendingPattern.test(name));
    const malformedPending = names.some(name =>
      name.startsWith(`.${installationHandoffV3CoreFileName}.pending.`)
      && !corePendingPattern.test(name));
    if (
      malformedPending
      || pendingNames.length > maximumRecoverableCorePendingFiles
    ) throw unsafeFile();
    let published = await tryReadInstallationHandoffV3Core(backupDirectory);
    if (
      published === null
      && names.some(name => !pendingNames.includes(name))
    ) {
      throw new InstallationHandoffV3Error(
        "recovery_conflict",
        "A pre-core backup directory contains unrecognized authority residue.",
      );
    }
    const validPending: Array<Readonly<{
      core: InstallationHandoffV3Core;
      evidence: InstallationHandoffV3PrivateFileEvidence;
      path: string;
    }>> = [];
    for (const name of pendingNames) {
      const path = join(backupDirectory, name);
      let read: Awaited<ReturnType<typeof readExactPrivateFile>>;
      try {
        read = await readExactPrivateFile(path, maximumCoreBytes);
      } catch {
        await unlinkBoundPrivateFile(path, maximumCoreBytes, directory);
        continue;
      }
      let core: InstallationHandoffV3Core;
      let text: string;
      try {
        text = new TextDecoder("utf-8", { fatal: true }).decode(read.bytes);
        core = parseInstallationHandoffV3Core(JSON.parse(text) as unknown);
      } catch {
        await unlinkBoundPrivateFile(
          path,
          maximumCoreBytes,
          directory,
          read.evidence,
        );
        continue;
      } finally {
        read.bytes.fill(0);
      }
      if (
        core.paths.backupDirectory !== backupDirectory
        || text !== `${JSON.stringify(core, null, 2)}\n`
      ) {
        await unlinkBoundPrivateFile(
          path,
          maximumCoreBytes,
          directory,
          read.evidence,
        );
        continue;
      }
      if (published !== null) {
        if (!isDeepStrictEqual(published.core, core)) {
          throw new InstallationHandoffV3Error(
            "recovery_conflict",
            "A pending core differs from the published immutable authority.",
          );
        }
        await unlinkBoundPrivateFile(
          path,
          maximumCoreBytes,
          directory,
          read.evidence,
        );
      } else {
        validPending.push({ core, evidence: read.evidence, path });
      }
    }
    if (published !== null) {
      await syncHeldDirectory(directory);
      return published;
    }
    if (validPending.length === 0) {
      await syncHeldDirectory(directory);
      return null;
    }
    const selected = validPending[0]!;
    if (validPending.some(item => !isDeepStrictEqual(item.core, selected.core))) {
      throw new InstallationHandoffV3Error(
        "recovery_conflict",
        "Multiple pending cores disagree before immutable publication.",
      );
    }
    const finalPath = join(
      backupDirectory,
      installationHandoffV3CoreFileName,
    );
    const [sourceAuthority, destinationAuthority] = await Promise.all([
      inspectProspectivePathAuthority(selected.path, "pending v3 core"),
      inspectProspectivePathAuthority(finalPath, "immutable v3 core"),
    ]);
    try {
      await renameWithPathAuthority(sourceAuthority, destinationAuthority);
    } catch (error: unknown) {
      published = await tryReadInstallationHandoffV3Core(backupDirectory);
      if (published === null || !isDeepStrictEqual(published.core, selected.core)) {
        throw error;
      }
    }
    await syncHeldDirectory(directory);
    published = await readInstallationHandoffV3Core(backupDirectory);
    if (!isDeepStrictEqual(published.core, selected.core)) throw unsafeFile();
    for (const item of validPending.slice(1)) {
      await unlinkBoundPrivateFile(
        item.path,
        maximumCoreBytes,
        directory,
        item.evidence,
      );
    }
    await syncHeldDirectory(directory);
    return published;
  } finally {
    await directory.handle.close();
  }
}

export async function createInstallationHandoffV3Core(
  backupDirectoryValue: string,
  coreValue: InstallationHandoffV3Core,
  options: InstallationHandoffV3PublicationTestOptions = {},
): Promise<InstallationHandoffV3CoreEvidence> {
  const backupDirectory = requireAbsoluteNormalized(
    backupDirectoryValue,
    "handoff backup directory",
  );
  const directory = await openHeldPrivateDirectory(backupDirectory);
  try {
    const core = parseInstallationHandoffV3Core(coreValue);
    if (core.paths.backupDirectory !== backupDirectory) throw invalidCore();
    const path = join(backupDirectory, installationHandoffV3CoreFileName);
    const encoded = Buffer.from(
      `${JSON.stringify(core, null, 2)}\n`,
      "utf8",
    );
    if (encoded.byteLength > maximumCoreBytes) throw invalidCore();
    try {
      const existing = await tryReadInstallationHandoffV3Core(backupDirectory);
      if (existing !== null) {
        if (!isDeepStrictEqual(existing.core, core)) {
          throw new InstallationHandoffV3Error(
            "recovery_conflict",
            "Immutable handoff authorization already exists with different content.",
          );
        }
        await syncHeldDirectory(directory);
        return existing.evidence;
      }
      await publishCreateOnlyPrivateFile(
        path,
        encoded,
        maximumCoreBytes,
        "immutable handoff authorization",
        options,
        directory,
      );
    } finally {
      encoded.fill(0);
    }
    const read = await readInstallationHandoffV3Core(backupDirectory);
    if (!isDeepStrictEqual(read.core, core)) {
      throw new InstallationHandoffV3Error(
        "filesystem_unsafe",
        "Immutable handoff authorization changed during publication.",
      );
    }
    await revalidateHeldDirectory(directory);
    return read.evidence;
  } finally {
    await directory.handle.close();
  }
}

export async function readInstallationHandoffV3Core(
  backupDirectoryValue: string,
  expected?: InstallationHandoffV3CoreEvidence,
): Promise<Readonly<{
  core: InstallationHandoffV3Core;
  evidence: InstallationHandoffV3CoreEvidence;
}>> {
  const backupDirectory = requireAbsoluteNormalized(
    backupDirectoryValue,
    "handoff backup directory",
  );
  const directory = await openHeldPrivateDirectory(backupDirectory);
  try {
    const path = join(backupDirectory, installationHandoffV3CoreFileName);
    if (
      expected !== undefined
      && (expected.path !== path || expected.schemaVersion !== 3)
    ) throw unsafeFile();
    const read = await readExactPrivateFile(path, maximumCoreBytes, expected);
    let value: unknown;
    let text: string;
    try {
      text = new TextDecoder("utf-8", { fatal: true }).decode(read.bytes);
      value = JSON.parse(text) as unknown;
    } catch {
      throw invalidCore();
    } finally {
      read.bytes.fill(0);
    }
    const core = parseInstallationHandoffV3Core(value);
    if (core.paths.backupDirectory !== backupDirectory) throw invalidCore();
    if (text !== `${JSON.stringify(core, null, 2)}\n`) throw invalidCore();
    const evidence: InstallationHandoffV3CoreEvidence = {
      ...read.evidence,
      path,
      schemaVersion: 3,
    };
    if (expected !== undefined && !isDeepStrictEqual(evidence, expected)) {
      throw unsafeFile();
    }
    await revalidateHeldDirectory(directory);
    return { core, evidence };
  } finally {
    await directory.handle.close();
  }
}

export async function createInstallationHandoffV3Progress(
  backupDirectoryValue: string,
  progressValue: InstallationHandoffV3Progress,
  options: InstallationHandoffV3PublicationTestOptions = {},
): Promise<InstallationHandoffV3ProgressFile> {
  const backupDirectory = requireAbsoluteNormalized(
    backupDirectoryValue,
    "handoff backup directory",
  );
  const directory = await openHeldPrivateDirectory(backupDirectory);
  try {
    const progress = parseInstallationHandoffV3Progress(progressValue);
    if (progress.phase !== "created" || progress.authorizedSidecar !== null) {
      throw invalidProgress();
    }
    await readInstallationHandoffV3Core(backupDirectory, progress.core);
    const path = join(backupDirectory, installationHandoffV3ProgressFileName);
    const existing = await tryReadInstallationHandoffV3Progress(
      backupDirectory,
      progress.core,
    );
    if (existing !== null) {
      if (!isDeepStrictEqual(existing.progress, progress)) {
        throw new InstallationHandoffV3Error(
          "recovery_conflict",
          "Initial handoff progress already exists with different content.",
        );
      }
      await syncHeldDirectory(directory);
      return existing;
    }
    const encoded = serializeProgress(progress);
    try {
      await publishCreateOnlyPrivateFile(
        path,
        encoded,
        maximumProgressBytes,
        "initial handoff progress",
        options,
        directory,
      );
    } finally {
      encoded.fill(0);
    }
    const result = await readInstallationHandoffV3Progress(
      backupDirectory,
      progress.core,
    );
    await revalidateHeldDirectory(directory);
    return result;
  } finally {
    await directory.handle.close();
  }
}

export async function readInstallationHandoffV3Progress(
  backupDirectoryValue: string,
  expectedCore?: InstallationHandoffV3CoreEvidence,
): Promise<InstallationHandoffV3ProgressFile> {
  const backupDirectory = requireAbsoluteNormalized(
    backupDirectoryValue,
    "handoff backup directory",
  );
  const directory = await openHeldPrivateDirectory(backupDirectory);
  try {
    const path = join(backupDirectory, installationHandoffV3ProgressFileName);
    const result = await readInstallationHandoffV3ProgressFile(
      path,
      backupDirectory,
      expectedCore,
    );
    await revalidateHeldDirectory(directory);
    return result;
  } finally {
    await directory.handle.close();
  }
}

/**
 * Reads the canonical progress leaf and the one fixed next-history leaf that
 * may already be durable before its forward-only CAS swap. This function is
 * strictly observational: recovery and cleanup may promote the same leaf only
 * while holding the operation locks.
 */
export async function readInstallationHandoffV3EffectiveProgress(
  backupDirectoryValue: string,
  expectedCore?: InstallationHandoffV3CoreEvidence,
): Promise<InstallationHandoffV3EffectiveProgressRead> {
  const backupDirectory = requireAbsoluteNormalized(
    backupDirectoryValue,
    "handoff backup directory",
  );
  const directory = await openHeldPrivateDirectory(backupDirectory);
  try {
    const canonical = await readInstallationHandoffV3ProgressFile(
      join(backupDirectory, installationHandoffV3ProgressFileName),
      backupDirectory,
      expectedCore,
    );
    const historyPath = progressHistoryPath(
      backupDirectory,
      canonical.progress.phase,
    );
    let effective: InstallationHandoffV3ProgressFile;
    try {
      effective = await readInstallationHandoffV3ProgressFile(
        historyPath,
        backupDirectory,
        canonical.progress.core,
      );
    } catch (error: unknown) {
      if (!hasCode(error, "ENOENT")) throw error;
      await revalidateHeldDirectory(directory);
      return { canonical, effective: canonical, source: "canonical" };
    }
    requireProgressTransition(canonical.progress, effective.progress);
    await revalidateHeldDirectory(directory);
    return {
      canonical,
      effective,
      source: "durable_next_history",
    };
  } finally {
    await directory.handle.close();
  }
}

export async function readInstallationHandoffV3RollbackOrigin(
  backupDirectoryValue: string,
  expectedCore: InstallationHandoffV3CoreEvidence,
): Promise<InstallationHandoffV3Progress> {
  const backupDirectory = requireAbsoluteNormalized(
    backupDirectoryValue,
    "handoff backup directory",
  );
  const directory = await openHeldPrivateDirectory(backupDirectory);
  try {
    const current = await readInstallationHandoffV3Progress(
      backupDirectory,
      expectedCore,
    );
    if (current.progress.phase !== "rolled_back") {
      throw new InstallationHandoffV3Error(
        "recovery_conflict",
        "Rollback origin requires terminal rolled-back progress.",
      );
    }
    let origin: InstallationHandoffV3Progress | null = null;
    let historyEnded = false;
    for (const phase of phaseOrder) {
      let retained: InstallationHandoffV3ProgressFile | null;
      try {
        retained = await readInstallationHandoffV3ProgressFile(
          progressHistoryPath(backupDirectory, phase),
          backupDirectory,
          expectedCore,
        );
      } catch (error: unknown) {
        if (!hasCode(error, "ENOENT")) throw error;
        retained = null;
      }
      if (retained === null) {
        historyEnded = true;
        continue;
      }
      if (historyEnded || retained.progress.phase !== phase) {
        throw new InstallationHandoffV3Error(
          "recovery_conflict",
          "Rolled-back progress history is not one exact monotone prefix.",
        );
      }
      if (phaseIndex(phase) >= phaseIndex("candidate_publish_prepared")) {
        throw new InstallationHandoffV3Error(
          "recovery_conflict",
          "Rolled-back progress history crosses the publication boundary.",
        );
      }
      if (origin !== null) {
        requireProgressTransition(origin, retained.progress);
      }
      origin = retained.progress;
    }
    if (origin === null) {
      throw new InstallationHandoffV3Error(
        "recovery_conflict",
        "Rolled-back progress lacks its exact retained origin.",
      );
    }
    requireProgressTransition(origin, current.progress);
    await revalidateHeldDirectory(directory);
    return origin;
  } finally {
    await directory.handle.close();
  }
}

export async function advanceInstallationHandoffV3Progress(
  backupDirectoryValue: string,
  current: InstallationHandoffV3ProgressFile,
  nextValue: InstallationHandoffV3Progress,
  dependencies: InstallationHandoffV3ProgressAdvanceOptions = {},
): Promise<InstallationHandoffV3ProgressFile> {
  const backupDirectory = requireAbsoluteNormalized(
    backupDirectoryValue,
    "handoff backup directory",
  );
  const directory = await openHeldPrivateDirectory(backupDirectory);
  try {
    return await advanceInstallationHandoffV3ProgressWithDirectory(
      backupDirectory,
      current,
      nextValue,
      dependencies,
      directory,
    );
  } finally {
    await directory.handle.close();
  }
}

export async function reconcileInstallationHandoffV3PreparedTransition(
  backupDirectoryValue: string,
  current: InstallationHandoffV3ProgressFile,
  options: Readonly<{
    beforeAdvance?: (
      next: InstallationHandoffV3Progress,
    ) => Promise<void> | void;
    afterDirectorySyncForTest?: () => Promise<void> | void;
  }> = {},
): Promise<Readonly<{
  kind: "advanced" | "none";
  progress: InstallationHandoffV3ProgressFile;
}>> {
  const backupDirectory = requireAbsoluteNormalized(
    backupDirectoryValue,
    "handoff backup directory",
  );
  const directory = await openHeldPrivateDirectory(backupDirectory);
  try {
    const observed = await readInstallationHandoffV3Progress(
      backupDirectory,
      current.progress.core,
    );
    if (!isDeepStrictEqual(observed, current)) {
      await syncHeldDirectory(directory);
      await options.afterDirectorySyncForTest?.();
      return { kind: "advanced", progress: observed };
    }
    const historyPath = progressHistoryPath(
      backupDirectory,
      current.progress.phase,
    );
    let candidate: InstallationHandoffV3ProgressFile;
    try {
      candidate = await readInstallationHandoffV3ProgressFile(
        historyPath,
        backupDirectory,
        current.progress.core,
      );
    } catch (error: unknown) {
      if (!hasCode(error, "ENOENT")) throw error;
      await syncHeldDirectory(directory);
      await options.afterDirectorySyncForTest?.();
      return { kind: "none", progress: observed };
    }
    requireProgressTransition(current.progress, candidate.progress);
    await options.beforeAdvance?.(candidate.progress);
    const advanced = await advanceInstallationHandoffV3ProgressWithDirectory(
      backupDirectory,
      current,
      candidate.progress,
      {},
      directory,
    );
    await syncHeldDirectory(directory);
    await options.afterDirectorySyncForTest?.();
    return { kind: "advanced", progress: advanced };
  } finally {
    await directory.handle.close();
  }
}

async function advanceInstallationHandoffV3ProgressWithDirectory(
  backupDirectory: string,
  current: InstallationHandoffV3ProgressFile,
  nextValue: InstallationHandoffV3Progress,
  dependencies: InstallationHandoffV3ProgressAdvanceOptions,
  directory: HeldPrivateDirectory,
): Promise<InstallationHandoffV3ProgressFile> {
  const next = parseInstallationHandoffV3Progress(nextValue);
  requireProgressTransition(current.progress, next);
  await readInstallationHandoffV3Core(backupDirectory, next.core);
  const observed = await readInstallationHandoffV3Progress(
    backupDirectory,
    current.progress.core,
  );
  const historyPath = progressHistoryPath(backupDirectory, current.progress.phase);
  if (!isDeepStrictEqual(observed, current)) {
    if (isDeepStrictEqual(observed.progress, next)) {
      await requireRetainedProgressHistory(historyPath, backupDirectory, current);
      await syncHeldDirectory(directory);
      return observed;
    }
    throw new InstallationHandoffV3Error(
      "recovery_conflict",
      "Handoff progress changed before its CAS update.",
    );
  }
  const path = join(backupDirectory, installationHandoffV3ProgressFileName);
  await prepareProgressHistoryCandidate(
    historyPath,
    backupDirectory,
    next,
    directory,
    dependencies.beforeProgressCandidate,
  );
  await dependencies.afterProgressCandidateDurable?.(next);
  await dependencies.beforeProgressPublishForTest?.(next);
  const [sourceAuthority, destinationAuthority] = await Promise.all([
    inspectProspectivePathAuthority(historyPath, "handoff progress candidate"),
    inspectProspectivePathAuthority(path, "handoff progress"),
  ]);
  try {
    await renameSwapForwardOnly(sourceAuthority, destinationAuthority, {
      ...(dependencies.beforeProgressSwap === undefined
        ? {}
        : {
            beforeRenameForTest: async () => {
              await dependencies.beforeProgressSwap?.(next);
            },
          }),
    });
  } catch (error: unknown) {
    await revalidateHeldDirectory(directory);
    const classified = await classifyProgressCAS(
      backupDirectory,
      current,
      next,
    );
    if (classified !== null) {
      await syncHeldDirectory(directory);
      return classified;
    }
    throw new InstallationHandoffV3Error(
      "recovery_conflict",
      `Handoff progress CAS is ambiguous: ${errorMessage(error)}`,
    );
  }
  await dependencies.afterProgressSwapBeforeSyncForTest?.(next);
  await syncHeldDirectory(directory);
  await dependencies.afterProgressPublishForTest?.(next);
  const published = await readInstallationHandoffV3Progress(
    backupDirectory,
    next.core,
  );
  if (!isDeepStrictEqual(published.progress, next)) {
    throw new InstallationHandoffV3Error(
      "recovery_conflict",
      "Handoff progress readback differs after CAS.",
    );
  }
  await requireRetainedProgressHistory(historyPath, backupDirectory, current);
  await revalidateHeldDirectory(directory);
  return published;
}

export function installationHandoffV3CoreReference(
  evidence: InstallationHandoffV3CoreEvidence,
): Readonly<{
  device: string;
  inode: string;
  path: string;
  schemaVersion: 3;
  sha256: string;
}> {
  return {
    device: evidence.device,
    inode: evidence.inode,
    path: evidence.path,
    schemaVersion: 3,
    sha256: evidence.sha256,
  };
}

export function installationHandoffV3Paths(
  base: InstallationHandoffPaths,
  backupDirectory: string,
  operationId: string,
): InstallationHandoffV3Paths {
  return {
    ...base,
    backupDirectory,
    candidateStage: candidateStagePath(base.applicationsDirectory, operationId),
    predecessorRetirementStage: predecessorRetirementStagePath(
      base.applicationsDirectory,
      operationId,
    ),
  };
}

export function candidateStagePath(
  applicationsDirectory: string,
  operationId: string,
): string {
  return join(applicationsDirectory, `.${operationId}.candidate.app`);
}

export function predecessorRetirementStagePath(
  applicationsDirectory: string,
  operationId: string,
): string {
  return join(applicationsDirectory, `.${operationId}.predecessor.bundle`);
}

export function createInstallationHandoffV3OperationId(
  bytes = randomBytes(12),
): string {
  if (bytes.byteLength !== 12) throw invalidCore();
  return `handoff_${Buffer.from(bytes).toString("hex")}`;
}

export async function inspectExactCandidateV3(
  pathValue: string,
  options: InstallationHandoffV3CandidateInspectionTestOptions = {},
): Promise<InstallationHandoffV3CandidateEvidence> {
  const path = requireAbsoluteNormalized(pathValue, "handoff candidate");
  const inspectBundle = options.inspectBundleForTest
    ?? inspectInstallationBundle;
  const verifyCandidate = options.verifyCandidateForTest
    ?? verifyPublishedReleaseCandidate;
  const rootBefore = await inspectDirectoryNode(path);
  const manifestBefore = await inspectCandidateManifest(path);
  const bundle = await inspectBundle(path, strictBundleSignaturePolicy);
  if (!isDeepStrictEqual(bundle.identity, exactCandidateIdentity)) {
    throw new InstallationHandoffV3Error(
      "candidate_invalid",
      "Ordinary handoff requires exact HRA v0.1.15 build 16.",
    );
  }
  const verified = await verifyCandidate(path);
  if (
    verified.commit !== manifestBefore.commit
    || verified.runtimeTreeSha256 !== manifestBefore.runtimeTreeSha256
  ) {
    throw new InstallationHandoffV3Error(
      "candidate_invalid",
      "Candidate package provenance differs from its runtime manifest.",
    );
  }
  const bundleAfter = await inspectBundle(path, strictBundleSignaturePolicy);
  const manifestAfter = await inspectCandidateManifest(path, manifestBefore);
  const rootAfter = await inspectDirectoryNode(path);
  if (
    !isDeepStrictEqual(bundle, bundleAfter)
    || !isDeepStrictEqual(bundleAfter.identity, exactCandidateIdentity)
    || !isDeepStrictEqual(rootBefore, rootAfter)
    || !isDeepStrictEqual(manifestBefore, manifestAfter)
  ) {
    throw new InstallationHandoffV3Error(
      "filesystem_unsafe",
      "Candidate changed while its v3 authority was collected.",
    );
  }
  return {
    bundle,
    custodyProbeSupervisor: verified.custodyProbeSupervisor,
    manifest: manifestBefore,
    root: rootBefore,
  };
}

function phaseIndex(phase: InstallationHandoffV3Phase): number {
  if (phase === "rolled_back") return -1;
  return phaseOrder.indexOf(phase);
}

function requireProgressTransition(
  current: InstallationHandoffV3Progress,
  next: InstallationHandoffV3Progress,
): void {
  if (!isDeepStrictEqual(current.core, next.core)) throw invalidProgress();
  if (current.phase === "rolled_back") {
    throw new InstallationHandoffV3Error(
      "recovery_conflict",
      "Rolled-back handoff progress is terminal.",
    );
  }
  if (next.phase === "rolled_back") {
    if (phaseIndex(current.phase) >= phaseIndex("candidate_publish_prepared")) {
      throw new InstallationHandoffV3Error(
        "recovery_conflict",
        "Rollback cannot cross the durable candidate publication boundary.",
      );
    }
    return;
  }
  if (phaseIndex(next.phase) !== phaseIndex(current.phase) + 1) {
    throw new InstallationHandoffV3Error(
      "recovery_conflict",
      "Handoff progress transition is not monotone.",
    );
  }
  if (
    current.candidateStage !== null
    && !isDeepStrictEqual(current.candidateStage, next.candidateStage)
  ) throw invalidProgress();
  if (
    current.authorizedSidecar !== null
    && !isDeepStrictEqual(
      current.authorizedSidecar,
      next.authorizedSidecar,
    )
  ) throw invalidProgress();
  if (
    current.keychainContinuity === "unavailable_after_process_restart"
    && next.keychainContinuity !== "unavailable_after_process_restart"
  ) throw invalidProgress();
}

async function classifyProgressCAS(
  backupDirectory: string,
  current: InstallationHandoffV3ProgressFile,
  next: InstallationHandoffV3Progress,
): Promise<InstallationHandoffV3ProgressFile | null> {
  const observed = await readInstallationHandoffV3Progress(
    backupDirectory,
    next.core,
  );
  const historyPath = progressHistoryPath(
    backupDirectory,
    current.progress.phase,
  );
  if (isDeepStrictEqual(observed.progress, next)) {
    await requireRetainedProgressHistory(historyPath, backupDirectory, current);
    return observed;
  }
  if (!isDeepStrictEqual(observed, current)) return null;
  const candidate = await readInstallationHandoffV3ProgressFile(
    historyPath,
    backupDirectory,
    next.core,
  );
  if (!isDeepStrictEqual(candidate.progress, next)) {
    throw new InstallationHandoffV3Error(
      "recovery_conflict",
      "Handoff progress CAS history differs from both exact outcomes.",
    );
  }
  return null;
}

function progressHistoryPath(
  backupDirectory: string,
  phase: InstallationHandoffV3Phase,
): string {
  return join(
    backupDirectory,
    `handoff-progress-v3.history.${phase}.json`,
  );
}

async function tryReadInstallationHandoffV3Core(
  backupDirectory: string,
): Promise<Readonly<{
  core: InstallationHandoffV3Core;
  evidence: InstallationHandoffV3CoreEvidence;
}> | null> {
  try {
    return await readInstallationHandoffV3Core(backupDirectory);
  } catch (error: unknown) {
    if (hasCode(error, "ENOENT")) return null;
    throw error;
  }
}

async function tryReadInstallationHandoffV3Progress(
  backupDirectory: string,
  expectedCore: InstallationHandoffV3CoreEvidence,
): Promise<InstallationHandoffV3ProgressFile | null> {
  try {
    return await readInstallationHandoffV3Progress(
      backupDirectory,
      expectedCore,
    );
  } catch (error: unknown) {
    if (hasCode(error, "ENOENT")) return null;
    throw error;
  }
}

async function readInstallationHandoffV3ProgressFile(
  path: string,
  backupDirectory: string,
  expectedCore?: InstallationHandoffV3CoreEvidence,
): Promise<InstallationHandoffV3ProgressFile> {
  const read = await readExactPrivateFile(path, maximumProgressBytes);
  let value: unknown;
  let text: string;
  try {
    text = new TextDecoder("utf-8", { fatal: true }).decode(read.bytes);
    value = JSON.parse(text) as unknown;
  } catch {
    throw invalidProgress();
  } finally {
    read.bytes.fill(0);
  }
  const progress = parseInstallationHandoffV3Progress(value);
  const expectedCorePath = join(
    backupDirectory,
    installationHandoffV3CoreFileName,
  );
  if (
    progress.core.path !== expectedCorePath
    || progress.core.schemaVersion !== 3
    || (
      expectedCore !== undefined
      && !isDeepStrictEqual(progress.core, expectedCore)
    )
  ) throw invalidProgress();
  if (text !== `${JSON.stringify(progress, null, 2)}\n`) {
    throw invalidProgress();
  }
  await readInstallationHandoffV3Core(backupDirectory, progress.core);
  return { evidence: read.evidence, progress };
}

async function prepareProgressHistoryCandidate(
  historyPath: string,
  backupDirectory: string,
  next: InstallationHandoffV3Progress,
  directory: HeldPrivateDirectory,
  beforePublication?: (
    next: InstallationHandoffV3Progress,
  ) => Promise<void> | void,
): Promise<void> {
  try {
    const existing = await readInstallationHandoffV3ProgressFile(
      historyPath,
      backupDirectory,
      next.core,
    );
    if (!isDeepStrictEqual(existing.progress, next)) {
      throw new InstallationHandoffV3Error(
        "recovery_conflict",
        "Retained handoff progress history conflicts with the next CAS value.",
      );
    }
    return;
  } catch (error: unknown) {
    if (!hasCode(error, "ENOENT")) throw error;
  }
  const encoded = serializeProgress(next);
  try {
    await publishCreateOnlyPrivateFile(
      historyPath,
      encoded,
      maximumProgressBytes,
      "handoff progress history",
      beforePublication === undefined
        ? {}
        : {
            beforeRenameForTest: async () => {
              await beforePublication(next);
            },
          },
      directory,
    );
  } finally {
    encoded.fill(0);
  }
  const prepared = await readInstallationHandoffV3ProgressFile(
    historyPath,
    backupDirectory,
    next.core,
  );
  if (!isDeepStrictEqual(prepared.progress, next)) {
    throw new InstallationHandoffV3Error(
      "recovery_conflict",
      "Prepared handoff progress history differs from the next CAS value.",
    );
  }
}

async function requireRetainedProgressHistory(
  historyPath: string,
  backupDirectory: string,
  current: InstallationHandoffV3ProgressFile,
): Promise<void> {
  const retained = await readInstallationHandoffV3ProgressFile(
    historyPath,
    backupDirectory,
    current.progress.core,
  );
  if (!isDeepStrictEqual(retained, current)) {
    throw new InstallationHandoffV3Error(
      "recovery_conflict",
      "Retained handoff progress differs from the exact CAS input.",
    );
  }
}

async function publishCreateOnlyPrivateFile(
  path: string,
  bytes: Buffer,
  maximumBytes: number,
  label: string,
  options: InstallationHandoffV3PublicationTestOptions,
  heldDirectory: HeldPrivateDirectory,
): Promise<InstallationHandoffV3PrivateFileEvidence> {
  const parent = dirname(path);
  await assertPrivateCanonicalDirectory(parent);
  if (heldDirectory.path !== parent) throw unsafeFile();
  const pending = join(
    parent,
    `.${basename(path)}.pending.${process.pid}.${randomBytes(12).toString("hex")}`,
  );
  const expected = await writeCreateOnlyPrivateFile(
    pending,
    bytes,
    maximumBytes,
  );
  await syncHeldDirectory(heldDirectory);
  await options.afterCandidateSyncForTest?.();
  let sourceAuthority: Awaited<ReturnType<
    typeof inspectProspectivePathAuthority
  >>;
  let destinationAuthority: Awaited<ReturnType<
    typeof inspectProspectivePathAuthority
  >>;
  try {
    [sourceAuthority, destinationAuthority] = await Promise.all([
      inspectProspectivePathAuthority(pending, `${label} candidate`),
      inspectProspectivePathAuthority(path, label),
    ]);
  } catch (error: unknown) {
    await removeUnpublishedPrivateCandidate(
      path,
      pending,
      maximumBytes,
      expected,
      heldDirectory,
    );
    throw error;
  }
  try {
    await renameWithPathAuthority(sourceAuthority, destinationAuthority, {
      ...(options.beforeRenameForTest === undefined
        ? {}
        : { beforeRenameForTest: options.beforeRenameForTest }),
    });
  } catch (error: unknown) {
    await revalidateHeldDirectory(heldDirectory);
    const classified = await tryReadExactPrivateFile(
      path,
      maximumBytes,
      expected,
    );
    if (classified === null) {
      await removeUnpublishedPrivateCandidate(
        path,
        pending,
        maximumBytes,
        expected,
        heldDirectory,
      );
      throw error;
    }
    classified.bytes.fill(0);
    await syncHeldDirectory(heldDirectory);
    return classified.evidence;
  }
  await options.afterRenameForTest?.();
  await syncHeldDirectory(heldDirectory);
  const published = await readExactPrivateFile(path, maximumBytes, expected);
  published.bytes.fill(0);
  return published.evidence;
}

async function removeUnpublishedPrivateCandidate(
  finalPath: string,
  pendingPath: string,
  maximumBytes: number,
  expected: InstallationHandoffV3PrivateFileEvidence,
  directory: HeldPrivateDirectory,
): Promise<void> {
  await unlinkBoundPrivateFile(
    pendingPath,
    maximumBytes,
    directory,
    expected,
  );
  await revalidateHeldDirectory(directory);
  const names = await readdir(directory.path);
  await revalidateHeldDirectory(directory);
  const finalName = basename(finalPath);
  const pendingPrefix = `.${finalName}.pending.`;
  if (
    names.includes(finalName)
    || names.some(name => name.startsWith(pendingPrefix))
  ) throw unsafeFile();
}

async function writeCreateOnlyPrivateFile(
  path: string,
  bytes: Buffer,
  maximumBytes: number,
): Promise<InstallationHandoffV3PrivateFileEvidence> {
  requireAbsoluteNormalized(path, "private handoff file");
  await assertPrivateCanonicalDirectory(dirname(path));
  if (bytes.byteLength === 0 || bytes.byteLength > maximumBytes) {
    bytes.fill(0);
    throw new InstallationHandoffV3Error(
      "backup_invalid",
      "Handoff file exceeds its bounded encoding.",
    );
  }
  const handle = await open(
    path,
    constants.O_WRONLY | constants.O_CREAT | constants.O_EXCL
      | constants.O_NOFOLLOW | closeOnExec,
    0o600,
  );
  const digest = createHash("sha256").update(bytes).digest("hex");
  try {
    await handle.writeFile(bytes);
    await handle.chmod(0o600);
    await handle.sync();
    const held = await handle.stat({ bigint: true });
    const published = await lstat(path, { bigint: true });
    const currentUser = process.geteuid?.();
    if (
      !held.isFile()
      || held.isSymbolicLink()
      || held.nlink !== 1n
      || (held.mode & 0o777n) !== 0o600n
      || currentUser === undefined
      || held.uid !== BigInt(currentUser)
      || held.size !== BigInt(bytes.byteLength)
      || held.dev !== published.dev
      || held.ino !== published.ino
      || published.isSymbolicLink()
    ) throw unsafeFile();
    return {
      bytes: bytes.byteLength,
      device: held.dev.toString(10),
      inode: held.ino.toString(10),
      sha256: digest,
    };
  } finally {
    bytes.fill(0);
    await handle.close();
  }
}

async function unlinkBoundPrivateFile(
  path: string,
  maximumBytes: number,
  directory: HeldPrivateDirectory,
  expected?: InstallationHandoffV3PrivateFileEvidence,
): Promise<void> {
  if (dirname(path) !== directory.path) throw unsafeFile();
  const handle = await open(
    path,
    constants.O_RDONLY | constants.O_NOFOLLOW | closeOnExec,
  );
  try {
    const held = await handle.stat({ bigint: true });
    const published = await lstat(path, { bigint: true });
    const currentUser = process.geteuid?.();
    if (
      !held.isFile()
      || held.isSymbolicLink()
      || held.nlink !== 1n
      || (held.mode & 0o777n) !== 0o600n
      || held.size > BigInt(maximumBytes)
      || currentUser === undefined
      || held.uid !== BigInt(currentUser)
      || held.dev !== published.dev
      || held.ino !== published.ino
      || published.isSymbolicLink()
      || (
        expected !== undefined
        && (
          held.dev.toString(10) !== expected.device
          || held.ino.toString(10) !== expected.inode
          || Number(held.size) !== expected.bytes
        )
      )
    ) throw unsafeFile();
    await unlink(path);
    const after = await handle.stat({ bigint: true });
    if (
      after.dev !== held.dev
      || after.ino !== held.ino
      || after.nlink !== 0n
    ) throw unsafeFile();
    await syncHeldDirectory(directory);
    try {
      await lstat(path);
      throw unsafeFile();
    } catch (error: unknown) {
      if (!hasCode(error, "ENOENT")) throw error;
    }
  } finally {
    await handle.close();
  }
}

async function readExactPrivateFile(
  path: string,
  maximumBytes: number,
  expected?: Readonly<{
    bytes: number;
    device: string;
    inode: string;
    sha256: string;
  }>,
): Promise<Readonly<{
  bytes: Buffer;
  evidence: Readonly<{
    bytes: number;
    device: string;
    inode: string;
    sha256: string;
  }>;
}>> {
  requireAbsoluteNormalized(path, "private handoff file");
  await assertPrivateCanonicalDirectory(dirname(path));
  const handle = await open(
    path,
    constants.O_RDONLY | constants.O_NOFOLLOW | closeOnExec,
  );
  try {
    const before = await handle.stat({ bigint: true });
    const publishedBefore = await lstat(path, { bigint: true });
    const currentUser = process.geteuid?.();
    if (
      !before.isFile()
      || before.isSymbolicLink()
      || before.nlink !== 1n
      || (before.mode & 0o777n) !== 0o600n
      || currentUser === undefined
      || before.uid !== BigInt(currentUser)
      || before.size <= 0n
      || before.size > BigInt(maximumBytes)
      || publishedBefore.dev !== before.dev
      || publishedBefore.ino !== before.ino
      || publishedBefore.isSymbolicLink()
    ) throw unsafeFile();
    const capacity = Number(before.size) + 1;
    const storage = Buffer.alloc(capacity);
    let offset = 0;
    while (offset < capacity) {
      const { bytesRead } = await handle.read(
        storage,
        offset,
        capacity - offset,
        null,
      );
      if (bytesRead === 0) break;
      offset += bytesRead;
    }
    const after = await handle.stat({ bigint: true });
    const publishedAfter = await lstat(path, { bigint: true });
    if (
      offset !== Number(before.size)
      || before.dev !== after.dev
      || before.ino !== after.ino
      || before.size !== after.size
      || before.mtimeNs !== after.mtimeNs
      || before.ctimeNs !== after.ctimeNs
      || after.dev !== publishedAfter.dev
      || after.ino !== publishedAfter.ino
      || publishedAfter.isSymbolicLink()
    ) {
      storage.fill(0);
      throw unsafeFile();
    }
    const bytes = storage.subarray(0, offset);
    const evidence = {
      bytes: offset,
      device: before.dev.toString(10),
      inode: before.ino.toString(10),
      sha256: createHash("sha256").update(bytes).digest("hex"),
    };
    if (expected !== undefined && !isDeepStrictEqual(evidence, {
      bytes: expected.bytes,
      device: expected.device,
      inode: expected.inode,
      sha256: expected.sha256,
    })) {
      bytes.fill(0);
      throw unsafeFile();
    }
    return { bytes, evidence };
  } finally {
    await handle.close();
  }
}

async function tryReadExactPrivateFile(
  path: string,
  maximumBytes: number,
  expected?: InstallationHandoffV3PrivateFileEvidence,
): Promise<Awaited<ReturnType<typeof readExactPrivateFile>> | null> {
  try {
    return await readExactPrivateFile(path, maximumBytes, expected);
  } catch (error: unknown) {
    if (hasCode(error, "ENOENT")) return null;
    throw error;
  }
}

async function inspectCandidateManifest(
  appPath: string,
  expected?: InstallationHandoffV3ManifestEvidence,
): Promise<InstallationHandoffV3ManifestEvidence> {
  const path = join(appPath, "Contents/Resources/runtime/manifest.json");
  const handle = await open(
    path,
    constants.O_RDONLY | constants.O_NOFOLLOW | closeOnExec,
  );
  try {
    const before = await handle.stat({ bigint: true });
    const published = await lstat(path, { bigint: true });
    if (
      !before.isFile()
      || before.isSymbolicLink()
      || before.nlink !== 1n
      || (before.mode & 0o022n) !== 0n
      || before.size <= 0n
      || before.size > BigInt(maximumManifestBytes)
      || published.dev !== before.dev
      || published.ino !== before.ino
    ) throw unsafeFile();
    const bytes = await handle.readFile();
    const after = await handle.stat({ bigint: true });
    if (
      bytes.byteLength !== Number(before.size)
      || after.dev !== before.dev
      || after.ino !== before.ino
      || after.size !== before.size
      || after.mtimeNs !== before.mtimeNs
      || after.ctimeNs !== before.ctimeNs
    ) throw unsafeFile();
    let manifest: unknown;
    let manifestSha256: string;
    try {
      manifestSha256 = createHash("sha256").update(bytes).digest("hex");
      manifest = JSON.parse(bytes.toString("utf8")) as unknown;
    } finally {
      bytes.fill(0);
    }
    if (!isRecord(manifest)) throw invalidCandidate();
    const release = manifest["release"];
    const runtime = manifest["runtime"];
    if (!isRecord(release) || !isRecord(runtime)) throw invalidCandidate();
    const evidence = {
      bytes: Number(before.size),
      commit: release["commit"],
      device: before.dev.toString(10),
      inode: before.ino.toString(10),
      runtimeTreeSha256: runtime["treeSha256"],
      sha256: manifestSha256,
    };
    const parsed = candidateSchema.shape.manifest.safeParse(evidence);
    if (!parsed.success) throw invalidCandidate();
    if (expected !== undefined && !isDeepStrictEqual(parsed.data, expected)) {
      throw unsafeFile();
    }
    return parsed.data;
  } finally {
    await handle.close();
  }
}

async function inspectDirectoryNode(
  path: string,
): Promise<InstallationHandoffV3NodeEvidence> {
  const status = await lstat(path, { bigint: true });
  if (
    !status.isDirectory()
    || status.isSymbolicLink()
    || await realpath(path) !== path
  ) throw unsafeFile();
  return {
    device: status.dev.toString(10),
    inode: status.ino.toString(10),
  };
}

function serializeProgress(progress: InstallationHandoffV3Progress): Buffer {
  return Buffer.from(
    `${JSON.stringify(parseInstallationHandoffV3Progress(progress), null, 2)}\n`,
    "utf8",
  );
}

async function openHeldPrivateDirectory(
  pathValue: string,
): Promise<HeldPrivateDirectory> {
  const path = requireAbsoluteNormalized(pathValue, "handoff backup directory");
  await assertPrivateCanonicalDirectory(path);
  const before = await lstat(path, { bigint: true });
  const handle = await open(
    path,
    constants.O_RDONLY | constants.O_DIRECTORY | constants.O_NOFOLLOW
      | closeOnExec,
  );
  try {
    const held = await handle.stat({ bigint: true });
    const published = await lstat(path, { bigint: true });
    const currentUser = process.geteuid?.();
    if (
      !held.isDirectory()
      || held.isSymbolicLink()
      || currentUser === undefined
      || held.uid !== BigInt(currentUser)
      || (held.mode & privateDirectoryModeMask) !== 0n
      || held.dev !== before.dev
      || held.ino !== before.ino
      || held.dev !== published.dev
      || held.ino !== published.ino
      || published.isSymbolicLink()
      || await realpath(path) !== path
    ) throw unsafeFile();
    return {
      device: held.dev,
      handle,
      inode: held.ino,
      mode: held.mode & 0o777n,
      owner: held.uid,
      path,
    };
  } catch (error: unknown) {
    await handle.close();
    throw error;
  }
}

async function revalidateHeldDirectory(
  directory: HeldPrivateDirectory,
): Promise<void> {
  const [held, published, canonical] = await Promise.all([
    directory.handle.stat({ bigint: true }),
    lstat(directory.path, { bigint: true }),
    realpath(directory.path),
  ]);
  if (
    !held.isDirectory()
    || held.isSymbolicLink()
    || held.dev !== directory.device
    || held.ino !== directory.inode
    || held.uid !== directory.owner
    || (held.mode & 0o777n) !== directory.mode
    || held.dev !== published.dev
    || held.ino !== published.ino
    || published.isSymbolicLink()
    || canonical !== directory.path
  ) throw unsafeFile();
}

async function syncHeldDirectory(directory: HeldPrivateDirectory): Promise<void> {
  await revalidateHeldDirectory(directory);
  await directory.handle.sync();
  await revalidateHeldDirectory(directory);
}

async function assertPrivateCanonicalDirectory(pathValue: string): Promise<void> {
  const path = requireAbsoluteNormalized(pathValue, "handoff backup directory");
  const status = await lstat(path, { bigint: true });
  const currentUser = process.geteuid?.();
  if (
    !status.isDirectory()
    || status.isSymbolicLink()
    || (status.mode & privateDirectoryModeMask) !== 0n
    || currentUser === undefined
    || status.uid !== BigInt(currentUser)
    || await realpath(path) !== path
  ) throw unsafeFile();
}

function requireAbsoluteNormalized(value: string, label: string): string {
  if (!isAbsoluteNormalizedNonRoot(value)) {
    throw new InstallationHandoffV3Error(
      "filesystem_unsafe",
      `${label} must be an absolute normalized non-root path.`,
    );
  }
  return value;
}

function isAbsoluteNormalizedNonRoot(value: string): boolean {
  return isAbsolute(value)
    && resolve(value) === value
    && value !== sep
    && !value.includes("\0");
}

function containsForbiddenKey(
  value: unknown,
  seen: WeakSet<object>,
): boolean {
  if (value === null || typeof value !== "object" || seen.has(value)) {
    return false;
  }
  seen.add(value);
  return Object.entries(value).some(([key, child]) =>
    forbiddenKeys.has(key) || containsForbiddenKey(child, seen)
  );
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return value !== null && typeof value === "object" && !Array.isArray(value);
}

function invalidCore(): InstallationHandoffV3Error {
  return new InstallationHandoffV3Error(
    "backup_invalid",
    "Immutable schema-v3 handoff authorization is invalid.",
  );
}

function invalidProgress(): InstallationHandoffV3Error {
  return new InstallationHandoffV3Error(
    "backup_invalid",
    "Schema-v3 handoff progress is invalid.",
  );
}

function invalidCandidate(): InstallationHandoffV3Error {
  return new InstallationHandoffV3Error(
    "candidate_invalid",
    "Schema-v3 candidate evidence is invalid.",
  );
}

function unsafeFile(): InstallationHandoffV3Error {
  return new InstallationHandoffV3Error(
    "filesystem_unsafe",
    "Schema-v3 handoff file authority is unsafe.",
  );
}

function errorMessage(error: unknown): string {
  return error instanceof Error ? error.message : String(error);
}

function hasCode(error: unknown, code: string): boolean {
  return error instanceof Error
    && "code" in error
    && (error as NodeJS.ErrnoException).code === code;
}
