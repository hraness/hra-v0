import { createHash, randomBytes } from "node:crypto";
import { constants, type BigIntStats } from "node:fs";
import {
  chmod,
  lstat,
  mkdir,
  open,
  readdir,
  readlink,
  realpath,
  rename,
  writeFile,
} from "node:fs/promises";
import { userInfo } from "node:os";
import {
  basename,
  dirname,
  isAbsolute,
  join,
  relative,
  resolve,
  sep,
} from "node:path";
import { isDeepStrictEqual } from "node:util";

import { z } from "@hra-internal/schema";

const oCloexec = (constants as typeof constants & { O_CLOEXEC?: number })
  .O_CLOEXEC ?? 0;

import { strictBundleSignaturePolicy } from "./historical-oprte-preview";
import {
  assertKeychainContinuity,
  assertStateContinuity,
  defaultInstallationHandoffDependencies,
  eraseKeychainEvidence,
  inspectInstallationBundle,
  inspectKeychainContinuity,
  inspectStateContinuity,
  inspectStateContinuityWithoutHarnessEnrollmentSidecar,
  installationHandoffPaths,
  type BundleContinuityEvidence,
  type HeldLock,
  type InstallationHandoffDependencies,
  type InstallationHandoffPaths,
  type KeychainEvidence,
  type StateContinuityEvidence,
} from "./installation-handoff";
import {
  parseFrozenV0114InstallationHandoffReceipt,
} from "./frozen-v0114-installation-handoff-receipt";
import {
  authoritiesOverlap,
  inspectProspectivePathAuthority,
  renameWithPathAuthority,
  renameSwapForwardOnly,
} from "./installation-path-authority";
import {
  acquireControlPlaneLifetimeLock,
  type ControlPlaneLifetimeLock,
} from "./src/state/control-plane-lock";
import {
  verifyPublishedReleaseCandidate,
} from "./release-download-contract";
import {
  productionCustodyProbeSupervisorAuthoritySchema,
  type CustodyProbeSupervisorAuthorityEvidence,
} from "./custody-probe-supervisor-authority";
import {
  inspectResidentEnrollmentCustodyNoUi,
} from "./resident-custody-probe-adapter";
import {
  canonicalHarnessKeyEnrollmentSidecar,
  authorizedHarnessKeyEnrollmentSidecar,
  createForwardHarnessKeyEnrollmentAuthorization,
  harnessKeyEnrollmentSidecarSchema,
  readHarnessKeyEnrollmentSidecar,
  removeExactHarnessKeyEnrollmentSidecar,
  writeHarnessKeyEnrollmentSidecar,
  type HarnessKeyEnrollmentFile,
  type HarnessKeyEnrollmentFileEvidence,
  type HarnessKeyEnrollmentSidecar,
} from "./src/state/harness-key-enrollment";

export const forwardRecoveryConfirmation =
  "FORWARD-RECOVER-HRA-0.1.14-TO-0.1.15" as const;
export const forwardRecoveryResumeConfirmation =
  "RESUME-FORWARD-HRA-RECOVERY" as const;
export const forwardRecoveryCleanupConfirmation =
  "CLEAN-FORWARD-HRA-RECOVERY" as const;

export const frozenHraV0114Origin = Object.freeze({
  commit: "7b39c459827b2acf45aa2d911c94fdb5d4f37860",
  identity: Object.freeze({
    build: "15",
    bundleIdentifier: "kitchen.hraness",
    executable: "hra",
    version: "0.1.14",
  }),
  runtimeTreeSha256:
    "abe6451154a706398cc819ea6b4f25e46195572c9bdd39bf70cb033790e4bd93",
} as const);

export const forwardHraV0115CandidateIdentity = Object.freeze({
  build: "16",
  bundleIdentifier: "kitchen.hraness",
  executable: "hra",
  version: "0.1.15",
} as const);

const maximumReceiptBytes = 1024 * 1024;
const maximumManifestBytes = 4 * 1024 * 1024;
const maximumTreeBytes = 128 * 1024 * 1024 * 1024;
const maximumTreeEntries = 2_000_000;
const operationIdPattern = /^forward_[a-f0-9]{24}$/u;
const sha256Pattern = /^[0-9a-f]{64}$/u;
const commitPattern = /^[0-9a-f]{40}$/u;
const decimalBigIntPattern = /^(?:0|[1-9][0-9]*)$/u;
const forbiddenReceiptKeys = new Set(["__proto__", "constructor", "prototype"]);

export type ForwardRecoveryFaultPoint =
  | "after_authorizing_receipt"
  | "after_enrollment_authorized"
  | "after_prepared"
  | "after_swap_before_receipt"
  | "after_published_receipt"
  | "after_verified_receipt"
  | "after_retired_origin_cleanup";

export type ForwardKeychainContinuity =
  | "pending_same_process"
  | "verified_same_process"
  | "unavailable_after_process_restart"
  | "not_applicable";

export type ForwardRecoveryPhase =
  | "authorizing"
  | "prepared"
  | "published"
  | "verified"
  | "complete"
  | "aborted";

export type ForwardRecoveryDisposition =
  | "prepublish"
  | "prepublish_cleanup"
  | "postpublish"
  | "postpublish_cleanup"
  | "complete"
  | "aborted"
  | "conflict";

export interface ForwardNodeEvidence {
  readonly device: string;
  readonly inode: string;
}

export interface ForwardManifestEvidence extends ForwardNodeEvidence {
  readonly bytes: number;
  readonly commit: string;
  readonly runtimeTreeSha256: string;
  readonly sha256: string;
}

export interface ForwardBundleEvidence {
  readonly bundle: BundleContinuityEvidence;
  readonly manifest: ForwardManifestEvidence;
  readonly root: ForwardNodeEvidence;
}

export interface ForwardCandidateEvidence extends ForwardBundleEvidence {
  readonly custodyProbeSupervisor: CustodyProbeSupervisorAuthorityEvidence;
}

export interface ForwardCommittedOriginReceiptEvidence
  extends ForwardNodeEvidence {
  readonly backupDirectory: string;
  readonly bundle: BundleContinuityEvidence;
  readonly bytes: number;
  readonly operationId: string;
  readonly sha256: string;
}

export interface ForwardRecoveryReceiptPaths extends InstallationHandoffPaths {
  readonly cleanupTombstoneApp: string;
  readonly forwardBackupDirectory: string;
  readonly retiredOriginApp: string;
}

interface ForwardReceiptCommon {
  readonly schemaVersion: 1;
  readonly createdAt: number;
  readonly operationId: string;
  readonly paths: ForwardRecoveryReceiptPaths;
  readonly preState: StateContinuityEvidence;
  readonly state: StateContinuityEvidence;
  readonly origin: ForwardBundleEvidence;
  readonly candidate: ForwardCandidateEvidence;
  readonly committedOriginReceipt: ForwardCommittedOriginReceiptEvidence;
  readonly keychainDescriptors: readonly string[];
  readonly enrollment: Readonly<{
    readonly authorizedSidecar: HarnessKeyEnrollmentSidecar;
    readonly file: HarnessKeyEnrollmentFileEvidence | null;
  }>;
}

export type ForwardRecoveryReceipt =
  | Readonly<ForwardReceiptCommon & {
      phase: "authorizing" | "prepared" | "published";
      keychainContinuity:
        | "pending_same_process"
        | "unavailable_after_process_restart";
    }>
  | Readonly<ForwardReceiptCommon & {
      phase: "verified";
      keychainContinuity: "verified_same_process";
    }>
  | Readonly<ForwardReceiptCommon & {
      phase: "complete";
      keychainContinuity:
        | "verified_same_process"
        | "unavailable_after_process_restart";
    }>
  | Readonly<ForwardReceiptCommon & {
      phase: "aborted";
      keychainContinuity: "not_applicable";
    }>;

export interface ForwardRecoveryInput {
  readonly backupDirectory: string;
  readonly candidateApp: string;
  readonly confirmation: string;
  readonly originHandoffBackupDirectory: string;
  readonly paths?: InstallationHandoffPaths;
  readonly onCheckpoint?: (point: ForwardRecoveryFaultPoint) => void;
}

export interface ForwardRecoveryResumeInput {
  readonly backupDirectory: string;
  readonly confirmation: string;
  readonly onCheckpoint?: (point: ForwardRecoveryFaultPoint) => void;
}

export interface ForwardRecoveryCleanupInput {
  readonly backupDirectory: string;
  readonly confirmation: string;
  readonly onCheckpoint?: (point: ForwardRecoveryFaultPoint) => void;
}

export interface ForwardRecoveryStatus {
  readonly disposition: ForwardRecoveryDisposition;
  readonly keychainContinuity:
    | "verified_same_process"
    | "unavailable_after_process_restart"
    | "not_checked"
    | "not_applicable";
  readonly operationId: string;
  readonly phase: ForwardRecoveryPhase;
  readonly state: "unchanged" | "not_inspected";
}

type ForwardPublishResult = Readonly<{
  status: "published" | "postcondition_unknown_after_swap";
}>;

export interface ForwardRecoveryDependencies {
  readonly acquireControlPlaneLock: (
    controlPlanePath: string,
  ) => ControlPlaneLifetimeLock;
  readonly acquireNativeLock: (path: string) => HeldLock;
  readonly assertKeychain: (evidence: KeychainEvidence) => Promise<void>;
  readonly captureKeychain: (controlPlanePath: string) => Promise<KeychainEvidence>;
  readonly copyTree: (source: string, destination: string) => Promise<void>;
  readonly eraseKeychain: (evidence: KeychainEvidence | null) => void;
  readonly inspectBundle: (path: string) => Promise<ForwardBundleEvidence>;
  readonly inspectCandidate: (path: string) => Promise<ForwardCandidateEvidence>;
  readonly inspectOrigin: (path: string) => Promise<ForwardBundleEvidence>;
  readonly inspectEnrollmentKeychainNoUi: (
    candidateApp: string,
    authority: CustodyProbeSupervisorAuthorityEvidence,
  ) => Promise<ForwardEnrollmentCustodyObservation>;
  readonly readEnrollmentSidecar: (
    controlPlanePath: string,
  ) => Promise<HarnessKeyEnrollmentFile | null>;
  readonly writeEnrollmentSidecar: (
    controlPlanePath: string,
    sidecar: HarnessKeyEnrollmentSidecar,
    expected: HarnessKeyEnrollmentFile | null,
  ) => Promise<HarnessKeyEnrollmentFile>;
  readonly removeEnrollmentSidecar: (
    controlPlanePath: string,
    expected: HarnessKeyEnrollmentFile,
  ) => Promise<void>;
  readonly inspectState: (
    stateRoot: string,
    controlPlanePath: string,
  ) => Promise<StateContinuityEvidence>;
  readonly inspectStateWithoutEnrollmentSidecar: (
    stateRoot: string,
    controlPlanePath: string,
  ) => Promise<StateContinuityEvidence>;
  readonly now: () => number;
  readonly openFilesAreQuiescent: (
    paths: InstallationHandoffPaths,
  ) => Promise<boolean>;
  readonly publishForward: (
    source: string,
    destination: string,
  ) => Promise<ForwardPublishResult>;
  readonly quitApplications: (bundleRoots: readonly string[]) => Promise<void>;
  readonly randomBytes: (length: number) => Uint8Array;
  readonly stageForDeletion: (source: string, tombstone: string) => Promise<void>;
  readonly syncStagedTree: (path: string) => Promise<void>;
  readonly updaterIsQuiescent: (
    paths: InstallationHandoffPaths,
  ) => Promise<boolean>;
}

const forwardEnrollmentCustodyObservationSchema = z.discriminatedUnion(
  "state",
  [
    z.object({ state: z.literal("absent") }).strict(),
    z.object({
      envelopeSha256: z.string().regex(sha256Pattern),
      state: z.literal("present"),
      strictAcl: z.literal(true),
    }).strict(),
  ],
);

export type ForwardEnrollmentCustodyObservation = z.infer<
  typeof forwardEnrollmentCustodyObservationSchema
>;

export class InstallationForwardRecoveryError extends Error {
  readonly code:
    | "app_running"
    | "candidate_invalid"
    | "confirmation_invalid"
    | "continuity_failed"
    | "filesystem_unsafe"
    | "invalid_arguments"
    | "keychain_unavailable"
    | "origin_invalid"
    | "receipt_invalid"
    | "recovery_conflict"
    | "updater_active";

  constructor(code: InstallationForwardRecoveryError["code"], message: string) {
    super(message);
    this.name = "InstallationForwardRecoveryError";
    this.code = code;
  }
}

/** Test-only process-loss signal. CLI callers cannot install a checkpoint. */
export class ForwardRecoveryProcessExitForTest extends Error {
  constructor(point: ForwardRecoveryFaultPoint) {
    super(`process-exit:${point}`);
    this.name = "ForwardRecoveryProcessExitForTest";
  }
}

const nonNegativeSafeIntegerSchema = z.number().int().nonnegative()
  .max(Number.MAX_SAFE_INTEGER);
const sha256Schema = z.string().regex(sha256Pattern);
const decimalBigIntSchema = z.string().regex(decimalBigIntPattern);
const normalizedPathSchema = z.string().min(2).max(4096).refine(
  value => isAbsoluteNormalizedNonRoot(value),
  "path must be absolute, normalized, and non-root",
);
const nodeEvidenceSchema = z.object({
  device: decimalBigIntSchema,
  inode: decimalBigIntSchema,
}).strict();
const manifestEvidenceSchema = nodeEvidenceSchema.extend({
  bytes: nonNegativeSafeIntegerSchema.max(maximumManifestBytes),
  commit: z.string().regex(commitPattern),
  runtimeTreeSha256: sha256Schema,
  sha256: sha256Schema,
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
    migrationVersion: z.literal(62),
    quickCheck: z.literal("ok"),
    rows: z.record(
      z.string().regex(/^[A-Za-z_][A-Za-z0-9_]{0,127}$/u),
      nonNegativeSafeIntegerSchema,
    ).refine(value => Object.keys(value).length <= 4096, "too many database rows"),
  }).strict(),
  dispatchWorktreeLanes: nonNegativeSafeIntegerSchema,
  harnessWorktreeLanes: nonNegativeSafeIntegerSchema,
  localTaskWorktreeLanes: nonNegativeSafeIntegerSchema,
  sessionEntries: nonNegativeSafeIntegerSchema,
  tree: treeEvidenceSchema,
}).strict();
const strictSignatureEvidenceSchema = z.object({
  policy: z.literal(strictBundleSignaturePolicy),
}).strict();
const identitySchema = (identity: Readonly<{
  build: string;
  bundleIdentifier: string;
  executable: string;
  version: string;
}>) => z.object({
  build: z.literal(identity.build),
  bundleIdentifier: z.literal(identity.bundleIdentifier),
  executable: z.literal(identity.executable),
  version: z.literal(identity.version),
}).strict();
const bundleSchema = (identity: Parameters<typeof identitySchema>[0]) => z.object({
  identity: identitySchema(identity),
  signature: strictSignatureEvidenceSchema,
  tree: treeEvidenceSchema,
}).strict();
const committedOriginReceiptEvidenceSchema = nodeEvidenceSchema.extend({
  backupDirectory: normalizedPathSchema,
  bundle: bundleSchema(frozenHraV0114Origin.identity),
  bytes: nonNegativeSafeIntegerSchema.max(maximumReceiptBytes),
  operationId: z.string().regex(/^handoff_[a-f0-9]{24}$/u),
  sha256: sha256Schema,
}).strict();
const forwardBundleSchema = (
  identity: Parameters<typeof identitySchema>[0],
  exactManifest?: Readonly<{ commit: string; runtimeTreeSha256: string }>,
) => z.object({
  bundle: bundleSchema(identity),
  manifest: manifestEvidenceSchema.superRefine((value, context) => {
    if (
      exactManifest !== undefined
      && (
        value.commit !== exactManifest.commit
        || value.runtimeTreeSha256 !== exactManifest.runtimeTreeSha256
      )
    ) {
      context.addIssue({ code: "custom", message: "manifest provenance differs" });
    }
  }),
  root: nodeEvidenceSchema,
}).strict();
const forwardCandidateSchema = forwardBundleSchema(
  forwardHraV0115CandidateIdentity,
).extend({
  custodyProbeSupervisor: productionCustodyProbeSupervisorAuthoritySchema,
}).strict();
const pathsSchema = z.object({
  applicationsDirectory: normalizedPathSchema,
  candidateApp: normalizedPathSchema,
  canonicalApp: normalizedPathSchema,
  predecessorApp: normalizedPathSchema,
  stateRoot: normalizedPathSchema,
  controlPlanePath: normalizedPathSchema,
  nativeInstanceLockPath: normalizedPathSchema,
  updateHazardPath: normalizedPathSchema,
  updateHazardTemporaryPath: normalizedPathSchema,
  sparkleCacheRoots: z.array(normalizedPathSchema).min(1).max(16),
  cleanupTombstoneApp: normalizedPathSchema,
  forwardBackupDirectory: normalizedPathSchema,
  retiredOriginApp: normalizedPathSchema,
}).strict().superRefine((value, context) => {
  const operationId = extractOperationId(basename(value.retiredOriginApp));
  if (
    operationId === null
    || value.canonicalApp !== join(value.applicationsDirectory, "HRA.app")
    || value.predecessorApp !== join(value.applicationsDirectory, "OPRTE.app")
    || value.controlPlanePath !== join(value.stateRoot, "control-plane.sqlite")
    || value.cleanupTombstoneApp
      !== join(
        value.forwardBackupDirectory,
        `retired-${operationId ?? "invalid"}.app`,
      )
    || value.retiredOriginApp
      !== join(
        value.applicationsDirectory,
        `.${operationId ?? "invalid"}.forward-candidate.app`,
      )
  ) {
    context.addIssue({ code: "custom", message: "forward paths differ from fixed layout" });
  }
});
const keychainDescriptorsSchema = z.array(
  z.string().max(2048).refine(value => {
    const separator = value.indexOf("\u0000");
    return separator > 0
      && separator === value.lastIndexOf("\u0000")
      && separator < value.length - 1;
  }, "invalid Keychain descriptor"),
).max(4096).superRefine((value, context) => {
  if (new Set(value).size !== value.length) {
    context.addIssue({ code: "custom", message: "duplicate Keychain descriptor" });
  }
  const sorted = [...value].sort();
  if (sorted.some((entry, index) => entry !== value[index])) {
    context.addIssue({ code: "custom", message: "unsorted Keychain descriptors" });
  }
});
const enrollmentFileEvidenceSchema = z.object({
  bytes: nonNegativeSafeIntegerSchema.max(64 * 1_024),
  device: decimalBigIntSchema,
  inode: decimalBigIntSchema,
  sha256: sha256Schema,
}).strict();
const enrollmentPendingSchema = z.object({
  authorizedSidecar: harnessKeyEnrollmentSidecarSchema.refine(
    sidecar => sidecar.phase === "authorized"
      && sidecar.authorization.kind === "forward_recovery_v1",
    "forward enrollment sidecar must remain authorized",
  ),
  file: z.null(),
}).strict();
const enrollmentBoundSchema = z.object({
  authorizedSidecar: harnessKeyEnrollmentSidecarSchema.refine(
    sidecar => sidecar.phase === "authorized"
      && sidecar.authorization.kind === "forward_recovery_v1",
    "forward enrollment sidecar must remain authorized",
  ),
  file: enrollmentFileEvidenceSchema,
}).strict();
const receiptCommonShape = {
  schemaVersion: z.literal(1),
  createdAt: nonNegativeSafeIntegerSchema,
  operationId: z.string().regex(operationIdPattern),
  paths: pathsSchema,
  preState: stateEvidenceSchema,
  state: stateEvidenceSchema,
  origin: forwardBundleSchema(frozenHraV0114Origin.identity, {
    commit: frozenHraV0114Origin.commit,
    runtimeTreeSha256: frozenHraV0114Origin.runtimeTreeSha256,
  }),
  candidate: forwardCandidateSchema,
  committedOriginReceipt: committedOriginReceiptEvidenceSchema,
  keychainDescriptors: keychainDescriptorsSchema,
} as const;
const forwardRecoveryReceiptSchema = z.discriminatedUnion("phase", [
  z.object({
    ...receiptCommonShape,
    phase: z.literal("authorizing"),
    keychainContinuity: z.enum([
      "pending_same_process",
      "unavailable_after_process_restart",
    ]),
    enrollment: enrollmentPendingSchema,
  }).strict(),
  z.object({
    ...receiptCommonShape,
    phase: z.enum(["prepared", "published"]),
    keychainContinuity: z.enum([
      "pending_same_process",
      "unavailable_after_process_restart",
    ]),
    enrollment: enrollmentBoundSchema,
  }).strict(),
  z.object({
    ...receiptCommonShape,
    phase: z.literal("verified"),
    keychainContinuity: z.literal("verified_same_process"),
    enrollment: enrollmentBoundSchema,
  }).strict(),
  z.object({
    ...receiptCommonShape,
    phase: z.literal("complete"),
    keychainContinuity: z.enum([
      "verified_same_process",
      "unavailable_after_process_restart",
    ]),
    enrollment: enrollmentBoundSchema,
  }).strict(),
  z.object({
    ...receiptCommonShape,
    phase: z.literal("aborted"),
    keychainContinuity: z.literal("not_applicable"),
    enrollment: enrollmentPendingSchema,
  }).strict(),
]).superRefine((value, context) => {
  if (
    value.paths.retiredOriginApp
      !== forwardRecoveryStagePath(value.paths.applicationsDirectory, value.operationId)
  ) {
    context.addIssue({ code: "custom", message: "operation staging path differs" });
  }
  if (JSON.stringify(value.origin.bundle) !== JSON.stringify(
    value.committedOriginReceipt.bundle,
  )) {
    context.addIssue({
      code: "custom",
      message: "origin bundle differs from committed schema-v2 evidence",
    });
  }
  const authorization = value.enrollment.authorizedSidecar.authorization;
  if (
    authorization.kind !== "forward_recovery_v1"
    || authorization.operationId !== value.operationId
    || JSON.stringify(authorization.committedOriginReceipt)
      !== JSON.stringify(value.committedOriginReceipt)
    || JSON.stringify(authorization.candidate) !== JSON.stringify(value.candidate)
    || authorization.preStateSha256
      !== createForwardHarnessKeyEnrollmentAuthorization({
        operationId: value.operationId,
        committedOriginReceipt: value.committedOriginReceipt,
        candidate: value.candidate,
        preState: value.preState,
      }).preStateSha256
  ) {
    context.addIssue({
      code: "custom",
      message: "enrollment authorization differs from forward evidence",
    });
  }
  if (
    (value.phase === "authorizing" || value.phase === "aborted")
    && JSON.stringify(value.state) !== JSON.stringify(value.preState)
  ) {
    context.addIssue({
      code: "custom",
      message: "pre-enrollment phase must retain exact pre-state evidence",
    });
  }
});

export function parseForwardRecoveryReceipt(value: unknown): ForwardRecoveryReceipt {
  if (containsForbiddenReceiptKey(value, new WeakSet<object>())) {
    throw invalidReceipt();
  }
  const parsed = forwardRecoveryReceiptSchema.safeParse(value);
  if (!parsed.success) throw invalidReceipt();
  return parsed.data;
}

function containsForbiddenReceiptKey(
  value: unknown,
  seen: WeakSet<object>,
): boolean {
  if (value === null || typeof value !== "object" || seen.has(value)) return false;
  seen.add(value);
  return Object.entries(value).some(([key, child]) =>
    forbiddenReceiptKeys.has(key) || containsForbiddenReceiptKey(child, seen)
  );
}

function invalidReceipt(): InstallationForwardRecoveryError {
  return new InstallationForwardRecoveryError(
    "receipt_invalid",
    "Forward-recovery receipt is invalid.",
  );
}

function extractOperationId(stageName: string): string | null {
  const match = /^\.(forward_[a-f0-9]{24})\.forward-candidate\.app$/u.exec(stageName);
  return match?.[1] ?? null;
}

export function forwardRecoveryStagePath(
  applicationsDirectory: string,
  operationId: string,
): string {
  const directory = requireAbsoluteNormalized(
    applicationsDirectory,
    "Applications directory",
  );
  if (!operationIdPattern.test(operationId)) {
    throw new InstallationForwardRecoveryError(
      "invalid_arguments",
      "Forward-recovery operation ID is invalid.",
    );
  }
  return join(directory, `.${operationId}.forward-candidate.app`);
}

export function forwardRecoveryTombstonePath(
  backupDirectory: string,
  operationId: string,
): string {
  const directory = requireAbsoluteNormalized(
    backupDirectory,
    "forward backup directory",
  );
  if (!operationIdPattern.test(operationId)) {
    throw new InstallationForwardRecoveryError(
      "invalid_arguments",
      "Forward-recovery operation ID is invalid.",
    );
  }
  return join(directory, `retired-${operationId}.app`);
}

type BoundedFileRead = Readonly<{
  bytes: Buffer;
  evidence: Readonly<ForwardNodeEvidence & { bytes: number; sha256: string }>;
}>;

async function readBoundedNoFollowFile(
  path: string,
  maximumBytes: number,
  expected?: Readonly<ForwardNodeEvidence & { bytes: number; sha256: string }>,
): Promise<BoundedFileRead> {
  const closeOnExecValue: unknown = Reflect.get(constants, "O_CLOEXEC");
  const closeOnExec = typeof closeOnExecValue === "number" ? closeOnExecValue : 0;
  const noFollow = typeof constants.O_NOFOLLOW === "number" ? constants.O_NOFOLLOW : 0;
  const handle = await open(path, constants.O_RDONLY | noFollow | closeOnExec);
  try {
    const before = await handle.stat({ bigint: true });
    const publishedBefore = await lstat(path, { bigint: true });
    if (
      !before.isFile()
      || before.isSymbolicLink()
      || before.nlink !== 1n
      || before.size > BigInt(maximumBytes)
      || before.dev !== publishedBefore.dev
      || before.ino !== publishedBefore.ino
      || publishedBefore.isSymbolicLink()
    ) {
      throw new InstallationForwardRecoveryError(
        "filesystem_unsafe",
        `Forward-recovery file authority is unsafe: ${basename(path)}.`,
      );
    }
    const bytes = await handle.readFile();
    const after = await handle.stat({ bigint: true });
    const publishedAfter = await lstat(path, { bigint: true });
    const evidence = {
      bytes: bytes.byteLength,
      device: before.dev.toString(10),
      inode: before.ino.toString(10),
      sha256: createHash("sha256").update(bytes).digest("hex"),
    };
    if (
      bytes.byteLength !== Number(before.size)
      || before.dev !== after.dev
      || before.ino !== after.ino
      || before.size !== after.size
      || before.mtimeNs !== after.mtimeNs
      || before.ctimeNs !== after.ctimeNs
      || after.dev !== publishedAfter.dev
      || after.ino !== publishedAfter.ino
      || publishedAfter.isSymbolicLink()
      || (
        expected !== undefined
        && (
          evidence.device !== expected.device
          || evidence.inode !== expected.inode
          || evidence.bytes !== expected.bytes
          || evidence.sha256 !== expected.sha256
        )
      )
    ) {
      bytes.fill(0);
      throw new InstallationForwardRecoveryError(
        "filesystem_unsafe",
        `Forward-recovery file changed while held: ${basename(path)}.`,
      );
    }
    return { bytes, evidence };
  } finally {
    await handle.close();
  }
}

async function inspectRootNode(path: string): Promise<ForwardNodeEvidence> {
  const status = await lstat(path, { bigint: true });
  if (
    !status.isDirectory()
    || status.isSymbolicLink()
    || await realpath(path) !== path
  ) {
    throw new InstallationForwardRecoveryError(
      "filesystem_unsafe",
      `Forward-recovery bundle root is unsafe: ${basename(path)}.`,
    );
  }
  return {
    device: status.dev.toString(10),
    inode: status.ino.toString(10),
  };
}

function requireRecord(value: unknown, label: string): Record<string, unknown> {
  if (value === null || typeof value !== "object" || Array.isArray(value)) {
    throw new InstallationForwardRecoveryError(
      "candidate_invalid",
      `${label} must be one object.`,
    );
  }
  return value as Record<string, unknown>;
}

function parseRuntimeManifest(
  bytes: Buffer,
  evidence: BoundedFileRead["evidence"],
): ForwardManifestEvidence {
  let value: unknown;
  try {
    value = JSON.parse(bytes.toString("utf8")) as unknown;
  } catch {
    throw new InstallationForwardRecoveryError(
      "candidate_invalid",
      "Runtime manifest JSON is invalid.",
    );
  } finally {
    bytes.fill(0);
  }
  if (containsForbiddenReceiptKey(value, new WeakSet<object>())) {
    throw new InstallationForwardRecoveryError(
      "candidate_invalid",
      "Runtime manifest contains a forbidden object key.",
    );
  }
  const manifest = requireRecord(value, "Runtime manifest");
  const release = requireRecord(manifest["release"], "Runtime manifest release");
  const runtime = requireRecord(manifest["runtime"], "Runtime manifest runtime");
  const commit = release["commit"];
  const runtimeTreeSha256 = runtime["treeSha256"];
  if (
    manifest["schemaVersion"] !== 1
    || typeof commit !== "string"
    || !commitPattern.test(commit)
    || typeof runtimeTreeSha256 !== "string"
    || !sha256Pattern.test(runtimeTreeSha256)
  ) {
    throw new InstallationForwardRecoveryError(
      "candidate_invalid",
      "Runtime manifest provenance is invalid.",
    );
  }
  return {
    ...evidence,
    commit,
    runtimeTreeSha256,
  };
}

async function inspectRuntimeManifest(
  appPath: string,
  expected?: ForwardManifestEvidence,
): Promise<ForwardManifestEvidence> {
  const path = join(appPath, "Contents", "Resources", "runtime", "manifest.json");
  const read = await readBoundedNoFollowFile(path, maximumManifestBytes, expected);
  const parsed = parseRuntimeManifest(read.bytes, read.evidence);
  if (
    expected !== undefined
    && (
      parsed.commit !== expected.commit
      || parsed.runtimeTreeSha256 !== expected.runtimeTreeSha256
    )
  ) {
    throw new InstallationForwardRecoveryError(
      "filesystem_unsafe",
      "Runtime manifest provenance changed after publication.",
    );
  }
  return parsed;
}

async function inspectCommittedOriginReceipt(
  backupDirectoryValue: string,
  expected?: ForwardCommittedOriginReceiptEvidence,
): Promise<ForwardCommittedOriginReceiptEvidence> {
  const backupDirectory = requireAbsoluteNormalized(
    backupDirectoryValue,
    "committed-origin backup directory",
  );
  await assertPrivateDirectory(backupDirectory);
  const path = join(backupDirectory, "handoff-receipt.json");
  const read = await readBoundedNoFollowFile(path, maximumReceiptBytes, expected);
  let value: unknown;
  try {
    value = JSON.parse(read.bytes.toString("utf8")) as unknown;
  } catch {
    throw new InstallationForwardRecoveryError(
      "origin_invalid",
      "Committed-origin handoff receipt JSON is invalid.",
    );
  } finally {
    read.bytes.fill(0);
  }
  let prior;
  try {
    prior = parseFrozenV0114InstallationHandoffReceipt(value);
  } catch {
    throw new InstallationForwardRecoveryError(
      "origin_invalid",
      "Committed origin is not a frozen schema-v2 HRA handoff receipt.",
    );
  }
  if (
    prior.phase !== "committed"
    || prior.candidate.identity.version !== frozenHraV0114Origin.identity.version
    || prior.candidate.identity.build !== frozenHraV0114Origin.identity.build
    || prior.candidateCommit !== frozenHraV0114Origin.commit
  ) {
    throw new InstallationForwardRecoveryError(
      "origin_invalid",
      "Committed origin is not the exact v0.1.14 build 15 handoff authority.",
    );
  }
  const evidence = {
    ...read.evidence,
    backupDirectory,
    bundle: prior.candidate,
    operationId: prior.operationId,
  };
  if (
    expected !== undefined
    && (
      evidence.backupDirectory !== expected.backupDirectory
      || JSON.stringify(evidence.bundle) !== JSON.stringify(expected.bundle)
      || evidence.bytes !== expected.bytes
      || evidence.device !== expected.device
      || evidence.inode !== expected.inode
      || evidence.operationId !== expected.operationId
      || evidence.sha256 !== expected.sha256
    )
  ) {
    throw new InstallationForwardRecoveryError(
      "origin_invalid",
      "Committed-origin handoff receipt changed after preparation.",
    );
  }
  return evidence;
}

function inside(root: string, path: string): boolean {
  const value = relative(root, path);
  return value === "" || (
    value !== ".."
    && !value.startsWith(`..${sep}`)
    && !isAbsolute(value)
  );
}

async function sha256NoFollowFile(path: string): Promise<string> {
  const value = await readBoundedNoFollowFile(path, maximumTreeBytes);
  try {
    return value.evidence.sha256;
  } finally {
    value.bytes.fill(0);
  }
}

async function inspectRuntimeTreeSha256(appPath: string): Promise<string> {
  const root = join(appPath, "Contents", "Resources", "runtime");
  const entries: Array<Readonly<{
    path: string;
    sha256?: string;
    target?: string;
    type: "file" | "symlink";
  }>> = [];
  let count = 0;
  async function visit(directory: string): Promise<void> {
    const children = await readdir(directory, { withFileTypes: true });
    children.sort((left, right) => left.name.localeCompare(right.name));
    for (const child of children) {
      count += 1;
      if (count > maximumTreeEntries) {
        throw new InstallationForwardRecoveryError(
          "origin_invalid",
          "Origin runtime tree is too large.",
        );
      }
      const path = join(directory, child.name);
      const relativePath = relative(root, path).split(sep).join("/");
      if (relativePath === "manifest.json") continue;
      if (child.isSymbolicLink()) {
        const target = await readlink(path);
        if (target.startsWith("/") || !inside(root, resolve(dirname(path), target))) {
          throw new InstallationForwardRecoveryError(
            "origin_invalid",
            `Origin runtime symlink escapes its root: ${relativePath}.`,
          );
        }
        entries.push({ path: relativePath, target, type: "symlink" });
      } else if (child.isDirectory()) {
        await visit(path);
      } else if (child.isFile()) {
        entries.push({
          path: relativePath,
          sha256: await sha256NoFollowFile(path),
          type: "file",
        });
      } else {
        throw new InstallationForwardRecoveryError(
          "origin_invalid",
          `Origin runtime contains a special file: ${relativePath}.`,
        );
      }
    }
  }
  await visit(root);
  return createHash("sha256")
    .update(`${JSON.stringify(entries)}\n`, "utf8")
    .digest("hex");
}

function assertIdentity(
  actual: BundleContinuityEvidence["identity"],
  expected: BundleContinuityEvidence["identity"],
  label: string,
): void {
  if (JSON.stringify(actual) !== JSON.stringify(expected)) {
    throw new InstallationForwardRecoveryError(
      label === "origin" ? "origin_invalid" : "candidate_invalid",
      `${label} bundle identity differs from the forward-recovery contract.`,
    );
  }
}

async function inspectGenericForwardBundle(path: string): Promise<ForwardBundleEvidence> {
  const rootBefore = await inspectRootNode(path);
  const manifest = await inspectRuntimeManifest(path);
  const bundle = await inspectInstallationBundle(path, strictBundleSignaturePolicy);
  const manifestAfter = await inspectRuntimeManifest(path, manifest);
  const rootAfter = await inspectRootNode(path);
  if (
    !sameNode(rootBefore, rootAfter)
    || JSON.stringify(manifest) !== JSON.stringify(manifestAfter)
  ) {
    throw new InstallationForwardRecoveryError(
      "filesystem_unsafe",
      "Application bundle changed while forward evidence was collected.",
    );
  }
  return { bundle, manifest, root: rootBefore };
}

async function inspectExactOrigin(path: string): Promise<ForwardBundleEvidence> {
  const evidence = await inspectGenericForwardBundle(path);
  assertIdentity(evidence.bundle.identity, frozenHraV0114Origin.identity, "origin");
  const actualRuntimeTree = await inspectRuntimeTreeSha256(path);
  if (
    evidence.manifest.commit !== frozenHraV0114Origin.commit
    || evidence.manifest.runtimeTreeSha256 !== frozenHraV0114Origin.runtimeTreeSha256
    || actualRuntimeTree !== frozenHraV0114Origin.runtimeTreeSha256
  ) {
    throw new InstallationForwardRecoveryError(
      "origin_invalid",
      "Canonical HRA is not the exact published v0.1.14 build 15 origin.",
    );
  }
  const finalEvidence = await inspectGenericForwardBundle(path);
  assertForwardBundleContent(evidence, finalEvidence, "origin revalidation", true);
  return evidence;
}

async function inspectExactCandidate(path: string): Promise<ForwardCandidateEvidence> {
  const evidence = await inspectGenericForwardBundle(path);
  assertIdentity(
    evidence.bundle.identity,
    forwardHraV0115CandidateIdentity,
    "candidate",
  );
  const packageEvidence = await verifyPublishedReleaseCandidate(path);
  if (
    packageEvidence.commit !== evidence.manifest.commit
    || packageEvidence.runtimeTreeSha256 !== evidence.manifest.runtimeTreeSha256
  ) {
    throw new InstallationForwardRecoveryError(
      "candidate_invalid",
      "Candidate provenance differs from its exact packaged runtime.",
    );
  }
  return Object.freeze({
    ...evidence,
    custodyProbeSupervisor: packageEvidence.custodyProbeSupervisor,
  });
}

async function publishForwardWithPathAuthority(
  source: string,
  destination: string,
): Promise<ForwardPublishResult> {
  const sourceAuthority = await inspectProspectivePathAuthority(
    source,
    "forward publication candidate",
  );
  const destinationAuthority = await inspectProspectivePathAuthority(
    destination,
    "forward publication origin",
  );
  if (sourceAuthority.missing.length > 0 || destinationAuthority.missing.length > 0) {
    throw new InstallationForwardRecoveryError(
      "filesystem_unsafe",
      "Forward publication requires both exact bundle leaves.",
    );
  }
  return await renameSwapForwardOnly(sourceAuthority, destinationAuthority);
}

const keychainDependencies: InstallationHandoffDependencies =
  defaultInstallationHandoffDependencies;

export const defaultForwardRecoveryDependencies: ForwardRecoveryDependencies = {
  acquireControlPlaneLock: acquireControlPlaneLifetimeLock,
  acquireNativeLock: defaultInstallationHandoffDependencies.acquireNativeLock,
  assertKeychain: async evidence => {
    await assertKeychainContinuity(evidence, keychainDependencies);
  },
  captureKeychain: async controlPlanePath =>
    await inspectKeychainContinuity(controlPlanePath, keychainDependencies),
  copyTree: defaultInstallationHandoffDependencies.copyTree,
  eraseKeychain: eraseKeychainEvidence,
  inspectBundle: inspectGenericForwardBundle,
  inspectCandidate: inspectExactCandidate,
  inspectOrigin: inspectExactOrigin,
  inspectEnrollmentKeychainNoUi: inspectResidentEnrollmentCustodyNoUi,
  readEnrollmentSidecar: readHarnessKeyEnrollmentSidecar,
  writeEnrollmentSidecar: writeHarnessKeyEnrollmentSidecar,
  removeEnrollmentSidecar: removeExactHarnessKeyEnrollmentSidecar,
  inspectState: async (stateRoot, controlPlanePath) =>
    await inspectStateContinuity(stateRoot, controlPlanePath, false),
  inspectStateWithoutEnrollmentSidecar: async (stateRoot, controlPlanePath) =>
    await inspectStateContinuityWithoutHarnessEnrollmentSidecar(
      stateRoot,
      controlPlanePath,
      false,
    ),
  now: Date.now,
  openFilesAreQuiescent: defaultInstallationHandoffDependencies.openFilesAreQuiescent,
  publishForward: publishForwardWithPathAuthority,
  quitApplications: defaultInstallationHandoffDependencies.quitApplications,
  randomBytes,
  stageForDeletion: async (source, tombstone) => {
    const sourceAuthority = await inspectProspectivePathAuthority(
      source,
      "forward cleanup source",
    );
    const destinationAuthority = await inspectProspectivePathAuthority(
      tombstone,
      "forward cleanup tombstone",
    );
    if (sourceAuthority.missing.length > 0 || destinationAuthority.missing.length !== 1) {
      throw new InstallationForwardRecoveryError(
        "filesystem_unsafe",
        "Forward cleanup requires one exact source and one missing tombstone leaf.",
      );
    }
    await renameWithPathAuthority(sourceAuthority, destinationAuthority, {
      exchange: false,
    });
    const sourceParent = dirname(source);
    const tombstoneParent = dirname(tombstone);
    await syncDirectory(sourceParent);
    if (tombstoneParent !== sourceParent) {
      await syncDirectory(tombstoneParent);
    }
  },
  syncStagedTree: syncForwardRecoveryTreeDurably,
  updaterIsQuiescent: defaultInstallationHandoffDependencies.updaterIsQuiescent,
};

export async function performForwardRecovery(
  input: ForwardRecoveryInput,
  dependencies: ForwardRecoveryDependencies = defaultForwardRecoveryDependencies,
): Promise<Readonly<{
  disposition: "complete";
  keychainContinuity: "verified_same_process";
  operationId: string;
  status: "forward_recovered";
}>> {
  requireConfirmation(
    input.confirmation,
    forwardRecoveryConfirmation,
  );
  const candidateApp = requireAbsoluteNormalized(input.candidateApp, "candidate app");
  const backupDirectory = requireAbsoluteNormalized(
    input.backupDirectory,
    "backup directory",
  );
  const originHandoffBackupDirectory = requireAbsoluteNormalized(
    input.originHandoffBackupDirectory,
    "committed-origin backup directory",
  );
  const basePaths = input.paths
    ?? installationHandoffPaths(candidateApp, userInfo().homedir, "/Applications");
  validateBasePaths(basePaths, candidateApp);
  await requireMissing(backupDirectory, "Forward backup directory already exists.");
  const operationId = createOperationId(dependencies.randomBytes(12));
  const paths: ForwardRecoveryReceiptPaths = {
    ...basePaths,
    cleanupTombstoneApp: forwardRecoveryTombstonePath(
      backupDirectory,
      operationId,
    ),
    forwardBackupDirectory: backupDirectory,
    retiredOriginApp: forwardRecoveryStagePath(
      basePaths.applicationsDirectory,
      operationId,
    ),
  };
  await validateNewOperationAuthorities(
    paths,
    backupDirectory,
    originHandoffBackupDirectory,
  );
  await mkdir(backupDirectory, { mode: 0o700 });
  await chmod(backupDirectory, 0o700);
  await assertPrivateDirectory(backupDirectory);
  await assertSameFilesystem(paths.canonicalApp, backupDirectory);

  const locks = await stopAndLock(paths, dependencies);
  let receipt: ForwardRecoveryReceipt | null = null;
  let stagedCandidate: ForwardCandidateEvidence | null = null;
  let keychainBefore: KeychainEvidence | null = null;
  try {
    await requireQuiescent(paths, dependencies);
    await requireOprteAbsent(paths);
    const [origin, candidate, committedOriginReceipt, preState] = await Promise.all([
      dependencies.inspectOrigin(paths.canonicalApp),
      dependencies.inspectCandidate(paths.candidateApp),
      inspectCommittedOriginReceipt(originHandoffBackupDirectory),
      dependencies.inspectState(paths.stateRoot, paths.controlPlanePath),
    ]);
    requireMigration62(preState);
    if (JSON.stringify(origin.bundle) !== JSON.stringify(committedOriginReceipt.bundle)) {
      throw new InstallationForwardRecoveryError(
        "origin_invalid",
        "Canonical B14 bundle differs from its exact committed schema-v2 evidence.",
      );
    }
    keychainBefore = await dependencies.captureKeychain(paths.controlPlanePath);
    await requireEnrollmentKeychainAbsent(
      paths.candidateApp,
      candidate.custodyProbeSupervisor,
      dependencies,
    );
    const [candidateAfterInitialProbe, stateAfterInitialProbe] = await Promise.all([
      dependencies.inspectCandidate(paths.candidateApp),
      dependencies.inspectState(paths.stateRoot, paths.controlPlanePath),
    ]);
    assertForwardCandidateContent(
      candidate,
      candidateAfterInitialProbe,
      "post-probe source v0.1.15 candidate",
      true,
    );
    assertStateContinuity(
      preState,
      stateAfterInitialProbe,
      "post-probe forward pre-state",
    );

    await requireMissing(
      paths.retiredOriginApp,
      "Forward candidate staging path already exists.",
    );
    await dependencies.copyTree(paths.candidateApp, paths.retiredOriginApp);
    stagedCandidate = await dependencies.inspectCandidate(paths.retiredOriginApp);
    assertForwardCandidateContent(
      candidate,
      stagedCandidate,
      "staged v0.1.15 candidate",
      false,
    );
    await dependencies.syncStagedTree(paths.retiredOriginApp);
    stagedCandidate = await dependencies.inspectCandidate(paths.retiredOriginApp);
    assertForwardCandidateContent(
      candidate,
      stagedCandidate,
      "durable staged v0.1.15 candidate",
      false,
    );
    const createdAt = dependencies.now();
    if (!Number.isSafeInteger(createdAt) || createdAt < 0) {
      throw new InstallationForwardRecoveryError(
        "invalid_arguments",
        "Forward-recovery time is invalid.",
      );
    }
    const authorizedSidecar = authorizedHarnessKeyEnrollmentSidecar(
      createForwardHarnessKeyEnrollmentAuthorization({
        operationId,
        committedOriginReceipt,
        candidate: stagedCandidate,
        preState,
      }),
    );
    receipt = parseForwardRecoveryReceipt({
      schemaVersion: 1,
      createdAt,
      operationId,
      paths,
      preState,
      state: preState,
      origin,
      candidate: stagedCandidate,
      committedOriginReceipt,
      keychainDescriptors: keychainBefore.descriptors,
      enrollment: {
        authorizedSidecar,
        file: null,
      },
      phase: "authorizing",
      keychainContinuity: "pending_same_process",
    });
    await writeReceipt(backupDirectory, receipt);
    input.onCheckpoint?.("after_authorizing_receipt");
    receipt = await authorizeEnrollmentSidecar(
      backupDirectory,
      receipt,
      dependencies,
      "pending_same_process",
      input.onCheckpoint,
    );
    input.onCheckpoint?.("after_prepared");

    await dependencies.syncStagedTree(paths.retiredOriginApp);
    await verifyPrepublishLayout(receipt, dependencies);
    assertStateContinuity(
      receipt.state,
      await dependencies.inspectState(paths.stateRoot, paths.controlPlanePath),
      "forward prepublication state",
    );
    await dependencies.assertKeychain(keychainBefore);
    await requireEnrollmentKeychainAbsent(
      paths.retiredOriginApp,
      receipt.candidate.custodyProbeSupervisor,
      dependencies,
    );
    await verifyPrepublishEnrollmentSidecar(receipt, dependencies);
    // Keep the exact receipt-bound bundle/origin proof immediately adjacent
    // to the one-way kernel swap. The earlier durability traversal cannot be
    // treated as publication authority because it intentionally hashes no
    // release semantics.
    await verifyPrepublishLayout(receipt, dependencies);
    const publication = await dependencies.publishForward(
      paths.retiredOriginApp,
      paths.canonicalApp,
    );
    await syncDirectory(paths.applicationsDirectory);
    input.onCheckpoint?.("after_swap_before_receipt");
    if (publication.status === "postcondition_unknown_after_swap") {
      const disposition = await classifyDisposition(receipt, dependencies);
      if (disposition !== "postpublish") {
        throw new InstallationForwardRecoveryError(
          "recovery_conflict",
          "Forward swap returned an unknown postcondition and exact publication cannot be proven.",
        );
      }
    }
    receipt = await advanceReceipt(backupDirectory, receipt, {
      phase: "published",
      keychainContinuity: "pending_same_process",
    });
    input.onCheckpoint?.("after_published_receipt");

    await verifyPostpublishLayout(receipt, dependencies, keychainBefore);
    receipt = await advanceReceipt(backupDirectory, receipt, {
      phase: "verified",
      keychainContinuity: "verified_same_process",
    });
    input.onCheckpoint?.("after_verified_receipt");
    await removeRetiredOrigin(receipt, dependencies);
    input.onCheckpoint?.("after_retired_origin_cleanup");
    receipt = await advanceReceipt(backupDirectory, receipt, {
      phase: "complete",
      keychainContinuity: "verified_same_process",
    });
    return {
      disposition: "complete",
      keychainContinuity: "verified_same_process",
      operationId,
      status: "forward_recovered",
    };
  } catch (error: unknown) {
    if (error instanceof ForwardRecoveryProcessExitForTest) throw error;
    if (receipt !== null) {
      const disposition = await classifyDisposition(receipt, dependencies);
      if (disposition === "prepublish") {
        receipt = await abortPrepublishRecovery(
          backupDirectory,
          receipt,
          dependencies,
        );
      } else if (disposition === "conflict") {
        throw new InstallationForwardRecoveryError(
          "recovery_conflict",
          `Forward recovery failed and filesystem authority is ambiguous: ${message(error)}`,
        );
      }
    } else if (stagedCandidate !== null && await exists(paths.retiredOriginApp)) {
      await stageAndRemoveBundle(
        paths.retiredOriginApp,
        paths.cleanupTombstoneApp,
        stagedCandidate,
        "unreceipted candidate cleanup",
        dependencies.inspectCandidate,
        dependencies,
        assertForwardCandidateContent,
      );
    }
    throw error;
  } finally {
    dependencies.eraseKeychain(keychainBefore);
    locks.controlPlane.release();
    locks.native.release();
  }
}

export async function inspectForwardRecoveryStatus(
  backupDirectoryValue: string,
  dependencies: ForwardRecoveryDependencies = defaultForwardRecoveryDependencies,
): Promise<ForwardRecoveryStatus> {
  const backupDirectory = requireAbsoluteNormalized(
    backupDirectoryValue,
    "backup directory",
  );
  await assertPrivateDirectory(backupDirectory);
  const receipt = await readReceipt(backupDirectory);
  await verifyCommittedOriginReceipt(receipt);
  const disposition = await classifyDisposition(receipt, dependencies);
  if (disposition === "conflict") {
    throw new InstallationForwardRecoveryError(
      "recovery_conflict",
      "Forward-recovery bundle disposition is ambiguous.",
    );
  }
  const postpublish = disposition === "postpublish"
    || disposition === "postpublish_cleanup"
    || disposition === "complete";
  if (postpublish) {
    await verifyCanonicalCandidate(receipt, dependencies);
  } else if (
    disposition === "prepublish"
    || disposition === "prepublish_cleanup"
    || disposition === "aborted"
  ) {
    await verifyCanonicalOrigin(receipt, dependencies);
  }
  await verifyEnrollmentForStatus(receipt, disposition, dependencies);
  return {
    disposition,
    keychainContinuity: receipt.keychainContinuity === "not_applicable"
        ? "not_applicable"
        : postpublish
          ? "unavailable_after_process_restart"
          : "not_checked",
    operationId: receipt.operationId,
    phase: receipt.phase,
    state: "not_inspected",
  };
}

async function verifyEnrollmentForStatus(
  receipt: ForwardRecoveryReceipt,
  disposition: ForwardRecoveryDisposition,
  dependencies: ForwardRecoveryDependencies,
): Promise<void> {
  const current = await dependencies.readEnrollmentSidecar(
    receipt.paths.controlPlanePath,
  );
  if (receipt.phase === "aborted") {
    if (current !== null) throw recoveryConflict();
    return;
  }
  if (receipt.phase === "authorizing") {
    if (
      current !== null
      && !sameEnrollmentSidecar(
        current.sidecar,
        receipt.enrollment.authorizedSidecar,
      )
    ) throw recoveryConflict();
    const candidateApp = await exactPrepublishCandidatePath(receipt, dependencies);
    const stateWithoutEnrollment = await dependencies
      .inspectStateWithoutEnrollmentSidecar(
        receipt.paths.stateRoot,
        receipt.paths.controlPlanePath,
      );
    assertStateContinuity(
      receipt.preState,
      stateWithoutEnrollment,
      "authorizing status state without enrollment sidecar",
    );
    await requireEnrollmentKeychainAbsent(
      candidateApp,
      receipt.candidate.custodyProbeSupervisor,
      dependencies,
    );
    const after = await dependencies.readEnrollmentSidecar(
      receipt.paths.controlPlanePath,
    );
    if (
      (current === null) !== (after === null)
      || (current !== null && after !== null && !sameEnrollmentFile(current, after))
    ) throw recoveryConflict();
    return;
  }
  if (
    disposition === "prepublish"
    || disposition === "prepublish_cleanup"
  ) {
    await verifyPrepublishEnrollmentSidecar(
      receipt,
      dependencies,
      await exactPrepublishCandidatePath(receipt, dependencies),
    );
    return;
  }
  await verifyPostpublishEnrollmentSidecar(receipt, dependencies);
}

export async function resumeForwardRecovery(
  input: ForwardRecoveryResumeInput,
  dependencies: ForwardRecoveryDependencies = defaultForwardRecoveryDependencies,
): Promise<ForwardRecoveryStatus> {
  requireConfirmation(input.confirmation, forwardRecoveryResumeConfirmation);
  const backupDirectory = requireAbsoluteNormalized(
    input.backupDirectory,
    "backup directory",
  );
  await assertPrivateDirectory(backupDirectory);
  let receipt = await readReceipt(backupDirectory);
  const locks = await stopAndLock(receipt.paths, dependencies);
  let keychainBefore: KeychainEvidence | null = null;
  try {
    await requireQuiescent(receipt.paths, dependencies);
    await requireOprteAbsent(receipt.paths);
    await assertSameFilesystem(
      receipt.paths.canonicalApp,
      receipt.paths.forwardBackupDirectory,
    );
    await verifyCommittedOriginReceipt(receipt);
    const disposition = await classifyDisposition(receipt, dependencies);
    if (disposition === "conflict") {
      throw recoveryConflict();
    }
    if (disposition === "complete") {
      await verifyPostpublishWithoutRetiredOrigin(receipt, dependencies);
      return statusForReceipt(receipt, disposition, "unchanged", true);
    }
    if (disposition === "aborted") {
      await verifyEnrollmentForStatus(receipt, disposition, dependencies);
      return statusForReceipt(receipt, disposition, "not_inspected", true);
    }
    if (disposition === "prepublish_cleanup") {
      await verifyCanonicalOrigin(receipt, dependencies);
      await cleanupPrepublishEnrollment(receipt, dependencies);
      await removeStagedCandidate(receipt, dependencies);
      receipt = await advanceReceipt(backupDirectory, receipt, {
        phase: "aborted",
        keychainContinuity: "not_applicable",
        state: receipt.preState,
        enrollment: {
          ...receipt.enrollment,
          file: null,
        },
      });
      return statusForReceipt(receipt, "aborted", "not_inspected");
    }
    if (disposition === "prepublish") {
      if (receipt.phase !== "authorizing" && receipt.phase !== "prepared") {
        throw recoveryConflict();
      }
      keychainBefore = await dependencies.captureKeychain(
        receipt.paths.controlPlanePath,
      );
      if (JSON.stringify(keychainBefore.descriptors) !== JSON.stringify(
        receipt.keychainDescriptors,
      )) {
        throw new InstallationForwardRecoveryError(
          "continuity_failed",
          "Keychain descriptor inventory changed before resumed publication.",
        );
      }
      await requireEnrollmentKeychainAbsent(
        receipt.paths.retiredOriginApp,
        receipt.candidate.custodyProbeSupervisor,
        dependencies,
      );
      if (receipt.phase === "authorizing") {
        receipt = await authorizeEnrollmentSidecar(
          backupDirectory,
          receipt,
          dependencies,
          "unavailable_after_process_restart",
          input.onCheckpoint,
        );
        input.onCheckpoint?.("after_prepared");
      }
      await dependencies.syncStagedTree(receipt.paths.retiredOriginApp);
      await verifyPrepublishLayout(receipt, dependencies);
      const currentState = await dependencies.inspectState(
        receipt.paths.stateRoot,
        receipt.paths.controlPlanePath,
      );
      assertStateContinuity(receipt.state, currentState, "resumed prepublication state");
      await dependencies.assertKeychain(keychainBefore);
      await requireEnrollmentKeychainAbsent(
        receipt.paths.retiredOriginApp,
        receipt.candidate.custodyProbeSupervisor,
        dependencies,
      );
      await verifyPrepublishEnrollmentSidecar(receipt, dependencies);
      await verifyPrepublishLayout(receipt, dependencies);
      const publication = await dependencies.publishForward(
        receipt.paths.retiredOriginApp,
        receipt.paths.canonicalApp,
      );
      await syncDirectory(receipt.paths.applicationsDirectory);
      input.onCheckpoint?.("after_swap_before_receipt");
      if (
        publication.status === "postcondition_unknown_after_swap"
        && await classifyDisposition(receipt, dependencies) !== "postpublish"
      ) {
        throw recoveryConflict();
      }
      receipt = await advanceReceipt(backupDirectory, receipt, {
        phase: "published",
        keychainContinuity: "unavailable_after_process_restart",
      });
      input.onCheckpoint?.("after_published_receipt");
      await verifyPostpublishLayout(receipt, dependencies, keychainBefore);
      await removeRetiredOrigin(receipt, dependencies);
      input.onCheckpoint?.("after_retired_origin_cleanup");
      receipt = await advanceReceipt(backupDirectory, receipt, {
        phase: "complete",
        keychainContinuity: "unavailable_after_process_restart",
      });
      return statusForReceipt(receipt, "complete", "unchanged", true);
    }

    if (disposition === "postpublish_cleanup") {
      await verifyPostpublishWithoutRetiredOrigin(receipt, dependencies);
      await removeRetiredOrigin(receipt, dependencies);
      receipt = await advanceReceipt(backupDirectory, receipt, {
        phase: "complete",
        keychainContinuity: "unavailable_after_process_restart",
      });
      return statusForReceipt(receipt, "complete", "unchanged", true);
    }
    if (receipt.phase === "verified") {
      await verifyPostpublishLayout(receipt, dependencies, null);
      await removeRetiredOrigin(receipt, dependencies);
      receipt = await advanceReceipt(backupDirectory, receipt, {
        phase: "complete",
        keychainContinuity: "unavailable_after_process_restart",
      });
      return statusForReceipt(receipt, "complete", "unchanged", true);
    }
    await verifyPostpublishLayout(receipt, dependencies, null);
    if (receipt.phase === "prepared") {
      receipt = await advanceReceipt(backupDirectory, receipt, {
        phase: "published",
        keychainContinuity: "unavailable_after_process_restart",
      });
    }
    await removeRetiredOrigin(receipt, dependencies);
    input.onCheckpoint?.("after_retired_origin_cleanup");
    receipt = await advanceReceipt(backupDirectory, receipt, {
      phase: "complete",
      keychainContinuity: "unavailable_after_process_restart",
    });
    return statusForReceipt(receipt, "complete", "unchanged", true);
  } finally {
    dependencies.eraseKeychain(keychainBefore);
    locks.controlPlane.release();
    locks.native.release();
  }
}

export async function cleanupForwardRecovery(
  input: ForwardRecoveryCleanupInput,
  dependencies: ForwardRecoveryDependencies = defaultForwardRecoveryDependencies,
): Promise<ForwardRecoveryStatus> {
  requireConfirmation(input.confirmation, forwardRecoveryCleanupConfirmation);
  const backupDirectory = requireAbsoluteNormalized(
    input.backupDirectory,
    "backup directory",
  );
  await assertPrivateDirectory(backupDirectory);
  let receipt = await readReceipt(backupDirectory);
  const locks = await stopAndLock(receipt.paths, dependencies);
  try {
    await requireQuiescent(receipt.paths, dependencies);
    await requireOprteAbsent(receipt.paths);
    await assertSameFilesystem(
      receipt.paths.canonicalApp,
      receipt.paths.forwardBackupDirectory,
    );
    await verifyCommittedOriginReceipt(receipt);
    const disposition = await classifyDisposition(receipt, dependencies);
    if (disposition === "conflict") throw recoveryConflict();
    if (disposition === "complete") {
      await verifyPostpublishWithoutRetiredOrigin(receipt, dependencies);
      return statusForReceipt(receipt, disposition, "unchanged", true);
    }
    if (disposition === "aborted") {
      await verifyEnrollmentForStatus(receipt, disposition, dependencies);
      return statusForReceipt(receipt, disposition, "not_inspected", true);
    }
    if (disposition === "prepublish_cleanup") {
      await verifyCanonicalOrigin(receipt, dependencies);
      await cleanupPrepublishEnrollment(receipt, dependencies);
      await removeStagedCandidate(receipt, dependencies);
      receipt = await advanceReceipt(backupDirectory, receipt, {
        phase: "aborted",
        keychainContinuity: "not_applicable",
        state: receipt.preState,
        enrollment: {
          ...receipt.enrollment,
          file: null,
        },
      });
      return statusForReceipt(receipt, "aborted", "not_inspected");
    }
    if (disposition === "prepublish") {
      receipt = await abortPrepublishRecovery(
        backupDirectory,
        receipt,
        dependencies,
      );
      return statusForReceipt(receipt, "aborted", "not_inspected");
    }

    if (disposition === "postpublish_cleanup") {
      await verifyPostpublishWithoutRetiredOrigin(receipt, dependencies);
      await removeRetiredOrigin(receipt, dependencies);
      receipt = await advanceReceipt(backupDirectory, receipt, {
        phase: "complete",
        keychainContinuity: "unavailable_after_process_restart",
      });
      return statusForReceipt(receipt, "complete", "unchanged", true);
    }
    await verifyPostpublishLayout(receipt, dependencies, null);
    if (receipt.phase === "prepared") {
      receipt = await advanceReceipt(backupDirectory, receipt, {
        phase: "published",
        keychainContinuity: "unavailable_after_process_restart",
      });
    }
    await removeRetiredOrigin(receipt, dependencies);
    input.onCheckpoint?.("after_retired_origin_cleanup");
    receipt = await advanceReceipt(backupDirectory, receipt, {
      phase: "complete",
      keychainContinuity: "unavailable_after_process_restart",
    });
    return statusForReceipt(receipt, "complete", "unchanged", true);
  } finally {
    locks.controlPlane.release();
    locks.native.release();
  }
}

type ForwardLocks = Readonly<{
  controlPlane: ControlPlaneLifetimeLock;
  native: HeldLock;
}>;

async function stopAndLock(
  paths: InstallationHandoffPaths,
  dependencies: ForwardRecoveryDependencies,
): Promise<ForwardLocks> {
  await dependencies.quitApplications([paths.canonicalApp, paths.predecessorApp]);
  let native: HeldLock;
  try {
    native = dependencies.acquireNativeLock(paths.nativeInstanceLockPath);
  } catch (error: unknown) {
    throw new InstallationForwardRecoveryError(
      "app_running",
      `Native instance lock is unavailable: ${message(error)}`,
    );
  }
  let controlPlane: ControlPlaneLifetimeLock | null = null;
  try {
    await dependencies.quitApplications([paths.canonicalApp, paths.predecessorApp]);
    controlPlane = dependencies.acquireControlPlaneLock(paths.controlPlanePath);
    controlPlane.bindControlPlane();
    return { controlPlane, native };
  } catch (error: unknown) {
    controlPlane?.release();
    native.release();
    throw new InstallationForwardRecoveryError(
      "app_running",
      `Forward-recovery locks are unavailable: ${message(error)}`,
    );
  }
}

async function requireQuiescent(
  paths: InstallationHandoffPaths,
  dependencies: ForwardRecoveryDependencies,
): Promise<void> {
  if (!await dependencies.updaterIsQuiescent(paths)) {
    throw new InstallationForwardRecoveryError(
      "updater_active",
      "A package updater or update staging path is active.",
    );
  }
  if (!await dependencies.openFilesAreQuiescent(paths)) {
    throw new InstallationForwardRecoveryError(
      "app_running",
      "HRA state or application bundles still have open files.",
    );
  }
}

async function requireOprteAbsent(paths: InstallationHandoffPaths): Promise<void> {
  if (await exists(paths.predecessorApp)) {
    throw new InstallationForwardRecoveryError(
      "origin_invalid",
      "Forward recovery requires OPRTE.app to remain absent.",
    );
  }
}

function requireMigration62(state: StateContinuityEvidence): void {
  if (state.database.migrationVersion !== 62) {
    throw new InstallationForwardRecoveryError(
      "origin_invalid",
      "Forward recovery requires exact control-plane migration 62.",
    );
  }
}

async function requireEnrollmentKeychainAbsent(
  candidateApp: string,
  authority: CustodyProbeSupervisorAuthorityEvidence,
  dependencies: ForwardRecoveryDependencies,
): Promise<void> {
  const observation = await inspectEnrollmentCustody(
    candidateApp,
    authority,
    dependencies,
  );
  if (observation.state !== "absent") {
    throw new InstallationForwardRecoveryError(
      "continuity_failed",
      "Forward recovery requires the exact v2 enrollment descriptor to be absent.",
    );
  }
}

function parseForwardEnrollmentCustodyObservation(
  value: unknown,
): ForwardEnrollmentCustodyObservation {
  const parsed = forwardEnrollmentCustodyObservationSchema.safeParse(value);
  if (!parsed.success) {
    throw new InstallationForwardRecoveryError(
      "keychain_unavailable",
      "Exact no-UI enrollment custody inspection returned invalid evidence.",
    );
  }
  return parsed.data;
}

async function authorizeEnrollmentSidecar(
  backupDirectory: string,
  receipt: ForwardRecoveryReceipt,
  dependencies: ForwardRecoveryDependencies,
  keychainContinuity:
    | "pending_same_process"
    | "unavailable_after_process_restart",
  onCheckpoint?: (point: ForwardRecoveryFaultPoint) => void,
): Promise<ForwardRecoveryReceipt> {
  if (receipt.phase !== "authorizing" || receipt.enrollment.file !== null) {
    throw recoveryConflict();
  }
  await verifyCanonicalOrigin(receipt, dependencies);
  await verifyCommittedOriginReceipt(receipt);
  await verifyPrepublishLayout(receipt, dependencies);
  await requireEnrollmentKeychainAbsent(
    receipt.paths.retiredOriginApp,
    receipt.candidate.custodyProbeSupervisor,
    dependencies,
  );
  await verifyPrepublishLayout(receipt, dependencies);
  const stateBefore = await dependencies.inspectState(
    receipt.paths.stateRoot,
    receipt.paths.controlPlanePath,
  );
  let file = await dependencies.readEnrollmentSidecar(
    receipt.paths.controlPlanePath,
  );
  if (file === null) {
    assertStateContinuity(
      receipt.preState,
      stateBefore,
      "forward pre-enrollment state",
    );
    file = await dependencies.writeEnrollmentSidecar(
      receipt.paths.controlPlanePath,
      receipt.enrollment.authorizedSidecar,
      null,
    );
  } else if (
    JSON.stringify(file.sidecar)
      !== JSON.stringify(receipt.enrollment.authorizedSidecar)
  ) {
    throw new InstallationForwardRecoveryError(
      "recovery_conflict",
      "Forward enrollment sidecar differs from its receipt authorization.",
    );
  }
  onCheckpoint?.("after_enrollment_authorized");
  await requireEnrollmentKeychainAbsent(
    receipt.paths.retiredOriginApp,
    receipt.candidate.custodyProbeSupervisor,
    dependencies,
  );
  const state = await dependencies.inspectState(
    receipt.paths.stateRoot,
    receipt.paths.controlPlanePath,
  );
  const stateWithoutEnrollment = await dependencies
    .inspectStateWithoutEnrollmentSidecar(
      receipt.paths.stateRoot,
      receipt.paths.controlPlanePath,
    );
  assertStateContinuity(
    receipt.preState,
    stateWithoutEnrollment,
    "forward state excluding exact enrollment sidecar",
  );
  assertSoleEnrollmentSidecarDelta(receipt.preState, state, file.evidence);
  return await advanceReceipt(backupDirectory, receipt, {
    phase: "prepared",
    keychainContinuity,
    state,
    enrollment: {
      authorizedSidecar: receipt.enrollment.authorizedSidecar,
      file: file.evidence,
    },
  });
}

function assertSoleEnrollmentSidecarDelta(
  before: StateContinuityEvidence,
  after: StateContinuityEvidence,
  file: HarnessKeyEnrollmentFileEvidence,
): void {
  const { tree: beforeTree, ...beforeSemantic } = before;
  const { tree: afterTree, ...afterSemantic } = after;
  if (
    JSON.stringify(beforeSemantic) !== JSON.stringify(afterSemantic)
    || afterTree.bytes !== beforeTree.bytes + file.bytes
    || afterTree.directories !== beforeTree.directories
    || afterTree.entries !== beforeTree.entries + 1
    || afterTree.files !== beforeTree.files + 1
    || afterTree.symlinks !== beforeTree.symlinks
    || afterTree.digest === beforeTree.digest
  ) {
    throw new InstallationForwardRecoveryError(
      "continuity_failed",
      "Forward enrollment authorization was not the sole protected-state delta.",
    );
  }
}

async function verifyPrepublishEnrollmentSidecar(
  receipt: ForwardRecoveryReceipt,
  dependencies: ForwardRecoveryDependencies,
  candidateApp: string = receipt.paths.retiredOriginApp,
): Promise<void> {
  const expected = receipt.enrollment.file;
  if (expected === null) throw recoveryConflict();
  const [candidateBefore, stateBefore, currentBefore] = await Promise.all([
    dependencies.inspectCandidate(candidateApp),
    dependencies.inspectStateWithoutEnrollmentSidecar(
      receipt.paths.stateRoot,
      receipt.paths.controlPlanePath,
    ),
    dependencies.readEnrollmentSidecar(receipt.paths.controlPlanePath),
  ]);
  assertForwardCandidateContent(
    receipt.candidate,
    candidateBefore,
    "prepublication enrollment probe candidate",
    true,
  );
  assertStateContinuity(
    receipt.preState,
    stateBefore,
    "prepublication state without enrollment sidecar",
  );
  assertExactAuthorizedEnrollmentFile(receipt, currentBefore, expected);
  await requireEnrollmentKeychainAbsent(
    candidateApp,
    receipt.candidate.custodyProbeSupervisor,
    dependencies,
  );
  const [candidateAfter, stateAfter, currentAfter] = await Promise.all([
    dependencies.inspectCandidate(candidateApp),
    dependencies.inspectStateWithoutEnrollmentSidecar(
      receipt.paths.stateRoot,
      receipt.paths.controlPlanePath,
    ),
    dependencies.readEnrollmentSidecar(receipt.paths.controlPlanePath),
  ]);
  assertForwardCandidateContent(
    receipt.candidate,
    candidateAfter,
    "post-probe prepublication candidate",
    true,
  );
  assertStateContinuity(
    receipt.preState,
    stateAfter,
    "post-probe prepublication state without enrollment sidecar",
  );
  assertExactAuthorizedEnrollmentFile(receipt, currentAfter, expected);
}

async function verifyPostpublishEnrollmentSidecar(
  receipt: ForwardRecoveryReceipt,
  dependencies: ForwardRecoveryDependencies,
): Promise<void> {
  const expected = receipt.enrollment.file;
  if (expected === null) throw recoveryConflict();
  const [candidateBefore, stateBefore, currentBefore] = await Promise.all([
    dependencies.inspectCandidate(receipt.paths.canonicalApp),
    dependencies.inspectStateWithoutEnrollmentSidecar(
      receipt.paths.stateRoot,
      receipt.paths.controlPlanePath,
    ),
    dependencies.readEnrollmentSidecar(receipt.paths.controlPlanePath),
  ]);
  assertForwardCandidateContent(
    receipt.candidate,
    candidateBefore,
    "postpublication enrollment probe candidate",
    true,
  );
  assertStateContinuity(
    receipt.preState,
    stateBefore,
    "postpublication state without enrollment sidecar",
  );
  if (currentBefore === null) throw enrollmentContinuityFailed();
  assertEnrollmentAuthorizationUnchanged(
    receipt.enrollment.authorizedSidecar,
    currentBefore.sidecar,
  );
  const observation = await inspectEnrollmentCustody(
    receipt.paths.canonicalApp,
    receipt.candidate.custodyProbeSupervisor,
    dependencies,
  );
  assertPostpublishEnrollmentCustody(currentBefore, expected, observation);
  const [candidateAfter, stateAfter, currentAfter] = await Promise.all([
    dependencies.inspectCandidate(receipt.paths.canonicalApp),
    dependencies.inspectStateWithoutEnrollmentSidecar(
      receipt.paths.stateRoot,
      receipt.paths.controlPlanePath,
    ),
    dependencies.readEnrollmentSidecar(receipt.paths.controlPlanePath),
  ]);
  assertForwardCandidateContent(
    receipt.candidate,
    candidateAfter,
    "post-probe published candidate",
    true,
  );
  assertStateContinuity(
    receipt.preState,
    stateAfter,
    "post-probe state without enrollment sidecar",
  );
  if (
    currentAfter === null
    || !sameEnrollmentFile(currentBefore, currentAfter)
  ) throw enrollmentContinuityFailed();
}

function assertExactAuthorizedEnrollmentFile(
  receipt: ForwardRecoveryReceipt,
  current: HarnessKeyEnrollmentFile | null,
  expected: HarnessKeyEnrollmentFileEvidence,
): void {
  if (
    current === null
    || !sameEnrollmentSidecar(
      current.sidecar,
      receipt.enrollment.authorizedSidecar,
    )
    || !sameEnrollmentEvidence(current.evidence, expected)
  ) throw enrollmentContinuityFailed();
}

function assertEnrollmentAuthorizationUnchanged(
  authorized: HarnessKeyEnrollmentSidecar,
  current: HarnessKeyEnrollmentSidecar,
): void {
  const authorizedBase = canonicalHarnessKeyEnrollmentSidecar(authorized);
  const currentBase = canonicalHarnessKeyEnrollmentSidecar({
    authorization: current.authorization,
    descriptor: current.descriptor,
    expectedKeychainState: current.expectedKeychainState,
    kind: current.kind,
    phase: "authorized",
    schemaVersion: current.schemaVersion,
  });
  if (currentBase !== authorizedBase) throw enrollmentContinuityFailed();
}

function assertPostpublishEnrollmentCustody(
  current: HarnessKeyEnrollmentFile,
  originalAuthorizedEvidence: HarnessKeyEnrollmentFileEvidence,
  observation: ForwardEnrollmentCustodyObservation,
): void {
  if (current.sidecar.phase === "authorized") {
    if (
      observation.state !== "absent"
      || !sameEnrollmentEvidence(
        current.evidence,
        originalAuthorizedEvidence,
      )
    ) throw enrollmentContinuityFailed();
    return;
  }
  if (current.sidecar.phase === "prepared") {
    if (observation.state === "absent") return;
    if (
      observation.envelopeSha256
        === current.sidecar.attempt.envelopeSha256
    ) return;
    throw enrollmentContinuityFailed();
  }
  if (
    observation.state !== "present"
    || observation.envelopeSha256
      !== current.sidecar.attempt.envelopeSha256
  ) throw enrollmentContinuityFailed();
}

function sameEnrollmentFile(
  left: HarnessKeyEnrollmentFile,
  right: HarnessKeyEnrollmentFile,
): boolean {
  return sameEnrollmentSidecar(left.sidecar, right.sidecar)
    && sameEnrollmentEvidence(left.evidence, right.evidence);
}

function sameEnrollmentSidecar(
  left: HarnessKeyEnrollmentSidecar,
  right: HarnessKeyEnrollmentSidecar,
): boolean {
  return canonicalHarnessKeyEnrollmentSidecar(left)
    === canonicalHarnessKeyEnrollmentSidecar(right);
}

function sameEnrollmentEvidence(
  left: HarnessKeyEnrollmentFileEvidence,
  right: HarnessKeyEnrollmentFileEvidence,
): boolean {
  return left.bytes === right.bytes
    && left.device === right.device
    && left.inode === right.inode
    && left.sha256 === right.sha256;
}

function enrollmentContinuityFailed(): InstallationForwardRecoveryError {
  return new InstallationForwardRecoveryError(
    "continuity_failed",
    "Forward enrollment authority or custody changed unexpectedly.",
  );
}

async function inspectEnrollmentCustody(
  candidateApp: string,
  authority: CustodyProbeSupervisorAuthorityEvidence,
  dependencies: ForwardRecoveryDependencies,
): Promise<ForwardEnrollmentCustodyObservation> {
  try {
    return parseForwardEnrollmentCustodyObservation(
      await dependencies.inspectEnrollmentKeychainNoUi(candidateApp, authority),
    );
  } catch (error: unknown) {
    if (error instanceof InstallationForwardRecoveryError) throw error;
    throw new InstallationForwardRecoveryError(
      "keychain_unavailable",
      "Exact no-UI enrollment custody inspection failed.",
    );
  }
}

async function cleanupPrepublishEnrollment(
  receipt: ForwardRecoveryReceipt,
  dependencies: ForwardRecoveryDependencies,
): Promise<void> {
  await verifyCanonicalOrigin(receipt, dependencies);
  await verifyCommittedOriginReceipt(receipt);
  const candidateApp = await exactPrepublishCandidatePath(receipt, dependencies);
  await requireEnrollmentKeychainAbsent(
    candidateApp,
    receipt.candidate.custodyProbeSupervisor,
    dependencies,
  );
  if (await exactPrepublishCandidatePath(receipt, dependencies) !== candidateApp) {
    throw recoveryConflict();
  }
  const current = await dependencies.readEnrollmentSidecar(
    receipt.paths.controlPlanePath,
  );
  if (current !== null) {
    if (
      !sameEnrollmentSidecar(
        current.sidecar,
        receipt.enrollment.authorizedSidecar,
      )
      || (
        receipt.enrollment.file !== null
        && !sameEnrollmentEvidence(
          current.evidence,
          receipt.enrollment.file,
        )
      )
    ) {
      throw new InstallationForwardRecoveryError(
        "recovery_conflict",
        "Prepublication enrollment sidecar is not exact cleanup authority.",
      );
    }
    await dependencies.removeEnrollmentSidecar(
      receipt.paths.controlPlanePath,
      current,
    );
  }
  const restoredState = await dependencies.inspectState(
    receipt.paths.stateRoot,
    receipt.paths.controlPlanePath,
  );
  assertStateContinuity(
    receipt.preState,
    restoredState,
    "forward enrollment abort state",
  );
  assertStateContinuity(
    receipt.preState,
    await dependencies.inspectStateWithoutEnrollmentSidecar(
      receipt.paths.stateRoot,
      receipt.paths.controlPlanePath,
    ),
    "forward enrollment abort state without sidecar",
  );
}

async function exactPrepublishCandidatePath(
  receipt: ForwardRecoveryReceipt,
  dependencies: ForwardRecoveryDependencies,
): Promise<string> {
  for (const path of [
    receipt.paths.retiredOriginApp,
    receipt.paths.cleanupTombstoneApp,
  ]) {
    try {
      const current = await dependencies.inspectCandidate(path);
      assertForwardCandidateContent(
        receipt.candidate,
        current,
        "prepublication custody probe candidate",
        true,
      );
      return path;
    } catch {
      // Exactly one classified prepublication candidate path may be present.
    }
  }
  throw recoveryConflict();
}

async function abortPrepublishRecovery(
  backupDirectory: string,
  receipt: ForwardRecoveryReceipt,
  dependencies: ForwardRecoveryDependencies,
): Promise<ForwardRecoveryReceipt> {
  await cleanupPrepublishEnrollment(receipt, dependencies);
  await removeStagedCandidate(receipt, dependencies);
  return await advanceReceipt(backupDirectory, receipt, {
    phase: "aborted",
    keychainContinuity: "not_applicable",
    state: receipt.preState,
    enrollment: {
      ...receipt.enrollment,
      file: null,
    },
  });
}

async function verifyCommittedOriginReceipt(
  receipt: ForwardRecoveryReceipt,
): Promise<void> {
  await inspectCommittedOriginReceipt(
    receipt.committedOriginReceipt.backupDirectory,
    receipt.committedOriginReceipt,
  );
}

async function verifyPrepublishLayout(
  receipt: ForwardRecoveryReceipt,
  dependencies: ForwardRecoveryDependencies,
): Promise<void> {
  await requireOprteAbsent(receipt.paths);
  await verifyCommittedOriginReceipt(receipt);
  const [origin, candidate] = await Promise.all([
    dependencies.inspectOrigin(receipt.paths.canonicalApp),
    dependencies.inspectCandidate(receipt.paths.retiredOriginApp),
  ]);
  assertForwardBundleContent(receipt.origin, origin, "canonical origin", true);
  assertForwardCandidateContent(
    receipt.candidate,
    candidate,
    "staged candidate",
    true,
  );
}

async function verifyPostpublishLayout(
  receipt: ForwardRecoveryReceipt,
  dependencies: ForwardRecoveryDependencies,
  keychainBefore: KeychainEvidence | null,
): Promise<void> {
  await requireOprteAbsent(receipt.paths);
  await verifyCommittedOriginReceipt(receipt);
  const [candidate, origin] = await Promise.all([
    dependencies.inspectCandidate(receipt.paths.canonicalApp),
    dependencies.inspectOrigin(receipt.paths.retiredOriginApp),
  ]);
  assertForwardCandidateContent(
    receipt.candidate,
    candidate,
    "published candidate",
    true,
  );
  assertForwardBundleContent(receipt.origin, origin, "retired origin", true);
  await verifyPostpublishEnrollmentSidecar(receipt, dependencies);
  if (keychainBefore !== null) {
    await dependencies.assertKeychain(keychainBefore);
  }
}

async function verifyCanonicalCandidate(
  receipt: ForwardRecoveryReceipt,
  dependencies: ForwardRecoveryDependencies,
): Promise<void> {
  const current = await dependencies.inspectCandidate(receipt.paths.canonicalApp);
  assertForwardCandidateContent(
    receipt.candidate,
    current,
    "published candidate",
    true,
  );
}

async function verifyCanonicalOrigin(
  receipt: ForwardRecoveryReceipt,
  dependencies: ForwardRecoveryDependencies,
): Promise<void> {
  const current = await dependencies.inspectOrigin(receipt.paths.canonicalApp);
  assertForwardBundleContent(receipt.origin, current, "canonical origin", true);
}

async function verifyPostpublishWithoutRetiredOrigin(
  receipt: ForwardRecoveryReceipt,
  dependencies: ForwardRecoveryDependencies,
): Promise<void> {
  await verifyCommittedOriginReceipt(receipt);
  await verifyCanonicalCandidate(receipt, dependencies);
  await verifyPostpublishEnrollmentSidecar(receipt, dependencies);
}

async function classifyDisposition(
  receipt: ForwardRecoveryReceipt,
  dependencies: ForwardRecoveryDependencies,
): Promise<ForwardRecoveryDisposition> {
  const [canonical, staged, tombstone] = await Promise.all([
    inspectBundleLeaf(receipt.paths.canonicalApp, dependencies),
    inspectBundleLeaf(receipt.paths.retiredOriginApp, dependencies),
    inspectRootLeaf(receipt.paths.cleanupTombstoneApp),
  ]);
  const canonicalIsOrigin = bundleLeafMatches(receipt.origin, canonical);
  const canonicalIsCandidate = bundleLeafMatches(receipt.candidate, canonical);
  const stagedIsOrigin = bundleLeafMatches(receipt.origin, staged);
  const stagedIsCandidate = bundleLeafMatches(receipt.candidate, staged);
  const tombstoneIsOrigin = rootLeafMatches(receipt.origin.root, tombstone);
  const tombstoneIsCandidate = rootLeafMatches(receipt.candidate.root, tombstone);
  if (
    canonicalIsOrigin
    && stagedIsCandidate
    && tombstone.kind === "missing"
    && (receipt.phase === "authorizing" || receipt.phase === "prepared")
  ) {
    return "prepublish";
  }
  if (
    canonicalIsOrigin
    && staged.kind === "missing"
    && tombstoneIsCandidate
    && (receipt.phase === "authorizing" || receipt.phase === "prepared")
  ) {
    return "prepublish_cleanup";
  }
  if (
    canonicalIsCandidate
    && stagedIsOrigin
    && tombstone.kind === "missing"
    && receipt.phase !== "complete"
    && receipt.phase !== "aborted"
  ) {
    return "postpublish";
  }
  if (
    canonicalIsCandidate
    && staged.kind === "missing"
    && tombstoneIsOrigin
    && (receipt.phase === "published" || receipt.phase === "verified")
  ) {
    return "postpublish_cleanup";
  }
  if (
    canonicalIsCandidate
    && staged.kind === "missing"
    && tombstoneIsOrigin
    && receipt.phase === "complete"
  ) {
    return "complete";
  }
  if (
    canonicalIsOrigin
    && staged.kind === "missing"
    && tombstoneIsCandidate
    && receipt.phase === "aborted"
  ) {
    return "aborted";
  }
  return "conflict";
}

type ObservedBundleLeaf =
  | Readonly<{ kind: "missing" }>
  | Readonly<{ evidence: ForwardBundleEvidence; kind: "exact" }>
  | Readonly<{ kind: "present_invalid" }>;

type ObservedRootLeaf =
  | Readonly<{ kind: "missing" }>
  | Readonly<{ evidence: ForwardNodeEvidence; kind: "exact" }>
  | Readonly<{ kind: "present_invalid" }>;

async function inspectBundleLeaf(
  path: string,
  dependencies: ForwardRecoveryDependencies,
): Promise<ObservedBundleLeaf> {
  try {
    await lstat(path);
  } catch (error: unknown) {
    if (error instanceof Error && "code" in error && error.code === "ENOENT") {
      return { kind: "missing" };
    }
    return { kind: "present_invalid" };
  }
  try {
    return { evidence: await dependencies.inspectBundle(path), kind: "exact" };
  } catch {
    return { kind: "present_invalid" };
  }
}

async function inspectRootLeaf(path: string): Promise<ObservedRootLeaf> {
  try {
    await lstat(path);
  } catch (error: unknown) {
    if (error instanceof Error && "code" in error && error.code === "ENOENT") {
      return { kind: "missing" };
    }
    return { kind: "present_invalid" };
  }
  try {
    return { evidence: await inspectRootNode(path), kind: "exact" };
  } catch {
    return { kind: "present_invalid" };
  }
}

function bundleLeafMatches(
  expected: ForwardBundleEvidence,
  actual: ObservedBundleLeaf,
): boolean {
  if (actual.kind !== "exact") return false;
  try {
    assertForwardBundleContent(expected, actual.evidence, "disposition", true);
    return true;
  } catch {
    return false;
  }
}

function rootLeafMatches(
  expected: ForwardNodeEvidence,
  actual: ObservedRootLeaf,
): boolean {
  return actual.kind === "exact" && sameNode(expected, actual.evidence);
}

function assertForwardBundleContent(
  expected: ForwardBundleEvidence,
  actual: ForwardBundleEvidence,
  label: string,
  requireNodeIdentity: boolean,
): void {
  const sameContent = JSON.stringify(expected.bundle) === JSON.stringify(actual.bundle)
    && expected.manifest.bytes === actual.manifest.bytes
    && expected.manifest.commit === actual.manifest.commit
    && expected.manifest.runtimeTreeSha256 === actual.manifest.runtimeTreeSha256
    && expected.manifest.sha256 === actual.manifest.sha256;
  const sameNodes = sameNode(expected.root, actual.root)
    && expected.manifest.device === actual.manifest.device
    && expected.manifest.inode === actual.manifest.inode;
  if (!sameContent || (requireNodeIdentity && !sameNodes)) {
    throw new InstallationForwardRecoveryError(
      "continuity_failed",
      `${label} differs from its receipt-bound bundle evidence.`,
    );
  }
}

function assertForwardCandidateContent(
  expected: ForwardCandidateEvidence,
  actual: ForwardCandidateEvidence,
  label: string,
  requireNodeIdentity: boolean,
): void {
  assertForwardBundleContent(expected, actual, label, requireNodeIdentity);
  if (!isDeepStrictEqual(
    expected.custodyProbeSupervisor,
    actual.custodyProbeSupervisor,
  )) {
    throw new InstallationForwardRecoveryError(
      "continuity_failed",
      `${label} differs from its receipt-bound supervisor authority.`,
    );
  }
}

async function removeStagedCandidate(
  receipt: ForwardRecoveryReceipt,
  dependencies: ForwardRecoveryDependencies,
): Promise<void> {
  await stageAndRemoveBundle(
    receipt.paths.retiredOriginApp,
    receipt.paths.cleanupTombstoneApp,
    receipt.candidate,
    "candidate abort cleanup",
    dependencies.inspectCandidate,
    dependencies,
    assertForwardCandidateContent,
  );
}

async function removeRetiredOrigin(
  receipt: ForwardRecoveryReceipt,
  dependencies: ForwardRecoveryDependencies,
): Promise<void> {
  await stageAndRemoveBundle(
    receipt.paths.retiredOriginApp,
    receipt.paths.cleanupTombstoneApp,
    receipt.origin,
    "retired origin cleanup",
    dependencies.inspectOrigin,
    dependencies,
  );
}

async function stageAndRemoveBundle<T extends ForwardBundleEvidence>(
  staging: string,
  tombstone: string,
  expected: T,
  label: string,
  inspectExact: (path: string) => Promise<T>,
  dependencies: ForwardRecoveryDependencies,
  assertExact: (
    expected: T,
    actual: T,
    label: string,
    requireNodeIdentity: boolean,
  ) => void = assertForwardBundleContent,
): Promise<void> {
  if (await exists(staging)) {
    const actual = await inspectExact(staging);
    assertExact(expected, actual, label, true);
    await requireMissing(
      tombstone,
      "Forward cleanup tombstone already exists before staging.",
    );
    await dependencies.stageForDeletion(staging, tombstone);
  }
  const tombstoneRoot = await inspectRootNode(tombstone);
  if (!sameNode(expected.root, tombstoneRoot)) {
    throw new InstallationForwardRecoveryError(
      "recovery_conflict",
      `${label} tombstone differs from its receipt-bound root.`,
    );
  }
}

function statusForReceipt(
  receipt: ForwardRecoveryReceipt,
  disposition: Exclude<
    ForwardRecoveryDisposition,
    "conflict" | "prepublish_cleanup" | "postpublish_cleanup"
  >,
  state: ForwardRecoveryStatus["state"],
  processBoundary = false,
): ForwardRecoveryStatus {
  const postpublish = disposition === "postpublish" || disposition === "complete";
  return {
    disposition,
    keychainContinuity: processBoundary && postpublish
      ? "unavailable_after_process_restart"
      : receipt.keychainContinuity === "verified_same_process"
      ? "verified_same_process"
      : receipt.keychainContinuity === "not_applicable"
        ? "not_applicable"
        : postpublish
          ? "unavailable_after_process_restart"
          : "not_checked",
    operationId: receipt.operationId,
    phase: receipt.phase,
    state,
  };
}

async function advanceReceipt(
  backupDirectory: string,
  receipt: ForwardRecoveryReceipt,
  transition: Readonly<{
    phase: ForwardRecoveryPhase;
    keychainContinuity: ForwardKeychainContinuity;
    state?: StateContinuityEvidence;
    enrollment?: ForwardRecoveryReceipt["enrollment"];
  }>,
): Promise<ForwardRecoveryReceipt> {
  assertForwardTransition(receipt.phase, transition.phase);
  const next = parseForwardRecoveryReceipt({ ...receipt, ...transition });
  await writeReceipt(backupDirectory, next, receipt);
  return next;
}

function assertForwardTransition(
  from: ForwardRecoveryPhase,
  to: ForwardRecoveryPhase,
): void {
  const allowed = (
    (from === "authorizing" && (to === "prepared" || to === "aborted"))
    || (from === "prepared" && (to === "published" || to === "aborted"))
    || (from === "published" && (to === "published" || to === "verified" || to === "complete"))
    || (from === "verified" && to === "complete")
  );
  if (!allowed) {
    throw new InstallationForwardRecoveryError(
      "recovery_conflict",
      `Forward receipt transition ${from} -> ${to} is not monotone.`,
    );
  }
}

async function writeReceipt(
  backupDirectory: string,
  receipt: ForwardRecoveryReceipt,
  expectedCurrent?: ForwardRecoveryReceipt,
): Promise<void> {
  await assertPrivateDirectory(backupDirectory);
  const path = join(backupDirectory, "forward-recovery-receipt.json");
  if (await exists(path)) {
    const current = await readReceipt(backupDirectory);
    if (
      expectedCurrent === undefined
      || JSON.stringify(current) !== JSON.stringify(expectedCurrent)
    ) {
      throw new InstallationForwardRecoveryError(
        "recovery_conflict",
        "Forward-recovery receipt changed before its monotone update.",
      );
    }
  } else if (expectedCurrent !== undefined) {
    throw new InstallationForwardRecoveryError(
      "recovery_conflict",
      "Forward-recovery receipt disappeared before its monotone update.",
    );
  }
  const temporary = join(
    backupDirectory,
    `.forward-recovery-receipt.${process.pid}.${Date.now()}.tmp`,
  );
  const encoded = `${JSON.stringify(parseForwardRecoveryReceipt(receipt), null, 2)}\n`;
  if (Buffer.byteLength(encoded, "utf8") > maximumReceiptBytes) {
    throw new InstallationForwardRecoveryError(
      "receipt_invalid",
      "Forward-recovery receipt is too large.",
    );
  }
  await writeFile(temporary, encoded, { flag: "wx", mode: 0o600 });
  const handle = await open(temporary, "r");
  try {
    await handle.sync();
  } finally {
    await handle.close();
  }
  await rename(temporary, path);
  await chmod(path, 0o600);
  await syncDirectory(backupDirectory);
}

async function readReceipt(backupDirectory: string): Promise<ForwardRecoveryReceipt> {
  const path = join(backupDirectory, "forward-recovery-receipt.json");
  const read = await readBoundedNoFollowFile(path, maximumReceiptBytes);
  try {
    const receipt = parseForwardRecoveryReceipt(
      JSON.parse(read.bytes.toString("utf8")) as unknown,
    );
    if (receipt.paths.forwardBackupDirectory !== backupDirectory) {
      throw invalidReceipt();
    }
    return receipt;
  } catch (error: unknown) {
    if (error instanceof InstallationForwardRecoveryError) throw error;
    throw invalidReceipt();
  } finally {
    read.bytes.fill(0);
  }
}

async function validateNewOperationAuthorities(
  paths: ForwardRecoveryReceiptPaths,
  backupDirectory: string,
  originHandoffBackupDirectory: string,
): Promise<void> {
  const authorities = await Promise.all([
    inspectProspectivePathAuthority(paths.candidateApp, "candidate app"),
    inspectProspectivePathAuthority(paths.canonicalApp, "canonical HRA"),
    inspectProspectivePathAuthority(paths.retiredOriginApp, "forward stage"),
    inspectProspectivePathAuthority(paths.stateRoot, "state root"),
    inspectProspectivePathAuthority(backupDirectory, "forward backup"),
    inspectProspectivePathAuthority(
      originHandoffBackupDirectory,
      "committed-origin backup",
    ),
  ]);
  const labels = [
    "candidate app",
    "canonical HRA",
    "forward stage",
    "state root",
    "forward backup",
    "committed-origin backup",
  ] as const;
  for (let left = 0; left < authorities.length; left += 1) {
    for (let right = left + 1; right < authorities.length; right += 1) {
      if (authoritiesOverlap(authorities[left]!, authorities[right]!)) {
        throw new InstallationForwardRecoveryError(
          "filesystem_unsafe",
          `${labels[left]} overlaps ${labels[right]}.`,
        );
      }
    }
  }
}

function validateBasePaths(
  paths: InstallationHandoffPaths,
  candidateApp: string,
): void {
  for (const [label, path] of Object.entries({
    applicationsDirectory: paths.applicationsDirectory,
    candidateApp: paths.candidateApp,
    canonicalApp: paths.canonicalApp,
    predecessorApp: paths.predecessorApp,
    stateRoot: paths.stateRoot,
    controlPlanePath: paths.controlPlanePath,
    nativeInstanceLockPath: paths.nativeInstanceLockPath,
    updateHazardPath: paths.updateHazardPath,
    updateHazardTemporaryPath: paths.updateHazardTemporaryPath,
  })) {
    requireAbsoluteNormalized(path, label);
  }
  for (const [index, path] of paths.sparkleCacheRoots.entries()) {
    requireAbsoluteNormalized(path, `sparkleCacheRoots[${index}]`);
  }
  if (
    paths.candidateApp !== candidateApp
    || paths.canonicalApp !== join(paths.applicationsDirectory, "HRA.app")
    || paths.predecessorApp !== join(paths.applicationsDirectory, "OPRTE.app")
    || paths.controlPlanePath !== join(paths.stateRoot, "control-plane.sqlite")
  ) {
    throw new InstallationForwardRecoveryError(
      "filesystem_unsafe",
      "Forward-recovery paths differ from the fixed HRA compatibility layout.",
    );
  }
}

async function assertPrivateDirectory(path: string): Promise<void> {
  const status = await lstat(path);
  const expectedUser = process.geteuid?.();
  if (
    expectedUser === undefined
    || !status.isDirectory()
    || status.isSymbolicLink()
    || status.uid !== expectedUser
    || (status.mode & 0o077) !== 0
    || await realpath(path) !== path
  ) {
    throw new InstallationForwardRecoveryError(
      "filesystem_unsafe",
      "Forward-recovery directory is not one canonical user-only directory.",
    );
  }
}

async function assertSameFilesystem(left: string, right: string): Promise<void> {
  const [leftStatus, rightStatus] = await Promise.all([
    lstat(left, { bigint: true }),
    lstat(right, { bigint: true }),
  ]);
  if (leftStatus.dev !== rightStatus.dev) {
    throw new InstallationForwardRecoveryError(
      "filesystem_unsafe",
      "Forward backup and canonical HRA must share one filesystem.",
    );
  }
}

function requireConfirmation(actual: string, expected: string): void {
  if (actual !== expected) {
    throw new InstallationForwardRecoveryError(
      "confirmation_invalid",
      `Confirmation must be ${expected}.`,
    );
  }
}

function createOperationId(bytes: Uint8Array): string {
  if (bytes.byteLength !== 12) {
    throw new InstallationForwardRecoveryError(
      "invalid_arguments",
      "Forward-recovery operation entropy is invalid.",
    );
  }
  return `forward_${Buffer.from(bytes).toString("hex")}`;
}

function isAbsoluteNormalizedNonRoot(value: string): boolean {
  return isAbsolute(value)
    && resolve(value) === value
    && value !== resolve(value, sep)
    && !value.includes("\u0000");
}

function requireAbsoluteNormalized(value: string, label: string): string {
  if (!isAbsoluteNormalizedNonRoot(value)) {
    throw new InstallationForwardRecoveryError(
      "invalid_arguments",
      `${label} must be an absolute normalized non-root path.`,
    );
  }
  return value;
}

function sameNode(left: ForwardNodeEvidence, right: ForwardNodeEvidence): boolean {
  return left.device === right.device && left.inode === right.inode;
}

async function requireMissing(path: string, failure: string): Promise<void> {
  if (await exists(path)) {
    throw new InstallationForwardRecoveryError("filesystem_unsafe", failure);
  }
}

async function exists(path: string): Promise<boolean> {
  try {
    await lstat(path);
    return true;
  } catch (error: unknown) {
    if (error instanceof Error && "code" in error && error.code === "ENOENT") {
      return false;
    }
    throw error;
  }
}

async function syncDirectory(path: string): Promise<void> {
  const handle = await open(
    path,
    constants.O_RDONLY
      | constants.O_DIRECTORY
      | constants.O_NOFOLLOW
      | oCloexec,
  );
  try {
    await handle.sync();
  } finally {
    await handle.close();
  }
}

function sameDurableNode(left: BigIntStats, right: BigIntStats): boolean {
  return left.dev === right.dev
    && left.ino === right.ino
    && left.mode === right.mode
    && left.nlink === right.nlink
    && left.uid === right.uid
    && left.gid === right.gid
    && left.size === right.size
    && left.mtimeNs === right.mtimeNs
    && left.ctimeNs === right.ctimeNs;
}

async function exactDirectoryNames(path: string): Promise<readonly string[]> {
  return (await readdir(path)).sort((left, right) => left.localeCompare(right));
}

async function syncForwardNodeDurably(path: string): Promise<void> {
  const before = await lstat(path, { bigint: true });
  if (before.isSymbolicLink()) {
    const targetBefore = await readlink(path);
    const after = await lstat(path, { bigint: true });
    if (!sameDurableNode(before, after) || await readlink(path) !== targetBefore) {
      throw new InstallationForwardRecoveryError(
        "filesystem_unsafe",
        `Staged symlink changed during durability proof: ${path}`,
      );
    }
    return;
  }
  if (!before.isFile() && !before.isDirectory()) {
    throw new InstallationForwardRecoveryError(
      "filesystem_unsafe",
      `Staged tree contains an unsupported node: ${path}`,
    );
  }
  if (before.isFile() && before.nlink !== 1n) {
    throw new InstallationForwardRecoveryError(
      "filesystem_unsafe",
      `Staged tree contains a hard-linked file: ${path}`,
    );
  }
  const handle = await open(
    path,
    constants.O_RDONLY
      | constants.O_NOFOLLOW
      | oCloexec
      | (before.isDirectory() ? constants.O_DIRECTORY : 0),
  );
  try {
    const opened = await handle.stat({ bigint: true });
    if (!sameDurableNode(before, opened)) {
      throw new InstallationForwardRecoveryError(
        "filesystem_unsafe",
        `Staged node changed before durability proof: ${path}`,
      );
    }
    const namesBefore = before.isDirectory() ? await exactDirectoryNames(path) : null;
    if (namesBefore !== null) {
      for (const name of namesBefore) {
        if (name === "." || name === ".." || name.includes("/") || name.includes("\0")) {
          throw new InstallationForwardRecoveryError(
            "filesystem_unsafe",
            `Staged directory contains an invalid leaf: ${path}`,
          );
        }
        await syncForwardNodeDurably(join(path, name));
      }
      const namesAfter = await exactDirectoryNames(path);
      if (JSON.stringify(namesAfter) !== JSON.stringify(namesBefore)) {
        throw new InstallationForwardRecoveryError(
          "filesystem_unsafe",
          `Staged directory changed during durability proof: ${path}`,
        );
      }
    }
    await handle.sync();
    const descriptorAfter = await handle.stat({ bigint: true });
    const pathAfter = await lstat(path, { bigint: true });
    if (
      !sameDurableNode(before, descriptorAfter)
      || !sameDurableNode(before, pathAfter)
    ) {
      throw new InstallationForwardRecoveryError(
        "filesystem_unsafe",
        `Staged node changed during durability proof: ${path}`,
      );
    }
  } finally {
    await handle.close();
  }
}

export async function syncForwardRecoveryTreeDurably(path: string): Promise<void> {
  await syncForwardNodeDurably(path);
  await syncDirectory(dirname(path));
}

function recoveryConflict(): InstallationForwardRecoveryError {
  return new InstallationForwardRecoveryError(
    "recovery_conflict",
    "Forward-recovery bundle disposition is ambiguous.",
  );
}

function message(error: unknown): string {
  return error instanceof Error ? error.message : String(error);
}

function flagValues(args: readonly string[]): ReadonlyMap<string, string> {
  const values = new Map<string, string>();
  for (let index = 0; index < args.length; index += 2) {
    const name = args[index];
    const value = args[index + 1];
    if (
      name === undefined
      || value === undefined
      || !name.startsWith("--")
      || values.has(name)
    ) {
      throw new InstallationForwardRecoveryError(
        "invalid_arguments",
        "Forward-recovery flags are invalid.",
      );
    }
    values.set(name, value);
  }
  return values;
}

function requireFlag(values: ReadonlyMap<string, string>, name: string): string {
  const value = values.get(name);
  if (value === undefined || value.length === 0) {
    throw new InstallationForwardRecoveryError(
      "invalid_arguments",
      `Missing ${name}.`,
    );
  }
  return value;
}

async function main(): Promise<void> {
  try {
    const [command, ...args] = process.argv.slice(2);
    if (command === "forward" && args.length === 8) {
      const values = flagValues(args);
      const result = await performForwardRecovery({
        backupDirectory: requireFlag(values, "--backup-directory"),
        candidateApp: requireFlag(values, "--candidate-app"),
        confirmation: requireFlag(values, "--confirm"),
        originHandoffBackupDirectory: requireFlag(
          values,
          "--origin-handoff-backup-directory",
        ),
      });
      process.stdout.write(`${JSON.stringify({ schemaVersion: 1, ...result })}\n`);
      return;
    }
    if (command === "status" && args.length === 2) {
      const values = flagValues(args);
      const result = await inspectForwardRecoveryStatus(
        requireFlag(values, "--backup-directory"),
      );
      process.stdout.write(`${JSON.stringify({ schemaVersion: 1, ...result })}\n`);
      return;
    }
    if (command === "resume" && args.length === 4) {
      const values = flagValues(args);
      const result = await resumeForwardRecovery({
        backupDirectory: requireFlag(values, "--backup-directory"),
        confirmation: requireFlag(values, "--confirm"),
      });
      process.stdout.write(`${JSON.stringify({ schemaVersion: 1, ...result })}\n`);
      return;
    }
    if (command === "cleanup" && args.length === 4) {
      const values = flagValues(args);
      const result = await cleanupForwardRecovery({
        backupDirectory: requireFlag(values, "--backup-directory"),
        confirmation: requireFlag(values, "--confirm"),
      });
      process.stdout.write(`${JSON.stringify({ schemaVersion: 1, ...result })}\n`);
      return;
    }
    throw new InstallationForwardRecoveryError(
      "invalid_arguments",
      "Usage: installation-forward-recovery.ts forward --candidate-app ABS --origin-handoff-backup-directory ABS --backup-directory ABS --confirm FORWARD-RECOVER-HRA-0.1.14-TO-0.1.15 | status --backup-directory ABS | resume --backup-directory ABS --confirm RESUME-FORWARD-HRA-RECOVERY | cleanup --backup-directory ABS --confirm CLEAN-FORWARD-HRA-RECOVERY",
    );
  } catch (error: unknown) {
    const failure = error instanceof InstallationForwardRecoveryError
      ? error
      : new InstallationForwardRecoveryError("continuity_failed", message(error));
    process.stderr.write(`${JSON.stringify({
      schemaVersion: 1,
      status: "error",
      code: failure.code,
      message: failure.message,
    })}\n`);
    process.exitCode = 1;
  }
}

if (import.meta.main) await main();
