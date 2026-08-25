import { createHash, randomBytes } from "node:crypto";
import { constants, type BigIntStats } from "node:fs";
import {
  lstat,
  open,
  readdir,
  realpath,
  unlink,
} from "node:fs/promises";
import { basename, dirname, isAbsolute, join, resolve, sep } from "node:path";

import { z } from "@hra-internal/schema";

import { strictBundleSignaturePolicy } from "../../historical-oprte-preview";
import {
  productionCustodyProbeSupervisorAuthoritySchema,
} from "../../custody-probe-supervisor-authority";

import {
  HARNESS_INSTALL_MASTER_KEY_BYTES,
  canonicalHarnessInstallKeyEnvelope,
  harnessInstallKeyDescriptor,
  serializeHarnessInstallMaster,
} from "../harness/key-custody";
import {
  inspectProspectivePathAuthority,
  renameWithPathAuthority,
} from "../../installation-path-authority";
import { controlPlaneLifetimeLockPath } from "./control-plane-lock";

export const harnessKeyEnrollmentSidecarFileName =
  ".hra-harness-key-enrollment-v1.json" as const;
export const harnessKeyEnrollmentSidecarCandidateFileName =
  ".hra-harness-key-enrollment-v1.json.tmp" as const;

export const maximumHarnessKeyEnrollmentSidecarBytes = 64 * 1_024;
const hexSha256Schema = z.string().regex(/^[a-f0-9]{64}$/u);
const decimalBigIntSchema = z.string().regex(/^(?:0|[1-9][0-9]*)$/u);
const nonNegativeSafeIntegerSchema = z.number().int().nonnegative()
  .max(Number.MAX_SAFE_INTEGER);
const operationIdSchema = z.union([
  z.string().regex(/^forward_[a-f0-9]{24}$/u),
  z.string().regex(/^fresh_[a-f0-9]{24}$/u),
  z.string().regex(/^handoff_[a-f0-9]{24}$/u),
]);
const forbiddenKeys = new Set(["__proto__", "constructor", "prototype"]);

const treeEvidenceSchema = z.object({
  bytes: nonNegativeSafeIntegerSchema.max(128 * 1_024 * 1_024 * 1_024),
  directories: nonNegativeSafeIntegerSchema.max(2_000_000),
  digest: hexSha256Schema,
  entries: nonNegativeSafeIntegerSchema.max(2_000_000),
  files: nonNegativeSafeIntegerSchema.max(2_000_000),
  symlinks: nonNegativeSafeIntegerSchema.max(2_000_000),
}).strict().superRefine((tree, context) => {
  if (tree.entries !== tree.directories + tree.files + tree.symlinks) {
    context.addIssue({ code: "custom", message: "tree entry counts differ" });
  }
});

const bundleIdentitySchema = z.object({
  build: z.literal("16"),
  bundleIdentifier: z.literal("kitchen.hraness"),
  executable: z.literal("hra"),
  version: z.literal("0.1.15"),
}).strict();

const predecessorIdentitySchema = z.object({
  build: z.literal("5"),
  bundleIdentifier: z.literal("kitchen.hraness"),
  executable: z.literal("oprte"),
  version: z.literal("0.1.4"),
}).strict();

const priorHraIdentitySchema = z.discriminatedUnion("version", [
  z.object({
    build: z.literal("8"),
    bundleIdentifier: z.literal("kitchen.hraness"),
    executable: z.literal("hra"),
    version: z.literal("0.1.7"),
  }).strict(),
  z.object({
    build: z.literal("9"),
    bundleIdentifier: z.literal("kitchen.hraness"),
    executable: z.literal("hra"),
    version: z.literal("0.1.8"),
  }).strict(),
  z.object({
    build: z.literal("10"),
    bundleIdentifier: z.literal("kitchen.hraness"),
    executable: z.literal("hra"),
    version: z.literal("0.1.9"),
  }).strict(),
  z.object({
    build: z.literal("11"),
    bundleIdentifier: z.literal("kitchen.hraness"),
    executable: z.literal("hra"),
    version: z.literal("0.1.10"),
  }).strict(),
  z.object({
    build: z.literal("13"),
    bundleIdentifier: z.literal("kitchen.hraness"),
    executable: z.literal("hra"),
    version: z.literal("0.1.12"),
  }).strict(),
  z.object({
    build: z.literal("14"),
    bundleIdentifier: z.literal("kitchen.hraness"),
    executable: z.literal("hra"),
    version: z.literal("0.1.13"),
  }).strict(),
  z.object({
    build: z.literal("15"),
    bundleIdentifier: z.literal("kitchen.hraness"),
    executable: z.literal("hra"),
    version: z.literal("0.1.14"),
  }).strict(),
]);

const priorHraBundleEvidenceSchema = z.object({
  identity: priorHraIdentitySchema,
  signature: z.object({ policy: z.literal(strictBundleSignaturePolicy) }).strict(),
  tree: treeEvidenceSchema,
}).strict();

const stateEvidenceSchema = z.object({
  accountHomes: nonNegativeSafeIntegerSchema,
  chatWorktreeLanes: nonNegativeSafeIntegerSchema,
  database: z.object({
    databaseSha256: hexSha256Schema,
    migrationVersion: nonNegativeSafeIntegerSchema,
    quickCheck: z.literal("ok"),
    rows: z.record(
      z.string().regex(/^[A-Za-z_][A-Za-z0-9_]{0,127}$/u),
      nonNegativeSafeIntegerSchema,
    ),
  }).strict(),
  dispatchWorktreeLanes: nonNegativeSafeIntegerSchema,
  harnessWorktreeLanes: nonNegativeSafeIntegerSchema,
  localTaskWorktreeLanes: nonNegativeSafeIntegerSchema,
  sessionEntries: nonNegativeSafeIntegerSchema,
  tree: treeEvidenceSchema,
}).strict();

const bundleEvidenceSchema = z.object({
  identity: bundleIdentitySchema,
  signature: z.object({ policy: z.literal(strictBundleSignaturePolicy) }).strict(),
  tree: treeEvidenceSchema,
}).strict();

const nodeEvidenceSchema = z.object({
  device: decimalBigIntSchema,
  inode: decimalBigIntSchema,
}).strict();

const candidateEvidenceSchema = z.object({
  bundle: bundleEvidenceSchema,
  manifest: nodeEvidenceSchema.extend({
    bytes: z.number().int().nonnegative().max(4 * 1_024 * 1_024),
    commit: z.string().regex(/^[a-f0-9]{40}$/u),
    runtimeTreeSha256: hexSha256Schema,
    sha256: hexSha256Schema,
  }).strict(),
  root: nodeEvidenceSchema,
}).strict();

const forwardCandidateEvidenceSchema = candidateEvidenceSchema.extend({
  custodyProbeSupervisor: productionCustodyProbeSupervisorAuthoritySchema,
}).strict();

const committedOriginReceiptEvidenceSchema = nodeEvidenceSchema.extend({
  backupDirectory: z.string().min(2).max(4_096).refine(
    isAbsoluteNormalizedNonRoot,
    "backup directory must be absolute and normalized",
  ),
  bundle: z.object({
    identity: z.object({
      build: z.literal("15"),
      bundleIdentifier: z.literal("kitchen.hraness"),
      executable: z.literal("hra"),
      version: z.literal("0.1.14"),
    }).strict(),
    signature: z.object({ policy: z.literal(strictBundleSignaturePolicy) }).strict(),
    tree: treeEvidenceSchema,
  }).strict(),
  bytes: z.number().int().positive().max(1_024 * 1_024),
  operationId: z.string().regex(/^handoff_[a-f0-9]{24}$/u),
  sha256: hexSha256Schema,
}).strict();

const descriptorSchema = z.object({
  name: z.literal(harnessInstallKeyDescriptor.name),
  service: z.literal(harnessInstallKeyDescriptor.service),
}).strict();

const forwardAuthorizationSchema = z.object({
  candidate: forwardCandidateEvidenceSchema,
  committedOriginReceipt: committedOriginReceiptEvidenceSchema,
  kind: z.literal("forward_recovery_v1"),
  operationId: z.string().regex(/^forward_[a-f0-9]{24}$/u),
  preStateSha256: hexSha256Schema,
}).strict();

const freshAuthorizationSchema = z.object({
  kind: z.literal("fresh_install_v1"),
  operationId: z.string().regex(/^fresh_[a-f0-9]{24}$/u),
}).strict();

const installationHandoffV3AuthorizationSchema = z.object({
  candidate: forwardCandidateEvidenceSchema,
  kind: z.literal("installation_handoff_v3"),
  operationId: z.string().regex(/^handoff_[a-f0-9]{24}$/u),
  predecessorIdentity: predecessorIdentitySchema,
  preState: stateEvidenceSchema,
  preStateSha256: hexSha256Schema,
  priorHra: priorHraBundleEvidenceSchema.nullable(),
  receipt: z.object({
    device: decimalBigIntSchema,
    inode: decimalBigIntSchema,
    path: z.string().min(2).max(4_096).refine(
      isAbsoluteNormalizedNonRoot,
      "receipt path must be absolute and normalized",
    ),
    schemaVersion: z.literal(3),
    sha256: hexSha256Schema,
  }).strict(),
}).strict().superRefine((value, context) => {
  if (value.preStateSha256 !== digestHarnessKeyEnrollmentPreState(value.preState)) {
    context.addIssue({ code: "custom", message: "pre-state digest differs" });
  }
});

const authorizationSchema = z.discriminatedUnion("kind", [
  forwardAuthorizationSchema,
  freshAuthorizationSchema,
  installationHandoffV3AuthorizationSchema,
]);

const commonShape = {
  schemaVersion: z.literal(1),
  kind: z.literal("hra-harness-key-enrollment"),
  descriptor: descriptorSchema,
  expectedKeychainState: z.literal("absent"),
  authorization: authorizationSchema,
} as const;

const attemptSchema = z.object({
  envelopeSha256: hexSha256Schema,
  nonce: hexSha256Schema,
}).strict();

export const harnessKeyEnrollmentSidecarSchema = z.discriminatedUnion("phase", [
  z.object({
    ...commonShape,
    phase: z.literal("authorized"),
  }).strict(),
  z.object({
    ...commonShape,
    phase: z.literal("prepared"),
    attempt: attemptSchema,
  }).strict(),
  z.object({
    ...commonShape,
    phase: z.literal("enrolled"),
    attempt: attemptSchema,
  }).strict(),
]);

export type HarnessKeyEnrollmentSidecar = z.infer<
  typeof harnessKeyEnrollmentSidecarSchema
>;
export type ForwardHarnessKeyEnrollmentAuthorization = z.infer<
  typeof forwardAuthorizationSchema
>;
export type InstallationHandoffV3EnrollmentAuthorization = z.infer<
  typeof installationHandoffV3AuthorizationSchema
>;
export type InstallationHandoffV3EnrollmentAuthorizationInput = Readonly<{
  candidate: unknown;
  operationId: string;
  predecessorIdentity: unknown;
  preState: unknown;
  priorHra: unknown;
  receipt: unknown;
}>;

export interface HarnessKeyEnrollmentFileEvidence {
  readonly bytes: number;
  readonly device: string;
  readonly inode: string;
  readonly sha256: string;
}

export type HarnessKeyEnrollmentFile = Readonly<{
  evidence: HarnessKeyEnrollmentFileEvidence;
  sidecar: HarnessKeyEnrollmentSidecar;
}>;

export type HarnessKeyEnrollmentObservation =
  | Readonly<{ state: "absent"; strictAcl: false }>
  | Readonly<{
      state: "present";
      envelope: string;
      strictAcl: true | false;
    }>;

export interface HarnessKeyEnrollmentKeychain {
  inspectExactNoUi(): Promise<HarnessKeyEnrollmentObservation>;
  validatePreparedAcl(expectedEnvelopeSha256: string): Promise<Readonly<{
    envelopeSha256: string;
    validated: true;
  }>>;
  migratePreparedAcl(expectedEnvelopeSha256: string): Promise<Readonly<{
    envelopeSha256: string;
    strictAcl: true;
  }>>;
  createExactIfAbsentNoUi(envelope: string): Promise<Readonly<{
    created: boolean;
    envelope: string;
    strictAcl: boolean;
  }>>;
}

export interface EnsureHarnessKeyEnrollmentOptions {
  readonly controlPlanePath: string;
  readonly keychain: HarnessKeyEnrollmentKeychain;
  readonly allowFreshAuthorization: boolean;
  readonly randomBytes?: (length: number) => Uint8Array;
}

export interface HarnessKeyEnrollmentPublicationOptions {
  /** Test-only race seam immediately before the descriptor-relative rename. */
  readonly beforePublishForTest?: () => Promise<void> | void;
}

export class HarnessKeyEnrollmentError extends Error {
  readonly code:
    | "authorization_missing"
    | "custody_conflict"
    | "custody_unavailable"
    | "invalid_sidecar"
    | "unsafe_filesystem";

  constructor(code: HarnessKeyEnrollmentError["code"], message: string) {
    super(message);
    this.name = "HarnessKeyEnrollmentError";
    this.code = code;
  }
}

export function harnessKeyEnrollmentSidecarPath(
  controlPlanePath: string,
): string {
  if (
    !isAbsoluteNormalizedNonRoot(controlPlanePath)
    || basename(controlPlanePath) !== "control-plane.sqlite"
  ) {
    throw new HarnessKeyEnrollmentError(
      "unsafe_filesystem",
      "Harness key enrollment requires the canonical control-plane path.",
    );
  }
  return join(dirname(controlPlanePath), harnessKeyEnrollmentSidecarFileName);
}

export function harnessKeyEnrollmentSidecarCandidatePath(
  controlPlanePath: string,
): string {
  return join(
    dirname(harnessKeyEnrollmentSidecarPath(controlPlanePath)),
    harnessKeyEnrollmentSidecarCandidateFileName,
  );
}

export function parseHarnessKeyEnrollmentSidecar(
  value: unknown,
): HarnessKeyEnrollmentSidecar {
  if (containsForbiddenKey(value, new WeakSet<object>())) throw invalidSidecar();
  const parsed = harnessKeyEnrollmentSidecarSchema.safeParse(value);
  if (!parsed.success) throw invalidSidecar();
  return parsed.data;
}

export function canonicalHarnessKeyEnrollmentSidecar(
  value: unknown,
): string {
  return `${JSON.stringify(parseHarnessKeyEnrollmentSidecar(value), null, 2)}\n`;
}

export function digestCanonicalEvidence(value: unknown): string {
  return sha256(canonicalEvidenceJson(value));
}

export function digestHarnessKeyEnrollmentPreState(value: unknown): string {
  return sha256(
    `hra-harness-key-enrollment-pre-state-v1\0${canonicalEvidenceJson(value)}`,
  );
}

export function createForwardHarnessKeyEnrollmentAuthorization(input: {
  readonly operationId: string;
  readonly committedOriginReceipt: unknown;
  readonly candidate: unknown;
  readonly preState: unknown;
}): ForwardHarnessKeyEnrollmentAuthorization {
  return forwardAuthorizationSchema.parse({
    kind: "forward_recovery_v1",
    operationId: operationIdSchema.parse(input.operationId),
    committedOriginReceipt: input.committedOriginReceipt,
    candidate: input.candidate,
    preStateSha256: digestHarnessKeyEnrollmentPreState(input.preState),
  });
}

export function createInstallationHandoffV3EnrollmentAuthorization(
  input: InstallationHandoffV3EnrollmentAuthorizationInput,
): InstallationHandoffV3EnrollmentAuthorization {
  return installationHandoffV3AuthorizationSchema.parse({
    candidate: input.candidate,
    kind: "installation_handoff_v3",
    operationId: operationIdSchema.parse(input.operationId),
    predecessorIdentity: input.predecessorIdentity,
    preState: input.preState,
    preStateSha256: digestHarnessKeyEnrollmentPreState(input.preState),
    priorHra: input.priorHra,
    receipt: input.receipt,
  });
}

export function installationHandoffV3EnrollmentAuthorizationMatches(
  authorizationValue: unknown,
  input: InstallationHandoffV3EnrollmentAuthorizationInput,
): boolean {
  const parsed = installationHandoffV3AuthorizationSchema.safeParse(
    authorizationValue,
  );
  if (!parsed.success) return false;
  try {
    return canonicalEvidenceJson(parsed.data) === canonicalEvidenceJson(
      createInstallationHandoffV3EnrollmentAuthorization(input),
    );
  } catch {
    return false;
  }
}

export function authorizedHarnessKeyEnrollmentSidecar(
  authorization:
    | ForwardHarnessKeyEnrollmentAuthorization
    | InstallationHandoffV3EnrollmentAuthorization,
): HarnessKeyEnrollmentSidecar {
  return parseHarnessKeyEnrollmentSidecar({
    schemaVersion: 1,
    kind: "hra-harness-key-enrollment",
    descriptor: harnessInstallKeyDescriptor,
    expectedKeychainState: "absent",
    authorization,
    phase: "authorized",
  });
}

export async function readHarnessKeyEnrollmentSidecar(
  controlPlanePath: string,
): Promise<HarnessKeyEnrollmentFile | null> {
  const path = harnessKeyEnrollmentSidecarPath(controlPlanePath);
  let handle: Awaited<ReturnType<typeof open>>;
  try {
    handle = await open(
      path,
      constants.O_RDONLY | constants.O_NOFOLLOW | closeOnExecFlag(),
    );
  } catch (error: unknown) {
    if (hasCode(error, "ENOENT")) return null;
    throw unsafeFilesystem();
  }
  try {
    const before = await handle.stat({ bigint: true });
    const publishedBefore = await lstat(path, { bigint: true });
    assertSafeSidecarMetadata(before, publishedBefore);
    if (
      before.size <= 0n
      || before.size > BigInt(maximumHarnessKeyEnrollmentSidecarBytes)
    ) {
      throw invalidSidecar();
    }
    const bytes = Buffer.alloc(Number(before.size));
    let offset = 0;
    while (offset < bytes.byteLength) {
      const result = await handle.read(
        bytes,
        offset,
        bytes.byteLength - offset,
        null,
      );
      if (result.bytesRead === 0) throw invalidSidecar();
      offset += result.bytesRead;
    }
    const extra = Buffer.alloc(1);
    if ((await handle.read(extra, 0, 1, null)).bytesRead !== 0) {
      throw invalidSidecar();
    }
    const after = await handle.stat({ bigint: true });
    const publishedAfter = await lstat(path, { bigint: true });
    assertSafeSidecarMetadata(before, after);
    assertSafeSidecarMetadata(before, publishedAfter);
    const text = new TextDecoder("utf-8", { fatal: true }).decode(bytes);
    let value: unknown;
    try {
      value = JSON.parse(text) as unknown;
    } catch {
      throw invalidSidecar();
    }
    const sidecar = parseHarnessKeyEnrollmentSidecar(value);
    const canonical = canonicalHarnessKeyEnrollmentSidecar(sidecar);
    if (text !== canonical) throw invalidSidecar();
    return Object.freeze({
      sidecar,
      evidence: Object.freeze({
        bytes: bytes.byteLength,
        device: before.dev.toString(10),
        inode: before.ino.toString(10),
        sha256: sha256(bytes),
      }),
    });
  } catch (error: unknown) {
    if (error instanceof HarnessKeyEnrollmentError) throw error;
    throw invalidSidecar();
  } finally {
    await handle.close();
  }
}

export async function writeHarnessKeyEnrollmentSidecar(
  controlPlanePath: string,
  sidecarValue: unknown,
  expected: HarnessKeyEnrollmentFile | null,
  options: HarnessKeyEnrollmentPublicationOptions = {},
): Promise<HarnessKeyEnrollmentFile> {
  const sidecar = parseHarnessKeyEnrollmentSidecar(sidecarValue);
  const path = harnessKeyEnrollmentSidecarPath(controlPlanePath);
  const parent = dirname(path);
  await assertPrivateCanonicalDirectory(parent);
  await removeSafeCandidate(controlPlanePath);
  const current = await readHarnessKeyEnrollmentSidecar(controlPlanePath);
  if (!sameEnrollmentFile(expected, current)) {
    throw new HarnessKeyEnrollmentError(
      "custody_conflict",
      "Harness key enrollment state changed before its monotone update.",
    );
  }
  if (expected !== null) assertSidecarTransition(expected.sidecar, sidecar);
  const candidate = harnessKeyEnrollmentSidecarCandidatePath(controlPlanePath);
  const encoded = canonicalHarnessKeyEnrollmentSidecar(sidecar);
  if (
    Buffer.byteLength(encoded, "utf8")
      > maximumHarnessKeyEnrollmentSidecarBytes
  ) {
    throw invalidSidecar();
  }
  let handle: Awaited<ReturnType<typeof open>> | null = null;
  try {
    handle = await open(
      candidate,
      constants.O_WRONLY
        | constants.O_CREAT
        | constants.O_EXCL
        | constants.O_NOFOLLOW
        | closeOnExecFlag(),
      0o600,
    );
    await handle.writeFile(encoded, { encoding: "utf8" });
    await handle.chmod(0o600);
    await handle.sync();
    await assertExpectedCurrent(path, expected);
    const [candidateAuthority, destinationAuthority] = await Promise.all([
      inspectProspectivePathAuthority(candidate, "enrollment candidate"),
      inspectProspectivePathAuthority(path, "enrollment sidecar"),
    ]);
    if (
      candidateAuthority.missing.length !== 0
      || destinationAuthority.missing.length !== (expected === null ? 1 : 0)
    ) {
      throw new HarnessKeyEnrollmentError(
        "custody_conflict",
        "Harness key enrollment publication authority changed.",
      );
    }
    const heldCandidate = await handle.stat({ bigint: true });
    const candidateLeaf = candidateAuthority.existing.at(-1);
    if (
      candidateLeaf === undefined
      || candidateLeaf.path !== candidate
      || heldCandidate.dev !== candidateLeaf.device
      || heldCandidate.ino !== candidateLeaf.inode
      || !heldCandidate.isFile()
      || heldCandidate.nlink !== 1n
      || (heldCandidate.mode & 0o777n) !== 0o600n
    ) {
      throw new HarnessKeyEnrollmentError(
        "custody_conflict",
        "Harness key enrollment candidate changed before publication.",
      );
    }
    try {
      await renameWithPathAuthority(
        candidateAuthority,
        destinationAuthority,
        {
          exchange: expected !== null,
          ...(options.beforePublishForTest === undefined
            ? {}
            : { beforeRenameForTest: options.beforePublishForTest }),
        },
      );
    } catch {
      throw new HarnessKeyEnrollmentError(
        "custody_conflict",
        "Harness key enrollment publication lost filesystem authority.",
      );
    }
    await syncDirectory(parent);
    const written = await readHarnessKeyEnrollmentSidecar(controlPlanePath);
    if (written === null || JSON.stringify(written.sidecar) !== JSON.stringify(sidecar)) {
      throw new HarnessKeyEnrollmentError(
        "custody_conflict",
        "Harness key enrollment publication changed unexpectedly.",
      );
    }
    const publishedCandidate = await handle.stat({ bigint: true });
    if (
      publishedCandidate.dev.toString(10) !== written.evidence.device
      || publishedCandidate.ino.toString(10) !== written.evidence.inode
      || publishedCandidate.nlink !== 1n
    ) {
      throw new HarnessKeyEnrollmentError(
        "custody_conflict",
        "Harness key enrollment candidate identity changed during publication.",
      );
    }
    if (expected !== null) {
      await unlinkBoundSingleLinkFile(candidate, expected.evidence);
    }
    return written;
  } finally {
    await handle?.close().catch(() => undefined);
  }
}

export async function removeExactHarnessKeyEnrollmentSidecar(
  controlPlanePath: string,
  expected: HarnessKeyEnrollmentFile,
): Promise<void> {
  const path = harnessKeyEnrollmentSidecarPath(controlPlanePath);
  await assertPrivateCanonicalDirectory(dirname(path));
  await unlinkBoundSingleLinkFile(path, expected.evidence);
  if (await readHarnessKeyEnrollmentSidecar(controlPlanePath) !== null) {
    throw new HarnessKeyEnrollmentError(
      "custody_conflict",
      "Harness key enrollment state remained after exact removal.",
    );
  }
}

export async function inspectFreshHarnessKeyEnrollmentRoot(
  controlPlanePath: string,
): Promise<boolean> {
  const path = harnessKeyEnrollmentSidecarPath(controlPlanePath);
  const root = dirname(path);
  await assertPrivateCanonicalDirectory(root);
  const lockPath = controlPlaneLifetimeLockPath(controlPlanePath);
  const names = await readdir(root);
  if (
    names.length !== 1
    || names[0] !== basename(lockPath)
  ) return false;
  try {
    const status = await lstat(lockPath, { bigint: true });
    const currentUser = process.geteuid?.();
    return status.isFile()
      && !status.isSymbolicLink()
      && status.nlink === 1n
      && (status.mode & 0o777n) === 0o600n
      && currentUser !== undefined
      && status.uid === BigInt(currentUser);
  } catch {
    return false;
  }
}

export async function ensureHarnessKeyEnrollment(
  options: EnsureHarnessKeyEnrollmentOptions,
): Promise<HarnessKeyEnrollmentFile> {
  const random = options.randomBytes ?? randomBytes;
  let current = await readHarnessKeyEnrollmentSidecar(options.controlPlanePath);
  if (current === null) {
    const observation = await inspectCustody(options.keychain);
    if (observation.state !== "absent" || !options.allowFreshAuthorization) {
      throw new HarnessKeyEnrollmentError(
        "authorization_missing",
        "Harness key enrollment authorization is unavailable.",
      );
    }
    current = await writeHarnessKeyEnrollmentSidecar(
      options.controlPlanePath,
      freshAuthorizedSidecar(createOperationId(random(12))),
      null,
    );
  }

  if (current.sidecar.phase === "enrolled") {
    const observation = await inspectCustody(options.keychain);
    assertMatchingStrictCustody(current.sidecar.attempt.envelopeSha256, observation);
    return current;
  }

  if (current.sidecar.phase === "authorized") {
    const observation = await inspectCustody(options.keychain);
    if (observation.state !== "absent") {
      throw new HarnessKeyEnrollmentError(
        "custody_conflict",
        "Authorized Harness key enrollment found unexpected existing custody.",
      );
    }
  } else {
    let observation: HarnessKeyEnrollmentObservation;
    try {
      observation = await inspectCustody(options.keychain);
    } catch (error: unknown) {
      if (
        !isExactV015PreparedAclMigration(current)
        || !(error instanceof HarnessKeyEnrollmentError)
        || error.code !== "custody_unavailable"
      ) throw error;
      const rebound = await readHarnessKeyEnrollmentSidecar(
        options.controlPlanePath,
      );
      if (!sameEnrollmentFile(current, rebound)) {
        throw new HarnessKeyEnrollmentError(
          "custody_conflict",
          "Prepared Harness key enrollment changed before ACL migration.",
        );
      }
      await validatePreparedCustody(
        options.keychain,
        current.sidecar.attempt.envelopeSha256,
      );
      const validatedUnchanged = await readHarnessKeyEnrollmentSidecar(
        options.controlPlanePath,
      );
      if (!sameEnrollmentFile(current, validatedUnchanged)) {
        throw new HarnessKeyEnrollmentError(
          "custody_conflict",
          "Prepared Harness key enrollment changed during ACL validation.",
        );
      }
      await migratePreparedCustody(
        options.keychain,
        current.sidecar.attempt.envelopeSha256,
      );
      const migratedUnchanged = await readHarnessKeyEnrollmentSidecar(
        options.controlPlanePath,
      );
      if (!sameEnrollmentFile(current, migratedUnchanged)) {
        throw new HarnessKeyEnrollmentError(
          "custody_conflict",
          "Prepared Harness key enrollment changed during ACL migration.",
        );
      }
      observation = await inspectCustody(options.keychain);
    }
    if (observation.state === "present") {
      assertMatchingStrictCustody(
        current.sidecar.attempt.envelopeSha256,
        observation,
      );
      return await writeHarnessKeyEnrollmentSidecar(
        options.controlPlanePath,
        { ...current.sidecar, phase: "enrolled" },
        current,
      );
    }
  }

  const generated = random(HARNESS_INSTALL_MASTER_KEY_BYTES);
  let envelope: string;
  try {
    envelope = serializeHarnessInstallMaster(generated);
  } finally {
    generated.fill(0);
  }
  const prepared = await writeHarnessKeyEnrollmentSidecar(
    options.controlPlanePath,
    {
      ...current.sidecar,
      phase: "prepared",
      attempt: {
        envelopeSha256: sha256(envelope),
        nonce: Buffer.from(random(32)).toString("hex"),
      },
    },
    current,
  );
  if (prepared.sidecar.phase !== "prepared") {
    throw new HarnessKeyEnrollmentError(
      "custody_conflict",
      "Harness key enrollment did not publish its prepared phase.",
    );
  }
  const created = await createCustody(options.keychain, envelope);
  if (!created.created) {
    throw new HarnessKeyEnrollmentError(
      "custody_conflict",
      "Harness key enrollment lost its create-only custody race.",
    );
  }
  if (
    canonicalHarnessInstallKeyEnvelope(created.envelope) !== envelope
    || created.strictAcl !== true
  ) {
    throw new HarnessKeyEnrollmentError(
      "custody_conflict",
      "Harness key enrollment creation returned unexpected authority.",
    );
  }
  const readback = await inspectCustody(options.keychain);
  assertMatchingStrictCustody(prepared.sidecar.attempt.envelopeSha256, readback);
  return await writeHarnessKeyEnrollmentSidecar(
    options.controlPlanePath,
    { ...prepared.sidecar, phase: "enrolled" },
    prepared,
  );
}

function isExactV015PreparedAclMigration(
  current: HarnessKeyEnrollmentFile,
): current is HarnessKeyEnrollmentFile & Readonly<{
  sidecar: Extract<HarnessKeyEnrollmentSidecar, { phase: "prepared" }>;
}> {
  if (current.sidecar.phase !== "prepared") return false;
  const authorization = current.sidecar.authorization;
  if (authorization.kind !== "forward_recovery_v1") return false;
  const identity = authorization.candidate.bundle.identity;
  return identity.version === "0.1.15"
    && identity.build === "16"
    && identity.bundleIdentifier === "kitchen.hraness"
    && identity.executable === "hra"
    && current.sidecar.descriptor.service === harnessInstallKeyDescriptor.service
    && current.sidecar.descriptor.name === harnessInstallKeyDescriptor.name
    && current.sidecar.expectedKeychainState === "absent";
}

function freshAuthorizedSidecar(operationId: string): HarnessKeyEnrollmentSidecar {
  return parseHarnessKeyEnrollmentSidecar({
    schemaVersion: 1,
    kind: "hra-harness-key-enrollment",
    descriptor: harnessInstallKeyDescriptor,
    expectedKeychainState: "absent",
    authorization: {
      kind: "fresh_install_v1",
      operationId,
    },
    phase: "authorized",
  });
}

async function inspectCustody(
  keychain: HarnessKeyEnrollmentKeychain,
): Promise<HarnessKeyEnrollmentObservation> {
  try {
    const result = await keychain.inspectExactNoUi();
    if (result.state === "absent" && result.strictAcl === false) return result;
    if (result.state === "present" && typeof result.strictAcl === "boolean") {
      return {
        ...result,
        envelope: canonicalHarnessInstallKeyEnvelope(result.envelope),
      };
    }
  } catch {
    // Collapse native/Keychain detail into one path-free error.
  }
  throw new HarnessKeyEnrollmentError(
    "custody_unavailable",
    "Harness key enrollment custody is unavailable.",
  );
}

async function createCustody(
  keychain: HarnessKeyEnrollmentKeychain,
  envelope: string,
): Promise<Readonly<{ created: boolean; envelope: string; strictAcl: boolean }>> {
  try {
    return await keychain.createExactIfAbsentNoUi(envelope);
  } catch {
    throw new HarnessKeyEnrollmentError(
      "custody_unavailable",
      "Harness key enrollment custody is unavailable.",
    );
  }
}

async function migratePreparedCustody(
  keychain: HarnessKeyEnrollmentKeychain,
  expectedEnvelopeSha256: string,
): Promise<void> {
  try {
    const result = await keychain.migratePreparedAcl(
      hexSha256Schema.parse(expectedEnvelopeSha256),
    );
    if (
      result.strictAcl !== true
      || result.envelopeSha256 !== expectedEnvelopeSha256
    ) throw new Error("prepared ACL migration result differs");
  } catch {
    throw new HarnessKeyEnrollmentError(
      "custody_unavailable",
      "Harness key enrollment ACL migration is unavailable.",
    );
  }
}

async function validatePreparedCustody(
  keychain: HarnessKeyEnrollmentKeychain,
  expectedEnvelopeSha256: string,
): Promise<void> {
  try {
    const result = await keychain.validatePreparedAcl(
      hexSha256Schema.parse(expectedEnvelopeSha256),
    );
    if (
      result.validated !== true
      || result.envelopeSha256 !== expectedEnvelopeSha256
    ) throw new Error("prepared ACL validation result differs");
  } catch {
    throw new HarnessKeyEnrollmentError(
      "custody_unavailable",
      "Harness key enrollment ACL validation is unavailable.",
    );
  }
}

function assertMatchingStrictCustody(
  expectedDigest: string,
  observation: HarnessKeyEnrollmentObservation,
): void {
  if (
    observation.state !== "present"
    || observation.strictAcl !== true
    || sha256(observation.envelope) !== expectedDigest
  ) {
    throw new HarnessKeyEnrollmentError(
      "custody_conflict",
      "Harness key enrollment custody differs from enrolled authority.",
    );
  }
}

function assertSidecarTransition(
  previous: HarnessKeyEnrollmentSidecar,
  next: HarnessKeyEnrollmentSidecar,
): void {
  const previousBase = { ...previous, phase: undefined, attempt: undefined };
  const nextBase = { ...next, phase: undefined, attempt: undefined };
  if (JSON.stringify(previousBase) !== JSON.stringify(nextBase)) {
    throw new HarnessKeyEnrollmentError(
      "custody_conflict",
      "Harness key enrollment authority is immutable.",
    );
  }
  const allowed = previous.phase === "authorized" && next.phase === "prepared"
    || previous.phase === "prepared" && next.phase === "prepared"
    || previous.phase === "prepared" && next.phase === "enrolled"
    || previous.phase === "enrolled" && next.phase === "enrolled";
  if (!allowed) {
    throw new HarnessKeyEnrollmentError(
      "custody_conflict",
      `Harness key enrollment transition ${previous.phase} -> ${next.phase} is invalid.`,
    );
  }
  if (
    previous.phase === "prepared"
    && next.phase === "enrolled"
    && JSON.stringify(previous.attempt) !== JSON.stringify(next.attempt)
  ) {
    throw new HarnessKeyEnrollmentError(
      "custody_conflict",
      "Harness key enrollment attempt changed while enrolling.",
    );
  }
}

async function assertExpectedCurrent(
  path: string,
  expected: HarnessKeyEnrollmentFile | null,
): Promise<void> {
  const current = await readHarnessKeyEnrollmentSidecar(
    join(dirname(path), "control-plane.sqlite"),
  );
  if (!sameEnrollmentFile(expected, current)) {
    throw new HarnessKeyEnrollmentError(
      "custody_conflict",
      "Harness key enrollment state changed before filesystem mutation.",
    );
  }
}

function sameEnrollmentFile(
  left: HarnessKeyEnrollmentFile | null,
  right: HarnessKeyEnrollmentFile | null,
): boolean {
  return left === null || right === null
    ? left === right
    : JSON.stringify(left) === JSON.stringify(right);
}

async function removeSafeCandidate(controlPlanePath: string): Promise<void> {
  const candidate = harnessKeyEnrollmentSidecarCandidatePath(controlPlanePath);
  try {
    await lstat(candidate, { bigint: true });
  } catch (error: unknown) {
    if (hasCode(error, "ENOENT")) return;
    throw unsafeFilesystem();
  }
  await unlinkBoundSingleLinkFile(candidate, null);
}

async function unlinkBoundSingleLinkFile(
  path: string,
  expected: HarnessKeyEnrollmentFileEvidence | null,
): Promise<void> {
  let handle: Awaited<ReturnType<typeof open>>;
  try {
    handle = await open(
      path,
      constants.O_RDONLY | constants.O_NOFOLLOW | closeOnExecFlag(),
    );
  } catch {
    throw unsafeFilesystem();
  }
  try {
    const status = await handle.stat({ bigint: true });
    const published = await lstat(path, { bigint: true });
    assertSafeSidecarMetadata(status, published);
    if (expected !== null) {
      if (
        status.dev.toString(10) !== expected.device
        || status.ino.toString(10) !== expected.inode
        || Number(status.size) !== expected.bytes
      ) {
        throw new HarnessKeyEnrollmentError(
          "custody_conflict",
          "Harness key enrollment file changed before exact removal.",
        );
      }
    } else if (status.size > BigInt(maximumHarnessKeyEnrollmentSidecarBytes)) {
      throw unsafeFilesystem();
    }
    await unlink(path);
    const after = await handle.stat({ bigint: true });
    if (
      after.dev !== status.dev
      || after.ino !== status.ino
      || after.nlink !== 0n
    ) {
      throw new HarnessKeyEnrollmentError(
        "custody_conflict",
        "Harness key enrollment removal lost inode authority.",
      );
    }
    await syncDirectory(dirname(path));
    try {
      await lstat(path);
      throw new HarnessKeyEnrollmentError(
        "custody_conflict",
        "Harness key enrollment path was replaced during removal.",
      );
    } catch (error: unknown) {
      if (!hasCode(error, "ENOENT")) throw error;
    }
  } finally {
    await handle.close();
  }
}

async function assertPrivateCanonicalDirectory(path: string): Promise<void> {
  const status = await lstat(path);
  const currentUser = process.geteuid?.();
  if (
    !status.isDirectory()
    || status.isSymbolicLink()
    || (status.mode & 0o077) !== 0
    || currentUser === undefined
    || status.uid !== currentUser
    || await realpath(path) !== path
  ) throw unsafeFilesystem();
}

function assertSafeSidecarMetadata(
  expected: BigIntStats,
  actual: BigIntStats,
): void {
  const currentUser = process.geteuid?.();
  if (
    !actual.isFile()
    || actual.isSymbolicLink()
    || actual.nlink !== 1n
    || (actual.mode & 0o777n) !== 0o600n
    || currentUser === undefined
    || actual.uid !== BigInt(currentUser)
    || !sameNode(expected, actual)
  ) throw unsafeFilesystem();
}

function sameNode(left: BigIntStats, right: BigIntStats): boolean {
  return left.dev === right.dev
    && left.ino === right.ino
    && left.size === right.size
    && left.mode === right.mode
    && left.nlink === right.nlink
    && left.mtimeNs === right.mtimeNs
    && left.ctimeNs === right.ctimeNs;
}

async function syncDirectory(path: string): Promise<void> {
  const handle = await open(
    path,
    constants.O_RDONLY
      | constants.O_DIRECTORY
      | constants.O_NOFOLLOW
      | closeOnExecFlag(),
  );
  try {
    await handle.sync();
  } finally {
    await handle.close();
  }
}

function closeOnExecFlag(): number {
  const value: unknown = Reflect.get(constants, "O_CLOEXEC");
  return typeof value === "number" ? value : 0;
}

function createOperationId(bytes: Uint8Array): string {
  if (bytes.byteLength !== 12) {
    throw new HarnessKeyEnrollmentError(
      "custody_unavailable",
      "Harness key enrollment entropy is unavailable.",
    );
  }
  return `fresh_${Buffer.from(bytes).toString("hex")}`;
}

function sha256(value: string | Uint8Array): string {
  return createHash("sha256").update(value).digest("hex");
}

function canonicalEvidenceJson(value: unknown): string {
  if (value === null) return "null";
  if (typeof value === "string" || typeof value === "boolean") {
    return JSON.stringify(value);
  }
  if (typeof value === "number") {
    if (!Number.isSafeInteger(value) || value < 0) {
      throw new HarnessKeyEnrollmentError(
        "invalid_sidecar",
        "Harness key enrollment evidence contains an invalid number.",
      );
    }
    return JSON.stringify(value);
  }
  if (Array.isArray(value)) {
    return `[${value.map(canonicalEvidenceJson).join(",")}]`;
  }
  if (
    typeof value !== "object"
    || Object.getPrototypeOf(value) !== Object.prototype
    || containsForbiddenKey(value, new WeakSet<object>())
  ) {
    throw new HarnessKeyEnrollmentError(
      "invalid_sidecar",
      "Harness key enrollment evidence is not canonical JSON.",
    );
  }
  return `{${Object.keys(value).sort().map((key) => {
    const child = Reflect.get(value, key) as unknown;
    if (child === undefined) {
      throw new HarnessKeyEnrollmentError(
        "invalid_sidecar",
        "Harness key enrollment evidence contains an undefined value.",
      );
    }
    return `${JSON.stringify(key)}:${canonicalEvidenceJson(child)}`;
  }).join(",")}}`;
}

function isAbsoluteNormalizedNonRoot(value: string): boolean {
  return isAbsolute(value)
    && resolve(value) === value
    && value !== resolve(value, sep)
    && !value.includes("\0");
}

function containsForbiddenKey(value: unknown, seen: WeakSet<object>): boolean {
  if (value === null || typeof value !== "object" || seen.has(value)) return false;
  seen.add(value);
  return Object.entries(value).some(([key, child]) =>
    forbiddenKeys.has(key) || containsForbiddenKey(child, seen)
  );
}

function invalidSidecar(): HarnessKeyEnrollmentError {
  return new HarnessKeyEnrollmentError(
    "invalid_sidecar",
    "Harness key enrollment sidecar is invalid.",
  );
}

function unsafeFilesystem(): HarnessKeyEnrollmentError {
  return new HarnessKeyEnrollmentError(
    "unsafe_filesystem",
    "Harness key enrollment filesystem authority is unsafe.",
  );
}

function hasCode(error: unknown, code: string): boolean {
  return error instanceof Error && "code" in error && error.code === code;
}
