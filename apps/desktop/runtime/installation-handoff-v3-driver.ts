import { constants } from "node:fs";
import { chmod, lstat, mkdir, open, readdir, realpath, rm } from "node:fs/promises";
import { basename, dirname, isAbsolute, join, resolve, sep } from "node:path";
import { isDeepStrictEqual } from "node:util";

import {
  advanceInstallationHandoffV3Progress,
  createInstallationHandoffV3Core,
  createInstallationHandoffV3OperationId,
  createInstallationHandoffV3Progress,
  defaultInstallationHandoffV3Dependencies,
  installationHandoffV3CoreReference,
  installationHandoffV3Paths,
  readInstallationHandoffV3Core,
  readInstallationHandoffV3EffectiveProgress,
  readInstallationHandoffV3Progress,
  readInstallationHandoffV3RollbackOrigin,
  reconcileInstallationHandoffV3PreparedTransition,
  recoverInstallationHandoffV3CorePublication,
  type InstallationHandoffV3CandidateEvidence,
  type InstallationHandoffV3Core,
  type InstallationHandoffV3CoreEvidence,
  type InstallationHandoffV3CustodyObservation,
  type InstallationHandoffV3Dependencies,
  type InstallationHandoffV3Phase,
  type InstallationHandoffV3Progress,
  type InstallationHandoffV3ProgressFile,
} from "./installation-handoff-v3";
import {
  assertKeychainContinuity,
  assertStateContinuity,
  eraseKeychainEvidence,
  inspectKeychainContinuity,
  inspectStateContinuity,
  inspectStateContinuityWithoutHarnessEnrollmentSidecar,
  installationHandoffPaths,
  type BundleContinuityEvidence,
  type HeldLock,
  type InstallationHandoffPaths,
  type KeychainEvidence,
  type StateContinuityEvidence,
} from "./installation-handoff";
import {
  authoritiesOverlap,
  inspectProspectivePathAuthority,
  renameExclForwardOnly,
  renameSwapForwardOnly,
} from "./installation-path-authority";
import { syncForwardRecoveryTreeDurably } from
  "./installation-forward-recovery";
import {
  expectedHistoricalOprtePreviewIdentity,
  expectedHistoricalOprtePreviewSignature,
  expectedHistoricalOprtePreviewTree,
  historicalOprtePreviewSignaturePolicy,
  strictBundleSignaturePolicy,
} from "./historical-oprte-preview";
import {
  authorizedHarnessKeyEnrollmentSidecar,
  createInstallationHandoffV3EnrollmentAuthorization,
  digestHarnessKeyEnrollmentPreState,
  installationHandoffV3EnrollmentAuthorizationMatches,
  readHarnessKeyEnrollmentSidecar,
  removeExactHarnessKeyEnrollmentSidecar,
  writeHarnessKeyEnrollmentSidecar,
  type HarnessKeyEnrollmentFile,
  type HarnessKeyEnrollmentSidecar,
} from "./src/state/harness-key-enrollment";

export const installationHandoffV3Confirmation =
  "RETIRE-OPRTE-IN-FAVOR-OF-HRA" as const;
export const installationHandoffV3ResumeConfirmation =
  "RESUME-HRA-INSTALLATION-HANDOFF-V3" as const;
export const installationHandoffV3RollbackConfirmation =
  "ROLL-BACK-HRA-TO-OPRTE" as const;
export const installationHandoffV3CleanupConfirmation =
  "CLEAN-COMMITTED-HRA-HANDOFF-STAGING" as const;

export type InstallationHandoffV3FaultPoint =
  | "after_core"
  | "after_created_progress"
  | "after_full_backup"
  | "after_candidate_smoke"
  | "after_bundle_archives"
  | "after_candidate_copy"
  | "before_candidate_stage_rename"
  | "after_candidate_stage_rename"
  | "after_candidate_staged"
  | "after_enrollment_authorizing"
  | "after_enrollment_sidecar"
  | "after_enrollment_authorized"
  | "before_candidate_publish_boundary"
  | "after_candidate_publish_boundary"
  | "before_candidate_publish_syscall"
  | "after_candidate_publish_syscall"
  | "after_candidate_installed"
  | "before_predecessor_retirement_syscall"
  | "after_predecessor_retirement_syscall"
  | "before_rollback_relocation"
  | "after_rollback_relocation_syscall"
  | "before_rollback_progress"
  | "before_committed_prior_cleanup"
  | "after_committed_prior_cleanup"
  | "before_committed_predecessor_cleanup"
  | "after_committed_predecessor_cleanup"
  | "after_predecessor_retired"
  | "after_verified"
  | "after_committed";

export type InstallationHandoffV3PhysicalDisposition =
  | "prestage"
  | "prepublish_unrecorded"
  | "prepublish"
  | "candidate_installed"
  | "predecessor_retired"
  | "committed_cleanup_pending"
  | "committed_clean"
  | "conflict";

export interface InstallationHandoffV3PhysicalObservation {
  readonly candidateStage:
    | InstallationHandoffV3CandidateEvidence
    | null;
  readonly disposition: InstallationHandoffV3PhysicalDisposition;
}

export interface InstallationHandoffV3RenameParentLease {
  readonly revalidate: () => Promise<void>;
  readonly release: () => Promise<void>;
  readonly syncAndRevalidate: () => Promise<void>;
}

export type InstallationHandoffV3ForwardRenameResult = Readonly<{
  status:
    | "published"
    | "postcondition_unknown_after_swap"
    | "postcondition_unknown_after_rename";
}>;

export interface InstallationHandoffV3DriverDependencies
  extends InstallationHandoffV3Dependencies {
  readonly assertKeychain: (evidence: KeychainEvidence) => Promise<void>;
  readonly acquireRenameParentLease: (
    source: string,
    destination: string,
  ) => Promise<InstallationHandoffV3RenameParentLease>;
  readonly captureKeychain: (
    controlPlanePath: string,
  ) => Promise<KeychainEvidence>;
  readonly derivePaths: (candidateApp: string) => InstallationHandoffPaths;
  readonly eraseKeychain: (evidence: KeychainEvidence | null) => void;
  readonly inspectStateV3: (
    stateRoot: string,
    controlPlanePath: string,
  ) => Promise<StateContinuityEvidence>;
  readonly inspectStateReadOnlyV3: (
    stateRoot: string,
    controlPlanePath: string,
  ) => Promise<StateContinuityEvidence>;
  readonly inspectStateWithoutEnrollmentSidecar: (
    stateRoot: string,
    controlPlanePath: string,
  ) => Promise<StateContinuityEvidence>;
  readonly publishCandidateForward: (
    source: string,
    destination: string,
    exchange: boolean,
    beforeRenameForTest?: () => Promise<void> | void,
  ) => Promise<InstallationHandoffV3ForwardRenameResult>;
  readonly readEnrollmentSidecar: (
    controlPlanePath: string,
  ) => Promise<HarnessKeyEnrollmentFile | null>;
  readonly removeEnrollmentSidecar: (
    controlPlanePath: string,
    expected: HarnessKeyEnrollmentFile,
  ) => Promise<void>;
  readonly relocateStageForward: (
    source: string,
    destination: string,
    beforeRenameForTest?: () => Promise<void> | void,
  ) => Promise<InstallationHandoffV3ForwardRenameResult>;
  readonly removePrivateTree: (path: string) => Promise<void>;
  readonly retirePredecessorForward: (
    source: string,
    destination: string,
    beforeRenameForTest?: () => Promise<void> | void,
  ) => Promise<InstallationHandoffV3ForwardRenameResult>;
  readonly syncTree: (path: string) => Promise<void>;
  readonly writeEnrollmentSidecar: (
    controlPlanePath: string,
    sidecar: HarnessKeyEnrollmentSidecar,
    expected: HarnessKeyEnrollmentFile | null,
  ) => Promise<HarnessKeyEnrollmentFile>;
}

export const defaultInstallationHandoffV3DriverDependencies:
  InstallationHandoffV3DriverDependencies = {
    ...defaultInstallationHandoffV3Dependencies,
    acquireRenameParentLease: acquireExactRenameParentLease,
    async assertKeychain(evidence) {
      await assertKeychainContinuity(
        evidence,
        defaultInstallationHandoffV3Dependencies,
      );
    },
    async captureKeychain(controlPlanePath) {
      return await inspectKeychainContinuity(
        controlPlanePath,
        defaultInstallationHandoffV3Dependencies,
      );
    },
    eraseKeychain: eraseKeychainEvidence,
    derivePaths: installationHandoffPaths,
    inspectStateV3: inspectStateContinuity,
    async inspectStateReadOnlyV3(stateRoot, controlPlanePath) {
      return await inspectStateContinuity(
        stateRoot,
        controlPlanePath,
        false,
      );
    },
    inspectStateWithoutEnrollmentSidecar:
      inspectStateContinuityWithoutHarnessEnrollmentSidecar,
    publishCandidateForward: publishCandidateForwardOnly,
    readEnrollmentSidecar: readHarnessKeyEnrollmentSidecar,
    removeEnrollmentSidecar: removeExactHarnessKeyEnrollmentSidecar,
    relocateStageForward: retirePredecessorForwardOnly,
    async removePrivateTree(path) {
      await rm(path, { force: false, recursive: true });
    },
    retirePredecessorForward: retirePredecessorForwardOnly,
    syncTree: syncForwardRecoveryTreeDurably,
    writeEnrollmentSidecar: writeHarnessKeyEnrollmentSidecar,
  };

export class InstallationHandoffV3DriverError extends Error {
  readonly code:
    | "app_running"
    | "candidate_invalid"
    | "confirmation_invalid"
    | "continuity_failed"
    | "custody_unavailable"
    | "filesystem_unsafe"
    | "forward_recovery_required"
    | "lock_unavailable"
    | "recovery_conflict"
    | "updater_active";

  constructor(code: InstallationHandoffV3DriverError["code"], message: string) {
    super(message);
    this.name = "InstallationHandoffV3DriverError";
    this.code = code;
  }
}

type InstallationHandoffV3Checkpoint = (
  point: InstallationHandoffV3FaultPoint,
) => Promise<void> | void;

export interface InstallationHandoffV3Input {
  readonly backupDirectory: string;
  readonly candidateApp: string;
  readonly confirmation: string;
  readonly onCheckpoint?: InstallationHandoffV3Checkpoint;
  readonly paths?: InstallationHandoffPaths;
}

export interface InstallationHandoffV3RecoveryInput {
  readonly backupDirectory: string;
  readonly confirmation: string;
  readonly onCheckpoint?: InstallationHandoffV3Checkpoint;
  readonly paths?: InstallationHandoffPaths;
}

export interface InstallationHandoffV3StatusInput {
  readonly backupDirectory: string;
  readonly paths?: InstallationHandoffPaths;
}

export interface InstallationHandoffV3Result {
  readonly backupDirectory: string;
  readonly disposition: InstallationHandoffV3PhysicalDisposition;
  readonly keychainContinuity:
    | "verified_same_process"
    | "unavailable_after_process_restart"
    | "not_applicable";
  readonly operationId: string;
  readonly phase: InstallationHandoffV3Phase;
  readonly stateDigest: string;
  readonly status: "committed" | "in_progress" | "rolled_back";
}

type OperationLocks = Readonly<{
  controlPlane: ReturnType<
    InstallationHandoffV3DriverDependencies["acquireControlPlaneLock"]
  >;
  native: HeldLock;
}>;

type IrreversibleGuard = { preparedMayBeDurable: boolean };

type ContinuationContext = {
  readonly checkpoint: InstallationHandoffV3Checkpoint | undefined;
  readonly core: InstallationHandoffV3Core;
  readonly coreEvidence: InstallationHandoffV3CoreEvidence;
  readonly dependencies: InstallationHandoffV3DriverDependencies;
  readonly guard: IrreversibleGuard;
  readonly keychain: KeychainEvidence | null;
  readonly sameProcess: boolean;
  progress: InstallationHandoffV3ProgressFile;
};

export async function performInstallationHandoffV3(
  input: InstallationHandoffV3Input,
  dependencies: InstallationHandoffV3DriverDependencies =
    defaultInstallationHandoffV3DriverDependencies,
): Promise<InstallationHandoffV3Result> {
  requireConfirmation(
    input.confirmation,
    installationHandoffV3Confirmation,
  );
  const backupDirectory = normalizedNonRoot(
    input.backupDirectory,
    "backup directory",
  );
  const basePaths = input.paths ?? dependencies.derivePaths(input.candidateApp);
  await validateV3Paths(
    basePaths,
    backupDirectory,
    input.candidateApp,
    dependencies,
  );

  if (await pathExists(backupDirectory)) {
    await requirePrivateBackupDirectory(backupDirectory);
    const recovered = await recoverInstallationHandoffV3CorePublication(
      backupDirectory,
    );
    if (recovered !== null) {
      const loaded = await loadV3Operation(
        backupDirectory,
        dependencies,
        basePaths,
      );
      if (loaded.core.paths.candidateApp !== normalizedNonRoot(
        input.candidateApp,
        "candidate app",
      )) throw recoveryConflict("Existing v3 authority names another candidate source.");
      return await runLoadedV3Operation(
        loaded,
        dependencies,
        input.onCheckpoint,
        false,
        null,
      );
    }
    if ((await requirePrivateBackupDirectory(backupDirectory)).length !== 0) {
      throw recoveryConflict("Pre-core residue recovery left unknown backup content.");
    }
  } else {
    await mkdir(backupDirectory, { mode: 0o700 });
    await chmod(backupDirectory, 0o700);
    await requirePrivateBackupDirectory(backupDirectory);
  }

  const operationId = createInstallationHandoffV3OperationId(
    Buffer.from(dependencies.randomBytes(12)),
  );
  const paths = installationHandoffV3Paths(
    basePaths,
    backupDirectory,
    operationId,
  );
  await requireMissingV3Stages(paths);
  const locks = await acquireV3OperationLocks(paths, dependencies);
  let keychain: KeychainEvidence | null = null;
  let progress: InstallationHandoffV3ProgressFile | null = null;
  let core: InstallationHandoffV3Core | null = null;
  let coreEvidence: InstallationHandoffV3CoreEvidence | null = null;
  const guard: IrreversibleGuard = { preparedMayBeDurable: false };
  try {
    const candidate = await dependencies.inspectCandidateV3(paths.candidateApp);
    const predecessor = await dependencies.inspectBundle(
      paths.predecessorApp,
      historicalOprtePreviewSignaturePolicy,
    );
    requireExactPredecessor(predecessor);
    const priorHra = await pathExists(paths.canonicalApp)
      ? await dependencies.inspectBundle(
          paths.canonicalApp,
          strictBundleSignaturePolicy,
        )
      : null;
    await assertPreEnrollmentState(
      paths,
      candidate,
      dependencies,
    );
    const preStateBeforeKeychain = await dependencies.inspectStateV3(
      paths.stateRoot,
      paths.controlPlanePath,
    );
    keychain = await dependencies.captureKeychain(paths.controlPlanePath);
    await assertPreEnrollmentState(
      paths,
      candidate,
      dependencies,
    );
    const preState = await dependencies.inspectStateV3(
      paths.stateRoot,
      paths.controlPlanePath,
    );
    assertStateContinuity(
      preStateBeforeKeychain,
      preState,
      "pre-core state",
    );
    core = {
      candidate,
      createdAt: dependencies.now(),
      keychainDescriptors: [...keychain.descriptors],
      kind: "hra-installation-handoff-authorization",
      operationId,
      paths,
      predecessor,
      preState,
      preStateSha256: digestHarnessKeyEnrollmentPreState(preState),
      priorHra,
      schemaVersion: 3,
    };
    coreEvidence = await createInstallationHandoffV3Core(
      backupDirectory,
      core,
    );
    await input.onCheckpoint?.("after_core");
    progress = await createInstallationHandoffV3Progress(
      backupDirectory,
      {
        authorizedSidecar: null,
        candidateStage: null,
        core: coreEvidence,
        keychainContinuity: "pending_same_process",
        phase: "created",
        schemaVersion: 3,
      },
    );
    await input.onCheckpoint?.("after_created_progress");
    return await continueInstallationHandoffV3({
      checkpoint: input.onCheckpoint,
      core,
      coreEvidence,
      dependencies,
      guard,
      keychain,
      progress,
      sameProcess: true,
    });
  } catch (error: unknown) {
    if (core !== null && coreEvidence !== null && progress !== null) {
      try {
        let current = await readInstallationHandoffV3Progress(
          backupDirectory,
          coreEvidence,
        );
        current = await reconcileV3PreparedTransitions(
          core,
          current,
          guard,
        );
        if (guard.preparedMayBeDurable) {
          throw forwardRecoveryRequired(error);
        }
        await rollbackInstallationHandoffV3Internal(
          core,
          current,
          dependencies,
          keychain,
          input.onCheckpoint,
        );
      } catch (rollbackError: unknown) {
        if (
          rollbackError instanceof InstallationHandoffV3DriverError
          && rollbackError.code === "forward_recovery_required"
        ) throw rollbackError;
        throw forwardRecoveryRequired(error, rollbackError);
      }
    } else if (guard.preparedMayBeDurable) {
      throw forwardRecoveryRequired(error);
    }
    throw error;
  } finally {
    dependencies.eraseKeychain(keychain);
    releaseV3OperationLocks(locks);
  }
}

export async function resumeInstallationHandoffV3(
  input: InstallationHandoffV3RecoveryInput,
  dependencies: InstallationHandoffV3DriverDependencies =
    defaultInstallationHandoffV3DriverDependencies,
): Promise<InstallationHandoffV3Result> {
  requireConfirmation(
    input.confirmation,
    installationHandoffV3ResumeConfirmation,
  );
  const backupDirectory = normalizedNonRoot(
    input.backupDirectory,
    "backup directory",
  );
  const loaded = await loadV3Operation(
    backupDirectory,
    dependencies,
    input.paths,
  );
  return await runLoadedV3Operation(
    loaded,
    dependencies,
    input.onCheckpoint,
    false,
    null,
  );
}

export async function rollbackInstallationHandoffV3(
  input: InstallationHandoffV3RecoveryInput,
  dependencies: InstallationHandoffV3DriverDependencies =
    defaultInstallationHandoffV3DriverDependencies,
): Promise<InstallationHandoffV3Result> {
  requireConfirmation(
    input.confirmation,
    installationHandoffV3RollbackConfirmation,
  );
  const loaded = await loadV3Operation(
    normalizedNonRoot(input.backupDirectory, "backup directory"),
    dependencies,
    input.paths,
  );
  const locks = await acquireV3OperationLocks(loaded.core.paths, dependencies);
  let keychain: KeychainEvidence | null = null;
  try {
    let progress = await readInstallationHandoffV3Progress(
      loaded.core.paths.backupDirectory,
      loaded.coreEvidence,
    );
    if (progress.progress.phase !== "rolled_back") {
      keychain = await dependencies.captureKeychain(
        loaded.core.paths.controlPlanePath,
      );
      await assertActiveRollbackKeychain(
        loaded.core,
        keychain,
        dependencies,
      );
    }
    const guard: IrreversibleGuard = { preparedMayBeDurable: false };
    progress = await reconcileV3PreparedTransitions(
      loaded.core,
      progress,
      guard,
    );
    if (guard.preparedMayBeDurable) {
      throw new InstallationHandoffV3DriverError(
        "forward_recovery_required",
        "Rollback found a durable prepared transition and must continue forward.",
      );
    }
    const rolledBack = await rollbackInstallationHandoffV3Internal(
      loaded.core,
      progress,
      dependencies,
      keychain,
      input.onCheckpoint,
    );
    return await resultFor(
      loaded.core,
      rolledBack.progress,
      dependencies,
      false,
    );
  } finally {
    dependencies.eraseKeychain(keychain);
    releaseV3OperationLocks(locks);
  }
}

export async function cleanupCommittedInstallationHandoffV3(
  input: InstallationHandoffV3RecoveryInput,
  dependencies: InstallationHandoffV3DriverDependencies =
    defaultInstallationHandoffV3DriverDependencies,
): Promise<InstallationHandoffV3Result> {
  requireConfirmation(
    input.confirmation,
    installationHandoffV3CleanupConfirmation,
  );
  const loaded = await loadV3Operation(
    normalizedNonRoot(input.backupDirectory, "backup directory"),
    dependencies,
    input.paths,
  );
  const locks = await acquireV3OperationLocks(loaded.core.paths, dependencies);
  let keychain: KeychainEvidence | null = null;
  try {
    let progress = await readInstallationHandoffV3Progress(
      loaded.core.paths.backupDirectory,
      loaded.coreEvidence,
    );
    if (progress.progress.phase !== "rolled_back") {
      keychain = await dependencies.captureKeychain(
        loaded.core.paths.controlPlanePath,
      );
      assertV3KeychainDescriptorInventory(loaded.core, keychain);
      await dependencies.assertKeychain(keychain);
    }
    const guard: IrreversibleGuard = {
      preparedMayBeDurable:
        phaseIndexV3(progress.progress.phase)
          >= phaseIndexV3("candidate_publish_prepared"),
    };
    progress = await reconcileV3PreparedTransitions(
      loaded.core,
      progress,
      guard,
    );
    if (progress.progress.phase !== "committed") {
      throw recoveryConflict("Committed cleanup requires committed v3 progress.");
    }
    if (keychain === null) {
      throw recoveryConflict("Committed cleanup lacks Keychain continuity.");
    }
    await assertPostAuthorizationState(
      loaded.core,
      progress.progress,
      dependencies,
    );
    await cleanupCommittedV3Stages(
      loaded.core,
      progress.progress,
      dependencies,
      input.onCheckpoint,
    );
    await dependencies.assertKeychain(keychain);
    return await resultFor(
      loaded.core,
      progress.progress,
      dependencies,
      false,
    );
  } finally {
    dependencies.eraseKeychain(keychain);
    releaseV3OperationLocks(locks);
  }
}

export async function inspectInstallationHandoffV3Status(
  input: InstallationHandoffV3StatusInput,
  dependencies: InstallationHandoffV3DriverDependencies =
    defaultInstallationHandoffV3DriverDependencies,
): Promise<InstallationHandoffV3Result> {
  const backupDirectory = normalizedNonRoot(
    input.backupDirectory,
    "backup directory",
  );
  const first = await inspectReadOnlyV3StatusSnapshot(
    backupDirectory,
    input.paths,
    dependencies,
  );
  const second = await inspectReadOnlyV3StatusSnapshot(
    backupDirectory,
    input.paths,
    dependencies,
  );
  if (!isDeepStrictEqual(first, second)) {
    throw recoveryConflict("Schema-v3 status changed across repeated read-only proof.");
  }
  return first.result;
}

async function inspectReadOnlyV3StatusSnapshot(
  backupDirectory: string,
  expectedPaths: InstallationHandoffPaths | undefined,
  dependencies: InstallationHandoffV3DriverDependencies,
) {
  await requirePrivateBackupDirectory(backupDirectory);
  const read = await readInstallationHandoffV3Core(backupDirectory);
  await validateV3Paths(
    read.core.paths,
    backupDirectory,
    read.core.paths.candidateApp,
    dependencies,
  );
  if (expectedPaths !== undefined) {
    assertBasePathsMatch(read.core.paths, expectedPaths);
  }
  let progressRead: Awaited<ReturnType<
    typeof readInstallationHandoffV3EffectiveProgress
  >> | null;
  try {
    progressRead = await readInstallationHandoffV3EffectiveProgress(
      backupDirectory,
      read.evidence,
    );
  } catch (error: unknown) {
    if (!hasCode(error, "ENOENT")) throw error;
    progressRead = null;
  }
  let progress: InstallationHandoffV3Progress = progressRead?.effective.progress ?? {
    authorizedSidecar: null,
    candidateStage: null,
    core: read.evidence,
    keychainContinuity: "unavailable_after_process_restart",
    phase: "created",
    schemaVersion: 3,
  };
  let syntheticRollbackCandidate:
    | InstallationHandoffV3CandidateEvidence
    | null
    | undefined;
  const rawPhysical = await inspectInstallationHandoffV3PhysicalDisposition(
    read.core,
    progress,
    dependencies,
  );
  if (!installationHandoffV3ProgressAllowsDisposition(
    progress.phase,
    rawPhysical.disposition,
  )) {
    const rollbackTombstone = await inspectRollbackCandidateTombstone(
      read.core,
      progress.candidateStage,
      dependencies,
    );
    if (
      phaseIndexV3(progress.phase)
        < phaseIndexV3("candidate_publish_prepared")
      && rawPhysical.disposition === "prestage"
      && rollbackTombstone === "exact"
    ) {
      syntheticRollbackCandidate = progress.candidateStage;
      await assertRolledBackState(read.core, dependencies, {
        expectedCandidate: syntheticRollbackCandidate,
        readOnly: true,
      });
      progress = {
        ...progress,
        authorizedSidecar: null,
        candidateStage: null,
        keychainContinuity: "not_applicable",
        phase: "rolled_back",
      };
    } else {
      throw recoveryConflict(
        `Status progress ${progress.phase} conflicts with ${rawPhysical.disposition}.`,
      );
    }
  }
  const physical = await assertProgressAndPhysicalState(
    read.core,
    progress,
    dependencies,
  );
  if (progress.phase === "rolled_back") {
    const durableHistoryOrigin = progressRead?.source === "durable_next_history"
      && progressRead.effective.progress.phase === "rolled_back"
      ? progressRead.canonical.progress.candidateStage
      : undefined;
    await assertRolledBackState(read.core, dependencies, {
      ...(syntheticRollbackCandidate === undefined
        ? durableHistoryOrigin === undefined
          ? { coreEvidence: progress.core }
          : { expectedCandidate: durableHistoryOrigin }
        : { expectedCandidate: syntheticRollbackCandidate }),
      readOnly: true,
    });
  } else if (
    phaseIndexV3(progress.phase)
      >= phaseIndexV3("enrollment_authorized")
  ) {
    await assertPostAuthorizationState(read.core, progress, dependencies);
  } else {
    await assertPreAuthorizationState(
      read.core,
      progress,
      dependencies,
      true,
    );
  }
  const state = progress.phase === "rolled_back"
    || phaseIndexV3(progress.phase) < phaseIndexV3("enrollment_authorized")
    ? await dependencies.inspectStateReadOnlyV3(
        read.core.paths.stateRoot,
        read.core.paths.controlPlanePath,
      )
    : await dependencies.inspectStateWithoutEnrollmentSidecar(
        read.core.paths.stateRoot,
        read.core.paths.controlPlanePath,
      );
  const sidecar = await dependencies.readEnrollmentSidecar(
    read.core.paths.controlPlanePath,
  );
  const tombstones = await inspectV3TombstoneSnapshot(
    read.core,
    progress,
    dependencies,
  );
  return {
    core: read.core,
    coreEvidence: read.evidence,
    effectiveProgressEvidence: progressRead?.effective.evidence ?? null,
    physical,
    progress,
    progressCanonical: progressRead?.canonical.progress ?? null,
    progressCanonicalEvidence: progressRead?.canonical.evidence ?? null,
    progressSource: progressRead?.source ?? "synthetic_created",
    result: await resultFor(
      read.core,
      progress,
      dependencies,
      false,
    ),
    sidecar,
    state,
    tombstones,
  };
}

async function runLoadedV3Operation(
  loaded: Readonly<{
    core: InstallationHandoffV3Core;
    coreEvidence: InstallationHandoffV3CoreEvidence;
    progress: InstallationHandoffV3ProgressFile;
  }>,
  dependencies: InstallationHandoffV3DriverDependencies,
  checkpoint: InstallationHandoffV3Checkpoint | undefined,
  sameProcess: boolean,
  keychain: KeychainEvidence | null,
): Promise<InstallationHandoffV3Result> {
  const locks = await acquireV3OperationLocks(loaded.core.paths, dependencies);
  const guard: IrreversibleGuard = {
    preparedMayBeDurable:
      phaseIndexV3(loaded.progress.progress.phase)
        >= phaseIndexV3("candidate_publish_prepared"),
  };
  let activeKeychain = keychain;
  try {
    let current = await readInstallationHandoffV3Progress(
      loaded.core.paths.backupDirectory,
      loaded.coreEvidence,
    );
    if (
      current.progress.phase !== "rolled_back"
      && activeKeychain === null
    ) {
      activeKeychain = await dependencies.captureKeychain(
        loaded.core.paths.controlPlanePath,
      );
      await assertActiveRollbackKeychain(
        loaded.core,
        activeKeychain,
        dependencies,
      );
    }
    current = await reconcileV3PreparedTransitions(
      loaded.core,
      current,
      guard,
    );
    current = await tryTerminalizeCompletedRollback(
      loaded.core,
      current,
      dependencies,
      activeKeychain,
    ) ?? current;
    if (current.progress.phase !== "rolled_back") {
      await assertActiveRollbackKeychain(
        loaded.core,
        activeKeychain,
        dependencies,
      );
    }
    await reconcilePrivateCandidateCopyResidue(
      loaded.core,
      current.progress,
      dependencies,
    );
    if (current.progress.phase !== "rolled_back") {
      await assertActiveRollbackKeychain(
        loaded.core,
        activeKeychain,
        dependencies,
      );
    }
    const physical = await assertProgressAndPhysicalState(
      loaded.core,
      current.progress,
      dependencies,
    );
    if (isPostBoundaryDisposition(physical.disposition)) {
      guard.preparedMayBeDurable = true;
    }
    return await continueInstallationHandoffV3({
      checkpoint,
      core: loaded.core,
      coreEvidence: loaded.coreEvidence,
      dependencies,
      guard,
      keychain: activeKeychain,
      progress: current,
      sameProcess,
    });
  } catch (error: unknown) {
    if (!guard.preparedMayBeDurable) {
      try {
        let current = await readInstallationHandoffV3Progress(
          loaded.core.paths.backupDirectory,
          loaded.coreEvidence,
        );
        current = await reconcileV3PreparedTransitions(
          loaded.core,
          current,
          guard,
        );
        if (guard.preparedMayBeDurable) {
          throw forwardRecoveryRequired(error);
        }
        if (activeKeychain === null) {
          activeKeychain = await dependencies.captureKeychain(
            loaded.core.paths.controlPlanePath,
          );
        }
        await assertActiveRollbackKeychain(
          loaded.core,
          activeKeychain,
          dependencies,
        );
        await rollbackInstallationHandoffV3Internal(
          loaded.core,
          current,
          dependencies,
          activeKeychain,
          checkpoint,
        );
      } catch (rollbackError: unknown) {
        if (
          rollbackError instanceof InstallationHandoffV3DriverError
          && rollbackError.code === "forward_recovery_required"
        ) throw rollbackError;
        throw forwardRecoveryRequired(error, rollbackError);
      }
      throw error;
    }
    throw forwardRecoveryRequired(error);
  } finally {
    dependencies.eraseKeychain(activeKeychain);
    releaseV3OperationLocks(locks);
  }
}

async function continueInstallationHandoffV3(
  context: ContinuationContext,
): Promise<InstallationHandoffV3Result> {
  for (;;) {
    const progress = context.progress.progress;
    await assertProgressAndPhysicalState(
      context.core,
      progress,
      context.dependencies,
    );
    switch (progress.phase) {
      case "created": {
        await ensureV3StateBackup(context.core, context.dependencies);
        context.progress = await advanceV3(context, "backed_up");
        await context.checkpoint?.("after_full_backup");
        break;
      }
      case "backed_up": {
        await assertPreAuthorizationState(
          context.core,
          progress,
          context.dependencies,
        );
        await context.dependencies.smokeCandidate(
          context.core.paths.candidateApp,
        );
        context.progress = await advanceV3(context, "smoked");
        await context.checkpoint?.("after_candidate_smoke");
        break;
      }
      case "smoked": {
        await ensureV3BundleArchives(context.core, context.dependencies);
        context.progress = await advanceV3(context, "bundles_archived");
        await context.checkpoint?.("after_bundle_archives");
        break;
      }
      case "bundles_archived": {
        const lease = await context.dependencies.acquireRenameParentLease(
          candidateCopyStage(context.core),
          context.core.paths.candidateStage,
        );
        try {
          const staged = await ensureV3CandidateStage(
            context.core,
            progress,
            context.dependencies,
            lease,
            context.checkpoint,
          );
          context.progress = await advanceV3(
            context,
            "candidate_staged",
            { candidateStage: staged },
          );
          await lease.revalidate();
        } finally {
          await lease.release();
        }
        await context.checkpoint?.("after_candidate_staged");
        break;
      }
      case "candidate_staged": {
        await assertPreAuthorizationState(
          context.core,
          progress,
          context.dependencies,
        );
        context.progress = await advanceV3(
          context,
          "enrollment_authorizing",
        );
        await context.checkpoint?.("after_enrollment_authorizing");
        break;
      }
      case "enrollment_authorizing": {
        const sidecar = await ensureV3AuthorizedSidecar(
          context.core,
          context.coreEvidence,
          progress,
          context.dependencies,
        );
        await context.checkpoint?.("after_enrollment_sidecar");
        context.progress = await advanceV3(
          context,
          "enrollment_authorized",
          { authorizedSidecar: sidecar.evidence },
        );
        await context.checkpoint?.("after_enrollment_authorized");
        break;
      }
      case "enrollment_authorized": {
        await assertPostAuthorizationState(
          context.core,
          progress,
          context.dependencies,
        );
        if (context.keychain !== null) {
          await context.dependencies.assertKeychain(context.keychain);
        }
        await context.checkpoint?.("before_candidate_publish_boundary");
        await requireV3Quiescence(
          context.core.paths,
          context.dependencies,
        );
        context.progress = await advanceV3(
          context,
          "candidate_publish_prepared",
        );
        await context.checkpoint?.("after_candidate_publish_boundary");
        break;
      }
      case "candidate_publish_prepared": {
        const lease = await context.dependencies.acquireRenameParentLease(
          context.core.paths.candidateStage,
          context.core.paths.canonicalApp,
        );
        try {
          await lease.revalidate();
          await assertPostAuthorizationState(
            context.core,
            progress,
            context.dependencies,
          );
          const physical = await assertProgressAndPhysicalState(
            context.core,
            progress,
            context.dependencies,
          );
          if (physical.disposition === "prepublish") {
            if (context.keychain !== null) {
              await context.dependencies.assertKeychain(context.keychain);
            }
            await requireV3Quiescence(
              context.core.paths,
              context.dependencies,
            );
            await publishInstallationHandoffV3CandidateForward(
              context.core,
              progress,
              context.dependencies,
              async () => {
                await context.checkpoint?.("before_candidate_publish_syscall");
                if (context.keychain !== null) {
                  await context.dependencies.assertKeychain(context.keychain);
                }
                await requireV3Quiescence(
                  context.core.paths,
                  context.dependencies,
                );
                await lease.revalidate();
              },
            );
            await context.checkpoint?.("after_candidate_publish_syscall");
            if (context.keychain !== null) {
              await context.dependencies.assertKeychain(context.keychain);
            }
          } else if (physical.disposition !== "candidate_installed") {
            throw recoveryConflict(
              "Prepared candidate publication has no exact forward disposition.",
            );
          }
          await lease.syncAndRevalidate();
          const durable = await assertProgressAndPhysicalState(
            context.core,
            progress,
            context.dependencies,
          );
          if (durable.disposition !== "candidate_installed") {
            throw recoveryConflict(
              "Candidate publication changed before its progress proof.",
            );
          }
          await assertPostAuthorizationState(
            context.core,
            progress,
            context.dependencies,
          );
          context.progress = await advanceV3(context, "candidate_installed");
          await lease.revalidate();
        } finally {
          await lease.release();
        }
        await context.checkpoint?.("after_candidate_installed");
        break;
      }
      case "candidate_installed": {
        const lease = await context.dependencies.acquireRenameParentLease(
          context.core.paths.predecessorApp,
          context.core.paths.predecessorRetirementStage,
        );
        try {
          await lease.revalidate();
          await assertPostAuthorizationState(
            context.core,
            progress,
            context.dependencies,
          );
          const physical = await assertProgressAndPhysicalState(
            context.core,
            progress,
            context.dependencies,
          );
          if (physical.disposition === "candidate_installed") {
            if (context.keychain !== null) {
              await context.dependencies.assertKeychain(context.keychain);
            }
            await requireV3Quiescence(
              context.core.paths,
              context.dependencies,
            );
            await retireInstallationHandoffV3PredecessorForward(
              context.core,
              progress,
              context.dependencies,
              async () => {
                await context.checkpoint?.(
                  "before_predecessor_retirement_syscall",
                );
                if (context.keychain !== null) {
                  await context.dependencies.assertKeychain(context.keychain);
                }
                await requireV3Quiescence(
                  context.core.paths,
                  context.dependencies,
                );
                await lease.revalidate();
              },
            );
            await context.checkpoint?.("after_predecessor_retirement_syscall");
            if (context.keychain !== null) {
              await context.dependencies.assertKeychain(context.keychain);
            }
          } else if (physical.disposition !== "predecessor_retired") {
            throw recoveryConflict(
              "Installed candidate has no exact predecessor-retirement disposition.",
            );
          }
          await lease.syncAndRevalidate();
          const durable = await assertProgressAndPhysicalState(
            context.core,
            progress,
            context.dependencies,
          );
          if (durable.disposition !== "predecessor_retired") {
            throw recoveryConflict(
              "Predecessor retirement changed before its progress proof.",
            );
          }
          await assertPostAuthorizationState(
            context.core,
            progress,
            context.dependencies,
          );
          context.progress = await advanceV3(context, "predecessor_retired");
          await lease.revalidate();
        } finally {
          await lease.release();
        }
        await context.checkpoint?.("after_predecessor_retired");
        break;
      }
      case "predecessor_retired": {
        await assertFinalV3Continuity(context);
        context.progress = await advanceV3(context, "verified");
        await context.checkpoint?.("after_verified");
        break;
      }
      case "verified": {
        await assertFinalV3Continuity(context);
        context.progress = await advanceV3(context, "committed");
        await context.checkpoint?.("after_committed");
        break;
      }
      case "committed": {
        await assertFinalV3Continuity(context);
        await cleanupCommittedV3Stages(
          context.core,
          progress,
          context.dependencies,
          context.checkpoint,
        );
        return await resultFor(
          context.core,
          progress,
          context.dependencies,
          context.sameProcess,
        );
      }
      case "rolled_back": {
        await assertRolledBackState(context.core, context.dependencies, {
          coreEvidence: progress.core,
        });
        return await resultFor(
          context.core,
          progress,
          context.dependencies,
          context.sameProcess,
        );
      }
    }
  }
}

async function advanceV3(
  context: ContinuationContext,
  phase: InstallationHandoffV3Phase,
  overrides: Partial<Pick<
    InstallationHandoffV3Progress,
    "authorizedSidecar" | "candidateStage"
  >> = {},
): Promise<InstallationHandoffV3ProgressFile> {
  const current = context.progress.progress;
  const next: InstallationHandoffV3Progress = {
    ...current,
    ...overrides,
    keychainContinuity: continuityForNext(context, phase),
    phase,
  };
  const beforeProgressCandidate = phase === "candidate_publish_prepared"
    ? async () => {
        if (context.keychain !== null) {
          await context.dependencies.assertKeychain(context.keychain);
        }
        await requireV3Quiescence(
          context.core.paths,
          context.dependencies,
        );
      }
    : undefined;
  const beforeProgressSwap = phase === "candidate_publish_prepared"
    ? async () => {
        if (context.keychain !== null) {
          await context.dependencies.assertKeychain(context.keychain);
        }
        await requireV3Quiescence(
          context.core.paths,
          context.dependencies,
        );
      }
    : undefined;
  return await advanceInstallationHandoffV3Progress(
    context.core.paths.backupDirectory,
    context.progress,
    next,
    {
      ...(context.dependencies.afterProgressPublishForTest === undefined
        ? {}
        : {
            afterProgressPublishForTest:
              context.dependencies.afterProgressPublishForTest,
          }),
      ...(context.dependencies.afterProgressSwapBeforeSyncForTest === undefined
        ? {}
        : {
            afterProgressSwapBeforeSyncForTest:
              context.dependencies.afterProgressSwapBeforeSyncForTest,
          }),
      ...(context.dependencies.beforeProgressPublishForTest === undefined
        ? {}
        : {
            beforeProgressPublishForTest:
              context.dependencies.beforeProgressPublishForTest,
          }),
      ...(beforeProgressCandidate === undefined
        ? {}
        : { beforeProgressCandidate }),
      afterProgressCandidateDurable() {
        if (phase === "candidate_publish_prepared") {
          context.guard.preparedMayBeDurable = true;
        }
      },
      ...(beforeProgressSwap === undefined
        ? {}
        : { beforeProgressSwap }),
    },
  );
}

async function reconcileV3PreparedTransitions(
  core: InstallationHandoffV3Core,
  current: InstallationHandoffV3ProgressFile,
  guard: IrreversibleGuard,
): Promise<InstallationHandoffV3ProgressFile> {
  let cursor = current;
  for (;;) {
    const reconciled = await reconcileInstallationHandoffV3PreparedTransition(
      core.paths.backupDirectory,
      cursor,
      {
        beforeAdvance(next) {
          if (next.phase === "candidate_publish_prepared") {
            guard.preparedMayBeDurable = true;
          }
        },
      },
    );
    cursor = reconciled.progress;
    if (
      phaseIndexV3(cursor.progress.phase)
        >= phaseIndexV3("candidate_publish_prepared")
    ) guard.preparedMayBeDurable = true;
    if (reconciled.kind === "none") return cursor;
  }
}

function continuityForNext(
  context: ContinuationContext,
  phase: InstallationHandoffV3Phase,
): InstallationHandoffV3Progress["keychainContinuity"] {
  if (phase === "rolled_back") return "not_applicable";
  if (
    !context.sameProcess
    || context.keychain === null
    || context.progress.progress.keychainContinuity
      === "unavailable_after_process_restart"
  ) return "unavailable_after_process_restart";
  return phase === "verified" || phase === "committed"
    ? "verified_same_process"
    : context.progress.progress.keychainContinuity;
}

async function assertFinalV3Continuity(
  context: ContinuationContext,
): Promise<void> {
  const physical = await assertProgressAndPhysicalState(
    context.core,
    context.progress.progress,
    context.dependencies,
  );
  if (
    physical.disposition !== "predecessor_retired"
    && physical.disposition !== "committed_cleanup_pending"
    && physical.disposition !== "committed_clean"
  ) throw recoveryConflict("Final v3 continuity lacks the installed forward layout.");
  await assertPostAuthorizationState(
    context.core,
    context.progress.progress,
    context.dependencies,
  );
  if (context.keychain !== null) {
    await context.dependencies.assertKeychain(context.keychain);
  }
}

async function ensureV3StateBackup(
  core: InstallationHandoffV3Core,
  dependencies: InstallationHandoffV3DriverDependencies,
): Promise<void> {
  const stateBackup = join(core.paths.backupDirectory, "state");
  if (!await pathExists(stateBackup)) {
    await dependencies.copyTree(core.paths.stateRoot, stateBackup);
  }
  await dependencies.syncTree(stateBackup);
  const copied = await dependencies.inspectStateV3(
    stateBackup,
    join(stateBackup, basename(core.paths.controlPlanePath)),
  );
  assertStateContinuity(core.preState, copied, "schema-v3 state backup");
}

async function ensureV3BundleArchives(
  core: InstallationHandoffV3Core,
  dependencies: InstallationHandoffV3DriverDependencies,
): Promise<void> {
  await ensureExactBundleArchive(
    core.paths.predecessorApp,
    join(core.paths.backupDirectory, "predecessor.bundle"),
    core.predecessor,
    dependencies,
  );
  if (core.priorHra !== null) {
    await ensureExactBundleArchive(
      core.paths.canonicalApp,
      join(core.paths.backupDirectory, "prior-hra.bundle"),
      core.priorHra,
      dependencies,
    );
  } else if (await inspectReservedMissingPath(
    committedPriorHraTombstone(core),
    "reserved committed prior-HRA tombstone",
  ) !== "missing") {
    throw recoveryConflict(
      "No-prior handoff has a reserved committed prior-HRA tombstone.",
    );
  }
}

async function ensureExactBundleArchive(
  source: string,
  destination: string,
  expected: BundleContinuityEvidence,
  dependencies: InstallationHandoffV3DriverDependencies,
): Promise<void> {
  if (!await pathExists(destination)) {
    await dependencies.copyTree(source, destination);
  }
  await dependencies.syncTree(destination);
  const actual = await dependencies.inspectBundle(
    destination,
    expected.signature.policy,
  );
  if (!isDeepStrictEqual(actual, expected)) {
    throw recoveryConflict("A schema-v3 immutable bundle archive differs.");
  }
}

async function ensureV3CandidateStage(
  core: InstallationHandoffV3Core,
  progress: InstallationHandoffV3Progress,
  dependencies: InstallationHandoffV3DriverDependencies,
  lease: InstallationHandoffV3RenameParentLease,
  checkpoint?: InstallationHandoffV3Checkpoint,
): Promise<InstallationHandoffV3CandidateEvidence> {
  await lease.revalidate();
  let observation = await inspectInstallationHandoffV3PhysicalDisposition(
    core,
    progress,
    dependencies,
  );
  if (observation.disposition === "prestage") {
    const copyStage = candidateCopyStage(core);
    let copied = await inspectCandidateLogicalOrMissing(
      copyStage,
      core,
      dependencies,
    );
    if (copied === "invalid") {
      await removePrivateCandidateCopyStage(core, dependencies);
      copied = "missing";
    }
    if (copied === "missing") {
      try {
        await dependencies.copyTree(core.paths.candidateApp, copyStage);
      } catch (error: unknown) {
        await removePrivateCandidateCopyStage(core, dependencies);
        throw error;
      }
      await checkpoint?.("after_candidate_copy");
      await dependencies.syncTree(copyStage);
    }
    const copiedFirst = await dependencies.inspectCandidateV3(copyStage);
    assertInstallationHandoffV3CandidateLogicalEquality(
      core.candidate,
      copiedFirst,
      "candidate copy stage",
    );
    const copiedSecond = await dependencies.inspectCandidateV3(copyStage);
    if (!isDeepStrictEqual(copiedFirst, copiedSecond)) {
      throw recoveryConflict("Candidate copy stage changed across verification.");
    }
    await requireV3Quiescence(core.paths, dependencies);
    try {
      await dependencies.relocateStageForward(
        copyStage,
        core.paths.candidateStage,
        async () => {
          await checkpoint?.("before_candidate_stage_rename");
          await requireV3Quiescence(core.paths, dependencies);
          await lease.revalidate();
        },
      );
    } catch (error: unknown) {
      const [source, destination] = await Promise.all([
        inspectCandidateOrMissing(copyStage, copiedSecond, dependencies),
        inspectCandidateOrMissing(
          core.paths.candidateStage,
          copiedSecond,
          dependencies,
        ),
      ]);
      if (!(source === "missing" && destination === "exact")) throw error;
    }
    await checkpoint?.("after_candidate_stage_rename");
  }
  await lease.syncAndRevalidate();
  observation = await inspectInstallationHandoffV3PhysicalDisposition(
    core,
    progress,
    dependencies,
  );
  if (
    observation.disposition !== "prepublish_unrecorded"
    || observation.candidateStage === null
  ) throw recoveryConflict(
    "Candidate staging changed after durable parent revalidation.",
  );
  if (await inspectCandidateLogicalOrMissing(
    candidateCopyStage(core),
    core,
    dependencies,
  ) !== "missing") {
    throw recoveryConflict("Candidate copy residue remains after staging.");
  }
  const first = observation.candidateStage;
  const second = await dependencies.inspectCandidateV3(
    core.paths.candidateStage,
  );
  if (!isDeepStrictEqual(first, second)) {
    throw recoveryConflict("Staged candidate changed across its durable proof.");
  }
  assertInstallationHandoffV3CandidateLogicalEquality(
    core.candidate,
    second,
    "staged candidate",
  );
  return second;
}

async function assertPreEnrollmentState(
  paths: InstallationHandoffV3Core["paths"],
  candidate: InstallationHandoffV3CandidateEvidence,
  dependencies: InstallationHandoffV3DriverDependencies,
): Promise<void> {
  if (await dependencies.readEnrollmentSidecar(paths.controlPlanePath) !== null) {
    throw recoveryConflict("A Harness enrollment sidecar already exists.");
  }
  const actual = await dependencies.inspectCandidateV3(paths.candidateApp);
  if (!isDeepStrictEqual(actual, candidate)) {
    throw recoveryConflict("Candidate authority changed before v3 authorization.");
  }
  const custody = await dependencies.inspectEnrollmentKeychainNoUi(
    paths.candidateApp,
    candidate.custodyProbeSupervisor,
  );
  requireAbsentCustody(custody, "before schema-v3 authorization");
}

async function assertPreAuthorizationState(
  core: InstallationHandoffV3Core,
  progress: InstallationHandoffV3Progress,
  dependencies: InstallationHandoffV3DriverDependencies,
  readOnly = false,
): Promise<void> {
  if (await dependencies.readEnrollmentSidecar(core.paths.controlPlanePath) !== null) {
    throw recoveryConflict("Enrollment state appeared before its v3 authorization.");
  }
  const state = await (readOnly
    ? dependencies.inspectStateReadOnlyV3
    : dependencies.inspectStateV3)(
    core.paths.stateRoot,
    core.paths.controlPlanePath,
  );
  assertStateContinuity(core.preState, state, "preauthorization state");
  const candidatePath = progress.candidateStage === null
    ? core.paths.candidateApp
    : core.paths.candidateStage;
  await requireExactCandidateAt(core, candidatePath, progress, dependencies);
  const custody = await dependencies.inspectEnrollmentKeychainNoUi(
    candidatePath,
    core.candidate.custodyProbeSupervisor,
  );
  requireAbsentCustody(custody, "before enrollment authorization");
}

async function ensureV3AuthorizedSidecar(
  core: InstallationHandoffV3Core,
  coreEvidence: InstallationHandoffV3CoreEvidence,
  progress: InstallationHandoffV3Progress,
  dependencies: InstallationHandoffV3DriverDependencies,
): Promise<HarnessKeyEnrollmentFile> {
  const authorizationInput = v3EnrollmentAuthorizationInput(core, coreEvidence);
  let current = await dependencies.readEnrollmentSidecar(
    core.paths.controlPlanePath,
  );
  if (current === null) {
    const state = await dependencies.inspectStateV3(
      core.paths.stateRoot,
      core.paths.controlPlanePath,
    );
    assertStateContinuity(core.preState, state, "pre-sidecar state");
    await requireExactCandidateAt(
      core,
      core.paths.candidateStage,
      progress,
      dependencies,
    );
    const custody = await dependencies.inspectEnrollmentKeychainNoUi(
      core.paths.candidateStage,
      core.candidate.custodyProbeSupervisor,
    );
    requireAbsentCustody(custody, "before sidecar publication");
    current = await dependencies.writeEnrollmentSidecar(
      core.paths.controlPlanePath,
      authorizedHarnessKeyEnrollmentSidecar(
        createInstallationHandoffV3EnrollmentAuthorization(
          authorizationInput,
        ),
      ),
      null,
    );
  }
  if (
    !installationHandoffV3EnrollmentAuthorizationMatches(
      current.sidecar.authorization,
      authorizationInput,
    )
  ) throw recoveryConflict("Enrollment sidecar differs from immutable v3 authority.");
  const state = await dependencies.inspectStateWithoutEnrollmentSidecar(
    core.paths.stateRoot,
    core.paths.controlPlanePath,
  );
  assertStateContinuity(core.preState, state, "authorized-sidecar state");
  const custody = await dependencies.inspectEnrollmentKeychainNoUi(
    core.paths.candidateStage,
    core.candidate.custodyProbeSupervisor,
  );
  requireMonotoneCustody(current.sidecar, custody);
  return current;
}

async function assertPostAuthorizationState(
  core: InstallationHandoffV3Core,
  progress: InstallationHandoffV3Progress,
  dependencies: InstallationHandoffV3DriverDependencies,
): Promise<HarnessKeyEnrollmentFile> {
  if (progress.authorizedSidecar === null) {
    throw recoveryConflict("Progress lacks its initial sidecar evidence.");
  }
  const current = await dependencies.readEnrollmentSidecar(
    core.paths.controlPlanePath,
  );
  if (current === null) {
    throw recoveryConflict("The authorized enrollment sidecar is missing.");
  }
  if (!installationHandoffV3EnrollmentAuthorizationMatches(
    current.sidecar.authorization,
    v3EnrollmentAuthorizationInput(core, progress.core),
  )) throw recoveryConflict("Enrollment authority differs from immutable v3 core.");
  if (
    current.sidecar.phase === "authorized"
    && !isDeepStrictEqual(current.evidence, progress.authorizedSidecar)
  ) throw recoveryConflict("Authorized enrollment sidecar vnode changed.");
  const state = await dependencies.inspectStateWithoutEnrollmentSidecar(
    core.paths.stateRoot,
    core.paths.controlPlanePath,
  );
  assertStateContinuity(core.preState, state, "postauthorization state");
  const physical = await inspectInstallationHandoffV3PhysicalDisposition(
    core,
    progress,
    dependencies,
  );
  await assertExpectedV3Tombstones(
    core,
    progress,
    physical,
    dependencies,
  );
  const candidatePath = isPostBoundaryDisposition(physical.disposition)
    ? core.paths.canonicalApp
    : core.paths.candidateStage;
  await requireExactCandidateAt(core, candidatePath, progress, dependencies);
  const custody = await dependencies.inspectEnrollmentKeychainNoUi(
    candidatePath,
    core.candidate.custodyProbeSupervisor,
  );
  requireMonotoneCustody(current.sidecar, custody);
  return current;
}

function v3EnrollmentAuthorizationInput(
  core: InstallationHandoffV3Core,
  coreEvidence: InstallationHandoffV3CoreEvidence,
) {
  return {
    candidate: core.candidate,
    operationId: core.operationId,
    predecessorIdentity: core.predecessor.identity,
    preState: core.preState,
    priorHra: core.priorHra,
    receipt: installationHandoffV3CoreReference(coreEvidence),
  };
}

async function requireExactCandidateAt(
  core: InstallationHandoffV3Core,
  path: string,
  progress: InstallationHandoffV3Progress,
  dependencies: InstallationHandoffV3DriverDependencies,
): Promise<InstallationHandoffV3CandidateEvidence> {
  const candidate = await dependencies.inspectCandidateV3(path);
  assertInstallationHandoffV3CandidateLogicalEquality(
    core.candidate,
    candidate,
    "custody probe candidate",
  );
  if (
    path !== core.paths.candidateApp
    && progress.candidateStage !== null
    && !isDeepStrictEqual(candidate, progress.candidateStage)
  ) throw recoveryConflict("Custody probe candidate vnode authority changed.");
  return candidate;
}

function requireAbsentCustody(
  observation: InstallationHandoffV3CustodyObservation,
  label: string,
): void {
  if (observation.state !== "absent") {
    throw new InstallationHandoffV3DriverError(
      "custody_unavailable",
      `Harness custody must be absent ${label}.`,
    );
  }
}

function requireMonotoneCustody(
  sidecar: HarnessKeyEnrollmentSidecar,
  observation: InstallationHandoffV3CustodyObservation,
): void {
  if (sidecar.phase === "authorized") {
    requireAbsentCustody(observation, "while authorization is pending");
    return;
  }
  if (sidecar.phase === "prepared" && observation.state === "absent") return;
  if (
    observation.state === "present"
    && observation.strictAcl === true
    && observation.envelopeSha256 === sidecar.attempt.envelopeSha256
  ) return;
  throw new InstallationHandoffV3DriverError(
    "custody_unavailable",
    "Harness custody does not match the monotone enrollment sidecar.",
  );
}

async function rollbackInstallationHandoffV3Internal(
  core: InstallationHandoffV3Core,
  progressFileValue: InstallationHandoffV3ProgressFile,
  dependencies: InstallationHandoffV3DriverDependencies,
  keychain: KeychainEvidence | null,
  checkpoint?: InstallationHandoffV3Checkpoint,
): Promise<InstallationHandoffV3ProgressFile> {
  let progressFile = progressFileValue;
  let progress = progressFile.progress;
  if (progress.phase === "rolled_back") {
    await assertRolledBackState(core, dependencies, {
      coreEvidence: progress.core,
    });
    return progressFile;
  }
  await assertActiveRollbackKeychain(core, keychain, dependencies);
  if (
    phaseIndexV3(progress.phase)
      >= phaseIndexV3("candidate_publish_prepared")
  ) {
    throw new InstallationHandoffV3DriverError(
      "forward_recovery_required",
      "Rollback cannot cross the durable candidate publication boundary.",
    );
  }
  await assertActiveRollbackKeychain(core, keychain, dependencies);
  await removePrivateCandidateCopyStage(core, dependencies);
  await assertActiveRollbackKeychain(core, keychain, dependencies);
  const completed = await tryTerminalizeCompletedRollback(
    core,
    progressFile,
    dependencies,
    keychain,
  );
  if (completed !== null) {
    await assertActiveRollbackKeychain(core, keychain, dependencies);
    return completed;
  }
  await assertActiveRollbackKeychain(core, keychain, dependencies);
  let physical = await assertProgressAndPhysicalState(
    core,
    progress,
    dependencies,
  );
  if (
    physical.disposition !== "prestage"
    && physical.disposition !== "prepublish"
    && physical.disposition !== "prepublish_unrecorded"
  ) {
    throw new InstallationHandoffV3DriverError(
      "forward_recovery_required",
      "Rollback requires an exact prepublication physical disposition.",
    );
  }
  if (physical.disposition === "prepublish_unrecorded") {
    if (physical.candidateStage === null || progress.phase !== "bundles_archived") {
      throw recoveryConflict("Unrecorded rollback staging lacks exact evidence.");
    }
    const stageLease = await dependencies.acquireRenameParentLease(
      candidateCopyStage(core),
      core.paths.candidateStage,
    );
    try {
      await stageLease.syncAndRevalidate();
      const repeated = await inspectInstallationHandoffV3PhysicalDisposition(
        core,
        progress,
        dependencies,
      );
      if (
        repeated.disposition !== "prepublish_unrecorded"
        || repeated.candidateStage === null
        || !isDeepStrictEqual(repeated.candidateStage, physical.candidateStage)
      ) throw recoveryConflict(
        "Unrecorded candidate staging changed before its progress claim.",
      );
      await assertActiveRollbackKeychain(core, keychain, dependencies);
      progressFile = await advanceInstallationHandoffV3Progress(
        core.paths.backupDirectory,
        progressFile,
        {
          ...progress,
          candidateStage: physical.candidateStage,
          phase: "candidate_staged",
        },
        dependencies,
      );
      await stageLease.revalidate();
      await assertActiveRollbackKeychain(core, keychain, dependencies);
    } finally {
      await stageLease.release();
    }
    progress = progressFile.progress;
    physical = await assertProgressAndPhysicalState(
      core,
      progress,
      dependencies,
    );
  }

  const sidecar = await dependencies.readEnrollmentSidecar(
    core.paths.controlPlanePath,
  );
  if (sidecar !== null) {
    if (
      phaseIndexV3(progress.phase) < phaseIndexV3("enrollment_authorizing")
      || sidecar.sidecar.phase !== "authorized"
      || !installationHandoffV3EnrollmentAuthorizationMatches(
        sidecar.sidecar.authorization,
        v3EnrollmentAuthorizationInput(core, progress.core),
      )
      || (
        progress.authorizedSidecar !== null
        && !isDeepStrictEqual(
          sidecar.evidence,
          progress.authorizedSidecar,
        )
      )
    ) {
      throw new InstallationHandoffV3DriverError(
        "forward_recovery_required",
        "Rollback refuses a non-original enrollment sidecar.",
      );
    }
    const stateWithout = await dependencies.inspectStateWithoutEnrollmentSidecar(
      core.paths.stateRoot,
      core.paths.controlPlanePath,
    );
    assertStateContinuity(core.preState, stateWithout, "rollback state");
    const candidatePath = physical.disposition === "prestage"
      ? core.paths.candidateApp
      : core.paths.candidateStage;
    await requireExactCandidateAt(core, candidatePath, progress, dependencies);
    requireAbsentCustody(
      await dependencies.inspectEnrollmentKeychainNoUi(
        candidatePath,
        core.candidate.custodyProbeSupervisor,
      ),
      "during rollback",
    );
    const immediatelyBeforeRemoval = await inspectInstallationHandoffV3PhysicalDisposition(
      core,
      progress,
      dependencies,
    );
    if (!isDeepStrictEqual(immediatelyBeforeRemoval, physical)) {
      throw new InstallationHandoffV3DriverError(
        "forward_recovery_required",
        "Bundle layout changed before exact sidecar removal.",
      );
    }
    await assertActiveRollbackKeychain(core, keychain, dependencies);
    await dependencies.removeEnrollmentSidecar(
      core.paths.controlPlanePath,
      sidecar,
    );
    await assertActiveRollbackKeychain(core, keychain, dependencies);
  }
  if (await dependencies.readEnrollmentSidecar(core.paths.controlPlanePath) !== null) {
    throw new InstallationHandoffV3DriverError(
      "forward_recovery_required",
      "Enrollment sidecar removal is not exact.",
    );
  }

  const candidatePath = physical.disposition === "prestage"
    ? core.paths.candidateApp
    : core.paths.candidateStage;
  await requireExactCandidateAt(core, candidatePath, progress, dependencies);
  requireAbsentCustody(
    await dependencies.inspectEnrollmentKeychainNoUi(
      candidatePath,
      core.candidate.custodyProbeSupervisor,
    ),
    "after rollback authorization removal",
  );
  const state = await dependencies.inspectStateV3(
    core.paths.stateRoot,
    core.paths.controlPlanePath,
  );
  assertStateContinuity(core.preState, state, "rolled-back state");

  let rollbackLease: InstallationHandoffV3RenameParentLease | null = null;
  try {
    if (physical.disposition !== "prestage") {
      if (physical.candidateStage === null) {
        throw recoveryConflict("Rollback lost its exact staged-candidate evidence.");
      }
      rollbackLease = await dependencies.acquireRenameParentLease(
        core.paths.candidateStage,
        rollbackCandidateTombstone(core),
      );
      await assertActiveRollbackKeychain(core, keychain, dependencies);
      await relocateExactCandidateStage(
        core,
        physical.candidateStage,
        dependencies,
        rollbackLease,
        checkpoint,
      );
      await assertActiveRollbackKeychain(core, keychain, dependencies);
    }
    const after = await inspectInstallationHandoffV3PhysicalDisposition(
      core,
      progress,
      dependencies,
    );
    if (after.disposition !== "prestage") {
      throw new InstallationHandoffV3DriverError(
        "forward_recovery_required",
        "Rollback did not restore the exact original bundle layout.",
      );
    }
    await assertRolledBackState(core, dependencies, {
      expectedCandidate: progress.candidateStage,
    });
    await assertActiveRollbackKeychain(core, keychain, dependencies);
    await checkpoint?.("before_rollback_progress");
    await assertActiveRollbackKeychain(core, keychain, dependencies);
    const rolledBack = await advanceInstallationHandoffV3Progress(
      core.paths.backupDirectory,
      progressFile,
      {
        ...progress,
        authorizedSidecar: null,
        candidateStage: null,
        keychainContinuity: "not_applicable",
        phase: "rolled_back",
      },
      dependencies,
    );
    await rollbackLease?.revalidate();
    await assertActiveRollbackKeychain(core, keychain, dependencies);
    await assertRolledBackState(core, dependencies, {
      coreEvidence: rolledBack.progress.core,
    });
    await assertActiveRollbackKeychain(core, keychain, dependencies);
    return rolledBack;
  } finally {
    await rollbackLease?.release();
  }
}

async function tryTerminalizeCompletedRollback(
  core: InstallationHandoffV3Core,
  progressFile: InstallationHandoffV3ProgressFile,
  dependencies: InstallationHandoffV3DriverDependencies,
  keychain: KeychainEvidence | null,
): Promise<InstallationHandoffV3ProgressFile | null> {
  const progress = progressFile.progress;
  if (
    progress.phase === "rolled_back"
    || phaseIndexV3(progress.phase)
      >= phaseIndexV3("candidate_publish_prepared")
  ) return null;
  const physical = await inspectInstallationHandoffV3PhysicalDisposition(
    core,
    progress,
    dependencies,
  );
  if (physical.disposition !== "prestage") return null;
  const tombstone = await inspectRollbackCandidateTombstone(
    core,
    progress.candidateStage,
    dependencies,
  );
  if (tombstone !== "exact") return null;
  const lease = await dependencies.acquireRenameParentLease(
    core.paths.candidateStage,
    rollbackCandidateTombstone(core),
  );
  try {
    await lease.revalidate();
    const [physicalAgain, tombstoneAgain] = await Promise.all([
      inspectInstallationHandoffV3PhysicalDisposition(
        core,
        progress,
        dependencies,
      ),
      inspectRollbackCandidateTombstone(
        core,
        progress.candidateStage,
        dependencies,
      ),
    ]);
    if (
      physicalAgain.disposition !== "prestage"
      || tombstoneAgain !== "exact"
    ) throw recoveryConflict(
      "Completed rollback changed before held-parent terminalization.",
    );
    await lease.syncAndRevalidate();
    await assertActiveRollbackKeychain(core, keychain, dependencies);
    await assertRolledBackState(core, dependencies, {
      expectedCandidate: progress.candidateStage,
    });
    await assertActiveRollbackKeychain(core, keychain, dependencies);
    const terminal = await advanceInstallationHandoffV3Progress(
      core.paths.backupDirectory,
      progressFile,
      {
        ...progress,
        authorizedSidecar: null,
        candidateStage: null,
        keychainContinuity: "not_applicable",
        phase: "rolled_back",
      },
      dependencies,
    );
    await lease.revalidate();
    await assertActiveRollbackKeychain(core, keychain, dependencies);
    return terminal;
  } finally {
    await lease.release();
  }
}

async function relocateExactCandidateStage(
  core: InstallationHandoffV3Core,
  expected: InstallationHandoffV3CandidateEvidence,
  dependencies: InstallationHandoffV3DriverDependencies,
  lease: InstallationHandoffV3RenameParentLease,
  checkpoint?: InstallationHandoffV3Checkpoint,
): Promise<void> {
  const destination = rollbackCandidateTombstone(core);
  await lease.revalidate();
  const sourceState = await inspectCandidateOrMissing(
    core.paths.candidateStage,
    expected,
    dependencies,
  );
  const destinationState = await inspectCandidateOrMissing(
    destination,
    expected,
    dependencies,
  );
  if (sourceState === "exact" && destinationState === "missing") {
    await requireV3Quiescence(core.paths, dependencies);
    try {
      await dependencies.relocateStageForward(
        core.paths.candidateStage,
        destination,
        async () => {
          await checkpoint?.("before_rollback_relocation");
          await requireV3Quiescence(core.paths, dependencies);
          await lease.revalidate();
        },
      );
    } catch (error: unknown) {
      const [sourceAfter, destinationAfter] = await Promise.all([
        inspectCandidateOrMissing(
          core.paths.candidateStage,
          expected,
          dependencies,
        ),
        inspectCandidateOrMissing(destination, expected, dependencies),
      ]);
      if (!(sourceAfter === "missing" && destinationAfter === "exact")) {
        throw error;
      }
    }
  } else if (!(sourceState === "missing" && destinationState === "exact")) {
    throw recoveryConflict(
      "Rollback candidate tombstone has a conflicting layout.",
    );
  }
  await lease.syncAndRevalidate();
  if (
    await inspectCandidateOrMissing(
      core.paths.candidateStage,
      expected,
      dependencies,
    ) !== "missing"
    || await inspectCandidateOrMissing(
      destination,
      expected,
      dependencies,
    ) !== "exact"
  ) throw recoveryConflict(
    "Rollback candidate relocation changed after durable parent revalidation.",
  );
  await checkpoint?.("after_rollback_relocation_syscall");
}

async function cleanupCommittedV3Stages(
  core: InstallationHandoffV3Core,
  progress: InstallationHandoffV3Progress,
  dependencies: InstallationHandoffV3DriverDependencies,
  checkpoint?: InstallationHandoffV3Checkpoint,
): Promise<void> {
  let physical = await assertProgressAndPhysicalState(
    core,
    progress,
    dependencies,
  );
  if (core.priorHra !== null) {
    if (physical.disposition === "predecessor_retired") {
      await assertPostAuthorizationState(core, progress, dependencies);
      await relocateExactBundleStage(
        core,
        core.paths.candidateStage,
        committedPriorHraTombstone(core),
        core.priorHra,
        dependencies,
        "before_committed_prior_cleanup",
        "after_committed_prior_cleanup",
        checkpoint,
      );
      physical = await assertProgressAndPhysicalState(
        core,
        progress,
        dependencies,
      );
      await assertPostAuthorizationState(core, progress, dependencies);
    } else {
      await requireExactBundleTombstone(
        committedPriorHraTombstone(core),
        core.priorHra,
        dependencies,
      );
    }
  }
  if (
    physical.disposition === "predecessor_retired"
    || physical.disposition === "committed_cleanup_pending"
  ) {
    await assertPostAuthorizationState(core, progress, dependencies);
    await relocateExactBundleStage(
      core,
      core.paths.predecessorRetirementStage,
      committedPredecessorTombstone(core),
      core.predecessor,
      dependencies,
      "before_committed_predecessor_cleanup",
      "after_committed_predecessor_cleanup",
      checkpoint,
    );
    await assertPostAuthorizationState(core, progress, dependencies);
  } else {
    await requireExactBundleTombstone(
      committedPredecessorTombstone(core),
      core.predecessor,
      dependencies,
    );
  }
  const after = await assertProgressAndPhysicalState(
    core,
    progress,
    dependencies,
  );
  if (after.disposition !== "committed_clean") {
    throw recoveryConflict("Committed v3 staging cleanup is incomplete.");
  }
}

async function relocateExactBundleStage(
  core: InstallationHandoffV3Core,
  source: string,
  destination: string,
  expected: BundleContinuityEvidence,
  dependencies: InstallationHandoffV3DriverDependencies,
  beforePoint: InstallationHandoffV3FaultPoint,
  afterPoint: InstallationHandoffV3FaultPoint,
  checkpoint?: InstallationHandoffV3Checkpoint,
): Promise<void> {
  const lease = await dependencies.acquireRenameParentLease(source, destination);
  try {
    await lease.revalidate();
    const sourceState = await inspectBundleOrMissing(
      source,
      expected,
      dependencies,
    );
    const destinationState = await inspectBundleOrMissing(
      destination,
      expected,
      dependencies,
    );
    if (sourceState === "exact" && destinationState === "missing") {
      await requireV3Quiescence(core.paths, dependencies);
      try {
        await dependencies.relocateStageForward(
          source,
          destination,
          async () => {
            await checkpoint?.(beforePoint);
            await requireV3Quiescence(core.paths, dependencies);
            await lease.revalidate();
          },
        );
      } catch (error: unknown) {
        const [sourceAfter, destinationAfter] = await Promise.all([
          inspectBundleOrMissing(source, expected, dependencies),
          inspectBundleOrMissing(destination, expected, dependencies),
        ]);
        if (!(sourceAfter === "missing" && destinationAfter === "exact")) {
          throw error;
        }
      }
      await checkpoint?.(afterPoint);
    } else if (!(sourceState === "missing" && destinationState === "exact")) {
      throw recoveryConflict(
        "Committed staging tombstone has a conflicting layout.",
      );
    }
    await lease.syncAndRevalidate();
    await requireExactBundleTombstone(destination, expected, dependencies);
    if (await inspectBundleOrMissing(source, expected, dependencies) !== "missing") {
      throw recoveryConflict("Committed staging source remains after relocation.");
    }
    await lease.revalidate();
  } finally {
    await lease.release();
  }
}

async function requireExactBundleTombstone(
  path: string,
  expected: BundleContinuityEvidence,
  dependencies: InstallationHandoffV3DriverDependencies,
): Promise<void> {
  if (await inspectBundleOrMissing(path, expected, dependencies) !== "exact") {
    throw recoveryConflict("Committed staging tombstone is missing or changed.");
  }
}

async function inspectCandidateOrMissing(
  path: string,
  expected: InstallationHandoffV3CandidateEvidence,
  dependencies: InstallationHandoffV3DriverDependencies,
): Promise<"exact" | "missing" | "invalid"> {
  try {
    return isDeepStrictEqual(
      await dependencies.inspectCandidateV3(path),
      expected,
    ) ? "exact" : "invalid";
  } catch (error: unknown) {
    return hasCode(error, "ENOENT") ? "missing" : "invalid";
  }
}

async function inspectCandidateLogicalOrMissing(
  path: string,
  core: InstallationHandoffV3Core,
  dependencies: InstallationHandoffV3DriverDependencies,
): Promise<"exact" | "missing" | "invalid"> {
  try {
    const candidate = await dependencies.inspectCandidateV3(path);
    assertInstallationHandoffV3CandidateLogicalEquality(
      core.candidate,
      candidate,
      "candidate staging residue",
    );
    return "exact";
  } catch (error: unknown) {
    return hasCode(error, "ENOENT") ? "missing" : "invalid";
  }
}

async function removePrivateCandidateCopyStage(
  core: InstallationHandoffV3Core,
  dependencies: InstallationHandoffV3DriverDependencies,
): Promise<void> {
  const path = candidateCopyStage(core);
  if (!await pathExists(path)) return;
  const authority = await inspectProspectivePathAuthority(
    path,
    "private candidate copy residue",
  );
  const backupAuthority = await inspectProspectivePathAuthority(
    core.paths.backupDirectory,
    "v3 backup authority",
  );
  if (!authoritiesOverlap(backupAuthority, authority)) {
    throw filesystemUnsafe("Candidate copy residue escaped the private backup.");
  }
  await dependencies.removePrivateTree(path);
  await dependencies.syncTree(core.paths.backupDirectory);
  if (await pathExists(path)) {
    throw recoveryConflict("Candidate copy residue remains after bounded cleanup.");
  }
}

async function reconcilePrivateCandidateCopyResidue(
  core: InstallationHandoffV3Core,
  progress: InstallationHandoffV3Progress,
  dependencies: InstallationHandoffV3DriverDependencies,
): Promise<void> {
  if (progress.phase !== "bundles_archived") return;
  const physical = await inspectInstallationHandoffV3PhysicalDisposition(
    core,
    progress,
    dependencies,
  );
  if (physical.disposition !== "prestage") return;
  if (
    await inspectCandidateLogicalOrMissing(
      candidateCopyStage(core),
      core,
      dependencies,
    ) === "invalid"
  ) {
    await removePrivateCandidateCopyStage(core, dependencies);
  }
}

async function inspectBundleOrMissing(
  path: string,
  expected: BundleContinuityEvidence,
  dependencies: InstallationHandoffV3DriverDependencies,
): Promise<"exact" | "missing" | "invalid"> {
  try {
    return isDeepStrictEqual(
      await dependencies.inspectBundle(path, expected.signature.policy),
      expected,
    ) ? "exact" : "invalid";
  } catch (error: unknown) {
    return hasCode(error, "ENOENT") ? "missing" : "invalid";
  }
}

async function inspectRollbackCandidateTombstone(
  core: InstallationHandoffV3Core,
  expectedCandidate: InstallationHandoffV3CandidateEvidence | null,
  dependencies: InstallationHandoffV3DriverDependencies,
): Promise<"exact" | "missing" | "invalid"> {
  const path = rollbackCandidateTombstone(core);
  try {
    const candidate = await dependencies.inspectCandidateV3(path);
    assertInstallationHandoffV3CandidateLogicalEquality(
      core.candidate,
      candidate,
      "rollback candidate tombstone",
    );
    if (
      expectedCandidate !== null
      && !isDeepStrictEqual(candidate, expectedCandidate)
    ) return "invalid";
    return "exact";
  } catch (error: unknown) {
    return hasCode(error, "ENOENT") ? "missing" : "invalid";
  }
}

async function assertExpectedV3Tombstones(
  core: InstallationHandoffV3Core,
  progress: InstallationHandoffV3Progress,
  physical: InstallationHandoffV3PhysicalObservation,
  dependencies: InstallationHandoffV3DriverDependencies,
): Promise<void> {
  const [candidateCopy, rollback, prior, predecessor] = await Promise.all([
    inspectCandidateLogicalOrMissing(
      candidateCopyStage(core),
      core,
      dependencies,
    ),
    inspectRollbackCandidateTombstone(
      core,
      progress.candidateStage,
      dependencies,
    ),
    core.priorHra === null
      ? inspectReservedMissingPath(
          committedPriorHraTombstone(core),
          "reserved committed prior-HRA tombstone",
        )
      : inspectBundleOrMissing(
          committedPriorHraTombstone(core),
          core.priorHra,
          dependencies,
        ),
    inspectBundleOrMissing(
      committedPredecessorTombstone(core),
      core.predecessor,
      dependencies,
    ),
  ]);
  const candidateCopyMayExist = progress.phase === "bundles_archived"
    && physical.disposition === "prestage";
  if (
    candidateCopy === "invalid"
    || (!candidateCopyMayExist && candidateCopy !== "missing")
  ) {
    throw recoveryConflict("Unexpected candidate copy residue exists.");
  }
  if (progress.phase === "rolled_back") {
    if (
      rollback === "invalid"
      || prior !== "missing"
      || predecessor !== "missing"
    ) throw recoveryConflict("Rolled-back tombstone authority conflicts.");
    return;
  }
  if (rollback !== "missing") {
    throw recoveryConflict("Unexpected rollback tombstone authority exists.");
  }
  if (progress.phase !== "committed") {
    if (prior !== "missing" || predecessor !== "missing") {
      throw recoveryConflict("Committed tombstones exist before commitment.");
    }
    return;
  }
  const expectedPrior = core.priorHra !== null
    && (
      physical.disposition === "committed_cleanup_pending"
      || physical.disposition === "committed_clean"
    ) ? "exact" : "missing";
  const expectedPredecessor = physical.disposition === "committed_clean"
    ? "exact"
    : "missing";
  if (prior !== expectedPrior || predecessor !== expectedPredecessor) {
    throw recoveryConflict("Committed tombstones differ from physical cleanup.");
  }
}

async function inspectV3TombstoneSnapshot(
  core: InstallationHandoffV3Core,
  progress: InstallationHandoffV3Progress,
  dependencies: InstallationHandoffV3DriverDependencies,
) {
  return {
    candidateCopy: await inspectCandidateLogicalOrMissing(
      candidateCopyStage(core),
      core,
      dependencies,
    ),
    committedPredecessor: await inspectBundleOrMissing(
      committedPredecessorTombstone(core),
      core.predecessor,
      dependencies,
    ),
    committedPrior: core.priorHra === null
      ? await inspectReservedMissingPath(
          committedPriorHraTombstone(core),
          "reserved committed prior-HRA tombstone",
        )
      : await inspectBundleOrMissing(
          committedPriorHraTombstone(core),
          core.priorHra,
          dependencies,
        ),
    rollbackCandidate: await inspectRollbackCandidateTombstone(
      core,
      progress.candidateStage,
      dependencies,
    ),
  };
}

async function assertRolledBackState(
  core: InstallationHandoffV3Core,
  dependencies: InstallationHandoffV3DriverDependencies,
  options: Readonly<{
    coreEvidence?: InstallationHandoffV3CoreEvidence;
    expectedCandidate?: InstallationHandoffV3CandidateEvidence | null;
    readOnly?: boolean;
  }> = {},
): Promise<void> {
  if (await inspectCandidateLogicalOrMissing(
    candidateCopyStage(core),
    core,
    dependencies,
  ) !== "missing") {
    throw recoveryConflict("Rolled-back state retains candidate copy residue.");
  }
  const committedPrior = core.priorHra === null
    ? await inspectReservedMissingPath(
        committedPriorHraTombstone(core),
        "reserved committed prior-HRA tombstone",
      )
    : await inspectBundleOrMissing(
        committedPriorHraTombstone(core),
        core.priorHra,
        dependencies,
      );
  const committedPredecessor = await inspectBundleOrMissing(
    committedPredecessorTombstone(core),
    core.predecessor,
    dependencies,
  );
  if (committedPrior !== "missing" || committedPredecessor !== "missing") {
    throw recoveryConflict("Rolled-back state has committed cleanup tombstones.");
  }
  if (await dependencies.readEnrollmentSidecar(core.paths.controlPlanePath) !== null) {
    throw recoveryConflict("Rolled-back v3 state retains enrollment authority.");
  }
  const state = await (options.readOnly === true
    ? dependencies.inspectStateReadOnlyV3
    : dependencies.inspectStateV3)(
    core.paths.stateRoot,
    core.paths.controlPlanePath,
  );
  assertStateContinuity(core.preState, state, "rolled-back state");
  let expectedCandidate: InstallationHandoffV3CandidateEvidence | null;
  if (Object.hasOwn(options, "expectedCandidate")) {
    expectedCandidate = options.expectedCandidate ?? null;
  } else {
    if (options.coreEvidence === undefined) {
      throw recoveryConflict("Rolled-back state lacks immutable origin authority.");
    }
    expectedCandidate = (
      await readInstallationHandoffV3RollbackOrigin(
        core.paths.backupDirectory,
        options.coreEvidence,
      )
    ).candidateStage;
  }
  const rollbackCandidate = rollbackCandidateTombstone(core);
  const tombstone = await inspectRollbackCandidateTombstone(
    core,
    expectedCandidate,
    dependencies,
  );
  if (
    expectedCandidate === null
      ? tombstone !== "missing"
      : tombstone !== "exact"
  ) {
    throw recoveryConflict(
      expectedCandidate === null
        ? "Rollback without staging has an unexpected candidate tombstone."
        : "Required rollback candidate tombstone is missing or changed.",
    );
  }
  const candidatePath = expectedCandidate !== null
    ? rollbackCandidate
    : core.paths.candidateApp;
  const exactCandidate = await dependencies.inspectCandidateV3(candidatePath);
  assertInstallationHandoffV3CandidateLogicalEquality(
    core.candidate,
    exactCandidate,
    "rolled-back custody candidate",
  );
  requireAbsentCustody(
    await dependencies.inspectEnrollmentKeychainNoUi(
      candidatePath,
      core.candidate.custodyProbeSupervisor,
    ),
    "after rollback",
  );
}

function rollbackCandidateTombstone(core: InstallationHandoffV3Core): string {
  return join(core.paths.backupDirectory, "rolled-back-candidate.bundle");
}

function candidateCopyStage(core: InstallationHandoffV3Core): string {
  return join(core.paths.backupDirectory, "candidate-stage.copying.bundle");
}

function committedPriorHraTombstone(core: InstallationHandoffV3Core): string {
  return join(core.paths.backupDirectory, "committed-prior-hra.bundle");
}

function committedPredecessorTombstone(core: InstallationHandoffV3Core): string {
  return join(core.paths.backupDirectory, "committed-predecessor.bundle");
}

async function inspectReservedMissingPath(
  path: string,
  label: string,
): Promise<"missing" | "invalid"> {
  const authority = await inspectProspectivePathAuthority(path, label);
  return authority.missing.length === 1 ? "missing" : "invalid";
}

async function loadV3Operation(
  backupDirectory: string,
  dependencies: InstallationHandoffV3DriverDependencies,
  expectedPaths?: InstallationHandoffPaths,
): Promise<Readonly<{
  core: InstallationHandoffV3Core;
  coreEvidence: InstallationHandoffV3CoreEvidence;
  progress: InstallationHandoffV3ProgressFile;
}>> {
  await requirePrivateBackupDirectory(backupDirectory);
  await recoverInstallationHandoffV3CorePublication(backupDirectory);
  const read = await readInstallationHandoffV3Core(backupDirectory);
  await validateV3Paths(
    read.core.paths,
    backupDirectory,
    read.core.paths.candidateApp,
    dependencies,
  );
  if (expectedPaths !== undefined) {
    assertBasePathsMatch(read.core.paths, expectedPaths);
  }
  let progress: InstallationHandoffV3ProgressFile;
  try {
    progress = await readInstallationHandoffV3Progress(
      backupDirectory,
      read.evidence,
    );
  } catch (error: unknown) {
    if (!hasCode(error, "ENOENT")) throw error;
    progress = await createInstallationHandoffV3Progress(
      backupDirectory,
      {
        authorizedSidecar: null,
        candidateStage: null,
        core: read.evidence,
        keychainContinuity: "unavailable_after_process_restart",
        phase: "created",
        schemaVersion: 3,
      },
    );
  }
  return {
    core: read.core,
    coreEvidence: read.evidence,
    progress,
  };
}

async function validateV3Paths(
  paths: InstallationHandoffPaths,
  backupDirectory: string,
  candidateApp: string,
  dependencies: InstallationHandoffV3DriverDependencies,
): Promise<void> {
  for (const [label, value] of Object.entries({
    applicationsDirectory: paths.applicationsDirectory,
    backupDirectory,
    candidateApp: paths.candidateApp,
    canonicalApp: paths.canonicalApp,
    controlPlanePath: paths.controlPlanePath,
    nativeInstanceLockPath: paths.nativeInstanceLockPath,
    predecessorApp: paths.predecessorApp,
    stateRoot: paths.stateRoot,
    updateHazardPath: paths.updateHazardPath,
    updateHazardTemporaryPath: paths.updateHazardTemporaryPath,
  })) normalizedNonRoot(value, label);
  for (const [index, value] of paths.sparkleCacheRoots.entries()) {
    normalizedNonRoot(value, `sparkleCacheRoots[${index}]`);
  }
  if (
    paths.candidateApp !== normalizedNonRoot(candidateApp, "candidate app")
    || paths.canonicalApp !== join(paths.applicationsDirectory, "HRA.app")
    || paths.predecessorApp !== join(paths.applicationsDirectory, "OPRTE.app")
    || paths.controlPlanePath
      !== join(paths.stateRoot, "control-plane.sqlite")
  ) throw filesystemUnsafe("Schema-v3 paths differ from the fixed app layout.");
  const derived = dependencies.derivePaths(paths.candidateApp);
  assertBasePathsMatch(
    {
      ...paths,
      backupDirectory,
      candidateStage: join(paths.applicationsDirectory, ".unused-candidate.app"),
      predecessorRetirementStage: join(
        paths.applicationsDirectory,
        ".unused-predecessor.bundle",
      ),
    },
    derived,
  );
  const backupAuthority = await inspectProspectivePathAuthority(
    backupDirectory,
    "schema-v3 backup directory",
  );
  const candidateAuthority = await inspectProspectivePathAuthority(
    paths.candidateApp,
    "schema-v3 candidate app",
  );
  const protectedPaths = [
    paths.applicationsDirectory,
    paths.candidateApp,
    paths.canonicalApp,
    paths.predecessorApp,
    paths.stateRoot,
    paths.controlPlanePath,
    paths.nativeInstanceLockPath,
    paths.updateHazardPath,
    paths.updateHazardTemporaryPath,
    ...paths.sparkleCacheRoots,
  ];
  for (const protectedPath of protectedPaths) {
    const authority = await inspectProspectivePathAuthority(
      protectedPath,
      "schema-v3 protected path",
    );
    if (authoritiesOverlap(authority, backupAuthority)) {
      throw filesystemUnsafe(
        "Schema-v3 backup authority overlaps an application or state path.",
      );
    }
  }
  for (const installedPath of protectedPaths.filter(path =>
    path !== paths.candidateApp)) {
    const authority = await inspectProspectivePathAuthority(
      installedPath,
      "schema-v3 installed path",
    );
    if (authoritiesOverlap(candidateAuthority, authority)) {
      throw filesystemUnsafe(
        "Schema-v3 candidate source overlaps an installed application.",
      );
    }
  }
  const applicationsStatus = await lstat(
    paths.applicationsDirectory,
    { bigint: true },
  );
  const backupDevice = backupAuthority.existing.at(-1)?.device;
  if (
    !applicationsStatus.isDirectory()
    || backupDevice === undefined
    || applicationsStatus.dev !== backupDevice
  ) throw filesystemUnsafe(
    "Schema-v3 backup and Applications staging must share one filesystem.",
  );
}

function assertBasePathsMatch(
  actual: InstallationHandoffV3Core["paths"],
  expected: InstallationHandoffPaths,
): void {
  const projected: InstallationHandoffPaths = {
    applicationsDirectory: actual.applicationsDirectory,
    candidateApp: actual.candidateApp,
    canonicalApp: actual.canonicalApp,
    controlPlanePath: actual.controlPlanePath,
    nativeInstanceLockPath: actual.nativeInstanceLockPath,
    predecessorApp: actual.predecessorApp,
    sparkleCacheRoots: actual.sparkleCacheRoots,
    stateRoot: actual.stateRoot,
    updateHazardPath: actual.updateHazardPath,
    updateHazardTemporaryPath: actual.updateHazardTemporaryPath,
  };
  if (!isDeepStrictEqual(projected, expected)) {
    throw recoveryConflict("Recovery paths differ from immutable v3 authority.");
  }
}

async function requireMissingV3Stages(
  paths: InstallationHandoffV3Core["paths"],
): Promise<void> {
  for (const [label, path] of [
    ["candidate stage", paths.candidateStage],
    ["predecessor retirement stage", paths.predecessorRetirementStage],
  ] as const) {
    const authority = await inspectProspectivePathAuthority(path, label);
    if (authority.missing.length !== 1) {
      throw filesystemUnsafe(`Schema-v3 ${label} already exists or is unsafe.`);
    }
  }
}

async function requirePrivateBackupDirectory(path: string): Promise<string[]> {
  const status = await lstat(path, { bigint: true });
  const expectedUser = process.geteuid?.();
  if (
    expectedUser === undefined
    || !status.isDirectory()
    || status.isSymbolicLink()
    || status.uid !== BigInt(expectedUser)
    || (status.mode & 0o077n) !== 0n
    || await realpath(path) !== path
  ) throw filesystemUnsafe("Schema-v3 backup directory is not canonical and private.");
  return await readdir(path);
}

async function acquireV3OperationLocks(
  paths: InstallationHandoffV3Core["paths"],
  dependencies: InstallationHandoffV3DriverDependencies,
): Promise<OperationLocks> {
  await dependencies.quitApplications([
    paths.predecessorApp,
    paths.canonicalApp,
  ]);
  let native: HeldLock;
  try {
    native = dependencies.acquireNativeLock(paths.nativeInstanceLockPath);
  } catch (error: unknown) {
    throw new InstallationHandoffV3DriverError(
      "lock_unavailable",
      `Schema-v3 native lock is unavailable: ${errorMessage(error)}`,
    );
  }
  let controlPlane: OperationLocks["controlPlane"] | null = null;
  try {
    await dependencies.quitApplications([
      paths.predecessorApp,
      paths.canonicalApp,
    ]);
    controlPlane = dependencies.acquireControlPlaneLock(
      paths.controlPlanePath,
    );
    controlPlane.bindControlPlane();
    await requireV3Quiescence(paths, dependencies);
    return { controlPlane, native };
  } catch (error: unknown) {
    controlPlane?.release();
    native.release();
    throw error;
  }
}

function releaseV3OperationLocks(locks: OperationLocks): void {
  locks.controlPlane.release();
  locks.native.release();
}

async function requireV3Quiescence(
  paths: InstallationHandoffV3Core["paths"],
  dependencies: InstallationHandoffV3DriverDependencies,
): Promise<void> {
  if (!await dependencies.updaterIsQuiescent(paths)) {
    throw new InstallationHandoffV3DriverError(
      "updater_active",
      "An updater or installation hazard remains active.",
    );
  }
  if (!await dependencies.openFilesAreQuiescent(paths)) {
    throw new InstallationHandoffV3DriverError(
      "app_running",
      "An application still holds installed bundles or state open.",
    );
  }
}

async function assertProgressAndPhysicalState(
  core: InstallationHandoffV3Core,
  progress: InstallationHandoffV3Progress,
  dependencies: InstallationHandoffV3DriverDependencies,
): Promise<InstallationHandoffV3PhysicalObservation> {
  const physical = await inspectInstallationHandoffV3PhysicalDisposition(
    core,
    progress,
    dependencies,
  );
  await assertExpectedV3Tombstones(
    core,
    progress,
    physical,
    dependencies,
  );
  if (!installationHandoffV3ProgressAllowsDisposition(
    progress.phase,
    physical.disposition,
  )) {
    throw recoveryConflict(
      `Progress phase ${progress.phase} conflicts with physical disposition ${physical.disposition}.`,
    );
  }
  return physical;
}

async function resultFor(
  core: InstallationHandoffV3Core,
  progress: InstallationHandoffV3Progress,
  dependencies: InstallationHandoffV3DriverDependencies,
  sameProcess: boolean,
): Promise<InstallationHandoffV3Result> {
  const physical = await assertProgressAndPhysicalState(
    core,
    progress,
    dependencies,
  );
  const status = progress.phase === "committed"
    ? "committed"
    : progress.phase === "rolled_back"
      ? "rolled_back"
      : "in_progress";
  const keychainContinuity = status === "rolled_back"
    ? "not_applicable"
    : sameProcess
        && progress.keychainContinuity === "verified_same_process"
      ? "verified_same_process"
      : "unavailable_after_process_restart";
  return {
    backupDirectory: core.paths.backupDirectory,
    disposition: physical.disposition,
    keychainContinuity,
    operationId: core.operationId,
    phase: progress.phase,
    stateDigest: core.preState.tree.digest,
    status,
  };
}

function isPostBoundaryDisposition(
  disposition: InstallationHandoffV3PhysicalDisposition,
): boolean {
  return disposition === "candidate_installed"
    || disposition === "predecessor_retired"
    || disposition === "committed_cleanup_pending"
    || disposition === "committed_clean";
}

function requireExactPredecessor(actual: BundleContinuityEvidence): void {
  if (!isDeepStrictEqual(actual, {
    identity: expectedHistoricalOprtePreviewIdentity,
    signature: expectedHistoricalOprtePreviewSignature,
    tree: expectedHistoricalOprtePreviewTree,
  })) throw new InstallationHandoffV3DriverError(
    "candidate_invalid",
    "The predecessor differs from the exact historical OPRTE authority.",
  );
}

function assertV3KeychainDescriptorInventory(
  core: InstallationHandoffV3Core,
  evidence: KeychainEvidence,
): void {
  if (!isDeepStrictEqual(evidence.descriptors, core.keychainDescriptors)) {
    throw new InstallationHandoffV3DriverError(
      "continuity_failed",
      "Resumed-process Keychain descriptors differ from immutable v3 authority.",
    );
  }
}

async function assertActiveRollbackKeychain(
  core: InstallationHandoffV3Core,
  keychain: KeychainEvidence | null,
  dependencies: InstallationHandoffV3DriverDependencies,
): Promise<void> {
  if (keychain === null) {
    throw new InstallationHandoffV3DriverError(
      "continuity_failed",
      "Preboundary rollback lacks its active Keychain continuity lease.",
    );
  }
  assertV3KeychainDescriptorInventory(core, keychain);
  try {
    await dependencies.assertKeychain(keychain);
  } catch (error: unknown) {
    throw new InstallationHandoffV3DriverError(
      "continuity_failed",
      `Preboundary rollback Keychain continuity drifted: ${errorMessage(error)}`,
    );
  }
}

function requireConfirmation(actual: string, expected: string): void {
  if (actual !== expected) {
    throw new InstallationHandoffV3DriverError(
      "confirmation_invalid",
      `Confirmation must be ${expected}.`,
    );
  }
}

function normalizedNonRoot(value: string, label: string): string {
  if (
    !isAbsolute(value)
    || resolve(value) !== value
    || value === sep
    || value.includes("\0")
  ) throw filesystemUnsafe(`${label} must be absolute, normalized, and non-root.`);
  return value;
}

async function acquireExactRenameParentLease(
  source: string,
  destination: string,
): Promise<InstallationHandoffV3RenameParentLease> {
  const parentPaths = [dirname(source), dirname(destination)] as const;
  const held: Array<Readonly<{
    expected: Readonly<{ device: bigint; inode: bigint }>;
    handle: Awaited<ReturnType<typeof open>>;
    path: string;
  }>> = [];
  try {
    for (const [index, path] of parentPaths.entries()) {
      const authority = await inspectProspectivePathAuthority(
        path,
        `schema-v3 rename parent ${index + 1}`,
      );
      const expected = authority.existing.at(-1);
      if (
        authority.missing.length !== 0
        || expected === undefined
        || expected.path !== path
      ) throw filesystemUnsafe("Schema-v3 rename parent is not exact.");
      const noFollow = typeof constants.O_NOFOLLOW === "number"
        ? constants.O_NOFOLLOW
        : 0;
      const directoryOnly = typeof constants.O_DIRECTORY === "number"
        ? constants.O_DIRECTORY
        : 0;
      const closeOnExecValue: unknown = Reflect.get(constants, "O_CLOEXEC");
      const closeOnExec = typeof closeOnExecValue === "number"
        ? closeOnExecValue
        : 0;
      const handle = await open(
        path,
        constants.O_RDONLY | noFollow | directoryOnly | closeOnExec,
      );
      const opened = await handle.stat({ bigint: true });
      if (
        !opened.isDirectory()
        || opened.dev !== expected.device
        || opened.ino !== expected.inode
      ) {
        await handle.close();
        throw filesystemUnsafe("Schema-v3 rename parent changed while opening.");
      }
      held.push({ expected, handle, path });
    }
  } catch (error: unknown) {
    await Promise.all(held.map(async parent => {
      await parent.handle.close();
    }));
    throw error;
  }
  let released = false;
  const revalidate = async () => {
    if (released) throw filesystemUnsafe("Schema-v3 rename parent lease is closed.");
    for (const parent of held) {
      const [opened, published, canonical] = await Promise.all([
        parent.handle.stat({ bigint: true }),
        lstat(parent.path, { bigint: true }),
        realpath(parent.path),
      ]);
      if (
        !opened.isDirectory()
        || !published.isDirectory()
        || published.isSymbolicLink()
        || opened.dev !== parent.expected.device
        || opened.ino !== parent.expected.inode
        || published.dev !== parent.expected.device
        || published.ino !== parent.expected.inode
        || canonical !== parent.path
      ) throw filesystemUnsafe(
        "Schema-v3 held rename parent changed across revalidation.",
      );
    }
  };
  return {
    revalidate,
    async release() {
      if (released) return;
      released = true;
      await Promise.all(held.map(async parent => {
        await parent.handle.close();
      }));
    },
    async syncAndRevalidate() {
      if (released) throw filesystemUnsafe(
        "Schema-v3 rename parent lease is closed.",
      );
      for (const parent of held) await parent.handle.sync();
      await revalidate();
    },
  };
}

async function pathExists(path: string): Promise<boolean> {
  try {
    await lstat(path);
    return true;
  } catch (error: unknown) {
    if (hasCode(error, "ENOENT")) return false;
    throw error;
  }
}

function phaseIndexV3(phase: InstallationHandoffV3Phase): number {
  return [
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
  ].indexOf(phase);
}

function filesystemUnsafe(message: string): InstallationHandoffV3DriverError {
  return new InstallationHandoffV3DriverError("filesystem_unsafe", message);
}

function forwardRecoveryRequired(
  cause: unknown,
  rollback?: unknown,
): InstallationHandoffV3DriverError {
  return new InstallationHandoffV3DriverError(
    "forward_recovery_required",
    rollback === undefined
      ? `Schema-v3 handoff requires forward recovery: ${errorMessage(cause)}`
      : `Schema-v3 handoff requires forward recovery: ${errorMessage(cause)}; rollback proof failed: ${errorMessage(rollback)}`,
  );
}

function errorMessage(error: unknown): string {
  return error instanceof Error ? error.message : String(error);
}

function asError(error: unknown): Error {
  return error instanceof Error ? error : new Error(String(error));
}

export function assertInstallationHandoffV3CandidateLogicalEquality(
  expected: InstallationHandoffV3CandidateEvidence,
  actual: InstallationHandoffV3CandidateEvidence,
  label: string,
): void {
  const equal = isDeepStrictEqual(expected.bundle, actual.bundle)
    && isDeepStrictEqual(
      expected.custodyProbeSupervisor,
      actual.custodyProbeSupervisor,
    )
    && expected.manifest.bytes === actual.manifest.bytes
    && expected.manifest.commit === actual.manifest.commit
    && expected.manifest.runtimeTreeSha256 === actual.manifest.runtimeTreeSha256
    && expected.manifest.sha256 === actual.manifest.sha256;
  if (!equal) {
    throw new InstallationHandoffV3DriverError(
      "continuity_failed",
      `${label} differs from the immutable logical candidate authority.`,
    );
  }
}

export async function inspectInstallationHandoffV3PhysicalDisposition(
  core: InstallationHandoffV3Core,
  progress: InstallationHandoffV3Progress,
  dependencies: Pick<
    InstallationHandoffV3DriverDependencies,
    "inspectBundle" | "inspectCandidateV3"
  >,
): Promise<InstallationHandoffV3PhysicalObservation> {
  const [canonical, stage, predecessor, retiredPredecessor] = await Promise.all([
    inspectCanonicalLeaf(core, progress, dependencies),
    inspectCandidateStageLeaf(core, progress, dependencies),
    inspectExactBundleLeaf(
      core.paths.predecessorApp,
      core.predecessor,
      dependencies,
    ),
    inspectExactBundleLeaf(
      core.paths.predecessorRetirementStage,
      core.predecessor,
      dependencies,
    ),
  ]);
  const priorExpected = core.priorHra === null ? "missing" : "prior";
  const canonicalIsPrior = canonical.kind === priorExpected;
  const stageIsPrior = stage.kind === priorExpected;

  if (
    canonicalIsPrior
    && stage.kind === "missing"
    && predecessor.kind === "exact"
    && retiredPredecessor.kind === "missing"
  ) return { candidateStage: null, disposition: "prestage" };

  if (
    canonicalIsPrior
    && (stage.kind === "candidate" || stage.kind === "candidate_unrecorded")
    && predecessor.kind === "exact"
    && retiredPredecessor.kind === "missing"
  ) {
    return {
      candidateStage: stage.evidence,
      disposition: stage.kind === "candidate_unrecorded"
        ? "prepublish_unrecorded"
        : "prepublish",
    };
  }

  if (
    canonical.kind === "candidate"
    && stageIsPrior
    && predecessor.kind === "exact"
    && retiredPredecessor.kind === "missing"
  ) {
    return {
      candidateStage: canonical.evidence,
      disposition: "candidate_installed",
    };
  }

  if (
    canonical.kind === "candidate"
    && stageIsPrior
    && predecessor.kind === "missing"
    && retiredPredecessor.kind === "exact"
  ) {
    return {
      candidateStage: canonical.evidence,
      disposition: "predecessor_retired",
    };
  }

  if (
    canonical.kind === "candidate"
    && predecessor.kind === "missing"
    && retiredPredecessor.kind === "exact"
    && stage.kind === "missing"
  ) {
    return {
      candidateStage: canonical.evidence,
      disposition: "committed_cleanup_pending",
    };
  }

  if (
    canonical.kind === "candidate"
    && stage.kind === "missing"
    && predecessor.kind === "missing"
    && retiredPredecessor.kind === "missing"
  ) {
    return {
      candidateStage: canonical.evidence,
      disposition: "committed_clean",
    };
  }

  return { candidateStage: null, disposition: "conflict" };
}

export function installationHandoffV3ProgressAllowsDisposition(
  phase: InstallationHandoffV3Phase,
  disposition: InstallationHandoffV3PhysicalDisposition,
): boolean {
  if (disposition === "conflict") return false;
  switch (phase) {
    case "created":
    case "backed_up":
    case "smoked":
      return disposition === "prestage";
    case "bundles_archived":
      return disposition === "prestage"
        || disposition === "prepublish_unrecorded";
    case "candidate_staged":
    case "enrollment_authorizing":
    case "enrollment_authorized":
      return disposition === "prepublish";
    case "candidate_publish_prepared":
      return disposition === "prepublish"
        || disposition === "candidate_installed";
    case "candidate_installed":
      return disposition === "candidate_installed"
        || disposition === "predecessor_retired";
    case "predecessor_retired":
    case "verified":
      return disposition === "predecessor_retired";
    case "committed":
      return disposition === "predecessor_retired"
        || disposition === "committed_cleanup_pending"
        || disposition === "committed_clean";
    case "rolled_back":
      return disposition === "prestage";
  }
}

export async function publishInstallationHandoffV3CandidateForward(
  core: InstallationHandoffV3Core,
  progress: InstallationHandoffV3Progress,
  dependencies: Pick<
    InstallationHandoffV3DriverDependencies,
    | "inspectBundle"
    | "inspectCandidateV3"
    | "publishCandidateForward"
  >,
  beforeRenameForTest?: () => Promise<void> | void,
): Promise<InstallationHandoffV3PhysicalObservation> {
  if (
    progress.phase !== "candidate_publish_prepared"
    || progress.candidateStage === null
  ) throw recoveryConflict("Candidate publication lacks its durable boundary.");
  const before = await inspectInstallationHandoffV3PhysicalDisposition(
    core,
    progress,
    dependencies,
  );
  if (before.disposition !== "prepublish") {
    throw recoveryConflict("Candidate publication requires exact prepublish layout.");
  }
  const staged = await dependencies.inspectCandidateV3(core.paths.candidateStage);
  if (!isDeepStrictEqual(staged, progress.candidateStage)) {
    throw recoveryConflict("Staged candidate vnode authority changed before publication.");
  }
  assertInstallationHandoffV3CandidateLogicalEquality(
    core.candidate,
    staged,
    "staged candidate",
  );
  let renameError: unknown;
  try {
    await dependencies.publishCandidateForward(
      core.paths.candidateStage,
      core.paths.canonicalApp,
      core.priorHra !== null,
      beforeRenameForTest,
    );
  } catch (error: unknown) {
    renameError = error;
  }
  const after = await inspectInstallationHandoffV3PhysicalDisposition(
    core,
    progress,
    dependencies,
  );
  if (after.disposition !== "candidate_installed") {
    if (renameError !== undefined) throw asError(renameError);
    throw recoveryConflict(
      "Candidate publication returned without exact postpublication layout.",
    );
  }
  return after;
}

export async function retireInstallationHandoffV3PredecessorForward(
  core: InstallationHandoffV3Core,
  progress: InstallationHandoffV3Progress,
  dependencies: Pick<
    InstallationHandoffV3DriverDependencies,
    | "inspectBundle"
    | "inspectCandidateV3"
    | "retirePredecessorForward"
  >,
  beforeRenameForTest?: () => Promise<void> | void,
): Promise<InstallationHandoffV3PhysicalObservation> {
  const before = await inspectInstallationHandoffV3PhysicalDisposition(
    core,
    progress,
    dependencies,
  );
  if (before.disposition !== "candidate_installed") {
    throw recoveryConflict("Predecessor retirement requires installed candidate layout.");
  }
  let renameError: unknown;
  try {
    await dependencies.retirePredecessorForward(
      core.paths.predecessorApp,
      core.paths.predecessorRetirementStage,
      beforeRenameForTest,
    );
  } catch (error: unknown) {
    renameError = error;
  }
  const after = await inspectInstallationHandoffV3PhysicalDisposition(
    core,
    progress,
    dependencies,
  );
  if (after.disposition !== "predecessor_retired") {
    if (renameError !== undefined) throw asError(renameError);
    throw recoveryConflict(
      "Predecessor retirement returned without exact forward layout.",
    );
  }
  return after;
}

async function publishCandidateForwardOnly(
  source: string,
  destination: string,
  exchange: boolean,
  beforeRenameForTest?: () => Promise<void> | void,
): Promise<InstallationHandoffV3ForwardRenameResult> {
  const [sourceAuthority, destinationAuthority] = await Promise.all([
    inspectProspectivePathAuthority(source, "v3 candidate publication source"),
    inspectProspectivePathAuthority(
      destination,
      "v3 candidate publication destination",
    ),
  ]);
  return exchange
    ? await renameSwapForwardOnly(sourceAuthority, destinationAuthority, {
        ...(beforeRenameForTest === undefined
          ? {}
          : { beforeRenameForTest }),
      })
    : await renameExclForwardOnly(sourceAuthority, destinationAuthority, {
        ...(beforeRenameForTest === undefined
          ? {}
          : { beforeRenameForTest }),
      });
}

async function retirePredecessorForwardOnly(
  source: string,
  destination: string,
  beforeRenameForTest?: () => Promise<void> | void,
): Promise<InstallationHandoffV3ForwardRenameResult> {
  const [sourceAuthority, destinationAuthority] = await Promise.all([
    inspectProspectivePathAuthority(source, "v3 predecessor retirement source"),
    inspectProspectivePathAuthority(
      destination,
      "v3 predecessor retirement destination",
    ),
  ]);
  return await renameExclForwardOnly(sourceAuthority, destinationAuthority, {
    ...(beforeRenameForTest === undefined ? {} : { beforeRenameForTest }),
  });
}

type CandidateLeaf =
  | Readonly<{
      evidence: InstallationHandoffV3CandidateEvidence;
      kind: "candidate" | "candidate_unrecorded";
    }>
  | Readonly<{ kind: "prior" | "missing" | "invalid" }>;

type ExactBundleLeaf = Readonly<{ kind: "exact" | "missing" | "invalid" }>;

async function inspectCanonicalLeaf(
  core: InstallationHandoffV3Core,
  progress: InstallationHandoffV3Progress,
  dependencies: Pick<
    InstallationHandoffV3DriverDependencies,
    "inspectBundle" | "inspectCandidateV3"
  >,
): Promise<CandidateLeaf> {
  const candidate = await tryInspectCandidate(
    core.paths.canonicalApp,
    core,
    progress,
    dependencies,
  );
  if (candidate !== null) return candidate;
  if (core.priorHra !== null) {
    try {
      const actual = await dependencies.inspectBundle(
        core.paths.canonicalApp,
        strictBundleSignaturePolicy,
      );
      return isDeepStrictEqual(actual, core.priorHra)
        ? { kind: "prior" }
        : { kind: "invalid" };
    } catch (error: unknown) {
      if (hasCode(error, "ENOENT")) return { kind: "missing" };
      return { kind: "invalid" };
    }
  }
  return await pathMissing(core.paths.canonicalApp)
    ? { kind: "missing" }
    : { kind: "invalid" };
}

async function inspectCandidateStageLeaf(
  core: InstallationHandoffV3Core,
  progress: InstallationHandoffV3Progress,
  dependencies: Pick<
    InstallationHandoffV3DriverDependencies,
    "inspectBundle" | "inspectCandidateV3"
  >,
): Promise<CandidateLeaf> {
  const candidate = await tryInspectCandidate(
    core.paths.candidateStage,
    core,
    progress,
    dependencies,
  );
  if (candidate !== null) return candidate;
  if (core.priorHra !== null) {
    try {
      const actual = await dependencies.inspectBundle(
        core.paths.candidateStage,
        strictBundleSignaturePolicy,
      );
      return isDeepStrictEqual(actual, core.priorHra)
        ? { kind: "prior" }
        : { kind: "invalid" };
    } catch (error: unknown) {
      if (hasCode(error, "ENOENT")) return { kind: "missing" };
      return { kind: "invalid" };
    }
  }
  return await pathMissing(core.paths.candidateStage)
    ? { kind: "missing" }
    : { kind: "invalid" };
}

async function tryInspectCandidate(
  path: string,
  core: InstallationHandoffV3Core,
  progress: InstallationHandoffV3Progress,
  dependencies: Pick<
    InstallationHandoffV3DriverDependencies,
    "inspectCandidateV3"
  >,
): Promise<CandidateLeaf | null> {
  try {
    const evidence = await dependencies.inspectCandidateV3(path);
    assertInstallationHandoffV3CandidateLogicalEquality(
      core.candidate,
      evidence,
      "observed candidate",
    );
    if (progress.candidateStage === null) {
      return { evidence, kind: "candidate_unrecorded" };
    }
    return isDeepStrictEqual(evidence, progress.candidateStage)
      ? { evidence, kind: "candidate" }
      : { kind: "invalid" };
  } catch (error: unknown) {
    if (hasCode(error, "ENOENT")) return null;
    if (
      error instanceof InstallationHandoffV3DriverError
      && error.code === "continuity_failed"
    ) return null;
    return null;
  }
}

async function inspectExactBundleLeaf(
  path: string,
  expected: BundleContinuityEvidence,
  dependencies: Pick<InstallationHandoffV3DriverDependencies, "inspectBundle">,
): Promise<ExactBundleLeaf> {
  try {
    const actual = await dependencies.inspectBundle(
      path,
      expected.signature.policy,
    );
    return isDeepStrictEqual(actual, expected)
      ? { kind: "exact" }
      : { kind: "invalid" };
  } catch (error: unknown) {
    return hasCode(error, "ENOENT")
      ? { kind: "missing" }
      : { kind: "invalid" };
  }
}

async function pathMissing(path: string): Promise<boolean> {
  try {
    const authority = await inspectProspectivePathAuthority(path, "v3 observed path");
    return authority.missing.length === 1;
  } catch {
    return false;
  }
}

function recoveryConflict(message: string): InstallationHandoffV3DriverError {
  return new InstallationHandoffV3DriverError("recovery_conflict", message);
}

function hasCode(error: unknown, code: string): boolean {
  return error instanceof Error
    && "code" in error
    && (error as NodeJS.ErrnoException).code === code;
}
