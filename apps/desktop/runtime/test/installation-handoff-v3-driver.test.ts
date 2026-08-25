/* eslint-disable @typescript-eslint/await-thenable, @typescript-eslint/require-await --
 * Bun's async matchers and Promise-shaped fault dependencies are intentionally awaited.
 */
import { afterEach, describe, expect, test } from "bun:test";
import {
  chmod,
  mkdir,
  mkdtemp,
  readFile,
  realpath,
  rm,
  writeFile,
} from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";

import {
  assertInstallationHandoffV3CandidateLogicalEquality,
  cleanupCommittedInstallationHandoffV3,
  inspectInstallationHandoffV3PhysicalDisposition,
  inspectInstallationHandoffV3Status,
  installationHandoffV3CleanupConfirmation,
  installationHandoffV3Confirmation,
  installationHandoffV3ProgressAllowsDisposition,
  installationHandoffV3RollbackConfirmation,
  performInstallationHandoffV3,
  publishInstallationHandoffV3CandidateForward,
  resumeInstallationHandoffV3,
  rollbackInstallationHandoffV3,
  installationHandoffV3ResumeConfirmation,
  type InstallationHandoffV3DriverDependencies,
  type InstallationHandoffV3PhysicalDisposition,
} from "../installation-handoff-v3-driver";
import {
  expectedHistoricalOprtePreviewIdentity,
  expectedHistoricalOprtePreviewSignature,
  expectedHistoricalOprtePreviewTree,
} from "../historical-oprte-preview";
import {
  installationHandoffV3ProgressFileName,
  readInstallationHandoffV3Progress,
  type InstallationHandoffV3CandidateEvidence,
  type InstallationHandoffV3Core,
  type InstallationHandoffV3Progress,
} from "../installation-handoff-v3";
import {
  type HarnessKeyEnrollmentFile,
  type HarnessKeyEnrollmentSidecar,
} from "../src/state/harness-key-enrollment";
import { testCustodyProbeSupervisorAuthority } from
  "./fixtures/custody-probe-authority";

const roots: string[] = [];

afterEach(async () => {
  for (const root of roots.splice(0)) {
    await rm(root, { force: true, recursive: true });
  }
});

describe("schema-v3 handoff physical disposition", () => {
  test("classifies both swap and exclusive layouts from exact physical evidence", async () => {
    for (const prior of [true, false]) {
      const fixture = await dispositionFixture(prior);
      const expected = async (
        disposition: InstallationHandoffV3PhysicalDisposition,
      ) => {
        expect((await inspectInstallationHandoffV3PhysicalDisposition(
          fixture.core,
          fixture.progress,
          fixture.dependencies,
        )).disposition).toBe(disposition);
      };

      await expected("prestage");
      fixture.leaves.set(fixture.core.paths.candidateStage, "candidate");
      await expected("prepublish");

      fixture.leaves.set(fixture.core.paths.canonicalApp, "candidate");
      fixture.leaves.set(
        fixture.core.paths.candidateStage,
        prior ? "prior" : "missing",
      );
      await expected("candidate_installed");

      fixture.leaves.set(fixture.core.paths.predecessorApp, "missing");
      fixture.leaves.set(
        fixture.core.paths.predecessorRetirementStage,
        "predecessor",
      );
      await expected("predecessor_retired");

      if (prior) {
        fixture.leaves.set(fixture.core.paths.candidateStage, "missing");
        await expected("committed_cleanup_pending");
      }
      fixture.leaves.set(
        fixture.core.paths.predecessorRetirementStage,
        "missing",
      );
      await expected("committed_clean");
    }
  });

  test("derives an unrecorded staged vnode only from exact logical authority", async () => {
    const fixture = await dispositionFixture(true);
    fixture.leaves.set(fixture.core.paths.candidateStage, "candidate");
    const progress: InstallationHandoffV3Progress = {
      ...fixture.progress,
      candidateStage: null,
      phase: "bundles_archived",
    };
    const observation = await inspectInstallationHandoffV3PhysicalDisposition(
      fixture.core,
      progress,
      fixture.dependencies,
    );
    expect(observation).toEqual({
      candidateStage: fixture.stageCandidate,
      disposition: "prepublish_unrecorded",
    });

    fixture.stageCandidate.manifest.sha256 = "f".repeat(64);
    expect((await inspectInstallationHandoffV3PhysicalDisposition(
      fixture.core,
      progress,
      fixture.dependencies,
    )).disposition).toBe("conflict");
  });

  test("progress admits only crash-reachable physical dispositions", () => {
    expect(installationHandoffV3ProgressAllowsDisposition(
      "candidate_publish_prepared",
      "prepublish",
    )).toBeTrue();
    expect(installationHandoffV3ProgressAllowsDisposition(
      "candidate_publish_prepared",
      "candidate_installed",
    )).toBeTrue();
    expect(installationHandoffV3ProgressAllowsDisposition(
      "enrollment_authorized",
      "candidate_installed",
    )).toBeFalse();
    expect(installationHandoffV3ProgressAllowsDisposition(
      "candidate_installed",
      "prepublish",
    )).toBeFalse();
    expect(installationHandoffV3ProgressAllowsDisposition(
      "committed",
      "committed_clean",
    )).toBeTrue();
  });

  test("publishes only after repeated staged vnode and logical checks", async () => {
    for (const prior of [true, false]) {
      const fixture = await dispositionFixture(prior);
      fixture.leaves.set(fixture.core.paths.candidateStage, "candidate");
      const calls: string[] = [];
      const progress: InstallationHandoffV3Progress = {
        ...fixture.progress,
        authorizedSidecar: enrollmentEvidence(),
        phase: "candidate_publish_prepared",
      };
      const observation = await publishInstallationHandoffV3CandidateForward(
        fixture.core,
        progress,
        {
          ...fixture.dependencies,
          async publishCandidateForward(source, destination, exchange, before) {
            calls.push(`${source}->${destination}:${String(exchange)}`);
            await before?.();
            fixture.leaves.set(destination, "candidate");
            fixture.leaves.set(source, prior ? "prior" : "missing");
            return { status: "published" };
          },
        },
        () => {
          calls.push("before-rename");
        },
      );
      expect(observation.disposition).toBe("candidate_installed");
      expect(calls).toEqual([
        `${fixture.core.paths.candidateStage}->${fixture.core.paths.canonicalApp}:${String(prior)}`,
        "before-rename",
      ]);
    }
  });

  test("driver source cannot call a compensating publication primitive", async () => {
    const source = await readFile(
      join(import.meta.dir, "..", "installation-handoff-v3-driver.ts"),
      "utf8",
    );
    expect(source).not.toContain("renameWithPathAuthority");
    expect(source).not.toContain("publishBundle");
    expect(source).toContain("renameSwapForwardOnly");
    expect(source).toContain("renameExclForwardOnly");
    expect(source).toContain("applicationsStatus.dev !== backupDevice");
    expect(source).toContain(
      "backup and Applications staging must share one filesystem",
    );
  });

  test("logical equality ignores copied vnodes but binds package authority", () => {
    const source = candidateEvidence("1", "2", "3");
    const staged = candidateEvidence("7", "8", "3");
    expect(() => assertInstallationHandoffV3CandidateLogicalEquality(
      source,
      staged,
      "staged",
    )).not.toThrow();
    expect(() => assertInstallationHandoffV3CandidateLogicalEquality(
      source,
      {
        ...staged,
        custodyProbeSupervisor: {
          ...staged.custodyProbeSupervisor,
          sha256: "0".repeat(64),
        },
      },
      "staged",
    )).toThrow("immutable logical candidate authority");
  });
});

describe("schema-v3 handoff driver", () => {
  test("commits and cleans both swap and exclusive publication layouts", async () => {
    for (const prior of [true, false]) {
      const fixture = await flowFixture(prior);
      const result = await performInstallationHandoffV3(
        fixture.performInput,
        fixture.dependencies,
      );
      expect(result).toMatchObject({
        disposition: "committed_clean",
        keychainContinuity: "verified_same_process",
        phase: "committed",
        status: "committed",
      });
      expect(fixture.publishShapes).toEqual([prior ? "swap" : "exclusive"]);
      expect(fixture.leaves.get(fixture.paths.predecessorApp)).toBe("missing");
      expect(fixture.sidecar?.sidecar.phase).toBe("authorized");
    }
  });

  test("a durable prepared boundary fails forward and resumes with restart continuity unavailable", async () => {
    const fixture = await flowFixture(true);
    await expect(performInstallationHandoffV3(
      {
        ...fixture.performInput,
        onCheckpoint(point) {
          if (point === "after_candidate_publish_boundary") throw new Error("cut");
        },
      },
      fixture.dependencies,
    )).rejects.toMatchObject({ code: "forward_recovery_required" });
    expect((await inspectInstallationHandoffV3Status(
      { backupDirectory: fixture.backupDirectory, paths: fixture.paths },
      fixture.dependencies,
    ))).toMatchObject({
      disposition: "prepublish",
      keychainContinuity: "unavailable_after_process_restart",
      phase: "candidate_publish_prepared",
    });
    const resumed = await resumeInstallationHandoffV3(
      {
        backupDirectory: fixture.backupDirectory,
        confirmation: installationHandoffV3ResumeConfirmation,
        paths: fixture.paths,
      },
      fixture.dependencies,
    );
    expect(resumed).toMatchObject({
      disposition: "committed_clean",
      keychainContinuity: "unavailable_after_process_restart",
      phase: "committed",
    });
  });

  test("physical candidate publication dominates stale prepared progress for both syscall shapes", async () => {
    for (const prior of [true, false]) {
      const fixture = await flowFixture(prior);
      await expect(performInstallationHandoffV3(
        {
          ...fixture.performInput,
          onCheckpoint(point) {
            if (point === "after_candidate_publish_syscall") throw new Error("cut");
          },
        },
        fixture.dependencies,
      )).rejects.toMatchObject({ code: "forward_recovery_required" });
      expect((await inspectInstallationHandoffV3Status(
        { backupDirectory: fixture.backupDirectory, paths: fixture.paths },
        fixture.dependencies,
      )).disposition).toBe("candidate_installed");
      expect((await resumeInstallationHandoffV3(
        {
          backupDirectory: fixture.backupDirectory,
          confirmation: installationHandoffV3ResumeConfirmation,
          paths: fixture.paths,
        },
        fixture.dependencies,
      )).disposition).toBe("committed_clean");
      expect(fixture.publishShapes).toEqual([prior ? "swap" : "exclusive"]);
    }
  });

  test("a preboundary failure removes only exact authorization and rolls back exact staging", async () => {
    const fixture = await flowFixture(true);
    await expect(performInstallationHandoffV3(
      {
        ...fixture.performInput,
        onCheckpoint(point) {
          if (point === "after_enrollment_authorized") throw new Error("cut");
        },
      },
      fixture.dependencies,
    )).rejects.toThrow("cut");
    const status = await inspectInstallationHandoffV3Status(
      { backupDirectory: fixture.backupDirectory, paths: fixture.paths },
      fixture.dependencies,
    );
    expect(status).toMatchObject({
      disposition: "prestage",
      keychainContinuity: "not_applicable",
      phase: "rolled_back",
      status: "rolled_back",
    });
    expect(fixture.sidecar).toBeNull();
    expect(fixture.leaves.get(fixture.candidateStage)).toBe("missing");
    expect(fixture.leaves.get(join(
      fixture.backupDirectory,
      "rolled-back-candidate.bundle",
    ))).toBe("candidate");
  });

  test("automatic rollback consumes its Keychain lease around every destructive mutation", async () => {
    const beforeMutation = await flowFixture(true);
    await expect(performInstallationHandoffV3(
      {
        ...beforeMutation.performInput,
        onCheckpoint(point) {
          if (point === "after_created_progress") {
            beforeMutation.failKeychainOnNextAssertion();
            throw new Error("before rollback mutation");
          }
        },
      },
      beforeMutation.dependencies,
    )).rejects.toMatchObject({ code: "forward_recovery_required" });
    expect((await readInstallationHandoffV3Progress(
      beforeMutation.backupDirectory,
    )).progress.phase).toBe("created");

    const afterSidecarRemoval = await flowFixture(true);
    afterSidecarRemoval.failKeychainAfterSidecarRemoval();
    await expect(performInstallationHandoffV3(
      {
        ...afterSidecarRemoval.performInput,
        onCheckpoint(point) {
          if (point === "after_enrollment_authorized") {
            throw new Error("remove exact authorization");
          }
        },
      },
      afterSidecarRemoval.dependencies,
    )).rejects.toMatchObject({ code: "forward_recovery_required" });
    expect(afterSidecarRemoval.sidecar).toBeNull();
    expect((await readInstallationHandoffV3Progress(
      afterSidecarRemoval.backupDirectory,
    )).progress.phase).toBe("enrollment_authorized");
    expect(afterSidecarRemoval.leaves.get(afterSidecarRemoval.candidateStage))
      .toBe("candidate");

    const afterRelocation = await flowFixture(true);
    afterRelocation.failKeychainAfterRollbackRelocation();
    await expect(performInstallationHandoffV3(
      {
        ...afterRelocation.performInput,
        onCheckpoint(point) {
          if (point === "after_candidate_staged") {
            throw new Error("relocate staged candidate");
          }
        },
      },
      afterRelocation.dependencies,
    )).rejects.toMatchObject({ code: "forward_recovery_required" });
    expect((await readInstallationHandoffV3Progress(
      afterRelocation.backupDirectory,
    )).progress.phase).toBe("candidate_staged");
    expect(afterRelocation.leaves.get(join(
      afterRelocation.backupDirectory,
      "rolled-back-candidate.bundle",
    ))).toBe("candidate");
    expect(afterRelocation.renameParentLeases.every(lease => lease.released))
      .toBeTrue();
  });

  test("committed cleanup accepts genuine prepared and enrolled sidecar evolution", async () => {
    for (const phase of ["prepared", "enrolled"] as const) {
      const fixture = await flowFixture(true);
      await expect(performInstallationHandoffV3(
        {
          ...fixture.performInput,
          onCheckpoint(point) {
            if (point === "after_committed") throw new Error("cut");
          },
        },
        fixture.dependencies,
      )).rejects.toMatchObject({ code: "forward_recovery_required" });
      fixture.evolveEnrollment(phase);
      const result = await cleanupCommittedInstallationHandoffV3(
        {
          backupDirectory: fixture.backupDirectory,
          confirmation: installationHandoffV3CleanupConfirmation,
          paths: fixture.paths,
        },
        fixture.dependencies,
      );
      expect(result).toMatchObject({
        disposition: "committed_clean",
        keychainContinuity: "unavailable_after_process_restart",
        phase: "committed",
      });
      expect(fixture.sidecar?.sidecar.phase).toBe(phase);
    }
  });

  test("status is repeated and read-only with zero quit, lock, or publication calls", async () => {
    const fixture = await flowFixture(true);
    await performInstallationHandoffV3(
      fixture.performInput,
      fixture.dependencies,
    );
    fixture.clearEvents();
    const status = await inspectInstallationHandoffV3Status(
      { backupDirectory: fixture.backupDirectory, paths: fixture.paths },
      fixture.dependencies,
    );
    expect(status).toMatchObject({
      disposition: "committed_clean",
      phase: "committed",
      status: "committed",
    });
    expect(fixture.events).toEqual([]);
  });

  test("status reports durable prepared and committed history without promoting it", async () => {
    const prepared = await flowFixture(true);
    await expect(performInstallationHandoffV3(
      {
        ...prepared.performInput,
        onCheckpoint(point) {
          if (point === "after_candidate_publish_boundary") {
            throw new Error("prepared cut");
          }
        },
      },
      prepared.dependencies,
    )).rejects.toMatchObject({ code: "forward_recovery_required" });
    await restoreDurableNextHistory(
      prepared.backupDirectory,
      "enrollment_authorized",
    );
    const preparedCanonical = join(
      prepared.backupDirectory,
      installationHandoffV3ProgressFileName,
    );
    const preparedBefore = await readFile(preparedCanonical);
    expect((await readInstallationHandoffV3Progress(
      prepared.backupDirectory,
    )).progress.phase).toBe("enrollment_authorized");
    expect((await inspectInstallationHandoffV3Status(
      { backupDirectory: prepared.backupDirectory, paths: prepared.paths },
      prepared.dependencies,
    ))).toMatchObject({
      disposition: "prepublish",
      phase: "candidate_publish_prepared",
      status: "in_progress",
    });
    expect(await readFile(preparedCanonical)).toEqual(preparedBefore);

    const committed = await flowFixture(true);
    await expect(performInstallationHandoffV3(
      {
        ...committed.performInput,
        onCheckpoint(point) {
          if (point === "after_committed") throw new Error("committed cut");
        },
      },
      committed.dependencies,
    )).rejects.toMatchObject({ code: "forward_recovery_required" });
    await restoreDurableNextHistory(committed.backupDirectory, "verified");
    const committedCanonical = join(
      committed.backupDirectory,
      installationHandoffV3ProgressFileName,
    );
    const committedBefore = await readFile(committedCanonical);
    expect((await readInstallationHandoffV3Progress(
      committed.backupDirectory,
    )).progress.phase).toBe("verified");
    expect((await inspectInstallationHandoffV3Status(
      { backupDirectory: committed.backupDirectory, paths: committed.paths },
      committed.dependencies,
    ))).toMatchObject({
      disposition: "predecessor_retired",
      phase: "committed",
      status: "committed",
    });
    expect(await readFile(committedCanonical)).toEqual(committedBefore);
    expect((await cleanupCommittedInstallationHandoffV3(
      {
        backupDirectory: committed.backupDirectory,
        confirmation: installationHandoffV3CleanupConfirmation,
        paths: committed.paths,
      },
      committed.dependencies,
    )).disposition).toBe("committed_clean");
  });

  test("preauthorization and rolled-back status use only read-only state inspection", async () => {
    const preauthorization = await flowFixture(true);
    await expect(performInstallationHandoffV3(
      {
        ...preauthorization.performInput,
        onCheckpoint(point) {
          if (point === "after_created_progress") {
            preauthorization.failKeychainOnNextAssertion();
            throw new Error("status cut");
          }
        },
      },
      preauthorization.dependencies,
    )).rejects.toMatchObject({ code: "forward_recovery_required" });
    preauthorization.clearEvents();
    expect((await inspectInstallationHandoffV3Status(
      {
        backupDirectory: preauthorization.backupDirectory,
        paths: preauthorization.paths,
      },
      preauthorization.dependencies,
    )).phase).toBe("created");
    expect(preauthorization.events.length).toBeGreaterThan(0);
    expect(preauthorization.events.every(
      event => event === "state-read-only-inspection",
    )).toBeTrue();

    const rolledBack = await flowFixture(true);
    await expect(performInstallationHandoffV3(
      {
        ...rolledBack.performInput,
        onCheckpoint(point) {
          if (point === "after_candidate_staged") throw new Error("rollback");
        },
      },
      rolledBack.dependencies,
    )).rejects.toThrow("rollback");
    rolledBack.clearEvents();
    expect((await inspectInstallationHandoffV3Status(
      { backupDirectory: rolledBack.backupDirectory, paths: rolledBack.paths },
      rolledBack.dependencies,
    )).phase).toBe("rolled_back");
    expect(rolledBack.events.length).toBeGreaterThan(0);
    expect(rolledBack.events.every(
      event => event === "state-read-only-inspection",
    )).toBeTrue();
  });

  test("core creation rejects substituted production lock and hazard paths", async () => {
    for (const field of [
      "nativeInstanceLockPath",
      "updateHazardPath",
      "updateHazardTemporaryPath",
      "sparkleCacheRoots",
    ] as const) {
      const fixture = await flowFixture(true);
      await expect(performInstallationHandoffV3(
        fixture.performInput,
        {
          ...fixture.dependencies,
          derivePaths() {
            return {
              ...fixture.paths,
              [field]: field === "sparkleCacheRoots"
                ? [join(fixture.backupDirectory, "substituted-cache")]
                : join(fixture.backupDirectory, `substituted-${field}`),
            };
          },
        },
      )).rejects.toThrow("paths differ");
    }
  });

  test("restart binds a fresh Keychain descriptor inventory before the boundary", async () => {
    const fixture = await flowFixture(true);
    await expect(performInstallationHandoffV3(
      {
        ...fixture.performInput,
        onCheckpoint(point) {
          if (point === "after_enrollment_authorized") {
            fixture.evolveEnrollment("prepared");
            throw new Error("restart cut");
          }
        },
      },
      fixture.dependencies,
    )).rejects.toMatchObject({ code: "forward_recovery_required" });

    fixture.setCapturedDescriptors(["changed\0descriptor"]);
    await expect(resumeInstallationHandoffV3(
      {
        backupDirectory: fixture.backupDirectory,
        confirmation: installationHandoffV3ResumeConfirmation,
        paths: fixture.paths,
      },
      fixture.dependencies,
    )).rejects.toMatchObject({ code: "forward_recovery_required" });
    expect(fixture.publishShapes).toEqual([]);
  });

  test("restart retains a fresh same-process Keychain fingerprint lease", async () => {
    const fixture = await flowFixture(true);
    await expect(performInstallationHandoffV3(
      {
        ...fixture.performInput,
        onCheckpoint(point) {
          if (point === "after_enrollment_authorized") {
            fixture.evolveEnrollment("prepared");
            throw new Error("restart cut");
          }
        },
      },
      fixture.dependencies,
    )).rejects.toMatchObject({ code: "forward_recovery_required" });

    fixture.failKeychainOnNextAssertion();
    await expect(resumeInstallationHandoffV3(
      {
        backupDirectory: fixture.backupDirectory,
        confirmation: installationHandoffV3ResumeConfirmation,
        paths: fixture.paths,
      },
      fixture.dependencies,
    )).rejects.toMatchObject({ code: "forward_recovery_required" });
    expect(fixture.publishShapes).toEqual([]);
  });

  test("postboundary restart descriptor drift remains forward-only", async () => {
    const fixture = await flowFixture(true);
    await expect(performInstallationHandoffV3(
      {
        ...fixture.performInput,
        onCheckpoint(point) {
          if (point === "after_candidate_publish_boundary") {
            throw new Error("restart cut");
          }
        },
      },
      fixture.dependencies,
    )).rejects.toMatchObject({ code: "forward_recovery_required" });

    fixture.setCapturedDescriptors(["changed\0descriptor"]);
    await expect(resumeInstallationHandoffV3(
      {
        backupDirectory: fixture.backupDirectory,
        confirmation: installationHandoffV3ResumeConfirmation,
        paths: fixture.paths,
      },
      fixture.dependencies,
    )).rejects.toMatchObject({ code: "forward_recovery_required" });
    expect(fixture.publishShapes).toEqual([]);
    expect(fixture.leaves.get(fixture.paths.canonicalApp)).toBe("prior");
  });

  test("stale authorizing progress adopts exact prepared or enrolled custody", async () => {
    for (const phase of ["prepared", "enrolled"] as const) {
      const fixture = await flowFixture(true);
      await expect(performInstallationHandoffV3(
        {
          ...fixture.performInput,
          onCheckpoint(point) {
            if (point === "after_enrollment_sidecar") {
              fixture.evolveEnrollment(phase);
              throw new Error("authorization cut");
            }
          },
        },
        fixture.dependencies,
      )).rejects.toMatchObject({ code: "forward_recovery_required" });

      const resumed = await resumeInstallationHandoffV3(
        {
          backupDirectory: fixture.backupDirectory,
          confirmation: installationHandoffV3ResumeConfirmation,
          paths: fixture.paths,
        },
        fixture.dependencies,
      );
      expect(resumed).toMatchObject({
        disposition: "committed_clean",
        keychainContinuity: "unavailable_after_process_restart",
        phase: "committed",
      });
      expect(fixture.sidecar?.sidecar.phase).toBe(phase);
    }
  });

  test("an updater hazard appearing adjacent to publication prevents the rename", async () => {
    const fixture = await flowFixture(true);
    await expect(performInstallationHandoffV3(
      {
        ...fixture.performInput,
        onCheckpoint(point) {
          if (point === "before_candidate_publish_syscall") {
            fixture.setUpdaterQuiescent(false);
          }
        },
      },
      fixture.dependencies,
    )).rejects.toMatchObject({ code: "forward_recovery_required" });
    expect(fixture.leaves.get(fixture.paths.canonicalApp)).toBe("prior");
    expect((await inspectInstallationHandoffV3Status(
      { backupDirectory: fixture.backupDirectory, paths: fixture.paths },
      fixture.dependencies,
    ))).toMatchObject({
      disposition: "prepublish",
      phase: "candidate_publish_prepared",
    });
  });

  test("prepared intent rechecks live authority before its first durable history leaf", async () => {
    const fixture = await flowFixture(true);
    await expect(performInstallationHandoffV3(
      {
        ...fixture.performInput,
        onCheckpoint(point) {
          if (point === "before_candidate_publish_boundary") {
            fixture.failUpdaterAfterSuccessfulChecks(1);
          }
        },
      },
      fixture.dependencies,
    )).rejects.toMatchObject({ code: "updater_active" });
    expect((await inspectInstallationHandoffV3Status(
      { backupDirectory: fixture.backupDirectory, paths: fixture.paths },
      fixture.dependencies,
    ))).toMatchObject({
      disposition: "prestage",
      phase: "rolled_back",
      status: "rolled_back",
    });
    expect(fixture.publishShapes).toEqual([]);
  });

  test("prepared progress repeats Keychain and quiescence at its descriptor-bound swap", async () => {
    for (const kind of ["keychain", "quiescence"] as const) {
      const fixture = await flowFixture(true);
      fixture.failPreparedPreSwapProof(kind);
      await expect(performInstallationHandoffV3(
        fixture.performInput,
        fixture.dependencies,
      )).rejects.toMatchObject({ code: "forward_recovery_required" });
      expect((await inspectInstallationHandoffV3Status(
        { backupDirectory: fixture.backupDirectory, paths: fixture.paths },
        fixture.dependencies,
      ))).toMatchObject({
        disposition: "prepublish",
        phase: "candidate_publish_prepared",
      });
      expect(fixture.publishShapes).toEqual([]);
    }
  });

  test("an interrupted private candidate copy is bounded and recoverable", async () => {
    const fixture = await flowFixture(true);
    fixture.failCandidateCopyOnce();
    fixture.failPrivateRemoval(2);
    await expect(performInstallationHandoffV3(
      fixture.performInput,
      fixture.dependencies,
    )).rejects.toMatchObject({ code: "forward_recovery_required" });
    fixture.setUpdaterQuiescent(true);
    expect((await resumeInstallationHandoffV3(
      {
        backupDirectory: fixture.backupDirectory,
        confirmation: installationHandoffV3ResumeConfirmation,
        paths: fixture.paths,
      },
      fixture.dependencies,
    )).disposition).toBe("committed_clean");
  });

  test("candidate and predecessor renames recover from every syscall-side cut", async () => {
    for (const prior of [true, false]) {
      for (const point of [
        "before_candidate_publish_syscall",
        "before_predecessor_retirement_syscall",
        "after_predecessor_retirement_syscall",
      ] as const) {
        const fixture = await flowFixture(prior);
        await expect(performInstallationHandoffV3(
          {
            ...fixture.performInput,
            onCheckpoint(actual) {
              if (actual === point) throw new Error(`cut at ${point}`);
            },
          },
          fixture.dependencies,
        )).rejects.toMatchObject({ code: "forward_recovery_required" });
        expect((await resumeInstallationHandoffV3(
          {
            backupDirectory: fixture.backupDirectory,
            confirmation: installationHandoffV3ResumeConfirmation,
            paths: fixture.paths,
          },
          fixture.dependencies,
        )).disposition).toBe("committed_clean");
      }

      const candidateUnknown = await flowFixture(prior);
      candidateUnknown.failCandidatePublishAfterMutation();
      expect((await performInstallationHandoffV3(
        candidateUnknown.performInput,
        candidateUnknown.dependencies,
      )).disposition).toBe("committed_clean");

      const predecessorUnknown = await flowFixture(prior);
      predecessorUnknown.failRelocationAfterMutation(
        predecessorUnknown.predecessorRetirementStage,
      );
      expect((await performInstallationHandoffV3(
        predecessorUnknown.performInput,
        predecessorUnknown.dependencies,
      )).disposition).toBe("committed_clean");
    }
  });

  test("held parent fsync failure after mutation blocks progress until resume re-proves it", async () => {
    for (const prior of [true, false]) {
      const candidate = await flowFixture(prior);
      candidate.failCandidatePublishAfterMutation();
      await expect(performInstallationHandoffV3(
        {
          ...candidate.performInput,
          onCheckpoint(point) {
            if (point === "before_candidate_publish_syscall") {
              candidate.failNextRenameParentSync();
            }
          },
        },
        candidate.dependencies,
      )).rejects.toMatchObject({ code: "forward_recovery_required" });
      expect((await readInstallationHandoffV3Progress(
        candidate.backupDirectory,
      )).progress.phase).toBe("candidate_publish_prepared");
      const failedLease = candidate.renameParentLeases.findLast(
        lease => lease.destination === candidate.paths.canonicalApp,
      );
      expect(failedLease).toMatchObject({ released: true, syncs: 1 });
      expect(failedLease?.revalidations).toBeGreaterThanOrEqual(2);
      expect((await resumeInstallationHandoffV3(
        {
          backupDirectory: candidate.backupDirectory,
          confirmation: installationHandoffV3ResumeConfirmation,
          paths: candidate.paths,
        },
        candidate.dependencies,
      )).disposition).toBe("committed_clean");
      expect(candidate.renameParentLeases.every(lease => lease.released))
        .toBeTrue();
    }

    const predecessor = await flowFixture(true);
    predecessor.failRelocationAfterMutation(
      predecessor.predecessorRetirementStage,
    );
    await expect(performInstallationHandoffV3(
      {
        ...predecessor.performInput,
        onCheckpoint(point) {
          if (point === "before_predecessor_retirement_syscall") {
            predecessor.failNextRenameParentSync();
          }
        },
      },
      predecessor.dependencies,
    )).rejects.toMatchObject({ code: "forward_recovery_required" });
    expect((await readInstallationHandoffV3Progress(
      predecessor.backupDirectory,
    )).progress.phase).toBe("candidate_installed");
    const failedLease = predecessor.renameParentLeases.findLast(
      lease => lease.destination === predecessor.predecessorRetirementStage,
    );
    expect(failedLease).toMatchObject({ released: true, syncs: 1 });
    expect((await resumeInstallationHandoffV3(
      {
        backupDirectory: predecessor.backupDirectory,
        confirmation: installationHandoffV3ResumeConfirmation,
        paths: predecessor.paths,
      },
      predecessor.dependencies,
    )).disposition).toBe("committed_clean");
    expect(predecessor.renameParentLeases.every(lease => lease.released))
      .toBeTrue();
  });

  test("rollback relocation crash cuts reconcile the exact tombstone", async () => {
    for (const target of [
      "before_rollback_relocation",
      "after_rollback_relocation_syscall",
      "before_rollback_progress",
    ] as const) {
      const fixture = await flowFixture(true);
      let primaryCut = false;
      let relocationCut = false;
      await expect(performInstallationHandoffV3(
        {
          ...fixture.performInput,
          onCheckpoint(point) {
            if (point === "after_candidate_staged" && !primaryCut) {
              primaryCut = true;
              throw new Error("begin rollback");
            }
            if (point === target && !relocationCut) {
              relocationCut = true;
              throw new Error(`rollback cut at ${target}`);
            }
          },
        },
        fixture.dependencies,
      )).rejects.toMatchObject({ code: "forward_recovery_required" });
      expect((await rollbackInstallationHandoffV3(
        {
          backupDirectory: fixture.backupDirectory,
          confirmation: installationHandoffV3RollbackConfirmation,
          paths: fixture.paths,
        },
        fixture.dependencies,
      ))).toMatchObject({
        disposition: "prestage",
        phase: "rolled_back",
      });
    }

    const unknown = await flowFixture(true);
    unknown.failRelocationAfterMutation(join(
      unknown.backupDirectory,
      "rolled-back-candidate.bundle",
    ));
    await expect(performInstallationHandoffV3(
      {
        ...unknown.performInput,
        onCheckpoint(point) {
          if (point === "after_candidate_staged") throw new Error("rollback");
        },
      },
      unknown.dependencies,
    )).rejects.toThrow("rollback");
    expect((await inspectInstallationHandoffV3Status(
      { backupDirectory: unknown.backupDirectory, paths: unknown.paths },
      unknown.dependencies,
    ))).toMatchObject({ phase: "rolled_back", status: "rolled_back" });
  });

  test("rollback progress CAS reconciles both durable crash seams", async () => {
    for (const seam of [
      "before_publish",
      "after_swap_before_sync",
    ] as const) {
      const fixture = await flowFixture(true);
      fixture.cutProgress("rolled_back", seam);
      await expect(performInstallationHandoffV3(
        {
          ...fixture.performInput,
          onCheckpoint(point) {
            if (point === "after_candidate_staged") throw new Error("rollback");
          },
        },
        fixture.dependencies,
      )).rejects.toMatchObject({ code: "forward_recovery_required" });
      expect((await rollbackInstallationHandoffV3(
        {
          backupDirectory: fixture.backupDirectory,
          confirmation: installationHandoffV3RollbackConfirmation,
          paths: fixture.paths,
        },
        fixture.dependencies,
      ))).toMatchObject({ phase: "rolled_back", status: "rolled_back" });
    }
  });

  test("committed cleanup relocation cuts retain exact audit tombstones", async () => {
    const cases = [
      { point: "before_committed_prior_cleanup", prior: true },
      { point: "after_committed_prior_cleanup", prior: true },
      { point: "before_committed_predecessor_cleanup", prior: true },
      { point: "after_committed_predecessor_cleanup", prior: true },
      { point: "before_committed_predecessor_cleanup", prior: false },
      { point: "after_committed_predecessor_cleanup", prior: false },
    ] as const;
    for (const { point, prior } of cases) {
      const fixture = await flowFixture(prior);
      await expect(performInstallationHandoffV3(
        {
          ...fixture.performInput,
          onCheckpoint(actual) {
            if (actual === "after_committed") throw new Error("cleanup cut");
          },
        },
        fixture.dependencies,
      )).rejects.toMatchObject({ code: "forward_recovery_required" });
      await expect(cleanupCommittedInstallationHandoffV3(
        {
          backupDirectory: fixture.backupDirectory,
          confirmation: installationHandoffV3CleanupConfirmation,
          onCheckpoint(actual) {
            if (actual === point) throw new Error(`cleanup cut at ${point}`);
          },
          paths: fixture.paths,
        },
        fixture.dependencies,
      )).rejects.toThrow(`cleanup cut at ${point}`);
      expect((await cleanupCommittedInstallationHandoffV3(
        {
          backupDirectory: fixture.backupDirectory,
          confirmation: installationHandoffV3CleanupConfirmation,
          paths: fixture.paths,
        },
        fixture.dependencies,
      )).disposition).toBe("committed_clean");
    }

    for (const prior of [true, false]) {
      const fixture = await flowFixture(prior);
      await expect(performInstallationHandoffV3(
        {
          ...fixture.performInput,
          onCheckpoint(point) {
            if (point === "after_committed") throw new Error("cleanup cut");
          },
        },
        fixture.dependencies,
      )).rejects.toMatchObject({ code: "forward_recovery_required" });
      fixture.failRelocationAfterMutation(join(
        fixture.backupDirectory,
        "committed-predecessor.bundle",
      ));
      expect((await cleanupCommittedInstallationHandoffV3(
        {
          backupDirectory: fixture.backupDirectory,
          confirmation: installationHandoffV3CleanupConfirmation,
          paths: fixture.paths,
        },
        fixture.dependencies,
      )).disposition).toBe("committed_clean");
    }

    const priorUnknown = await flowFixture(true);
    await expect(performInstallationHandoffV3(
      {
        ...priorUnknown.performInput,
        onCheckpoint(point) {
          if (point === "after_committed") throw new Error("cleanup cut");
        },
      },
      priorUnknown.dependencies,
    )).rejects.toMatchObject({ code: "forward_recovery_required" });
    priorUnknown.failRelocationAfterMutation(join(
      priorUnknown.backupDirectory,
      "committed-prior-hra.bundle",
    ));
    expect((await cleanupCommittedInstallationHandoffV3(
      {
        backupDirectory: priorUnknown.backupDirectory,
        confirmation: installationHandoffV3CleanupConfirmation,
        paths: priorUnknown.paths,
      },
      priorUnknown.dependencies,
    )).disposition).toBe("committed_clean");
  });

  test("candidate staging rename cuts are exact and retryable", async () => {
    for (const point of [
      "before_candidate_stage_rename",
      "after_candidate_stage_rename",
    ] as const) {
      const fixture = await flowFixture(true);
      await expect(performInstallationHandoffV3(
        {
          ...fixture.performInput,
          onCheckpoint(actual) {
            if (actual === point) throw new Error(`stage cut at ${point}`);
          },
        },
        fixture.dependencies,
      )).rejects.toThrow(`stage cut at ${point}`);
      expect((await inspectInstallationHandoffV3Status(
        { backupDirectory: fixture.backupDirectory, paths: fixture.paths },
        fixture.dependencies,
      ))).toMatchObject({ phase: "rolled_back", status: "rolled_back" });
    }

    const unknown = await flowFixture(true);
    unknown.failRelocationAfterMutation(unknown.candidateStage);
    expect((await performInstallationHandoffV3(
      unknown.performInput,
      unknown.dependencies,
    )).disposition).toBe("committed_clean");
  });

  test("every relocation rechecks quiescence inside its forward syscall", async () => {
    const predecessor = await flowFixture(true);
    await expect(performInstallationHandoffV3(
      {
        ...predecessor.performInput,
        onCheckpoint(point) {
          if (point === "before_predecessor_retirement_syscall") {
            predecessor.failUpdaterAfterSuccessfulChecks(0);
          }
        },
      },
      predecessor.dependencies,
    )).rejects.toMatchObject({ code: "forward_recovery_required" });
    expect(predecessor.leaves.get(predecessor.paths.predecessorApp)).toBe(
      "predecessor",
    );

    const rollback = await flowFixture(true);
    await expect(performInstallationHandoffV3(
      {
        ...rollback.performInput,
        onCheckpoint(point) {
          if (point === "after_candidate_staged") throw new Error("rollback");
          if (point === "before_rollback_relocation") {
            rollback.failUpdaterAfterSuccessfulChecks(0);
          }
        },
      },
      rollback.dependencies,
    )).rejects.toMatchObject({ code: "forward_recovery_required" });
    expect((await rollbackInstallationHandoffV3(
      {
        backupDirectory: rollback.backupDirectory,
        confirmation: installationHandoffV3RollbackConfirmation,
        paths: rollback.paths,
      },
      rollback.dependencies,
    )).phase).toBe("rolled_back");

    for (const point of [
      "before_committed_prior_cleanup",
      "before_committed_predecessor_cleanup",
    ] as const) {
      const cleanup = await flowFixture(true);
      await expect(performInstallationHandoffV3(
        {
          ...cleanup.performInput,
          onCheckpoint(actual) {
            if (actual === "after_committed") throw new Error("cleanup");
          },
        },
        cleanup.dependencies,
      )).rejects.toMatchObject({ code: "forward_recovery_required" });
      await expect(cleanupCommittedInstallationHandoffV3(
        {
          backupDirectory: cleanup.backupDirectory,
          confirmation: installationHandoffV3CleanupConfirmation,
          onCheckpoint(actual) {
            if (actual === point) {
              cleanup.failUpdaterAfterSuccessfulChecks(0);
            }
          },
          paths: cleanup.paths,
        },
        cleanup.dependencies,
      )).rejects.toMatchObject({ code: "updater_active" });
    }

    const candidateStage = await flowFixture(true);
    await expect(performInstallationHandoffV3(
      {
        ...candidateStage.performInput,
        onCheckpoint(point) {
          if (point === "before_candidate_stage_rename") {
            candidateStage.failUpdaterAfterSuccessfulChecks(0);
          }
        },
      },
      candidateStage.dependencies,
    )).rejects.toMatchObject({ code: "updater_active" });
    expect(candidateStage.leaves.get(candidateStage.candidateStage)).toBe(
      "missing",
    );
  });

  test("every progress CAS crash seam either rolls back or continues forward", async () => {
    const transitions: readonly InstallationHandoffV3Progress["phase"][] = [
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
    const forward = new Set<InstallationHandoffV3Progress["phase"]>([
      "candidate_publish_prepared",
      "candidate_installed",
      "predecessor_retired",
      "verified",
      "committed",
    ]);
    for (const seam of [
      "before_publish",
      "after_swap_before_sync",
    ] as const) {
      for (const phase of transitions) {
        const fixture = await flowFixture(true);
        fixture.cutProgress(phase, seam);
        await expect(performInstallationHandoffV3(
          fixture.performInput,
          fixture.dependencies,
        )).rejects.toThrow("synthetic");
        if (!forward.has(phase)) {
          expect((await inspectInstallationHandoffV3Status(
            { backupDirectory: fixture.backupDirectory, paths: fixture.paths },
            fixture.dependencies,
          ))).toMatchObject({ phase: "rolled_back", status: "rolled_back" });
          continue;
        }
        expect((await resumeInstallationHandoffV3(
          {
            backupDirectory: fixture.backupDirectory,
            confirmation: installationHandoffV3ResumeConfirmation,
            paths: fixture.paths,
          },
          fixture.dependencies,
        )).disposition).toBe("committed_clean");
      }
    }
  }, 10_000);

  test("preboundary checkpoint cuts either retry the immutable core or restore exactly", async () => {
    const points = [
      "after_core",
      "after_created_progress",
      "after_full_backup",
      "after_candidate_smoke",
      "after_bundle_archives",
      "after_candidate_copy",
      "after_candidate_staged",
      "after_enrollment_authorizing",
      "after_enrollment_sidecar",
      "after_enrollment_authorized",
    ] as const;
    for (const point of points) {
      const fixture = await flowFixture(true);
      await expect(performInstallationHandoffV3(
        {
          ...fixture.performInput,
          onCheckpoint(actual) {
            if (actual === point) throw new Error(`cut at ${point}`);
          },
        },
        fixture.dependencies,
      )).rejects.toThrow(`cut at ${point}`);
      if (point === "after_core") {
        expect((await resumeInstallationHandoffV3(
          {
            backupDirectory: fixture.backupDirectory,
            confirmation: installationHandoffV3ResumeConfirmation,
            paths: fixture.paths,
          },
          fixture.dependencies,
        )).disposition).toBe("committed_clean");
      } else {
        expect((await inspectInstallationHandoffV3Status(
          { backupDirectory: fixture.backupDirectory, paths: fixture.paths },
          fixture.dependencies,
        ))).toMatchObject({ phase: "rolled_back", status: "rolled_back" });
      }
    }
  });

  test("postboundary checkpoint cuts remain forward-only in both layouts", async () => {
    const points = [
      "after_candidate_publish_boundary",
      "after_candidate_publish_syscall",
      "after_candidate_installed",
      "after_predecessor_retirement_syscall",
      "after_predecessor_retired",
      "after_verified",
      "after_committed",
    ] as const;
    for (const prior of [true, false]) {
      for (const point of points) {
        const fixture = await flowFixture(prior);
        await expect(performInstallationHandoffV3(
          {
            ...fixture.performInput,
            onCheckpoint(actual) {
              if (actual === point) throw new Error(`cut at ${point}`);
            },
          },
          fixture.dependencies,
        )).rejects.toMatchObject({ code: "forward_recovery_required" });
        expect((await resumeInstallationHandoffV3(
          {
            backupDirectory: fixture.backupDirectory,
            confirmation: installationHandoffV3ResumeConfirmation,
            paths: fixture.paths,
          },
          fixture.dependencies,
        )).disposition).toBe("committed_clean");
      }
    }
  }, 10_000);

  test("status rejects missing and conflicting transaction tombstones", async () => {
    const missingPredecessor = await flowFixture(true);
    await performInstallationHandoffV3(
      missingPredecessor.performInput,
      missingPredecessor.dependencies,
    );
    missingPredecessor.leaves.set(join(
      missingPredecessor.backupDirectory,
      "committed-predecessor.bundle",
    ), "missing");
    await expect(inspectInstallationHandoffV3Status(
      {
        backupDirectory: missingPredecessor.backupDirectory,
        paths: missingPredecessor.paths,
      },
      missingPredecessor.dependencies,
    )).rejects.toThrow("tombstone");

    const missingRollback = await flowFixture(true);
    await expect(performInstallationHandoffV3(
      {
        ...missingRollback.performInput,
        onCheckpoint(point) {
          if (point === "after_candidate_staged") throw new Error("rollback");
        },
      },
      missingRollback.dependencies,
    )).rejects.toThrow("rollback");
    missingRollback.leaves.set(join(
      missingRollback.backupDirectory,
      "rolled-back-candidate.bundle",
    ), "missing");
    await expect(inspectInstallationHandoffV3Status(
      {
        backupDirectory: missingRollback.backupDirectory,
        paths: missingRollback.paths,
      },
      missingRollback.dependencies,
    )).rejects.toThrow("Required rollback candidate tombstone");

    const missingPrior = await flowFixture(true);
    await performInstallationHandoffV3(
      missingPrior.performInput,
      missingPrior.dependencies,
    );
    missingPrior.leaves.set(join(
      missingPrior.backupDirectory,
      "committed-prior-hra.bundle",
    ), "missing");
    await expect(inspectInstallationHandoffV3Status(
      { backupDirectory: missingPrior.backupDirectory, paths: missingPrior.paths },
      missingPrior.dependencies,
    )).rejects.toThrow("tombstone");

    const conflictingRollback = await flowFixture(true);
    await expect(performInstallationHandoffV3(
      {
        ...conflictingRollback.performInput,
        onCheckpoint(point) {
          if (point === "after_candidate_staged") throw new Error("rollback");
        },
      },
      conflictingRollback.dependencies,
    )).rejects.toThrow("rollback");
    conflictingRollback.leaves.set(join(
      conflictingRollback.backupDirectory,
      "rolled-back-candidate.bundle",
    ), "invalid");
    await expect(inspectInstallationHandoffV3Status(
      {
        backupDirectory: conflictingRollback.backupDirectory,
        paths: conflictingRollback.paths,
      },
      conflictingRollback.dependencies,
    )).rejects.toThrow("tombstone");
  });

  test("no-prior states prove the reserved prior tombstone is absent", async () => {
    const precommit = await flowFixture(false);
    await expect(performInstallationHandoffV3(
      {
        ...precommit.performInput,
        onCheckpoint(point) {
          if (point === "after_created_progress") {
            precommit.failKeychainOnNextAssertion();
            throw new Error("precommit cut");
          }
        },
      },
      precommit.dependencies,
    )).rejects.toMatchObject({ code: "forward_recovery_required" });
    await mkdir(join(
      precommit.backupDirectory,
      "committed-prior-hra.bundle",
    ), { mode: 0o700 });
    await expect(inspectInstallationHandoffV3Status(
      { backupDirectory: precommit.backupDirectory, paths: precommit.paths },
      precommit.dependencies,
    )).rejects.toThrow("tombstone");

    const rolledBack = await flowFixture(false);
    await expect(performInstallationHandoffV3(
      {
        ...rolledBack.performInput,
        onCheckpoint(point) {
          if (point === "after_candidate_staged") throw new Error("rollback");
        },
      },
      rolledBack.dependencies,
    )).rejects.toThrow("rollback");
    await mkdir(join(
      rolledBack.backupDirectory,
      "committed-prior-hra.bundle",
    ), { mode: 0o700 });
    await expect(inspectInstallationHandoffV3Status(
      { backupDirectory: rolledBack.backupDirectory, paths: rolledBack.paths },
      rolledBack.dependencies,
    )).rejects.toThrow("tombstone");

    const committed = await flowFixture(false);
    await performInstallationHandoffV3(
      committed.performInput,
      committed.dependencies,
    );
    await mkdir(join(
      committed.backupDirectory,
      "committed-prior-hra.bundle",
    ), { mode: 0o700 });
    await expect(inspectInstallationHandoffV3Status(
      { backupDirectory: committed.backupDirectory, paths: committed.paths },
      committed.dependencies,
    )).rejects.toThrow("tombstone");
  });
});

async function restoreDurableNextHistory(
  backupDirectory: string,
  previousPhase: InstallationHandoffV3Progress["phase"],
): Promise<void> {
  const canonicalPath = join(
    backupDirectory,
    installationHandoffV3ProgressFileName,
  );
  const historyPath = join(
    backupDirectory,
    `handoff-progress-v3.history.${previousPhase}.json`,
  );
  const [next, previous] = await Promise.all([
    readFile(canonicalPath),
    readFile(historyPath),
  ]);
  await writeFile(canonicalPath, previous, { mode: 0o600 });
  await writeFile(historyPath, next, { mode: 0o600 });
}

async function flowFixture(prior: boolean) {
  const root = await realpath(await mkdtemp(join(tmpdir(), "hra-v3-flow-")));
  roots.push(root);
  await chmod(root, 0o700);
  const applicationsDirectory = join(root, "Applications");
  const stateRoot = join(root, "state");
  const candidateApp = join(root, "source", "HRA.app");
  await mkdir(applicationsDirectory, { mode: 0o700 });
  await mkdir(stateRoot, { mode: 0o700 });
  await mkdir(candidateApp, { mode: 0o700, recursive: true });
  const backupDirectory = join(root, "backup");
  const operationId = `handoff_${"ab".repeat(12)}`;
  const candidateStage = join(
    applicationsDirectory,
    `.${operationId}.candidate.app`,
  );
  const predecessorRetirementStage = join(
    applicationsDirectory,
    `.${operationId}.predecessor.bundle`,
  );
  const paths = {
    applicationsDirectory,
    candidateApp,
    canonicalApp: join(applicationsDirectory, "HRA.app"),
    controlPlanePath: join(stateRoot, "control-plane.sqlite"),
    nativeInstanceLockPath: join(stateRoot, ".native.lock"),
    predecessorApp: join(applicationsDirectory, "OPRTE.app"),
    sparkleCacheRoots: [join(root, "Sparkle")],
    stateRoot,
    updateHazardPath: join(stateRoot, "hazard"),
    updateHazardTemporaryPath: join(stateRoot, ".hazard.tmp"),
  };
  await mkdir(paths.predecessorApp, { mode: 0o700 });
  if (prior) await mkdir(paths.canonicalApp, { mode: 0o700 });
  const sourceCandidate = candidateEvidence("1", "2", "3");
  const stageCandidate = candidateEvidence("7", "8", "3");
  const predecessor = {
    identity: expectedHistoricalOprtePreviewIdentity,
    signature: expectedHistoricalOprtePreviewSignature,
    tree: expectedHistoricalOprtePreviewTree,
  };
  const priorHra = prior ? {
    identity: {
      build: "15",
      bundleIdentifier: "kitchen.hraness",
      executable: "hra",
      version: "0.1.14",
    },
    signature: { policy: "strict" as const },
    tree: treeEvidence("4"),
  } : null;
  const leaves = new Map<string, FlowLeafKind>([
    [candidateApp, "source_candidate"],
    [candidateStage, "missing"],
    [paths.canonicalApp, prior ? "prior" : "missing"],
    [paths.predecessorApp, "predecessor"],
    [predecessorRetirementStage, "missing"],
  ]);
  const preState = stateEvidence();
  let sidecar: HarnessKeyEnrollmentFile | null = null;
  let custody:
    | { state: "absent" }
    | { envelopeSha256: string; state: "present"; strictAcl: true } = {
      state: "absent",
    };
  let enrollmentInode = 20;
  const publishShapes: string[] = [];
  const events: string[] = [];
  let capturedDescriptors: readonly string[] = ["name\0service"];
  let failKeychainAssertion: number | null = null;
  let keychainAssertions = 0;
  let failKeychainAfterSidecarRemoval = false;
  let failKeychainAfterRollbackRelocation = false;
  let updaterQuiescent = true;
  let updaterSuccessesBeforeFailure: number | null = null;
  let failCandidateCopyOnce = false;
  let privateRemovalFailures = 0;
  let candidatePublishFault: "after" | null = null;
  let preparedPreSwapFailure: "keychain" | "quiescence" | null = null;
  let renameParentSyncFailures = 0;
  const renameParentLeases: Array<{
    destination: string;
    released: boolean;
    revalidations: number;
    source: string;
    syncs: number;
  }> = [];
  let relocateFault:
    | Readonly<{ destination: string; seam: "after" }>
    | null = null;
  let progressCut:
    | Readonly<{
        phase: InstallationHandoffV3Progress["phase"];
        seam: "before_publish" | "after_swap_before_sync";
      }>
    | null = null;

  const nextEnrollmentEvidence = () => ({
    bytes: 500,
    device: "1",
    inode: String(enrollmentInode++),
    sha256: String(enrollmentInode % 10).repeat(64),
  });
  const moveLeaf = async (
    source: string,
    destination: string,
    before?: () => Promise<void> | void,
  ) => {
    await before?.();
    events.push(`relocate:${source}->${destination}`);
    const leaf = leaves.get(source) ?? "missing";
    if (leaf === "missing" || (leaves.get(destination) ?? "missing") !== "missing") {
      throw new Error("conflicting synthetic rename");
    }
    leaves.set(destination, leaf);
    leaves.set(source, "missing");
    if (
      failKeychainAfterRollbackRelocation
      && destination === join(
        backupDirectory,
        "rolled-back-candidate.bundle",
      )
    ) {
      failKeychainAfterRollbackRelocation = false;
      failKeychainAssertion = keychainAssertions + 1;
    }
    if (
      relocateFault?.destination === destination
      && relocateFault.seam === "after"
    ) {
      relocateFault = null;
      throw new Error("synthetic unknown relocation result");
    }
    return { status: "published" as const };
  };
  const dependencies: InstallationHandoffV3DriverDependencies = {
    acquireControlPlaneLock(controlPlanePath) {
      events.push("control-lock");
      return {
        path: `${controlPlanePath}.handoff.lock`,
        bindControlPlane() {
          events.push("control-bind");
          return {
            controlPlane: { device: "1", inode: "2" },
            controlPlanePath,
            stateRoot: { device: "1", inode: "1" },
          };
        },
        release() {},
      };
    },
    acquireNativeLock() {
      events.push("native-lock");
      return { release() {} };
    },
    async assertKeychain() {
      keychainAssertions += 1;
      if (failKeychainAssertion === keychainAssertions) {
        failKeychainAssertion = null;
        throw new Error("synthetic Keychain fingerprint drift");
      }
    },
    async captureKeychain() {
      return {
        descriptors: capturedDescriptors,
        fingerprints: new Map([["name\0service", Buffer.alloc(32, 1)]]),
        key: Buffer.alloc(32, 2),
      };
    },
    async copyTree(source, destination) {
      if (source === stateRoot) {
        await mkdir(destination, { mode: 0o700, recursive: true });
        return;
      }
      const leaf = leaves.get(source);
      if (leaf === undefined || leaf === "missing") throw new Error("copy source missing");
      if (destination.startsWith(`${backupDirectory}/`)) {
        await mkdir(destination, { mode: 0o700, recursive: true });
      }
      if (
        failCandidateCopyOnce
        && destination === join(
          backupDirectory,
          "candidate-stage.copying.bundle",
        )
      ) {
        failCandidateCopyOnce = false;
        leaves.set(destination, "invalid");
        throw new Error("synthetic interrupted candidate copy");
      }
      leaves.set(
        destination,
        leaf === "source_candidate" ? "candidate" : leaf,
      );
    },
    derivePaths() {
      return paths;
    },
    eraseKeychain() {},
    async inspectBundle(path) {
      const leaf = leaves.get(path);
      if (leaf === "predecessor") return predecessor;
      if (leaf === "prior" && priorHra !== null) return priorHra;
      throw leaf === "missing" || leaf === undefined
        ? enoent()
        : new Error("not a matching bundle");
    },
    async inspectCandidateV3(path) {
      const leaf = leaves.get(path);
      if (leaf === "source_candidate") return sourceCandidate;
      if (leaf === "candidate") return stageCandidate;
      throw leaf === "missing" || leaf === undefined
        ? enoent()
        : new Error("not a candidate");
    },
    async inspectEnrollmentKeychainNoUi(path) {
      const leaf = leaves.get(path);
      if (leaf !== "source_candidate" && leaf !== "candidate") {
        throw new Error("custody probe candidate is not exact");
      }
      return custody;
    },
    async inspectStateV3() {
      events.push("state-mutating-inspection");
      return preState;
    },
    async inspectStateReadOnlyV3() {
      events.push("state-read-only-inspection");
      return preState;
    },
    async inspectStateWithoutEnrollmentSidecar() {
      return preState;
    },
    async keychainRead() {
      return null;
    },
    now: () => 1,
    async openFilesAreQuiescent() {
      return true;
    },
    async publishBundle() {
      throw new Error("compensating publication is forbidden");
    },
    async publishCandidateForward(source, destination, exchange, before) {
      events.push("publish-candidate");
      publishShapes.push(exchange ? "swap" : "exclusive");
      await before?.();
      if (leaves.get(source) !== "candidate") throw new Error("candidate missing");
      if (exchange) {
        if (leaves.get(destination) !== "prior") throw new Error("prior missing");
        leaves.set(source, "prior");
      } else {
        if (leaves.get(destination) !== "missing") throw new Error("destination exists");
        leaves.set(source, "missing");
      }
      leaves.set(destination, "candidate");
      if (candidatePublishFault === "after") {
        candidatePublishFault = null;
        throw new Error("synthetic unknown candidate publication result");
      }
      return { status: "published" };
    },
    async quitApplications() {
      events.push("quit-applications");
    },
    randomBytes(length) {
      return new Uint8Array(length).fill(0xab);
    },
    async readEnrollmentSidecar() {
      return sidecar;
    },
    async relocateStageForward(source, destination, before) {
      return await moveLeaf(source, destination, before);
    },
    async removePrivateTree(path) {
      events.push("remove-private-tree");
      if (privateRemovalFailures > 0) {
        privateRemovalFailures -= 1;
        throw new Error("synthetic interrupted private residue cleanup");
      }
      leaves.set(path, "missing");
      await rm(path, { force: false, recursive: true });
    },
    async removeEnrollmentSidecar(_path, expected) {
      events.push("remove-sidecar");
      if (sidecar === null || sidecar.evidence.inode !== expected.evidence.inode) {
        throw new Error("sidecar changed");
      }
      sidecar = null;
      if (failKeychainAfterSidecarRemoval) {
        failKeychainAfterSidecarRemoval = false;
        failKeychainAssertion = keychainAssertions + 1;
      }
    },
    async retirePredecessorForward(source, destination, before) {
      return await moveLeaf(source, destination, before);
    },
    async smokeCandidate(path) {
      if (leaves.get(path) !== "source_candidate") throw new Error("smoke source changed");
    },
    async syncTree() {},
    async acquireRenameParentLease(source, destination) {
      events.push("acquire-rename-parent-lease");
      const evidence = {
        destination,
        released: false,
        revalidations: 0,
        source,
        syncs: 0,
      };
      renameParentLeases.push(evidence);
      return {
        async revalidate() {
          if (evidence.released) throw new Error("lease already released");
          evidence.revalidations += 1;
        },
        async release() {
          evidence.released = true;
        },
        async syncAndRevalidate() {
          if (evidence.released) throw new Error("lease already released");
          evidence.syncs += 1;
          if (renameParentSyncFailures > 0) {
            renameParentSyncFailures -= 1;
            throw new Error("synthetic held-parent fsync failure");
          }
          evidence.revalidations += 1;
          events.push("sync-rename-parents");
        },
      };
    },
    async updaterIsQuiescent() {
      if (updaterSuccessesBeforeFailure !== null) {
        if (updaterSuccessesBeforeFailure === 0) {
          updaterSuccessesBeforeFailure = null;
          return false;
        }
        updaterSuccessesBeforeFailure -= 1;
      }
      return updaterQuiescent;
    },
    async verifyCandidate() {
      return { commit: "5".repeat(40) };
    },
    async writeEnrollmentSidecar(_path, value, expected) {
      events.push("write-sidecar");
      if (expected !== sidecar) throw new Error("sidecar CAS changed");
      sidecar = {
        evidence: nextEnrollmentEvidence(),
        sidecar: value,
      };
      return sidecar;
    },
    async beforeProgressPublishForTest(next) {
      if (
        next.phase === "candidate_publish_prepared"
        && preparedPreSwapFailure !== null
      ) {
        if (preparedPreSwapFailure === "keychain") {
          failKeychainAssertion = keychainAssertions + 1;
        } else {
          updaterSuccessesBeforeFailure = 0;
        }
        preparedPreSwapFailure = null;
      }
      if (
        progressCut?.phase === next.phase
        && progressCut.seam === "before_publish"
      ) {
        progressCut = null;
        throw new Error(`synthetic pre-swap progress cut at ${next.phase}`);
      }
    },
    async afterProgressSwapBeforeSyncForTest(next) {
      if (
        progressCut?.phase === next.phase
        && progressCut.seam === "after_swap_before_sync"
      ) {
        progressCut = null;
        throw new Error(`synthetic post-swap progress cut at ${next.phase}`);
      }
    },
  };
  const performInput = {
    backupDirectory,
    candidateApp,
    confirmation: installationHandoffV3Confirmation,
    paths,
  };
  return {
    backupDirectory,
    candidateStage,
    clearEvents() {
      events.length = 0;
    },
    dependencies,
    evolveEnrollment(phase: "prepared" | "enrolled") {
      if (sidecar === null) throw new Error("sidecar missing");
      const envelopeSha256 = "d".repeat(64);
      const current = sidecar.sidecar;
      const next: HarnessKeyEnrollmentSidecar = {
        attempt: { envelopeSha256, nonce: "e".repeat(64) },
        authorization: current.authorization,
        descriptor: current.descriptor,
        expectedKeychainState: current.expectedKeychainState,
        kind: current.kind,
        phase,
        schemaVersion: current.schemaVersion,
      };
      sidecar = { evidence: nextEnrollmentEvidence(), sidecar: next };
      custody = phase === "prepared"
        ? { state: "absent" }
        : { envelopeSha256, state: "present", strictAcl: true };
    },
    events,
    leaves,
    paths,
    performInput,
    predecessorRetirementStage,
    publishShapes,
    renameParentLeases,
    failCandidateCopyOnce() {
      failCandidateCopyOnce = true;
    },
    failPrivateRemoval(times = 1) {
      privateRemovalFailures = times;
    },
    failCandidatePublishAfterMutation() {
      candidatePublishFault = "after";
    },
    failRelocationAfterMutation(destination: string) {
      relocateFault = { destination, seam: "after" };
    },
    failNextRenameParentSync() {
      renameParentSyncFailures += 1;
    },
    failPreparedPreSwapProof(kind: "keychain" | "quiescence") {
      preparedPreSwapFailure = kind;
    },
    failKeychainAfterSidecarRemoval() {
      failKeychainAfterSidecarRemoval = true;
    },
    failKeychainAfterRollbackRelocation() {
      failKeychainAfterRollbackRelocation = true;
    },
    cutProgress(
      phase: InstallationHandoffV3Progress["phase"],
      seam: "before_publish" | "after_swap_before_sync",
    ) {
      progressCut = { phase, seam };
    },
    setUpdaterQuiescent(value: boolean) {
      updaterQuiescent = value;
    },
    failUpdaterAfterSuccessfulChecks(count: number) {
      updaterSuccessesBeforeFailure = count;
    },
    setCapturedDescriptors(value: readonly string[]) {
      capturedDescriptors = value;
    },
    failKeychainOnNextAssertion() {
      failKeychainAssertion = keychainAssertions + 1;
    },
    get sidecar() {
      return sidecar;
    },
  };
}

type FlowLeafKind =
  | "candidate"
  | "invalid"
  | "source_candidate"
  | "prior"
  | "predecessor"
  | "missing";

async function dispositionFixture(prior: boolean) {
  const root = await realpath(await mkdtemp(join(tmpdir(), "hra-v3-layout-")));
  roots.push(root);
  await chmod(root, 0o700);
  await mkdir(join(root, "Applications"), { mode: 0o700 });
  const sourceCandidate = candidateEvidence("1", "2", "3");
  const stageCandidate = structuredClone(
    candidateEvidence("7", "8", "3"),
  ) as MutableCandidateEvidence;
  const predecessor = {
    identity: expectedHistoricalOprtePreviewIdentity,
    signature: expectedHistoricalOprtePreviewSignature,
    tree: expectedHistoricalOprtePreviewTree,
  };
  const priorHra = prior ? {
    identity: {
      build: "15",
      bundleIdentifier: "kitchen.hraness",
      executable: "hra",
      version: "0.1.14",
    },
    signature: { policy: "strict" as const },
    tree: treeEvidence("4"),
  } : null;
  const paths = {
    applicationsDirectory: join(root, "Applications"),
    backupDirectory: join(root, "backup"),
    candidateApp: join(root, "candidate", "HRA.app"),
    candidateStage: join(root, "Applications", ".handoff_candidate.app"),
    canonicalApp: join(root, "Applications", "HRA.app"),
    controlPlanePath: join(root, "state", "control-plane.sqlite"),
    nativeInstanceLockPath: join(root, "state", ".native.lock"),
    predecessorApp: join(root, "Applications", "OPRTE.app"),
    predecessorRetirementStage: join(
      root,
      "Applications",
      ".handoff_predecessor.bundle",
    ),
    sparkleCacheRoots: [join(root, "Sparkle")],
    stateRoot: join(root, "state"),
    updateHazardPath: join(root, "state", "hazard"),
    updateHazardTemporaryPath: join(root, "state", ".hazard.tmp"),
  };
  const core: InstallationHandoffV3Core = {
    candidate: sourceCandidate,
    createdAt: 1,
    keychainDescriptors: ["name\0service"],
    kind: "hra-installation-handoff-authorization",
    operationId: `handoff_${"a".repeat(24)}`,
    paths,
    predecessor,
    preState: stateEvidence(),
    preStateSha256: "9".repeat(64),
    priorHra,
    schemaVersion: 3,
  };
  const progress: InstallationHandoffV3Progress = {
    authorizedSidecar: null,
    candidateStage: stageCandidate,
    core: {
      bytes: 1,
      device: "1",
      inode: "2",
      path: join(paths.backupDirectory, "handoff-enrollment-authorization-v3.json"),
      schemaVersion: 3,
      sha256: "a".repeat(64),
    },
    keychainContinuity: "pending_same_process",
    phase: "candidate_staged",
    schemaVersion: 3,
  };
  const leaves = new Map<string, LeafKind>([
    [paths.canonicalApp, prior ? "prior" : "missing"],
    [paths.candidateStage, "missing"],
    [paths.predecessorApp, "predecessor"],
    [paths.predecessorRetirementStage, "missing"],
  ]);
  const dependencies = {
    async inspectCandidateV3(path: string) {
      if (leaves.get(path) === "candidate") return stageCandidate;
      throw leaves.get(path) === "missing"
        ? enoent()
        : new Error("not candidate");
    },
    async inspectBundle(path: string) {
      const leaf = leaves.get(path);
      if (leaf === "predecessor") return predecessor;
      if (leaf === "prior" && priorHra !== null) return priorHra;
      throw leaf === "missing" ? enoent() : new Error("not exact bundle");
    },
    async acquireRenameParentLease() {
      return {
        async revalidate() {},
        async release() {},
        async syncAndRevalidate() {},
      };
    },
  };
  return { core, dependencies, leaves, progress, stageCandidate };
}

type LeafKind = "candidate" | "prior" | "predecessor" | "missing";
type MutableCandidateEvidence = {
  -readonly [Key in keyof InstallationHandoffV3CandidateEvidence]:
    InstallationHandoffV3CandidateEvidence[Key] extends object
      ? { -readonly [Child in keyof InstallationHandoffV3CandidateEvidence[Key]]:
          InstallationHandoffV3CandidateEvidence[Key][Child] }
      : InstallationHandoffV3CandidateEvidence[Key]
};

function candidateEvidence(
  rootInode: string,
  manifestInode: string,
  logicalDigit: string,
): InstallationHandoffV3CandidateEvidence {
  return {
    bundle: {
      identity: {
        build: "16",
        bundleIdentifier: "kitchen.hraness",
        executable: "hra",
        version: "0.1.15",
      },
      signature: { policy: "strict" },
      tree: treeEvidence(logicalDigit),
    },
    custodyProbeSupervisor: testCustodyProbeSupervisorAuthority,
    manifest: {
      bytes: 2_048,
      commit: "5".repeat(40),
      device: "1",
      inode: manifestInode,
      runtimeTreeSha256: "6".repeat(64),
      sha256: "7".repeat(64),
    },
    root: { device: "1", inode: rootInode },
  };
}

function treeEvidence(digit: string) {
  return {
    bytes: 10,
    directories: 1,
    digest: digit.repeat(64),
    entries: 2,
    files: 1,
    symlinks: 0,
  };
}

function stateEvidence() {
  return {
    accountHomes: 0,
    chatWorktreeLanes: 0,
    database: {
      databaseSha256: "8".repeat(64),
      migrationVersion: 62,
      quickCheck: "ok" as const,
      rows: {},
    },
    dispatchWorktreeLanes: 0,
    harnessWorktreeLanes: 0,
    localTaskWorktreeLanes: 0,
    sessionEntries: 0,
    tree: treeEvidence("8"),
  };
}

function enrollmentEvidence() {
  return {
    bytes: 100,
    device: "1",
    inode: "10",
    sha256: "b".repeat(64),
  };
}

function enoent(): Error & { code: "ENOENT" } {
  return Object.assign(new Error("missing"), { code: "ENOENT" as const });
}
