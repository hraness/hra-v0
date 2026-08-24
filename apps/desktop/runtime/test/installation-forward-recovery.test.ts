/* eslint-disable @typescript-eslint/await-thenable --
 * Bun's async resolves/rejects matchers are intentionally awaited.
 */
import { afterAll, describe, expect, test } from "bun:test";
import { createHash } from "node:crypto";
import {
  chmod,
  cp,
  link,
  lstat,
  mkdir,
  mkdtemp,
  readFile,
  realpath,
  rename,
  rm,
  symlink,
  writeFile,
} from "node:fs/promises";
import { tmpdir } from "node:os";
import { basename, dirname, join } from "node:path";

import {
  cleanupForwardRecovery,
  ForwardRecoveryProcessExitForTest,
  forwardRecoveryCleanupConfirmation,
  forwardRecoveryConfirmation,
  forwardRecoveryResumeConfirmation,
  frozenHraV0114Origin,
  inspectForwardRecoveryStatus,
  performForwardRecovery,
  resumeForwardRecovery,
  syncForwardRecoveryTreeDurably,
  type ForwardBundleEvidence,
  type ForwardCandidateEvidence,
  type ForwardRecoveryDependencies,
  type ForwardRecoveryFaultPoint,
} from "../installation-forward-recovery";
import {
  expectedHistoricalOprtePreviewSignature,
  expectedHistoricalOprtePreviewTree,
} from "../historical-oprte-preview";
import type {
  BundleContinuityEvidence,
  InstallationHandoffPaths,
  KeychainEvidence,
  StateContinuityEvidence,
} from "../installation-handoff";
import {
  harnessKeyEnrollmentSidecarPath,
  readHarnessKeyEnrollmentSidecar,
  removeExactHarnessKeyEnrollmentSidecar,
  writeHarnessKeyEnrollmentSidecar,
} from "../src/state/harness-key-enrollment";
import {
  testCustodyProbeSupervisorAuthority,
} from "./fixtures/custody-probe-authority";

const roots: string[] = [];
const candidateCommit = "c".repeat(40);
const candidateRuntimeTree = "d".repeat(64);
const keychainDescriptors = ["service\u0000name"] as const;

afterAll(async () => {
  for (const root of roots) await rm(root, { force: true, recursive: true });
});

describe("B14 to B15 forward recovery", () => {
  test("durably syncs the full staged tree before prepared receipt and every swap", async () => {
    const fixture = await createFixture();
    const order: string[] = [];
    const dependencies: ForwardRecoveryDependencies = {
      ...fixture.dependencies,
      async publishForward(source, destination) {
        order.push("publish");
        return await fixture.dependencies.publishForward(source, destination);
      },
      async syncStagedTree(path) {
        order.push("sync-staged");
        await syncForwardRecoveryTreeDurably(path);
      },
    };
    expect(performForwardRecovery({
      backupDirectory: fixture.backupDirectory,
      candidateApp: fixture.paths.candidateApp,
      confirmation: forwardRecoveryConfirmation,
      originHandoffBackupDirectory: fixture.originBackupDirectory,
      onCheckpoint(point) {
        if (point === "after_prepared") {
          order.push("prepared-durable");
          throw new ForwardRecoveryProcessExitForTest(point);
        }
      },
      paths: fixture.paths,
    }, dependencies)).rejects.toThrow("process-exit:after_prepared");
    expect(order).toEqual(["sync-staged", "prepared-durable"]);

    order.length = 0;
    await resumeForwardRecovery({
      backupDirectory: fixture.backupDirectory,
      confirmation: forwardRecoveryResumeConfirmation,
    }, dependencies);
    expect(order.slice(0, 2)).toEqual(["sync-staged", "publish"]);
  });

  test("re-verifies exact candidate authority after every durability barrier", async () => {
    const initial = await createFixture();
    let initialMutated = false;
    const initialDependencies: ForwardRecoveryDependencies = {
      ...initial.dependencies,
      async syncStagedTree(path) {
        await initial.dependencies.syncStagedTree(path);
        if (!initialMutated) {
          initialMutated = true;
          await writeFile(join(path, "marker.txt"), "tampered-after-sync\n");
        }
      },
    };
    expect(performForwardRecovery({
      backupDirectory: initial.backupDirectory,
      candidateApp: initial.paths.candidateApp,
      confirmation: forwardRecoveryConfirmation,
      originHandoffBackupDirectory: initial.originBackupDirectory,
      paths: initial.paths,
    }, initialDependencies)).rejects.toThrow();
    expect(await appVersion(initial.paths.canonicalApp)).toBe("0.1.14");

    const resumed = await createFixture();
    expect(performForwardRecovery({
      backupDirectory: resumed.backupDirectory,
      candidateApp: resumed.paths.candidateApp,
      confirmation: forwardRecoveryConfirmation,
      originHandoffBackupDirectory: resumed.originBackupDirectory,
      onCheckpoint(point) {
        if (point === "after_prepared") {
          throw new ForwardRecoveryProcessExitForTest(point);
        }
      },
      paths: resumed.paths,
    }, resumed.dependencies)).rejects.toThrow("process-exit:after_prepared");
    const resumeDependencies: ForwardRecoveryDependencies = {
      ...resumed.dependencies,
      async syncStagedTree(path) {
        await resumed.dependencies.syncStagedTree(path);
        await writeFile(join(path, "marker.txt"), "tampered-on-resume\n");
      },
    };
    expect(resumeForwardRecovery({
      backupDirectory: resumed.backupDirectory,
      confirmation: forwardRecoveryResumeConfirmation,
    }, resumeDependencies)).rejects.toThrow();
    expect(await appVersion(resumed.paths.canonicalApp)).toBe("0.1.14");
  });

  test("rejects every substituted supervisor authority at the package join", async () => {
    const substitutions = [
      { cdHash: "1".repeat(40) },
      { sha256: "2".repeat(64) },
      { designatedRequirement: "identifier substituted" },
      {
        signing: {
          ...testCustodyProbeSupervisorAuthority.signing,
          authority: "substituted-release-authority",
        },
      },
    ] as const;
    for (const substitution of substitutions) {
      const fixture = await createFixture();
      let inspections = 0;
      const dependencies: ForwardRecoveryDependencies = {
        ...fixture.dependencies,
        async inspectCandidate(path) {
          const exact = await fixture.dependencies.inspectCandidate(path);
          inspections += 1;
          if (inspections === 1) return exact;
          return {
            ...exact,
            custodyProbeSupervisor: {
              ...exact.custodyProbeSupervisor,
              ...substitution,
            },
          };
        },
      };
      await expect(performForwardRecovery({
        backupDirectory: fixture.backupDirectory,
        candidateApp: fixture.paths.candidateApp,
        confirmation: forwardRecoveryConfirmation,
        originHandoffBackupDirectory: fixture.originBackupDirectory,
        paths: fixture.paths,
      }, dependencies)).rejects.toThrow(
        "receipt-bound supervisor authority",
      );
      expect(await appVersion(fixture.paths.canonicalApp)).toBe("0.1.14");
    }

    const positive = await createPreparedProcessLossFixture();
    await expect(inspectForwardRecoveryStatus(
      positive.backupDirectory,
      positive.dependencies,
    )).resolves.toMatchObject({ disposition: "prepublish" });
  });

  test("publishes once, preserves state/Keychain in-process, and retains exact B14 privately", async () => {
    const fixture = await createFixture();
    const result = await performForwardRecovery({
      backupDirectory: fixture.backupDirectory,
      candidateApp: fixture.paths.candidateApp,
      confirmation: forwardRecoveryConfirmation,
      originHandoffBackupDirectory: fixture.originBackupDirectory,
      paths: fixture.paths,
    }, fixture.dependencies);

    expect(result).toMatchObject({
      disposition: "complete",
      keychainContinuity: "verified_same_process",
      status: "forward_recovered",
    });
    expect(await appVersion(fixture.paths.canonicalApp)).toBe("0.1.15");
    const receipt = await readForwardReceipt(fixture.backupDirectory);
    expect(receipt["phase"]).toBe("complete");
    expect(receipt["keychainContinuity"]).toBe("verified_same_process");
    const receiptPaths = receipt["paths"] as Record<string, string>;
    expect(await appVersion(receiptPaths["cleanupTombstoneApp"]!)).toBe("0.1.14");
    expect(dirname(receiptPaths["cleanupTombstoneApp"]!)).toBe(
      fixture.backupDirectory,
    );
    expect(lstat(receiptPaths["retiredOriginApp"]!)).rejects.toMatchObject({
      code: "ENOENT",
    });
    expect(fixture.assertKeychainCalls()).toBeGreaterThanOrEqual(2);

    const externalStatus = await inspectForwardRecoveryStatus(
      fixture.backupDirectory,
      fixture.dependencies,
    );
    expect(externalStatus).toMatchObject({
      disposition: "complete",
      keychainContinuity: "unavailable_after_process_restart",
    });
  });

  test("prepublication failure aborts without changing canonical B14", async () => {
    const fixture = await createFixture();
    expect(performForwardRecovery({
      backupDirectory: fixture.backupDirectory,
      candidateApp: fixture.paths.candidateApp,
      confirmation: forwardRecoveryConfirmation,
      originHandoffBackupDirectory: fixture.originBackupDirectory,
      paths: fixture.paths,
      onCheckpoint(point) {
        if (point === "after_prepared") throw new Error("fault:prepared");
      },
    }, fixture.dependencies)).rejects.toThrow("fault:prepared");

    expect(await appVersion(fixture.paths.canonicalApp)).toBe("0.1.14");
    const receipt = await readForwardReceipt(fixture.backupDirectory);
    expect(receipt["phase"]).toBe("aborted");
    expect(await appVersion(
      (receipt["paths"] as Record<string, string>)["cleanupTombstoneApp"]!,
    )).toBe("0.1.15");
    expect(await inspectForwardRecoveryStatus(
      fixture.backupDirectory,
      fixture.dependencies,
    )).toMatchObject({
      disposition: "aborted",
      keychainContinuity: "not_applicable",
    });
  });

  test("resumes a durable prepared receipt after simulated process loss", async () => {
    const fixture = await createFixture();
    expect(performForwardRecovery({
      backupDirectory: fixture.backupDirectory,
      candidateApp: fixture.paths.candidateApp,
      confirmation: forwardRecoveryConfirmation,
      originHandoffBackupDirectory: fixture.originBackupDirectory,
      paths: fixture.paths,
      onCheckpoint(point) {
        if (point === "after_prepared") {
          throw new ForwardRecoveryProcessExitForTest(point);
        }
      },
    }, fixture.dependencies)).rejects.toThrow("process-exit:after_prepared");
    expect(await appVersion(fixture.paths.canonicalApp)).toBe("0.1.14");
    expect(await readForwardReceipt(fixture.backupDirectory)).toMatchObject({
      phase: "prepared",
    });

    const resumed = await resumeForwardRecovery({
      backupDirectory: fixture.backupDirectory,
      confirmation: forwardRecoveryResumeConfirmation,
    }, fixture.dependencies);
    expect(resumed).toMatchObject({
      disposition: "complete",
      keychainContinuity: "unavailable_after_process_restart",
    });
    expect(await appVersion(fixture.paths.canonicalApp)).toBe("0.1.15");
    await assertImmutableInputs(fixture);
  });

  for (const faultPoint of [
    "after_authorizing_receipt",
    "after_enrollment_authorized",
  ] as const satisfies readonly ForwardRecoveryFaultPoint[]) {
    test(`resumes the enrollment authorization crash cut at ${faultPoint}`, async () => {
      const fixture = await createFixture();
      expect(performForwardRecovery({
        backupDirectory: fixture.backupDirectory,
        candidateApp: fixture.paths.candidateApp,
        confirmation: forwardRecoveryConfirmation,
        originHandoffBackupDirectory: fixture.originBackupDirectory,
        paths: fixture.paths,
        onCheckpoint(point) {
          if (point === faultPoint) {
            throw new ForwardRecoveryProcessExitForTest(point);
          }
        },
      }, fixture.dependencies)).rejects.toThrow(`process-exit:${faultPoint}`);
      expect(await readForwardReceipt(fixture.backupDirectory)).toMatchObject({
        phase: "authorizing",
        enrollment: { file: null },
      });
      expect(await appVersion(fixture.paths.canonicalApp)).toBe("0.1.14");

      const resumed = await resumeForwardRecovery({
        backupDirectory: fixture.backupDirectory,
        confirmation: forwardRecoveryResumeConfirmation,
      }, fixture.dependencies);
      expect(resumed).toMatchObject({
        disposition: "complete",
        keychainContinuity: "unavailable_after_process_restart",
      });
      expect(await appVersion(fixture.paths.canonicalApp)).toBe("0.1.15");
    });
  }

  test("ordinary prepublication enrollment failure removes only its exact sidecar", async () => {
    const fixture = await createFixture();
    expect(performForwardRecovery({
      backupDirectory: fixture.backupDirectory,
      candidateApp: fixture.paths.candidateApp,
      confirmation: forwardRecoveryConfirmation,
      originHandoffBackupDirectory: fixture.originBackupDirectory,
      paths: fixture.paths,
      onCheckpoint(point) {
        if (point === "after_enrollment_authorized") {
          throw new Error("fault:authorized-sidecar");
        }
      },
    }, fixture.dependencies)).rejects.toThrow("fault:authorized-sidecar");
    expect(await readForwardReceipt(fixture.backupDirectory)).toMatchObject({
      phase: "aborted",
      enrollment: { file: null },
    });
    expect(await readHarnessKeyEnrollmentSidecar(fixture.paths.controlPlanePath))
      .toBeNull();
    expect(await appVersion(fixture.paths.canonicalApp)).toBe("0.1.14");
  });

  test("preseeded exact v2 custody is refused before authorization", async () => {
    const fixture = await createFixture();
    const dependencies: ForwardRecoveryDependencies = {
      ...fixture.dependencies,
      inspectEnrollmentKeychainNoUi: () => Promise.resolve({
        envelopeSha256: "9".repeat(64),
        state: "present",
        strictAcl: true,
      }),
    };
    expect(performForwardRecovery({
      backupDirectory: fixture.backupDirectory,
      candidateApp: fixture.paths.candidateApp,
      confirmation: forwardRecoveryConfirmation,
      originHandoffBackupDirectory: fixture.originBackupDirectory,
      paths: fixture.paths,
    }, dependencies)).rejects.toMatchObject({ code: "continuity_failed" });
    expect(await appVersion(fixture.paths.canonicalApp)).toBe("0.1.14");
    expect(await readHarnessKeyEnrollmentSidecar(fixture.paths.controlPlanePath))
      .toBeNull();
  });

  test("Keychain failure before swap aborts; failure after swap never reverses", async () => {
    const before = await createFixture();
    const beforeDependencies: ForwardRecoveryDependencies = {
      ...before.dependencies,
      assertKeychain: () => Promise.reject(new Error("keychain:before-swap")),
    };
    expect(performForwardRecovery({
      backupDirectory: before.backupDirectory,
      candidateApp: before.paths.candidateApp,
      confirmation: forwardRecoveryConfirmation,
      originHandoffBackupDirectory: before.originBackupDirectory,
      paths: before.paths,
    }, beforeDependencies)).rejects.toThrow("keychain:before-swap");
    expect(await appVersion(before.paths.canonicalApp)).toBe("0.1.14");
    expect(await readForwardReceipt(before.backupDirectory)).toMatchObject({
      phase: "aborted",
    });

    const after = await createFixture();
    let checks = 0;
    const afterDependencies: ForwardRecoveryDependencies = {
      ...after.dependencies,
      assertKeychain() {
        checks += 1;
        return checks === 2
          ? Promise.reject(new Error("keychain:after-swap"))
          : Promise.resolve();
      },
    };
    expect(performForwardRecovery({
      backupDirectory: after.backupDirectory,
      candidateApp: after.paths.candidateApp,
      confirmation: forwardRecoveryConfirmation,
      originHandoffBackupDirectory: after.originBackupDirectory,
      paths: after.paths,
    }, afterDependencies)).rejects.toThrow("keychain:after-swap");
    expect(await appVersion(after.paths.canonicalApp)).toBe("0.1.15");
    expect(await readForwardReceipt(after.backupDirectory)).toMatchObject({
      phase: "published",
    });
    await assertImmutableInputs(after);
  });

  for (const faultPoint of [
    "after_swap_before_receipt",
    "after_published_receipt",
  ] as const satisfies readonly ForwardRecoveryFaultPoint[]) {
    test(`never reverse-swaps after ${faultPoint}`, async () => {
      const fixture = await createFixture();
      expect(performInstallationFault(fixture, faultPoint)).rejects.toThrow(
        `fault:${faultPoint}`,
      );
      expect(await appVersion(fixture.paths.canonicalApp)).toBe("0.1.15");
      await assertImmutableInputs(fixture);
      const resumed = await resumeForwardRecovery({
        backupDirectory: fixture.backupDirectory,
        confirmation: forwardRecoveryResumeConfirmation,
      }, fixture.dependencies);
      expect(resumed).toMatchObject({
        disposition: "complete",
        keychainContinuity: "unavailable_after_process_restart",
      });
      expect(await appVersion(fixture.paths.canonicalApp)).toBe("0.1.15");
      await assertImmutableInputs(fixture);

      const cleaned = await cleanupForwardRecovery({
        backupDirectory: fixture.backupDirectory,
        confirmation: forwardRecoveryCleanupConfirmation,
      }, fixture.dependencies);
      expect(cleaned).toMatchObject({
        disposition: "complete",
        keychainContinuity: "unavailable_after_process_restart",
      });
      expect(await appVersion(fixture.paths.canonicalApp)).toBe("0.1.15");
    });
  }

  test("a crash after verified receipt degrades Keychain truth on resume", async () => {
    const fixture = await createFixture();
    expect(performInstallationFault(fixture, "after_verified_receipt"))
      .rejects.toThrow("fault:after_verified_receipt");
    const receiptBefore = await readForwardReceipt(fixture.backupDirectory);
    expect(receiptBefore).toMatchObject({
      phase: "verified",
      keychainContinuity: "verified_same_process",
    });

    const resumed = await resumeForwardRecovery({
      backupDirectory: fixture.backupDirectory,
      confirmation: forwardRecoveryResumeConfirmation,
    }, fixture.dependencies);
    expect(resumed).toMatchObject({
      disposition: "complete",
      keychainContinuity: "unavailable_after_process_restart",
    });
    expect(await readForwardReceipt(fixture.backupDirectory)).toMatchObject({
      phase: "complete",
      keychainContinuity: "unavailable_after_process_restart",
    });
    await assertImmutableInputs(fixture);
  });

  test("recovers the cut after exact B14 was atomically tombstoned", async () => {
    const fixture = await createFixture();
    expect(performInstallationFault(fixture, "after_retired_origin_cleanup"))
      .rejects.toThrow("fault:after_retired_origin_cleanup");
    expect(await appVersion(fixture.paths.canonicalApp)).toBe("0.1.15");

    const resumed = await resumeForwardRecovery({
      backupDirectory: fixture.backupDirectory,
      confirmation: forwardRecoveryResumeConfirmation,
    }, fixture.dependencies);
    expect(resumed).toMatchObject({
      disposition: "complete",
      keychainContinuity: "unavailable_after_process_restart",
    });
    const receipt = await readForwardReceipt(fixture.backupDirectory);
    expect(await appVersion(
      (receipt["paths"] as Record<string, string>)["cleanupTombstoneApp"]!,
    )).toBe("0.1.14");
    await assertImmutableInputs(fixture);
  });

  test("recovers a crash immediately after tombstone rename without deleting it", async () => {
    const fixture = await createFixture();
    let injected = false;
    const dependencies: ForwardRecoveryDependencies = {
      ...fixture.dependencies,
      async stageForDeletion(source, tombstone) {
        await fixture.dependencies.stageForDeletion(source, tombstone);
        if (!injected && (await appVersion(tombstone)) === "0.1.14") {
          injected = true;
          throw new Error("fault:after-tombstone-rename");
        }
      },
    };
    expect(performForwardRecovery({
      backupDirectory: fixture.backupDirectory,
      candidateApp: fixture.paths.candidateApp,
      confirmation: forwardRecoveryConfirmation,
      originHandoffBackupDirectory: fixture.originBackupDirectory,
      paths: fixture.paths,
    }, dependencies)).rejects.toThrow("fault:after-tombstone-rename");

    expect(await appVersion(fixture.paths.canonicalApp)).toBe("0.1.15");
    expect(await resumeForwardRecovery({
      backupDirectory: fixture.backupDirectory,
      confirmation: forwardRecoveryResumeConfirmation,
    }, fixture.dependencies)).toMatchObject({ disposition: "complete" });
    await assertImmutableInputs(fixture);
  });

  test("fails closed on B14 receipt tamper and present-invalid retired staging", async () => {
    const receiptFixture = await createFixture();
    expect(performInstallationFault(receiptFixture, "after_swap_before_receipt"))
      .rejects.toThrow();
    await writeFile(
      join(receiptFixture.originBackupDirectory, "handoff-receipt.json"),
      "{}\n",
    );
    expect(resumeForwardRecovery({
      backupDirectory: receiptFixture.backupDirectory,
      confirmation: forwardRecoveryResumeConfirmation,
    }, receiptFixture.dependencies)).rejects.toThrow("handoff-receipt.json");
    expect(await appVersion(receiptFixture.paths.canonicalApp)).toBe("0.1.15");

    const stageFixture = await createFixture();
    expect(performInstallationFault(stageFixture, "after_swap_before_receipt"))
      .rejects.toThrow();
    const receipt = await readForwardReceipt(stageFixture.backupDirectory);
    const stage = (receipt["paths"] as Record<string, string>)["retiredOriginApp"]!;
    await writeFile(join(stage, "marker.txt"), "tampered\n");
    expect(cleanupForwardRecovery({
      backupDirectory: stageFixture.backupDirectory,
      confirmation: forwardRecoveryCleanupConfirmation,
    }, stageFixture.dependencies)).rejects.toThrow("ambiguous");
    expect(await appVersion(stageFixture.paths.canonicalApp)).toBe("0.1.15");
    expect(await lstat(stage)).toBeDefined();
  });

  test("rejects symlinked, hardlinked, replaced, and moved committed-origin receipts", async () => {
    const symlinkFixture = await createPreparedProcessLossFixture();
    const symlinkReceipt = join(
      symlinkFixture.originBackupDirectory,
      "handoff-receipt.json",
    );
    const symlinkTarget = join(symlinkFixture.originBackupDirectory, "replacement.json");
    await rename(symlinkReceipt, symlinkTarget);
    await symlink(symlinkTarget, symlinkReceipt);
    expect(resumePrepared(symlinkFixture)).rejects.toThrow();
    expect(await appVersion(symlinkFixture.paths.canonicalApp)).toBe("0.1.14");

    const hardlinkFixture = await createPreparedProcessLossFixture();
    const hardlinkReceipt = join(
      hardlinkFixture.originBackupDirectory,
      "handoff-receipt.json",
    );
    await link(hardlinkReceipt, join(hardlinkFixture.originBackupDirectory, "second-link"));
    expect(resumePrepared(hardlinkFixture)).rejects.toThrow();
    expect(await appVersion(hardlinkFixture.paths.canonicalApp)).toBe("0.1.14");

    const replacementFixture = await createPreparedProcessLossFixture();
    const replacementReceipt = join(
      replacementFixture.originBackupDirectory,
      "handoff-receipt.json",
    );
    const sameBytes = await readFile(replacementReceipt);
    const replacement = join(replacementFixture.originBackupDirectory, "new-receipt");
    await writeFile(replacement, sameBytes, { mode: 0o600 });
    await rename(replacement, replacementReceipt);
    expect(resumePrepared(replacementFixture)).rejects.toThrow("changed");
    expect(await appVersion(replacementFixture.paths.canonicalApp)).toBe("0.1.14");

    const movedFixture = await createPreparedProcessLossFixture();
    const copiedBackup = join(dirname(movedFixture.backupDirectory), "copied-forward-backup");
    await cp(movedFixture.backupDirectory, copiedBackup, { recursive: true });
    await chmod(copiedBackup, 0o700);
    expect(inspectForwardRecoveryStatus(
      copiedBackup,
      movedFixture.dependencies,
    )).rejects.toThrow("invalid");
  });

  test("rejects a full-tree B14 mismatch before prepared resume", async () => {
    const fixture = await createPreparedProcessLossFixture();
    await writeFile(join(fixture.paths.canonicalApp, "marker.txt"), "0.1.14/15\nextra");
    expect(resumePrepared(fixture)).rejects.toThrow("ambiguous");
    expect(await appVersion(fixture.paths.canonicalApp)).toBe("0.1.14");
  });

  test("classifies unknown swap status without ever compensating", async () => {
    const swapped = await createFixture();
    const swappedDependencies: ForwardRecoveryDependencies = {
      ...swapped.dependencies,
      async publishForward(source, destination) {
        await swapped.dependencies.publishForward(source, destination);
        return { status: "postcondition_unknown_after_swap" };
      },
    };
    expect(await performForwardRecovery({
      backupDirectory: swapped.backupDirectory,
      candidateApp: swapped.paths.candidateApp,
      confirmation: forwardRecoveryConfirmation,
      originHandoffBackupDirectory: swapped.originBackupDirectory,
      paths: swapped.paths,
    }, swappedDependencies)).toMatchObject({ disposition: "complete" });
    expect(await appVersion(swapped.paths.canonicalApp)).toBe("0.1.15");

    const notSwapped = await createFixture();
    const notSwappedDependencies: ForwardRecoveryDependencies = {
      ...notSwapped.dependencies,
      publishForward: () => Promise.resolve({
        status: "postcondition_unknown_after_swap",
      }),
    };
    expect(performForwardRecovery({
      backupDirectory: notSwapped.backupDirectory,
      candidateApp: notSwapped.paths.candidateApp,
      confirmation: forwardRecoveryConfirmation,
      originHandoffBackupDirectory: notSwapped.originBackupDirectory,
      paths: notSwapped.paths,
    }, notSwappedDependencies)).rejects.toThrow("cannot be proven");
    expect(await appVersion(notSwapped.paths.canonicalApp)).toBe("0.1.14");
    expect(await readForwardReceipt(notSwapped.backupDirectory)).toMatchObject({
      phase: "aborted",
    });
  });

  test("treats externally reversed published layout as conflict", async () => {
    const fixture = await createFixture();
    expect(performInstallationFault(fixture, "after_published_receipt"))
      .rejects.toThrow();
    const receipt = await readForwardReceipt(fixture.backupDirectory);
    const stage = (receipt["paths"] as Record<string, string>)["retiredOriginApp"]!;
    await fixture.dependencies.publishForward(stage, fixture.paths.canonicalApp);
    expect(resumeForwardRecovery({
      backupDirectory: fixture.backupDirectory,
      confirmation: forwardRecoveryResumeConfirmation,
    }, fixture.dependencies)).rejects.toThrow("ambiguous");
    expect(await appVersion(fixture.paths.canonicalApp)).toBe("0.1.14");
  });

  test("refuses publication if OPRTE reappears or state differs", async () => {
    const oprteFixture = await createFixture();
    await mkdir(oprteFixture.paths.predecessorApp, { recursive: true });
    expect(performForwardRecovery({
      backupDirectory: oprteFixture.backupDirectory,
      candidateApp: oprteFixture.paths.candidateApp,
      confirmation: forwardRecoveryConfirmation,
      originHandoffBackupDirectory: oprteFixture.originBackupDirectory,
      paths: oprteFixture.paths,
    }, oprteFixture.dependencies)).rejects.toThrow("OPRTE.app to remain absent");
    expect(await appVersion(oprteFixture.paths.canonicalApp)).toBe("0.1.14");

    const stateFixture = await createFixture();
    expect(performInstallationFault(stateFixture, "after_swap_before_receipt"))
      .rejects.toThrow();
    const dependencies: ForwardRecoveryDependencies = {
      ...stateFixture.dependencies,
      inspectState: () => Promise.resolve({
        ...stateFixture.state,
        sessionEntries: stateFixture.state.sessionEntries + 1,
      }),
      inspectStateWithoutEnrollmentSidecar: () => Promise.resolve({
        ...stateFixture.state,
        sessionEntries: stateFixture.state.sessionEntries + 1,
      }),
    };
    expect(cleanupForwardRecovery({
      backupDirectory: stateFixture.backupDirectory,
      confirmation: forwardRecoveryCleanupConfirmation,
    }, dependencies)).rejects.toThrow("differs from the pre-handoff");
    expect(await appVersion(stateFixture.paths.canonicalApp)).toBe("0.1.15");
  });

  test("accepts genuine prepared and enrolled sidecar crash cuts after swap", async () => {
    const preparedFixture = await createFixture();
    const preparedObservation = { state: "absent" } as const;
    const preparedDependencies: ForwardRecoveryDependencies = {
      ...preparedFixture.dependencies,
      inspectEnrollmentKeychainNoUi: () => Promise.resolve(preparedObservation),
    };
    expect(performForwardRecovery({
      backupDirectory: preparedFixture.backupDirectory,
      candidateApp: preparedFixture.paths.candidateApp,
      confirmation: forwardRecoveryConfirmation,
      originHandoffBackupDirectory: preparedFixture.originBackupDirectory,
      onCheckpoint(point) {
        if (point === "after_swap_before_receipt") {
          throw new ForwardRecoveryProcessExitForTest(point);
        }
      },
      paths: preparedFixture.paths,
    }, preparedDependencies)).rejects.toThrow(
      "process-exit:after_swap_before_receipt",
    );
    await advanceEnrollmentSidecar(preparedFixture, "prepared");
    expect(inspectForwardRecoveryStatus(
      preparedFixture.backupDirectory,
      preparedDependencies,
    )).resolves.toMatchObject({ disposition: "postpublish" });
    expect(resumeForwardRecovery({
      backupDirectory: preparedFixture.backupDirectory,
      confirmation: forwardRecoveryResumeConfirmation,
    }, preparedDependencies)).resolves.toMatchObject({ disposition: "complete" });

    const enrolledFixture = await createFixture();
    let enrolledObservation:
      | { readonly state: "absent" }
      | {
          readonly envelopeSha256: string;
          readonly state: "present";
          readonly strictAcl: true;
        } = { state: "absent" };
    const enrolledDependencies: ForwardRecoveryDependencies = {
      ...enrolledFixture.dependencies,
      inspectEnrollmentKeychainNoUi: () => Promise.resolve(enrolledObservation),
    };
    expect(performForwardRecovery({
      backupDirectory: enrolledFixture.backupDirectory,
      candidateApp: enrolledFixture.paths.candidateApp,
      confirmation: forwardRecoveryConfirmation,
      originHandoffBackupDirectory: enrolledFixture.originBackupDirectory,
      onCheckpoint(point) {
        if (point === "after_swap_before_receipt") {
          throw new ForwardRecoveryProcessExitForTest(point);
        }
      },
      paths: enrolledFixture.paths,
    }, enrolledDependencies)).rejects.toThrow(
      "process-exit:after_swap_before_receipt",
    );
    const digest = await advanceEnrollmentSidecar(enrolledFixture, "enrolled");
    enrolledObservation = {
      envelopeSha256: digest,
      state: "present",
      strictAcl: true,
    };
    expect(inspectForwardRecoveryStatus(
      enrolledFixture.backupDirectory,
      enrolledDependencies,
    )).resolves.toMatchObject({ disposition: "postpublish" });
    expect(cleanupForwardRecovery({
      backupDirectory: enrolledFixture.backupDirectory,
      confirmation: forwardRecoveryCleanupConfirmation,
    }, enrolledDependencies)).resolves.toMatchObject({ disposition: "complete" });
    expect(inspectForwardRecoveryStatus(
      enrolledFixture.backupDirectory,
      enrolledDependencies,
    )).resolves.toMatchObject({ disposition: "complete" });
  });

  test("rejects postpublish enrollment authorization, absence, digest, and rollback tamper", async () => {
    const changedAuthorization = await completedEnrollmentFixture("enrolled");
    const changedPath = harnessKeyEnrollmentSidecarPath(
      changedAuthorization.fixture.paths.controlPlanePath,
    );
    const changedBytes = await readFile(changedPath, "utf8");
    await writeFile(
      changedPath,
      changedBytes.replace(
        /forward_[a-f0-9]{24}/u,
        `forward_${"d".repeat(24)}`,
      ),
    );
    expect(inspectForwardRecoveryStatus(
      changedAuthorization.fixture.backupDirectory,
      changedAuthorization.dependencies,
    )).rejects.toThrow("authority or custody changed");

    const missing = await completedEnrollmentFixture("enrolled");
    await rm(
      harnessKeyEnrollmentSidecarPath(missing.fixture.paths.controlPlanePath),
    );
    expect(inspectForwardRecoveryStatus(
      missing.fixture.backupDirectory,
      missing.dependencies,
    )).rejects.toThrow("authority or custody changed");

    const differentDigest = await completedEnrollmentFixture("prepared");
    differentDigest.setObservation({
      envelopeSha256: "e".repeat(64),
      state: "present",
      strictAcl: true,
    });
    expect(inspectForwardRecoveryStatus(
      differentDigest.fixture.backupDirectory,
      differentDigest.dependencies,
    )).rejects.toThrow("authority or custody changed");

    const rollback = await completedEnrollmentFixture("prepared");
    const rollbackPath = harnessKeyEnrollmentSidecarPath(
      rollback.fixture.paths.controlPlanePath,
    );
    const current = await readHarnessKeyEnrollmentSidecar(
      rollback.fixture.paths.controlPlanePath,
    );
    expect(current?.sidecar.phase).toBe("prepared");
    const receipt = await readForwardReceipt(rollback.fixture.backupDirectory);
    const authorized = (receipt["enrollment"] as {
      authorizedSidecar: unknown;
    }).authorizedSidecar;
    await writeFile(rollbackPath, `${JSON.stringify(authorized, null, 2)}\n`);
    expect(inspectForwardRecoveryStatus(
      rollback.fixture.backupDirectory,
      rollback.dependencies,
    )).rejects.toThrow("authority or custody changed");
  });

  test("does not bless a same-size protected-file mutation as the sidecar delta", async () => {
    const fixture = await createFixture();
    let sidecarPublished = false;
    const dependencies: ForwardRecoveryDependencies = {
      ...fixture.dependencies,
      async writeEnrollmentSidecar(controlPlanePath, sidecar, expected) {
        const written = await fixture.dependencies.writeEnrollmentSidecar(
          controlPlanePath,
          sidecar,
          expected,
        );
        sidecarPublished = true;
        return written;
      },
      inspectStateWithoutEnrollmentSidecar: () => Promise.resolve(sidecarPublished
        ? {
            ...fixture.state,
            tree: { ...fixture.state.tree, digest: "f".repeat(64) },
          }
        : fixture.state),
    };
    expect(performForwardRecovery({
      backupDirectory: fixture.backupDirectory,
      candidateApp: fixture.paths.candidateApp,
      confirmation: forwardRecoveryConfirmation,
      originHandoffBackupDirectory: fixture.originBackupDirectory,
      paths: fixture.paths,
    }, dependencies)).rejects.toThrow("differs from the pre-handoff");
    expect(await appVersion(fixture.paths.canonicalApp)).toBe("0.1.14");
  });
});

type Fixture = Awaited<ReturnType<typeof createFixture>>;

async function performInstallationFault(
  fixture: Fixture,
  faultPoint: ForwardRecoveryFaultPoint,
): Promise<unknown> {
  return await performForwardRecovery({
    backupDirectory: fixture.backupDirectory,
    candidateApp: fixture.paths.candidateApp,
    confirmation: forwardRecoveryConfirmation,
    originHandoffBackupDirectory: fixture.originBackupDirectory,
    paths: fixture.paths,
    onCheckpoint(point) {
      if (point === faultPoint) throw new Error(`fault:${point}`);
    },
  }, fixture.dependencies);
}

async function createPreparedProcessLossFixture(): Promise<Fixture> {
  const fixture = await createFixture();
  expect(performForwardRecovery({
    backupDirectory: fixture.backupDirectory,
    candidateApp: fixture.paths.candidateApp,
    confirmation: forwardRecoveryConfirmation,
    originHandoffBackupDirectory: fixture.originBackupDirectory,
    paths: fixture.paths,
    onCheckpoint(point) {
      if (point === "after_prepared") {
        throw new ForwardRecoveryProcessExitForTest(point);
      }
    },
  }, fixture.dependencies)).rejects.toThrow("process-exit:after_prepared");
  return fixture;
}

async function resumePrepared(fixture: Fixture): Promise<unknown> {
  return await resumeForwardRecovery({
    backupDirectory: fixture.backupDirectory,
    confirmation: forwardRecoveryResumeConfirmation,
  }, fixture.dependencies);
}

async function assertImmutableInputs(fixture: Fixture): Promise<void> {
  expect((await inspectFixtureBundle(fixture.paths.candidateApp)).bundle.tree.digest)
    .toBe(fixture.candidateSourceDigest);
  expect(await readFile(fixture.paths.controlPlanePath, "utf8"))
    .toBe(fixture.stateFileBytes);
  expect(lstat(fixture.paths.predecessorApp)).rejects.toMatchObject({
    code: "ENOENT",
  });
}

type MutableEnrollmentObservation =
  | { readonly state: "absent" }
  | {
      readonly envelopeSha256: string;
      readonly state: "present";
      readonly strictAcl: true;
    };

async function completedEnrollmentFixture(
  phase: "prepared" | "enrolled",
): Promise<Readonly<{
  dependencies: ForwardRecoveryDependencies;
  fixture: Fixture;
  setObservation(value: MutableEnrollmentObservation): void;
}>> {
  const fixture = await createFixture();
  let observation: MutableEnrollmentObservation = { state: "absent" };
  const dependencies: ForwardRecoveryDependencies = {
    ...fixture.dependencies,
    inspectEnrollmentKeychainNoUi: () => Promise.resolve(observation),
  };
  await performForwardRecovery({
    backupDirectory: fixture.backupDirectory,
    candidateApp: fixture.paths.candidateApp,
    confirmation: forwardRecoveryConfirmation,
    originHandoffBackupDirectory: fixture.originBackupDirectory,
    paths: fixture.paths,
  }, dependencies);
  const digest = await advanceEnrollmentSidecar(fixture, phase);
  if (phase === "enrolled") {
    observation = {
      envelopeSha256: digest,
      state: "present",
      strictAcl: true,
    };
  }
  return {
    dependencies,
    fixture,
    setObservation(value) {
      observation = value;
    },
  };
}

async function advanceEnrollmentSidecar(
  fixture: Fixture,
  phase: "prepared" | "enrolled",
): Promise<string> {
  const authorized = await readHarnessKeyEnrollmentSidecar(
    fixture.paths.controlPlanePath,
  );
  if (authorized === null || authorized.sidecar.phase !== "authorized") {
    throw new Error("fixture enrollment authorization is unavailable");
  }
  const attempt = {
    envelopeSha256: "7".repeat(64),
    nonce: "8".repeat(64),
  };
  const prepared = await writeHarnessKeyEnrollmentSidecar(
    fixture.paths.controlPlanePath,
    { ...authorized.sidecar, attempt, phase: "prepared" },
    authorized,
  );
  if (phase === "enrolled") {
    await writeHarnessKeyEnrollmentSidecar(
      fixture.paths.controlPlanePath,
      { ...prepared.sidecar, phase: "enrolled" },
      prepared,
    );
  }
  return attempt.envelopeSha256;
}

async function createFixture() {
  const root = await realpath(
    await mkdtemp(join(tmpdir(), "hra-forward-recovery-test-")),
  );
  roots.push(root);
  const applicationsDirectory = join(root, "Applications");
  const candidateDirectory = join(root, "candidate");
  const stateRoot = join(root, "state");
  const originBackupDirectory = join(root, "origin-backup");
  const backupDirectory = join(root, "forward-backup");
  await Promise.all([
    mkdir(applicationsDirectory, { recursive: true }),
    mkdir(candidateDirectory, { recursive: true }),
    mkdir(stateRoot, { recursive: true }),
    mkdir(originBackupDirectory, { recursive: true, mode: 0o700 }),
  ]);
  await Promise.all([
    chmod(originBackupDirectory, 0o700),
    chmod(stateRoot, 0o700),
  ]);
  const paths: InstallationHandoffPaths = {
    applicationsDirectory,
    candidateApp: join(candidateDirectory, "HRA.app"),
    canonicalApp: join(applicationsDirectory, "HRA.app"),
    predecessorApp: join(applicationsDirectory, "OPRTE.app"),
    stateRoot,
    controlPlanePath: join(stateRoot, "control-plane.sqlite"),
    nativeInstanceLockPath: join(stateRoot, ".native.lock"),
    updateHazardPath: join(stateRoot, "update.json"),
    updateHazardTemporaryPath: join(stateRoot, ".update.tmp"),
    sparkleCacheRoots: [join(root, "sparkle")],
  };
  await Promise.all([
    createApp(
      paths.canonicalApp,
      "0.1.14",
      "15",
      frozenHraV0114Origin.commit,
      frozenHraV0114Origin.runtimeTreeSha256,
    ),
    createApp(
      paths.candidateApp,
      "0.1.15",
      "16",
      candidateCommit,
      candidateRuntimeTree,
    ),
    writeFile(paths.controlPlanePath, "state-is-never-written\n"),
  ]);
  const state: StateContinuityEvidence = {
    accountHomes: 1,
    chatWorktreeLanes: 2,
    database: {
      databaseSha256: "1".repeat(64),
      migrationVersion: 62,
      quickCheck: "ok",
      rows: { account_profiles: 1 },
    },
    dispatchWorktreeLanes: 3,
    harnessWorktreeLanes: 4,
    localTaskWorktreeLanes: 5,
    sessionEntries: 6,
    tree: {
      bytes: 1,
      directories: 0,
      digest: "2".repeat(64),
      entries: 1,
      files: 1,
      symlinks: 0,
    },
  };
  const origin = await inspectFixtureBundle(paths.canonicalApp, "0.1.14");
  const candidateSourceDigest = (
    await inspectFixtureBundle(paths.candidateApp, "0.1.15")
  ).bundle.tree.digest;
  const stateFileBytes = await readFile(paths.controlPlanePath, "utf8");
  await writeFile(
    join(originBackupDirectory, "handoff-receipt.json"),
    `${JSON.stringify(priorHandoffReceipt(origin.bundle, state), null, 2)}\n`,
    { mode: 0o600 },
  );
  let keychainChecks = 0;
  const dependencies: ForwardRecoveryDependencies = {
    acquireControlPlaneLock: controlPlanePath => ({
      path: `${controlPlanePath}.lifetime.lock`,
      bindControlPlane() {
        return {
          controlPlanePath,
          stateRoot: { device: "1", inode: "1" },
          controlPlane: { device: "1", inode: "2" },
        };
      },
      release() {},
    }),
    acquireNativeLock: () => ({ release() {} }),
    assertKeychain(evidence) {
      expect(evidence.descriptors).toEqual(keychainDescriptors);
      keychainChecks += 1;
      return Promise.resolve();
    },
    captureKeychain(): Promise<KeychainEvidence> {
      return Promise.resolve({
        descriptors: keychainDescriptors,
        fingerprints: new Map([[keychainDescriptors[0], null]]),
        key: Buffer.alloc(32, 7),
      });
    },
    async copyTree(source, destination) {
      await cp(source, destination, { recursive: true, preserveTimestamps: true });
    },
    eraseKeychain(evidence) {
      evidence?.key.fill(0);
    },
    async inspectBundle(path) {
      return await inspectFixtureBundle(path);
    },
    async inspectCandidate(path) {
      return {
        ...await inspectFixtureBundle(path, "0.1.15"),
        custodyProbeSupervisor: testCustodyProbeSupervisorAuthority,
      } satisfies ForwardCandidateEvidence;
    },
    async inspectOrigin(path) {
      return await inspectFixtureBundle(path, "0.1.14");
    },
    inspectEnrollmentKeychainNoUi: () => Promise.resolve({ state: "absent" }),
    readEnrollmentSidecar: readHarnessKeyEnrollmentSidecar,
    writeEnrollmentSidecar: writeHarnessKeyEnrollmentSidecar,
    removeEnrollmentSidecar: removeExactHarnessKeyEnrollmentSidecar,
    async inspectState() {
      try {
        const bytes = await readFile(
          harnessKeyEnrollmentSidecarPath(paths.controlPlanePath),
        );
        return {
          ...state,
          tree: {
            ...state.tree,
            bytes: state.tree.bytes + bytes.byteLength,
            entries: state.tree.entries + 1,
            files: state.tree.files + 1,
            digest: createHash("sha256")
              .update(state.tree.digest, "utf8")
              .update(bytes)
              .digest("hex"),
          },
        };
      } catch (error: unknown) {
        if (error instanceof Error && "code" in error && error.code === "ENOENT") {
          return state;
        }
        throw error;
      }
    },
    inspectStateWithoutEnrollmentSidecar: () => Promise.resolve(state),
    now: () => 1_800_000_000_000,
    openFilesAreQuiescent: () => Promise.resolve(true),
    async publishForward(source, destination) {
      const temporary = join(dirname(source), `.swap-${basename(source)}`);
      await rename(source, temporary);
      await rename(destination, source);
      await rename(temporary, destination);
      return { status: "published" };
    },
    quitApplications: async () => {},
    randomBytes: () => new Uint8Array(12).fill(0xab),
    async stageForDeletion(source, tombstone) {
      await rename(source, tombstone);
    },
    syncStagedTree: async () => {},
    updaterIsQuiescent: () => Promise.resolve(true),
  };
  return {
    assertKeychainCalls: () => keychainChecks,
    backupDirectory,
    candidateSourceDigest,
    dependencies,
    originBackupDirectory,
    paths,
    state,
    stateFileBytes,
  };
}

async function createApp(
  path: string,
  version: string,
  build: string,
  commit: string,
  runtimeTreeSha256: string,
): Promise<void> {
  const runtime = join(path, "Contents", "Resources", "runtime");
  await mkdir(runtime, { recursive: true });
  await writeFile(join(path, "marker.txt"), `${version}/${build}\n`);
  await writeFile(join(runtime, "manifest.json"), `${JSON.stringify({
    schemaVersion: 1,
    release: { build: Number(build), commit, version },
    runtime: { treeSha256: runtimeTreeSha256 },
  })}\n`);
}

async function appVersion(path: string): Promise<string> {
  return (await readFile(join(path, "marker.txt"), "utf8")).trim().split("/")[0]!;
}

async function inspectFixtureBundle(
  path: string,
  expectedVersion?: "0.1.14" | "0.1.15",
): Promise<ForwardBundleEvidence> {
  const marker = (await readFile(join(path, "marker.txt"), "utf8")).trim();
  const [version, build] = marker.split("/");
  if (
    (version !== "0.1.14" && version !== "0.1.15")
    || build === undefined
    || (expectedVersion !== undefined && version !== expectedVersion)
  ) throw new Error("fixture bundle identity differs");
  const manifestPath = join(
    path,
    "Contents",
    "Resources",
    "runtime",
    "manifest.json",
  );
  const [root, manifestStatus, manifestBytes] = await Promise.all([
    lstat(path, { bigint: true }),
    lstat(manifestPath, { bigint: true }),
    readFile(manifestPath),
  ]);
  const manifest = JSON.parse(manifestBytes.toString("utf8")) as {
    release: { commit: string };
    runtime: { treeSha256: string };
  };
  const digest = createHash("sha256")
    .update(marker, "utf8")
    .update(manifestBytes)
    .digest("hex");
  const bundle: BundleContinuityEvidence = {
    identity: {
      build,
      bundleIdentifier: "kitchen.hraness",
      executable: "hra",
      version,
    },
    signature: { policy: "strict" },
    tree: {
      bytes: Buffer.byteLength(marker) + manifestBytes.byteLength,
      directories: 0,
      digest,
      entries: 2,
      files: 2,
      symlinks: 0,
    },
  };
  return {
    bundle,
    manifest: {
      bytes: manifestBytes.byteLength,
      commit: manifest.release.commit,
      device: manifestStatus.dev.toString(10),
      inode: manifestStatus.ino.toString(10),
      runtimeTreeSha256: manifest.runtime.treeSha256,
      sha256: createHash("sha256").update(manifestBytes).digest("hex"),
    },
    root: {
      device: root.dev.toString(10),
      inode: root.ino.toString(10),
    },
  };
}

function priorHandoffReceipt(
  candidate: BundleContinuityEvidence,
  state: StateContinuityEvidence,
): Record<string, unknown> {
  return {
    schemaVersion: 2,
    createdAt: 1,
    operationId: `handoff_${"a".repeat(24)}`,
    phase: "committed",
    candidateCommit: frozenHraV0114Origin.commit,
    hadPriorHra: false,
    state,
    predecessor: {
      identity: {
        build: "5",
        bundleIdentifier: "kitchen.hraness",
        executable: "oprte",
        version: "0.1.4",
      },
      signature: expectedHistoricalOprtePreviewSignature,
      tree: expectedHistoricalOprtePreviewTree,
    },
    candidate,
    keychainDescriptors,
  };
}

async function readForwardReceipt(
  backupDirectory: string,
): Promise<Record<string, unknown>> {
  return JSON.parse(
    await readFile(join(backupDirectory, "forward-recovery-receipt.json"), "utf8"),
  ) as Record<string, unknown>;
}
