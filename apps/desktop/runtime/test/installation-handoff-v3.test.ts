/* eslint-disable @typescript-eslint/await-thenable, @typescript-eslint/require-await --
 * Bun's async matchers and Promise-shaped inspection seams are intentionally awaited.
 */
import { afterEach, describe, expect, test } from "bun:test";
import {
  chmod,
  lstat,
  mkdir,
  mkdtemp,
  readFile,
  readdir,
  realpath,
  rename,
  rm,
  writeFile,
} from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";

import {
  advanceInstallationHandoffV3Progress,
  candidateStagePath,
  createInstallationHandoffV3Core,
  createInstallationHandoffV3Progress,
  installationHandoffV3CoreFileName,
  installationHandoffV3Paths,
  installationHandoffV3ProgressFileName,
  inspectExactCandidateV3,
  parseInstallationHandoffV3Core,
  parseInstallationHandoffV3Progress,
  predecessorRetirementStagePath,
  readInstallationHandoffV3Core,
  readInstallationHandoffV3EffectiveProgress,
  readInstallationHandoffV3Progress,
  reconcileInstallationHandoffV3PreparedTransition,
  recoverInstallationHandoffV3CorePublication,
  type InstallationHandoffV3Core,
  type InstallationHandoffV3Progress,
  type InstallationHandoffV3ProgressFile,
} from "../installation-handoff-v3";
import type {
  PublishedReleaseCandidateEvidence,
} from "../release-download-contract";
import {
  expectedHistoricalOprtePreviewIdentity,
  expectedHistoricalOprtePreviewSignature,
  expectedHistoricalOprtePreviewTree,
} from "../historical-oprte-preview";
import { digestHarnessKeyEnrollmentPreState } from
  "../src/state/harness-key-enrollment";
import { testCustodyProbeSupervisorAuthority } from
  "./fixtures/custody-probe-authority";

const roots: string[] = [];

afterEach(async () => {
  for (const root of roots.splice(0)) {
    await rm(root, { force: true, recursive: true });
  }
});

describe("schema-v3 installation handoff storage", () => {
  test("accepts only the exact ordinary authority and has no core self-cycle", async () => {
    const fixture = await createCoreFixture();
    const parsed = parseInstallationHandoffV3Core(fixture.core);
    expect(parsed).toEqual(fixture.core);
    expect(JSON.stringify(parsed)).not.toContain(
      installationHandoffV3CoreFileName,
    );

    const substituted = {
      ...fixture.core,
      candidate: {
        ...fixture.core.candidate,
        custodyProbeSupervisor: {
          ...fixture.core.candidate.custodyProbeSupervisor,
          designatedRequirement: "identifier substituted",
        },
      },
    };
    expect(() => parseInstallationHandoffV3Core(substituted)).toThrow(
      "Immutable schema-v3 handoff authorization is invalid",
    );

    const predecessorWithExtra = {
      ...fixture.core.predecessor,
      substituted: true,
    };
    expect(() => parseInstallationHandoffV3Core({
      ...fixture.core,
      predecessor: predecessorWithExtra,
    })).toThrow("Immutable schema-v3 handoff authorization is invalid");

    expect(() => parseInstallationHandoffV3Core({
      ...fixture.core,
      schemaVersion: 2,
    })).toThrow("Immutable schema-v3 handoff authorization is invalid");
  });

  test("rejects a hybrid candidate when the second full bundle scan changes", async () => {
    const root = await realpath(await mkdtemp(join(tmpdir(), "hra-v3-candidate-")));
    roots.push(root);
    const candidate = join(root, "HRA.app");
    const runtime = join(candidate, "Contents", "Resources", "runtime");
    await mkdir(runtime, { recursive: true, mode: 0o755 });
    const commit = "4".repeat(40);
    const runtimeTreeSha256 = "5".repeat(64);
    await writeFile(join(runtime, "manifest.json"), JSON.stringify({
      release: { commit },
      runtime: { treeSha256: runtimeTreeSha256 },
    }), { mode: 0o444 });
    const bundle = {
      identity: {
        build: "16",
        bundleIdentifier: "kitchen.hraness",
        executable: "hra",
        version: "0.1.15",
      },
      signature: { policy: "strict" as const },
      tree: treeEvidence("3"),
    };
    let scans = 0;
    expect(inspectExactCandidateV3(candidate, {
      async inspectBundleForTest() {
        scans += 1;
        return scans === 1
          ? bundle
          : { ...bundle, tree: treeEvidence("9") };
      },
      async verifyCandidateForTest() {
        return {
          commit,
          contract: undefined as never,
          custodyProbeSupervisor: testCustodyProbeSupervisorAuthority,
          repository: undefined as never,
          runtimeTreeSha256,
          tag: undefined as never,
        } satisfies PublishedReleaseCandidateEvidence;
      },
    })).rejects.toThrow("Candidate changed while its v3 authority was collected");
    expect(scans).toBe(2);
  });

  test("publishes the immutable core create-only from a durable candidate", async () => {
    const fixture = await createCoreFixture();
    const evidence = await createInstallationHandoffV3Core(
      fixture.root,
      fixture.core,
    );
    const path = join(fixture.root, installationHandoffV3CoreFileName);
    const status = await lstat(path, { bigint: true });
    expect(evidence).toMatchObject({
      bytes: Number(status.size),
      device: status.dev.toString(10),
      inode: status.ino.toString(10),
      path,
      schemaVersion: 3,
    });
    expect(Number(status.mode & 0o777n)).toBe(0o600);
    expect(status.nlink).toBe(1n);
    expect(await readInstallationHandoffV3Core(fixture.root, evidence))
      .toEqual({ core: fixture.core, evidence });

    const changed = {
      ...fixture.core,
      createdAt: fixture.core.createdAt + 1,
    };
    expect(createInstallationHandoffV3Core(fixture.root, changed)).rejects
      .toMatchObject({ code: "recovery_conflict" });
    expect(readInstallationHandoffV3Core(fixture.root, {
      ...evidence,
      path: join(fixture.root, "substituted-core.json"),
    })).rejects.toMatchObject({ code: "filesystem_unsafe" });
  });

  test("a crash before core publication cannot poison its immutable final name", async () => {
    const fixture = await createCoreFixture();
    expect(createInstallationHandoffV3Core(
      fixture.root,
      fixture.core,
      {
        afterCandidateSyncForTest() {
          throw new Error("crash:after-core-candidate-fsync");
        },
      },
    )).rejects.toThrow("crash:after-core-candidate-fsync");
    expect(lstat(join(fixture.root, installationHandoffV3CoreFileName)))
      .rejects.toMatchObject({ code: "ENOENT" });
    expect((await readdir(fixture.root)).some(name =>
      name.startsWith(`.${installationHandoffV3CoreFileName}.pending.`)
    )).toBeTrue();

    const recovered = await recoverInstallationHandoffV3CorePublication(
      fixture.root,
    );
    expect(recovered?.core).toEqual(fixture.core);
    expect((await readdir(fixture.root)).filter(name =>
      name.includes(".pending.")
    )).toEqual([]);
    const evidence = recovered!.evidence;
    expect((await readInstallationHandoffV3Core(fixture.root)).evidence)
      .toEqual(evidence);
  });

  test("pre-core recovery rejects unrecognized residue without removing it", async () => {
    const fixture = await createCoreFixture();
    const unknown = join(fixture.root, ".unknown-authority");
    await writeFile(unknown, "unknown", { mode: 0o600 });
    expect(recoverInstallationHandoffV3CorePublication(fixture.root))
      .rejects.toMatchObject({ code: "recovery_conflict" });
    expect(await readFile(unknown, "utf8")).toBe("unknown");
  });

  test("retry classifies an exact core renamed before parent fsync", async () => {
    const fixture = await createCoreFixture();
    expect(createInstallationHandoffV3Core(
      fixture.root,
      fixture.core,
      {
        afterRenameForTest() {
          throw new Error("crash:after-core-rename");
        },
      },
    )).rejects.toThrow("crash:after-core-rename");

    const evidence = await createInstallationHandoffV3Core(
      fixture.root,
      fixture.core,
    );
    expect((await readInstallationHandoffV3Core(fixture.root, evidence)).core)
      .toEqual(fixture.core);
  });

  test("never fsyncs a substituted private directory after core publication", async () => {
    const fixture = await createCoreFixture();
    const moved = `${fixture.root}.held`;
    roots.push(moved);
    expect(createInstallationHandoffV3Core(
      fixture.root,
      fixture.core,
      {
        async afterRenameForTest() {
          await rename(fixture.root, moved);
          await mkdir(fixture.root, { mode: 0o700 });
        },
      },
    )).rejects.toMatchObject({ code: "filesystem_unsafe" });
    expect(lstat(join(moved, installationHandoffV3CoreFileName))).resolves
      .toMatchObject({});
    expect(lstat(join(fixture.root, installationHandoffV3CoreFileName)))
      .rejects.toMatchObject({ code: "ENOENT" });
  });

  test("rejects a non-private backup directory on every storage entry", async () => {
    const fixture = await createCoreFixture();
    await chmod(fixture.root, 0o755);
    try {
      expect(createInstallationHandoffV3Core(fixture.root, fixture.core))
        .rejects.toMatchObject({ code: "filesystem_unsafe" });
      expect(readInstallationHandoffV3Core(fixture.root)).rejects
        .toMatchObject({ code: "filesystem_unsafe" });
    } finally {
      await chmod(fixture.root, 0o700);
    }
  });

  test("advances by exact CAS and retains every prior progress inode", async () => {
    const fixture = await createProgressFixture();
    const backedUp = nextProgress(fixture.current, "backed_up");
    const advanced = await advanceInstallationHandoffV3Progress(
      fixture.root,
      fixture.current,
      backedUp,
    );
    expect(advanced.progress).toEqual(backedUp);

    const historyPath = join(
      fixture.root,
      "handoff-progress-v3.history.created.json",
    );
    const historyStatus = await lstat(historyPath, { bigint: true });
    expect(historyStatus.dev.toString(10)).toBe(fixture.current.evidence.device);
    expect(historyStatus.ino.toString(10)).toBe(fixture.current.evidence.inode);
    expect(JSON.parse(await readFile(historyPath, "utf8"))).toEqual(
      fixture.current.progress,
    );
    expect(await readInstallationHandoffV3Progress(
      fixture.root,
      fixture.coreEvidence,
    )).toEqual(advanced);
  });

  test("recovers exact pre-swap and post-swap CAS crash cuts", async () => {
    const preSwap = await createProgressFixture();
    const backedUp = nextProgress(preSwap.current, "backed_up");
    expect(advanceInstallationHandoffV3Progress(
      preSwap.root,
      preSwap.current,
      backedUp,
      {
        beforeProgressPublishForTest() {
          throw new Error("crash:before-progress-swap");
        },
      },
    )).rejects.toThrow("crash:before-progress-swap");
    const recoveredPreSwap = await advanceInstallationHandoffV3Progress(
      preSwap.root,
      preSwap.current,
      backedUp,
    );
    expect(recoveredPreSwap.progress.phase).toBe("backed_up");

    const smoked = nextProgress(recoveredPreSwap, "smoked");
    expect(advanceInstallationHandoffV3Progress(
      preSwap.root,
      recoveredPreSwap,
      smoked,
      {
        afterProgressPublishForTest() {
          throw new Error("crash:after-progress-swap");
        },
      },
    )).rejects.toThrow("crash:after-progress-swap");
    const recoveredPostSwap = await advanceInstallationHandoffV3Progress(
      preSwap.root,
      recoveredPreSwap,
      smoked,
    );
    expect(recoveredPostSwap.progress.phase).toBe("smoked");
  });

  test("promotes the exact durable next-history candidate before alternate recovery", async () => {
    const fixture = await createProgressFixture();
    const backedUp = nextProgress(fixture.current, "backed_up");
    expect(advanceInstallationHandoffV3Progress(
      fixture.root,
      fixture.current,
      backedUp,
      {
        beforeProgressPublishForTest() {
          throw new Error("crash:history-fixed-before-swap");
        },
      },
    )).rejects.toThrow("crash:history-fixed-before-swap");
    const promoted = await reconcileInstallationHandoffV3PreparedTransition(
      fixture.root,
      fixture.current,
    );
    expect(promoted.kind).toBe("advanced");
    expect(promoted.progress.progress).toEqual(backedUp);
    const settled = await reconcileInstallationHandoffV3PreparedTransition(
      fixture.root,
      promoted.progress,
    );
    expect(settled).toEqual({ kind: "none", progress: promoted.progress });
  });

  test("reads a durable next-history leaf as effective without promoting it", async () => {
    const fixture = await createProgressFixture();
    const backedUp = nextProgress(fixture.current, "backed_up");
    const canonicalPath = join(
      fixture.root,
      installationHandoffV3ProgressFileName,
    );
    expect(advanceInstallationHandoffV3Progress(
      fixture.root,
      fixture.current,
      backedUp,
      {
        beforeProgressPublishForTest() {
          throw new Error("crash:durable-history-before-read-only-status");
        },
      },
    )).rejects.toThrow("crash:durable-history-before-read-only-status");
    const canonicalBefore = await readFile(canonicalPath);
    const first = await readInstallationHandoffV3EffectiveProgress(
      fixture.root,
      fixture.coreEvidence,
    );
    const second = await readInstallationHandoffV3EffectiveProgress(
      fixture.root,
      fixture.coreEvidence,
    );
    expect(first.source).toBe("durable_next_history");
    expect(first.canonical).toEqual(fixture.current);
    expect(first.effective.progress).toEqual(backedUp);
    expect(second).toEqual(first);
    expect(await readFile(canonicalPath)).toEqual(canonicalBefore);
    expect((await readInstallationHandoffV3Progress(
      fixture.root,
      fixture.coreEvidence,
    )).progress.phase).toBe("created");
  });

  test("runs the fixed-history proof after pending write and fsync immediately before rename", async () => {
    const fixture = await createProgressFixture();
    const backedUp = nextProgress(fixture.current, "backed_up");
    let afterHistoryPublication = false;
    await expect(advanceInstallationHandoffV3Progress(
      fixture.root,
      fixture.current,
      backedUp,
      {
        async beforeProgressCandidate() {
          const pendingNames = (await readdir(fixture.root)).filter((name) =>
            name.startsWith(
              ".handoff-progress-v3.history.created.json.pending.",
            )
          );
          expect(pendingNames).toHaveLength(1);
          expect(JSON.parse(await readFile(
            join(fixture.root, pendingNames[0]!),
            "utf8",
          ))).toEqual(backedUp);
          expect((await readdir(fixture.root))).not.toContain(
            "handoff-progress-v3.history.created.json",
          );
          throw new Error("crash:descriptor-bound-before-fixed-history");
        },
        beforeProgressPublishForTest() {
          afterHistoryPublication = true;
        },
      },
    )).rejects.toThrow("crash:descriptor-bound-before-fixed-history");
    expect(afterHistoryPublication).toBe(false);
    expect((await readInstallationHandoffV3Progress(
      fixture.root,
      fixture.coreEvidence,
    )).progress.phase).toBe("created");
    expect((await readdir(fixture.root))).not.toContain(
      "handoff-progress-v3.history.created.json",
    );
    expect((await readdir(fixture.root)).filter(name =>
      name.startsWith(
        ".handoff-progress-v3.history.created.json.pending.",
      )
    )).toEqual([]);
    expect((await advanceInstallationHandoffV3Progress(
      fixture.root,
      fixture.current,
      backedUp,
    )).progress).toEqual(backedUp);
  });

  test("revalidates at the descriptor-bound progress swap after fixed-history fsync", async () => {
    const fixture = await createProgressFixture();
    const backedUp = nextProgress(fixture.current, "backed_up");
    const historyPath = join(
      fixture.root,
      "handoff-progress-v3.history.created.json",
    );
    const order: string[] = [];
    expect(advanceInstallationHandoffV3Progress(
      fixture.root,
      fixture.current,
      backedUp,
      {
        async beforeProgressCandidate() {
          const pendingNames = (await readdir(fixture.root)).filter((name) =>
            name.startsWith(
              ".handoff-progress-v3.history.created.json.pending.",
            )
          );
          expect(pendingNames).toHaveLength(1);
          expect(JSON.parse(await readFile(
            join(fixture.root, pendingNames[0]!),
            "utf8",
          ))).toEqual(backedUp);
          expect((await readdir(fixture.root))).not.toContain(
            "handoff-progress-v3.history.created.json",
          );
          order.push("descriptor-bound-before-fixed-history");
        },
        async beforeProgressPublishForTest() {
          expect(JSON.parse(await readFile(historyPath, "utf8"))).toEqual(
            backedUp,
          );
          order.push("fixed-history-durable");
        },
        async beforeProgressSwap() {
          expect(JSON.parse(await readFile(historyPath, "utf8"))).toEqual(
            backedUp,
          );
          order.push("descriptor-bound-before-swap");
          throw new Error("crash:descriptor-bound-before-swap");
        },
      },
    )).rejects.toThrow("crash:descriptor-bound-before-swap");
    expect(order).toEqual([
      "descriptor-bound-before-fixed-history",
      "fixed-history-durable",
      "descriptor-bound-before-swap",
    ]);
    expect((await readInstallationHandoffV3EffectiveProgress(
      fixture.root,
      fixture.coreEvidence,
    )).effective.progress).toEqual(backedUp);
  });

  test("holds the exact backup directory across progress swap and fsync", async () => {
    const fixture = await createProgressFixture();
    const backedUp = nextProgress(fixture.current, "backed_up");
    const moved = `${fixture.root}.held`;
    roots.push(moved);
    expect(advanceInstallationHandoffV3Progress(
      fixture.root,
      fixture.current,
      backedUp,
      {
        async afterProgressSwapBeforeSyncForTest() {
          await rename(fixture.root, moved);
          await mkdir(fixture.root, { mode: 0o700 });
        },
      },
    )).rejects.toMatchObject({ code: "filesystem_unsafe" });
    expect(JSON.parse(await readFile(
      join(moved, installationHandoffV3ProgressFileName),
      "utf8",
    ))).toMatchObject({ phase: "backed_up" });
    expect(lstat(join(fixture.root, installationHandoffV3ProgressFileName)))
      .rejects.toMatchObject({ code: "ENOENT" });
  });

  test("retries a crash after the progress swap but before parent fsync", async () => {
    const fixture = await createProgressFixture();
    const backedUp = nextProgress(fixture.current, "backed_up");
    expect(advanceInstallationHandoffV3Progress(
      fixture.root,
      fixture.current,
      backedUp,
      {
        afterProgressSwapBeforeSyncForTest() {
          throw new Error("crash:after-swap-before-fsync");
        },
      },
    )).rejects.toThrow("crash:after-swap-before-fsync");
    const recovered = await advanceInstallationHandoffV3Progress(
      fixture.root,
      fixture.current,
      backedUp,
    );
    expect(recovered.progress.phase).toBe("backed_up");
  });

  test("restart reconciliation fsyncs an already-swapped canonical parent", async () => {
    const fixture = await createProgressFixture();
    const backedUp = nextProgress(fixture.current, "backed_up");
    await expect(advanceInstallationHandoffV3Progress(
      fixture.root,
      fixture.current,
      backedUp,
      {
        afterProgressSwapBeforeSyncForTest() {
          throw new Error("crash:process-exit-before-parent-fsync");
        },
      },
    )).rejects.toThrow("crash:process-exit-before-parent-fsync");
    const loadedAfterRestart = await readInstallationHandoffV3Progress(
      fixture.root,
      fixture.coreEvidence,
    );
    expect(loadedAfterRestart.progress).toEqual(backedUp);
    const order: string[] = [];
    const reconciled = await reconcileInstallationHandoffV3PreparedTransition(
      fixture.root,
      loadedAfterRestart,
      {
        afterDirectorySyncForTest() {
          order.push("held-parent-synced");
        },
      },
    );
    order.push("subsequent-work");
    expect(reconciled).toMatchObject({
      kind: "none",
      progress: { progress: backedUp },
    });
    expect(order).toEqual(["held-parent-synced", "subsequent-work"]);
  });

  test("rejects a conflicting durable pre-swap progress candidate", async () => {
    const fixture = await createProgressFixture();
    const backedUp = nextProgress(fixture.current, "backed_up");
    expect(advanceInstallationHandoffV3Progress(
      fixture.root,
      fixture.current,
      backedUp,
      {
        beforeProgressPublishForTest() {
          throw new Error("crash:before-swap");
        },
      },
    )).rejects.toThrow("crash:before-swap");
    const historyPath = join(
      fixture.root,
      "handoff-progress-v3.history.created.json",
    );
    await writeFile(historyPath, `${JSON.stringify({
      ...backedUp,
      phase: "smoked",
    }, null, 2)}\n`, { mode: 0o600 });
    expect(advanceInstallationHandoffV3Progress(
      fixture.root,
      fixture.current,
      backedUp,
    )).rejects.toThrow(
      "Retained handoff progress history conflicts with the next CAS value",
    );
  });

  test("enforces monotone sidecar evidence and terminal rollback", async () => {
    const fixture = await createProgressFixture();
    expect(() => parseInstallationHandoffV3Progress({
      ...fixture.current.progress,
      phase: "enrollment_authorized",
    })).toThrow("Schema-v3 handoff progress is invalid");
    expect(() => parseInstallationHandoffV3Progress({
      ...fixture.current.progress,
      authorizedSidecar: enrollmentEvidence("a"),
      candidateStage: null,
      keychainContinuity: "not_applicable",
      phase: "rolled_back",
    })).toThrow("Schema-v3 handoff progress is invalid");

    expect(advanceInstallationHandoffV3Progress(
      fixture.root,
      fixture.current,
      nextProgress(fixture.current, "smoked"),
    )).rejects.toThrow("Handoff progress transition is not monotone");
    const backedUp = await advanceInstallationHandoffV3Progress(
      fixture.root,
      fixture.current,
      nextProgress(fixture.current, "backed_up"),
    );
    expect(advanceInstallationHandoffV3Progress(
      fixture.root,
      backedUp,
      nextProgress(backedUp, "created"),
    )).rejects.toThrow("Handoff progress transition is not monotone");

    const rolledBack = nextProgress(backedUp, "rolled_back");
    const terminal = await advanceInstallationHandoffV3Progress(
      fixture.root,
      backedUp,
      rolledBack,
    );
    expect(terminal.progress.phase).toBe("rolled_back");
    expect(advanceInstallationHandoffV3Progress(
      fixture.root,
      terminal,
      {
        ...terminal.progress,
        keychainContinuity: "pending_same_process",
        phase: "created",
      },
    )).rejects.toThrow("Rolled-back handoff progress is terminal");
  });

  test("rejects rollback at the durable boundary and sidecar evidence drift", async () => {
    const fixture = await createProgressFixture();
    let current = fixture.current;
    for (const phase of [
      "backed_up",
      "smoked",
      "bundles_archived",
      "candidate_staged",
      "enrollment_authorizing",
      "enrollment_authorized",
      "candidate_publish_prepared",
    ] as const) {
      current = await advanceInstallationHandoffV3Progress(
        fixture.root,
        current,
        {
          ...current.progress,
          authorizedSidecar: phase === "enrollment_authorized"
              || current.progress.authorizedSidecar !== null
            ? enrollmentEvidence("a")
            : null,
          candidateStage: phase === "candidate_staged"
              || current.progress.candidateStage !== null
            ? fixture.core.candidate
            : null,
          phase,
        },
      );
    }
    expect(advanceInstallationHandoffV3Progress(
      fixture.root,
      current,
      {
        ...current.progress,
        authorizedSidecar: null,
        candidateStage: null,
        keychainContinuity: "not_applicable",
        phase: "rolled_back",
      },
    )).rejects.toThrow(
      "Rollback cannot cross the durable candidate publication boundary",
    );
    expect(advanceInstallationHandoffV3Progress(
      fixture.root,
      current,
      {
        ...current.progress,
        authorizedSidecar: enrollmentEvidence("b"),
        phase: "candidate_installed",
      },
    )).rejects.toThrow("Schema-v3 handoff progress is invalid");
  });
});

async function createCoreFixture(): Promise<Readonly<{
  core: InstallationHandoffV3Core;
  root: string;
}>> {
  const root = await realpath(await mkdtemp(join(tmpdir(), "hra-handoff-v3-")));
  roots.push(root);
  await chmod(root, 0o700);
  const operationId = `handoff_${"a".repeat(24)}`;
  const preState = {
    accountHomes: 1,
    chatWorktreeLanes: 2,
    database: {
      databaseSha256: "1".repeat(64),
      migrationVersion: 62,
      quickCheck: "ok" as const,
      rows: { account_profiles: 1, schema_migrations: 62 },
    },
    dispatchWorktreeLanes: 3,
    harnessWorktreeLanes: 4,
    localTaskWorktreeLanes: 5,
    sessionEntries: 6,
    tree: treeEvidence("2"),
  };
  const applicationsDirectory = join(root, "Applications");
  const basePaths = {
    applicationsDirectory,
    candidateApp: join(root, "HRA-candidate.app"),
    canonicalApp: join(applicationsDirectory, "HRA.app"),
    controlPlanePath: join(root, "state", "control-plane.sqlite"),
    nativeInstanceLockPath: join(root, "state", ".native.lock"),
    predecessorApp: join(applicationsDirectory, "OPRTE.app"),
    sparkleCacheRoots: [join(root, "Sparkle")],
    stateRoot: join(root, "state"),
    updateHazardPath: join(root, "state", "update-hazard.json"),
    updateHazardTemporaryPath: join(root, "state", ".update-hazard.tmp"),
  };
  const paths = installationHandoffV3Paths(basePaths, root, operationId);
  expect(paths.candidateStage).toBe(
    candidateStagePath(applicationsDirectory, operationId),
  );
  expect(paths.predecessorRetirementStage).toBe(
    predecessorRetirementStagePath(applicationsDirectory, operationId),
  );
  const core: InstallationHandoffV3Core = {
    candidate: {
      bundle: {
        identity: {
          build: "16",
          bundleIdentifier: "kitchen.hraness",
          executable: "hra",
          version: "0.1.15",
        },
        signature: { policy: "strict" },
        tree: treeEvidence("3"),
      },
      custodyProbeSupervisor: testCustodyProbeSupervisorAuthority,
      manifest: {
        bytes: 2_048,
        commit: "4".repeat(40),
        device: "7",
        inode: "8",
        runtimeTreeSha256: "5".repeat(64),
        sha256: "6".repeat(64),
      },
      root: { device: "9", inode: "10" },
    },
    createdAt: 1_800_000_000_000,
    keychainDescriptors: ["hra-install-key\0service"],
    kind: "hra-installation-handoff-authorization",
    operationId,
    paths,
    predecessor: {
      identity: expectedHistoricalOprtePreviewIdentity,
      signature: expectedHistoricalOprtePreviewSignature,
      tree: expectedHistoricalOprtePreviewTree,
    },
    preState,
    preStateSha256: digestHarnessKeyEnrollmentPreState(preState),
    priorHra: {
      identity: {
        build: "15",
        bundleIdentifier: "kitchen.hraness",
        executable: "hra",
        version: "0.1.14",
      },
      signature: { policy: "strict" },
      tree: treeEvidence("7"),
    },
    schemaVersion: 3,
  };
  return { core, root };
}

async function createProgressFixture(): Promise<Readonly<{
  core: InstallationHandoffV3Core;
  coreEvidence: Awaited<ReturnType<typeof createInstallationHandoffV3Core>>;
  current: InstallationHandoffV3ProgressFile;
  root: string;
}>> {
  const fixture = await createCoreFixture();
  const coreEvidence = await createInstallationHandoffV3Core(
    fixture.root,
    fixture.core,
  );
  const current = await createInstallationHandoffV3Progress(fixture.root, {
    authorizedSidecar: null,
    candidateStage: null,
    core: coreEvidence,
    keychainContinuity: "pending_same_process",
    phase: "created",
    schemaVersion: 3,
  });
  const status = await lstat(
    join(fixture.root, installationHandoffV3ProgressFileName),
    { bigint: true },
  );
  expect(Number(status.mode & 0o777n)).toBe(0o600);
  return { core: fixture.core, coreEvidence, current, root: fixture.root };
}

function nextProgress(
  current: InstallationHandoffV3ProgressFile,
  phase: InstallationHandoffV3Progress["phase"],
): InstallationHandoffV3Progress {
  return phase === "rolled_back"
    ? {
        ...current.progress,
        authorizedSidecar: null,
        candidateStage: null,
        keychainContinuity: "not_applicable",
        phase,
      }
    : { ...current.progress, phase };
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

function enrollmentEvidence(digit: string) {
  return {
    bytes: 1_024,
    device: "11",
    inode: "12",
    sha256: digit.repeat(64),
  };
}
