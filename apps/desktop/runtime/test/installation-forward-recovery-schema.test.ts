import { describe, expect, test } from "bun:test";

import {
  frozenHraV0114Origin,
  parseForwardRecoveryReceipt,
} from "../installation-forward-recovery";
import {
  authorizedHarnessKeyEnrollmentSidecar,
  createForwardHarnessKeyEnrollmentAuthorization,
} from "../src/state/harness-key-enrollment";
import {
  testCustodyProbeSupervisorAuthority,
} from "./fixtures/custody-probe-authority";

const operationId = `forward_${"a".repeat(24)}`;
const tree = {
  bytes: 1,
  directories: 0,
  digest: "a".repeat(64),
  entries: 1,
  files: 1,
  symlinks: 0,
};
const originBundle = {
  identity: frozenHraV0114Origin.identity,
  signature: { policy: "strict" },
  tree,
};

export function forwardReceiptFixture(): Record<string, unknown> {
  const state = {
    accountHomes: 0,
    chatWorktreeLanes: 0,
    database: {
      databaseSha256: "b".repeat(64),
      migrationVersion: 62,
      quickCheck: "ok" as const,
      rows: {},
    },
    dispatchWorktreeLanes: 0,
    harnessWorktreeLanes: 0,
    localTaskWorktreeLanes: 0,
    sessionEntries: 0,
    tree,
  };
  const origin = {
    bundle: originBundle,
    manifest: {
      bytes: 100,
      commit: frozenHraV0114Origin.commit,
      device: "9007199254740993",
      inode: "9007199254740995",
      runtimeTreeSha256: frozenHraV0114Origin.runtimeTreeSha256,
      sha256: "c".repeat(64),
    },
    root: { device: "9007199254740993", inode: "9007199254740994" },
  };
  const candidate = {
    bundle: {
      identity: {
        build: "16",
        bundleIdentifier: "kitchen.hraness",
        executable: "hra",
        version: "0.1.15",
      },
      signature: { policy: "strict" as const },
      tree: { ...tree, digest: "d".repeat(64) },
    },
    custodyProbeSupervisor: testCustodyProbeSupervisorAuthority,
    manifest: {
      bytes: 101,
      commit: "e".repeat(40),
      device: "9007199254740997",
      inode: "9007199254740999",
      runtimeTreeSha256: "f".repeat(64),
      sha256: "1".repeat(64),
    },
    root: { device: "9007199254740997", inode: "9007199254740998" },
  };
  const committedOriginReceipt = {
    backupDirectory: "/private/tmp/hra-v14-handoff",
    bundle: originBundle,
    bytes: 1000,
    device: "9007199254741001",
    inode: "9007199254741002",
    operationId: `handoff_${"2".repeat(24)}`,
    sha256: "3".repeat(64),
  };
  const authorizedSidecar = authorizedHarnessKeyEnrollmentSidecar(
    createForwardHarnessKeyEnrollmentAuthorization({
      operationId,
      committedOriginReceipt,
      candidate,
      preState: state,
    }),
  );
  return {
    schemaVersion: 1,
    createdAt: 1,
    operationId,
    paths: {
      applicationsDirectory: "/Applications",
      candidateApp: "/private/tmp/HRA-candidate.app",
      canonicalApp: "/Applications/HRA.app",
      predecessorApp: "/Applications/OPRTE.app",
      stateRoot: "/Users/test/Library/Application Support/OPRTE",
      controlPlanePath:
        "/Users/test/Library/Application Support/OPRTE/control-plane.sqlite",
      nativeInstanceLockPath:
        "/Users/test/Library/Application Support/OPRTE/.native.lock",
      updateHazardPath:
        "/Users/test/Library/Application Support/OPRTE/update.json",
      updateHazardTemporaryPath:
        "/Users/test/Library/Application Support/OPRTE/.update.tmp",
      sparkleCacheRoots: ["/Users/test/Library/Caches/kitchen.hraness/Sparkle"],
      cleanupTombstoneApp:
        `/private/tmp/hra-forward-backup/retired-${operationId}.app`,
      forwardBackupDirectory: "/private/tmp/hra-forward-backup",
      retiredOriginApp: `/Applications/.${operationId}.forward-candidate.app`,
    },
    preState: state,
    state: {
      ...state,
      tree: {
        ...state.tree,
        bytes: state.tree.bytes + 512,
        entries: state.tree.entries + 1,
        files: state.tree.files + 1,
        digest: "7".repeat(64),
      },
    },
    origin,
    candidate,
    committedOriginReceipt,
    keychainDescriptors: ["service\u0000name"],
    enrollment: {
      authorizedSidecar,
      file: {
        bytes: 512,
        device: "9007199254741010",
        inode: "9007199254741011",
        sha256: "8".repeat(64),
      },
    },
    phase: "prepared",
    keychainContinuity: "pending_same_process",
  };
}

describe("forward-recovery receipt schema v1", () => {
  test("accepts exact B14 origin, B15 candidate, migration 62, and decimal vnode strings", () => {
    expect(parseForwardRecoveryReceipt(forwardReceiptFixture())).toMatchObject({
      schemaVersion: 1,
      phase: "prepared",
      operationId,
      origin: { bundle: originBundle },
    });
  });

  test("rejects schema drift, unsafe vnode numbers, stale migration, and path drift", () => {
    const mutations = [
      { schemaVersion: 2 },
      { origin: { ...(forwardReceiptFixture()["origin"] as object), root: {
        device: Number.MAX_SAFE_INTEGER + 1,
        inode: "9007199254740994",
      } } },
      { state: {
        ...(forwardReceiptFixture()["state"] as object),
        database: {
          ...((forwardReceiptFixture()["state"] as Record<string, unknown>)["database"] as object),
          migrationVersion: 61,
        },
      } },
      { paths: {
        ...(forwardReceiptFixture()["paths"] as object),
        retiredOriginApp: "/Applications/.forward_bad.forward-candidate.app",
      } },
    ];
    for (const mutation of mutations) {
      expect(() => parseForwardRecoveryReceipt({
        ...forwardReceiptFixture(),
        ...mutation,
      })).toThrow("Forward-recovery receipt is invalid");
    }
  });

  test("binds canonical B14 to the exact committed schema-v2 candidate tree", () => {
    const receipt = forwardReceiptFixture();
    receipt["committedOriginReceipt"] = {
      ...(receipt["committedOriginReceipt"] as object),
      bundle: {
        ...originBundle,
        tree: { ...tree, digest: "4".repeat(64) },
      },
    };
    expect(() => parseForwardRecoveryReceipt(receipt)).toThrow(
      "Forward-recovery receipt is invalid",
    );
  });

  test("models phase and Keychain truth as one strict union", () => {
    for (const [phase, keychainContinuity] of [
      ["verified", "unavailable_after_process_restart"],
      ["aborted", "verified_same_process"],
      ["complete", "pending_same_process"],
    ] as const) {
      expect(() => parseForwardRecoveryReceipt({
        ...forwardReceiptFixture(),
        phase,
        keychainContinuity,
      })).toThrow("Forward-recovery receipt is invalid");
    }
  });

  test("rejects unknown and prototype-pollution keys at every depth", () => {
    expect(() => parseForwardRecoveryReceipt({
      ...forwardReceiptFixture(),
      extra: true,
    })).toThrow("Forward-recovery receipt is invalid");
    const receipt = forwardReceiptFixture();
    Object.defineProperty(receipt["state"] as object, "__proto__", {
      enumerable: true,
      value: { polluted: true },
    });
    expect(() => parseForwardRecoveryReceipt(receipt)).toThrow(
      "Forward-recovery receipt is invalid",
    );
  });
});
