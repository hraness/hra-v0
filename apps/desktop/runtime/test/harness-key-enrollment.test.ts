import { createHash } from "node:crypto";
import { appendFileSync } from "node:fs";
import {
  chmod,
  link,
  lstat,
  mkdtemp,
  readFile,
  realpath,
  rm,
  symlink,
  unlink,
  writeFile,
} from
  "node:fs/promises";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";

import { afterEach, describe, expect, test } from "bun:test";

import {
  HarnessKeyEnrollmentError,
  authorizedHarnessKeyEnrollmentSidecar,
  canonicalHarnessKeyEnrollmentSidecar,
  createForwardHarnessKeyEnrollmentAuthorization,
  createInstallationHandoffV3EnrollmentAuthorization,
  digestCanonicalEvidence,
  digestHarnessKeyEnrollmentPreState,
  ensureHarnessKeyEnrollment,
  harnessKeyEnrollmentSidecarPath,
  installationHandoffV3EnrollmentAuthorizationMatches,
  parseHarnessKeyEnrollmentSidecar,
  readHarnessKeyEnrollmentSidecar,
  removeExactHarnessKeyEnrollmentSidecar,
  writeHarnessKeyEnrollmentSidecar,
  type HarnessKeyEnrollmentKeychain,
  type HarnessKeyEnrollmentObservation,
} from "../src/state/harness-key-enrollment";
import {
  testCustodyProbeSupervisorAuthority,
} from "./fixtures/custody-probe-authority";
import { validateHarnessKeyEnrollmentProtectedFiles } from
  "../src/state/application-support";
import {
  HARNESS_INSTALL_MASTER_KEY_BYTES,
  serializeHarnessInstallMaster,
} from "../src/harness/key-custody";

const roots: string[] = [];
const supportedPriorHraIdentities = [
  { build: "8", version: "0.1.7" },
  { build: "9", version: "0.1.8" },
  { build: "10", version: "0.1.9" },
  { build: "11", version: "0.1.10" },
  { build: "13", version: "0.1.12" },
  { build: "14", version: "0.1.13" },
  { build: "15", version: "0.1.14" },
] as const;

afterEach(async () => {
  for (const root of roots.splice(0)) {
    await rm(root, { force: true, recursive: true });
  }
});

describe("Harness key enrollment", () => {
  test("fresh empty state enrolls once through create-only custody", async () => {
    const controlPlanePath = await emptyControlPlanePath();
    const envelope = fixtureEnvelope(7);
    const events: string[] = [];
    let present = false;
    const keychain: HarnessKeyEnrollmentKeychain = {
      inspectExactNoUi: () => {
        events.push("inspect");
        return Promise.resolve(present
          ? { state: "present", envelope, strictAcl: true }
          : { state: "absent", strictAcl: false });
      },
      createExactIfAbsentNoUi: (attempted) => {
        events.push("create");
        expect(attempted).toBe(envelope);
        present = true;
        return Promise.resolve({
          created: true,
          envelope,
          strictAcl: true,
        });
      },
    };
    const enrolled = await ensureHarnessKeyEnrollment({
      allowFreshAuthorization: true,
      controlPlanePath,
      keychain,
      randomBytes: deterministicRandom(7),
    });
    expect(enrolled.sidecar.phase).toBe("enrolled");
    expect(enrolled.sidecar.authorization.kind).toBe("fresh_install_v1");
    expect(events).toEqual(["inspect", "inspect", "create", "inspect"]);
    expect((await lstat(harnessKeyEnrollmentSidecarPath(controlPlanePath))).mode & 0o777)
      .toBe(0o600);

    events.length = 0;
    const repeated = await ensureHarnessKeyEnrollment({
      allowFreshAuthorization: false,
      controlPlanePath,
      keychain,
    });
    expect(repeated.evidence).toEqual(enrolled.evidence);
    expect(events).toEqual(["inspect"]);
  });

  test("missing authorization rejects existing product state and preseeded custody", async () => {
    const controlPlanePath = await emptyControlPlanePath();
    await writeFile(controlPlanePath, "not opened", { mode: 0o600 });
    const keychain = fixtureKeychain({
      state: "present",
      envelope: fixtureEnvelope(1),
      strictAcl: false,
    });
    expect(ensureHarnessKeyEnrollment({
      allowFreshAuthorization: false,
      controlPlanePath,
      keychain,
    })).rejects.toMatchObject({
      code: "authorization_missing",
    });
    expect(keychain.createCalls).toBe(0);
  });

  test("forward-authorized state rejects every pre-existing item", async () => {
    const controlPlanePath = await emptyControlPlanePath();
    await writeForwardAuthorized(controlPlanePath);
    const keychain = fixtureKeychain({
      state: "present",
      envelope: fixtureEnvelope(2),
      strictAcl: true,
    });
    expect(ensureHarnessKeyEnrollment({
      allowFreshAuthorization: false,
      controlPlanePath,
      keychain,
    })).rejects.toMatchObject({ code: "custody_conflict" });
    expect(keychain.createCalls).toBe(0);
  });

  test("prepared matching strict custody finalizes without recreating", async () => {
    const controlPlanePath = await emptyControlPlanePath();
    const envelope = fixtureEnvelope(3);
    await writePrepared(controlPlanePath, envelope);
    const keychain = fixtureKeychain({ state: "present", envelope, strictAcl: true });
    const enrolled = await ensureHarnessKeyEnrollment({
      allowFreshAuthorization: false,
      controlPlanePath,
      keychain,
    });
    expect(enrolled.sidecar.phase).toBe("enrolled");
    expect(keychain.createCalls).toBe(0);
  });

  test("prepared different or permissive custody fails closed", async () => {
    for (const observation of [
      {
        state: "present" as const,
        envelope: fixtureEnvelope(5),
        strictAcl: true as const,
      },
      {
        state: "present" as const,
        envelope: fixtureEnvelope(4),
        strictAcl: false as const,
      },
    ]) {
      const controlPlanePath = await emptyControlPlanePath();
      await writePrepared(controlPlanePath, fixtureEnvelope(4));
      const keychain = fixtureKeychain(observation);
      expect(ensureHarnessKeyEnrollment({
        allowFreshAuthorization: false,
        controlPlanePath,
        keychain,
      })).rejects.toMatchObject({ code: "custody_conflict" });
      expect(keychain.createCalls).toBe(0);
    }
  });

  test("prepared absent custody starts a fresh attempt and requires created true", async () => {
    const controlPlanePath = await emptyControlPlanePath();
    await writePrepared(controlPlanePath, fixtureEnvelope(6));
    const keychain = fixtureKeychain({ state: "absent", strictAcl: false }, false);
    expect(ensureHarnessKeyEnrollment({
      allowFreshAuthorization: false,
      controlPlanePath,
      keychain,
      randomBytes: deterministicRandom(8),
    })).rejects.toMatchObject({ code: "custody_conflict" });
    expect(keychain.createCalls).toBe(1);
    expect((await readHarnessKeyEnrollmentSidecar(controlPlanePath))?.sidecar.phase)
      .toBe("prepared");
  });

  test("enrolled custody never regenerates a missing item", async () => {
    const controlPlanePath = await emptyControlPlanePath();
    const envelope = fixtureEnvelope(9);
    const prepared = await writePrepared(controlPlanePath, envelope);
    await writeHarnessKeyEnrollmentSidecar(
      controlPlanePath,
      { ...prepared.sidecar, phase: "enrolled" },
      prepared,
    );
    const keychain = fixtureKeychain({ state: "absent", strictAcl: false });
    expect(ensureHarnessKeyEnrollment({
      allowFreshAuthorization: false,
      controlPlanePath,
      keychain,
    })).rejects.toMatchObject({ code: "custody_conflict" });
    expect(keychain.createCalls).toBe(0);
  });

  test("exact removal refuses replacement and removes only the bound inode", async () => {
    const controlPlanePath = await emptyControlPlanePath();
    const expected = await writeForwardAuthorized(controlPlanePath);
    const path = harnessKeyEnrollmentSidecarPath(controlPlanePath);
    await unlink(path);
    await writeFile(path, canonicalHarnessKeyEnrollmentSidecar(expected.sidecar), {
      mode: 0o600,
    });
    expect(removeExactHarnessKeyEnrollmentSidecar(controlPlanePath, expected))
      .rejects.toMatchObject({ code: "custody_conflict" });

    const replacement = await readHarnessKeyEnrollmentSidecar(controlPlanePath);
    expect(replacement).not.toBeNull();
    await removeExactHarnessKeyEnrollmentSidecar(controlPlanePath, replacement!);
    expect(await readHarnessKeyEnrollmentSidecar(controlPlanePath)).toBeNull();
  });

  test("sidecar rejects noncanonical bytes, unsafe mode, symlink, and hard link", async () => {
    for (const unsafe of ["noncanonical", "mode", "symlink", "hardlink"] as const) {
      const controlPlanePath = await emptyControlPlanePath();
      const path = harnessKeyEnrollmentSidecarPath(controlPlanePath);
      const sidecar = forwardAuthorizedSidecar();
      if (unsafe === "noncanonical") {
        await writeFile(path, JSON.stringify(sidecar), { mode: 0o600 });
      } else if (unsafe === "mode") {
        await writeFile(path, canonicalHarnessKeyEnrollmentSidecar(sidecar), {
          mode: 0o644,
        });
        await chmod(path, 0o644);
      } else if (unsafe === "symlink") {
        const target = join(dirname(path), "target");
        await writeFile(target, canonicalHarnessKeyEnrollmentSidecar(sidecar), {
          mode: 0o600,
        });
        await symlink(target, path);
      } else {
        const target = join(dirname(path), "target");
        await writeFile(target, canonicalHarnessKeyEnrollmentSidecar(sidecar), {
          mode: 0o600,
        });
        await link(target, path);
      }
      expect(readHarnessKeyEnrollmentSidecar(controlPlanePath))
        .rejects.toBeInstanceOf(HarnessKeyEnrollmentError);
    }
  });

  test("schema rejects unknown fields and impossible phase payloads", () => {
    const authorized = forwardAuthorizedSidecar();
    expect(() => parseHarnessKeyEnrollmentSidecar({
      ...authorized,
      unexpected: true,
    })).toThrow();
    expect(() => parseHarnessKeyEnrollmentSidecar({
      ...authorized,
      phase: "enrolled",
    })).toThrow();
    expect(() => parseHarnessKeyEnrollmentSidecar({
      ...authorized,
      phase: "prepared",
      attempt: { envelopeSha256: "0".repeat(64), nonce: "0".repeat(63) },
    })).toThrow();
  });

  test("forward authorization freezes the exact supervisor DR and signer", () => {
    for (const mutate of [
      (authority: Record<string, unknown>) => {
        authority["designatedRequirement"] = "identifier substituted";
      },
      (authority: Record<string, unknown>) => {
        authority["signing"] = {
          ...testCustodyProbeSupervisorAuthority.signing,
          authority: "substituted-release-authority",
        };
      },
    ]) {
      const sidecar = structuredClone(forwardAuthorizedSidecar()) as unknown as
        Record<string, unknown>;
      const authorization = sidecar["authorization"] as Record<string, unknown>;
      const candidate = authorization["candidate"] as Record<string, unknown>;
      const authority = candidate["custodyProbeSupervisor"] as
        Record<string, unknown>;
      mutate(authority);
      expect(() => parseHarnessKeyEnrollmentSidecar(sidecar)).toThrow(
        "Harness key enrollment sidecar is invalid",
      );
    }
  });

  test("schema-v3 authorization accepts only exact supported prior HRA pairs", () => {
    for (const identity of supportedPriorHraIdentities) {
      expect(installationHandoffV3AuthorizedSidecar(identity)).toMatchObject({
        authorization: {
          kind: "installation_handoff_v3",
          priorHra: { identity },
        },
        phase: "authorized",
      });
    }

    const valid = installationHandoffV3AuthorizedSidecar(
      supportedPriorHraIdentities[0],
    );
    if (valid.authorization.kind !== "installation_handoff_v3") {
      throw new Error("expected schema-v3 enrollment fixture");
    }
    const priorHra = valid.authorization.priorHra;
    if (priorHra === null) throw new Error("expected prior HRA fixture");
    for (const identity of [
      { build: "9", version: "0.1.7" },
      { build: "12", version: "0.1.11" },
      { build: "16", version: "0.1.15" },
    ]) {
      expect(() => parseHarnessKeyEnrollmentSidecar({
        ...valid,
        authorization: {
          ...valid.authorization,
          priorHra: {
            ...priorHra,
            identity: {
              ...priorHra.identity,
              ...identity,
            },
          },
        },
      })).toThrow(HarnessKeyEnrollmentError);
    }
  });

  test("schema-v3 authorization binds the exact supervisor authority to its immutable core", () => {
    const valid = installationHandoffV3AuthorizedSidecar(
      supportedPriorHraIdentities[6],
    );
    if (valid.authorization.kind !== "installation_handoff_v3") {
      throw new Error("expected schema-v3 enrollment fixture");
    }
    const authorization = valid.authorization;
    const input = {
      candidate: authorization.candidate,
      operationId: authorization.operationId,
      predecessorIdentity: authorization.predecessorIdentity,
      preState: authorization.preState,
      priorHra: authorization.priorHra,
      receipt: authorization.receipt,
    };
    expect(installationHandoffV3EnrollmentAuthorizationMatches(
      authorization,
      input,
    )).toBeTrue();

    for (const field of ["sha256", "cdHash"] as const) {
      const authority = authorization.candidate.custodyProbeSupervisor;
      const candidate = {
        ...authorization.candidate,
        custodyProbeSupervisor: {
          ...authority,
          [field]: (field === "sha256" ? "0".repeat(64) : "0".repeat(40)),
        },
      };
      expect(installationHandoffV3EnrollmentAuthorizationMatches(
        { ...authorization, candidate },
        input,
      )).toBeFalse();
    }

    for (const replacement of [
      { designatedRequirement: "identifier substituted" },
      {
        signing: {
          ...testCustodyProbeSupervisorAuthority.signing,
          authority: "substituted-release-authority",
        },
      },
    ]) {
      expect(() => parseHarnessKeyEnrollmentSidecar({
        ...valid,
        authorization: {
          ...authorization,
          candidate: {
            ...authorization.candidate,
            custodyProbeSupervisor: {
              ...authorization.candidate.custodyProbeSupervisor,
              ...replacement,
            },
          },
        },
      })).toThrow("Harness key enrollment sidecar is invalid");
    }
  });

  test("schema-v3 authorization rejects unsafe pre-state integers", () => {
    const valid = installationHandoffV3AuthorizedSidecar(
      supportedPriorHraIdentities[6],
    );
    if (valid.authorization.kind !== "installation_handoff_v3") {
      throw new Error("expected schema-v3 enrollment fixture");
    }
    const preState = {
      ...valid.authorization.preState,
      accountHomes: Number.MAX_SAFE_INTEGER + 1,
    };
    expect(() => parseHarnessKeyEnrollmentSidecar({
      ...valid,
      authorization: {
        ...valid.authorization,
        preState,
        preStateSha256: digestHarnessKeyEnrollmentPreState(preState),
      },
    })).toThrow(HarnessKeyEnrollmentError);
  });

  test("canonical evidence digest ignores object insertion order", () => {
    expect(digestCanonicalEvidence({ z: 2, a: { y: 1, x: 0 } })).toBe(
      digestCanonicalEvidence({ a: { x: 0, y: 1 }, z: 2 }),
    );
    expect(() => digestCanonicalEvidence({ invalid: undefined })).toThrow();
  });

  test("create-only publication rejects a destination race without overwrite", async () => {
    const controlPlanePath = await emptyControlPlanePath();
    const path = harnessKeyEnrollmentSidecarPath(controlPlanePath);
    const attacker = "attacker-owned replacement";
    expect(writeHarnessKeyEnrollmentSidecar(
      controlPlanePath,
      forwardAuthorizedSidecar(),
      null,
      {
        beforePublishForTest: async () => {
          await writeFile(path, attacker, { flag: "wx", mode: 0o600 });
        },
      },
    )).rejects.toMatchObject({ code: "custody_conflict" });
    expect(await readFile(path, "utf8")).toBe(attacker);
  });

  test("publication rejects a candidate inode replacement", async () => {
    const controlPlanePath = await emptyControlPlanePath();
    const candidate = join(
      dirname(controlPlanePath),
      ".hra-harness-key-enrollment-v1.json.tmp",
    );
    expect(writeHarnessKeyEnrollmentSidecar(
      controlPlanePath,
      forwardAuthorizedSidecar(),
      null,
      {
        beforePublishForTest: async () => {
          await unlink(candidate);
          await writeFile(candidate, "replacement", { mode: 0o600 });
        },
      },
    )).rejects.toMatchObject({ code: "custody_conflict" });
    expect(await readHarnessKeyEnrollmentSidecar(controlPlanePath)).toBeNull();
  });

  test("protected startup read rejects growth after its bounded initial stat", async () => {
    const controlPlanePath = await emptyControlPlanePath();
    await writeForwardAuthorized(controlPlanePath);
    expect(() => validateHarnessKeyEnrollmentProtectedFiles(
      dirname(controlPlanePath),
      (path) => appendFileSync(path, "growth"),
    )).toThrow("Harness key enrollment state is invalid");
  });
});

async function emptyControlPlanePath(): Promise<string> {
  const root = await realpath(
    await mkdtemp(join(tmpdir(), "hra-enrollment-")),
  );
  roots.push(root);
  await chmod(root, 0o700);
  return join(root, "control-plane.sqlite");
}

function forwardAuthorizedSidecar() {
  return authorizedHarnessKeyEnrollmentSidecar(
    createForwardHarnessKeyEnrollmentAuthorization({
      operationId: "forward_0123456789abcdef01234567",
      committedOriginReceipt: {
        backupDirectory: "/private/tmp/hra-origin-backup",
        bundle: {
          identity: {
            build: "15",
            bundleIdentifier: "kitchen.hraness",
            executable: "hra",
            version: "0.1.14",
          },
          signature: { policy: "strict" },
          tree: treeEvidence("1"),
        },
        bytes: 1024,
        device: "1",
        inode: "2",
        operationId: "handoff_0123456789abcdef01234567",
        sha256: "2".repeat(64),
      },
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
          bytes: 2048,
          commit: "4".repeat(40),
          device: "3",
          inode: "4",
          runtimeTreeSha256: "5".repeat(64),
          sha256: "6".repeat(64),
        },
        root: { device: "5", inode: "6" },
      },
      preState: { exact: "pre-state" },
    }),
  );
}

function installationHandoffV3AuthorizedSidecar(
  priorIdentity: Readonly<{ build: string; version: string }>,
) {
  const base = forwardAuthorizedSidecar();
  return parseHarnessKeyEnrollmentSidecar({
    ...base,
    authorization: createInstallationHandoffV3EnrollmentAuthorization({
      candidate: {
        bundle: {
          identity: {
            build: "16",
            bundleIdentifier: "kitchen.hraness",
            executable: "hra",
            version: "0.1.15",
          },
          signature: { policy: "strict" },
          tree: treeEvidence("8"),
        },
        custodyProbeSupervisor: testCustodyProbeSupervisorAuthority,
        manifest: {
          bytes: 2048,
          commit: "9".repeat(40),
          device: "7",
          inode: "8",
          runtimeTreeSha256: "a".repeat(64),
          sha256: "b".repeat(64),
        },
        root: { device: "9", inode: "10" },
      },
      operationId: "handoff_abcdef0123456789abcdef01",
      predecessorIdentity: {
        build: "5",
        bundleIdentifier: "kitchen.hraness",
        executable: "oprte",
        version: "0.1.4",
      },
      preState: {
        accountHomes: 1,
        chatWorktreeLanes: 2,
        database: {
          databaseSha256: "c".repeat(64),
          migrationVersion: 62,
          quickCheck: "ok",
          rows: { schema_migrations: 62 },
        },
        dispatchWorktreeLanes: 3,
        harnessWorktreeLanes: 4,
        localTaskWorktreeLanes: 5,
        sessionEntries: 6,
        tree: treeEvidence("d"),
      },
      priorHra: {
        identity: {
          ...priorIdentity,
          bundleIdentifier: "kitchen.hraness",
          executable: "hra",
        },
        signature: { policy: "strict" },
        tree: treeEvidence("e"),
      },
      receipt: {
        device: "11",
        inode: "12",
        path: "/private/tmp/hra-v3/handoff-receipt.json",
        schemaVersion: 3,
        sha256: "f".repeat(64),
      },
    }),
  });
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

async function writeForwardAuthorized(controlPlanePath: string) {
  return await writeHarnessKeyEnrollmentSidecar(
    controlPlanePath,
    forwardAuthorizedSidecar(),
    null,
  );
}

async function writePrepared(controlPlanePath: string, envelope: string) {
  const authorized = await writeForwardAuthorized(controlPlanePath);
  return await writeHarnessKeyEnrollmentSidecar(
    controlPlanePath,
    {
      ...authorized.sidecar,
      phase: "prepared",
      attempt: {
        envelopeSha256: createHash("sha256").update(envelope).digest("hex"),
        nonce: "7".repeat(64),
      },
    },
    authorized,
  );
}

function fixtureEnvelope(byte: number): string {
  return serializeHarnessInstallMaster(
    Uint8Array.from({ length: HARNESS_INSTALL_MASTER_KEY_BYTES }, () => byte),
  );
}

function deterministicRandom(byte: number): (length: number) => Uint8Array {
  return (length) => Uint8Array.from({ length }, () => byte);
}

function fixtureKeychain(
  initial: HarnessKeyEnrollmentObservation,
  createResult = true,
): HarnessKeyEnrollmentKeychain & { readonly createCalls: number } {
  let observation = initial;
  let createCalls = 0;
  return {
    get createCalls() {
      return createCalls;
    },
    inspectExactNoUi: () => Promise.resolve(observation),
    createExactIfAbsentNoUi: (envelope) => {
      createCalls += 1;
      if (createResult) {
        observation = { state: "present", envelope, strictAcl: true };
      }
      return Promise.resolve({
        created: createResult,
        envelope,
        strictAcl: true,
      });
    },
  };
}
