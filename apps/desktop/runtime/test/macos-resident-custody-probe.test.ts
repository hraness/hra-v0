import { createHash } from "node:crypto";
import {
  chmodSync,
  mkdirSync,
  mkdtempSync,
  realpathSync,
  rmSync,
  writeFileSync,
} from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { describe, expect, test } from "bun:test";

import {
  macosResidentCustodyProbeAbi,
  MacOSResidentCustodyProbeError,
  runMacOSResidentCustodyProbe,
  type MacOSResidentCustodyProbeDependencies,
  type MacOSResidentCustodyProbeNative,
  type ResidentProcessGeneration,
  type ResidentReapObservation,
  type ResidentTerminalObservation,
} from "../macos-resident-custody-probe";
import { testCustodyProbeSupervisorAuthority } from "./fixtures/custody-probe-authority";

const authorizationReceipt =
  "{\"authorization\":\"hra-parent-v1\"," +
  `"gatewayFileSha256":"${"1".repeat(64)}",` +
  "\"keychainAccessed\":false,\"ok\":true," +
  `"rendererAuthoritySha256":"${"2".repeat(64)}",` +
  "\"version\":1}\n";
const absentStatus = "{\"schemaVersion\":1,\"state\":\"absent\"}\n";
const presentStatus =
  `{"envelopeSha256":"${"3".repeat(64)}",` +
  "\"schemaVersion\":1,\"state\":\"present\",\"strictAcl\":true}\n";

type CandidateFixture = Readonly<{
  app: string;
  authority: typeof testCustodyProbeSupervisorAuthority;
  root: string;
  supervisor: string;
}>;

function candidateFixture(): CandidateFixture {
  const root = realpathSync(mkdtempSync(join(tmpdir(), "hra-resident-probe-")));
  chmodSync(root, 0o700);
  const app = join(root, "HRA.app");
  const supervisor = join(
    app,
    "Contents/Resources/runtime/bin/hra-custody-probe-supervisor",
  );
  const host = join(app, "Contents/MacOS/hra");
  mkdirSync(join(app, "Contents/Resources/runtime/bin"), { recursive: true });
  mkdirSync(join(app, "Contents/MacOS"), { recursive: true });
  const supervisorBytes = Buffer.from("synthetic-candidate-supervisor-v1\n");
  writeFileSync(supervisor, supervisorBytes, { mode: 0o755 });
  writeFileSync(host, "synthetic-host-v1\n", { mode: 0o755 });
  return {
    app,
    authority: Object.freeze({
      ...testCustodyProbeSupervisorAuthority,
      sha256: createHash("sha256").update(supervisorBytes).digest("hex"),
    }),
    root,
    supervisor,
  };
}

type FakeOptions = Readonly<{
  cleanupStall?: boolean;
  directChildConflictAt?: number;
  inspectSubstitutionAt?: number;
  killFailure?: boolean;
  liveCdHash?: string;
  mutateSupervisorAtInspect?: Readonly<{
    inspect: number;
    path: string;
  }>;
  output?: string;
  recoverableThrowAt?:
    | "children"
    | "close"
    | "group"
    | "inspect"
    | "poll"
    | "read"
    | "wait"
    | "write";
  restore?: boolean;
  spawnProcessIdentifier?: number;
  stderr?: string;
  timeout?: boolean;
  waitLeaseLoss?: boolean;
  waitLeaseLossAfterRecoverable?: boolean;
}>;

class FakeResidentNative implements MacOSResidentCustodyProbeNative {
  readonly events: string[] = [];
  readonly options: FakeOptions;
  readonly signalLease = Object.freeze({
    childAction: Buffer.alloc(macosResidentCustodyProbeAbi.sigactionBytes),
    mask: Buffer.alloc(macosResidentCustodyProbeAbi.sigsetBytes),
    pipeAction: Buffer.alloc(macosResidentCustodyProbeAbi.sigactionBytes),
  });
  directChildrenChecks = 0;
  gateWrites = 0;
  inspectCalls = 0;
  killCalls = 0;
  now = 0;
  processQueriesAfterLeaseLoss = 0;
  processQueriesAfterReap = 0;
  reapCalls = 0;
  restoreCalls = 0;
  terminateCalls = 0;

  private admitted = false;
  private killed = false;
  private leaseLost = false;
  private nextDescriptor = 10;
  private pid = 4242;
  private reaped = false;
  private recoverableThrown = false;
  private spawned = false;
  private stderrDescriptor = -1;
  private stderrRead = false;
  private stdoutDescriptor = -1;
  private stdoutRead = false;

  constructor(options: FakeOptions = {}) {
    this.options = options;
  }

  assertDirectChildren = (expectedPid: number | null): boolean => {
    this.maybeThrow("children");
    this.query(`children:${expectedPid ?? "none"}`);
    this.directChildrenChecks += 1;
    return this.options.directChildConflictAt !== this.directChildrenChecks;
  };

  close = (descriptor: number): void => {
    this.maybeThrow("close");
    if (descriptor >= 0) this.events.push(`close:${descriptor}`);
  };

  createPipe = (): Readonly<{ read: number; write: number }> => {
    const pipe = Object.freeze({
      read: this.nextDescriptor,
      write: this.nextDescriptor + 1,
    });
    this.nextDescriptor += 2;
    this.events.push(`pipe:${pipe.read}:${pipe.write}`);
    return pipe;
  };

  enterSignalPolicy = () => {
    this.events.push("signals:enter");
    return this.signalLease;
  };

  groupIsQuiescent = (
    processIdentifier: number,
    leaderTerminal: boolean,
  ): boolean => {
    this.maybeThrow("group");
    this.query(`group:${processIdentifier}`);
    return processIdentifier === this.pid && leaderTerminal
      && (this.admitted || this.killed);
  };

  inspectGeneration = (
    processIdentifier: number,
    path: string,
    expectedCdHash: string,
  ): ResidentProcessGeneration | null => {
    this.maybeThrow("inspect");
    this.query(`inspect:${processIdentifier}`);
    this.inspectCalls += 1;
    const mutation = this.options.mutateSupervisorAtInspect;
    if (mutation?.inspect === this.inspectCalls) {
      writeFileSync(mutation.path, "substituted-supervisor\n", { mode: 0o755 });
    }
    if (this.options.inspectSubstitutionAt === this.inspectCalls) return null;
    const liveCdHash = this.options.liveCdHash ?? expectedCdHash;
    if (liveCdHash !== expectedCdHash) return null;
    return Object.freeze({
      cdHash: liveCdHash,
      codeStatus: 0x20000001,
      path,
      pgid: processIdentifier,
      pid: processIdentifier,
      ppid: process.pid,
      startMicroseconds: 7n,
      startSeconds: 11n,
    });
  };

  killGroupOnce = (processIdentifier: number): "sent" => {
    this.query(`kill:${processIdentifier}`);
    this.killCalls += 1;
    if (this.options.killFailure) {
      throw new Error("synthetic kill failure");
    }
    this.killed = true;
    this.events.push("signal:group-kill");
    return "sent";
  };

  nowMilliseconds = (): number => {
    this.now += 1_000;
    return this.now;
  };

  pollReadable = (
    descriptors: readonly number[],
    timeoutMilliseconds: number,
  ): ReadonlyMap<number, number> => {
    this.maybeThrow("poll");
    this.events.push(`poll-timeout:${timeoutMilliseconds}`);
    this.events.push(`poll:${descriptors.join(",")}`);
    if (!this.terminalReady()) return new Map();
    return new Map(descriptors.map(descriptor => [descriptor, 0x11]));
  };

  read = (descriptor: number, maximumBytes: number): Buffer | null => {
    this.maybeThrow("read");
    this.events.push(`read-bound:${maximumBytes}`);
    if (descriptor === this.stdoutDescriptor) {
      if (this.stdoutRead) return null;
      this.stdoutRead = true;
      return Buffer.from(this.options.output ?? absentStatus);
    }
    if (descriptor === this.stderrDescriptor) {
      if (this.stderrRead) return null;
      this.stderrRead = true;
      const text = this.options.stderr ?? "";
      return text === "" ? null : Buffer.from(text);
    }
    throw new Error(`unexpected descriptor ${descriptor}`);
  };

  reap = (processIdentifier: number): ResidentReapObservation => {
    this.query(`reap:${processIdentifier}`);
    this.reapCalls += 1;
    this.reaped = true;
    this.events.push("leader:reaped");
    return this.killed
      ? Object.freeze({ exited: false, exitStatus: 0, signal: 9 })
      : Object.freeze({ exited: true, exitStatus: 0, signal: 0 });
  };

  restoreSignalPolicy = (): boolean => {
    this.restoreCalls += 1;
    this.events.push("signals:restore");
    return this.options.restore !== false;
  };

  spawn = (input: Parameters<MacOSResidentCustodyProbeNative["spawn"]>[0]): number => {
    this.events.push(`spawn:${input.executable}`);
    this.stdoutDescriptor = input.standardOutputReadDescriptor;
    this.stderrDescriptor = input.standardErrorReadDescriptor;
    expect(input.arguments[0]).toBe(input.executable);
    expect(input.lifetimeReadDescriptor).not.toBe(input.lifetimeWriteDescriptor);
    expect(input.environment).toContain("LANG=C");
    expect(input.environment).toContain("LC_ALL=C");
    expect(input.environment).toContain("PATH=/usr/bin:/bin");
    this.spawned = true;
    return this.options.spawnProcessIdentifier ?? this.pid;
  };

  waitWithoutReaping = (
    processIdentifier: number,
  ): ResidentTerminalObservation | null => {
    this.maybeThrow("wait");
    this.query(`wait:${processIdentifier}`);
    if (
      this.options.waitLeaseLoss
      || (this.options.waitLeaseLossAfterRecoverable && this.recoverableThrown)
    ) {
      this.leaseLost = true;
      throw new MacOSResidentCustodyProbeError(
        "permanent_failure",
        "synthetic ECHILD",
        true,
        true,
        true,
      );
    }
    if (!this.terminalReady()) return null;
    return this.killed
      ? Object.freeze({ code: 2, pid: processIdentifier, status: 9 })
      : Object.freeze({ code: 1, pid: processIdentifier, status: 0 });
  };

  write = (descriptor: number, bytes: Uint8Array): number => {
    this.maybeThrow("write");
    this.events.push(`write:${descriptor}:${Buffer.from(bytes).toString()}`);
    if (Buffer.from(bytes).toString() === "G") {
      this.admitted = true;
      this.gateWrites += 1;
    }
    return bytes.byteLength;
  };

  private query(event: string): void {
    if (this.leaseLost) this.processQueriesAfterLeaseLoss += 1;
    if (this.reaped) this.processQueriesAfterReap += 1;
    this.events.push(event);
  }

  private maybeThrow(
    event: NonNullable<FakeOptions["recoverableThrowAt"]>,
  ): void {
    if (
      this.spawned
      && !this.recoverableThrown
      && this.options.recoverableThrowAt === event
    ) {
      this.recoverableThrown = true;
      throw new Error(`synthetic recoverable ${event} failure`);
    }
  }

  private terminalReady(): boolean {
    return (this.killed && this.options.cleanupStall !== true)
      || (this.admitted && this.options.timeout !== true);
  }
}

function dependencies(native: FakeResidentNative): MacOSResidentCustodyProbeDependencies {
  return Object.freeze({
    native,
    terminateProcess: (error: MacOSResidentCustodyProbeError): never => {
      native.terminateCalls += 1;
      throw error;
    },
  });
}

function withCandidate(
  operation: (fixture: CandidateFixture) => void,
): void {
  const fixture = candidateFixture();
  try {
    operation(fixture);
  } finally {
    rmSync(fixture.root, { force: true, recursive: true });
  }
}

function expectContained(native: FakeResidentNative): void {
  expect(native.killCalls).toBe(1);
  expect(native.reapCalls).toBe(1);
  expect(native.restoreCalls).toBe(1);
  expect(native.processQueriesAfterReap).toBe(0);
  const reap = native.events.indexOf("leader:reaped");
  const lifetimeClose = native.events.lastIndexOf("close:15");
  expect(reap).toBeGreaterThanOrEqual(0);
  expect(lifetimeClose).toBeGreaterThan(reap);
}

describe("resident candidate-owned custody supervisor", () => {
  test("freezes the exact arm64 Darwin ABI used by raw FFI", () => {
    expect(macosResidentCustodyProbeAbi).toEqual({
      cldDumped: 3,
      cldExited: 1,
      cldKilled: 2,
      openCloseOnExec: 0x01000000,
      parentLeaseDescriptor: 3,
      posixSpawnHandleBytes: 8,
      procBsdInfoBytes: 136,
      procPgidOffset: 100,
      procPidOffset: 12,
      procPpidOffset: 16,
      procStartMicrosecondsOffset: 128,
      procStartSecondsOffset: 120,
      sigactionBytes: 16,
      siginfoBytes: 104,
      siginfoCodeOffset: 8,
      siginfoPidOffset: 12,
      siginfoStatusOffset: 20,
      sigsetBytes: 4,
    });
  });

  test("admits only after two exact live generations and returns no-UI absent status", () => {
    withCandidate(fixture => {
      const native = new FakeResidentNative({ output: absentStatus });
      const result = runMacOSResidentCustodyProbe({
        authority: fixture.authority,
        candidateApp: fixture.app,
        mode: "status",
      }, dependencies(native));
      expect(result).toEqual({ exitCode: 0, stderr: "", stdout: absentStatus });
      expect(native.inspectCalls).toBe(2);
      expect(native.gateWrites).toBe(1);
      expect(native.killCalls).toBe(0);
      expect(native.reapCalls).toBe(1);
      expect(native.restoreCalls).toBe(1);
      expect(native.processQueriesAfterReap).toBe(0);
    });
  });

  test("accepts only strictAcl plus exact digest for present status", () => {
    withCandidate(fixture => {
      const native = new FakeResidentNative({ output: presentStatus });
      expect(runMacOSResidentCustodyProbe({
        authority: fixture.authority,
        candidateApp: fixture.app,
        mode: "status",
      }, dependencies(native)).stdout).toBe(presentStatus);
    });
  });

  test("authorize-only output proves keychainAccessed false and exact authority digests", () => {
    withCandidate(fixture => {
      const native = new FakeResidentNative({ output: authorizationReceipt });
      expect(runMacOSResidentCustodyProbe({
        authority: fixture.authority,
        candidateApp: fixture.app,
        expectedStdout: authorizationReceipt,
        mode: "authorize",
      }, dependencies(native)).stdout).toBe(authorizationReceipt);
      expect(native.gateWrites).toBe(1);
    });
  });

  test("rejects an authorize expectation that could touch Keychain before spawn", () => {
    withCandidate(fixture => {
      const native = new FakeResidentNative();
      expect(() => runMacOSResidentCustodyProbe({
        authority: fixture.authority,
        candidateApp: fixture.app,
        expectedStdout: authorizationReceipt.replace(
          "keychainAccessed\":false",
          "keychainAccessed\":true",
        ),
        mode: "authorize",
      }, dependencies(native))).toThrow("not canonical or no-Keychain");
      expect(native.events).toEqual([]);
    });
  });

  test("contains a live-image substitution before GO with one group signal", () => {
    withCandidate(fixture => {
      const native = new FakeResidentNative({ inspectSubstitutionAt: 2 });
      expect(() => runMacOSResidentCustodyProbe({
        authority: fixture.authority,
        candidateApp: fixture.app,
        mode: "status",
      }, dependencies(native))).toThrow("immediately before GO");
      expect(native.gateWrites).toBe(0);
      expectContained(native);
    });
  });

  test("contains held-file mutation before GO and never accepts live evidence alone", () => {
    withCandidate(fixture => {
      const native = new FakeResidentNative({
        mutateSupervisorAtInspect: { inspect: 1, path: fixture.supervisor },
      });
      expect(() => runMacOSResidentCustodyProbe({
        authority: fixture.authority,
        candidateApp: fixture.app,
        mode: "status",
      }, dependencies(native))).toThrow("changed while held");
      expect(native.gateWrites).toBe(0);
      expectContained(native);
    });
  });

  test("times out synchronously, signals the exact group once, then reaps", () => {
    withCandidate(fixture => {
      const native = new FakeResidentNative({ timeout: true });
      expect(() => runMacOSResidentCustodyProbe({
        authority: fixture.authority,
        candidateApp: fixture.app,
        mode: "status",
      }, dependencies(native))).toThrow("bounded operation interval");
      expect(native.gateWrites).toBe(1);
      expectContained(native);
    });
  });

  test("rejects malformed status only after terminal quiescence and exact reap", () => {
    withCandidate(fixture => {
      const native = new FakeResidentNative({
        output: "{\"schemaVersion\":1,\"state\":\"present\",\"strictAcl\":false}\n",
      });
      expect(() => runMacOSResidentCustodyProbe({
        authority: fixture.authority,
        candidateApp: fixture.app,
        mode: "status",
      }, dependencies(native))).toThrow("not canonical");
      expect(native.killCalls).toBe(0);
      expect(native.reapCalls).toBe(1);
      expect(native.restoreCalls).toBe(1);
    });
  });

  test("bounds oversized output and never admits it as a receipt", () => {
    withCandidate(fixture => {
      const native = new FakeResidentNative({ output: "x".repeat(1_025) });
      expect(() => runMacOSResidentCustodyProbe({
        authority: fixture.authority,
        candidateApp: fixture.app,
        mode: "status",
      }, dependencies(native))).toThrow("output exceeded");
      expect(native.reapCalls).toBe(1);
      expect(native.restoreCalls).toBe(1);
    });
  });

  test("foreign direct child fails the exclusive interval and is contained", () => {
    withCandidate(fixture => {
      const native = new FakeResidentNative({ directChildConflictAt: 2 });
      expect(() => runMacOSResidentCustodyProbe({
        authority: fixture.authority,
        candidateApp: fixture.app,
        mode: "status",
      }, dependencies(native))).toThrow("foreign child");
      expect(native.gateWrites).toBe(0);
      expectContained(native);
    });
  });

  for (const fault of [
    "children",
    "close",
    "inspect",
    "wait",
    "write",
    "group",
    "poll",
    "read",
  ] as const) {
    test(`funnels a recoverable ${fault} exception through exact retirement`, () => {
      withCandidate(fixture => {
        const native = new FakeResidentNative({ recoverableThrowAt: fault });
        const operation = () => runMacOSResidentCustodyProbe({
          authority: fixture.authority,
          candidateApp: fixture.app,
          mode: "status",
        }, dependencies(native));
        if (fault === "poll" || fault === "read") {
          expect(operation).toThrow("output exceeded or violated");
        } else {
          expect(operation).toThrow(`synthetic recoverable ${fault} failure`);
        }
        expect(native.killCalls).toBeLessThanOrEqual(1);
        expect(native.reapCalls).toBe(1);
        expect(native.restoreCalls).toBe(1);
        expect(native.processQueriesAfterReap).toBe(0);
        const reap = native.events.indexOf("leader:reaped");
        const lifetimeClose = native.events.lastIndexOf("close:15");
        expect(lifetimeClose).toBeGreaterThan(reap);
      });
    });
  }

  test("kill ambiguity restores policy, closes capabilities, and terminates the process", () => {
    withCandidate(fixture => {
      const native = new FakeResidentNative({
        inspectSubstitutionAt: 2,
        killFailure: true,
      });
      let captured: unknown;
      try {
        runMacOSResidentCustodyProbe({
          authority: fixture.authority,
          candidateApp: fixture.app,
          mode: "status",
        }, dependencies(native));
      } catch (error) {
        captured = error;
      }
      expect(captured).toBeInstanceOf(MacOSResidentCustodyProbeError);
      expect((captured as MacOSResidentCustodyProbeError).processTerminal)
        .toBe(true);
      expect((captured as MacOSResidentCustodyProbeError).leaseLost).toBe(false);
      expect(native.killCalls).toBe(1);
      expect(native.reapCalls).toBe(0);
      expect(native.restoreCalls).toBe(1);
      expect(native.terminateCalls).toBe(1);
      expect(native.events).toContain("close:15");
    });
  });

  test("cleanup timeout restores policy then enforces process termination", () => {
    withCandidate(fixture => {
      const native = new FakeResidentNative({
        cleanupStall: true,
        timeout: true,
      });
      let captured: unknown;
      try {
        runMacOSResidentCustodyProbe({
          authority: fixture.authority,
          candidateApp: fixture.app,
          mode: "status",
        }, dependencies(native));
      } catch (error) {
        captured = error;
      }
      expect(captured).toBeInstanceOf(MacOSResidentCustodyProbeError);
      expect((captured as MacOSResidentCustodyProbeError).processTerminal)
        .toBe(true);
      expect((captured as MacOSResidentCustodyProbeError).leaseLost).toBe(false);
      expect(native.killCalls).toBe(1);
      expect(native.reapCalls).toBe(0);
      expect(native.restoreCalls).toBe(1);
      expect(native.terminateCalls).toBe(1);
      expect(native.events).toContain("close:15");
    });
  });

  test("ECHILD becomes permanent, closes lifetime authority, and never signals numerically", () => {
    withCandidate(fixture => {
      const native = new FakeResidentNative({ waitLeaseLoss: true });
      let captured: unknown;
      try {
        runMacOSResidentCustodyProbe({
          authority: fixture.authority,
          candidateApp: fixture.app,
          mode: "status",
        }, dependencies(native));
      } catch (error) {
        captured = error;
      }
      expect(captured).toBeInstanceOf(MacOSResidentCustodyProbeError);
      expect((captured as MacOSResidentCustodyProbeError).permanent).toBe(true);
      expect((captured as MacOSResidentCustodyProbeError).leaseLost).toBe(true);
      expect(native.killCalls).toBe(0);
      expect(native.reapCalls).toBe(0);
      expect(native.restoreCalls).toBe(1);
      expect(native.terminateCalls).toBe(1);
      expect(native.events).toContain("close:15");
    });
  });

  test("ambiguous spawn success without a PID lease restores capabilities then terminates", () => {
    withCandidate(fixture => {
      const native = new FakeResidentNative({ spawnProcessIdentifier: 0 });
      let captured: unknown;
      try {
        runMacOSResidentCustodyProbe({
          authority: fixture.authority,
          candidateApp: fixture.app,
          mode: "status",
        }, dependencies(native));
      } catch (error) {
        captured = error;
      }
      expect(captured).toBeInstanceOf(MacOSResidentCustodyProbeError);
      expect((captured as MacOSResidentCustodyProbeError).permanent).toBe(true);
      expect((captured as MacOSResidentCustodyProbeError).processTerminal)
        .toBe(true);
      expect((captured as MacOSResidentCustodyProbeError).leaseLost).toBe(true);
      expect(native.killCalls).toBe(0);
      expect(native.reapCalls).toBe(0);
      expect(native.processQueriesAfterLeaseLoss).toBe(0);
      expect(native.processQueriesAfterReap).toBe(0);
      expect(native.restoreCalls).toBe(1);
      expect(native.terminateCalls).toBe(1);
      for (const descriptor of [10, 11, 12, 13, 14, 15]) {
        expect(native.events).toContain(`close:${descriptor}`);
      }
      expect(native.events.filter(event => event === "signals:enter")).toHaveLength(1);
      expect(native.events.filter(event => event === "signals:restore")).toHaveLength(1);
    });
  });

  test("a later ECHILD overrides an earlier recoverable failure without reusing the PID lease", () => {
    withCandidate(fixture => {
      const native = new FakeResidentNative({
        recoverableThrowAt: "write",
        waitLeaseLossAfterRecoverable: true,
      });
      let captured: unknown;
      try {
        runMacOSResidentCustodyProbe({
          authority: fixture.authority,
          candidateApp: fixture.app,
          mode: "status",
        }, dependencies(native));
      } catch (error) {
        captured = error;
      }
      expect(captured).toBeInstanceOf(MacOSResidentCustodyProbeError);
      expect((captured as MacOSResidentCustodyProbeError).permanent).toBe(true);
      expect((captured as MacOSResidentCustodyProbeError).processTerminal)
        .toBe(true);
      expect((captured as MacOSResidentCustodyProbeError).leaseLost).toBe(true);
      expect(native.killCalls).toBe(0);
      expect(native.reapCalls).toBe(0);
      expect(native.processQueriesAfterLeaseLoss).toBe(0);
      expect(native.restoreCalls).toBe(1);
      expect(native.terminateCalls).toBe(1);
      for (const descriptor of [10, 11, 12, 13, 14, 15]) {
        expect(native.events).toContain(`close:${descriptor}`);
      }
      expect(native.events.filter(event => event === "signals:enter")).toHaveLength(1);
      expect(native.events.filter(event => event === "signals:restore")).toHaveLength(1);
    });
  });

  test("restore ambiguity is permanent and no process query follows reap", () => {
    withCandidate(fixture => {
      const native = new FakeResidentNative({ restore: false });
      let captured: unknown;
      try {
        runMacOSResidentCustodyProbe({
          authority: fixture.authority,
          candidateApp: fixture.app,
          mode: "status",
        }, dependencies(native));
      } catch (error) {
        captured = error;
      }
      expect(captured).toBeInstanceOf(MacOSResidentCustodyProbeError);
      expect((captured as MacOSResidentCustodyProbeError).permanent).toBe(true);
      expect(native.reapCalls).toBe(1);
      expect(native.restoreCalls).toBe(2);
      expect(native.terminateCalls).toBe(1);
      expect(native.processQueriesAfterReap).toBe(0);
    });
  });

  test("receipt SHA substitution fails before signal normalization or spawn", () => {
    withCandidate(fixture => {
      const native = new FakeResidentNative();
      expect(() => runMacOSResidentCustodyProbe({
        authority: { ...fixture.authority, sha256: "9".repeat(64) },
        candidateApp: fixture.app,
        mode: "status",
      }, dependencies(native))).toThrow("differs from receipt-bound authority");
      expect(native.events).toEqual([]);
    });
  });

  test("a supervisor FIFO substitution fails promptly before native state", async () => {
    const fixture = candidateFixture();
    let writer: ReturnType<typeof Bun.spawn> | null = null;
    try {
      rmSync(fixture.supervisor);
      const fifo = Bun.spawnSync(["/usr/bin/mkfifo", fixture.supervisor], {
        stderr: "pipe",
        stdout: "pipe",
      });
      expect(fifo.exitCode).toBe(0);
      writer = Bun.spawn([
        process.execPath,
        "-e",
        `setTimeout(() => require("node:fs").writeFileSync(${JSON.stringify(
          fixture.supervisor,
        )}, "unblock\\n"), 2000)`,
      ], {
        stderr: "ignore",
        stdout: "ignore",
      });
      const native = new FakeResidentNative();
      const started = performance.now();
      expect(() => runMacOSResidentCustodyProbe({
        authority: fixture.authority,
        candidateApp: fixture.app,
        mode: "status",
      }, dependencies(native))).toThrow("file authority is unsafe");
      expect(performance.now() - started).toBeLessThan(1_000);
      expect(native.events).toEqual([]);
    } finally {
      writer?.kill();
      if (writer !== null) await writer.exited;
      rmSync(fixture.root, { force: true, recursive: true });
    }
  });

  test("receipt CDHash substitution never reaches GO and is contained", () => {
    withCandidate(fixture => {
      const native = new FakeResidentNative({ liveCdHash: "7".repeat(40) });
      expect(() => runMacOSResidentCustodyProbe({
        authority: { ...fixture.authority, cdHash: "6".repeat(40) },
        candidateApp: fixture.app,
        mode: "status",
      }, dependencies(native))).toThrow("exact gated admission");
      expect(native.gateWrites).toBe(0);
      expectContained(native);
    });
  });

  test("signing and designated-requirement substitutions fail before native state", () => {
    withCandidate(fixture => {
      for (const authority of [
        {
          ...fixture.authority,
          signing: { ...fixture.authority.signing, mode: "adhoc" },
        },
        {
          ...fixture.authority,
          designatedRequirement: `${fixture.authority.designatedRequirement} `,
        },
      ]) {
        const native = new FakeResidentNative();
        expect(() => runMacOSResidentCustodyProbe({
          authority: authority as unknown as CandidateFixture["authority"],
          candidateApp: fixture.app,
          mode: "status",
        }, dependencies(native))).toThrow("receipt authority is invalid");
        expect(native.events).toEqual([]);
      }
    });
  });
});
