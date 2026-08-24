import { createHash } from "node:crypto";
import {
  closeSync,
  constants,
  fstatSync,
  lstatSync,
  openSync,
  readSync,
  realpathSync,
  writeSync,
  type BigIntStats,
} from "node:fs";
import { isAbsolute, join, normalize } from "node:path";

import {
  dlopen,
  FFIType,
  ptr,
  toBuffer,
} from "bun:ffi";

import {
  parseProductionCustodyProbeSupervisorAuthority,
  type CustodyProbeSupervisorAuthorityEvidence,
} from "./custody-probe-supervisor-authority";
import {
  macosCustodyProbeMaximumOutputBytes,
  parseCanonicalMacOSCustodyStatus,
  type MacOSCustodyStatus,
} from "./macos-custody-probe";

const darwinLibraryPath = "/usr/lib/libSystem.B.dylib";
const darwinProcessLibraryPath = "/usr/lib/libproc.dylib";

/**
 * The values and layouts below are the arm64 Darwin ABI used by the release
 * CLI. Keep them explicit: an SDK typedef change must fail a source review,
 * rather than silently changing the custody boundary.
 */
export const macosResidentCustodyProbeAbi = Object.freeze({
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
} as const);

const signalChild = 20;
const signalHangup = 1;
const signalInterrupt = 2;
const signalPipe = 13;
const signalQuit = 3;
const signalTerminate = 15;
const signalKill = 9;
const signalDefault = 0n;
const signalIgnored = 1n;
const signalSetMask = 3;

const posixSpawnSetProcessGroup = 0x0002;
const posixSpawnSetSignalDefault = 0x0004;
const posixSpawnSetSignalMask = 0x0008;
const posixSpawnCloseOnExecDefault = 0x4000;

const pollIn = 0x0001;
const pollError = 0x0008;
const pollHangup = 0x0010;
const pollInvalid = 0x0020;

const processGroupOnly = 2;
const processParentOnly = 6;
const processBsdInfoFlavor = 3;
const processZombieStatus = 5;

const waitPidType = 1;
const waitNoHang = 0x00000001;
const waitExited = 0x00000004;
const waitNoReap = 0x00000020;

const csOpsStatus = 0;
const csOpsCdHash = 5;
const csValid = 0x00000001;
const csAdHoc = 0x00000002;
const csGetTaskAllow = 0x00000004;
const csInstaller = 0x00000008;
const csInvalidAllowed = 0x00000020;
const csLinkerSigned = 0x00020000;
const csKilled = 0x01000000;
const csPlatformBinary = 0x04000000;
const csPlatformPath = 0x08000000;
const csDebugged = 0x10000000;
const csSigned = 0x20000000;
// Exact static bytes are independently bound to a CodeDirectory whose only
// flag is runtime. Live csops flags include kernel-derived/version-dependent
// bits, so admission requires only dynamic validity plus a signed image and
// forbids every authority-expanding/substitution posture below.
const requiredLiveCodeStatus = csValid | csSigned;
const forbiddenLiveCodeStatus = csAdHoc | csGetTaskAllow | csInstaller
  | csInvalidAllowed | csKilled | csPlatformBinary | csPlatformPath
  | csDebugged | csLinkerSigned;

const errnoInterrupted = 4;
const errnoNoChild = 10;
const errnoNoProcess = 3;

const maximumSupervisorBytes = 64 * 1024 * 1024;
const admissionMilliseconds = 5_000;
const operationMilliseconds = 50_000;
const cleanupMilliseconds = 10_000;
const pollSliceMilliseconds = 10;
const maximumListedProcesses = 256;

const systemLibrary = process.platform === "darwin"
  ? dlopen(darwinLibraryPath, {
    __error: { args: [], returns: FFIType.ptr },
    csops: {
      args: [FFIType.i32, FFIType.u32, FFIType.ptr, FFIType.u64],
      returns: FFIType.i32,
    },
    getpgid: { args: [FFIType.i32], returns: FFIType.i32 },
    kill: {
      args: [FFIType.i32, FFIType.i32],
      returns: FFIType.i32,
    },
    pipe: { args: [FFIType.ptr], returns: FFIType.i32 },
    poll: {
      args: [FFIType.ptr, FFIType.u64, FFIType.i32],
      returns: FFIType.i32,
    },
    posix_spawn: {
      args: [
        FFIType.ptr,
        FFIType.cstring,
        FFIType.ptr,
        FFIType.ptr,
        FFIType.ptr,
        FFIType.ptr,
      ],
      returns: FFIType.i32,
    },
    posix_spawn_file_actions_addclose: {
      args: [FFIType.ptr, FFIType.i32],
      returns: FFIType.i32,
    },
    posix_spawn_file_actions_adddup2: {
      args: [FFIType.ptr, FFIType.i32, FFIType.i32],
      returns: FFIType.i32,
    },
    posix_spawn_file_actions_destroy: {
      args: [FFIType.ptr],
      returns: FFIType.i32,
    },
    posix_spawn_file_actions_init: {
      args: [FFIType.ptr],
      returns: FFIType.i32,
    },
    posix_spawnattr_destroy: {
      args: [FFIType.ptr],
      returns: FFIType.i32,
    },
    posix_spawnattr_init: {
      args: [FFIType.ptr],
      returns: FFIType.i32,
    },
    posix_spawnattr_setflags: {
      args: [FFIType.ptr, FFIType.i16],
      returns: FFIType.i32,
    },
    posix_spawnattr_setpgroup: {
      args: [FFIType.ptr, FFIType.i32],
      returns: FFIType.i32,
    },
    posix_spawnattr_setsigdefault: {
      args: [FFIType.ptr, FFIType.ptr],
      returns: FFIType.i32,
    },
    posix_spawnattr_setsigmask: {
      args: [FFIType.ptr, FFIType.ptr],
      returns: FFIType.i32,
    },
    sigaction: {
      args: [FFIType.i32, FFIType.ptr, FFIType.ptr],
      returns: FFIType.i32,
    },
    sigaddset: {
      args: [FFIType.ptr, FFIType.i32],
      returns: FFIType.i32,
    },
    sigdelset: {
      args: [FFIType.ptr, FFIType.i32],
      returns: FFIType.i32,
    },
    sigemptyset: {
      args: [FFIType.ptr],
      returns: FFIType.i32,
    },
    sigprocmask: {
      args: [FFIType.i32, FFIType.ptr, FFIType.ptr],
      returns: FFIType.i32,
    },
    waitid: {
      args: [FFIType.i32, FFIType.u32, FFIType.ptr, FFIType.i32],
      returns: FFIType.i32,
    },
    waitpid: {
      args: [FFIType.i32, FFIType.ptr, FFIType.i32],
      returns: FFIType.i32,
    },
  })
  : null;

const processLibrary = process.platform === "darwin"
  ? dlopen(darwinProcessLibraryPath, {
    proc_listpids: {
      args: [FFIType.u32, FFIType.u32, FFIType.ptr, FFIType.i32],
      returns: FFIType.i32,
    },
    proc_pidinfo: {
      args: [
        FFIType.i32,
        FFIType.i32,
        FFIType.u64,
        FFIType.ptr,
        FFIType.i32,
      ],
      returns: FFIType.i32,
    },
    proc_pidpath: {
      args: [FFIType.i32, FFIType.ptr, FFIType.u32],
      returns: FFIType.i32,
    },
  })
  : null;

export type MacOSResidentCustodyProbeInput = Readonly<{
  authority: CustodyProbeSupervisorAuthorityEvidence;
  candidateApp: string;
}> & (
  | Readonly<{
    expectedStdout: string;
    mode: "authorize";
  }>
  | Readonly<{
    mode: "status";
  }>
  | Readonly<{
    dwellMilliseconds: number;
    mode: "smoke";
    smokeRoot: string;
  }>
);

export type MacOSResidentCustodyProbeResult = Readonly<{
  exitCode: 0;
  stderr: "";
  stdout: string;
}>;

export class MacOSResidentCustodyProbeError extends Error {
  readonly code:
    | "admission_failed"
    | "authority_invalid"
    | "child_conflict"
    | "filesystem_unsafe"
    | "input_invalid"
    | "output_invalid"
    | "permanent_failure"
    | "probe_failed"
    | "spawn_failed"
    | "unsupported_platform";
  readonly permanent: boolean;
  readonly processTerminal: boolean;
  readonly leaseLost: boolean;

  constructor(
    code: MacOSResidentCustodyProbeError["code"],
    message: string,
    permanent = false,
    processTerminal = false,
    leaseLost = false,
  ) {
    super(message);
    this.name = "MacOSResidentCustodyProbeError";
    this.code = code;
    this.permanent = permanent;
    this.processTerminal = processTerminal;
    this.leaseLost = leaseLost;
  }
}

type SignalPolicyLease = Readonly<{
  childAction: Buffer;
  mask: Buffer;
  pipeAction: Buffer;
}>;

type ResidentPipe = Readonly<{ read: number; write: number }>;

export type ResidentProcessGeneration = Readonly<{
  cdHash: string;
  codeStatus: number;
  path: string;
  pgid: number;
  pid: number;
  ppid: number;
  startMicroseconds: bigint;
  startSeconds: bigint;
}>;

export type ResidentTerminalObservation = Readonly<{
  code: 1 | 2 | 3;
  pid: number;
  status: number;
}>;

export type ResidentReapObservation = Readonly<{
  exited: boolean;
  exitStatus: number;
  signal: number;
}>;

export interface MacOSResidentCustodyProbeNative {
  readonly assertDirectChildren: (expectedPid: number | null) => boolean;
  readonly close: (descriptor: number) => void;
  readonly createPipe: () => ResidentPipe;
  readonly enterSignalPolicy: () => SignalPolicyLease;
  readonly groupIsQuiescent: (
    processIdentifier: number,
    leaderTerminal: boolean,
  ) => boolean;
  readonly inspectGeneration: (
    processIdentifier: number,
    path: string,
    expectedCdHash: string,
  ) => ResidentProcessGeneration | null;
  readonly killGroupOnce: (processIdentifier: number) => "missing" | "sent";
  readonly nowMilliseconds: () => number;
  readonly pollReadable: (
    descriptors: readonly number[],
    timeoutMilliseconds: number,
  ) => ReadonlyMap<number, number>;
  readonly read: (descriptor: number, maximumBytes: number) => Buffer | null;
  readonly reap: (processIdentifier: number) => ResidentReapObservation;
  readonly restoreSignalPolicy: (lease: SignalPolicyLease) => boolean;
  readonly spawn: (input: Readonly<{
    arguments: readonly string[];
    environment: readonly string[];
    executable: string;
    lifetimeReadDescriptor: number;
    lifetimeWriteDescriptor: number;
    standardErrorReadDescriptor: number;
    standardErrorWriteDescriptor: number;
    standardOutputReadDescriptor: number;
    standardOutputWriteDescriptor: number;
  }>) => number;
  readonly waitWithoutReaping: (
    processIdentifier: number,
  ) => ResidentTerminalObservation | null;
  readonly write: (descriptor: number, bytes: Uint8Array) => number;
}

export interface MacOSResidentCustodyProbeDependencies {
  readonly native: MacOSResidentCustodyProbeNative;
  readonly terminateProcess: (error: MacOSResidentCustodyProbeError) => never;
}

type HeldSupervisor = Readonly<{
  descriptor: number;
  metadata: BigIntStats;
  path: string;
  sha256: string;
}>;

type OutputPipeState = {
  bytes: Buffer[];
  descriptor: number;
  eof: boolean;
  length: number;
  overflow: boolean;
};

let residentProbeActive = false;

function requireDarwinLibraries(): Readonly<{
  process: NonNullable<typeof processLibrary>;
  system: NonNullable<typeof systemLibrary>;
}> {
  if (systemLibrary === null || processLibrary === null) {
    throw new MacOSResidentCustodyProbeError(
      "unsupported_platform",
      "Resident custody probing is available only on macOS.",
    );
  }
  return { process: processLibrary, system: systemLibrary };
}

function errnoBuffer(): Buffer {
  const { system } = requireDarwinLibraries();
  const location = system.symbols.__error();
  if (location === null) {
    throw new MacOSResidentCustodyProbeError(
      "permanent_failure",
      "Darwin errno storage is unavailable.",
      true,
    );
  }
  return toBuffer(location, 0, 4);
}

function nativeErrno(): number {
  return errnoBuffer().readInt32LE(0);
}

function clearNativeErrno(): void {
  errnoBuffer().writeInt32LE(0, 0);
}

function closeDescriptor(descriptor: number): void {
  if (descriptor < 0) return;
  try {
    closeSync(descriptor);
  } catch {
    // Every descriptor close is idempotently best-effort during containment.
  }
}

function cloexecFlag(): number {
  const value: unknown = Reflect.get(constants, "O_CLOEXEC");
  if (
    value !== undefined
    && value !== macosResidentCustodyProbeAbi.openCloseOnExec
  ) {
    throw new MacOSResidentCustodyProbeError(
      "permanent_failure",
      "Darwin O_CLOEXEC differs from its frozen SDK ABI.",
      true,
    );
  }
  return macosResidentCustodyProbeAbi.openCloseOnExec;
}

function nonBlockingFlag(): number {
  const value: unknown = Reflect.get(constants, "O_NONBLOCK");
  if (typeof value !== "number") {
    throw new MacOSResidentCustodyProbeError(
      "permanent_failure",
      "Darwin O_NONBLOCK is unavailable.",
      true,
    );
  }
  return value;
}

function duplicatePipeDescriptor(
  descriptor: number,
  access: "read" | "write",
): number {
  const accessFlag = access === "read" ? constants.O_RDONLY : constants.O_WRONLY;
  return openSync(`/dev/fd/${descriptor}`, accessFlag | cloexecFlag());
}

function createDarwinPipe(): ResidentPipe {
  const { system } = requireDarwinLibraries();
  const descriptors = Buffer.alloc(8);
  clearNativeErrno();
  if (system.symbols.pipe(ptr(descriptors)) !== 0) {
    throw new MacOSResidentCustodyProbeError(
      "spawn_failed",
      `Darwin pipe creation failed (errno=${nativeErrno()}).`,
    );
  }
  const rawRead = descriptors.readInt32LE(0);
  const rawWrite = descriptors.readInt32LE(4);
  let read = -1;
  let write = -1;
  try {
    // Darwin cannot execute /dev/fd/N, but opening it is a non-variadic Node
    // fs operation that safely duplicates a pipe end with O_CLOEXEC. No FFI
    // open/fcntl call is permitted in this module.
    read = duplicatePipeDescriptor(rawRead, "read");
    write = duplicatePipeDescriptor(rawWrite, "write");
    return Object.freeze({ read, write });
  } catch (error) {
    closeDescriptor(read);
    closeDescriptor(write);
    throw error;
  } finally {
    closeDescriptor(rawRead);
    closeDescriptor(rawWrite);
  }
}

function signalAction(handler: bigint): Buffer {
  const action = Buffer.alloc(macosResidentCustodyProbeAbi.sigactionBytes);
  action.writeBigUInt64LE(handler, 0);
  action.writeUInt32LE(0, 8);
  action.writeInt32LE(0, 12);
  return action;
}

function enterDarwinSignalPolicy(): SignalPolicyLease {
  const { system } = requireDarwinLibraries();
  const childAction = Buffer.alloc(macosResidentCustodyProbeAbi.sigactionBytes);
  const pipeAction = Buffer.alloc(macosResidentCustodyProbeAbi.sigactionBytes);
  const oldMask = Buffer.alloc(macosResidentCustodyProbeAbi.sigsetBytes);
  const defaultChild = signalAction(signalDefault);
  const ignoredPipe = signalAction(signalIgnored);
  const unblockedMask = Buffer.alloc(macosResidentCustodyProbeAbi.sigsetBytes);
  let childChanged = false;
  let pipeChanged = false;
  let maskChanged = false;
  try {
    if (
      system.symbols.sigaction(
        signalChild,
        ptr(defaultChild),
        ptr(childAction),
      ) !== 0
    ) {
      throw new Error("SIGCHLD disposition");
    }
    childChanged = true;
    if (
      system.symbols.sigaction(
        signalPipe,
        ptr(ignoredPipe),
        ptr(pipeAction),
      ) !== 0
    ) {
      throw new Error("SIGPIPE disposition");
    }
    pipeChanged = true;
    if (
      system.symbols.sigprocmask(
        signalSetMask,
        null,
        ptr(oldMask),
      ) !== 0
    ) {
      throw new Error("signal mask capture");
    }
    oldMask.copy(unblockedMask);
    if (
      system.symbols.sigdelset(ptr(unblockedMask), signalChild) !== 0
      || system.symbols.sigprocmask(
        signalSetMask,
        ptr(unblockedMask),
        ptr(oldMask),
      ) !== 0
    ) {
      throw new Error("SIGCHLD unblock");
    }
    maskChanged = true;
    return Object.freeze({
      childAction: Buffer.from(childAction),
      mask: Buffer.from(oldMask),
      pipeAction: Buffer.from(pipeAction),
    });
  } catch (error) {
    let restored = true;
    if (childChanged) {
      restored = system.symbols.sigaction(
        signalChild,
        ptr(childAction),
        ptr(Buffer.alloc(macosResidentCustodyProbeAbi.sigactionBytes)),
      ) === 0 && restored;
    }
    if (pipeChanged) {
      restored = system.symbols.sigaction(
        signalPipe,
        ptr(pipeAction),
        ptr(Buffer.alloc(macosResidentCustodyProbeAbi.sigactionBytes)),
      ) === 0 && restored;
    }
    if (maskChanged) {
      restored = system.symbols.sigprocmask(
        signalSetMask,
        ptr(oldMask),
        ptr(Buffer.alloc(macosResidentCustodyProbeAbi.sigsetBytes)),
      ) === 0 && restored;
    }
    throw new MacOSResidentCustodyProbeError(
      restored ? "spawn_failed" : "permanent_failure",
      restored
        ? `Resident signal-policy admission failed: ${String(error)}.`
        : "Resident signal-policy admission and restoration both failed.",
      !restored,
      !restored,
    );
  }
}

function restoreDarwinSignalPolicy(lease: SignalPolicyLease): boolean {
  const { system } = requireDarwinLibraries();
  const scratchAction = Buffer.alloc(macosResidentCustodyProbeAbi.sigactionBytes);
  const scratchMask = Buffer.alloc(macosResidentCustodyProbeAbi.sigsetBytes);
  // Restore all three pieces even if an earlier call fails. A false result is
  // a permanent process error: callers must not continue with partial policy.
  const child = system.symbols.sigaction(
    signalChild,
    ptr(lease.childAction),
    ptr(scratchAction),
  ) === 0;
  const pipe = system.symbols.sigaction(
    signalPipe,
    ptr(lease.pipeAction),
    ptr(scratchAction),
  ) === 0;
  // Restore the prior mask last. If it unblocks a pending signal, its exact
  // prior disposition is already installed before delivery can occur.
  const mask = system.symbols.sigprocmask(
    signalSetMask,
    ptr(lease.mask),
    ptr(scratchMask),
  ) === 0;
  return mask && pipe && child;
}

function cStringVector(values: readonly string[]): Readonly<{
  storage: readonly Buffer[];
  table: Buffer;
}> {
  const storage = values.map(value => {
    if (value.length === 0 || value.includes("\0")) {
      throw new MacOSResidentCustodyProbeError(
        "input_invalid",
        "Resident probe argv/environment contains an invalid string.",
      );
    }
    return Buffer.from(`${value}\0`, "utf8");
  });
  const table = Buffer.alloc((storage.length + 1) * 8);
  storage.forEach((value, index) => {
    const address = ptr(value);
    if (address === null) {
      throw new MacOSResidentCustodyProbeError(
        "permanent_failure",
        "Resident probe could not bind an argv/environment pointer.",
        true,
      );
    }
    table.writeBigUInt64LE(BigInt(address), index * 8);
  });
  return { storage, table };
}

function spawnDarwin(input: Parameters<MacOSResidentCustodyProbeNative["spawn"]>[0]): number {
  const { system } = requireDarwinLibraries();
  const attributes = Buffer.alloc(macosResidentCustodyProbeAbi.posixSpawnHandleBytes);
  const actions = Buffer.alloc(macosResidentCustodyProbeAbi.posixSpawnHandleBytes);
  const childMask = Buffer.alloc(macosResidentCustodyProbeAbi.sigsetBytes);
  const childDefaults = Buffer.alloc(macosResidentCustodyProbeAbi.sigsetBytes);
  const processIdentifier = Buffer.alloc(4);
  let attributesInitialized = false;
  let actionsInitialized = false;
  let nullDescriptor = -1;
  try {
    if (system.symbols.posix_spawnattr_init(ptr(attributes)) !== 0) {
      throw new Error("posix_spawnattr_init");
    }
    attributesInitialized = true;
    if (system.symbols.posix_spawn_file_actions_init(ptr(actions)) !== 0) {
      throw new Error("posix_spawn_file_actions_init");
    }
    actionsInitialized = true;
    if (
      system.symbols.sigemptyset(ptr(childMask)) !== 0
      || system.symbols.sigemptyset(ptr(childDefaults)) !== 0
      || system.symbols.sigaddset(ptr(childDefaults), signalHangup) !== 0
      || system.symbols.sigaddset(ptr(childDefaults), signalInterrupt) !== 0
      || system.symbols.sigaddset(ptr(childDefaults), signalQuit) !== 0
      || system.symbols.sigaddset(ptr(childDefaults), signalTerminate) !== 0
      || system.symbols.sigaddset(ptr(childDefaults), signalChild) !== 0
      || system.symbols.sigaddset(ptr(childDefaults), signalPipe) !== 0
    ) {
      throw new Error("child signal sets");
    }
    const flags = posixSpawnCloseOnExecDefault | posixSpawnSetProcessGroup
      | posixSpawnSetSignalDefault | posixSpawnSetSignalMask;
    nullDescriptor = openSync(
      "/dev/null",
      constants.O_RDONLY | cloexecFlag(),
    );
    if (
      system.symbols.posix_spawnattr_setflags(ptr(attributes), flags) !== 0
      || system.symbols.posix_spawnattr_setpgroup(ptr(attributes), 0) !== 0
      || system.symbols.posix_spawnattr_setsigmask(
        ptr(attributes),
        ptr(childMask),
      ) !== 0
      || system.symbols.posix_spawnattr_setsigdefault(
        ptr(attributes),
        ptr(childDefaults),
      ) !== 0
      // File actions are ordered. Close parent-side descriptors before fd 3
      // is installed, so even the lowest available-pipe collision is safe.
      || system.symbols.posix_spawn_file_actions_addclose(
        ptr(actions),
        input.standardOutputReadDescriptor,
      ) !== 0
      || system.symbols.posix_spawn_file_actions_addclose(
        ptr(actions),
        input.standardErrorReadDescriptor,
      ) !== 0
      || system.symbols.posix_spawn_file_actions_addclose(
        ptr(actions),
        input.lifetimeWriteDescriptor,
      ) !== 0
      || system.symbols.posix_spawn_file_actions_adddup2(
        ptr(actions),
        nullDescriptor,
        0,
      ) !== 0
      || system.symbols.posix_spawn_file_actions_adddup2(
        ptr(actions),
        input.standardOutputWriteDescriptor,
        1,
      ) !== 0
      || system.symbols.posix_spawn_file_actions_adddup2(
        ptr(actions),
        input.standardErrorWriteDescriptor,
        2,
      ) !== 0
      || system.symbols.posix_spawn_file_actions_adddup2(
        ptr(actions),
        input.lifetimeReadDescriptor,
        macosResidentCustodyProbeAbi.parentLeaseDescriptor,
      ) !== 0
    ) {
      throw new Error("posix_spawn configuration");
    }
    const arguments_ = cStringVector(input.arguments);
    const environment = cStringVector(input.environment);
    const executable = Buffer.from(`${input.executable}\0`, "utf8");
    const status = system.symbols.posix_spawn(
      ptr(processIdentifier),
      executable,
      ptr(actions),
      ptr(attributes),
      ptr(arguments_.table),
      ptr(environment.table),
    );
    // Keep argv/env backing storage live through the native call.
    void arguments_.storage;
    void environment.storage;
    if (status !== 0) {
      throw new MacOSResidentCustodyProbeError(
        "spawn_failed",
        `Resident supervisor spawn failed (status=${status}).`,
      );
    }
    return processIdentifier.readInt32LE(0);
  } catch (error) {
    if (error instanceof MacOSResidentCustodyProbeError) throw error;
    throw new MacOSResidentCustodyProbeError(
      "spawn_failed",
      `Resident supervisor spawn setup failed: ${String(error)}.`,
    );
  } finally {
    closeDescriptor(nullDescriptor);
    if (actionsInitialized) {
      system.symbols.posix_spawn_file_actions_destroy(ptr(actions));
    }
    if (attributesInitialized) {
      system.symbols.posix_spawnattr_destroy(ptr(attributes));
    }
  }
}

function listedProcesses(type: number, identifier: number): number[] | null {
  const { process: processApi } = requireDarwinLibraries();
  const bytes = Buffer.alloc(maximumListedProcesses * 4);
  clearNativeErrno();
  const count = processApi.symbols.proc_listpids(
    type,
    identifier,
    ptr(bytes),
    bytes.byteLength,
  );
  if (count < 0 || count >= bytes.byteLength || count % 4 !== 0) return null;
  const result: number[] = [];
  for (let offset = 0; offset < count; offset += 4) {
    const pid = bytes.readInt32LE(offset);
    if (pid > 0) result.push(pid);
  }
  return [...new Set(result)].sort((left, right) => left - right);
}

function assertDarwinDirectChildren(expectedPid: number | null): boolean {
  const children = listedProcesses(processParentOnly, process.pid);
  if (children === null) return false;
  return expectedPid === null
    ? children.length === 0
    : children.every(pid => pid === expectedPid);
}

function inspectDarwinGeneration(
  processIdentifier: number,
  path: string,
  expectedCdHash: string,
): ResidentProcessGeneration | null {
  const { process: processApi, system } = requireDarwinLibraries();
  const information = Buffer.alloc(macosResidentCustodyProbeAbi.procBsdInfoBytes);
  const informationBytes = processApi.symbols.proc_pidinfo(
    processIdentifier,
    processBsdInfoFlavor,
    0,
    ptr(information),
    information.byteLength,
  );
  if (informationBytes !== information.byteLength) return null;
  const pid = information.readUInt32LE(macosResidentCustodyProbeAbi.procPidOffset);
  const ppid = information.readUInt32LE(macosResidentCustodyProbeAbi.procPpidOffset);
  const pgid = information.readUInt32LE(macosResidentCustodyProbeAbi.procPgidOffset);
  const processStatus = information.readUInt32LE(4);
  const startSeconds = information.readBigUInt64LE(
    macosResidentCustodyProbeAbi.procStartSecondsOffset,
  );
  const startMicroseconds = information.readBigUInt64LE(
    macosResidentCustodyProbeAbi.procStartMicrosecondsOffset,
  );
  if (
    pid !== processIdentifier
    || ppid !== process.pid
    || pgid !== processIdentifier
    || processStatus === processZombieStatus
    || startSeconds === 0n
    || startMicroseconds >= 1_000_000n
    || system.symbols.getpgid(processIdentifier) !== processIdentifier
  ) return null;

  const processPath = Buffer.alloc(4096);
  const pathLength = processApi.symbols.proc_pidpath(
    processIdentifier,
    ptr(processPath),
    processPath.byteLength,
  );
  if (
    pathLength <= 0
    || pathLength >= processPath.byteLength
    || processPath.subarray(0, pathLength).toString("utf8") !== path
  ) return null;

  const cdHash = Buffer.alloc(20);
  const codeStatus = Buffer.alloc(4);
  if (
    system.symbols.csops(processIdentifier, csOpsCdHash, ptr(cdHash), 20) !== 0
    || system.symbols.csops(
      processIdentifier,
      csOpsStatus,
      ptr(codeStatus),
      4,
    ) !== 0
  ) return null;
  const status = codeStatus.readUInt32LE(0);
  if (
    cdHash.toString("hex") !== expectedCdHash
    || (status & requiredLiveCodeStatus) !== requiredLiveCodeStatus
    || (status & forbiddenLiveCodeStatus) !== 0
  ) return null;
  return Object.freeze({
    cdHash: cdHash.toString("hex"),
    codeStatus: status,
    path,
    pgid,
    pid,
    ppid,
    startMicroseconds,
    startSeconds,
  });
}

function waitDarwinWithoutReaping(
  processIdentifier: number,
): ResidentTerminalObservation | null {
  const { system } = requireDarwinLibraries();
  const information = Buffer.alloc(macosResidentCustodyProbeAbi.siginfoBytes);
  while (true) {
    clearNativeErrno();
    const status = system.symbols.waitid(
      waitPidType,
      processIdentifier,
      ptr(information),
      waitExited | waitNoReap | waitNoHang,
    );
    if (status === 0) {
      const pid = information.readInt32LE(
        macosResidentCustodyProbeAbi.siginfoPidOffset,
      );
      if (pid === 0) return null;
      const code = information.readInt32LE(
        macosResidentCustodyProbeAbi.siginfoCodeOffset,
      );
      if (
        pid !== processIdentifier
        || (code !== macosResidentCustodyProbeAbi.cldExited
          && code !== macosResidentCustodyProbeAbi.cldKilled
          && code !== macosResidentCustodyProbeAbi.cldDumped)
      ) {
        throw new MacOSResidentCustodyProbeError(
          "permanent_failure",
          "Resident WNOWAIT returned ambiguous child identity.",
          true,
          true,
          true,
        );
      }
      return Object.freeze({
        code,
        pid,
        status: information.readInt32LE(
          macosResidentCustodyProbeAbi.siginfoStatusOffset,
        ),
      });
    }
    const error = nativeErrno();
    if (error === errnoInterrupted) continue;
    if (error === errnoNoChild) {
      throw new MacOSResidentCustodyProbeError(
        "permanent_failure",
        "Resident WNOWAIT child lease was lost (ECHILD).",
        true,
        true,
        true,
      );
    }
    throw new MacOSResidentCustodyProbeError(
      "probe_failed",
      `Resident WNOWAIT failed while its lease remained held (errno=${error}).`,
    );
  }
}

function darwinGroupIsQuiescent(
  processIdentifier: number,
  leaderTerminal: boolean,
): boolean {
  const members = listedProcesses(processGroupOnly, processIdentifier);
  if (members === null) return false;
  for (const member of members) {
    if (member === processIdentifier && leaderTerminal) continue;
    const generation = Buffer.alloc(macosResidentCustodyProbeAbi.procBsdInfoBytes);
    const { process: processApi } = requireDarwinLibraries();
    clearNativeErrno();
    const count = processApi.symbols.proc_pidinfo(
      member,
      processBsdInfoFlavor,
      0,
      ptr(generation),
      generation.byteLength,
    );
    if (count === 0 && nativeErrno() === errnoNoProcess) continue;
    if (
      count !== generation.byteLength
      || generation.readUInt32LE(macosResidentCustodyProbeAbi.procPidOffset)
        !== member
    ) return false;
    if (
      generation.readUInt32LE(macosResidentCustodyProbeAbi.procPgidOffset)
        !== processIdentifier
    ) continue;
    if (generation.readUInt32LE(4) !== processZombieStatus) return false;
  }
  return true;
}

function pollDarwinReadable(
  descriptors: readonly number[],
  timeoutMilliseconds: number,
): ReadonlyMap<number, number> {
  const { system } = requireDarwinLibraries();
  if (descriptors.length === 0) {
    clearNativeErrno();
    const status = system.symbols.poll(null, 0, timeoutMilliseconds);
    if (status === 0 || (status < 0 && nativeErrno() === errnoInterrupted)) {
      return new Map();
    }
    throw new MacOSResidentCustodyProbeError(
      "probe_failed",
      `Resident empty poll failed (status=${status}, errno=${nativeErrno()}).`,
    );
  }
  const records = Buffer.alloc(descriptors.length * 8);
  descriptors.forEach((descriptor, index) => {
    records.writeInt32LE(descriptor, index * 8);
    records.writeInt16LE(pollIn | pollHangup, index * 8 + 4);
  });
  clearNativeErrno();
  const status = system.symbols.poll(
    ptr(records),
    descriptors.length,
    timeoutMilliseconds,
  );
  if (status < 0) {
    if (nativeErrno() === errnoInterrupted) return new Map();
    throw new MacOSResidentCustodyProbeError(
      "probe_failed",
      `Resident pipe poll failed (errno=${nativeErrno()}).`,
    );
  }
  const result = new Map<number, number>();
  descriptors.forEach((descriptor, index) => {
    const events = records.readInt16LE(index * 8 + 6);
    if (events !== 0) result.set(descriptor, events);
  });
  return result;
}

function readDarwinPipe(descriptor: number, maximumBytes: number): Buffer | null {
  const bytes = Buffer.alloc(Math.max(1, maximumBytes));
  while (true) {
    try {
      const count = readSync(descriptor, bytes, 0, bytes.byteLength, null);
      return count === 0 ? null : Buffer.from(bytes.subarray(0, count));
    } catch (error: unknown) {
      const code = (error as NodeJS.ErrnoException).code;
      if (code === "EINTR") continue;
      throw error;
    }
  }
}

function killDarwinGroupOnce(processIdentifier: number): "missing" | "sent" {
  const { system } = requireDarwinLibraries();
  clearNativeErrno();
  if (system.symbols.kill(-processIdentifier, signalKill) === 0) return "sent";
  if (nativeErrno() === errnoNoProcess) return "missing";
  throw new MacOSResidentCustodyProbeError(
    "permanent_failure",
    `Resident group termination became ambiguous (errno=${nativeErrno()}).`,
    true,
    true,
  );
}

function reapDarwin(processIdentifier: number): ResidentReapObservation {
  const { system } = requireDarwinLibraries();
  const statusBuffer = Buffer.alloc(4);
  while (true) {
    clearNativeErrno();
    const waited = system.symbols.waitpid(
      processIdentifier,
      ptr(statusBuffer),
      0,
    );
    if (waited === processIdentifier) {
      const status = statusBuffer.readInt32LE(0);
      return Object.freeze({
        exited: (status & 0x7f) === 0,
        exitStatus: (status >>> 8) & 0xff,
        signal: status & 0x7f,
      });
    }
    const error = nativeErrno();
    if (waited < 0 && error === errnoInterrupted) continue;
    if (waited < 0 && error === errnoNoChild) {
      throw new MacOSResidentCustodyProbeError(
        "permanent_failure",
        "Resident exact reap lost its child lease (ECHILD).",
        true,
        true,
        true,
      );
    }
    throw new MacOSResidentCustodyProbeError(
      "permanent_failure",
      `Resident exact reap became ambiguous (pid=${waited}, errno=${error}).`,
      true,
      true,
      true,
    );
  }
}

const defaultMacOSResidentCustodyProbeNative = Object.freeze({
  assertDirectChildren: assertDarwinDirectChildren,
  close: closeDescriptor,
  createPipe: createDarwinPipe,
  enterSignalPolicy: enterDarwinSignalPolicy,
  groupIsQuiescent: darwinGroupIsQuiescent,
  inspectGeneration: inspectDarwinGeneration,
  killGroupOnce: killDarwinGroupOnce,
  nowMilliseconds: () => performance.now(),
  pollReadable: pollDarwinReadable,
  read: readDarwinPipe,
  reap: reapDarwin,
  restoreSignalPolicy: restoreDarwinSignalPolicy,
  spawn: spawnDarwin,
  waitWithoutReaping: waitDarwinWithoutReaping,
  write: (descriptor, bytes) => writeSync(descriptor, bytes),
} satisfies MacOSResidentCustodyProbeNative);

export const defaultMacOSResidentCustodyProbeDependencies = Object.freeze({
  native: defaultMacOSResidentCustodyProbeNative,
  terminateProcess: (error: MacOSResidentCustodyProbeError): never => {
    // Continuing the release CLI after losing an unreaped child lease or
    // failing exact signal restoration would make every later PID unsafe.
    void error;
    process.abort();
  },
} satisfies MacOSResidentCustodyProbeDependencies);

function requireCanonicalAbsolutePath(path: string, label: string): string {
  if (
    !isAbsolute(path)
    || normalize(path) !== path
    || path === "/"
    || path.includes("\0")
  ) {
    throw new MacOSResidentCustodyProbeError(
      "input_invalid",
      `${label} must be an absolute normalized non-root path.`,
    );
  }
  let canonical: string;
  try {
    canonical = realpathSync(path);
  } catch {
    throw new MacOSResidentCustodyProbeError(
      "filesystem_unsafe",
      `${label} is unavailable.`,
    );
  }
  if (canonical !== path) {
    throw new MacOSResidentCustodyProbeError(
      "filesystem_unsafe",
      `${label} is not canonical.`,
    );
  }
  return canonical;
}

function sameFile(left: BigIntStats, right: BigIntStats): boolean {
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

function sha256Descriptor(descriptor: number, size: bigint): string {
  const digest = createHash("sha256");
  const chunk = Buffer.alloc(64 * 1024);
  let offset = 0;
  while (BigInt(offset) < size) {
    const remaining = size - BigInt(offset);
    const maximum = remaining > BigInt(chunk.byteLength)
      ? chunk.byteLength
      : Number(remaining);
    const count = readSync(descriptor, chunk, 0, maximum, offset);
    if (count <= 0) {
      throw new MacOSResidentCustodyProbeError(
        "filesystem_unsafe",
        "Resident supervisor could not be read completely.",
      );
    }
    digest.update(chunk.subarray(0, count));
    offset += count;
  }
  return digest.digest("hex");
}

function holdSupervisor(
  candidateApp: string,
  authority: CustodyProbeSupervisorAuthorityEvidence,
): HeldSupervisor {
  const candidateMetadata = lstatSync(candidateApp, { bigint: true });
  if (!candidateMetadata.isDirectory() || candidateMetadata.isSymbolicLink()) {
    throw new MacOSResidentCustodyProbeError(
      "filesystem_unsafe",
      "Candidate application root is not one canonical directory.",
    );
  }
  const path = join(
    candidateApp,
    "Contents",
    "Resources",
    "runtime",
    authority.runtimeRelativePath,
  );
  if (realpathSync(path) !== path) {
    throw new MacOSResidentCustodyProbeError(
      "filesystem_unsafe",
      "Resident supervisor path is not canonical.",
    );
  }
  const descriptor = openSync(
    path,
    constants.O_RDONLY
      | constants.O_NOFOLLOW
      | cloexecFlag()
      | nonBlockingFlag(),
  );
  try {
    const held = fstatSync(descriptor, { bigint: true });
    const named = lstatSync(path, { bigint: true });
    if (
      !held.isFile()
      || held.isSymbolicLink()
      || named.isSymbolicLink()
      || held.nlink !== 1n
      || held.size <= 0n
      || held.size > BigInt(maximumSupervisorBytes)
      || (held.mode & 0o111n) === 0n
      || !sameFile(held, named)
    ) {
      throw new MacOSResidentCustodyProbeError(
        "filesystem_unsafe",
        "Resident supervisor file authority is unsafe.",
      );
    }
    const sha256 = sha256Descriptor(descriptor, held.size);
    const after = fstatSync(descriptor, { bigint: true });
    const namedAfter = lstatSync(path, { bigint: true });
    if (
      sha256 !== authority.sha256
      || !sameFile(held, after)
      || !sameFile(held, namedAfter)
    ) {
      throw new MacOSResidentCustodyProbeError(
        "authority_invalid",
        "Resident supervisor differs from receipt-bound authority.",
      );
    }
    return Object.freeze({ descriptor, metadata: held, path, sha256 });
  } catch (error) {
    closeDescriptor(descriptor);
    throw error;
  }
}

function requireHeldSupervisorExact(
  held: HeldSupervisor,
  authority: CustodyProbeSupervisorAuthorityEvidence,
): void {
  const descriptor = fstatSync(held.descriptor, { bigint: true });
  const named = lstatSync(held.path, { bigint: true });
  if (
    realpathSync(held.path) !== held.path
    || !sameFile(held.metadata, descriptor)
    || !sameFile(held.metadata, named)
    || sha256Descriptor(held.descriptor, held.metadata.size) !== held.sha256
    || held.sha256 !== authority.sha256
  ) {
    throw new MacOSResidentCustodyProbeError(
      "authority_invalid",
      "Resident supervisor authority changed while held.",
    );
  }
}

function requireCandidateExecutable(candidateApp: string): string {
  const path = join(candidateApp, "Contents", "MacOS", "hra");
  if (realpathSync(path) !== path) {
    throw new MacOSResidentCustodyProbeError(
      "filesystem_unsafe",
      "Candidate host path is not canonical.",
    );
  }
  const metadata = lstatSync(path, { bigint: true });
  if (
    !metadata.isFile()
    || metadata.isSymbolicLink()
    || metadata.nlink !== 1n
    || (metadata.mode & 0o111n) === 0n
  ) {
    throw new MacOSResidentCustodyProbeError(
      "filesystem_unsafe",
      "Candidate host executable authority is unsafe.",
    );
  }
  return path;
}

function requireInput(
  input: MacOSResidentCustodyProbeInput,
): Readonly<{
  arguments: readonly string[];
  authority: CustodyProbeSupervisorAuthorityEvidence;
  candidateApp: string;
  expectedStdout: string | null;
  host: string;
  mode: MacOSResidentCustodyProbeInput["mode"];
}> {
  let authority: CustodyProbeSupervisorAuthorityEvidence;
  try {
    authority = parseProductionCustodyProbeSupervisorAuthority(input.authority);
  } catch {
    throw new MacOSResidentCustodyProbeError(
      "authority_invalid",
      "Resident supervisor receipt authority is invalid.",
    );
  }
  const candidateApp = requireCanonicalAbsolutePath(
    input.candidateApp,
    "Candidate application",
  );
  const host = requireCandidateExecutable(candidateApp);
  if (input.mode === "authorize") {
    if (!canonicalAuthorizationOutput(input.expectedStdout)) {
      throw new MacOSResidentCustodyProbeError(
        "input_invalid",
        "Expected authorize-only receipt is not canonical or no-Keychain.",
      );
    }
    return {
      arguments: ["authorize", host],
      authority,
      candidateApp,
      expectedStdout: input.expectedStdout,
      host,
      mode: input.mode,
    };
  }
  if (input.mode === "status") {
    return {
      arguments: ["status", host],
      authority,
      candidateApp,
      expectedStdout: null,
      host,
      mode: input.mode,
    };
  }
  if (
    !Number.isSafeInteger(input.dwellMilliseconds)
    || input.dwellMilliseconds <= 0
    || input.dwellMilliseconds > 30_000
  ) {
    throw new MacOSResidentCustodyProbeError(
      "input_invalid",
      "Resident smoke dwell is outside its native bound.",
    );
  }
  const smokeRoot = requireCanonicalAbsolutePath(input.smokeRoot, "Smoke root");
  return {
    arguments: [
      "smoke",
      host,
      smokeRoot,
      String(input.dwellMilliseconds),
    ],
    authority,
    candidateApp,
    expectedStdout: "",
    host,
    mode: input.mode,
  };
}

function canonicalAuthorizationOutput(text: string): boolean {
  return /^\{"authorization":"hra-parent-v1","gatewayFileSha256":"[0-9a-f]{64}","keychainAccessed":false,"ok":true,"rendererAuthoritySha256":"[0-9a-f]{64}","version":1\}\n$/u
    .test(text);
}

function sanitizedEnvironment(): readonly string[] {
  const environment = ["LANG=C", "LC_ALL=C", "PATH=/usr/bin:/bin"];
  for (const name of ["HOME", "LOGNAME", "TMPDIR", "USER"] as const) {
    const value = process.env[name];
    if (
      value !== undefined
      && value.length > 0
      && !value.includes("\0")
      && !value.includes("\n")
    ) {
      environment.push(`${name}=${value}`);
    }
  }
  return Object.freeze(environment);
}

function sameGeneration(
  left: ResidentProcessGeneration,
  right: ResidentProcessGeneration,
): boolean {
  return left.pid === right.pid
    && left.ppid === right.ppid
    && left.pgid === right.pgid
    && left.startSeconds === right.startSeconds
    && left.startMicroseconds === right.startMicroseconds
    && left.path === right.path
    && left.cdHash === right.cdHash
    && left.codeStatus === right.codeStatus;
}

function closeNativeDescriptor(
  native: MacOSResidentCustodyProbeNative,
  descriptor: number,
): boolean {
  if (descriptor < 0) return true;
  try {
    native.close(descriptor);
    return true;
  } catch {
    return false;
  }
}

function closeOutput(
  state: OutputPipeState,
  native: MacOSResidentCustodyProbeNative,
): boolean {
  const closed = closeNativeDescriptor(native, state.descriptor);
  state.descriptor = -1;
  state.eof = true;
  return closed;
}

function drainReadyOutput(
  state: OutputPipeState,
  events: number,
  native: MacOSResidentCustodyProbeNative,
): boolean {
  if (state.eof) return true;
  if ((events & (pollError | pollInvalid)) !== 0) {
    closeOutput(state, native);
    return false;
  }
  if ((events & (pollIn | pollHangup)) === 0) return true;
  const remaining = macosCustodyProbeMaximumOutputBytes + 1 - state.length;
  let bytes: Buffer | null;
  try {
    bytes = native.read(state.descriptor, Math.max(1, remaining));
  } catch (error) {
    if (error instanceof MacOSResidentCustodyProbeError && error.permanent) {
      throw error;
    }
    closeOutput(state, native);
    return false;
  }
  if (bytes === null) {
    return closeOutput(state, native);
  }
  state.bytes.push(bytes);
  state.length += bytes.byteLength;
  if (state.length > macosCustodyProbeMaximumOutputBytes) {
    state.overflow = true;
    closeOutput(state, native);
    return false;
  }
  return true;
}

function pollAndDrainOutputs(
  stdout: OutputPipeState,
  stderr: OutputPipeState,
  native: MacOSResidentCustodyProbeNative,
): boolean {
  const descriptors = [stdout, stderr]
    .filter(state => !state.eof)
    .map(state => state.descriptor);
  let ready: ReadonlyMap<number, number>;
  try {
    ready = native.pollReadable(descriptors, pollSliceMilliseconds);
  } catch (error) {
    if (error instanceof MacOSResidentCustodyProbeError && error.permanent) {
      throw error;
    }
    closeOutput(stdout, native);
    closeOutput(stderr, native);
    return false;
  }
  return drainReadyOutput(
    stdout,
    ready.get(stdout.descriptor) ?? 0,
    native,
  ) && drainReadyOutput(
    stderr,
    ready.get(stderr.descriptor) ?? 0,
    native,
  );
}

function recoverableOperationError(error: unknown): Error {
  if (
    error instanceof MacOSResidentCustodyProbeError
    && (error.permanent || error.processTerminal || error.leaseLost)
  ) {
    throw error;
  }
  return error instanceof Error ? error : new Error(String(error));
}

function throwPermanentRestorationFailure(): never {
  throw new MacOSResidentCustodyProbeError(
    "permanent_failure",
    "Resident signal policy restoration is permanently ambiguous.",
    true,
    true,
  );
}

function outputText(state: OutputPipeState): string {
  return Buffer.concat(state.bytes, state.length).toString("utf8");
}

function validateOutput(
  mode: MacOSResidentCustodyProbeInput["mode"],
  stdout: string,
  stderr: string,
  expectedStdout: string | null,
): void {
  if (stderr !== "") {
    throw new MacOSResidentCustodyProbeError(
      "output_invalid",
      "Resident supervisor emitted standard error.",
    );
  }
  if (mode === "authorize") {
    if (
      expectedStdout === null
      || stdout !== expectedStdout
      || !canonicalAuthorizationOutput(stdout)
    ) {
      throw new MacOSResidentCustodyProbeError(
        "output_invalid",
        "Resident authorize-only receipt differs or accessed Keychain.",
      );
    }
    return;
  }
  if (mode === "status") {
    try {
      // This accepts only absent or one strictAcl=true envelope digest. The
      // host status mode performs exactly one no-UI descriptor digest read.
      parseCanonicalMacOSCustodyStatus(stdout);
    } catch {
      throw new MacOSResidentCustodyProbeError(
        "output_invalid",
        "Resident no-UI custody status is not canonical.",
      );
    }
    return;
  }
  if (stdout !== "") {
    throw new MacOSResidentCustodyProbeError(
      "output_invalid",
      "Resident smoke supervisor emitted unexpected output.",
    );
  }
}

/**
 * Run one candidate-owned supervisor under an exclusive, fully synchronous
 * PID/PGID lifetime lease.
 *
 * Same-UID boundary: posix_spawn must name the canonical path because Darwin
 * rejects executable /dev/fd paths. Before GO, S is blocked on fd 3 and has no
 * candidate authority. R holds and re-hashes the receipt-bound bytes, then
 * repeats the live path/generation/CDHash/posture check immediately before the
 * sole admission byte. A same-UID rename or exec substitution can therefore
 * only make the operation fail closed before authorize/status/smoke begins.
 */
function runMacOSResidentCustodyProbeCore(
  input: MacOSResidentCustodyProbeInput,
  dependencies: MacOSResidentCustodyProbeDependencies =
    defaultMacOSResidentCustodyProbeDependencies,
): MacOSResidentCustodyProbeResult {
  if (residentProbeActive) {
    throw new MacOSResidentCustodyProbeError(
      "child_conflict",
      "Another resident custody probe is already active.",
    );
  }
  const normalized = requireInput(input);
  const held = holdSupervisor(normalized.candidateApp, normalized.authority);
  const native = dependencies.native;
  let signalLease: SignalPolicyLease | null = null;
  let signalRestored = false;
  let processIdentifier = -1;
  let signalIssued = false;
  let lifetime: ResidentPipe | null = null;
  let standardOutput: ResidentPipe | null = null;
  let standardError: ResidentPipe | null = null;
  let operationFailure: Error | null = null;
  const stdoutState: OutputPipeState = {
    bytes: [], descriptor: -1, eof: false, length: 0, overflow: false,
  };
  const stderrState: OutputPipeState = {
    bytes: [], descriptor: -1, eof: false, length: 0, overflow: false,
  };
  residentProbeActive = true;
  try {
    if (!native.assertDirectChildren(null)) {
      throw new MacOSResidentCustodyProbeError(
        "child_conflict",
        "Resident probe requires an exclusive no-other-child interval.",
      );
    }
    signalLease = native.enterSignalPolicy();
    standardOutput = native.createPipe();
    standardError = native.createPipe();
    lifetime = native.createPipe();
    stdoutState.descriptor = standardOutput.read;
    stderrState.descriptor = standardError.read;
    const spawnedProcessIdentifier = native.spawn({
      arguments: [held.path, ...normalized.arguments],
      environment: sanitizedEnvironment(),
      executable: held.path,
      lifetimeReadDescriptor: lifetime.read,
      lifetimeWriteDescriptor: lifetime.write,
      standardErrorReadDescriptor: standardError.read,
      standardErrorWriteDescriptor: standardError.write,
      standardOutputReadDescriptor: standardOutput.read,
      standardOutputWriteDescriptor: standardOutput.write,
    });
    if (
      !Number.isSafeInteger(spawnedProcessIdentifier)
      || spawnedProcessIdentifier <= 1
    ) {
      // POSIX reports that a child was created, but without a usable PID its
      // identity and lifetime lease are unknowable. Capabilities and signal
      // policy can still be restored, but this process must not continue.
      throw new MacOSResidentCustodyProbeError(
        "permanent_failure",
        "Resident supervisor spawn succeeded without a usable PID lease.",
        true,
        true,
        true,
      );
    }
    processIdentifier = spawnedProcessIdentifier;
    let terminal: ResidentTerminalObservation | null = null;
    let quiescent = false;
    try {
    native.close(standardOutput.write);
    native.close(standardError.write);
    native.close(lifetime.read);
    standardOutput = { ...standardOutput, write: -1 };
    standardError = { ...standardError, write: -1 };
    lifetime = { ...lifetime, read: -1 };

    const admissionDeadline = native.nowMilliseconds() + admissionMilliseconds;
    let admittedGeneration: ResidentProcessGeneration | null = null;
    while (native.nowMilliseconds() < admissionDeadline) {
      if (!native.assertDirectChildren(processIdentifier)) {
        operationFailure = new MacOSResidentCustodyProbeError(
          "child_conflict",
          "A foreign child entered the resident probe interval.",
        );
        break;
      }
      const terminal = native.waitWithoutReaping(processIdentifier);
      if (terminal !== null) {
        operationFailure = new MacOSResidentCustodyProbeError(
          "admission_failed",
          "Resident supervisor exited before admission.",
        );
        break;
      }
      const generation = native.inspectGeneration(
        processIdentifier,
        held.path,
        normalized.authority.cdHash,
      );
      if (generation !== null) {
        admittedGeneration = generation;
        break;
      }
      native.pollReadable([], pollSliceMilliseconds);
    }
    if (admittedGeneration === null && operationFailure === null) {
      operationFailure = new MacOSResidentCustodyProbeError(
        "admission_failed",
        "Resident supervisor did not reach exact gated admission.",
      );
    }

    if (operationFailure === null && admittedGeneration !== null) {
      try {
        // No candidate result is eligible yet. Repeat both independent sides
        // of authority immediately before G: held immutable bytes/path and the
        // live kernel process image/generation/CDHash/posture.
        requireHeldSupervisorExact(held, normalized.authority);
        const repeated = native.inspectGeneration(
          processIdentifier,
          held.path,
          normalized.authority.cdHash,
        );
        if (
          repeated === null
          || !sameGeneration(admittedGeneration, repeated)
          || !native.assertDirectChildren(processIdentifier)
          || native.waitWithoutReaping(processIdentifier) !== null
        ) {
          throw new MacOSResidentCustodyProbeError(
            "admission_failed",
            "Resident supervisor authority changed immediately before GO.",
          );
        }
        if (native.write(lifetime.write, Buffer.from("G")) !== 1) {
          throw new MacOSResidentCustodyProbeError(
            "admission_failed",
            "Resident supervisor admission byte was not written exactly.",
          );
        }
      } catch (error) {
        operationFailure = recoverableOperationError(error);
      }
    }

    const operationDeadline = native.nowMilliseconds() + operationMilliseconds;
    while (operationFailure === null && native.nowMilliseconds() < operationDeadline) {
      if (!native.assertDirectChildren(processIdentifier)) {
        operationFailure = new MacOSResidentCustodyProbeError(
          "child_conflict",
          "A foreign child entered the admitted resident interval.",
        );
        break;
      }
      terminal = native.waitWithoutReaping(processIdentifier);
      quiescent = terminal !== null
        && native.groupIsQuiescent(processIdentifier, true);
      if (!pollAndDrainOutputs(stdoutState, stderrState, native)) {
        operationFailure = new MacOSResidentCustodyProbeError(
          "output_invalid",
          "Resident supervisor output exceeded or violated its pipe bound.",
        );
        break;
      }
      if (terminal !== null && quiescent && stdoutState.eof && stderrState.eof) {
        break;
      }
    }
    if (
      operationFailure === null
      && (terminal === null || !quiescent || !stdoutState.eof || !stderrState.eof)
    ) {
      operationFailure = new MacOSResidentCustodyProbeError(
        "probe_failed",
        "Resident supervisor exceeded its bounded operation interval.",
      );
    }
    } catch (error) {
      operationFailure = recoverableOperationError(error);
    }

    if (operationFailure !== null) {
      try {
        terminal = native.waitWithoutReaping(processIdentifier);
        quiescent = terminal !== null
          && native.groupIsQuiescent(processIdentifier, true);
      } catch (error) {
        const retirementFailure = recoverableOperationError(error);
        operationFailure ??= retirementFailure;
        terminal = null;
        quiescent = false;
      }
      if (!quiescent) {
        try {
          native.killGroupOnce(processIdentifier);
          signalIssued = true;
        } catch (error) {
          if (
            error instanceof MacOSResidentCustodyProbeError
            && error.processTerminal
          ) throw error;
          throw new MacOSResidentCustodyProbeError(
            "permanent_failure",
            `Resident group termination failed: ${String(error)}.`,
            true,
            true,
          );
        }
      }
    }

    const cleanupDeadline = native.nowMilliseconds() + cleanupMilliseconds;
    while (native.nowMilliseconds() < cleanupDeadline) {
      try {
        terminal = native.waitWithoutReaping(processIdentifier);
        quiescent = terminal !== null
          && native.groupIsQuiescent(processIdentifier, true);
      } catch (error) {
        const retirementFailure = recoverableOperationError(error);
        operationFailure ??= retirementFailure;
        terminal = null;
        quiescent = false;
      }
      const outputOkay = pollAndDrainOutputs(
        stdoutState,
        stderrState,
        native,
      );
      if (!outputOkay && operationFailure === null) {
        operationFailure = new MacOSResidentCustodyProbeError(
          "output_invalid",
          "Resident supervisor output failed during retirement.",
        );
      }
      if (terminal !== null && quiescent && stdoutState.eof && stderrState.eof) {
        break;
      }
    }
    if (terminal === null || !quiescent || !stdoutState.eof || !stderrState.eof) {
      throw new MacOSResidentCustodyProbeError(
        "permanent_failure",
        "Resident supervisor could not be retired within its exact lease.",
        true,
        true,
      );
    }

    // Final descriptor evidence is captured before reap. After the exact
    // waitpid below this function performs no numeric PID/PGID query/signal.
    try {
      requireHeldSupervisorExact(held, normalized.authority);
    } catch (error) {
      operationFailure ??= recoverableOperationError(error);
    }
    const reaping = native.reap(processIdentifier);
    if (!closeNativeDescriptor(native, lifetime.write)) {
      operationFailure ??= new MacOSResidentCustodyProbeError(
        "probe_failed",
        "Resident lifetime writer close failed after exact reap.",
      );
    }
    lifetime = { ...lifetime, write: -1 };
    if (
      terminal.code !== macosResidentCustodyProbeAbi.cldExited
      || terminal.status !== 0
      || !reaping.exited
      || reaping.exitStatus !== 0
      || reaping.signal !== 0
    ) {
      operationFailure ??= new MacOSResidentCustodyProbeError(
        "probe_failed",
        signalIssued
          ? "Resident supervisor was contained after probe failure."
          : "Resident supervisor did not exit cleanly.",
      );
    }

    let restored = false;
    try {
      restored = native.restoreSignalPolicy(signalLease);
    } catch {
      restored = false;
    }
    if (!restored) {
      throw new MacOSResidentCustodyProbeError(
        "permanent_failure",
        "Resident signal policy could not be restored after exact reap.",
        true,
        true,
      );
    }
    signalRestored = true;
    if (operationFailure !== null) throw operationFailure;
    const stdout = outputText(stdoutState);
    const stderr = outputText(stderrState);
    validateOutput(
      normalized.mode,
      stdout,
      stderr,
      normalized.expectedStdout,
    );
    return Object.freeze({ exitCode: 0, stderr: "", stdout });
  } finally {
    let restorationAmbiguous = false;
    // Lease-loss is a fatal permanent error. Close capabilities so S/H native
    // watchers retire, but never send or query a numeric PID after ECHILD.
    if (lifetime !== null) {
      closeNativeDescriptor(native, lifetime.read);
      closeNativeDescriptor(native, lifetime.write);
    }
    if (standardOutput !== null) {
      closeNativeDescriptor(native, standardOutput.read);
      closeNativeDescriptor(native, standardOutput.write);
    }
    if (standardError !== null) {
      closeNativeDescriptor(native, standardError.read);
      closeNativeDescriptor(native, standardError.write);
    }
    closeOutput(stdoutState, native);
    closeOutput(stderrState, native);
    closeDescriptor(held.descriptor);
    if (
      signalLease !== null
      && !signalRestored
    ) {
      try {
        restorationAmbiguous = !native.restoreSignalPolicy(signalLease);
      } catch {
        restorationAmbiguous = true;
      }
    }
    residentProbeActive = false;
    if (restorationAmbiguous) {
      // Deliberately replace any recoverable error with a permanent one.
      throwPermanentRestorationFailure();
    }
  }
}

export function runMacOSResidentCustodyProbe(
  input: MacOSResidentCustodyProbeInput,
  dependencies: MacOSResidentCustodyProbeDependencies =
    defaultMacOSResidentCustodyProbeDependencies,
): MacOSResidentCustodyProbeResult {
  try {
    return runMacOSResidentCustodyProbeCore(input, dependencies);
  } catch (error) {
    if (
      error instanceof MacOSResidentCustodyProbeError
      && error.processTerminal
    ) {
      return dependencies.terminateProcess(error);
    }
    throw error;
  }
}

export function inspectMacOSResidentEnrollmentCustodyNoUi(
  candidateApp: string,
  authority: CustodyProbeSupervisorAuthorityEvidence,
  dependencies: MacOSResidentCustodyProbeDependencies =
    defaultMacOSResidentCustodyProbeDependencies,
): MacOSCustodyStatus {
  const result = runMacOSResidentCustodyProbe(
    { authority, candidateApp, mode: "status" },
    dependencies,
  );
  return parseCanonicalMacOSCustodyStatus(result.stdout);
}
