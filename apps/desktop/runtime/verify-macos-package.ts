import { createHash } from "node:crypto";
import {
  closeSync,
  constants,
  fstatSync,
  openSync,
  readSync,
  type BigIntStats,
} from "node:fs";
import {
  cp,
  lstat,
  mkdtemp,
  open,
  readFile,
  readdir,
  readlink,
  realpath,
  rm,
  rmdir,
} from "node:fs/promises";
import { tmpdir } from "node:os";
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

import {
  CString,
  dlopen,
  FFIType,
  ptr,
  toBuffer,
} from "bun:ffi";

import { loadBunNativeLicenseInventory } from "./bun-native-licenses";
import {
  type CodexNativeLicenseInventory,
  renderCodexNativeLicenseNotices,
  serializeCodexNativeLicenseInventory,
  verifyCodexNativeLicenseInventory,
  verifyCodexNativePayloadsAtPaths,
} from "./codex-native-licenses";
import {
  codexSignatureNormalizationEntry,
  codexSignatureNormalizationManifestEntries,
  codexSignatureNormalizationPolicy,
  parseCodexSignatureNormalizationEntitlements,
  reconstructCodexSignatureSource,
  verifyCodexSignatureNormalizationContent,
  verifyCodexSignatureNormalizationPackaged,
  verifyCodexSignatureNormalizationSource,
} from "./codex-signature-normalization";
import {
  correspondingSourceSpecs,
  verifyCorrespondingSourceArchive,
} from "./corresponding-sources";
import {
  custodyProbeSupervisorPackageContract,
  hranessUiStylesheetInput,
  imageNormalizerPackageContract,
  macosPackage,
  requiredLicenseFileNames,
  requiredRuntimeBinFileNames,
  trustedThirdPartyTeams,
} from "./macos-package-config";
import type {
  CustodyProbeSupervisorAuthorityEvidence,
} from "./custody-probe-supervisor-authority";
export type {
  CustodyProbeSupervisorAuthorityEvidence,
} from "./custody-probe-supervisor-authority";
import {
  authorizeResidentCustodyCandidate,
  inspectResidentEnrollmentCustodyNoUi,
  smokeResidentCustodyCandidate,
} from "./resident-custody-probe-adapter";
import { loadGcmDependencyLicenseInventory } from "./gcm-dependency-licenses";
import { exactGatewayFileSha256 } from "./generate-gateway-file-authority";
import runtimeVersions from "./runtime-versions.json";
import {
  assertReleaseStrictVerification,
  codeSignatureHasExactRequirement,
  codeSignatureHasNoEntitlements,
  type CodeSignature,
  extractExactReleaseCmsCertificateChain,
  parseCodeSignatureDetails,
  verifyReleaseCmsHasNoTime,
} from "./package-macos";
import {
  loadProductionReleaseAuthority,
  parseReleaseSigningAuthority,
  productionReleaseAuthorityPins,
  productionReleaseSigning,
  releaseDesignatedRequirement,
  structuralAuthorityDescription,
  type ReleaseSigningAuthority,
} from "./release-signing-authority";
import {
  packagedRendererAuthorityEntries,
  rendererAuthorityRoot,
} from "./renderer-authority";
import { structuralManifestSigning } from "./structural-release-signing";
import {
  createShippedJavaScriptLicenseInventory,
  renderShippedJavaScriptLicenseNotices,
  serializeShippedJavaScriptLicenseInventory,
  verifyShippedJavaScriptLicenseInventory,
} from "./shipped-javascript-licenses";

type CommandResult = Readonly<{
  exitCode: number;
  stderr: string;
  stdout: string;
}>;

type RuntimeTreeEntry = Readonly<{
  path: string;
  sha256?: string;
  target?: string;
  type: "file" | "symlink";
}>;

export type MacOSAppEvidence = Readonly<{
  commit: string;
  custodyProbeSupervisor: CustodyProbeSupervisorAuthorityEvidence;
  runtimeManifest: unknown;
  treeSha256: string;
}>;

export interface MacOSPackageResidentProbeDependencies {
  /** Test-only seam after the resident group is fully quiescent. */
  readonly afterSmokeForTest?: (smokeRoot: string) => Promise<void> | void;
  readonly authorizeCandidate: typeof authorizeResidentCustodyCandidate;
  /** Test-only seam after marker lstat and before descriptor-relative open. */
  readonly beforeSmokeMarkerOpenForTest?: (
    markerPath: string,
  ) => Promise<void> | void;
  /** Test-only seam after marker open/fstat and before its bounded read. */
  readonly beforeSmokeMarkerReadForTest?: (
    markerPath: string,
  ) => Promise<void> | void;
  readonly smokeCandidate: typeof smokeResidentCustodyCandidate;
}

export const defaultMacOSPackageResidentProbeDependencies = Object.freeze({
  authorizeCandidate: authorizeResidentCustodyCandidate,
  smokeCandidate: smokeResidentCustodyCandidate,
} satisfies MacOSPackageResidentProbeDependencies);

const maximumSmokeMarkerBytes = 4_096;
const maximumSmokeCleanupDepth = 8;
const maximumSmokeCleanupEntries = 128;
const maximumSmokeCleanupPasses = 16;
const darwinDirectoryEntryNameOffset = 21;
const darwinVnodeFdInfoBytes = 1_200;
const darwinVnodeFdPathOffset = 176;
const darwinMaximumPathBytes = 1_024;
const darwinAtRemoveDirectory = 0x80;
const darwinOpenCloseOnExec = 0x01000000;
const darwinOpenNonBlocking = 0x00000004;

const smokeRootNativeLibrary = process.platform === "darwin"
  ? dlopen("/usr/lib/libSystem.B.dylib", {
    __error: { args: [], returns: FFIType.ptr },
    closedir: { args: [FFIType.ptr], returns: FFIType.i32 },
    dup: { args: [FFIType.i32], returns: FFIType.i32 },
    fdopendir: { args: [FFIType.i32], returns: FFIType.ptr },
    openat: {
      args: [FFIType.i32, FFIType.cstring, FFIType.i32],
      returns: FFIType.i32,
    },
    readdir: { args: [FFIType.ptr], returns: FFIType.ptr },
    unlinkat: {
      args: [FFIType.i32, FFIType.cstring, FFIType.i32],
      returns: FFIType.i32,
    },
  })
  : null;

const smokeRootProcessLibrary = process.platform === "darwin"
  ? dlopen("/usr/lib/libproc.dylib", {
    proc_pidfdinfo: {
      args: [
        FFIType.i32,
        FFIType.i32,
        FFIType.i32,
        FFIType.ptr,
        FFIType.i32,
      ],
      returns: FFIType.i32,
    },
  })
  : null;

type HeldSmokeRoot = Readonly<{
  handle: Awaited<ReturnType<typeof open>>;
  metadata: BigIntStats;
  path: string;
}>;

function requireSmokeOpenFlag(name: "O_CLOEXEC" | "O_NONBLOCK"): number {
  const value: unknown = Reflect.get(constants, name);
  const expected = name === "O_CLOEXEC"
    ? darwinOpenCloseOnExec
    : darwinOpenNonBlocking;
  if (value !== undefined && value !== expected) {
    throw new Error(`Package launch smoke found an unexpected Darwin ${name}.`);
  }
  return expected;
}

function smokeFileOpenFlags(): number {
  return constants.O_RDONLY
    | constants.O_NOFOLLOW
    | requireSmokeOpenFlag("O_CLOEXEC")
    | requireSmokeOpenFlag("O_NONBLOCK");
}

function smokeDirectoryOpenFlags(): number {
  return smokeFileOpenFlags() | constants.O_DIRECTORY;
}

function sameNode(left: BigIntStats, right: BigIntStats): boolean {
  return left.dev === right.dev && left.ino === right.ino;
}

function sameSmokeRootAuthority(
  expected: BigIntStats,
  actual: BigIntStats,
): boolean {
  return sameNode(expected, actual)
    && actual.isDirectory()
    && !actual.isSymbolicLink()
    && actual.uid === expected.uid
    && actual.gid === expected.gid
    && (actual.mode & 0o777n) === (expected.mode & 0o777n);
}

function sameSmokeMarkerAuthority(
  expected: BigIntStats,
  actual: BigIntStats,
): boolean {
  return sameNode(expected, actual)
    && actual.mode === expected.mode
    && actual.nlink === expected.nlink
    && actual.uid === expected.uid
    && actual.gid === expected.gid
    && actual.size === expected.size
    && actual.mtimeNs === expected.mtimeNs
    && actual.ctimeNs === expected.ctimeNs;
}

async function holdSmokeRoot(smokeRoot: string): Promise<HeldSmokeRoot> {
  const before = await lstat(smokeRoot, { bigint: true });
  const handle = await open(smokeRoot, smokeDirectoryOpenFlags());
  try {
    const [held, published, canonical] = await Promise.all([
      handle.stat({ bigint: true }),
      lstat(smokeRoot, { bigint: true }),
      realpath(smokeRoot),
    ]);
    const currentUser = process.geteuid?.();
    if (
      currentUser === undefined
      || canonical !== smokeRoot
      || !before.isDirectory()
      || before.isSymbolicLink()
      || before.uid !== BigInt(currentUser)
      || (before.mode & 0o777n) !== 0o700n
      || !sameSmokeRootAuthority(before, held)
      || !sameSmokeRootAuthority(before, published)
    ) {
      throw new Error("Package launch smoke root authority is unsafe.");
    }
    return Object.freeze({ handle, metadata: held, path: smokeRoot });
  } catch (error: unknown) {
    await handle.close();
    throw error;
  }
}

async function revalidateHeldSmokeRoot(root: HeldSmokeRoot): Promise<void> {
  try {
    const [held, published, canonical] = await Promise.all([
      root.handle.stat({ bigint: true }),
      lstat(root.path, { bigint: true }),
      realpath(root.path),
    ]);
    if (
      canonical !== root.path
      || !sameSmokeRootAuthority(root.metadata, held)
      || !sameSmokeRootAuthority(root.metadata, published)
    ) throw new Error("changed");
  } catch {
    throw new Error("Package launch smoke root authority changed.");
  }
}

function requireSmokeRootLibraries(): Readonly<{
  process: NonNullable<typeof smokeRootProcessLibrary>;
  system: NonNullable<typeof smokeRootNativeLibrary>;
}> {
  if (smokeRootNativeLibrary === null || smokeRootProcessLibrary === null) {
    throw new Error("Exact package smoke-root custody is available only on macOS.");
  }
  return { process: smokeRootProcessLibrary, system: smokeRootNativeLibrary };
}

function smokeLeaf(name: string): Buffer {
  if (
    name.length === 0
    || name === "."
    || name === ".."
    || name.includes("/")
    || name.includes("\0")
    || Buffer.byteLength(name, "utf8") > 255
  ) throw new Error("Package launch smoke cleanup found an invalid leaf.");
  return Buffer.from(`${name}\0`);
}

function smokeNativeErrno(): Buffer {
  const location = requireSmokeRootLibraries().system.symbols.__error();
  if (location === null) {
    throw new Error("Package launch smoke cleanup cannot inspect Darwin errno.");
  }
  return toBuffer(location, 0, 4);
}

function listSmokeDirectory(descriptor: number): readonly string[] {
  const { system } = requireSmokeRootLibraries();
  const duplicate = system.symbols.dup(descriptor);
  if (duplicate < 0) {
    throw new Error("Package launch smoke cleanup cannot duplicate its root.");
  }
  const stream = system.symbols.fdopendir(duplicate);
  if (stream === null) {
    closeSync(duplicate);
    throw new Error("Package launch smoke cleanup cannot enumerate its root.");
  }
  const names: string[] = [];
  const seen = new Set<string>();
  let failure: Error | null = null;
  try {
    smokeNativeErrno().writeInt32LE(0, 0);
    while (true) {
      const entry = system.symbols.readdir(stream);
      if (entry === null) break;
      const name = String(new CString(entry, darwinDirectoryEntryNameOffset));
      if (name === "." || name === "..") continue;
      smokeLeaf(name);
      if (seen.has(name) || names.length >= maximumSmokeCleanupEntries) {
        throw new Error("Package launch smoke cleanup inventory is not bounded.");
      }
      seen.add(name);
      names.push(name);
    }
    if (smokeNativeErrno().readInt32LE(0) !== 0) {
      throw new Error("Package launch smoke cleanup enumeration was incomplete.");
    }
  } catch (error: unknown) {
    failure = error instanceof Error ? error : new Error(String(error));
  } finally {
    if (system.symbols.closedir(stream) !== 0 && failure === null) {
      failure = new Error("Package launch smoke cleanup could not close its inventory.");
    }
  }
  if (failure !== null) throw failure;
  return names.sort((left, right) => left.localeCompare(right));
}

function openSmokeDirectoryAt(parent: number, name: string): number | null {
  const descriptor = requireSmokeRootLibraries().system.symbols.openat(
    parent,
    smokeLeaf(name),
    smokeDirectoryOpenFlags(),
  );
  return descriptor < 0 ? null : descriptor;
}

function cleanHeldSmokeDirectory(
  descriptor: number,
  depth = 0,
): void {
  if (depth > maximumSmokeCleanupDepth) {
    throw new Error("Package launch smoke cleanup tree is too deep.");
  }
  const { system } = requireSmokeRootLibraries();
  for (let pass = 0; pass < maximumSmokeCleanupPasses; pass += 1) {
    const names = listSmokeDirectory(descriptor);
    if (names.length === 0) return;
    for (const name of names) {
      const child = openSmokeDirectoryAt(descriptor, name);
      if (child === null) {
        // This removes only the current non-directory leaf. A concurrent swap
        // to a directory makes unlinkat fail rather than traversing it.
        system.symbols.unlinkat(descriptor, smokeLeaf(name), 0);
        continue;
      }
      try {
        const childAuthority = fstatSync(child, { bigint: true });
        cleanHeldSmokeDirectory(child, depth + 1);
        const rebound = openSmokeDirectoryAt(descriptor, name);
        if (rebound === null) continue;
        let exact = false;
        try {
          exact = sameNode(
            childAuthority,
            fstatSync(rebound, { bigint: true }),
          );
        } finally {
          closeSync(rebound);
        }
        if (exact) {
          system.symbols.unlinkat(
            descriptor,
            smokeLeaf(name),
            darwinAtRemoveDirectory,
          );
        }
      } finally {
        closeSync(child);
      }
    }
  }
  throw new Error("Package launch smoke cleanup did not reach an empty root.");
}

function heldSmokeRootPath(root: HeldSmokeRoot): string {
  const { process: processNative } = requireSmokeRootLibraries();
  const bytes = Buffer.alloc(darwinVnodeFdInfoBytes);
  const count = processNative.symbols.proc_pidfdinfo(
    process.pid,
    root.handle.fd,
    2,
    ptr(bytes),
    bytes.byteLength,
  );
  if (count !== bytes.byteLength) {
    throw new Error("Package launch smoke root path authority is unavailable.");
  }
  const pathBytes = bytes.subarray(
    darwinVnodeFdPathOffset,
    darwinVnodeFdPathOffset + darwinMaximumPathBytes,
  );
  const terminator = pathBytes.indexOf(0);
  if (terminator <= 0) {
    throw new Error("Package launch smoke root path authority is invalid.");
  }
  const path = new TextDecoder("utf-8", { fatal: true }).decode(
    pathBytes.subarray(0, terminator),
  );
  if (
    !isAbsolute(path)
    || resolve(path) !== path
    || path === sep
    || path.includes("\0")
  ) throw new Error("Package launch smoke root path authority is invalid.");
  return path;
}

async function lstatOrNull(path: string): Promise<BigIntStats | null> {
  try {
    return await lstat(path, { bigint: true });
  } catch (error: unknown) {
    if (
      error instanceof Error
      && "code" in error
      && (error as NodeJS.ErrnoException).code === "ENOENT"
    ) return null;
    throw error;
  }
}

async function unlinkHeldSmokeRoot(root: HeldSmokeRoot): Promise<void> {
  const { system } = requireSmokeRootLibraries();
  for (let pass = 0; pass < maximumSmokeCleanupPasses; pass += 1) {
    cleanHeldSmokeDirectory(root.handle.fd);
    const currentPath = heldSmokeRootPath(root);
    const current = await lstatOrNull(currentPath);
    if (current === null || !sameSmokeRootAuthority(root.metadata, current)) {
      const repeatedPath = heldSmokeRootPath(root);
      const repeated = await lstatOrNull(repeatedPath);
      if (repeated === null || !sameSmokeRootAuthority(root.metadata, repeated)) {
        return;
      }
      continue;
    }
    const parent = openSync(dirname(currentPath), smokeDirectoryOpenFlags());
    try {
      const leaf = basename(currentPath);
      const rebound = openSmokeDirectoryAt(parent, leaf);
      if (rebound === null) continue;
      let exact = false;
      try {
        exact = sameNode(root.metadata, fstatSync(rebound, { bigint: true }));
      } finally {
        closeSync(rebound);
      }
      if (!exact) continue;
      system.symbols.unlinkat(parent, smokeLeaf(leaf), darwinAtRemoveDirectory);
    } finally {
      closeSync(parent);
    }
  }
  throw new Error("Package launch smoke original root could not be removed exactly.");
}

async function removeHeldSmokeRootExactly(root: HeldSmokeRoot): Promise<void> {
  let failure: Error | null = null;
  try {
    await unlinkHeldSmokeRoot(root);
    const published = await lstatOrNull(root.path);
    if (published !== null) {
      if (sameSmokeRootAuthority(root.metadata, published)) {
        throw new Error("Package launch smoke left its original root published.");
      }
      // The smoke name was replaced. Never recurse through a root that is not
      // the held original vnode; surface the residue for explicit inspection.
      throw new Error("Package launch smoke root was replaced during cleanup.");
    }
  } catch (error: unknown) {
    failure = error instanceof Error ? error : new Error(String(error));
  } finally {
    try {
      await root.handle.close();
    } catch (closeError: unknown) {
      failure ??= closeError instanceof Error
        ? closeError
        : new Error(String(closeError));
    }
  }
  if (failure !== null) throw failure;
}

async function readHeldSmokeMarker(
  root: HeldSmokeRoot,
  dependencies: MacOSPackageResidentProbeDependencies,
): Promise<Record<string, unknown>> {
  await revalidateHeldSmokeRoot(root);
  const markerName = "gateway-ready.json";
  const markerPath = join(root.path, markerName);
  const before = await lstat(markerPath, { bigint: true });
  const currentUser = process.geteuid?.();
  if (
    currentUser === undefined
    || !before.isFile()
    || before.isSymbolicLink()
    || before.uid !== BigInt(currentUser)
    || before.nlink !== 1n
    || (before.mode & 0o777n) !== 0o600n
    || before.size < 1n
    || before.size > BigInt(maximumSmokeMarkerBytes)
  ) throw new Error("Package launch smoke marker authority is unsafe.");
  await dependencies.beforeSmokeMarkerOpenForTest?.(markerPath);
  const descriptor = requireSmokeRootLibraries().system.symbols.openat(
    root.handle.fd,
    smokeLeaf(markerName),
    smokeFileOpenFlags(),
  );
  if (descriptor < 0) {
    throw new Error("Package launch smoke marker could not be opened exactly.");
  }
  const bytes = Buffer.alloc(maximumSmokeMarkerBytes + 1);
  try {
    const held = fstatSync(descriptor, { bigint: true });
    if (!sameSmokeMarkerAuthority(before, held)) {
      throw new Error("Package launch smoke marker authority changed before open.");
    }
    await dependencies.beforeSmokeMarkerReadForTest?.(markerPath);
    let total = 0;
    while (total < bytes.byteLength) {
      const count = readSync(
        descriptor,
        bytes,
        total,
        bytes.byteLength - total,
        total,
      );
      if (count === 0) break;
      total += count;
    }
    if (total !== Number(held.size) || total > maximumSmokeMarkerBytes) {
      throw new Error("Package launch smoke marker size changed during read.");
    }
    const [after, namedAfter] = await Promise.all([
      Promise.resolve(fstatSync(descriptor, { bigint: true })),
      lstat(markerPath, { bigint: true }),
      revalidateHeldSmokeRoot(root),
    ]);
    if (
      !sameSmokeMarkerAuthority(held, after)
      || !sameSmokeMarkerAuthority(held, namedAfter)
    ) throw new Error("Package launch smoke marker authority changed during read.");
    const text = new TextDecoder("utf-8", { fatal: true }).decode(
      bytes.subarray(0, total),
    );
    return record(JSON.parse(text), "package smoke marker");
  } finally {
    bytes.fill(0);
    closeSync(descriptor);
  }
}

function inside(root: string, path: string): boolean {
  const fromRoot = relative(root, path);
  return fromRoot === "" || (
    !fromRoot.startsWith(`..${sep}`)
    && fromRoot !== ".."
    && !fromRoot.startsWith(sep)
  );
}

async function run(
  argv: readonly string[],
  options: Readonly<{
    allowFailure?: boolean;
    cwd?: string;
  }> = {},
): Promise<CommandResult> {
  const child = Bun.spawn([...argv], {
    cwd: options.cwd ?? macosPackage.desktopRoot,
    env: process.env,
    stderr: "pipe",
    stdout: "pipe",
  });
  const [stdout, stderr, exitCode] = await Promise.all([
    new Response(child.stdout).text(),
    new Response(child.stderr).text(),
    child.exited,
  ]);
  if (exitCode !== 0 && options.allowFailure !== true) {
    throw new Error(
      `${argv.join(" ")} failed with exit code ${exitCode}: ${stderr.trim()}`,
    );
  }
  return { exitCode, stderr, stdout };
}

export async function sha256File(path: string): Promise<string> {
  const handle = await open(path, "r");
  const hasher = createHash("sha256");
  try {
    for await (const chunk of handle.readableWebStream()) {
      hasher.update(chunk as Uint8Array);
    }
  } finally {
    await handle.close();
  }
  return hasher.digest("hex");
}

type DmgSnapshot = Readonly<{
  bytes: number;
  path: string;
  remove: () => Promise<void>;
  sha256: string;
}>;

function sameRegularFileAuthority(
  expected: BigIntStats,
  actual: BigIntStats,
): boolean {
  return expected.dev === actual.dev
    && expected.ino === actual.ino
    && expected.mode === actual.mode
    && expected.nlink === actual.nlink
    && expected.uid === actual.uid
    && expected.gid === actual.gid
    && expected.size === actual.size
    && expected.mtimeNs === actual.mtimeNs
    && expected.ctimeNs === actual.ctimeNs
    && actual.isFile()
    && !actual.isSymbolicLink();
}

async function snapshotDmg(dmgPath: string): Promise<DmgSnapshot> {
  if (
    !isAbsolute(dmgPath)
    || resolve(dmgPath) !== dmgPath
    || await realpath(dmgPath) !== dmgPath
  ) throw new Error("Release DMG path must be absolute and canonical.");
  const temporaryRoot = await mkdtemp(join(tmpdir(), "hra-dmg-snapshot-"));
  const snapshotPath = join(temporaryRoot, "release.dmg");
  let source: Awaited<ReturnType<typeof open>> | undefined;
  let destination: Awaited<ReturnType<typeof open>> | undefined;
  const buffer = Buffer.allocUnsafe(1024 * 1024);
  try {
    const before = await lstat(dmgPath, { bigint: true });
    source = await open(
      dmgPath,
      constants.O_RDONLY
        | constants.O_NOFOLLOW
        | requireSmokeOpenFlag("O_CLOEXEC"),
    );
    const held = await source.stat({ bigint: true });
    const currentUser = process.geteuid?.();
    if (
      currentUser === undefined
      || held.uid !== BigInt(currentUser)
      || held.nlink !== 1n
      || held.size <= 0n
      || held.size > BigInt(Number.MAX_SAFE_INTEGER)
      || !sameRegularFileAuthority(before, held)
    ) throw new Error("Release DMG source authority is unsafe.");
    destination = await open(
      snapshotPath,
      constants.O_WRONLY
        | constants.O_CREAT
        | constants.O_EXCL
        | requireSmokeOpenFlag("O_CLOEXEC"),
      0o400,
    );
    const hasher = createHash("sha256");
    let offset = 0;
    while (offset < Number(held.size)) {
      const requested = Math.min(buffer.length, Number(held.size) - offset);
      const { bytesRead } = await source.read(buffer, 0, requested, offset);
      if (bytesRead <= 0) {
        throw new Error("Release DMG ended before its held size.");
      }
      hasher.update(buffer.subarray(0, bytesRead));
      let written = 0;
      while (written < bytesRead) {
        const result = await destination.write(
          buffer,
          written,
          bytesRead - written,
          offset + written,
        );
        if (result.bytesWritten <= 0) {
          throw new Error("Release DMG snapshot write did not progress.");
        }
        written += result.bytesWritten;
      }
      offset += bytesRead;
    }
    await destination.sync();
    const [heldAfter, namedAfter, snapshotStatus] = await Promise.all([
      source.stat({ bigint: true }),
      lstat(dmgPath, { bigint: true }),
      destination.stat({ bigint: true }),
    ]);
    if (
      !sameRegularFileAuthority(held, heldAfter)
      || !sameRegularFileAuthority(held, namedAfter)
      || !snapshotStatus.isFile()
      || snapshotStatus.isSymbolicLink()
      || snapshotStatus.uid !== BigInt(currentUser)
      || snapshotStatus.nlink !== 1n
      || (snapshotStatus.mode & 0o777n) !== 0o400n
      || snapshotStatus.size !== held.size
    ) throw new Error("Release DMG changed while taking its exact snapshot.");
    await destination.close();
    destination = undefined;
    await source.close();
    source = undefined;
    const sha256 = hasher.digest("hex");
    return Object.freeze({
      bytes: Number(held.size),
      path: snapshotPath,
      remove: async () => {
        await rm(temporaryRoot, { force: true, recursive: true });
      },
      sha256,
    });
  } catch (error: unknown) {
    await destination?.close().catch(() => undefined);
    await source?.close().catch(() => undefined);
    await rm(temporaryRoot, { force: true, recursive: true });
    throw error;
  } finally {
    buffer.fill(0);
  }
}

export async function verifyRegularReleaseEntries(
  releaseDirectory: string,
  names: readonly string[],
): Promise<void> {
  for (const name of names) {
    const status = await lstat(join(releaseDirectory, name));
    if (!status.isFile() || status.isSymbolicLink()) {
      throw new Error(`Release entry must be a regular file: ${name}`);
    }
  }
}

async function walkTree(root: string): Promise<RuntimeTreeEntry[]> {
  const entries: RuntimeTreeEntry[] = [];
  async function visit(directory: string): Promise<void> {
    const children = await readdir(directory, { withFileTypes: true });
    children.sort((left, right) => left.name.localeCompare(right.name));
    for (const child of children) {
      const path = join(directory, child.name);
      const relativePath = relative(root, path).split(sep).join("/");
      if (child.isSymbolicLink()) {
        const target = await readlink(path);
        if (target.startsWith("/") || !inside(root, resolve(dirname(path), target))) {
          throw new Error(`Runtime symlink escapes its root: ${relativePath}`);
        }
        entries.push({ path: relativePath, target, type: "symlink" });
      } else if (child.isDirectory()) {
        await visit(path);
      } else if (child.isFile()) {
        entries.push({ path: relativePath, sha256: await sha256File(path), type: "file" });
      } else {
        throw new Error(`Special runtime file is forbidden: ${relativePath}`);
      }
    }
  }
  await visit(root);
  return entries;
}

async function plistValue(path: string, key: string): Promise<string> {
  const result = await run([
    "/usr/bin/plutil",
    "-extract",
    key,
    "raw",
    "-o",
    "-",
    path,
  ]);
  return result.stdout.trim();
}

async function plistHasKey(path: string, key: string): Promise<boolean> {
  return (await run([
    "/usr/bin/plutil",
    "-extract",
    key,
    "raw",
    "-o",
    "-",
    path,
  ], { allowFailure: true })).exitCode === 0;
}

function record(value: unknown, label: string): Record<string, unknown> {
  if (typeof value !== "object" || value === null || Array.isArray(value)) {
    throw new Error(`${label} must be an object.`);
  }
  return value as Record<string, unknown>;
}

function string(value: unknown, label: string): string {
  if (typeof value !== "string" || value.length === 0) {
    throw new Error(`${label} must be a non-empty string.`);
  }
  return value;
}

function number(value: unknown, label: string): number {
  if (!Number.isSafeInteger(value) || Number(value) <= 0) {
    throw new Error(`${label} must be a positive integer.`);
  }
  return Number(value);
}

type VerifiedCodeSignature = CodeSignature & Readonly<{
  cdHash: string;
  identifier: string;
}>;

type InspectedCodeSignature = Readonly<{
  display: CommandResult;
  signature: VerifiedCodeSignature;
}>;

async function inspectCodeSignature(path: string): Promise<InspectedCodeSignature> {
  const result = await run([
    "/usr/bin/codesign",
    "--display",
    "--verbose=4",
    path,
  ]);
  const signature = parseCodeSignatureDetails(
    `${result.stdout}\n${result.stderr}`,
  );
  if (signature.cdHash === null || signature.identifier === null) {
    throw new Error(`Missing code signature metadata: ${path}`);
  }
  return Object.freeze({
    display: result,
    signature: Object.freeze({
      ...signature,
      cdHash: signature.cdHash,
      identifier: signature.identifier,
    }),
  });
}

async function codeSignature(path: string): Promise<VerifiedCodeSignature> {
  return (await inspectCodeSignature(path)).signature;
}

function exactCodeCertificateChain(
  cms: Buffer,
): Readonly<{ leaf: Buffer; root: Buffer }> {
  const [leaf, root] = extractExactReleaseCmsCertificateChain(cms);
  return Object.freeze({ leaf, root });
}

function certificateRecord(bytes: Buffer): Readonly<{
  derBase64: string;
  sha1: string;
  sha256: string;
}> {
  return {
    derBase64: bytes.toString("base64"),
    sha1: createHash("sha1").update(bytes).digest("hex"),
    sha256: createHash("sha256").update(bytes).digest("hex"),
  };
}

async function structuralAuthorityFromCodeIdentity(
  path: string,
): Promise<ReleaseSigningAuthority> {
  const inspected = await inspectCodeSignature(path);
  const { cms } = await verifyReleaseCmsHasNoTime(inspected.display, path);
  const certificates = exactCodeCertificateChain(cms);
  const authority = parseReleaseSigningAuthority({
    description: structuralAuthorityDescription,
    leaf: certificateRecord(certificates.leaf),
    policy: {
      architecture: "arm64",
      codeDirectoryHash: "sha256",
      cmsSigningTime: "none",
      hardenedRuntime: true,
      pageSize: 16_384,
      secureTimestamp: "none",
    },
    root: certificateRecord(certificates.root),
    schemaVersion: 1,
  }, undefined, new Date(), "structural");
  if (
    authority.leaf.sha1 === productionReleaseAuthorityPins.leafSha1
    || authority.leaf.sha256 === productionReleaseAuthorityPins.leafSha256
    || authority.root.sha1 === productionReleaseAuthorityPins.rootSha1
    || authority.root.sha256 === productionReleaseAuthorityPins.rootSha256
  ) {
    throw new Error("Structural signing authority collides with production pins.");
  }
  return authority;
}

async function verifyReleaseCodeIdentity(
  path: string,
  identifier: string,
  authority: ReleaseSigningAuthority,
): Promise<void> {
  const inspected = await inspectCodeSignature(path);
  const signature = inspected.signature;
  if (
    signature.identifier !== identifier
    || signature.teamIdentifier !== null
    || signature.signatureKind === null
    || signature.signatureKind === "adhoc"
    || signature.hashType !== "sha256"
    || signature.hashChoices.length !== 1
    || signature.hashChoices[0] !== "sha256"
    || signature.pageSize !== 16_384
    || signature.timestamp !== null
    || signature.flags.length !== 1
    || signature.flags[0] !== "runtime"
  ) {
    throw new Error(`Release code-signing posture differs: ${path}`);
  }
  const { cms, executable } = await verifyReleaseCmsHasNoTime(
    inspected.display,
    path,
  );
  const entitlements = await run([
    "/usr/bin/codesign",
    "--display",
    "--entitlements",
    "-",
    path,
  ]);
  if (!codeSignatureHasNoEntitlements(entitlements, executable)) {
    throw new Error(`Release code must not carry entitlements: ${path}`);
  }
  const strictVerification = await run([
    "/usr/bin/codesign",
    "--verify",
    "--all-architectures",
    "--strict",
    "--verbose=6",
    path,
  ], { allowFailure: true });
  assertReleaseStrictVerification(path, strictVerification);
  const requirements = await run([
    "/usr/bin/codesign",
    "--display",
    "--requirements",
    "-",
    path,
  ]);
  if (
    !codeSignatureHasExactRequirement(
      requirements,
      executable,
      releaseDesignatedRequirement(identifier, {
        leafSha1: authority.leaf.sha1,
        rootSha1: authority.root.sha1,
      }),
    )
  ) {
    throw new Error(`Release designated requirement differs: ${path}`);
  }
  const certificates = exactCodeCertificateChain(cms);
  if (
    !certificates.leaf.equals(authority.leaf.der)
    || !certificates.root.equals(authority.root.der)
    || createHash("sha1").update(certificates.leaf).digest("hex")
      !== authority.leaf.sha1
    || createHash("sha256").update(certificates.leaf).digest("hex")
      !== authority.leaf.sha256
    || createHash("sha1").update(certificates.root).digest("hex")
      !== authority.root.sha1
    || createHash("sha256").update(certificates.root).digest("hex")
      !== authority.root.sha256
  ) {
    throw new Error(`Release certificate chain differs: ${path}`);
  }
}

async function codeSignatureEntitlements(
  path: string,
): Promise<Readonly<Record<string, boolean>>> {
  const result = await run([
    "/usr/bin/codesign",
    "--display",
    "--entitlements",
    "-",
    "--xml",
    path,
  ]);
  return parseCodexSignatureNormalizationEntitlements(
    `${result.stdout}\n${result.stderr}`,
  );
}

export function parseCustodyProbeSupervisorAuthorityEvidence(
  value: unknown,
  expectedSigning: Readonly<Record<string, unknown>>,
  expectedAuthority: ReleaseSigningAuthority,
): CustodyProbeSupervisorAuthorityEvidence {
  const authority = record(value, "runtime custody probe supervisor");
  const actualFields = Object.keys(authority).sort();
  const expectedFields = [
    "architecture",
    "cdHash",
    "codeDirectoryFlags",
    "designatedRequirement",
    "entitlements",
    "identifier",
    "pageSize",
    "runtimeRelativePath",
    "sha256",
    "signing",
    "timestamp",
  ].sort();
  const cdHash = string(
    authority["cdHash"],
    "custody probe supervisor CodeDirectory hash",
  );
  const sha256 = string(
    authority["sha256"],
    "custody probe supervisor SHA-256",
  );
  const expectedDesignatedRequirement = releaseDesignatedRequirement(
    custodyProbeSupervisorPackageContract.identifier,
    {
      leafSha1: expectedAuthority.leaf.sha1,
      rootSha1: expectedAuthority.root.sha1,
    },
  );
  if (
    !isDeepStrictEqual(actualFields, expectedFields)
    || authority["architecture"] !== macosPackage.architecture
    || authority["identifier"]
      !== custodyProbeSupervisorPackageContract.identifier
    || authority["runtimeRelativePath"]
      !== custodyProbeSupervisorPackageContract.runtimeRelativePath
    || !/^[0-9a-f]{40}$/u.test(cdHash)
    || !/^[0-9a-f]{64}$/u.test(sha256)
    || !isDeepStrictEqual(authority["codeDirectoryFlags"], ["runtime"])
    || authority["designatedRequirement"] !== expectedDesignatedRequirement
    || !isDeepStrictEqual(authority["entitlements"], {})
    || authority["pageSize"] !== 16_384
    || !isDeepStrictEqual(authority["signing"], expectedSigning)
    || authority["timestamp"] !== null
  ) {
    throw new Error("Custody probe supervisor manifest authority differs.");
  }
  return Object.freeze({
    architecture: "arm64",
    cdHash,
    codeDirectoryFlags: Object.freeze(["runtime"] as const),
    designatedRequirement: expectedDesignatedRequirement,
    entitlements: Object.freeze({}),
    identifier: custodyProbeSupervisorPackageContract.identifier,
    pageSize: 16_384,
    runtimeRelativePath:
      custodyProbeSupervisorPackageContract.runtimeRelativePath,
    sha256,
    signing: Object.freeze({ ...expectedSigning }),
    timestamp: null,
  });
}

export const custodyProbeSupervisorDependencies = Object.freeze([
  "/System/Library/Frameworks/CoreFoundation.framework/Versions/A/CoreFoundation",
  "/System/Library/Frameworks/Foundation.framework/Versions/C/Foundation",
  "/System/Library/Frameworks/Security.framework/Versions/A/Security",
  "/usr/lib/libSystem.B.dylib",
  "/usr/lib/libobjc.A.dylib",
] as const);

export function parseCustodyProbeSupervisorDependencies(
  path: string,
  dependencyOutput: string,
): readonly string[] {
  const lines = dependencyOutput.trimEnd().split("\n");
  if (lines[0] !== `${path}:` || lines.length < 2) {
    throw new Error(`Release helper dependency inventory is invalid: ${path}`);
  }
  const dependencies = lines.slice(1).map((line) => {
    const match = /^\t(\/\S+) \(compatibility version [^)]+\)$/u.exec(line);
    if (match?.[1] === undefined) {
      throw new Error(`Release helper has an invalid load command: ${path}`);
    }
    return match[1];
  }).sort();
  if (!isDeepStrictEqual(dependencies, custodyProbeSupervisorDependencies)) {
    throw new Error(`Release helper dependency allowlist differs: ${path}`);
  }
  return Object.freeze(dependencies);
}

async function verifyThinArm64SystemMachO(path: string): Promise<void> {
  const architectures = (await run([
    "/usr/bin/lipo",
    "-archs",
    path,
  ])).stdout.trim();
  if (architectures !== "arm64") {
    throw new Error(`Release helper is not thin arm64 code: ${path}`);
  }
  const dependencyOutput = (await run([
    "/usr/bin/otool",
    "-L",
    path,
  ])).stdout;
  parseCustodyProbeSupervisorDependencies(path, dependencyOutput);
}

export async function verifyExactAdHocGatewayPosture(path: string): Promise<void> {
  const architectures = (await run([
    "/usr/bin/lipo",
    "-archs",
    path,
  ])).stdout.trim();
  const gateway = await codeSignature(path);
  if (
    architectures !== "arm64"
    || gateway.identifier !== "oprte-gateway"
    || gateway.teamIdentifier !== null
    || gateway.signatureKind !== "adhoc"
    || gateway.hashType !== "sha256"
    || gateway.pageSize !== 16_384
    || gateway.timestamp !== null
    || gateway.flags.length !== 2
    || !gateway.flags.includes("runtime")
    || !gateway.flags.includes("adhoc")
  ) {
    throw new Error("Gateway code-signing posture differs.");
  }
  const gatewayEntitlements = await codeSignatureEntitlements(path);
  if (
    Object.keys(gatewayEntitlements).length !== 1
    || gatewayEntitlements[
      "com.apple.security.cs.allow-unsigned-executable-memory"
    ] !== true
  ) {
    throw new Error("Gateway entitlements differ from the exact JIT policy.");
  }
  await run([
    "/usr/bin/codesign",
    "--verify",
    "--strict",
    "--verbose=6",
    path,
  ]);
}

async function verifyRuntimeManifest(
  appPath: string,
  expectedSigning: Readonly<Record<string, unknown>>,
  expectedAuthority: ReleaseSigningAuthority,
): Promise<MacOSAppEvidence> {
  const runtimeRoot = join(appPath, "Contents/Resources/runtime");
  const manifestPath = join(runtimeRoot, "manifest.json");
  const manifest = record(
    JSON.parse(await readFile(manifestPath, "utf8")),
    "runtime manifest",
  );
  if (manifest["schemaVersion"] !== 1) {
    throw new Error("Runtime manifest schema is unsupported.");
  }
  const release = record(manifest["release"], "runtime manifest release");
  const runtime = record(manifest["runtime"], "runtime manifest runtime");
  if (
    release["version"] !== macosPackage.version
    || number(release["build"], "release build") !== macosPackage.build
    || release["architecture"] !== macosPackage.architecture
    || release["minimumMacOS"] !== macosPackage.minimumMacOS
    || !isDeepStrictEqual(release["signing"], expectedSigning)
  ) {
    throw new Error("Runtime manifest release identity differs from the package.");
  }
  const commit = string(release["commit"], "release commit");
  if (!/^[0-9a-f]{40}$/u.test(commit)) {
    throw new Error("Runtime manifest source commit is invalid.");
  }

  const gateway = record(runtime["gateway"], "runtime gateway");
  const custodyProbeSupervisor = parseCustodyProbeSupervisorAuthorityEvidence(
    runtime["custodyProbeSupervisor"],
    expectedSigning,
    expectedAuthority,
  );
  const dataRemover = record(runtime["dataRemover"], "runtime data remover");
  const gitExecutor = record(runtime["gitExecutor"], "runtime Git executor");
  const imageNormalizer = record(runtime["imageNormalizer"], "runtime image normalizer");
  const keychainCustodian = record(runtime["keychainCustodian"], "runtime Keychain custodian");
  const codex = record(runtime["codex"], "runtime Codex");
  const git = record(runtime["git"], "runtime Git");
  const gitCredentialManager = record(
    runtime["gitCredentialManager"],
    "runtime Git Credential Manager",
  );
  const gitLfs = record(runtime["gitLfs"], "runtime Git LFS");
  const ripgrep = record(runtime["ripgrep"], "runtime ripgrep");
  const expectedHashes = new Map([
    [
      custodyProbeSupervisorPackageContract.runtimeRelativePath,
      custodyProbeSupervisor.sha256,
    ],
    [
      imageNormalizerPackageContract.runtimeRelativePath,
      string(imageNormalizer["sha256"], "image normalizer SHA-256"),
    ],
    ["bin/oprte-gateway", string(gateway["sha256"], "gateway SHA-256")],
    ["bin/oprte-data-remover", string(dataRemover["sha256"], "data remover SHA-256")],
    ["bin/oprte-git-executor", string(gitExecutor["sha256"], "Git executor SHA-256")],
    ["bin/oprte-keychain-custodian", string(keychainCustodian["sha256"], "Keychain custodian SHA-256")],
    ["codex/bin/codex", string(codex["binarySha256"], "Codex SHA-256")],
    ["git/bin/git", string(git["binarySha256"], "Git SHA-256")],
    [
      "git/libexec/git-core/git-credential-manager",
      string(gitCredentialManager["binarySha256"], "Git Credential Manager SHA-256"),
    ],
    ["git/libexec/git-core/git-lfs", string(gitLfs["binarySha256"], "Git LFS SHA-256")],
    ["codex/codex-path/rg", string(ripgrep["binarySha256"], "ripgrep SHA-256")],
  ]);
  for (const [path, expected] of expectedHashes) {
    if (!/^[0-9a-f]{64}$/u.test(expected) || await sha256File(join(runtimeRoot, path)) !== expected) {
      throw new Error(`Runtime hash differs: ${path}`);
    }
  }
  if (
    gateway["bunVersion"] !== runtimeVersions.bun.version
    || gateway["compilerBinarySha256"] !== runtimeVersions.bun.binarySha256
    || gateway["compilerReleaseAssetSha256"] !== runtimeVersions.bun.releaseAssetSha256
    || gateway["compilerSourceCommit"] !== runtimeVersions.bun.sourceCommit
    || gateway["completeSourceArchiveSha256"]
      !== runtimeVersions.bun.completeSourceArchiveSha256
    || gateway["dependencyLicenseInventorySha256"]
      !== runtimeVersions.bun.dependencyLicenseInventorySha256
    || gateway["dependencyLicenseNoticesSha256"]
      !== runtimeVersions.bun.dependencyLicenseNoticesSha256
    || codex["version"] !== runtimeVersions.codex.version
    || codex["sourceCommit"] !== runtimeVersions.codex.sourceCommit
    || codex["dependencyLicenseInventorySha256"]
      !== runtimeVersions.codex.dependencyLicenseInventorySha256
    || codex["dependencyLicenseNoticesSha256"]
      !== runtimeVersions.codex.dependencyLicenseNoticesSha256
    || codex["sourceBinarySha256"]
      !== codexSignatureNormalizationEntry("bin/codex").source.sha256
    || git["version"] !== runtimeVersions.git.version
    || git["assetSha256"] !== runtimeVersions.git.assetSha256
    || gitCredentialManager["version"] !== runtimeVersions.gitCredentialManager.version
    || gitCredentialManager["sourceCommit"] !== runtimeVersions.gitCredentialManager.sourceCommit
    || gitCredentialManager["licenseSha256"] !== runtimeVersions.gitCredentialManager.licenseSha256
    || gitCredentialManager["noticeSha256"] !== runtimeVersions.gitCredentialManager.noticeSha256
    || gitCredentialManager["depsJsonSha256"] !== runtimeVersions.gitCredentialManager.depsJsonSha256
    || gitCredentialManager["runtimeConfigSha256"] !== runtimeVersions.gitCredentialManager.runtimeConfigSha256
    || gitCredentialManager["dependencyLicenseInventorySha256"]
      !== runtimeVersions.gitCredentialManager.dependencyLicenseInventorySha256
    || gitCredentialManager["dependencyLicenseNoticesSha256"]
      !== runtimeVersions.gitCredentialManager.dependencyLicenseNoticesSha256
    || gitCredentialManager["dotnetRuntimeVersion"]
      !== runtimeVersions.gitCredentialManager.dotnetRuntimeVersion
    || gitCredentialManager["dotnetRuntimeSourceCommit"]
      !== runtimeVersions.gitCredentialManager.dotnetRuntimeSourceCommit
    || gitLfs["version"] !== runtimeVersions.gitLfs.version
    || gitLfs["sourceCommit"] !== runtimeVersions.gitLfs.sourceCommit
    || gitLfs["licenseSha256"] !== runtimeVersions.gitLfs.licenseSha256
    || ripgrep["version"] !== runtimeVersions.ripgrep.version
    || ripgrep["sourceCommit"] !== runtimeVersions.ripgrep.sourceCommit
    || ripgrep["pcre2LicenseSha256"] !== runtimeVersions.ripgrep.pcre2.licenseSha256
  ) {
    throw new Error("Runtime version pins differ from the manifest.");
  }

  const dataRemoverSignature = await codeSignature(join(runtimeRoot, "bin/oprte-data-remover"));
  if (dataRemover["cdHash"] !== dataRemoverSignature.cdHash) {
    throw new Error("Data remover CodeDirectory hash differs from the manifest.");
  }
  const imageNormalizerSignature = await codeSignature(
    join(runtimeRoot, imageNormalizerPackageContract.runtimeRelativePath),
  );
  if (imageNormalizer["cdHash"] !== imageNormalizerSignature.cdHash) {
    throw new Error("Image normalizer CodeDirectory hash differs from the manifest.");
  }
  const expectedNormalized = codexSignatureNormalizationManifestEntries();
  const normalized = runtime["normalizedSignatures"];
  if (!isDeepStrictEqual(normalized, expectedNormalized)) {
    throw new Error("Runtime manifest normalized Codex signatures differ from policy.");
  }
  const normalizedPaths = new Set<string>();
  for (const entry of codexSignatureNormalizationPolicy.entries) {
    const absolute = resolve(appPath, entry.appRelativePath);
    const deltaPath = resolve(appPath, entry.sourceDelta.path);
    if (!inside(appPath, absolute) || !inside(appPath, deltaPath)) {
      throw new Error(`Normalized Codex evidence escaped the app: ${entry.payloadPath}`);
    }
    const [status, deltaStatus] = await Promise.all([
      lstat(absolute),
      lstat(deltaPath),
    ]);
    if (
      !status.isFile()
      || status.isSymbolicLink()
      || status.nlink !== 1
      || !deltaStatus.isFile()
      || deltaStatus.isSymbolicLink()
      || deltaStatus.nlink !== 1
      || deltaStatus.size !== entry.sourceDelta.size
      || await sha256File(deltaPath) !== entry.sourceDelta.sha256
    ) {
      throw new Error(`Normalized Codex evidence differs: ${entry.payloadPath}`);
    }
    verifyCodexSignatureNormalizationPackaged(entry, {
      sha256: await sha256File(absolute),
      signature: {
        ...await codeSignature(absolute),
        entitlements: await codeSignatureEntitlements(absolute),
      },
      size: status.size,
    });
    await run([
      "/usr/bin/codesign",
      "--verify",
      "--strict",
      "--verbose=6",
      absolute,
    ]);
    normalizedPaths.add(entry.appRelativePath);
  }
  const preserved = runtime["preservedSignatures"];
  if (!Array.isArray(preserved) || preserved.length === 0) {
    throw new Error("Runtime manifest has no preserved third-party signatures.");
  }
  for (const [index, rawEntry] of preserved.entries()) {
    const entry = record(rawEntry, `preserved signature ${index}`);
    const path = string(entry["path"], `preserved signature ${index} path`);
    const team = string(entry["teamIdentifier"], `preserved signature ${index} team`);
    if (!trustedThirdPartyTeams.has(team)) {
      throw new Error(`Untrusted preserved signature team: ${team}`);
    }
    if (normalizedPaths.has(path)) {
      throw new Error(`Normalized signature cannot also be preserved: ${path}`);
    }
    const absolute = resolve(appPath, path);
    if (!inside(appPath, absolute)) {
      throw new Error(`Preserved signature escaped the app: ${path}`);
    }
    const signature = await codeSignature(absolute);
    if (signature.teamIdentifier !== team) {
      throw new Error(`Preserved signature changed: ${path}`);
    }
    await run(["/usr/bin/codesign", "--verify", "--strict", absolute]);
  }

  const tree = (await walkTree(runtimeRoot))
    .filter((entry) => entry.path !== "manifest.json");
  const actualTreeSha256 = createHash("sha256")
    .update(`${JSON.stringify(tree)}\n`, "utf8")
    .digest("hex");
  const treeSha256 = string(runtime["treeSha256"], "runtime tree SHA-256");
  if (actualTreeSha256 !== treeSha256) {
    throw new Error("Runtime tree hash differs from the manifest.");
  }
  return {
    commit,
    custodyProbeSupervisor,
    runtimeManifest: manifest,
    treeSha256,
  };
}

async function verifyReconstructedCodexSourcePayloads(
  appPath: string,
  inventory: CodexNativeLicenseInventory,
  manifestPath: string,
): Promise<void> {
  const temporaryRoot = await realpath(
    await mkdtemp(join(tmpdir(), "hra-codex-source-recovery-")),
  );
  const temporaryStatus = await lstat(temporaryRoot);
  if (
    !temporaryStatus.isDirectory()
    || temporaryStatus.isSymbolicLink()
    || temporaryStatus.uid !== process.getuid?.()
    || (temporaryStatus.mode & 0o777) !== 0o700
  ) {
    await rm(temporaryRoot, { force: true, recursive: true });
    throw new Error("Codex source recovery root is not an owner-private directory.");
  }
  const vendorRoot = join(temporaryRoot, "vendor");
  try {
    await cp(join(appPath, "Contents/Resources/runtime/codex"), vendorRoot, {
      force: false,
      recursive: true,
      verbatimSymlinks: true,
    });
    for (const entry of codexSignatureNormalizationPolicy.entries) {
      const packagedPath = resolve(appPath, entry.appRelativePath);
      const deltaPath = resolve(appPath, entry.sourceDelta.path);
      const reconstructedPath = join(vendorRoot, entry.payloadPath);
      await rm(reconstructedPath, { force: true });
      await reconstructCodexSignatureSource(
        packagedPath,
        deltaPath,
        reconstructedPath,
      );
      await verifyCodexSignatureNormalizationContent(
        reconstructedPath,
        packagedPath,
      );
      const status = await lstat(reconstructedPath);
      if (!status.isFile() || status.isSymbolicLink() || status.nlink !== 1) {
        throw new Error(
          `Reconstructed Codex source is not a regular single-link file: ${entry.payloadPath}`,
        );
      }
      verifyCodexSignatureNormalizationSource(entry, {
        sha256: await sha256File(reconstructedPath),
        signature: await codeSignature(reconstructedPath),
        size: status.size,
      });
      const sourceStrict = await run([
        "/usr/bin/codesign",
        "--verify",
        "--strict",
        "--verbose=6",
        reconstructedPath,
      ], { allowFailure: true });
      process.stdout.write(
        `Reconstructed Codex source signature ${entry.payloadPath}: strict ${sourceStrict.exitCode === 0 ? "accepted" : "rejected"}; source provenance remains exact.\n`,
      );
    }
    await verifyCodexNativePayloadsAtPaths(inventory, {
      manifestPath,
      vendorRoot,
    });
  } finally {
    await rm(temporaryRoot, { force: true, recursive: true });
  }
}

export async function verifyMacOSApp(
  appPath = macosPackage.appBundlePath,
  options: Readonly<{ profile?: "production" | "structural" }> = {},
): Promise<MacOSAppEvidence> {
  const stat = await lstat(appPath);
  if (!stat.isDirectory() || stat.isSymbolicLink()) {
    throw new Error(`Packaged app must be a real directory: ${appPath}`);
  }
  const canonical = await realpath(appPath);
  if (!canonical.endsWith(".app")) {
    throw new Error("Packaged app path must end in .app.");
  }
  const contentsRoot = join(canonical, "Contents");
  const runtimeRoot = join(contentsRoot, "Resources/runtime");
  const plist = join(contentsRoot, "Info.plist");
  const hostExecutable = join(
    contentsRoot,
    `MacOS/${macosPackage.executableName}`,
  );
  const profile = options.profile ?? "production";
  const releaseAuthority = profile === "production"
    ? await loadProductionReleaseAuthority()
    : await structuralAuthorityFromCodeIdentity(hostExecutable);
  const expectedReleaseSigning = profile === "production"
    ? productionReleaseSigning
    : structuralManifestSigning(releaseAuthority);
  const expectedPlist = new Map([
    ["CFBundleDisplayName", macosPackage.displayName],
    ["CFBundleExecutable", macosPackage.executableName],
    ["CFBundleIdentifier", macosPackage.bundleIdentifier],
    ["CFBundleName", macosPackage.productName],
    ["CFBundleShortVersionString", macosPackage.version],
    ["CFBundleVersion", String(macosPackage.build)],
    ["LSMinimumSystemVersion", macosPackage.minimumMacOS],
  ]);
  for (const [key, expected] of expectedPlist) {
    if (await plistValue(plist, key) !== expected) {
      throw new Error(`Info.plist ${key} differs from ${expected}.`);
    }
  }
  for (const key of ["SUFeedURL", "SUPublicEDKey", "SUEnableAutomaticChecks"]) {
    if (await plistHasKey(plist, key)) {
      throw new Error(`Ad-hoc package must not contain ${key}.`);
    }
  }
  try {
    await lstat(join(contentsRoot, "Frameworks/Sparkle.framework"));
    throw new Error("Ad-hoc package must not bundle Sparkle.framework.");
  } catch (error) {
    if (!(error instanceof Error && "code" in error && error.code === "ENOENT")) {
      throw error;
    }
  }

  const bins = (await readdir(join(runtimeRoot, "bin"))).sort();
  if (JSON.stringify(bins) !== JSON.stringify([...requiredRuntimeBinFileNames])) {
    throw new Error(`Runtime bin set differs: ${bins.join(", ")}`);
  }
  const licenses = (await readdir(join(runtimeRoot, "licenses"))).sort();
  if (JSON.stringify(licenses) !== JSON.stringify([...requiredLicenseFileNames])) {
    throw new Error(`Runtime license set differs: ${licenses.join(", ")}`);
  }
  const licenseRoot = join(runtimeRoot, "licenses");
  const stagedHranessUiLicenseSha256 = await sha256File(
    join(licenseRoot, "HRANESS-UI-LICENSE.txt"),
  );
  if (stagedHranessUiLicenseSha256 !== hranessUiStylesheetInput.licenseSha256) {
    throw new Error("Staged hraness/ui license hash differs.");
  }
  const stagedInventoryText = await readFile(
    join(licenseRoot, "SHIPPED-JAVASCRIPT-LICENSES.json"),
    "utf8",
  );
  const stagedInventory = verifyShippedJavaScriptLicenseInventory(
    JSON.parse(stagedInventoryText) as unknown,
  );
  if (serializeShippedJavaScriptLicenseInventory(stagedInventory) !== stagedInventoryText) {
    throw new Error("Staged JavaScript license inventory is not canonical.");
  }
  const expectedInventory = await createShippedJavaScriptLicenseInventory();
  if (
    serializeShippedJavaScriptLicenseInventory(expectedInventory)
    !== stagedInventoryText
  ) {
    throw new Error("Staged JavaScript license inventory differs from installed production dependencies.");
  }
  const stagedNotices = await readFile(
    join(licenseRoot, "SHIPPED-JAVASCRIPT-LICENSES.txt"),
    "utf8",
  );
  if (stagedNotices !== renderShippedJavaScriptLicenseNotices(stagedInventory)) {
    throw new Error("Staged JavaScript license notices differ from their inventory.");
  }
  await loadGcmDependencyLicenseInventory({
    gcmRoot: join(runtimeRoot, "git/libexec/git-core"),
    inventoryPath: join(licenseRoot, "GCM-DEPENDENCY-LICENSES.json"),
    noticesPath: join(licenseRoot, "GCM-DEPENDENCY-LICENSES.txt"),
  });
  await loadBunNativeLicenseInventory({
    inventoryPath: join(licenseRoot, "BUN-DEPENDENCY-LICENSES.json"),
    noticesPath: join(licenseRoot, "BUN-DEPENDENCY-LICENSES.txt"),
  });
  const stagedCodexInventoryText = await readFile(
    join(licenseRoot, "CODEX-NATIVE-LICENSES.json"),
    "utf8",
  );
  const stagedCodexInventory = verifyCodexNativeLicenseInventory(
    JSON.parse(stagedCodexInventoryText) as unknown,
  );
  if (
    serializeCodexNativeLicenseInventory(stagedCodexInventory)
    !== stagedCodexInventoryText
  ) {
    throw new Error("Staged Codex native license inventory is not canonical.");
  }
  const stagedCodexNotices = await readFile(
    join(licenseRoot, "CODEX-NATIVE-LICENSES.txt"),
    "utf8",
  );
  if (stagedCodexNotices !== renderCodexNativeLicenseNotices(stagedCodexInventory)) {
    throw new Error("Staged Codex native license notices differ from their inventory.");
  }
  const release = await verifyRuntimeManifest(
    canonical,
    expectedReleaseSigning,
    releaseAuthority,
  );
  await verifyReconstructedCodexSourcePayloads(
    canonical,
    stagedCodexInventory,
    join(licenseRoot, "CODEX-platform-package.json"),
  );
  const [stagedRuntimeVersions, sourceRuntimeVersions] = await Promise.all([
    readFile(join(licenseRoot, "RUNTIME-VERSIONS.json"), "utf8"),
    readFile(join(import.meta.dir, "runtime-versions.json"), "utf8"),
  ]);
  if (stagedRuntimeVersions !== sourceRuntimeVersions) {
    throw new Error("Staged runtime version pins differ from source.");
  }

  const dataRemover = await codeSignature(join(runtimeRoot, "bin/oprte-data-remover"));
  if (dataRemover.identifier !== "oprte-data-remover") {
    throw new Error("Data remover code identifier differs.");
  }
  if (await plistValue(plist, "KitchenExpectedDataRemoverCDHashV1") !== dataRemover.cdHash) {
    throw new Error("Info.plist does not seal the data remover CodeDirectory hash.");
  }
  const custodian = await codeSignature(join(runtimeRoot, "bin/oprte-keychain-custodian"));
  if (custodian.identifier !== "oprte-keychain-custodian") {
    throw new Error("Keychain custodian code identifier differs.");
  }
  await verifyReleaseCodeIdentity(
    join(runtimeRoot, "bin/oprte-keychain-custodian"),
    "oprte-keychain-custodian",
    releaseAuthority,
  );
  const custodyProbeSupervisorPath = join(
    runtimeRoot,
    custodyProbeSupervisorPackageContract.runtimeRelativePath,
  );
  const custodyProbeSupervisor = await codeSignature(
    custodyProbeSupervisorPath,
  );
  const verifiedRuntimeManifest = record(
    release.runtimeManifest,
    "verified runtime manifest",
  );
  const verifiedRuntime = record(
    verifiedRuntimeManifest["runtime"],
    "verified runtime manifest runtime",
  );
  const verifiedCustodyProbeSupervisor = record(
    verifiedRuntime["custodyProbeSupervisor"],
    "verified runtime custody probe supervisor",
  );
  if (
    custodyProbeSupervisor.identifier
      !== custodyProbeSupervisorPackageContract.identifier
    || custodyProbeSupervisor.cdHash
      !== string(
        verifiedCustodyProbeSupervisor["cdHash"],
        "verified custody probe supervisor CodeDirectory hash",
      )
  ) {
    throw new Error("Custody probe supervisor code identity differs from its manifest.");
  }
  await verifyReleaseCodeIdentity(
    custodyProbeSupervisorPath,
    custodyProbeSupervisorPackageContract.identifier,
    releaseAuthority,
  );
  await verifyThinArm64SystemMachO(custodyProbeSupervisorPath);
  const imageNormalizerPath = join(
    runtimeRoot,
    imageNormalizerPackageContract.runtimeRelativePath,
  );
  const imageNormalizer = await codeSignature(imageNormalizerPath);
  if (
    imageNormalizer.identifier !== imageNormalizerPackageContract.identifier
    || imageNormalizer.teamIdentifier !== null
  ) {
    throw new Error("Image normalizer code identity differs.");
  }
  await run(["/usr/bin/codesign", "--verify", "--strict", imageNormalizerPath]);
  const imageNormalizerEntitlements = await run([
    "/usr/bin/codesign",
    "--display",
    "--entitlements",
    "-",
    imageNormalizerPath,
  ], { allowFailure: true });
  if (!codeSignatureHasNoEntitlements(
    imageNormalizerEntitlements,
    imageNormalizerPath,
  )) {
    throw new Error("Image normalizer must not carry entitlements.");
  }
  const imageNormalizerImports = await run([
    "/usr/bin/nm",
    "-u",
    imageNormalizerPath,
  ]);
  if (/^_(?:accept|bind|connect|getaddrinfo|listen|recv(?:from|msg)?|send(?:file|msg|to)?|socket|socketpair)$/mu
    .test(imageNormalizerImports.stdout)) {
    throw new Error("Image normalizer must not import network operations.");
  }
  await verifyExactAdHocGatewayPosture(
    join(runtimeRoot, "bin/oprte-gateway"),
  );
  await verifyReleaseCodeIdentity(
    hostExecutable,
    macosPackage.bundleIdentifier,
    releaseAuthority,
  );
  await verifyReleaseCodeIdentity(
    canonical,
    macosPackage.bundleIdentifier,
    releaseAuthority,
  );
  await run([
    "/usr/bin/codesign",
    "--verify",
    "--deep",
    "--strict",
    "--verbose=4",
    canonical,
  ]);
  const archs = (await run([
    "/usr/bin/lipo",
    "-archs",
    join(contentsRoot, `MacOS/${macosPackage.executableName}`),
  ])).stdout.trim();
  if (archs !== macosPackage.architecture) {
    throw new Error(`Host architecture differs: ${archs}`);
  }
  const codexVersion = (await run([join(runtimeRoot, "codex/bin/codex"), "--version"])).stdout.trim();
  if (codexVersion !== `codex-cli ${runtimeVersions.codex.version}`) {
    throw new Error(`Bundled Codex version differs: ${codexVersion}`);
  }
  const gitVersion = (await run([join(runtimeRoot, "git/bin/git"), "--version"])).stdout.trim();
  if (gitVersion !== `git version ${runtimeVersions.git.version}`) {
    throw new Error(`Bundled Git version differs: ${gitVersion}`);
  }
  const gitLfsVersion = (await run([
    join(runtimeRoot, "git/libexec/git-core/git-lfs"),
    "version",
  ])).stdout.trim();
  if (gitLfsVersion !== runtimeVersions.gitLfs.versionOutput) {
    throw new Error(`Bundled Git LFS version differs: ${gitLfsVersion}`);
  }
  const gitCredentialManagerVersion = (await run([
    join(runtimeRoot, "git/libexec/git-core/git-credential-manager"),
    "--version",
  ])).stdout.trim();
  if (gitCredentialManagerVersion !== runtimeVersions.gitCredentialManager.versionOutput) {
    throw new Error(
      `Bundled Git Credential Manager version differs: ${gitCredentialManagerVersion}`,
    );
  }
  const ripgrepVersion = (await run([
    join(runtimeRoot, "codex/codex-path/rg"),
    "--version",
  ])).stdout.trim();
  if (ripgrepVersion !== runtimeVersions.ripgrep.versionOutput) {
    throw new Error(`Bundled ripgrep version differs: ${ripgrepVersion}`);
  }
  return release;
}

export async function launchSmokeMacOSApp(
  appPath: string,
  dwellMilliseconds = 8_000,
  authority?: CustodyProbeSupervisorAuthorityEvidence,
  dependencies: MacOSPackageResidentProbeDependencies =
    defaultMacOSPackageResidentProbeDependencies,
): Promise<void> {
  const exactAuthority = authority
    ?? (await verifyMacOSApp(appPath)).custodyProbeSupervisor;
  const smokeRoot = await realpath(
    await mkdtemp(join(tmpdir(), "hra-package-smoke-")),
  );
  let heldRoot: HeldSmokeRoot | null = null;
  try {
    heldRoot = await holdSmokeRoot(smokeRoot);
    if (
      !Number.isSafeInteger(dwellMilliseconds)
      || dwellMilliseconds <= 0
      || dwellMilliseconds > 30_000
    ) {
      throw new Error("Package launch smoke dwell is outside its native bound.");
    }
    await dependencies.smokeCandidate(
      appPath,
      exactAuthority,
      smokeRoot,
      dwellMilliseconds,
    );
    await dependencies.afterSmokeForTest?.(smokeRoot);
    const marker = await readHeldSmokeMarker(heldRoot, dependencies);
    if (
      !isDeepStrictEqual(Object.keys(marker).sort(), [
        "bunVersion",
        "codexVersion",
        "gitVersion",
        "schemaVersion",
      ])
      || marker["schemaVersion"] !== 1
      || marker["bunVersion"] !== "1.3.14"
      || marker["codexVersion"] !== `codex-cli ${runtimeVersions.codex.version}`
      || marker["gitVersion"] !== `git version ${runtimeVersions.git.version}`
    ) {
      throw new Error("Packaged gateway did not prove its isolated runtime identity.");
    }
  } finally {
    if (heldRoot === null) {
      // No descriptor authority was established, so cleanup must not recurse
      // through whatever may now occupy the freshly allocated path.
      await rmdir(smokeRoot);
    } else {
      await removeHeldSmokeRootExactly(heldRoot);
    }
  }
}

export async function probePackagedCustodyAuthorization(
  appPath: string,
  authority?: CustodyProbeSupervisorAuthorityEvidence,
  dependencies: MacOSPackageResidentProbeDependencies =
    defaultMacOSPackageResidentProbeDependencies,
): Promise<void> {
  const exactAuthority = authority
    ?? (await verifyMacOSApp(appPath)).custodyProbeSupervisor;
  const gatewayFileSha256 = await exactGatewayFileSha256(join(
    appPath,
    "Contents/Resources/runtime/bin/oprte-gateway",
  ));
  const rendererAuthoritySha256 = rendererAuthorityRoot(
    await packagedRendererAuthorityEntries(join(
      appPath,
      "Contents/Resources/frontend/dist",
    )),
  );
  const expectedReceipt =
    `{"authorization":"hra-parent-v1",` +
    `"gatewayFileSha256":"${gatewayFileSha256}",` +
    `"keychainAccessed":false,"ok":true,` +
    `"rendererAuthoritySha256":"${rendererAuthoritySha256}",` +
    `"version":1}\n`;
  await dependencies.authorizeCandidate(
    appPath,
    exactAuthority,
    expectedReceipt,
  );
  // The helper bound its response to the exact authority that it revalidated;
  // independently recompute the final package again after the probe so a
  // same-user mutation cannot win between the verifier's first read and the
  // authorize-only response.
  const gatewayAfter = await exactGatewayFileSha256(join(
    appPath,
    "Contents/Resources/runtime/bin/oprte-gateway",
  ));
  const rendererAfter = rendererAuthorityRoot(
    await packagedRendererAuthorityEntries(join(
      appPath,
      "Contents/Resources/frontend/dist",
    )),
  );
  if (
    gatewayAfter !== gatewayFileSha256
    || rendererAfter !== rendererAuthoritySha256
  ) {
    throw new Error("Packaged custody authority changed across its native probe.");
  }
}

export async function probePackagedCustodyStatus(
  appPath: string,
  authority?: CustodyProbeSupervisorAuthorityEvidence,
  inspectCandidate: typeof inspectResidentEnrollmentCustodyNoUi =
    inspectResidentEnrollmentCustodyNoUi,
): Promise<void> {
  const exactAuthority = authority
    ?? (await verifyMacOSApp(appPath)).custodyProbeSupervisor;
  await inspectCandidate(appPath, exactAuthority);
}

async function verifyMacOSDmgSnapshot(
  dmgPath: string,
  options: Readonly<{
    custodyAuthorizationProbe?: boolean;
    launchSmoke?: boolean;
  }> = {},
): Promise<MacOSAppEvidence> {
  const temporaryRoot = await mkdtemp(join(tmpdir(), "hra-dmg-verify-"));
  const mountPoint = join(temporaryRoot, "mount");
  await Bun.write(join(temporaryRoot, ".keep"), "");
  await run(["/bin/mkdir", mountPoint]);
  let attached = false;
  let evidence: MacOSAppEvidence | undefined;
  try {
    await run([
      "/usr/bin/hdiutil",
      "attach",
      "-nobrowse",
      "-readonly",
      "-mountpoint",
      mountPoint,
      dmgPath,
    ]);
    attached = true;
    const entries = (await readdir(mountPoint)).sort();
    if (JSON.stringify(entries) !== JSON.stringify(["Applications", "HRA.app"])) {
      throw new Error(`DMG root differs: ${entries.join(", ")}`);
    }
    const applications = await lstat(join(mountPoint, "Applications"));
    if (!applications.isSymbolicLink() || await readlink(join(mountPoint, "Applications")) !== "/Applications") {
      throw new Error("DMG Applications link differs.");
    }
    const mountedApp = join(mountPoint, "HRA.app");
    evidence = await verifyMacOSApp(mountedApp);
    if (options.custodyAuthorizationProbe === true) {
      await probePackagedCustodyStatus(
        mountedApp,
        evidence.custodyProbeSupervisor,
      );
      await probePackagedCustodyAuthorization(
        mountedApp,
        evidence.custodyProbeSupervisor,
      );
    }
    if (options.launchSmoke === true) {
      await launchSmokeMacOSApp(
        mountedApp,
        8_000,
        evidence.custodyProbeSupervisor,
      );
    }
  } finally {
    if (attached) {
      await run(["/usr/bin/hdiutil", "detach", mountPoint], { allowFailure: true });
    }
    await rm(temporaryRoot, { force: true, recursive: true });
  }
  if (evidence === undefined) {
    throw new Error("DMG verification produced no application evidence.");
  }
  return evidence;
}

export async function verifyMacOSDmg(
  dmgPath: string,
  options: Readonly<{
    custodyAuthorizationProbe?: boolean;
    launchSmoke?: boolean;
  }> = {},
): Promise<MacOSAppEvidence> {
  const snapshot = await snapshotDmg(dmgPath);
  try {
    return await verifyMacOSDmgSnapshot(snapshot.path, options);
  } finally {
    await snapshot.remove();
  }
}

export async function verifyMacOSReleaseArtifacts(
  releaseDirectory = macosPackage.releaseDirectory,
): Promise<void> {
  const status = await lstat(releaseDirectory);
  if (!status.isDirectory() || status.isSymbolicLink()) {
    throw new Error(`Release path must be a real directory: ${releaseDirectory}`);
  }
  const dmgName = `${macosPackage.artifactBaseName}.dmg`;
  const checksumName = `${dmgName}.sha256`;
  const manifestName =
    `HRA-${macosPackage.version}-${macosPackage.build}-release-manifest.json`;
  const expectedEntries = [
    checksumName,
    dmgName,
    manifestName,
    ...correspondingSourceSpecs.map((spec) => spec.archiveName),
  ].sort();
  const entries = (await readdir(releaseDirectory)).sort();
  if (JSON.stringify(entries) !== JSON.stringify(expectedEntries)) {
    throw new Error(`Release artifact set differs: ${entries.join(", ")}`);
  }
  await verifyRegularReleaseEntries(releaseDirectory, expectedEntries);

  const { dmgBytes, dmgEvidence, dmgSha256 } = await verifyDmgAndChecksum(
    releaseDirectory,
  );
  const rawManifest: unknown = JSON.parse(
    await readFile(join(releaseDirectory, manifestName), "utf8"),
  );
  const manifest = record(rawManifest, "release manifest");
  if (manifest["schemaVersion"] !== 1) {
    throw new Error("Release manifest schema is unsupported.");
  }
  const artifact = record(manifest["artifact"], "release artifact");
  if (
    artifact["name"] !== dmgName
    || artifact["sha256"] !== dmgSha256
    || number(artifact["bytes"], "release artifact bytes") !== dmgBytes
  ) {
    throw new Error("Release artifact evidence differs from the DMG.");
  }
  const release = record(manifest["release"], "release identity");
  if (
    release["architecture"] !== macosPackage.architecture
    || number(release["build"], "release build") !== macosPackage.build
    || release["commit"] !== dmgEvidence.commit
    || release["minimumMacOS"] !== macosPackage.minimumMacOS
    || release["notarized"] !== false
    || !isDeepStrictEqual(release["signing"], productionReleaseSigning)
    || release["version"] !== macosPackage.version
  ) {
    throw new Error("Release identity differs from the mounted app.");
  }
  const rawSources = manifest["correspondingSources"];
  if (!Array.isArray(rawSources) || rawSources.length !== correspondingSourceSpecs.length) {
    throw new Error("Release corresponding-source evidence differs.");
  }
  for (const [index, spec] of correspondingSourceSpecs.entries()) {
    const recorded = record(rawSources[index], `corresponding source ${index}`);
    const actual = await verifyCorrespondingSourceArchive(
      join(releaseDirectory, spec.archiveName),
      spec,
    );
    if (
      spec.project === "Bun"
      && actual.sha256 !== runtimeVersions.bun.completeSourceArchiveSha256
    ) {
      throw new Error("Bun complete corresponding-source hash differs from its runtime pin.");
    }
    if (
      recorded["archiveName"] !== actual.archiveName
      || number(recorded["bytes"], `corresponding source ${index} bytes`) !== actual.bytes
      || recorded["commit"] !== actual.commit
      || recorded["project"] !== actual.project
      || recorded["repository"] !== actual.repository
      || recorded["sha256"] !== actual.sha256
      || JSON.stringify(recorded["externalSources"])
        !== JSON.stringify(actual.externalSources)
      || JSON.stringify(recorded["submodules"]) !== JSON.stringify(actual.submodules)
    ) {
      throw new Error(`${spec.project} corresponding-source evidence differs.`);
    }
  }
  if (
    manifest["runtimeTreeSha256"] !== dmgEvidence.treeSha256
    || manifest["sourceTreeCleanAtPackaging"] !== true
    || JSON.stringify(manifest["runtimeManifest"])
      !== JSON.stringify(dmgEvidence.runtimeManifest)
  ) {
    throw new Error("Release provenance differs from the mounted app.");
  }
}

async function verifyDmgAndChecksum(
  releaseDirectory: string,
): Promise<Readonly<{
  dmgBytes: number;
  dmgEvidence: MacOSAppEvidence;
  dmgSha256: string;
}>> {
  const dmgName = `${macosPackage.artifactBaseName}.dmg`;
  const dmgPath = join(releaseDirectory, dmgName);
  const checksumName = `${dmgName}.sha256`;
  const snapshot = await snapshotDmg(dmgPath);
  try {
    const checksum = await readFile(join(releaseDirectory, checksumName), "utf8");
    if (checksum !== `${snapshot.sha256}  ${dmgName}\n`) {
      throw new Error("Release checksum file differs from the DMG.");
    }
    return {
      dmgBytes: snapshot.bytes,
      dmgEvidence: await verifyMacOSDmgSnapshot(snapshot.path),
      dmgSha256: snapshot.sha256,
    };
  } finally {
    await snapshot.remove();
  }
}

export async function verifyMacOSCoreArtifacts(
  releaseDirectory = macosPackage.releaseDirectory,
): Promise<void> {
  const status = await lstat(releaseDirectory);
  if (!status.isDirectory() || status.isSymbolicLink()) {
    throw new Error(`Release path must be a real directory: ${releaseDirectory}`);
  }
  const dmgName = `${macosPackage.artifactBaseName}.dmg`;
  const expectedEntries = [`${dmgName}.sha256`, dmgName].sort();
  const entries = (await readdir(releaseDirectory)).sort();
  if (JSON.stringify(entries) !== JSON.stringify(expectedEntries)) {
    throw new Error(`Core package artifact set differs: ${entries.join(", ")}`);
  }
  await verifyRegularReleaseEntries(releaseDirectory, expectedEntries);
  await verifyDmgAndChecksum(releaseDirectory);
}

type VerificationArguments = Readonly<{
  app: string | undefined;
  coreReleaseDirectory: string | undefined;
  custodyAuthorizationProbe: boolean;
  dmg: string | undefined;
  launchSmoke: boolean;
  releaseDirectory: string | undefined;
  structural: boolean;
}>;

export function parseVerificationArguments(
  argv: readonly string[],
): VerificationArguments {
  const values = new Map<string, string>();
  const flags = new Set<string>();
  const valueOptions = new Set([
    "--app",
    "--core-release-directory",
    "--dmg",
    "--release-directory",
  ]);
  const flagOptions = new Set([
    "--custody-authorization-probe",
    "--launch-smoke",
    "--structural",
  ]);
  for (let index = 0; index < argv.length; index += 1) {
    const argument = argv[index]!;
    if (valueOptions.has(argument)) {
      const value = argv[index + 1];
      if (
        values.has(argument)
        || value === undefined
        || value.length === 0
        || value.startsWith("--")
      ) {
        throw new Error(`Verifier option ${argument} is duplicated or missing its value.`);
      }
      values.set(argument, value);
      index += 1;
      continue;
    }
    if (flagOptions.has(argument)) {
      if (flags.has(argument)) {
        throw new Error(`Verifier flag ${argument} is duplicated.`);
      }
      flags.add(argument);
      continue;
    }
    throw new Error(`Verifier argument is unsupported: ${argument}`);
  }
  const parsed: VerificationArguments = {
    app: values.get("--app"),
    coreReleaseDirectory: values.get("--core-release-directory"),
    custodyAuthorizationProbe: flags.has("--custody-authorization-probe"),
    dmg: values.get("--dmg"),
    launchSmoke: flags.has("--launch-smoke"),
    releaseDirectory: values.get("--release-directory"),
    structural: flags.has("--structural"),
  };
  const primaryModes = [
    parsed.app === undefined ? undefined : "app",
    parsed.coreReleaseDirectory === undefined ? undefined : "core",
    parsed.dmg === undefined ? undefined : "dmg",
    parsed.releaseDirectory === undefined ? undefined : "release",
  ].filter((value): value is string => value !== undefined);
  if (primaryModes.length > 1) {
    throw new Error("Verifier app, DMG, core-release, and release modes are mutually exclusive.");
  }
  if (
    (parsed.coreReleaseDirectory !== undefined
      || parsed.releaseDirectory !== undefined)
    && (parsed.custodyAuthorizationProbe || parsed.launchSmoke)
  ) {
    throw new Error("Release-directory verification cannot include executable probes.");
  }
  if (
    parsed.structural
    && (
      parsed.app === undefined
      || parsed.coreReleaseDirectory !== undefined
      || parsed.dmg !== undefined
      || parsed.releaseDirectory !== undefined
      || parsed.custodyAuthorizationProbe
      || parsed.launchSmoke
    )
  ) {
    throw new Error("Structural verification requires only one explicit app path.");
  }
  return parsed;
}

async function main(): Promise<void> {
  const arguments_ = parseVerificationArguments(process.argv.slice(2));
  const appPath = resolve(arguments_.app ?? macosPackage.appBundlePath);
  const {
    coreReleaseDirectory,
    custodyAuthorizationProbe,
    dmg,
    launchSmoke,
    releaseDirectory,
    structural,
  } = arguments_;
  if (structural) {
    const expectedStructuralApp = resolve(
      macosPackage.desktopRoot,
      "zig-out/structural/package/HRA-structural.app",
    );
    if (appPath !== expectedStructuralApp) {
      throw new Error("Structural verifier app path differs from its isolated root.");
    }
    await verifyMacOSApp(appPath, { profile: "structural" });
    process.stdout.write(`${appPath}\n`);
    return;
  }
  if (coreReleaseDirectory !== undefined) {
    const resolvedCoreReleaseDirectory = resolve(coreReleaseDirectory);
    await verifyMacOSCoreArtifacts(resolvedCoreReleaseDirectory);
    process.stdout.write(`${resolvedCoreReleaseDirectory}\n`);
    return;
  }
  if (releaseDirectory !== undefined) {
    const resolvedReleaseDirectory = resolve(releaseDirectory);
    await verifyMacOSReleaseArtifacts(resolvedReleaseDirectory);
    process.stdout.write(`${resolvedReleaseDirectory}\n`);
    return;
  }
  if (dmg === undefined) {
    const evidence = await verifyMacOSApp(appPath);
    if (custodyAuthorizationProbe) {
      await probePackagedCustodyStatus(
        appPath,
        evidence.custodyProbeSupervisor,
      );
      await probePackagedCustodyAuthorization(
        appPath,
        evidence.custodyProbeSupervisor,
      );
    }
    if (launchSmoke) {
      await launchSmokeMacOSApp(
        appPath,
        8_000,
        evidence.custodyProbeSupervisor,
      );
    }
    process.stdout.write(`${appPath}\n`);
    return;
  }
  const dmgPath = resolve(dmg);
  if (basename(dmgPath) !== `${macosPackage.artifactBaseName}.dmg`) {
    throw new Error(`Unexpected DMG name: ${basename(dmgPath)}`);
  }
  await verifyMacOSDmg(dmgPath, { custodyAuthorizationProbe, launchSmoke });
  process.stdout.write(`${dmgPath}\n`);
}

if (import.meta.main) await main();
