import { createHash } from "node:crypto";
import { constants, type BigIntStats } from "node:fs";
import {
  chmod,
  copyFile,
  cp,
  lstat,
  mkdtemp,
  mkdir,
  open,
  readdir,
  readFile,
  readlink,
  realpath,
  rm,
  writeFile,
} from "node:fs/promises";
import { tmpdir } from "node:os";
import { dirname, isAbsolute, join, relative, resolve, sep } from "node:path";

import { loadBunNativeLicenseInventory } from "./bun-native-licenses";
import {
  type CodexNativeLicenseInventory,
  loadCodexNativeLicenseInventory,
  verifyInstalledCodexNativePayloads,
} from "./codex-native-licenses";
import {
  CODEX_SIGNATURE_NORMALIZATION_ENTITLEMENTS_FILE,
  codexSignatureNormalizationEntry,
  codexSignatureNormalizationCodesignArguments,
  codexSignatureNormalizationManifestEntries,
  codexSignatureNormalizationPolicy,
  codexSignatureNormalizationSigning,
  createCodexSignatureSourceDelta,
  parseCodexSignatureNormalizationEntitlements,
  verifyCodexSignatureNormalizationContent,
  verifyCodexSignatureNormalizationInventory,
  verifyCodexSignatureNormalizationPackaged,
  verifyCodexSignatureNormalizationSource,
} from "./codex-signature-normalization";
import { verifyPackagedFrontend } from "./frontend-package-integrity";
import { exactGatewayFileSha256 } from "./generate-gateway-file-authority";
import { loadGcmDependencyLicenseInventory } from "./gcm-dependency-licenses";
import {
  custodyProbeSupervisorPackageContract,
  hranessUiStylesheetInput,
  imageNormalizerPackageContract,
  macosPackage,
  requiredLicenseFileNames,
  trustedThirdPartyTeams,
} from "./macos-package-config";
import { inspectReleaseSourceRepository } from "./release-provenance";
import runtimeVersions from "./runtime-versions.json";
import {
  createShippedJavaScriptLicenseInventory,
  renderShippedJavaScriptLicenseNotices,
  serializeShippedJavaScriptLicenseInventory,
  verifyShippedJavaScriptLicenseInventory,
} from "./shipped-javascript-licenses";
import { verifyRuntimePins } from "./verify-runtime-pins";
import {
  loadProductionReleaseAuthority,
  productionReleaseAuthorityPins,
  productionReleaseSigning,
  productionSigningKeychainPath,
  releaseDesignatedRequirement,
  type ReleaseSigningAuthority,
} from "./release-signing-authority";

export type CommandResult = Readonly<{
  exitCode: number;
  stderr: string;
  stdout: string;
}>;

export type SigningCommandProcess = Readonly<{
  exited: Promise<number>;
  killProcessGroup: (signal: NodeJS.Signals) => void;
  stderr: ReadableStream<Uint8Array>;
  stdout: ReadableStream<Uint8Array>;
}>;

export type SigningCommandTimer = Readonly<{
  clear: (handle: unknown) => void;
  schedule: (callback: () => void, milliseconds: number) => unknown;
}>;

export type SigningCommandPolicy = Readonly<{
  cleanupGraceMs?: number;
  maxOutputBytes: number;
  timeoutMs: number;
  timer?: SigningCommandTimer;
}>;

export const productionSigningCommandPolicy = Object.freeze({
  cleanupGraceMs: 5_000,
  maxOutputBytes: 64 * 1_024,
  timeoutMs: 30_000,
});

const successfulSigningCommandExitCodes = Object.freeze([0]);

const productionSigningUsabilityIdentifier =
  "hra-release-signing-usability-probe";

export type CodeSignature = Readonly<{
  cdHash: string | null;
  flags: readonly string[];
  hashChoices: readonly string[];
  hashType: string | null;
  identifier: string | null;
  infoPlistBound: boolean | null;
  internalRequirementsCount: number | null;
  pageSize: number | null;
  runtimeVersion: string | null;
  sealedResources: string | null;
  signatureKind: "adhoc" | "cms" | null;
  teamIdentifier: string | null;
  timestamp: string | null;
}>;

type RuntimeTreeEntry = Readonly<{
  path: string;
  sha256?: string;
  target?: string;
  type: "file" | "symlink";
}>;

export type PackageSigningContext = Readonly<{
  authority: ReleaseSigningAuthority;
  designatedRequirement: (identifier: string) => string;
  identity: string;
  keychain: string;
  label: "production" | "structural fixture";
  manifestSigning: Readonly<Record<string, unknown>>;
  sign: (path: string, identifier: string) => Promise<void>;
}>;

type PackageLayout = Readonly<{
  appRoot: string;
  binRoot: string;
  contentsRoot: string;
  infoPlist: string;
  licensesRoot: string;
  ownedCode: readonly Readonly<{ identifier: string; path: string }>[];
  resourcesRoot: string;
  runtimeRoot: string;
}>;

function packageLayout(appRoot: string): PackageLayout {
  const contentsRoot = join(appRoot, "Contents");
  const resourcesRoot = join(contentsRoot, "Resources");
  const runtimeRoot = join(resourcesRoot, "runtime");
  const binRoot = join(runtimeRoot, "bin");
  return Object.freeze({
    appRoot,
    binRoot,
    contentsRoot,
    infoPlist: join(contentsRoot, "Info.plist"),
    licensesRoot: join(runtimeRoot, "licenses"),
    ownedCode: Object.freeze([
      {
        identifier: imageNormalizerPackageContract.identifier,
        path: join(runtimeRoot, imageNormalizerPackageContract.runtimeRelativePath),
      },
      { identifier: "oprte-data-remover", path: join(binRoot, "oprte-data-remover") },
      { identifier: "oprte-git-executor", path: join(binRoot, "oprte-git-executor") },
      { identifier: "oprte-keychain-custodian", path: join(binRoot, "oprte-keychain-custodian") },
      {
        identifier: custodyProbeSupervisorPackageContract.identifier,
        path: join(runtimeRoot, custodyProbeSupervisorPackageContract.runtimeRelativePath),
      },
      {
        identifier: macosPackage.bundleIdentifier,
        path: join(contentsRoot, `MacOS/${macosPackage.executableName}`),
      },
    ]),
    resourcesRoot,
    runtimeRoot,
  });
}

function inside(root: string, path: string): boolean {
  const fromRoot = relative(root, path);
  return fromRoot === "" || (
    !fromRoot.startsWith(`..${sep}`)
    && fromRoot !== ".."
    && !fromRoot.startsWith(sep)
  );
}

async function requireRealDirectory(path: string): Promise<void> {
  const stat = await lstat(path);
  if (!stat.isDirectory() || stat.isSymbolicLink()) {
    throw new Error(`Expected a real directory: ${path}`);
  }
}

async function run(
  argv: readonly string[],
  options: Readonly<{ allowFailure?: boolean }> = {},
): Promise<CommandResult> {
  const child = Bun.spawn([...argv], {
    cwd: macosPackage.desktopRoot,
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

const defaultSigningCommandTimer: SigningCommandTimer = Object.freeze({
  clear: (handle) => {
    clearTimeout(handle as ReturnType<typeof setTimeout>);
  },
  schedule: (callback, milliseconds) => setTimeout(callback, milliseconds),
});

type SigningCommandFailureKind = "failed" | "output" | "timeout";

class SigningCommandFailure extends Error {
  readonly kind: SigningCommandFailureKind;

  constructor(kind: SigningCommandFailureKind) {
    const disposition = kind === "output"
      ? "exceeded its output limit"
      : kind === "timeout"
        ? "timed out"
        : "failed";
    super(
      `Release signing command ${disposition} without exposing signing-custody paths or output.`,
    );
    this.name = "SigningCommandFailure";
    this.kind = kind;
  }
}

function validateSigningCommandPolicy(
  policy: SigningCommandPolicy,
): void {
  if (
    !Number.isSafeInteger(policy.maxOutputBytes)
    || policy.maxOutputBytes <= 0
    || !Number.isSafeInteger(policy.timeoutMs)
    || policy.timeoutMs <= 0
    || (policy.cleanupGraceMs !== undefined
      && (!Number.isSafeInteger(policy.cleanupGraceMs)
        || policy.cleanupGraceMs <= 0))
  ) {
    throw new Error("Signing command policy must use positive safe integers.");
  }
}

async function settlesWithin(
  task: Promise<unknown>,
  milliseconds: number,
  timer: SigningCommandTimer,
): Promise<boolean> {
  let handle: unknown;
  const deadline = new Promise<false>((resolveDeadline) => {
    handle = timer.schedule(() => resolveDeadline(false), milliseconds);
  });
  try {
    return await Promise.race([
      task.then(() => true),
      deadline,
    ]);
  } finally {
    timer.clear(handle);
  }
}

async function collectSigningCommandStream(
  stream: ReadableStream<Uint8Array>,
  budget: { observedBytes: number },
  maxOutputBytes: number,
): Promise<string> {
  const reader = stream.getReader();
  const decoder = new TextDecoder("utf-8", { fatal: true });
  let text = "";
  try {
    while (true) {
      const next = await reader.read();
      if (next.done) break;
      budget.observedBytes += next.value.byteLength;
      if (budget.observedBytes > maxOutputBytes) {
        throw new SigningCommandFailure("output");
      }
      text += decoder.decode(next.value, { stream: true });
    }
    return text + decoder.decode();
  } finally {
    reader.releaseLock();
  }
}

/**
 * Collects a custody-touching process group behind one fixed deadline and one
 * shared stdout/stderr byte budget. Failure gives the whole group a bounded
 * TERM cleanup interval before KILL. The start callback is injected so this
 * behavior stays portable and deterministic in tests.
 */
export async function runBoundedSigningCommand(
  start: () => SigningCommandProcess,
  policy: SigningCommandPolicy = productionSigningCommandPolicy,
  acceptedExitCodes: readonly number[] = successfulSigningCommandExitCodes,
): Promise<CommandResult> {
  validateSigningCommandPolicy(policy);
  if (
    acceptedExitCodes.length === 0
    || acceptedExitCodes.length > 4
    || acceptedExitCodes.some(exitCode =>
      !Number.isSafeInteger(exitCode) || exitCode < 0 || exitCode > 255)
    || new Set(acceptedExitCodes).size !== acceptedExitCodes.length
  ) {
    throw new Error("Signing command accepted exit codes are invalid.");
  }
  const timer = policy.timer ?? defaultSigningCommandTimer;
  let child: SigningCommandProcess;
  try {
    child = start();
  } catch {
    throw new SigningCommandFailure("failed");
  }
  const budget = { observedBytes: 0 };
  const stdoutTask = collectSigningCommandStream(
    child.stdout,
    budget,
    policy.maxOutputBytes,
  );
  const stderrTask = collectSigningCommandStream(
    child.stderr,
    budget,
    policy.maxOutputBytes,
  );
  const commandTask = Promise.all([stdoutTask, stderrTask, child.exited]);
  void commandTask.catch(() => undefined);
  const cleanupTask = Promise.allSettled([
    child.exited,
    stdoutTask,
    stderrTask,
  ]);
  const cleanupGraceMs = policy.cleanupGraceMs
    ?? productionSigningCommandPolicy.cleanupGraceMs;
  let timeoutHandle: unknown;
  const timeoutTask = new Promise<never>((_resolveTimeout, rejectTimeout) => {
    timeoutHandle = timer.schedule(
      () => rejectTimeout(new SigningCommandFailure("timeout")),
      policy.timeoutMs,
    );
  });
  let commandCompleted = false;
  try {
    const [stdout, stderr, exitCode] = await Promise.race([
      commandTask,
      timeoutTask,
    ]);
    commandCompleted = true;
    if (!acceptedExitCodes.includes(exitCode)) {
      throw new SigningCommandFailure("failed");
    }
    return { exitCode, stderr, stdout };
  } catch (error: unknown) {
    if (!commandCompleted) {
      try {
        child.killProcessGroup("SIGTERM");
      } catch {
        // A process group that already exited needs no further termination.
      }
      if (!await settlesWithin(cleanupTask, cleanupGraceMs, timer)) {
        try {
          child.killProcessGroup("SIGKILL");
        } catch {
          // A process group that exited during the grace period is already clean.
        }
      }
    }
    await cleanupTask;
    if (error instanceof SigningCommandFailure) throw error;
    throw new SigningCommandFailure("failed");
  } finally {
    timer.clear(timeoutHandle);
  }
}

async function runSigningCommand(
  argv: readonly string[],
  acceptedExitCodes: readonly number[] = successfulSigningCommandExitCodes,
): Promise<CommandResult> {
  const env = Object.fromEntries([
    "DEVELOPER_DIR",
    "HOME",
    "LANG",
    "LC_ALL",
    "LOGNAME",
    "PATH",
    "SECURITYSESSIONID",
    "TMPDIR",
    "USER",
  ].flatMap((name) => {
    const value = process.env[name];
    return value === undefined ? [] : [[name, value] as const];
  }));
  return runBoundedSigningCommand(() => {
    const child = Bun.spawn([...argv], {
      cwd: macosPackage.desktopRoot,
      detached: true,
      env,
      stderr: "pipe",
      stdout: "pipe",
    });
    if (!Number.isSafeInteger(child.pid) || child.pid <= 1) {
      try {
        child.kill("SIGKILL");
      } catch {
        // A malformed or already-exited child cannot be used for group control.
      }
      throw new Error("Release signing command has no safe process-group leader.");
    }
    const processGroup = -child.pid;
    return {
      exited: child.exited,
      killProcessGroup: signal => process.kill(processGroup, signal),
      stderr: child.stderr,
      stdout: child.stdout,
    };
  }, productionSigningCommandPolicy, acceptedExitCodes);
}

export function assertReleaseStrictVerification(
  path: string,
  result: CommandResult,
): void {
  const expectedSuccess =
    `${path}: valid on disk\n${path}: satisfies its Designated Requirement\n`;
  if (
    result.exitCode === 0
    && result.stdout.length === 0
    && (result.stderr.length === 0 || result.stderr === expectedSuccess)
  ) return;
  const expectedTrustFailure =
    `${path}: CSSMERR_TP_NOT_TRUSTED\nIn architecture: arm64\n`;
  if (
    result.exitCode === 1
    && result.stdout.length === 0
    && result.stderr === expectedTrustFailure
  ) return;
  const stderrSha256 = createHash("sha256")
    .update(result.stderr)
    .digest("hex");
  throw new Error(
    `Release strict verification differs: ${path} (exit ${result.exitCode}, stdout bytes ${result.stdout.length}, stderr bytes ${result.stderr.length}, stderr sha256 ${stderrSha256}).`,
  );
}

type ProductionSigningKeychainControl = Readonly<{
  dispose: () => Promise<void>;
  helper: string;
  passphraseFile: string;
}>;

const releaseKeychainControlSourceSha256 =
  "e6a1748c5142d6970e055f270212a3e132f290161f5638dde8bed78351021965";

function sameSigningSourceAuthority(
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

async function snapshotReleaseKeychainControlSource(
  source: string,
  root: string,
): Promise<string> {
  const effectiveUserId = process.geteuid?.();
  if (effectiveUserId === undefined) {
    throw new Error("Release signer source custody is unavailable.");
  }
  const before = await lstat(source, { bigint: true });
  const heldSource = await open(
    source,
    constants.O_RDONLY | constants.O_NOFOLLOW,
  );
  try {
    const held = await heldSource.stat({ bigint: true });
    if (
      !sameSigningSourceAuthority(before, held)
      || held.uid !== BigInt(effectiveUserId)
      || held.nlink !== 1n
      || (held.mode & 0o022n) !== 0n
      || held.size <= 0n
      || held.size > 256n * 1_024n
    ) throw new Error("Release signer source authority is unsafe.");
    const bytes = await heldSource.readFile();
    const [heldAfter, namedAfter] = await Promise.all([
      heldSource.stat({ bigint: true }),
      lstat(source, { bigint: true }),
    ]);
    const digest = createHash("sha256").update(bytes).digest("hex");
    if (
      BigInt(bytes.byteLength) !== held.size
      || !sameSigningSourceAuthority(held, heldAfter)
      || !sameSigningSourceAuthority(held, namedAfter)
      || digest !== releaseKeychainControlSourceSha256
    ) throw new Error("Release signer source changed during its exact read.");
    const snapshot = join(root, "release-keychain-control.snapshot.c");
    await writeFile(snapshot, bytes, { flag: "wx", mode: 0o400 });
    bytes.fill(0);
    const snapshotStatus = await lstat(snapshot);
    if (
      !snapshotStatus.isFile()
      || snapshotStatus.isSymbolicLink()
      || snapshotStatus.uid !== effectiveUserId
      || snapshotStatus.nlink !== 1
      || snapshotStatus.mode !== 0o100400
      || await sha256(snapshot) !== releaseKeychainControlSourceSha256
    ) {
      await rm(snapshot, { force: true });
      throw new Error("Release signer source snapshot differs.");
    }
    return snapshot;
  } finally {
    await heldSource.close();
  }
}

export async function compileReleaseKeychainControl(
  root: string,
): Promise<string> {
  const canonicalRoot = await realpath(root);
  const rootStatus = await lstat(root);
  const effectiveUserId = process.geteuid;
  if (
    effectiveUserId === undefined
    || canonicalRoot !== root
    || !rootStatus.isDirectory()
    || rootStatus.isSymbolicLink()
    || rootStatus.uid !== effectiveUserId()
    || (rootStatus.mode & 0o077) !== 0
  ) {
    throw new Error("Release signer build custody is unsafe.");
  }
  const source = join(import.meta.dir, "release-keychain-control.c");
  const sourceSnapshot = await snapshotReleaseKeychainControlSource(source, root);
  const helper = join(root, "hra-release-keychain-control");
  try {
    const compilation = await runSigningCommand([
      "/usr/bin/clang",
      "-std=c17",
      "-O2",
      "-Wall",
      "-Wextra",
      "-Werror",
      "-Wno-deprecated-declarations",
      "-fblocks",
      "-fstack-protector-strong",
      "-D_FORTIFY_SOURCE=2",
      "-Wl,-no_adhoc_codesign",
      "-framework",
      "Security",
      "-framework",
      "CoreFoundation",
      sourceSnapshot,
      "-o",
      helper,
    ]);
    if (compilation.stdout !== "" || compilation.stderr !== "") {
      throw new Error("Release signer compilation was noisy.");
    }
    const hardened = await runSigningCommand(
      releaseKeychainControlCodesignArguments(helper),
    );
    if (hardened.stdout !== "" || hardened.stderr !== "") {
      throw new Error("Release signer hardening was noisy.");
    }
    await chmod(helper, 0o700);
    const helperStatus = await lstat(helper);
    if (
      !helperStatus.isFile()
      || helperStatus.isSymbolicLink()
      || helperStatus.nlink !== 1
      || helperStatus.uid !== effectiveUserId()
      || helperStatus.mode !== 0o100700
    ) {
      throw new Error("Release signer output is unsafe.");
    }
    const [architectures, display, entitlements, strictVerification] =
      await Promise.all([
        runSigningCommand(["/usr/bin/lipo", "-archs", helper]),
        runSigningCommand([
          "/usr/bin/codesign",
          "--display",
          "--verbose=4",
          helper,
        ]),
        runSigningCommand([
          "/usr/bin/codesign",
          "--display",
          "--entitlements",
          "-",
          helper,
        ]),
        runSigningCommand([
          "/usr/bin/codesign",
          "--verify",
          "--all-architectures",
          "--strict",
          helper,
        ]),
      ]);
    const signature = parseCodeSignatureDetails(
      `${display.stdout}\n${display.stderr}`,
    );
    if (
      architectures.stderr !== ""
      || architectures.stdout.trim() !== "arm64"
      || strictVerification.stdout !== ""
      || strictVerification.stderr !== ""
      || signature.identifier !== "hra-release-keychain-control"
      || signature.teamIdentifier !== null
      || signature.signatureKind !== "adhoc"
      || signature.hashType !== "sha256"
      || signature.hashChoices.length !== 1
      || signature.hashChoices[0] !== "sha256"
      || signature.pageSize !== 16_384
      || signature.timestamp !== null
      || signature.flags.length !== 2
      || !signature.flags.includes("adhoc")
      || !signature.flags.includes("runtime")
      || !codeSignatureHasNoEntitlements(entitlements, helper)
    ) throw new Error("Release signer hardening posture differs.");
    return helper;
  } catch {
    await rm(helper, { force: true });
    throw new Error(
      "Release signer creation failed without exposing custody paths or command output.",
    );
  } finally {
    await rm(sourceSnapshot, { force: true });
  }
}

export function releaseKeychainControlCodesignArguments(
  helper: string,
): readonly string[] {
  return [
    "/usr/bin/codesign",
    "--force",
    "--sign",
    "-",
    "--options",
    "runtime",
    "--timestamp=none",
    "--digest-algorithm=sha256",
    "--pagesize",
    "16384",
    "--identifier",
    "hra-release-keychain-control",
    helper,
  ];
}

async function productionSigningKeychainControl(): Promise<
  ProductionSigningKeychainControl
> {
  const passphraseFile =
    process.env.HRA_RELEASE_SIGNING_KEYCHAIN_PASSPHRASE_FILE;
  if (
    passphraseFile === undefined
    || !isAbsolute(passphraseFile)
    || resolve(passphraseFile) !== passphraseFile
  ) {
    throw new Error(
      "Production signing requires a normalized absolute Keychain passphrase-file path.",
    );
  }
  let canonicalPassphraseFile: string;
  let passphraseStatus: Awaited<ReturnType<typeof lstat>>;
  let passphraseParentStatus: Awaited<ReturnType<typeof lstat>>;
  try {
    [
      canonicalPassphraseFile,
      passphraseStatus,
      passphraseParentStatus,
    ] = await Promise.all([
      realpath(passphraseFile),
      lstat(passphraseFile),
      lstat(dirname(passphraseFile)),
    ]);
  } catch {
    throw new Error("Production signing Keychain control custody is unavailable.");
  }
  const effectiveUserId = process.geteuid;
  const repositoryRoot = resolve(macosPackage.desktopRoot, "../..");
  if (
    effectiveUserId === undefined
    || canonicalPassphraseFile !== passphraseFile
    || !passphraseStatus.isFile()
    || passphraseStatus.isSymbolicLink()
    || passphraseStatus.nlink !== 1
    || passphraseStatus.uid !== effectiveUserId()
    || (passphraseStatus.mode & 0o077) !== 0
    || passphraseStatus.size < 32
    || passphraseStatus.size > 512
    || !passphraseParentStatus.isDirectory()
    || passphraseParentStatus.isSymbolicLink()
    || passphraseParentStatus.uid !== effectiveUserId()
    || (passphraseParentStatus.mode & 0o077) !== 0
    || inside(repositoryRoot, passphraseFile)
  ) {
    throw new Error("Production signing Keychain control custody is unsafe.");
  }
  const root = await realpath(await mkdtemp(join(
    tmpdir(),
    "hra-release-keychain-control-",
  )));
  await chmod(root, 0o700);
  let helper: string;
  try {
    helper = await compileReleaseKeychainControl(root);
  } catch {
    await rm(root, { force: true, recursive: true });
    throw new Error(
      "Release Keychain control-helper creation failed without exposing custody paths or command output.",
    );
  }
  return Object.freeze({
    dispose: () => rm(root, { force: true, recursive: true }),
    helper,
    passphraseFile,
  });
}

async function controlProductionSigningKeychain(
  control: ProductionSigningKeychainControl,
  keychain: string,
): Promise<void> {
  const result = await runSigningCommand([
    control.helper,
    "lock",
    keychain,
  ]);
  if (result.stdout !== "" || result.stderr !== "") {
    throw new Error(
      "Production signing Keychain control emitted unexpected output.",
    );
  }
}

async function signWithProductionKeychain(
  control: ProductionSigningKeychainControl,
  keychain: string,
  authority: ReleaseSigningAuthority,
  path: string,
  identifier: string,
): Promise<void> {
  const result = await runSigningCommand([
    control.helper,
    "sign",
    keychain,
    control.passphraseFile,
    authority.leaf.sha1,
    authority.root.sha1,
    identifier,
    path,
  ]);
  if (result.stdout !== "" || result.stderr !== "") {
    throw new Error("Production release signer emitted unexpected output.");
  }
}

async function sha256(path: string): Promise<string> {
  const file = await open(path, "r");
  const hasher = createHash("sha256");
  try {
    for await (const chunk of file.readableWebStream()) {
      hasher.update(chunk as Uint8Array);
    }
  } finally {
    await file.close();
  }
  return hasher.digest("hex");
}

async function setPlist(
  layout: PackageLayout,
  key: string,
  type: "bool" | "string",
  value: string,
): Promise<void> {
  const replace = await run([
    "/usr/bin/plutil",
    "-replace",
    key,
    `-${type}`,
    value,
    layout.infoPlist,
  ], { allowFailure: true });
  if (replace.exitCode === 0) return;
  await run([
    "/usr/bin/plutil",
    "-insert",
    key,
    `-${type}`,
    value,
    layout.infoPlist,
  ]);
}

async function removePlistKey(
  layout: PackageLayout,
  key: string,
): Promise<void> {
  await run([
    "/usr/bin/plutil",
    "-remove",
    key,
    layout.infoPlist,
  ], { allowFailure: true });
}

async function copyExclusive(source: string, destination: string): Promise<void> {
  await copyFile(source, destination, constants.COPYFILE_EXCL);
}

async function stageLicenseFiles(layout: PackageLayout, options: Readonly<{
  codexPackageRoot: string;
  codexPlatformPackageJson: string;
  gitPackageRoot: string;
  gitRoot: string;
}>): Promise<CodexNativeLicenseInventory> {
  const repositoryRoot = resolve(macosPackage.desktopRoot, "../..");
  await loadGcmDependencyLicenseInventory({
    gcmRoot: join(options.gitRoot, "libexec/git-core"),
  });
  await loadBunNativeLicenseInventory();
  const codexNativeInventory = await loadCodexNativeLicenseInventory();
  await verifyInstalledCodexNativePayloads(
    codexNativeInventory,
    dirname(options.codexPlatformPackageJson),
  );
  const hranessUiRoot = join(macosPackage.desktopRoot, "node_modules/@hraness/ui");
  const hranessUiInputs = new Map<string, string>([
    ["checked license", join(macosPackage.desktopRoot, "runtime/HRANESS-UI-LICENSE.txt")],
    ["license", join(hranessUiRoot, "LICENSE")],
    ["manifest", join(hranessUiRoot, "package.json")],
    ["stylesheet", join(hranessUiRoot, "src/components.css")],
  ]);
  const hranessUiExpected = new Map<string, string>([
    ["checked license", hranessUiStylesheetInput.licenseSha256],
    ["license", hranessUiStylesheetInput.licenseSha256],
    ["manifest", hranessUiStylesheetInput.packageJsonSha256],
    ["stylesheet", hranessUiStylesheetInput.stylesheetSha256],
  ]);
  for (const [label, path] of hranessUiInputs) {
    const actual = await sha256(path);
    const expected = hranessUiExpected.get(label);
    if (actual !== expected) {
      throw new Error(`hraness/ui ${label} hash differs: ${actual}`);
    }
  }
  const sources = new Map<string, string>([
    ["BUN-DEPENDENCY-LICENSES.json", join(macosPackage.desktopRoot, "runtime/BUN-DEPENDENCY-LICENSES.json")],
    ["BUN-DEPENDENCY-LICENSES.txt", join(macosPackage.desktopRoot, "runtime/BUN-DEPENDENCY-LICENSES.txt")],
    ["BUN-LICENSE.md", join(macosPackage.desktopRoot, "runtime/BUN-LICENSE.md")],
    ["BUN-PROVENANCE.md", join(macosPackage.desktopRoot, "runtime/BUN-PROVENANCE.md")],
    ["CODEX-APP-SDK-LICENSE.txt", join(repositoryRoot, "packages/internal/codex-app-sdk/LICENSE")],
    ["CODEX-LICENSE.txt", join(macosPackage.desktopRoot, "runtime/CODEX-LICENSE.txt")],
    ["CODEX-NATIVE-LICENSES.json", join(macosPackage.desktopRoot, "runtime/CODEX-NATIVE-LICENSES.json")],
    ["CODEX-NATIVE-LICENSES.txt", join(macosPackage.desktopRoot, "runtime/CODEX-NATIVE-LICENSES.txt")],
    ["CODEX-NOTICE.txt", join(macosPackage.desktopRoot, "runtime/CODEX-NOTICE.txt")],
    ["CODEX-SIGNATURE-NORMALIZATION.md", join(macosPackage.desktopRoot, "runtime/CODEX-SIGNATURE-NORMALIZATION.md")],
    ["CODEX-package.json", join(options.codexPackageRoot, "package.json")],
    ["CODEX-platform-package.json", options.codexPlatformPackageJson],
    ["DESKTOP-THIRD-PARTY-NOTICES.md", join(macosPackage.desktopRoot, "runtime/THIRD_PARTY_NOTICES.md")],
    ["DUGITE-LICENSE.txt", join(options.gitPackageRoot, "LICENSE")],
    ["EVILCHARTS-LICENSE.txt", join(repositoryRoot, "packages/internal/design-kit/vendor/evilcharts/LICENSE")],
    ["EVILCHARTS-UPSTREAM.md", join(repositoryRoot, "packages/internal/design-kit/vendor/evilcharts/UPSTREAM.md")],
    ["GEIST-MONO-OFL.txt", join(repositoryRoot, "packages/internal/design-kit/src/fonts/geist-mono/OFL.txt")],
    ["GEIST-MONO-PROVENANCE.md", join(repositoryRoot, "packages/internal/design-kit/src/fonts/geist-mono/PROVENANCE.md")],
    ["GEIST-OFL.txt", join(repositoryRoot, "packages/internal/design-kit/src/fonts/geist/OFL.txt")],
    ["GEIST-PROVENANCE.md", join(repositoryRoot, "packages/internal/design-kit/src/fonts/geist/PROVENANCE.md")],
    ["GCM-DEPENDENCY-LICENSES.json", join(macosPackage.desktopRoot, "runtime/GCM-DEPENDENCY-LICENSES.json")],
    ["GCM-DEPENDENCY-LICENSES.txt", join(macosPackage.desktopRoot, "runtime/GCM-DEPENDENCY-LICENSES.txt")],
    ["GIT-COPYING.txt", join(macosPackage.desktopRoot, "runtime/GIT-COPYING.txt")],
    ["GIT-CORRESPONDING-SOURCE.txt", join(macosPackage.desktopRoot, "runtime/GIT-CORRESPONDING-SOURCE.txt")],
    ["GIT-CREDENTIAL-MANAGER-LICENSE.txt", join(macosPackage.desktopRoot, "runtime/GIT-CREDENTIAL-MANAGER-LICENSE.txt")],
    ["GIT-CREDENTIAL-MANAGER-NOTICE.txt", join(options.gitRoot, "libexec/git-core/NOTICE")],
    ["GIT-CREDENTIAL-MANAGER-PROVENANCE.md", join(macosPackage.desktopRoot, "runtime/GIT-CREDENTIAL-MANAGER-PROVENANCE.md")],
    ["GIT-LFS-LICENSE.md", join(macosPackage.desktopRoot, "runtime/GIT-LFS-LICENSE.md")],
    ["GIT-LFS-PROVENANCE.md", join(macosPackage.desktopRoot, "runtime/GIT-LFS-PROVENANCE.md")],
    ["HRANESS-UI-LICENSE.txt", join(macosPackage.desktopRoot, "runtime/HRANESS-UI-LICENSE.txt")],
    ["HRANESS-UI-PROVENANCE.md", join(macosPackage.desktopRoot, "runtime/HRANESS-UI-PROVENANCE.md")],
    ["HRA-LICENSE.txt", join(repositoryRoot, "LICENSE")],
    ["JAVASCRIPT-LICENSE-OVERRIDES.md", join(macosPackage.desktopRoot, "runtime/JAVASCRIPT-LICENSE-OVERRIDES.md")],
    ["JELLY-UI-LICENSE.txt", join(repositoryRoot, "packages/internal/design-kit/vendor/jelly-ui/LICENSE")],
    ["JELLY-UI-UPSTREAM.md", join(repositoryRoot, "packages/internal/design-kit/vendor/jelly-ui/UPSTREAM.md")],
    ["NATIVE-SDK-LICENSE.txt", join(macosPackage.desktopRoot, "node_modules/@native-sdk/cli/LICENSE")],
    ["NOTO-PHOENIX-LICENSE.txt", join(repositoryRoot, "assets/brand/phoenix/LICENSE")],
    ["NOTO-PHOENIX-PROVENANCE.md", join(repositoryRoot, "assets/brand/phoenix/PROVENANCE.md")],
    ["PCRE2-LICENCE.md", join(macosPackage.desktopRoot, "runtime/PCRE2-LICENCE.md")],
    ["RIPGREP-COPYING.txt", join(macosPackage.desktopRoot, "runtime/RIPGREP-COPYING.txt")],
    ["RIPGREP-LICENSE-MIT.txt", join(macosPackage.desktopRoot, "runtime/RIPGREP-LICENSE-MIT.txt")],
    ["RIPGREP-PROVENANCE.md", join(macosPackage.desktopRoot, "runtime/RIPGREP-PROVENANCE.md")],
    ["RIPGREP-UNLICENSE.txt", join(macosPackage.desktopRoot, "runtime/RIPGREP-UNLICENSE.txt")],
    ["ROOT-THIRD-PARTY-NOTICES.md", join(repositoryRoot, "THIRD_PARTY_NOTICES.md")],
    ["RUNTIME-VERSIONS.json", join(macosPackage.desktopRoot, "runtime/runtime-versions.json")],
    ["SPDX-MIT-LICENSE.txt", join(macosPackage.desktopRoot, "runtime/SPDX-MIT-LICENSE.txt")],
    ["embedded-git.json", join(options.gitPackageRoot, "script/embedded-git.json")],
  ]);
  for (const [name, source] of sources) {
    await copyExclusive(source, join(layout.licensesRoot, name));
  }

  const shippedPackages = await createShippedJavaScriptLicenseInventory();
  verifyShippedJavaScriptLicenseInventory(shippedPackages);
  await writeFile(
    join(layout.licensesRoot, "SHIPPED-JAVASCRIPT-LICENSES.json"),
    serializeShippedJavaScriptLicenseInventory(shippedPackages),
    { flag: "wx" },
  );
  await writeFile(
    join(layout.licensesRoot, "SHIPPED-JAVASCRIPT-LICENSES.txt"),
    renderShippedJavaScriptLicenseNotices(shippedPackages),
    { flag: "wx" },
  );
  const actual = (await readdir(layout.licensesRoot)).sort();
  if (JSON.stringify(actual) !== JSON.stringify([...requiredLicenseFileNames])) {
    throw new Error(`Packaged license set differs: ${actual.join(", ")}`);
  }
  return codexNativeInventory;
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
        if (target.startsWith("/")) {
          throw new Error(`Absolute runtime symlink is forbidden: ${relativePath}`);
        }
        const resolvedTarget = resolve(dirname(path), target);
        if (!inside(root, resolvedTarget)) {
          throw new Error(`Runtime symlink escapes its root: ${relativePath}`);
        }
        entries.push({ path: relativePath, target, type: "symlink" });
      } else if (child.isDirectory()) {
        await visit(path);
      } else if (child.isFile()) {
        entries.push({ path: relativePath, sha256: await sha256(path), type: "file" });
      } else {
        throw new Error(`Special runtime file is forbidden: ${relativePath}`);
      }
    }
  }
  await visit(root);
  return entries;
}

async function isMachO(path: string): Promise<boolean> {
  const handle = await open(path, "r");
  const bytes = Buffer.alloc(4);
  try {
    const { bytesRead } = await handle.read(bytes, 0, bytes.length, 0);
    if (bytesRead !== bytes.length) return false;
  } finally {
    await handle.close();
  }
  return new Set([
    "cafebabe",
    "cafebabf",
    "cefaedfe",
    "cffaedfe",
    "feedface",
    "feedfacf",
  ]).has(bytes.toString("hex"));
}

export function parseCodeSignatureDetails(details: string): CodeSignature {
  const value = (pattern: RegExp): string | null =>
    pattern.exec(details)?.[1]?.trim() ?? null;
  const rawTeam = value(/^TeamIdentifier=(.+)$/mu);
  const rawFlags = value(/^CodeDirectory .* flags=0x[0-9a-fA-F]+\(([^)]*)\)/mu);
  const rawHashChoices = value(/^Hash choices=(.+)$/mu);
  const rawInfoPlist = value(/^Info\.plist=(.+)$/mu);
  const rawRequirementsCount = value(/^Internal requirements count=([0-9]+) size=/mu);
  const rawPageSize = value(/^Page size=([0-9]+)$/mu);
  const rawSignature = value(/^Signature=(.+)$/mu);
  const rawSignatureSize = value(/^Signature size=([0-9]+)$/mu);
  const signatureSize = rawSignatureSize === null
    ? null
    : Number(rawSignatureSize);
  return {
    cdHash: value(/^CDHash=([0-9a-fA-F]+)$/mu)?.toLowerCase() ?? null,
    flags: rawFlags === null || rawFlags.length === 0 ? [] : rawFlags.split(","),
    hashChoices: rawHashChoices === null || rawHashChoices.length === 0
      ? []
      : rawHashChoices.split(","),
    hashType: value(/^Hash type=([^ ]+) size=/mu),
    identifier: value(/^Identifier=(.+)$/mu),
    infoPlistBound: rawInfoPlist === null ? null : rawInfoPlist !== "not bound",
    internalRequirementsCount:
      rawRequirementsCount === null ? null : Number(rawRequirementsCount),
    pageSize: rawPageSize === null ? null : Number(rawPageSize),
    runtimeVersion: value(/^Runtime Version=(.+)$/mu),
    sealedResources: value(/^Sealed Resources=(.+)$/mu),
    signatureKind: rawSignature === "adhoc"
      ? "adhoc"
      : rawSignature === null
        && signatureSize !== null
        && Number.isSafeInteger(signatureSize)
        && signatureSize > 0
        && signatureSize <= 64 * 1_024
        ? "cms"
        : null,
    teamIdentifier: rawTeam === "not set" ? null : rawTeam,
    timestamp: value(/^Timestamp=(.+)$/mu),
  };
}

export function codeSignatureHasNoEntitlements(
  result: Readonly<{ stderr: string; stdout: string }>,
  path: string,
): boolean {
  if (path.includes("\n") || path.includes("\r")) return false;
  const lines = `${result.stdout}\n${result.stderr}`
    .split("\n")
    .filter(line => line.length > 0);
  return lines.length === 1 && lines[0] === `Executable=${path}`;
}

export function codeSignatureHasExactRequirement(
  result: Readonly<{ stderr: string; stdout: string }>,
  path: string,
  requirement: string,
): boolean {
  return !path.includes("\n")
    && !path.includes("\r")
    && !requirement.includes("\n")
    && !requirement.includes("\r")
    && result.stderr === `Executable=${path}\n`
    && result.stdout === `${requirement}\n`;
}

function codeSignatureExecutablePath(
  result: Readonly<{ stderr: string; stdout: string }>,
  signedPath: string,
): string | null {
  const values = `${result.stdout}\n${result.stderr}`
    .split("\n")
    .flatMap(line => line.startsWith("Executable=")
      ? [line.slice("Executable=".length)]
      : []);
  const executable = values.length === 1 ? values[0] : undefined;
  if (
    executable === undefined
    || !isAbsolute(executable)
    || resolve(executable) !== executable
    || executable.includes("\r")
  ) return null;
  return executable === signedPath || inside(signedPath, executable)
    ? executable
    : null;
}

type DerElement = Readonly<{
  constructed: boolean;
  end: number;
  tagClass: number;
  tagNumber: number;
  valueStart: number;
}>;

function derElement(bytes: Buffer, offset: number, limit: number): DerElement {
  if (offset < 0 || offset + 2 > limit || limit > bytes.length) {
    throw new Error("CMS DER is truncated.");
  }
  const firstTag = bytes[offset]!;
  const tagClass = firstTag >>> 6;
  const constructed = (firstTag & 0x20) !== 0;
  let tagNumber = firstTag & 0x1f;
  let cursor = offset + 1;
  if (tagNumber === 0x1f) {
    tagNumber = 0;
    let width = 0;
    while (true) {
      if (cursor >= limit || width >= 4) {
        throw new Error("CMS DER tag is invalid.");
      }
      const part = bytes[cursor++]!;
      if (width === 0 && (part & 0x7f) === 0) {
        throw new Error("CMS DER tag is not minimal.");
      }
      tagNumber = (tagNumber * 128) + (part & 0x7f);
      width += 1;
      if ((part & 0x80) === 0) break;
    }
    if (tagNumber < 0x1f) {
      throw new Error("CMS DER tag is not minimal.");
    }
  }
  if (cursor >= limit) throw new Error("CMS DER length is missing.");
  const firstLength = bytes[cursor++]!;
  let length = firstLength;
  if ((firstLength & 0x80) !== 0) {
    const width = firstLength & 0x7f;
    if (width === 0 || width > 4 || cursor + width > limit) {
      throw new Error("CMS DER length is invalid.");
    }
    if (bytes[cursor] === 0) throw new Error("CMS DER length is not minimal.");
    length = 0;
    for (let index = 0; index < width; index += 1) {
      length = (length * 256) + bytes[cursor + index]!;
    }
    if (length < 128) throw new Error("CMS DER length is not minimal.");
    cursor += width;
  }
  const end = cursor + length;
  if (!Number.isSafeInteger(end) || end > limit) {
    throw new Error("CMS DER value is truncated.");
  }
  return { constructed, end, tagClass, tagNumber, valueStart: cursor };
}

export function releaseCmsHasNoTimeAttributes(cms: Buffer): boolean {
  const forbiddenOids = new Set([
    "2a864886f70d010905",
    "2a864886f70d0109100104",
    "2a864886f70d010910020e",
  ]);
  let nodes = 0;
  const inspect = (offset: number, limit: number, depth: number): number => {
    if (depth > 64 || nodes >= 16_384) {
      throw new Error("CMS DER exceeds its structural bound.");
    }
    const element = derElement(cms, offset, limit);
    nodes += 1;
    if (element.tagClass === 0 && element.tagNumber === 6) {
      const oid = cms.subarray(element.valueStart, element.end).toString("hex");
      if (forbiddenOids.has(oid)) {
        throw new Error("CMS contains a forbidden time attribute.");
      }
    }
    if (element.constructed) {
      let child = element.valueStart;
      while (child < element.end) child = inspect(child, element.end, depth + 1);
      if (child !== element.end) throw new Error("CMS DER children differ.");
    }
    return element.end;
  };
  try {
    return cms.length > 0 && inspect(0, cms.length, 0) === cms.length;
  } catch {
    return false;
  }
}

type DerChild = Readonly<{
  element: DerElement;
  start: number;
}>;

function directDerChildren(bytes: Buffer, parent: DerElement): readonly DerChild[] {
  if (!parent.constructed) throw new Error("CMS DER parent is not constructed.");
  const children: DerChild[] = [];
  let cursor = parent.valueStart;
  while (cursor < parent.end) {
    if (children.length >= 64) {
      throw new Error("CMS DER direct-child bound was exceeded.");
    }
    const start = cursor;
    const element = derElement(bytes, start, parent.end);
    children.push({ element, start });
    cursor = element.end;
  }
  if (cursor !== parent.end) throw new Error("CMS DER direct children differ.");
  return children;
}

function hasExactDerTag(
  element: DerElement,
  tagClass: number,
  tagNumber: number,
  constructed: boolean,
): boolean {
  return element.tagClass === tagClass
    && element.tagNumber === tagNumber
    && element.constructed === constructed;
}

export function extractExactReleaseCmsCertificateChain(
  cms: Buffer,
): readonly [Buffer, Buffer] {
  if (!releaseCmsHasNoTimeAttributes(cms)) {
    throw new Error("Release CMS time posture or DER structure differs.");
  }
  const contentInfo = derElement(cms, 0, cms.length);
  if (
    contentInfo.end !== cms.length
    || !hasExactDerTag(contentInfo, 0, 16, true)
  ) throw new Error("Release CMS ContentInfo differs.");
  const contentFields = directDerChildren(cms, contentInfo);
  if (
    contentFields.length !== 2
    || !hasExactDerTag(contentFields[0]!.element, 0, 6, false)
    || cms.subarray(
      contentFields[0]!.element.valueStart,
      contentFields[0]!.element.end,
    ).toString("hex") !== "2a864886f70d010702"
    || !hasExactDerTag(contentFields[1]!.element, 2, 0, true)
  ) throw new Error("Release CMS signed-data wrapper differs.");
  const wrappedFields = directDerChildren(cms, contentFields[1]!.element);
  if (
    wrappedFields.length !== 1
    || !hasExactDerTag(wrappedFields[0]!.element, 0, 16, true)
  ) throw new Error("Release CMS SignedData differs.");
  const signedDataFields = directDerChildren(cms, wrappedFields[0]!.element);
  if (
    signedDataFields.length !== 5
    || !hasExactDerTag(signedDataFields[0]!.element, 0, 2, false)
    || !hasExactDerTag(signedDataFields[1]!.element, 0, 17, true)
    || !hasExactDerTag(signedDataFields[2]!.element, 0, 16, true)
    || !hasExactDerTag(signedDataFields[3]!.element, 2, 0, true)
    || !hasExactDerTag(signedDataFields[4]!.element, 0, 17, true)
  ) throw new Error("Release CMS SignedData field inventory differs.");
  const certificateFields = directDerChildren(
    cms,
    signedDataFields[3]!.element,
  );
  if (
    certificateFields.length !== 2
    || certificateFields.some(({ element }) =>
      !hasExactDerTag(element, 0, 16, true))
  ) throw new Error("Release CMS certificate inventory differs.");
  const certificates = certificateFields.map(({ element, start }) =>
    Buffer.from(cms.subarray(start, element.end))) as [Buffer, Buffer];
  if (Buffer.compare(certificates[0], certificates[1]) >= 0) {
    throw new Error("Release CMS certificate DER order differs.");
  }
  return Object.freeze(certificates);
}

function readUint32LittleEndian(bytes: Buffer, offset: number): number {
  if (offset < 0 || offset + 4 > bytes.length) {
    throw new Error("Release Mach-O is truncated.");
  }
  return bytes.readUInt32LE(offset);
}

function readUint32BigEndian(bytes: Buffer, offset: number): number {
  if (offset < 0 || offset + 4 > bytes.length) {
    throw new Error("Release signature is truncated.");
  }
  return bytes.readUInt32BE(offset);
}

export function extractThinArm64ReleaseCms(executable: Buffer): Buffer {
  if (
    readUint32LittleEndian(executable, 0) !== 0xfeedfacf
    || readUint32LittleEndian(executable, 4) !== 0x0100000c
  ) throw new Error("Release executable is not one thin arm64 Mach-O.");
  const commandCount = readUint32LittleEndian(executable, 16);
  const commandBytes = readUint32LittleEndian(executable, 20);
  if (commandCount > 256 || 32 + commandBytes > executable.length) {
    throw new Error("Release Mach-O load commands are invalid.");
  }
  let cursor = 32;
  let signatureRange: Readonly<{ length: number; offset: number }> | undefined;
  for (let index = 0; index < commandCount; index += 1) {
    const command = readUint32LittleEndian(executable, cursor);
    const size = readUint32LittleEndian(executable, cursor + 4);
    if (size < 8 || size % 4 !== 0 || cursor + size > 32 + commandBytes) {
      throw new Error("Release Mach-O load command is malformed.");
    }
    if (command === 0x1d) {
      if (size !== 16 || signatureRange !== undefined) {
        throw new Error("Release Mach-O code-signature command differs.");
      }
      signatureRange = {
        length: readUint32LittleEndian(executable, cursor + 12),
        offset: readUint32LittleEndian(executable, cursor + 8),
      };
    }
    cursor += size;
  }
  if (
    cursor !== 32 + commandBytes
    || signatureRange === undefined
    || signatureRange.length < 12
    || signatureRange.offset < cursor
    || signatureRange.offset + signatureRange.length > executable.length
  ) throw new Error("Release Mach-O code-signature range is invalid.");
  const signature = executable.subarray(
    signatureRange.offset,
    signatureRange.offset + signatureRange.length,
  );
  if (readUint32BigEndian(signature, 0) !== 0xfade0cc0) {
    throw new Error("Release signature SuperBlob is invalid.");
  }
  const length = readUint32BigEndian(signature, 4);
  const slots = readUint32BigEndian(signature, 8);
  if (length > signature.length || slots > 64 || 12 + slots * 8 > length) {
    throw new Error("Release signature index is invalid.");
  }
  let cms: Buffer | undefined;
  for (let index = 0; index < slots; index += 1) {
    const type = readUint32BigEndian(signature, 12 + index * 8);
    const offset = readUint32BigEndian(signature, 16 + index * 8);
    if (offset < 12 + slots * 8 || offset + 8 > length) {
      throw new Error("Release signature slot is invalid.");
    }
    const blobLength = readUint32BigEndian(signature, offset + 4);
    if (blobLength < 8 || offset + blobLength > length) {
      throw new Error("Release signature blob is invalid.");
    }
    if (type === 0x10000) {
      if (cms !== undefined || readUint32BigEndian(signature, offset) !== 0xfade0b01) {
        throw new Error("Release CMS slot differs.");
      }
      cms = signature.subarray(offset + 8, offset + blobLength);
    }
  }
  if (cms === undefined || !releaseCmsHasNoTimeAttributes(cms)) {
    throw new Error("Release CMS time posture differs.");
  }
  return cms;
}

export async function verifyReleaseCmsHasNoTime(
  display: CommandResult,
  signedPath: string,
): Promise<Readonly<{ cms: Buffer; executable: string }>> {
  const executable = codeSignatureExecutablePath(display, signedPath);
  if (executable === null || await realpath(executable) !== executable) {
    throw new Error(`Release signature executable differs: ${signedPath}`);
  }
  const cms = extractThinArm64ReleaseCms(await readFile(executable));
  return Object.freeze({ cms, executable });
}

async function codeSignature(path: string): Promise<CodeSignature> {
  const result = await run([
    "/usr/bin/codesign",
    "--display",
    "--verbose=4",
    path,
  ], { allowFailure: true });
  return parseCodeSignatureDetails(`${result.stdout}\n${result.stderr}`);
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

async function signAdHoc(
  path: string,
  options: Readonly<{ entitlements?: string; identifier?: string }> = {},
): Promise<void> {
  await run([
    "/usr/bin/codesign",
    "--force",
    "--sign",
    "-",
    "--options",
    "runtime",
    ...(options.identifier === undefined
      ? []
      : ["--identifier", options.identifier]),
    ...(options.entitlements === undefined
      ? []
      : ["--entitlements", options.entitlements]),
    path,
  ]);
}

export type ProductionSigningUsabilityProbe = Readonly<{
  dispose: () => Promise<void>;
  path: string;
}>;

export type ProductionSigningUsabilityDependencies = Readonly<{
  createDisposableMachO: () => Promise<ProductionSigningUsabilityProbe>;
  signAndVerify: (
    path: string,
    identifier: string,
    context: PackageSigningContext,
  ) => Promise<void>;
}>;

async function createDisposableProductionSigningMachO(): Promise<
  ProductionSigningUsabilityProbe
> {
  const directory = await mkdtemp(join(
    macosPackage.desktopRoot,
    "zig-out/.release-signing-preflight-",
  ));
  const path = join(directory, "hra-release-signing-usability-probe");
  try {
    const extracted = await runSigningCommand([
      "/usr/bin/lipo",
      "/usr/bin/true",
      "-thin",
      "arm64e",
      "-output",
      path,
    ]);
    if (extracted.stdout !== "" || extracted.stderr !== "") {
      throw new Error("The disposable release-signing probe extraction was noisy.");
    }
    await chmod(path, 0o700);
    if (!await isMachO(path)) {
      throw new Error("The disposable release-signing probe is not Mach-O code.");
    }
    return Object.freeze({
      dispose: async () => {
        await rm(directory, { force: true, recursive: true });
      },
      path,
    });
  } catch (error: unknown) {
    await rm(directory, { force: true, recursive: true });
    throw error;
  }
}

const productionSigningUsabilityDependencies = Object.freeze({
  createDisposableMachO: createDisposableProductionSigningMachO,
  signAndVerify: signReleaseCode,
}) satisfies ProductionSigningUsabilityDependencies;

export async function verifyProductionSigningUsability(
  context: PackageSigningContext,
  dependencies: ProductionSigningUsabilityDependencies =
    productionSigningUsabilityDependencies,
): Promise<void> {
  let failed = false;
  let probe: ProductionSigningUsabilityProbe | undefined;
  try {
    probe = await dependencies.createDisposableMachO();
    await dependencies.signAndVerify(
      probe.path,
      productionSigningUsabilityIdentifier,
      context,
    );
  } catch {
    failed = true;
  } finally {
    if (probe !== undefined) {
      try {
        await probe.dispose();
      } catch {
        failed = true;
      }
    }
  }
  if (failed) {
    throw new Error(
      "Production release signing usability preflight failed without exposing signing-custody paths or output.",
    );
  }
}

async function resolveProductionSigningContext(
  keychain: string,
  control: ProductionSigningKeychainControl,
): Promise<PackageSigningContext> {
  const authority = await loadProductionReleaseAuthority();
  const inventory = await runSigningCommand([
    "/usr/bin/security",
    "find-certificate",
    "-a",
    "-p",
    keychain,
  ]);
  const certificates = [...inventory.stdout.matchAll(
    /-----BEGIN CERTIFICATE-----\n([A-Za-z0-9+/=\n]+)-----END CERTIFICATE-----/gu,
  )].map(match => Buffer.from(match[1]!.replaceAll("\n", ""), "base64"));
  const certificateHashes = certificates.map(certificate =>
    createHash("sha256").update(certificate).digest("hex"));
  if (
    certificates.length !== 2
    || new Set(certificateHashes).size !== 2
    || !certificates.some(certificate => certificate.equals(authority.leaf.der))
    || !certificates.some(certificate => certificate.equals(authority.root.der))
  ) {
    throw new Error(
      "The operator-supplied keychain does not contain exactly the production release leaf and root certificates.",
    );
  }
  const context: PackageSigningContext = Object.freeze({
    authority,
    designatedRequirement: releaseDesignatedRequirement,
    identity: productionReleaseAuthorityPins.leafSha1,
    keychain,
    label: "production",
    manifestSigning: productionReleaseSigning,
    sign: (path, identifier) => signWithProductionKeychain(
      control,
      keychain,
      authority,
      path,
      identifier,
    ),
  });
  await verifyProductionSigningUsability(context);
  return context;
}

export async function withProductionSigningContext<T>(
  operation: (context: PackageSigningContext) => Promise<T>,
): Promise<T> {
  const keychain = await productionSigningKeychainPath();
  const control = await productionSigningKeychainControl();
  let result: T | undefined;
  let operationError: unknown;
  try {
    result = await operation(await resolveProductionSigningContext(
      keychain,
      control,
    ));
  } catch (error: unknown) {
    operationError = error;
  }
  let cleanupError: Error | undefined;
  try {
    await controlProductionSigningKeychain(control, keychain);
  } catch {
    cleanupError = new Error(
      "Production signing Keychain lock failed without exposing custody paths or command output.",
    );
  }
  try {
    await control.dispose();
  } catch {
    cleanupError ??= new Error(
      "Production signing Keychain control-helper cleanup failed.",
    );
  }
  if (cleanupError !== undefined) throw cleanupError;
  if (operationError !== undefined) {
    throw operationError instanceof Error
      ? operationError
      : new Error("Production signing operation failed.");
  }
  return result as T;
}

function verifyExtractedReleaseCertificates(
  cms: Buffer,
  authority: ReleaseSigningAuthority,
): void {
  const [leaf, root] = extractExactReleaseCmsCertificateChain(cms);
  if (
    !leaf.equals(authority.leaf.der)
    || !root.equals(authority.root.der)
    || createHash("sha1").update(leaf).digest("hex")
      !== authority.leaf.sha1
    || createHash("sha256").update(leaf).digest("hex")
      !== authority.leaf.sha256
    || createHash("sha1").update(root).digest("hex")
      !== authority.root.sha1
    || createHash("sha256").update(root).digest("hex")
      !== authority.root.sha256
  ) {
    throw new Error("Embedded production release certificates differ.");
  }
}

export async function signReleaseCode(
  path: string,
  identifier: string,
  context: PackageSigningContext,
): Promise<void> {
  const requirement = context.designatedRequirement(identifier);
  await context.sign(path, identifier);
  const [display, designated, entitlements, strictVerification] =
    await Promise.all([
      runSigningCommand([
        "/usr/bin/codesign",
        "--display",
        "--verbose=4",
        path,
      ]),
      runSigningCommand([
        "/usr/bin/codesign",
        "--display",
        "--requirements",
        "-",
        path,
      ]),
      runSigningCommand([
        "/usr/bin/codesign",
        "--display",
        "--entitlements",
        "-",
        path,
      ]),
      runSigningCommand([
        "/usr/bin/codesign",
        "--verify",
        "--all-architectures",
        "--strict",
        "--verbose=6",
        path,
      ], [0, 1]),
    ]);
  assertReleaseStrictVerification(path, strictVerification);
  const signature = parseCodeSignatureDetails(
    `${display.stdout}\n${display.stderr}`,
  );
  const { cms, executable } = await verifyReleaseCmsHasNoTime(display, path);
  if (
    signature.identifier !== identifier
    || signature.teamIdentifier !== null
    || signature.signatureKind !== "cms"
    || signature.pageSize !== 16_384
    || signature.timestamp !== null
    || signature.hashType !== "sha256"
    || signature.hashChoices.length !== 1
    || signature.hashChoices[0] !== "sha256"
    || signature.flags.length !== 1
    || signature.flags[0] !== "runtime"
    || !codeSignatureHasExactRequirement(designated, executable, requirement)
    || !codeSignatureHasNoEntitlements(entitlements, executable)
  ) {
    throw new Error(`${context.label} release signature posture differs: ${path}`);
  }
  verifyExtractedReleaseCertificates(cms, context.authority);
}

async function normalizeCodexSignatures(
  layout: PackageLayout,
  inventory: CodexNativeLicenseInventory,
  sourceVendorRoot: string,
): Promise<ReturnType<typeof codexSignatureNormalizationManifestEntries>> {
  verifyCodexSignatureNormalizationInventory(inventory);
  const entitlementsPath = join(
    import.meta.dir,
    CODEX_SIGNATURE_NORMALIZATION_ENTITLEMENTS_FILE,
  );
  const entitlementsStatus = await lstat(entitlementsPath);
  if (
    !entitlementsStatus.isFile()
    || entitlementsStatus.isSymbolicLink()
    || entitlementsStatus.nlink !== 1
    || await sha256(entitlementsPath)
      !== codexSignatureNormalizationSigning.entitlementsSha256
  ) {
    throw new Error("Codex signature normalization entitlements differ from policy.");
  }
  for (const entry of codexSignatureNormalizationPolicy.entries) {
    const path = join(layout.runtimeRoot, "codex", entry.payloadPath);
    const status = await lstat(path);
    if (!status.isFile() || status.isSymbolicLink() || status.nlink !== 1) {
      throw new Error(
        `Codex normalization source must be a regular single-link file: ${entry.payloadPath}`,
      );
    }
    verifyCodexSignatureNormalizationSource(entry, {
      sha256: await sha256(path),
      signature: await codeSignature(path),
      size: status.size,
    });
    const sourceStrict = await run([
      "/usr/bin/codesign",
      "--verify",
      "--strict",
      "--verbose=6",
      path,
    ], { allowFailure: true });
    process.stdout.write(
      `Codex source signature ${entry.payloadPath}: strict ${sourceStrict.exitCode === 0 ? "accepted" : "rejected"}; applying reviewed deterministic normalization.\n`,
    );
    await run(codexSignatureNormalizationCodesignArguments(
      entry,
      entitlementsPath,
      path,
    ));
    const packagedStatus = await lstat(path);
    verifyCodexSignatureNormalizationPackaged(entry, {
      sha256: await sha256(path),
      signature: {
        ...await codeSignature(path),
        entitlements: await codeSignatureEntitlements(path),
      },
      size: packagedStatus.size,
    });
    const sourcePath = join(sourceVendorRoot, entry.payloadPath);
    await verifyCodexSignatureNormalizationContent(sourcePath, path);
    await run([
      "/usr/bin/codesign",
      "--verify",
      "--strict",
      "--verbose=6",
      path,
    ]);
    const delta = await createCodexSignatureSourceDelta(
      sourcePath,
      path,
    );
    const deltaSha256 = createHash("sha256").update(delta).digest("hex");
    if (
      delta.byteLength !== entry.sourceDelta.size
      || deltaSha256 !== entry.sourceDelta.sha256
    ) {
      throw new Error(`Codex signature source delta differs: ${entry.payloadPath}`);
    }
    const deltaPath = resolve(layout.appRoot, entry.sourceDelta.path);
    if (!inside(layout.appRoot, deltaPath)) {
      throw new Error(`Codex signature source delta escaped the app: ${entry.payloadPath}`);
    }
    await mkdir(dirname(deltaPath), { recursive: true, mode: 0o755 });
    await writeFile(deltaPath, delta, { flag: "wx", mode: 0o644 });
  }
  return codexSignatureNormalizationManifestEntries();
}

async function signRuntimeTree(
  layout: PackageLayout,
  preserveExactSignedPaths: ReadonlySet<string>,
): Promise<ReadonlyArray<Readonly<{
  path: string;
  teamIdentifier: string;
}>>> {
  const preserved: Array<Readonly<{ path: string; teamIdentifier: string }>> = [];
  const ownedPaths = new Set(layout.ownedCode.map((entry) => entry.path));
  const files = (await walkTree(layout.runtimeRoot))
    .filter((entry) => entry.type === "file" && entry.path !== "manifest.json")
    .map((entry) => join(layout.runtimeRoot, entry.path));
  const machOFiles: string[] = [];
  for (const path of files) {
    if (await isMachO(path)) machOFiles.push(path);
  }
  machOFiles.sort((left, right) => right.split(sep).length - left.split(sep).length || left.localeCompare(right));
  for (const path of machOFiles) {
    if (ownedPaths.has(path)) continue;
    const signature = await codeSignature(path);
    if (preserveExactSignedPaths.has(path)) {
      if (
        signature.identifier === null
        || !/^[0-9a-f]{40,64}$/u.test(signature.cdHash ?? "")
      ) {
        throw new Error(`Exact Codex payload lacks a valid signature: ${path}`);
      }
      await run(["/usr/bin/codesign", "--verify", "--strict", path]);
      if (signature.teamIdentifier !== null) {
        if (!trustedThirdPartyTeams.has(signature.teamIdentifier)) {
          throw new Error(
            `Unexpected third-party signing team ${signature.teamIdentifier}: ${path}`,
          );
        }
        preserved.push({
          path: relative(layout.appRoot, path).split(sep).join("/"),
          teamIdentifier: signature.teamIdentifier,
        });
      }
      continue;
    }
    if (signature.teamIdentifier !== null) {
      if (!trustedThirdPartyTeams.has(signature.teamIdentifier)) {
        throw new Error(
          `Unexpected third-party signing team ${signature.teamIdentifier}: ${path}`,
        );
      }
      await run(["/usr/bin/codesign", "--verify", "--strict", path]);
      preserved.push({
        path: relative(layout.appRoot, path).split(sep).join("/"),
        teamIdentifier: signature.teamIdentifier,
      });
      continue;
    }
    await signAdHoc(path);
  }
  for (const entry of layout.ownedCode) {
    if (
      entry.identifier === "oprte-keychain-custodian"
      || entry.identifier === custodyProbeSupervisorPackageContract.identifier
      || entry.identifier === macosPackage.bundleIdentifier
    ) {
      continue;
    }
    await signAdHoc(entry.path, entry);
  }
  return preserved.sort((left, right) => left.path.localeCompare(right.path));
}

export async function packageMacOS(
  signingContext: PackageSigningContext,
  options: Readonly<{
    appRoot?: string;
    packageRoot?: string;
  }> = {},
): Promise<void> {
  if (process.platform !== "darwin" || process.arch !== "arm64") {
    throw new Error("HRA macOS packaging requires Apple Silicon macOS.");
  }
  const appRoot = resolve(options.appRoot ?? macosPackage.appBundlePath);
  const layout = packageLayout(appRoot);
  const {
    binRoot,
    licensesRoot,
    resourcesRoot,
    runtimeRoot,
  } = layout;
  const sourceRepository = await inspectReleaseSourceRepository();
  await requireRealDirectory(appRoot);
  const canonicalPackageRoot = await realpath(options.packageRoot ??
    join(macosPackage.desktopRoot, "zig-out/package"));
  const canonicalAppRoot = await realpath(appRoot);
  if (!inside(canonicalPackageRoot, canonicalAppRoot) || !canonicalAppRoot.endsWith(".app")) {
    throw new Error("Refusing to mutate an app outside the exact package root.");
  }
  await verifyPackagedFrontend({
    packageDirectory: join(resourcesRoot, "frontend/dist"),
    sourceDirectory: join(macosPackage.desktopRoot, "frontend/dist"),
  });

  const pins = await verifyRuntimePins();
  const sourceGatewayPath = join(
    macosPackage.desktopRoot,
    "runtime/dist/oprte-gateway",
  );
  const sourceGatewaySha256 = await exactGatewayFileSha256(sourceGatewayPath);
  await rm(runtimeRoot, { force: true, recursive: true });
  await mkdir(binRoot, { recursive: true, mode: 0o755 });
  await mkdir(licensesRoot, { recursive: true, mode: 0o755 });
  await Promise.all([
    copyExclusive(
      join(macosPackage.desktopRoot, imageNormalizerPackageContract.sourceRelativePath),
      join(runtimeRoot, imageNormalizerPackageContract.runtimeRelativePath),
    ),
    copyExclusive(sourceGatewayPath, join(binRoot, "oprte-gateway")),
    copyExclusive(join(macosPackage.desktopRoot, "zig-out/bin/oprte-data-remover"), join(binRoot, "oprte-data-remover")),
    copyExclusive(join(macosPackage.desktopRoot, "zig-out/bin/oprte-git-executor"), join(binRoot, "oprte-git-executor")),
    copyExclusive(join(macosPackage.desktopRoot, "zig-out/bin/oprte-keychain-custodian"), join(binRoot, "oprte-keychain-custodian")),
    copyExclusive(
      join(
        macosPackage.desktopRoot,
        custodyProbeSupervisorPackageContract.sourceRelativePath,
      ),
      join(
        runtimeRoot,
        custodyProbeSupervisorPackageContract.runtimeRelativePath,
      ),
    ),
    cp(pins.codexVendorRoot, join(runtimeRoot, "codex"), {
      force: false,
      recursive: true,
      verbatimSymlinks: true,
    }),
    cp(pins.gitRoot, join(runtimeRoot, "git"), {
      force: false,
      recursive: true,
      verbatimSymlinks: true,
    }),
  ]);
  await Promise.all(layout.ownedCode
    .filter((entry) => dirname(entry.path) === binRoot)
    .map((entry) => chmod(entry.path, 0o755)));
  const codexNativeInventory = await stageLicenseFiles(layout, {
    codexPackageRoot: pins.codexPackageRoot,
    codexPlatformPackageJson: pins.codexPlatformPackageJson,
    gitPackageRoot: pins.gitPackageRoot,
    gitRoot: pins.gitRoot,
  });

  await setPlist(layout, "CFBundleExecutable", "string", macosPackage.executableName);
  await setPlist(layout, "CFBundleIdentifier", "string", macosPackage.bundleIdentifier);
  await setPlist(layout, "CFBundleName", "string", macosPackage.productName);
  await setPlist(layout, "CFBundleDisplayName", "string", macosPackage.displayName);
  await setPlist(layout, "CFBundleShortVersionString", "string", macosPackage.version);
  await setPlist(layout, "CFBundleVersion", "string", String(macosPackage.build));
  await setPlist(layout, "LSMinimumSystemVersion", "string", macosPackage.minimumMacOS);
  for (const key of [
    "SUAllowsAutomaticUpdates",
    "SUAutomaticallyUpdate",
    "SUEnableAutomaticChecks",
    "SUFeedURL",
    "SUPublicEDKey",
    "SURequireSignedFeed",
    "SUSignedFeedFailureExpirationInterval",
    "SUVerifyUpdateBeforeExtraction",
  ]) {
    await removePlistKey(layout, key);
  }

  const packagedGatewayPath = join(binRoot, "oprte-gateway");
  if (await exactGatewayFileSha256(packagedGatewayPath) !== sourceGatewaySha256) {
    throw new Error("The packaged gateway differs from the final signed build authority.");
  }
  const exactCodexPayloadPaths = new Set(
    codexNativeInventory.platformPackage.payloads.map((payload) =>
      join(runtimeRoot, "codex", payload.path)),
  );
  exactCodexPayloadPaths.add(packagedGatewayPath);
  const normalizedSignatures = await normalizeCodexSignatures(
    layout,
    codexNativeInventory,
    pins.codexVendorRoot,
  );
  const preservedSignatures = await signRuntimeTree(
    layout,
    exactCodexPayloadPaths,
  );
  if (await exactGatewayFileSha256(packagedGatewayPath) !== sourceGatewaySha256) {
    throw new Error("Packaging mutated the exact signed gateway authority.");
  }
  const gatewaySignature = await codeSignature(packagedGatewayPath);
  if (
    gatewaySignature.identifier !== "oprte-gateway"
    || gatewaySignature.teamIdentifier !== null
    || gatewaySignature.signatureKind !== "adhoc"
    || gatewaySignature.pageSize !== 16_384
    || gatewaySignature.timestamp !== null
    || !gatewaySignature.flags.includes("runtime")
  ) {
    throw new Error("The preserved gateway signature posture differs from policy.");
  }
  const gatewayEntitlementValues = await codeSignatureEntitlements(
    packagedGatewayPath,
  );
  if (
    Object.keys(gatewayEntitlementValues).length !== 1
    || gatewayEntitlementValues[
      "com.apple.security.cs.allow-unsigned-executable-memory"
    ] !== true
  ) {
    throw new Error("The preserved gateway entitlements differ from policy.");
  }
  const keychainCustodianPath = join(binRoot, "oprte-keychain-custodian");
  await signReleaseCode(
    keychainCustodianPath,
    "oprte-keychain-custodian",
    signingContext,
  );
  const custodyProbeSupervisorPath = join(
    runtimeRoot,
    custodyProbeSupervisorPackageContract.runtimeRelativePath,
  );
  await signReleaseCode(
    custodyProbeSupervisorPath,
    custodyProbeSupervisorPackageContract.identifier,
    signingContext,
  );
  const custodyProbeSupervisorSignature = await codeSignature(
    custodyProbeSupervisorPath,
  );
  if (!/^[0-9a-f]{40}$/u.test(custodyProbeSupervisorSignature.cdHash ?? "")) {
    throw new Error("The custody probe supervisor has no valid CodeDirectory hash.");
  }
  const dataRemoverSignature = await codeSignature(join(binRoot, "oprte-data-remover"));
  if (!/^[0-9a-f]{40,64}$/u.test(dataRemoverSignature.cdHash ?? "")) {
    throw new Error("The data remover has no valid CodeDirectory hash.");
  }
  await setPlist(
    layout,
    "KitchenExpectedDataRemoverCDHashV1",
    "string",
    dataRemoverSignature.cdHash!,
  );
  const imageNormalizerSignature = await codeSignature(
    join(runtimeRoot, imageNormalizerPackageContract.runtimeRelativePath),
  );
  if (!/^[0-9a-f]{40,64}$/u.test(imageNormalizerSignature.cdHash ?? "")) {
    throw new Error("The image normalizer has no valid CodeDirectory hash.");
  }

  const runtimeTree = (await walkTree(runtimeRoot))
    .filter((entry) => entry.path !== "manifest.json");
  const runtimeTreeSha256 = createHash("sha256")
    .update(`${JSON.stringify(runtimeTree)}\n`, "utf8")
    .digest("hex");
  const manifest = {
    schemaVersion: 1,
    release: {
      architecture: macosPackage.architecture,
      build: macosPackage.build,
      commit: sourceRepository.commit,
      minimumMacOS: macosPackage.minimumMacOS,
      signing: signingContext.manifestSigning,
      version: macosPackage.version,
    },
    runtime: {
      codex: {
        binarySha256: await sha256(join(runtimeRoot, "codex/bin/codex")),
        dependencyLicenseInventorySha256:
          runtimeVersions.codex.dependencyLicenseInventorySha256,
        dependencyLicenseNoticesSha256:
          runtimeVersions.codex.dependencyLicenseNoticesSha256,
        sourceBinarySha256:
          codexSignatureNormalizationEntry("bin/codex").source.sha256,
        sourceCommit: runtimeVersions.codex.sourceCommit,
        version: runtimeVersions.codex.version,
      },
      custodyProbeSupervisor: {
        architecture: macosPackage.architecture,
        cdHash: custodyProbeSupervisorSignature.cdHash,
        codeDirectoryFlags: ["runtime"],
        designatedRequirement: signingContext.designatedRequirement(
          custodyProbeSupervisorPackageContract.identifier,
        ),
        entitlements: {},
        identifier: custodyProbeSupervisorPackageContract.identifier,
        pageSize: 16_384,
        runtimeRelativePath:
          custodyProbeSupervisorPackageContract.runtimeRelativePath,
        sha256: await sha256(custodyProbeSupervisorPath),
        signing: signingContext.manifestSigning,
        timestamp: null,
      },
      dataRemover: {
        cdHash: dataRemoverSignature.cdHash,
        sha256: await sha256(join(binRoot, "oprte-data-remover")),
      },
      gateway: {
        bunVersion: pins.bunCompiler.version,
        compilerBinarySha256: pins.bunCompiler.binarySha256,
        compilerReleaseAssetSha256: runtimeVersions.bun.releaseAssetSha256,
        compilerSourceCommit: runtimeVersions.bun.sourceCommit,
        completeSourceArchiveSha256: runtimeVersions.bun.completeSourceArchiveSha256,
        dependencyLicenseInventorySha256:
          runtimeVersions.bun.dependencyLicenseInventorySha256,
        dependencyLicenseNoticesSha256:
          runtimeVersions.bun.dependencyLicenseNoticesSha256,
        sha256: await sha256(join(binRoot, "oprte-gateway")),
      },
      git: {
        assetSha256: runtimeVersions.git.assetSha256,
        binarySha256: await sha256(join(runtimeRoot, "git/bin/git")),
        version: runtimeVersions.git.version,
      },
      gitCredentialManager: {
        binarySha256: await sha256(
          join(runtimeRoot, "git/libexec/git-core/git-credential-manager"),
        ),
        licenseSha256: runtimeVersions.gitCredentialManager.licenseSha256,
        noticeSha256: runtimeVersions.gitCredentialManager.noticeSha256,
        depsJsonSha256: runtimeVersions.gitCredentialManager.depsJsonSha256,
        dependencyLicenseInventorySha256:
          runtimeVersions.gitCredentialManager.dependencyLicenseInventorySha256,
        dependencyLicenseNoticesSha256:
          runtimeVersions.gitCredentialManager.dependencyLicenseNoticesSha256,
        dotnetRuntimeSourceCommit:
          runtimeVersions.gitCredentialManager.dotnetRuntimeSourceCommit,
        dotnetRuntimeVersion: runtimeVersions.gitCredentialManager.dotnetRuntimeVersion,
        runtimeConfigSha256: runtimeVersions.gitCredentialManager.runtimeConfigSha256,
        sourceCommit: runtimeVersions.gitCredentialManager.sourceCommit,
        version: runtimeVersions.gitCredentialManager.version,
      },
      gitExecutor: {
        sha256: await sha256(join(binRoot, "oprte-git-executor")),
      },
      imageNormalizer: {
        cdHash: imageNormalizerSignature.cdHash,
        sha256: await sha256(
          join(runtimeRoot, imageNormalizerPackageContract.runtimeRelativePath),
        ),
      },
      keychainCustodian: {
        sha256: await sha256(join(binRoot, "oprte-keychain-custodian")),
      },
      gitLfs: {
        binarySha256: await sha256(join(runtimeRoot, "git/libexec/git-core/git-lfs")),
        licenseSha256: runtimeVersions.gitLfs.licenseSha256,
        sourceCommit: runtimeVersions.gitLfs.sourceCommit,
        version: runtimeVersions.gitLfs.version,
      },
      normalizedSignatures,
      preservedSignatures,
      ripgrep: {
        binarySha256: await sha256(join(runtimeRoot, "codex/codex-path/rg")),
        pcre2LicenseSha256: runtimeVersions.ripgrep.pcre2.licenseSha256,
        sourceCommit: runtimeVersions.ripgrep.sourceCommit,
        version: runtimeVersions.ripgrep.version,
      },
      treeSha256: runtimeTreeSha256,
    },
  } as const;
  await writeFile(
    join(runtimeRoot, "manifest.json"),
    `${JSON.stringify(manifest, null, 2)}\n`,
    { flag: "wx" },
  );

  await signReleaseCode(
    appRoot,
    macosPackage.bundleIdentifier,
    signingContext,
  );
  await run([
    "/usr/bin/codesign",
    "--verify",
    "--deep",
    "--strict",
    "--verbose=4",
    appRoot,
  ]);
  process.stdout.write(`${appRoot}\n`);
}

async function main(): Promise<void> {
  if (
    process.argv.length !== 4
    || process.argv[2] !== "--signing"
    || process.argv[3] !== "production"
  ) {
    throw new Error(
      "Usage: package-macos.ts --signing production. Structural CI packaging uses a separate nonrelease entry point.",
    );
  }
  await withProductionSigningContext(context => packageMacOS(context));
}

if (import.meta.main) await main();
