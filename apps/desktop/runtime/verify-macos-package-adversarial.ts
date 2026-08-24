import { createHash } from "node:crypto";
import {
  chmod,
  copyFile,
  cp,
  lstat,
  mkdtemp,
  open,
  readFile,
  readlink,
  readdir,
  realpath,
  rm,
  writeFile,
} from "node:fs/promises";
import { tmpdir } from "node:os";
import { join, relative, resolve, sep } from "node:path";

import { macosPackage } from "./macos-package-config";
import { runMacOSCustodyProbe } from "./macos-custody-probe";
import {
  authorizeResidentCustodyCandidate,
} from "./resident-custody-probe-adapter";
import type {
  CustodyProbeSupervisorAuthorityEvidence,
} from "./custody-probe-supervisor-authority";
import {
  signReleaseCode,
  type PackageSigningContext,
  withProductionSigningContext,
} from "./package-macos";
import {
  packagedRendererAuthorityEntries,
  rendererAuthorityRoot,
} from "./renderer-authority";
import { withStructuralSigningFixture } from "./structural-release-signing";
import {
  verifyExactAdHocGatewayPosture,
  verifyMacOSApp,
} from "./verify-macos-package";

type CommandResult = Readonly<{
  exitCode: number;
  stderr: string;
  stdout: string;
}>;

type AuthoritySnapshot = Readonly<{
  gateway: string;
  helper: string;
  host: string;
  manifest: string;
  renderer: string;
}>;

type AdversarialSigningContexts = Readonly<{
  attacker: PackageSigningContext;
  production: PackageSigningContext;
}>;

type FixtureMutation = Readonly<{
  attacker: PackageSigningContext;
  appRoot: string;
  production: PackageSigningContext;
}>;

type TreeEntry = Readonly<{
  mode: number;
  path: string;
  sha256?: string;
  target?: string;
  type: "directory" | "file" | "symlink";
}>;

const maximumCommandOutputBytes = 64 * 1024;

function commandEnvironment(): Readonly<Record<string, string>> {
  const environment: Record<string, string> = {
    LANG: "C",
    LC_ALL: "C",
    PATH: "/usr/bin:/bin",
  };
  for (const name of ["HOME", "LOGNAME", "TMPDIR", "USER"] as const) {
    const value = process.env[name];
    if (value !== undefined && value.length > 0 && !value.includes("\0")) {
      environment[name] = value;
    }
  }
  return environment;
}

export function escapeExtendedRegularExpression(value: string): string {
  return value.replace(/[.*+?^${}()|[\]\\]/gu, "\\$&");
}

async function run(
  argv: readonly string[],
  label: string,
  acceptedExitCodes: readonly number[] = [0],
): Promise<CommandResult> {
  const child = Bun.spawn([...argv], {
    cwd: macosPackage.desktopRoot,
    env: commandEnvironment(),
    stderr: "pipe",
    stdout: "pipe",
  });
  const [stdoutBytes, stderrBytes, exitCode] = await Promise.all([
    new Response(child.stdout).arrayBuffer(),
    new Response(child.stderr).arrayBuffer(),
    child.exited,
  ]);
  if (
    stdoutBytes.byteLength > maximumCommandOutputBytes
    || stderrBytes.byteLength > maximumCommandOutputBytes
  ) {
    throw new Error(`${label} exceeded its bounded output allowance.`);
  }
  const stdout = Buffer.from(stdoutBytes).toString("utf8");
  const stderr = Buffer.from(stderrBytes).toString("utf8");
  if (!acceptedExitCodes.includes(exitCode)) {
    throw new Error(`${label} failed without exposing fixture paths or output.`);
  }
  return Object.freeze({ exitCode, stderr, stdout });
}

async function sha256(path: string): Promise<string> {
  const descriptor = await open(path, "r");
  const hasher = createHash("sha256");
  try {
    for await (const chunk of descriptor.readableWebStream()) {
      hasher.update(chunk as Uint8Array);
    }
  } finally {
    await descriptor.close();
  }
  return hasher.digest("hex");
}

export async function mutateRendererIndexFixture(
  rendererRoot: string,
): Promise<void> {
  const indexPath = join(rendererRoot, "index.html");
  const manifestPath = join(rendererRoot, "asset-manifest.zon");
  const original = await readFile(indexPath);
  const mutated = Buffer.concat([
    original,
    Buffer.from("\n<!-- adversarial renderer -->\n", "utf8"),
  ]);
  const rowPrefix =
    '  .{ .id = "index.html", .bundle_path = "index.html", ' +
    '.source_path = "frontend/dist/index.html", .byte_len = ';
  const originalRow =
    `${rowPrefix}${original.byteLength}, .hash = "` +
    `${createHash("sha256").update(original).digest("hex")}" },`;
  const mutatedRow =
    `${rowPrefix}${mutated.byteLength}, .hash = "` +
    `${createHash("sha256").update(mutated).digest("hex")}" },`;
  const manifest = await readFile(manifestPath, "utf8");
  if (manifest.split(originalRow).length !== 2) {
    throw new Error("Renderer-only fixture manifest is not exact before mutation.");
  }
  await writeFile(indexPath, mutated);
  await writeFile(manifestPath, manifest.replace(originalRow, mutatedRow));
}

async function packageTreeAuthority(root: string): Promise<readonly TreeEntry[]> {
  const entries: TreeEntry[] = [];
  const visit = async (directory: string): Promise<void> => {
    const children = await readdir(directory, { withFileTypes: true });
    children.sort((left, right) => left.name.localeCompare(right.name));
    for (const child of children) {
      const absolute = join(directory, child.name);
      const path = relative(root, absolute).split(sep).join("/");
      const status = await lstat(absolute);
      const mode = status.mode & 0o7777;
      if (status.isSymbolicLink()) {
        entries.push({ mode, path, target: await readlink(absolute), type: "symlink" });
      } else if (status.isDirectory()) {
        entries.push({ mode, path, type: "directory" });
        await visit(absolute);
      } else if (status.isFile() && status.nlink === 1) {
        entries.push({ mode, path, sha256: await sha256(absolute), type: "file" });
      } else {
        throw new Error(`Adversarial package tree has an unsafe entry: ${path}`);
      }
    }
  };
  await visit(root);
  return Object.freeze(entries);
}

function changedTreePaths(
  baseline: readonly TreeEntry[],
  candidate: readonly TreeEntry[],
): readonly string[] {
  const baselineEntries = new Map(baseline.map(entry => [entry.path, entry]));
  const candidateEntries = new Map(candidate.map(entry => [entry.path, entry]));
  const paths = new Set([...baselineEntries.keys(), ...candidateEntries.keys()]);
  return Object.freeze([...paths]
    .filter(path => JSON.stringify(baselineEntries.get(path))
      !== JSON.stringify(candidateEntries.get(path)))
    .sort());
}

function requireOnlyExpectedTreeChanges(
  baseline: readonly TreeEntry[],
  candidate: readonly TreeEntry[],
  allowed: readonly string[],
  required: readonly string[],
): void {
  const changed = changedTreePaths(baseline, candidate);
  const allowedSet = new Set(allowed);
  const changedSet = new Set(changed);
  const unexpected = changed.filter(path => !allowedSet.has(path));
  const missing = required.filter(path => !changedSet.has(path));
  if (unexpected.length > 0 || missing.length > 0) {
    throw new Error(
      `Adversarial fixture tree delta differs (unexpected=${unexpected.join(",")}; missing=${missing.join(",")}).`,
    );
  }
}

function packagePaths(appRoot: string): Readonly<{
  gateway: string;
  helper: string;
  host: string;
  manifest: string;
  renderer: string;
}> {
  const runtime = join(appRoot, "Contents/Resources/runtime");
  return Object.freeze({
    gateway: join(runtime, "bin/oprte-gateway"),
    helper: join(runtime, "bin/oprte-keychain-custodian"),
    host: join(appRoot, `Contents/MacOS/${macosPackage.executableName}`),
    manifest: join(runtime, "manifest.json"),
    renderer: join(appRoot, "Contents/Resources/frontend/dist"),
  });
}

async function authoritySnapshot(appRoot: string): Promise<AuthoritySnapshot> {
  const paths = packagePaths(appRoot);
  const [gateway, helper, host, manifest, rendererEntries] = await Promise.all([
    sha256(paths.gateway),
    sha256(paths.helper),
    sha256(paths.host),
    sha256(paths.manifest),
    packagedRendererAuthorityEntries(paths.renderer),
  ]);
  return Object.freeze({
    gateway,
    helper,
    host,
    manifest,
    renderer: rendererAuthorityRoot(rendererEntries),
  });
}

function requireEqual(
  actual: string,
  expected: string,
  label: string,
): void {
  if (actual !== expected) {
    throw new Error(`Adversarial fixture changed an unrelated ${label}.`);
  }
}

async function requireNoFixtureProcess(root: string): Promise<void> {
  const processes = await run(
    [
      "/usr/bin/pgrep",
      "-f",
      "--",
      escapeExtendedRegularExpression(root),
    ],
    "Adversarial fixture residue inspection",
    [0, 1],
  );
  if (processes.exitCode === 0 && processes.stdout.trim().length > 0) {
    throw new Error("Adversarial package probe left a fixture process alive.");
  }
}

async function requireDeepSeal(appRoot: string): Promise<void> {
  await run([
    "/usr/bin/codesign",
    "--verify",
    "--deep",
    "--strict",
    "--verbose=6",
    appRoot,
  ], "Adversarial fixture deep seal verification");
}

async function requireProductionVerifierRejects(appRoot: string): Promise<void> {
  let rejected = false;
  try {
    await verifyMacOSApp(appRoot);
  } catch {
    rejected = true;
  }
  if (!rejected) {
    throw new Error("Production verifier accepted an adversarial package fixture.");
  }
}

async function requireAuthorizeOnlyRejection(
  appRoot: string,
  authority: CustodyProbeSupervisorAuthorityEvidence,
  snapshot: AuthoritySnapshot,
): Promise<void> {
  const expectedReceipt =
    `{"authorization":"hra-parent-v1","gatewayFileSha256":"${snapshot.gateway}",` +
    `"keychainAccessed":false,"ok":true,"rendererAuthoritySha256":"${snapshot.renderer}",` +
    "\"version\":1}\n";
  let rejected = false;
  try {
    await authorizeResidentCustodyCandidate(
      appRoot,
      authority,
      expectedReceipt,
    );
  } catch {
    rejected = true;
  }
  if (!rejected) {
    throw new Error(
      "Adversarial package reached or forged the resident authorize-only custody boundary.",
    );
  }
}

function requireDirectParentAuthorizationRejection(appRoot: string): void {
  const result = runMacOSCustodyProbe([
    "reject-authorize",
    packagePaths(appRoot).host,
  ]);
  if (result.exitCode !== 0 || result.stdout !== "" || result.stderr !== "") {
    throw new Error(
      "The malicious parent was not rejected by the exact helper authorization boundary.",
    );
  }
}

async function requireMissing(path: string, label: string): Promise<void> {
  try {
    await lstat(path);
  } catch (error: unknown) {
    if (error instanceof Error && "code" in error && error.code === "ENOENT") {
      return;
    }
    throw error;
  }
  throw new Error(`${label} was unexpectedly created.`);
}

async function signAdversarialGateway(path: string): Promise<void> {
  await run([
    "/usr/bin/codesign",
    "--force",
    "--sign",
    "-",
    "--identifier",
    "oprte-gateway",
    "--options",
    "runtime",
    "--pagesize",
    "16384",
    "--timestamp=none",
    "--entitlements",
    join(macosPackage.desktopRoot, "runtime/gateway.release.entitlements.plist"),
    path,
  ], "Adversarial gateway signing");
  await run(
    ["/usr/bin/codesign", "--verify", "--strict", "--verbose=6", path],
    "Adversarial gateway signature verification",
  );
  await verifyExactAdHocGatewayPosture(path);
}

async function copyMaliciousExecutable(
  destination: string,
  sourceName: "hra-custody-malicious-helper"
    | "hra-custody-malicious-parent"
    | "hra-custody-probe-fixture",
): Promise<void> {
  await rm(destination, { force: true });
  await copyFile(
    join(macosPackage.desktopRoot, `zig-out/bin/${sourceName}`),
    destination,
  );
  await chmod(destination, 0o755);
}

async function searchListBytes(): Promise<string> {
  return (await run(
    ["/usr/bin/security", "list-keychains", "-d", "user"],
    "Adversarial Keychain search-list inspection",
  )).stdout;
}

async function withAdversarialSigningContexts<T>(
  operation: (contexts: AdversarialSigningContexts) => Promise<T>,
): Promise<T> {
  return withProductionSigningContext(production =>
    withStructuralSigningFixture(attacker =>
      operation(Object.freeze({ attacker, production }))));
}

async function runFixture(
  root: string,
  label: string,
  productionApp: string,
  baseline: AuthoritySnapshot,
  baselineTree: readonly TreeEntry[],
  custodyProbeSupervisor: CustodyProbeSupervisorAuthorityEvidence,
  contexts: AdversarialSigningContexts,
  mutate: (fixture: FixtureMutation) => Promise<void>,
  assertSingleFault: (snapshot: AuthoritySnapshot) => void,
  treeDelta: Readonly<{
    allowed: readonly string[];
    expectStaticAcceptance?: true;
    required: readonly string[];
  }>,
  assertAfterProbe?: (appRoot: string) => Promise<void> | void,
): Promise<void> {
  const appRoot = join(root, `${label}.app`);
  await cp(productionApp, appRoot, {
    force: false,
    preserveTimestamps: true,
    recursive: true,
    verbatimSymlinks: true,
  });
  try {
    await mutate({ appRoot, ...contexts });
    const snapshot = await authoritySnapshot(appRoot);
    const fixtureTree = await packageTreeAuthority(appRoot);
    assertSingleFault(snapshot);
    requireOnlyExpectedTreeChanges(
      baselineTree,
      fixtureTree,
      treeDelta.allowed,
      treeDelta.required,
    );
    requireEqual(snapshot.manifest, baseline.manifest, "runtime manifest");
    if (snapshot.host === baseline.host) {
      throw new Error("Adversarial fixture did not replace the outer CodeDirectory.");
    }
    await requireDeepSeal(appRoot);
    if (treeDelta.expectStaticAcceptance === true) {
      await verifyMacOSApp(appRoot);
    } else {
      await requireProductionVerifierRejects(appRoot);
    }
    await requireAuthorizeOnlyRejection(
      appRoot,
      custodyProbeSupervisor,
      snapshot,
    );
    await assertAfterProbe?.(appRoot);
    await requireNoFixtureProcess(root);
  } finally {
    await rm(appRoot, { force: true, recursive: true });
  }
}

async function main(): Promise<void> {
  if (
    process.argv.length !== 4
    || process.argv[2] !== "--app"
  ) {
    throw new Error(
      "Usage: verify-macos-package-adversarial.ts --app <production HRA.app>",
    );
  }
  const productionApp = await realpath(resolve(process.argv[3]!));
  const expectedApp = await realpath(macosPackage.appBundlePath);
  if (productionApp !== expectedApp) {
    throw new Error("Adversarial verification requires the exact production app path.");
  }
  const productionStatus = await lstat(productionApp);
  if (!productionStatus.isDirectory() || productionStatus.isSymbolicLink()) {
    throw new Error("Production app is not a real directory.");
  }
  const baselineEvidence = await verifyMacOSApp(productionApp);
  const baseline = await authoritySnapshot(productionApp);
  const baselineTree = await packageTreeAuthority(productionApp);
  const hostTreePath = `Contents/MacOS/${macosPackage.executableName}`;
  const codeResourcesTreePath = "Contents/_CodeSignature/CodeResources";
  const gatewayTreePath = "Contents/Resources/runtime/bin/oprte-gateway";
  const helperTreePath =
    "Contents/Resources/runtime/bin/oprte-keychain-custodian";
  const rendererIndexTreePath = "Contents/Resources/frontend/dist/index.html";
  const rendererManifestTreePath =
    "Contents/Resources/frontend/dist/asset-manifest.zon";
  const searchListBefore = await searchListBytes();
  const root = await realpath(await mkdtemp(join(
    tmpdir(),
    "hra-package-adversarial-",
  )));
  await chmod(root, 0o700);
  try {
    await withAdversarialSigningContexts(async ({ attacker, production }) => {
      const contexts = Object.freeze({ attacker, production });
      await runFixture(
        root,
        "renderer-only",
        productionApp,
        baseline,
        baselineTree,
        baselineEvidence.custodyProbeSupervisor,
        contexts,
        async ({ appRoot }) => {
          await mutateRendererIndexFixture(packagePaths(appRoot).renderer);
          await signReleaseCode(
            appRoot,
            macosPackage.bundleIdentifier,
            production,
          );
        },
        (snapshot) => {
          requireEqual(snapshot.gateway, baseline.gateway, "gateway");
          requireEqual(snapshot.helper, baseline.helper, "helper");
          if (snapshot.renderer === baseline.renderer) {
            throw new Error("Renderer-only fixture did not change renderer authority.");
          }
        },
        {
          allowed: [
            codeResourcesTreePath,
            hostTreePath,
            rendererIndexTreePath,
            rendererManifestTreePath,
          ],
          expectStaticAcceptance: true,
          required: [
            hostTreePath,
            rendererIndexTreePath,
            rendererManifestTreePath,
          ],
        },
      );
      await runFixture(
        root,
        "gateway-only",
        productionApp,
        baseline,
        baselineTree,
        baselineEvidence.custodyProbeSupervisor,
        contexts,
        async ({ appRoot }) => {
          await copyMaliciousExecutable(
            packagePaths(appRoot).gateway,
            "hra-custody-probe-fixture",
          );
          await signAdversarialGateway(packagePaths(appRoot).gateway);
          await signReleaseCode(
            appRoot,
            macosPackage.bundleIdentifier,
            production,
          );
        },
        (snapshot) => {
          requireEqual(snapshot.helper, baseline.helper, "helper");
          requireEqual(snapshot.renderer, baseline.renderer, "renderer");
          if (snapshot.gateway === baseline.gateway) {
            throw new Error("Gateway-only fixture did not change the gateway.");
          }
        },
        {
          allowed: [codeResourcesTreePath, gatewayTreePath, hostTreePath],
          required: [gatewayTreePath, hostTreePath],
        },
      );
      await runFixture(
        root,
        "helper-only",
        productionApp,
        baseline,
        baselineTree,
        baselineEvidence.custodyProbeSupervisor,
        contexts,
        async ({ appRoot }) => {
          const helper = packagePaths(appRoot).helper;
          await copyMaliciousExecutable(
            helper,
            "hra-custody-malicious-helper",
          );
          await signReleaseCode(
            helper,
            "oprte-keychain-custodian",
            attacker,
          );
          await signReleaseCode(
            appRoot,
            macosPackage.bundleIdentifier,
            production,
          );
        },
        (snapshot) => {
          requireEqual(snapshot.gateway, baseline.gateway, "gateway");
          requireEqual(snapshot.renderer, baseline.renderer, "renderer");
          if (snapshot.helper === baseline.helper) {
            throw new Error("Helper-only fixture did not change the helper.");
          }
        },
        {
          allowed: [codeResourcesTreePath, helperTreePath, hostTreePath],
          required: [helperTreePath, hostTreePath],
        },
        async (appRoot) => {
          await requireMissing(
            `${packagePaths(appRoot).helper}.executed`,
            "Malicious helper execution marker",
          );
        },
      );
      await runFixture(
        root,
        "attacker-outer-only",
        productionApp,
        baseline,
        baselineTree,
        baselineEvidence.custodyProbeSupervisor,
        contexts,
        async ({ appRoot }) => {
          await signReleaseCode(
            appRoot,
            macosPackage.bundleIdentifier,
            attacker,
          );
        },
        (snapshot) => {
          requireEqual(snapshot.gateway, baseline.gateway, "gateway");
          requireEqual(snapshot.helper, baseline.helper, "helper");
          requireEqual(snapshot.renderer, baseline.renderer, "renderer");
        },
        {
          allowed: [codeResourcesTreePath, hostTreePath],
          required: [hostTreePath],
        },
      );
      await runFixture(
        root,
        "malicious-parent-exact-helper",
        productionApp,
        baseline,
        baselineTree,
        baselineEvidence.custodyProbeSupervisor,
        contexts,
        async ({ appRoot }) => {
          await copyMaliciousExecutable(
            packagePaths(appRoot).host,
            "hra-custody-malicious-parent",
          );
          await signReleaseCode(
            appRoot,
            macosPackage.bundleIdentifier,
            attacker,
          );
        },
        (snapshot) => {
          requireEqual(snapshot.gateway, baseline.gateway, "gateway");
          requireEqual(snapshot.helper, baseline.helper, "helper");
          requireEqual(snapshot.renderer, baseline.renderer, "renderer");
        },
        {
          allowed: [codeResourcesTreePath, hostTreePath],
          required: [hostTreePath],
        },
        (appRoot) => requireDirectParentAuthorizationRejection(appRoot),
      );
      await runFixture(
        root,
        "malicious-parent-equal-attacker-chain",
        productionApp,
        baseline,
        baselineTree,
        baselineEvidence.custodyProbeSupervisor,
        contexts,
        async ({ appRoot }) => {
          await copyMaliciousExecutable(
            packagePaths(appRoot).host,
            "hra-custody-malicious-parent",
          );
          await signReleaseCode(
            packagePaths(appRoot).helper,
            "oprte-keychain-custodian",
            attacker,
          );
          await signReleaseCode(
            appRoot,
            macosPackage.bundleIdentifier,
            attacker,
          );
        },
        (snapshot) => {
          requireEqual(snapshot.gateway, baseline.gateway, "gateway");
          requireEqual(snapshot.renderer, baseline.renderer, "renderer");
          if (snapshot.helper === baseline.helper) {
            throw new Error("Attacker-chain helper fixture did not change the helper.");
          }
        },
        {
          allowed: [codeResourcesTreePath, helperTreePath, hostTreePath],
          required: [helperTreePath, hostTreePath],
        },
        (appRoot) => requireDirectParentAuthorizationRejection(appRoot),
      );
    });
    if (await searchListBytes() !== searchListBefore) {
      throw new Error("Adversarial gate changed the user Keychain search list.");
    }
    await requireNoFixtureProcess(root);
    if (JSON.stringify(await readdir(root)) !== "[]") {
      throw new Error("Adversarial fixture root retained package artifacts.");
    }
    const after = await authoritySnapshot(productionApp);
    if (JSON.stringify(after) !== JSON.stringify(baseline)) {
      throw new Error("Adversarial gate mutated the production package.");
    }
    const [afterTree, afterEvidence] = await Promise.all([
      packageTreeAuthority(productionApp),
      verifyMacOSApp(productionApp),
    ]);
    if (
      JSON.stringify(afterTree) !== JSON.stringify(baselineTree)
      || JSON.stringify(afterEvidence) !== JSON.stringify(baselineEvidence)
    ) {
      throw new Error("Adversarial gate changed complete production package authority.");
    }
  } finally {
    await rm(root, { force: true, recursive: true });
  }
}

if (import.meta.main) await main();
