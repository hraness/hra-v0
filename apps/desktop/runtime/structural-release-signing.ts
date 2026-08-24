import { createHash, randomBytes } from "node:crypto";
import {
  chmod,
  lstat,
  mkdtemp,
  readFile,
  realpath,
  rm,
  writeFile,
} from "node:fs/promises";
import { join } from "node:path";
import { tmpdir } from "node:os";

import {
  compileReleaseKeychainControl,
  type PackageSigningContext,
} from "./package-macos";
import {
  parseReleaseSigningAuthority,
  structuralAuthorityDescription,
  type ReleaseSigningAuthority,
} from "./release-signing-authority";

type CommandResult = Readonly<{
  exitCode: number;
  stderr: string;
  stdout: string;
}>;

const maximumCommandOutputBytes = 64 * 1024;

function errorFromUnknown(error: unknown, fallback: string): Error {
  return error instanceof Error ? error : new Error(fallback);
}

function structuralEnvironment(): Readonly<Record<string, string>> {
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

async function runStructuralCommand(
  argv: readonly string[],
  label: string,
  allowFailure = false,
): Promise<CommandResult> {
  const child = Bun.spawn([...argv], {
    cwd: "/",
    env: structuralEnvironment(),
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
  if (exitCode !== 0 && !allowFailure) {
    throw new Error(`${label} failed without exposing fixture custody paths or output.`);
  }
  return { exitCode, stderr, stdout };
}

function certificateRecord(der: Buffer): Readonly<{
  derBase64: string;
  sha1: string;
  sha256: string;
}> {
  return {
    derBase64: der.toString("base64"),
    sha1: createHash("sha1").update(der).digest("hex"),
    sha256: createHash("sha256").update(der).digest("hex"),
  };
}

export function structuralManifestSigning(
  authority: ReleaseSigningAuthority,
): Readonly<Record<string, unknown>> {
  return Object.freeze({
    architecture: "arm64",
    authority: "hra-structural-signing-v1",
    cmsSigningTime: "none",
    codeDirectoryHash: "sha256",
    developerId: false,
    ephemeral: true,
    hardenedRuntime: true,
    leafCertificateSha256: authority.leaf.sha256,
    mode: "structural-ephemeral-cms-v1",
    notarized: false,
    pageSize: 16_384,
    releaseEligible: false,
    rootCertificateSha256: authority.root.sha256,
    secureTimestamp: "none",
    systemTrust: false,
  });
}

export function structuralDesignatedRequirement(
  authority: ReleaseSigningAuthority,
  identifier: string,
): string {
  if (!/^[A-Za-z0-9.-]+$/u.test(identifier)) {
    throw new Error("Structural signing identifier is invalid.");
  }
  return `designated => identifier "${identifier}" and certificate root = H"${authority.root.sha1}" and certificate leaf = H"${authority.leaf.sha1}"`;
}

function parseSearchList(stdout: string): readonly string[] {
  const paths = stdout.trim().length === 0
    ? []
    : stdout.trimEnd().split("\n").map((line) => {
      const match = /^\s*"([^"\\]+)"\s*$/u.exec(line);
      if (match === null || !match[1]!.startsWith("/")) {
        throw new Error("The user Keychain search list has an unsupported shape.");
      }
      return match[1]!;
    });
  if (new Set(paths).size !== paths.length) {
    throw new Error("The user Keychain search list contains duplicates.");
  }
  return paths;
}

async function verifySearchListUnchanged(beforeText: string): Promise<void> {
  const after = await runStructuralCommand(
    ["/usr/bin/security", "list-keychains", "-d", "user"],
    "Structural fixture Keychain search-list inspection",
  );
  parseSearchList(after.stdout);
  if (after.stdout !== beforeText) {
    throw new Error("Structural signing observed a Keychain search-list mutation.");
  }
}

export async function withStructuralSigningFixture<T>(
  operation: (context: PackageSigningContext) => Promise<T>,
): Promise<T> {
  if (process.platform !== "darwin" || process.arch !== "arm64") {
    throw new Error("Structural signing fixtures require Apple Silicon macOS.");
  }
  const root = await realpath(await mkdtemp(join(
    tmpdir(),
    "hra-structural-signing-",
  )));
  await chmod(root, 0o700);
  const keychain = join(root, "fixture.keychain-db");
  const password = randomBytes(32).toString("hex");
  const passwordFile = join(root, "fixture.keychain.pass");
  const rootKey = join(root, "root.key.pem");
  const rootPem = join(root, "root.cert.pem");
  const rootDer = join(root, "root.cert.der");
  const leafKey = join(root, "leaf.key.pem");
  const leafRequest = join(root, "leaf.csr.pem");
  const leafPem = join(root, "leaf.cert.pem");
  const leafDer = join(root, "leaf.cert.der");
  const identityArchive = join(root, "identity.p12");
  const rootConfig = join(root, "root.cnf");
  const leafConfig = join(root, "leaf.cnf");
  const searchBefore = await runStructuralCommand(
    ["/usr/bin/security", "list-keychains", "-d", "user"],
    "Structural fixture Keychain search-list snapshot",
  );
  parseSearchList(searchBefore.stdout);
  let operationError: unknown;
  let cleanupError: unknown;
  let result: T | undefined;
  try {
    await Promise.all([
      writeFile(passwordFile, `${password}\n`, { flag: "wx", mode: 0o600 }),
      writeFile(rootConfig, [
        "[req]",
        "distinguished_name=dn",
        "prompt=no",
        "x509_extensions=v3_ca",
        "[dn]",
        "CN=HRA Structural Fixture Root",
        "[v3_ca]",
        "basicConstraints=critical,CA:true,pathlen:0",
        "keyUsage=critical,keyCertSign,cRLSign",
        "subjectKeyIdentifier=hash",
        "authorityKeyIdentifier=keyid:always",
        "",
      ].join("\n"), { flag: "wx", mode: 0o600 }),
      writeFile(leafConfig, [
        "[v3_leaf]",
        "basicConstraints=critical,CA:false",
        "keyUsage=critical,digitalSignature",
        "extendedKeyUsage=critical,codeSigning",
        "subjectKeyIdentifier=hash",
        "authorityKeyIdentifier=keyid:always",
        "",
      ].join("\n"), { flag: "wx", mode: 0o600 }),
    ]);
    const helper = await compileReleaseKeychainControl(root);
    await runStructuralCommand(
      ["/usr/bin/openssl", "genrsa", "-out", rootKey, "4096"],
      "Structural root-key generation",
    );
    await runStructuralCommand([
      "/usr/bin/openssl", "req", "-new", "-x509", "-sha256", "-days", "366",
      "-key", rootKey, "-out", rootPem, "-config", rootConfig,
    ], "Structural root-certificate generation");
    await runStructuralCommand(
      ["/usr/bin/openssl", "genrsa", "-out", leafKey, "3072"],
      "Structural leaf-key generation",
    );
    await runStructuralCommand([
      "/usr/bin/openssl", "req", "-new", "-sha256", "-key", leafKey,
      "-out", leafRequest, "-subj", "/CN=HRA Structural Fixture Leaf",
    ], "Structural leaf-request generation");
    await runStructuralCommand([
      "/usr/bin/openssl", "x509", "-req", "-sha256", "-days", "180",
      "-in", leafRequest, "-CA", rootPem, "-CAkey", rootKey,
      "-CAcreateserial", "-out", leafPem, "-extfile", leafConfig,
      "-extensions", "v3_leaf",
    ], "Structural leaf-certificate generation");
    await Promise.all([
      runStructuralCommand([
        "/usr/bin/openssl", "x509", "-in", rootPem, "-outform", "DER",
        "-out", rootDer,
      ], "Structural root DER conversion"),
      runStructuralCommand([
        "/usr/bin/openssl", "x509", "-in", leafPem, "-outform", "DER",
        "-out", leafDer,
      ], "Structural leaf DER conversion"),
    ]);
    const [rootBytes, leafBytes] = await Promise.all([
      readFile(rootDer),
      readFile(leafDer),
    ]);
    const authority = parseReleaseSigningAuthority({
      description: structuralAuthorityDescription,
      leaf: certificateRecord(leafBytes),
      policy: {
        architecture: "arm64",
        cmsSigningTime: "none",
        codeDirectoryHash: "sha256",
        hardenedRuntime: true,
        pageSize: 16_384,
        secureTimestamp: "none",
      },
      root: certificateRecord(rootBytes),
      schemaVersion: 1,
    }, undefined, new Date(), "structural");
    await runStructuralCommand([
      "/usr/bin/openssl", "pkcs12", "-export", "-inkey", leafKey,
      "-in", leafPem, "-certfile", rootPem, "-name", "HRA Structural Fixture",
      "-passout", `pass:${password}`, "-out", identityArchive,
    ], "Structural signing-identity archive generation");
    await runStructuralCommand(
      ["/usr/bin/security", "create-keychain", "-p", password, keychain],
      "Structural Keychain creation",
    );
    await chmod(keychain, 0o600);
    const keychainStatus = await lstat(keychain);
    if (
      await realpath(keychain) !== keychain
      || !keychainStatus.isFile()
      || keychainStatus.isSymbolicLink()
      || keychainStatus.nlink !== 1
      || keychainStatus.uid !== process.geteuid?.()
      || keychainStatus.mode !== 0o100600
    ) throw new Error("Structural Keychain file custody is unsafe.");
    await runStructuralCommand(
      ["/usr/bin/security", "set-keychain-settings", "-lut", "21600", keychain],
      "Structural Keychain settings",
    );
    await runStructuralCommand(
      ["/usr/bin/security", "unlock-keychain", "-p", password, keychain],
      "Structural Keychain unlock",
    );
    await runStructuralCommand([
      "/usr/bin/security", "import", identityArchive, "-k", keychain,
      "-P", password, "-x", "-T", helper,
    ], "Structural signing-identity import");
    const identities = await runStructuralCommand([
      "/usr/bin/security", "find-identity", "-p", "codesigning", keychain,
    ], "Structural signing-identity inventory");
    const identityHashes = [...`${identities.stdout}\n${identities.stderr}`.matchAll(
      /\) ([0-9A-F]{40}) /gu,
    )].map(match => match[1]!.toLowerCase());
    if (identityHashes.length !== 1 || identityHashes[0] !== authority.leaf.sha1) {
      throw new Error("Structural Keychain identity inventory differs from its exact leaf.");
    }
    await runStructuralCommand(
      ["/usr/bin/security", "lock-keychain", keychain],
      "Structural Keychain lock",
    );
    result = await operation({
      authority,
      designatedRequirement: identifier =>
        structuralDesignatedRequirement(authority, identifier),
      identity: authority.leaf.sha1,
      keychain,
      label: "structural fixture",
      manifestSigning: structuralManifestSigning(authority),
      sign: async (path, identifier) => {
        const signed = await runStructuralCommand([
          helper,
          "sign",
          keychain,
          passwordFile,
          authority.leaf.sha1,
          authority.root.sha1,
          identifier,
          path,
        ], "Structural release signing");
        if (signed.stdout !== "" || signed.stderr !== "") {
          throw new Error("Structural release signer emitted unexpected output.");
        }
      },
    });
  } catch (error) {
    operationError = error;
  } finally {
    try {
      await runStructuralCommand(
        ["/usr/bin/security", "delete-keychain", keychain],
        "Structural Keychain deletion",
        true,
      );
      await verifySearchListUnchanged(searchBefore.stdout);
    } catch (error) {
      cleanupError = error;
    }
    try {
      await rm(root, { force: true, recursive: true });
    } catch (error) {
      cleanupError ??= error;
    }
  }
  if (cleanupError !== undefined) {
    throw errorFromUnknown(cleanupError, "Structural signing cleanup failed.");
  }
  if (operationError !== undefined) {
    throw errorFromUnknown(operationError, "Structural signing operation failed.");
  }
  return result as T;
}
