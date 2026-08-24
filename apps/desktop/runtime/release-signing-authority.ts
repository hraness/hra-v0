import { createHash, X509Certificate } from "node:crypto";
import { lstat, readFile, realpath } from "node:fs/promises";
import { isAbsolute, relative, resolve, sep } from "node:path";

export const productionReleaseAuthorityPins = Object.freeze({
  leafSha1: "a832db4e88735e225c4658ace7f533883ba60093",
  leafSha256: "e9e2d5d8864e000a274dc7b0291945b89eb857ac9abbe3bf537a590a78c7bd75",
  rootSha1: "651e6cba108ead96946c332590b919c96d237729",
  rootSha256: "549669449ea928f1a60fe2cfeb494a6059b6ddc1d9fc71a69a6571d8cc4eb68f",
} as const);

export const productionReleaseSigning = Object.freeze({
  architecture: "arm64",
  authority: "hra-release-signing-v2",
  cmsSigningTime: "none",
  codeDirectoryHash: "sha256",
  developerId: false,
  hardenedRuntime: true,
  leafCertificateSha256: productionReleaseAuthorityPins.leafSha256,
  mode: "self-managed-cms-v2",
  notarized: false,
  pageSize: 16_384,
  rootCertificateSha256: productionReleaseAuthorityPins.rootSha256,
  secureTimestamp: "none",
  systemTrust: false,
} as const);

const productionAuthorityDescription =
  "Locally self-managed, build-isolated HRA release authority v2. These are public certificates only; the package and repository contain no private key material.";
export const structuralAuthorityDescription =
  "Ephemeral nonrelease HRA structural signing fixture v1. The temporary private key and Keychain are destroyed after the structural package gate.";

export type ReleaseSigningAuthorityProfile = "production" | "structural";

type CertificatePins = Readonly<{
  leafSha1: string;
  leafSha256: string;
  rootSha1: string;
  rootSha256: string;
}>;

export interface ReleaseSigningAuthority {
  readonly leaf: Readonly<{
    der: Buffer;
    sha1: string;
    sha256: string;
    x509: X509Certificate;
  }>;
  readonly policy: Readonly<{
    architecture: "arm64";
    cmsSigningTime: "none";
    codeDirectoryHash: "sha256";
    hardenedRuntime: true;
    pageSize: 16_384;
    secureTimestamp: "none";
  }>;
  readonly root: Readonly<{
    der: Buffer;
    sha1: string;
    sha256: string;
    x509: X509Certificate;
  }>;
}

type DerNode = Readonly<{
  end: number;
  start: number;
  tag: number;
  valueEnd: number;
  valueStart: number;
}>;

function exactKeys(
  value: Record<string, unknown>,
  expected: readonly string[],
  label: string,
): void {
  const actual = Object.keys(value).sort();
  const canonical = [...expected].sort();
  if (JSON.stringify(actual) !== JSON.stringify(canonical)) {
    throw new Error(`${label} fields differ: ${actual.join(", ")}`);
  }
}

function derNode(bytes: Buffer, offset: number): DerNode {
  if (!Number.isSafeInteger(offset) || offset < 0 || offset + 2 > bytes.length) {
    throw new Error("Certificate DER is truncated.");
  }
  const tag = bytes[offset]!;
  const firstLength = bytes[offset + 1]!;
  let length = firstLength;
  let valueStart = offset + 2;
  if ((firstLength & 0x80) !== 0) {
    const width = firstLength & 0x7f;
    if (width === 0 || width > 4 || valueStart + width > bytes.length) {
      throw new Error("Certificate DER has an invalid length.");
    }
    if (bytes[valueStart] === 0) {
      throw new Error("Certificate DER length is not minimally encoded.");
    }
    length = 0;
    for (let index = 0; index < width; index += 1) {
      length = (length * 256) + bytes[valueStart + index]!;
    }
    if (length < 128) {
      throw new Error("Certificate DER length is not minimally encoded.");
    }
    valueStart += width;
  }
  const valueEnd = valueStart + length;
  if (!Number.isSafeInteger(valueEnd) || valueEnd > bytes.length) {
    throw new Error("Certificate DER value is truncated.");
  }
  return { end: valueEnd, start: offset, tag, valueEnd, valueStart };
}

function derChildren(bytes: Buffer, parent: DerNode): readonly DerNode[] {
  const children: DerNode[] = [];
  let offset = parent.valueStart;
  while (offset < parent.valueEnd) {
    const child = derNode(bytes, offset);
    if (child.end > parent.valueEnd) {
      throw new Error("Certificate DER child escapes its parent.");
    }
    children.push(child);
    offset = child.end;
  }
  if (offset !== parent.valueEnd) {
    throw new Error("Certificate DER children have trailing ambiguity.");
  }
  return children;
}

function derValueHex(bytes: Buffer, node: DerNode): string {
  return bytes.subarray(node.valueStart, node.valueEnd).toString("hex");
}

type CertificateDerPosture = Readonly<{
  extensions: ReadonlyMap<string, Readonly<{ critical: boolean; valueHex: string }>>;
  signatureAlgorithmOidHex: string;
  tbsSignatureAlgorithmOidHex: string;
}>;

function certificateDerPosture(bytes: Buffer): CertificateDerPosture {
  const certificate = derNode(bytes, 0);
  if (certificate.tag !== 0x30 || certificate.end !== bytes.length) {
    throw new Error("Certificate DER envelope is not one exact sequence.");
  }
  const certificateFields = derChildren(bytes, certificate);
  if (certificateFields.length !== 3 || certificateFields[0]?.tag !== 0x30) {
    throw new Error("Certificate DER fields are invalid.");
  }
  const tbsFields = derChildren(bytes, certificateFields[0]);
  const versionOffset = tbsFields[0]?.tag === 0xa0 ? 1 : 0;
  const tbsSignature = tbsFields[versionOffset + 1];
  const outerSignature = certificateFields[1];
  if (tbsSignature?.tag !== 0x30 || outerSignature?.tag !== 0x30) {
    throw new Error("Certificate signature algorithms are invalid.");
  }
  const tbsAlgorithm = derChildren(bytes, tbsSignature)[0];
  const outerAlgorithm = derChildren(bytes, outerSignature)[0];
  if (tbsAlgorithm?.tag !== 0x06 || outerAlgorithm?.tag !== 0x06) {
    throw new Error("Certificate signature algorithm OID is missing.");
  }

  const extensionsField = tbsFields.find(field => field.tag === 0xa3);
  if (extensionsField === undefined) {
    throw new Error("Certificate extensions are missing.");
  }
  const extensionEnvelope = derChildren(bytes, extensionsField);
  if (extensionEnvelope.length !== 1 || extensionEnvelope[0]?.tag !== 0x30) {
    throw new Error("Certificate extensions envelope is invalid.");
  }
  const extensions = new Map<string, Readonly<{ critical: boolean; valueHex: string }>>();
  for (const extension of derChildren(bytes, extensionEnvelope[0])) {
    if (extension.tag !== 0x30) {
      throw new Error("Certificate extension is invalid.");
    }
    const fields = derChildren(bytes, extension);
    const oid = fields[0];
    const criticalField = fields.length === 3 ? fields[1] : undefined;
    const value = fields.at(-1);
    if (
      (fields.length !== 2 && fields.length !== 3)
      || oid?.tag !== 0x06
      || value?.tag !== 0x04
      || (criticalField !== undefined
        && (criticalField.tag !== 0x01 || derValueHex(bytes, criticalField) !== "ff"))
    ) {
      throw new Error("Certificate extension fields are invalid.");
    }
    const oidHex = derValueHex(bytes, oid);
    if (extensions.has(oidHex)) {
      throw new Error("Certificate extension OID is duplicated.");
    }
    extensions.set(oidHex, {
      critical: criticalField !== undefined,
      valueHex: derValueHex(bytes, value),
    });
  }
  return {
    extensions,
    signatureAlgorithmOidHex: derValueHex(bytes, outerAlgorithm),
    tbsSignatureAlgorithmOidHex: derValueHex(bytes, tbsAlgorithm),
  };
}

function exactExtension(
  posture: CertificateDerPosture,
  oidHex: string,
  expected: Readonly<{ critical: boolean; valueHex: string }>,
  label: string,
): void {
  const actual = posture.extensions.get(oidHex);
  if (
    actual === undefined
    || actual.critical !== expected.critical
    || actual.valueHex !== expected.valueHex
  ) {
    throw new Error(`${label} certificate extension differs from policy.`);
  }
}

function verifyKeyIdentifiers(
  root: CertificateDerPosture,
  leaf: CertificateDerPosture,
): void {
  const rootSubject = root.extensions.get("551d0e");
  const rootAuthority = root.extensions.get("551d23");
  const leafSubject = leaf.extensions.get("551d0e");
  const leafAuthority = leaf.extensions.get("551d23");
  const rootMatch = /^0414([0-9a-f]{40})$/u.exec(rootSubject?.valueHex ?? "");
  const leafMatch = /^0414([0-9a-f]{40})$/u.exec(leafSubject?.valueHex ?? "");
  if (
    rootSubject?.critical !== false
    || rootAuthority?.critical !== false
    || leafSubject?.critical !== false
    || leafAuthority?.critical !== false
    || rootMatch === null
    || leafMatch === null
    || rootMatch[1] === leafMatch[1]
    || rootAuthority.valueHex !== `30168014${rootMatch[1]}`
    || leafAuthority.valueHex !== `30168014${rootMatch[1]}`
  ) {
    throw new Error("Release certificate key identifiers differ from policy.");
  }
}

function certificate(
  value: unknown,
  label: string,
  expected?: Readonly<{ sha1: string; sha256: string }>,
): ReleaseSigningAuthority["leaf"] {
  if (typeof value !== "object" || value === null || Array.isArray(value)) {
    throw new Error(`${label} release certificate is invalid.`);
  }
  const candidate = value as Record<string, unknown>;
  exactKeys(candidate, ["derBase64", "sha1", "sha256"], `${label} certificate`);
  if (
    typeof candidate.derBase64 !== "string"
    || typeof candidate.sha1 !== "string"
    || typeof candidate.sha256 !== "string"
    || !/^[0-9a-f]{40}$/u.test(candidate.sha1)
    || !/^[0-9a-f]{64}$/u.test(candidate.sha256)
    || (expected !== undefined
      && (candidate.sha1 !== expected.sha1 || candidate.sha256 !== expected.sha256))
  ) {
    throw new Error(`${label} release certificate pins differ from policy.`);
  }
  const der = Buffer.from(candidate.derBase64, "base64");
  if (
    der.length === 0
    || der.toString("base64") !== candidate.derBase64
    || createHash("sha1").update(der).digest("hex") !== candidate.sha1
    || createHash("sha256").update(der).digest("hex") !== candidate.sha256
  ) {
    throw new Error(`${label} release certificate DER differs from its pins.`);
  }
  return {
    der,
    sha1: candidate.sha1,
    sha256: candidate.sha256,
    x509: new X509Certificate(der),
  };
}

function verifyAuthorityCertificates(
  authority: ReleaseSigningAuthority,
  nowValue: Date,
): void {
  const root = authority.root.x509;
  const leaf = authority.leaf.x509;
  const rootPosture = certificateDerPosture(authority.root.der);
  const leafPosture = certificateDerPosture(authority.leaf.der);
  const sha256WithRsaOidHex = "2a864886f70d01010b";
  if (
    rootPosture.signatureAlgorithmOidHex !== sha256WithRsaOidHex
    || rootPosture.tbsSignatureAlgorithmOidHex !== sha256WithRsaOidHex
    || leafPosture.signatureAlgorithmOidHex !== sha256WithRsaOidHex
    || leafPosture.tbsSignatureAlgorithmOidHex !== sha256WithRsaOidHex
  ) {
    throw new Error("Release certificate signature algorithm is not SHA-256 with RSA.");
  }
  exactExtension(rootPosture, "551d13", {
    critical: true,
    valueHex: "30060101ff020100",
  }, "Root basic-constraints");
  exactExtension(rootPosture, "551d0f", {
    critical: true,
    valueHex: "03020106",
  }, "Root key-usage");
  exactExtension(leafPosture, "551d13", {
    critical: true,
    valueHex: "3000",
  }, "Leaf basic-constraints");
  exactExtension(leafPosture, "551d0f", {
    critical: true,
    valueHex: "03020780",
  }, "Leaf key-usage");
  exactExtension(leafPosture, "551d25", {
    critical: true,
    valueHex: "300a06082b06010505070303",
  }, "Leaf extended-key-usage");
  verifyKeyIdentifiers(rootPosture, leafPosture);
  const rootExtensionOids = [...rootPosture.extensions.keys()].sort();
  const leafExtensionOids = [...leafPosture.extensions.keys()].sort();
  if (
    JSON.stringify(rootExtensionOids)
      !== JSON.stringify(["551d0e", "551d0f", "551d13", "551d23"].sort())
    || JSON.stringify(leafExtensionOids)
      !== JSON.stringify(["551d0e", "551d0f", "551d13", "551d23", "551d25"].sort())
  ) {
    throw new Error("Release certificate extension inventory differs from policy.");
  }
  if (
    root.subject !== root.issuer
    || !root.verify(root.publicKey)
    || root.ca !== true
    || leaf.issuer !== root.subject
    || !leaf.verify(root.publicKey)
    || leaf.verify(leaf.publicKey)
    || leaf.ca !== false
  ) {
    throw new Error("Release certificate issuance or CA posture differs from policy.");
  }
  if (
    root.publicKey.asymmetricKeyType !== "rsa"
    || root.publicKey.asymmetricKeyDetails?.modulusLength !== 4096
    || root.publicKey.asymmetricKeyDetails.publicExponent !== 65_537n
    || leaf.publicKey.asymmetricKeyType !== "rsa"
    || leaf.publicKey.asymmetricKeyDetails?.modulusLength !== 3072
    || leaf.publicKey.asymmetricKeyDetails.publicExponent !== 65_537n
  ) {
    throw new Error("Release certificate public-key posture differs from policy.");
  }
  const rootFrom = root.validFromDate.getTime();
  const rootTo = root.validToDate.getTime();
  const leafFrom = leaf.validFromDate.getTime();
  const leafTo = leaf.validToDate.getTime();
  const now = nowValue.getTime();
  const minimumRemainingValidity = 30 * 24 * 60 * 60 * 1_000;
  if (
    ![rootFrom, rootTo, leafFrom, leafTo, now].every(Number.isFinite)
    || rootFrom > leafFrom
    || leafTo > rootTo
    || rootFrom > now
    || now + minimumRemainingValidity > rootTo
    || leafFrom > now
    || now + minimumRemainingValidity > leafTo
  ) {
    throw new Error("Release certificate validity interval differs from policy.");
  }
}

export function parseReleaseSigningAuthority(
  raw: unknown,
  expectedPins?: CertificatePins,
  now = new Date(),
  profile: ReleaseSigningAuthorityProfile = "production",
): ReleaseSigningAuthority {
  if (typeof raw !== "object" || raw === null || Array.isArray(raw)) {
    throw new Error("Release signing authority is invalid.");
  }
  const value = raw as Record<string, unknown>;
  exactKeys(
    value,
    ["description", "leaf", "policy", "root", "schemaVersion"],
    "Release signing authority",
  );
  if (
    value.schemaVersion !== 1
    || value.description !== (profile === "production"
      ? productionAuthorityDescription
      : structuralAuthorityDescription)
  ) {
    throw new Error("Release signing authority schema is unsupported.");
  }
  if (typeof value.policy !== "object" || value.policy === null || Array.isArray(value.policy)) {
    throw new Error("Release signing authority policy is invalid.");
  }
  const policy = value.policy as Record<string, unknown>;
  exactKeys(
    policy,
    [
      "architecture",
      "cmsSigningTime",
      "codeDirectoryHash",
      "hardenedRuntime",
      "pageSize",
      "secureTimestamp",
    ],
    "Release signing authority policy",
  );
  if (
    policy.architecture !== "arm64"
    || policy.cmsSigningTime !== "none"
    || policy.codeDirectoryHash !== "sha256"
    || policy.hardenedRuntime !== true
    || policy.pageSize !== 16_384
    || policy.secureTimestamp !== "none"
  ) {
    throw new Error("Release signing authority policy differs from production v2.");
  }
  const authority: ReleaseSigningAuthority = {
    leaf: certificate(value.leaf, "Leaf", expectedPins === undefined ? undefined : {
      sha1: expectedPins.leafSha1,
      sha256: expectedPins.leafSha256,
    }),
    policy: {
      architecture: "arm64",
      cmsSigningTime: "none",
      codeDirectoryHash: "sha256",
      hardenedRuntime: true,
      pageSize: 16_384,
      secureTimestamp: "none",
    },
    root: certificate(value.root, "Root", expectedPins === undefined ? undefined : {
      sha1: expectedPins.rootSha1,
      sha256: expectedPins.rootSha256,
    }),
  };
  verifyAuthorityCertificates(authority, now);
  return authority;
}

export async function loadReleaseSigningAuthority(
  source: string | URL,
  expectedPins?: CertificatePins,
  now = new Date(),
): Promise<ReleaseSigningAuthority> {
  const serialized = await readFile(source, "utf8");
  const raw: unknown = JSON.parse(serialized);
  if (`${JSON.stringify(raw, null, 2)}\n` !== serialized) {
    throw new Error("Release signing authority JSON is not canonical.");
  }
  return parseReleaseSigningAuthority(raw, expectedPins, now);
}

export async function loadProductionReleaseAuthority(): Promise<ReleaseSigningAuthority> {
  return await loadReleaseSigningAuthority(
    new URL("./release-signing-authority-v2.json", import.meta.url),
    productionReleaseAuthorityPins,
  );
}

export function releaseDesignatedRequirement(
  identifier: string,
  pins: Readonly<{ leafSha1: string; rootSha1: string }> = productionReleaseAuthorityPins,
): string {
  if (!/^[A-Za-z0-9.-]+$/u.test(identifier)) {
    throw new Error("Release code-signing identifier is invalid.");
  }
  return `designated => identifier "${identifier}" and certificate root = H"${pins.rootSha1}" and certificate leaf = H"${pins.leafSha1}"`;
}

export async function productionSigningKeychainPath(): Promise<string> {
  const configured = process.env.HRA_RELEASE_SIGNING_KEYCHAIN;
  if (
    configured === undefined
    || !isAbsolute(configured)
    || resolve(configured) !== configured
  ) {
    throw new Error(
      "HRA_RELEASE_SIGNING_KEYCHAIN must name an absolute normalized operator-supplied isolated keychain.",
    );
  }
  let canonical: string;
  let status: Awaited<ReturnType<typeof lstat>>;
  try {
    [canonical, status] = await Promise.all([
      realpath(configured),
      lstat(configured),
    ]);
  } catch {
    throw new Error("The release signing keychain could not be opened safely.");
  }
  const effectiveUserId = process.geteuid;
  const repositoryRoot = resolve(import.meta.dir, "../../..");
  const fromRepository = relative(repositoryRoot, configured);
  const insideRepository = fromRepository === "" || (
    fromRepository !== ".."
    && !fromRepository.startsWith(`..${sep}`)
    && !fromRepository.startsWith(sep)
  );
  if (
    effectiveUserId === undefined
    ||
    canonical !== configured
    || !status.isFile()
    || status.isSymbolicLink()
    || status.nlink !== 1
    || status.uid !== effectiveUserId()
    || (status.mode & 0o077) !== 0
    || insideRepository
  ) {
    throw new Error("The release signing keychain has unsafe path or file metadata.");
  }
  return configured;
}
