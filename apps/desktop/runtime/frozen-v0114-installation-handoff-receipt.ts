import { z } from "@hra-internal/schema";

import {
  expectedHistoricalOprtePreviewIdentity,
  expectedHistoricalOprtePreviewSignature,
  expectedHistoricalOprtePreviewTree,
  historicalOprtePreviewSignaturePolicy,
  strictBundleSignaturePolicy,
  type BundleSignatureEvidence,
} from "./historical-oprte-preview";

const maximumTreeEntries = 2_000_000;
const maximumTreeBytes = 128 * 1_024 * 1_024 * 1_024;
const forbiddenKeys = new Set(["__proto__", "constructor", "prototype"]);
const nonNegativeSafeIntegerSchema = z.number().int().nonnegative()
  .max(Number.MAX_SAFE_INTEGER);
const sha256Schema = z.string().regex(/^[0-9a-f]{64}$/u);

export interface FrozenV0114TreeEvidence {
  readonly bytes: number;
  readonly directories: number;
  readonly digest: string;
  readonly entries: number;
  readonly files: number;
  readonly symlinks: number;
}

export interface FrozenV0114BundleEvidence {
  readonly identity: Readonly<{
    readonly build: string;
    readonly bundleIdentifier: string;
    readonly executable: string;
    readonly version: string;
  }>;
  readonly signature: BundleSignatureEvidence;
  readonly tree: FrozenV0114TreeEvidence;
}

export interface FrozenV0114InstallationHandoffReceipt {
  readonly candidate: FrozenV0114BundleEvidence;
  readonly candidateCommit: string;
  readonly createdAt: number;
  readonly hadPriorHra: boolean;
  readonly keychainDescriptors: readonly string[];
  readonly operationId: string;
  readonly phase:
    | "created"
    | "backed_up"
    | "smoked"
    | "bundles_archived"
    | "candidate_staged"
    | "candidate_installed"
    | "predecessor_retired"
    | "verified"
    | "committed"
    | "rolled_back";
  readonly predecessor: FrozenV0114BundleEvidence;
  readonly priorHra?: FrozenV0114BundleEvidence;
  readonly schemaVersion: 2;
  readonly state: Readonly<{
    readonly accountHomes: number;
    readonly chatWorktreeLanes: number;
    readonly database: Readonly<{
      readonly databaseSha256: string;
      readonly migrationVersion: number;
      readonly quickCheck: "ok";
      readonly rows: Readonly<Record<string, number>>;
    }>;
    readonly dispatchWorktreeLanes: number;
    readonly harnessWorktreeLanes: number;
    readonly localTaskWorktreeLanes: number;
    readonly sessionEntries: number;
    readonly tree: FrozenV0114TreeEvidence;
  }>;
}

const treeEvidenceSchema = z.object({
  bytes: nonNegativeSafeIntegerSchema.max(maximumTreeBytes),
  directories: nonNegativeSafeIntegerSchema.max(maximumTreeEntries),
  digest: sha256Schema,
  entries: nonNegativeSafeIntegerSchema.max(maximumTreeEntries),
  files: nonNegativeSafeIntegerSchema.max(maximumTreeEntries),
  symlinks: nonNegativeSafeIntegerSchema.max(maximumTreeEntries),
}).strict().superRefine((value, context) => {
  if (value.entries !== value.directories + value.files + value.symlinks) {
    context.addIssue({ code: "custom", message: "tree entry counts differ" });
  }
});

const stateEvidenceSchema = z.object({
  accountHomes: nonNegativeSafeIntegerSchema,
  chatWorktreeLanes: nonNegativeSafeIntegerSchema,
  database: z.object({
    databaseSha256: sha256Schema,
    migrationVersion: nonNegativeSafeIntegerSchema,
    quickCheck: z.literal("ok"),
    rows: z.record(
      z.string().regex(/^[A-Za-z_][A-Za-z0-9_]{0,127}$/u),
      nonNegativeSafeIntegerSchema,
    ).refine(value => Object.keys(value).length <= 4_096, "too many rows"),
  }).strict(),
  dispatchWorktreeLanes: nonNegativeSafeIntegerSchema,
  harnessWorktreeLanes: nonNegativeSafeIntegerSchema,
  localTaskWorktreeLanes: nonNegativeSafeIntegerSchema,
  sessionEntries: nonNegativeSafeIntegerSchema,
  tree: treeEvidenceSchema,
}).strict();

const identitySchema = (identity: Readonly<{
  build: string;
  bundleIdentifier: string;
  executable: string;
  version: string;
}>) => z.object({
  build: z.literal(identity.build),
  bundleIdentifier: z.literal(identity.bundleIdentifier),
  executable: z.literal(identity.executable),
  version: z.literal(identity.version),
}).strict();

const strictSignatureSchema = z.object({
  policy: z.literal(strictBundleSignaturePolicy),
}).strict();

const historicalSignatureSchema = z.object({
  policy: z.literal(historicalOprtePreviewSignaturePolicy),
  cmsByteLength: z.literal(expectedHistoricalOprtePreviewSignature.cmsByteLength),
  cmsSigningTimeMs: z.literal(
    expectedHistoricalOprtePreviewSignature.cmsSigningTimeMs,
  ),
  codeDirectoryByteLength: z.literal(
    expectedHistoricalOprtePreviewSignature.codeDirectoryByteLength,
  ),
  codeDirectoryCdHash: z.literal(
    expectedHistoricalOprtePreviewSignature.codeDirectoryCdHash,
  ),
  codeDirectorySha256: z.literal(
    expectedHistoricalOprtePreviewSignature.codeDirectorySha256,
  ),
  codeResourcesSha256: z.literal(
    expectedHistoricalOprtePreviewSignature.codeResourcesSha256,
  ),
  designatedRequirement: z.literal(
    expectedHistoricalOprtePreviewSignature.designatedRequirement,
  ),
  executableSha256: z.literal(
    expectedHistoricalOprtePreviewSignature.executableSha256,
  ),
  infoPlistSha256: z.literal(
    expectedHistoricalOprtePreviewSignature.infoPlistSha256,
  ),
  leafCertificateSha1: z.literal(
    expectedHistoricalOprtePreviewSignature.leafCertificateSha1,
  ),
  leafCertificateSha256: z.literal(
    expectedHistoricalOprtePreviewSignature.leafCertificateSha256,
  ),
  leafNotAfterMs: z.literal(
    expectedHistoricalOprtePreviewSignature.leafNotAfterMs,
  ),
  leafNotBeforeMs: z.literal(
    expectedHistoricalOprtePreviewSignature.leafNotBeforeMs,
  ),
  rootCertificateSha1: z.literal(
    expectedHistoricalOprtePreviewSignature.rootCertificateSha1,
  ),
  rootCertificateSha256: z.literal(
    expectedHistoricalOprtePreviewSignature.rootCertificateSha256,
  ),
  rootGroup: z.literal(expectedHistoricalOprtePreviewSignature.rootGroup),
  rootMode: z.literal(expectedHistoricalOprtePreviewSignature.rootMode),
  rootNotAfterMs: z.literal(
    expectedHistoricalOprtePreviewSignature.rootNotAfterMs,
  ),
  rootNotBeforeMs: z.literal(
    expectedHistoricalOprtePreviewSignature.rootNotBeforeMs,
  ),
  rootOwner: z.literal(expectedHistoricalOprtePreviewSignature.rootOwner),
  xattrCount: z.literal(expectedHistoricalOprtePreviewSignature.xattrCount),
  xattrInventorySha256: z.literal(
    expectedHistoricalOprtePreviewSignature.xattrInventorySha256,
  ),
  xattrName: z.literal(expectedHistoricalOprtePreviewSignature.xattrName),
  xattrValueHex: z.literal(
    expectedHistoricalOprtePreviewSignature.xattrValueHex,
  ),
}).strict();

const bundleSchema = (
  identity: Parameters<typeof identitySchema>[0],
  signature: typeof strictSignatureSchema | typeof historicalSignatureSchema,
) => z.object({
  identity: identitySchema(identity),
  signature,
  tree: treeEvidenceSchema,
}).strict();

const candidateSchema = bundleSchema({
  build: "15",
  bundleIdentifier: "kitchen.hraness",
  executable: "hra",
  version: "0.1.14",
}, strictSignatureSchema);

const predecessorSchema = z.object({
  identity: identitySchema(expectedHistoricalOprtePreviewIdentity),
  signature: historicalSignatureSchema,
  tree: z.object({
    bytes: z.literal(expectedHistoricalOprtePreviewTree.bytes),
    directories: z.literal(expectedHistoricalOprtePreviewTree.directories),
    digest: z.literal(expectedHistoricalOprtePreviewTree.digest),
    entries: z.literal(expectedHistoricalOprtePreviewTree.entries),
    files: z.literal(expectedHistoricalOprtePreviewTree.files),
    symlinks: z.literal(expectedHistoricalOprtePreviewTree.symlinks),
  }).strict(),
}).strict();

const priorHraSchema = z.union([
  ["8", "0.1.7"],
  ["9", "0.1.8"],
  ["10", "0.1.9"],
  ["11", "0.1.10"],
  ["13", "0.1.12"],
  ["14", "0.1.13"],
].map(([build, version]) => bundleSchema({
  build: build!,
  bundleIdentifier: "kitchen.hraness",
  executable: "hra",
  version: version!,
}, strictSignatureSchema)) as [
  ReturnType<typeof bundleSchema>,
  ReturnType<typeof bundleSchema>,
  ...ReturnType<typeof bundleSchema>[],
]);

const descriptorSchema = z.string().max(2_048).refine(value => {
  const separator = value.indexOf("\0");
  return separator > 0
    && separator === value.lastIndexOf("\0")
    && separator < value.length - 1;
}, "invalid Keychain descriptor");

const receiptSchema = z.object({
  schemaVersion: z.literal(2),
  createdAt: nonNegativeSafeIntegerSchema,
  operationId: z.string().regex(/^handoff_[0-9a-f]{24}$/u),
  phase: z.enum([
    "created",
    "backed_up",
    "smoked",
    "bundles_archived",
    "candidate_staged",
    "candidate_installed",
    "predecessor_retired",
    "verified",
    "committed",
    "rolled_back",
  ]),
  candidateCommit: z.string().regex(/^[0-9a-f]{40}$/u),
  hadPriorHra: z.boolean(),
  state: stateEvidenceSchema,
  predecessor: predecessorSchema,
  candidate: candidateSchema,
  priorHra: priorHraSchema.optional(),
  keychainDescriptors: z.array(descriptorSchema).max(4_096)
    .superRefine((value, context) => {
      if (new Set(value).size !== value.length) {
        context.addIssue({ code: "custom", message: "duplicate descriptors" });
      }
      const sorted = [...value].sort();
      if (sorted.some((descriptor, index) => descriptor !== value[index])) {
        context.addIssue({ code: "custom", message: "unsorted descriptors" });
      }
    }),
}).strict().superRefine((value, context) => {
  if (value.hadPriorHra !== (value.priorHra !== undefined)) {
    context.addIssue({ code: "custom", message: "prior HRA evidence mismatch" });
  }
});

export function parseFrozenV0114InstallationHandoffReceipt(
  value: unknown,
): FrozenV0114InstallationHandoffReceipt {
  if (containsForbiddenKey(value, new WeakSet<object>())) throw invalidReceipt();
  const parsed = receiptSchema.safeParse(value);
  if (!parsed.success) throw invalidReceipt();
  const { priorHra, ...required } = parsed.data;
  return priorHra === undefined ? required : { ...required, priorHra };
}

function containsForbiddenKey(
  value: unknown,
  seen: WeakSet<object>,
): boolean {
  if (value === null || typeof value !== "object" || seen.has(value)) {
    return false;
  }
  seen.add(value);
  return Object.entries(value).some(([key, child]) =>
    forbiddenKeys.has(key) || containsForbiddenKey(child, seen)
  );
}

function invalidReceipt(): Error {
  return new Error("Frozen v0.1.14 installation-handoff receipt is invalid.");
}
