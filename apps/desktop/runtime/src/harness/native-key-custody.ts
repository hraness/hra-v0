import { createHash, randomBytes } from "node:crypto";

import { z } from "@hra-internal/schema";

import {
  canonicalHarnessInstallKeyEnvelope,
  harnessInstallKeyDescriptor,
  HarnessKeyCustodyError,
  type HarnessEstablishedSecretStore,
  type HarnessSecretDescriptor,
  type HarnessSecretStore,
} from "./key-custody";
import {
  nativeHarnessCustodyFailureStages,
  nativeLegacyHarnessCustodyFailureStages,
  nativeLegacyHarnessCustodyFailureSubstages,
  type NativeHarnessCustodyFailureStage,
  type NativeLegacyHarnessCustodyFailureSubstage,
} from "./native-key-custody-protocol";

export {
  nativeHarnessCustodyFailureStages,
  nativeLegacyHarnessCustodyFailureSubstages,
  type NativeHarnessCustodyFailureStage,
  type NativeLegacyHarnessCustodyFailureSubstage,
} from "./native-key-custody-protocol";

const nativeRequestIdSchema = z.string()
  .regex(/^native-harness-[a-f0-9]{24}$/u);
const nativeBindingSchema = z.string()
  .regex(/^binding_[a-f0-9]{48}$/u);
const canonicalEnvelopeSchema = z.string().min(1).max(256);
const envelopeSha256Schema = z.string().regex(/^[a-f0-9]{64}$/u);

export const nativeHarnessCustodyActionSchema = z.enum([
  "read",
  "validatePreparedAcl",
  "migratePreparedAcl",
  "setIfAbsent",
  "deleteBoth",
]);
export type NativeHarnessCustodyAction = z.infer<
  typeof nativeHarnessCustodyActionSchema
>;

export const nativeHarnessCustodyFailureStageSchema = z.enum(
  nativeHarnessCustodyFailureStages,
);
export const nativeLegacyHarnessCustodyFailureSubstageSchema = z.enum(
  nativeLegacyHarnessCustodyFailureSubstages,
);
const nativeLegacyHarnessCustodyFailureStageSchema = z.enum(
  nativeLegacyHarnessCustodyFailureStages,
);
const nativeNonLegacyHarnessCustodyFailureStageSchema = z.enum(
  nativeHarnessCustodyFailureStages.filter(
    (stage) =>
      !(nativeLegacyHarnessCustodyFailureStages as readonly string[]).includes(
        stage,
      ),
  ) as [
    Exclude<
      NativeHarnessCustodyFailureStage,
      (typeof nativeLegacyHarnessCustodyFailureStages)[number]
    >,
    ...Exclude<
      NativeHarnessCustodyFailureStage,
      (typeof nativeLegacyHarnessCustodyFailureStages)[number]
    >[],
  ],
);

const authenticatedRemovalSchema = z.object({
  operationId: z.string().regex(/^op_[A-Za-z0-9_-]{7,93}$/u),
  previewId: z.string().regex(/^removal_[A-Za-z0-9_-]{7,88}$/u),
  nativeRemovalCapability: z.string().regex(/^[a-f0-9]{64}$/u),
  receiptAuthentication: z.string()
    .regex(/^hmac_sha256_[a-f0-9]{64}$/u),
}).strict();
export type AuthenticatedHarnessCustodyRemoval = z.infer<
  typeof authenticatedRemovalSchema
>;

const nativeHarnessCustodyResultBase = {
  kind: z.literal("harnessCustodyNativeResult"),
  version: z.literal(1),
  nativeRequestId: nativeRequestIdSchema,
  binding: nativeBindingSchema,
} as const;

const nativeHarnessCustodyReadAbsentResultSchema = z.object({
  ...nativeHarnessCustodyResultBase,
  action: z.literal("read"),
  ok: z.literal(true),
  state: z.literal("absent"),
  strictAcl: z.literal(false),
  value: z.null(),
  migratedFromLegacy: z.literal(false),
  legacyPreserved: z.literal(false),
}).strict();

const nativeHarnessCustodyReadPresentResultSchema = z.object({
  ...nativeHarnessCustodyResultBase,
  action: z.literal("read"),
  ok: z.literal(true),
  state: z.literal("present"),
  strictAcl: z.literal(true),
  value: canonicalEnvelopeSchema,
  migratedFromLegacy: z.boolean(),
  legacyPreserved: z.boolean(),
}).strict().superRefine((result, context) => {
  if (result.migratedFromLegacy && !result.legacyPreserved) {
    context.addIssue({
      code: "custom",
      message: "a migrated legacy Harness key must remain preserved",
      path: ["legacyPreserved"],
    });
  }
});

const nativeHarnessCustodySetResultSchema = z.object({
  ...nativeHarnessCustodyResultBase,
  action: z.literal("setIfAbsent"),
  ok: z.literal(true),
  value: canonicalEnvelopeSchema,
  created: z.boolean(),
  strictAcl: z.literal(true),
}).strict();

const nativeHarnessCustodyPreparedMigrationResultSchema = z.object({
  ...nativeHarnessCustodyResultBase,
  action: z.literal("migratePreparedAcl"),
  ok: z.literal(true),
  envelopeSha256: envelopeSha256Schema,
  strictAcl: z.literal(true),
}).strict();

const nativeHarnessCustodyPreparedValidationResultSchema = z.object({
  ...nativeHarnessCustodyResultBase,
  action: z.literal("validatePreparedAcl"),
  ok: z.literal(true),
  envelopeSha256: envelopeSha256Schema,
  validated: z.literal(true),
}).strict();

const nativeHarnessCustodyDeleteResultSchema = z.object({
  ...nativeHarnessCustodyResultBase,
  action: z.literal("deleteBoth"),
  ok: z.literal(true),
  deletedV1: z.boolean(),
  deletedV2: z.boolean(),
  absentV1: z.literal(true),
  absentV2: z.literal(true),
}).strict();

const nativeHarnessCustodyFailureResultSchema = z.object({
  ...nativeHarnessCustodyResultBase,
  action: nativeHarnessCustodyActionSchema,
  ok: z.literal(false),
  failureStage: nativeNonLegacyHarnessCustodyFailureStageSchema,
}).strict();

const nativeLegacyHarnessCustodyFailureResultSchema = z.object({
  ...nativeHarnessCustodyResultBase,
  action: nativeHarnessCustodyActionSchema,
  ok: z.literal(false),
  failureStage: nativeLegacyHarnessCustodyFailureStageSchema,
  legacySubstage: nativeLegacyHarnessCustodyFailureSubstageSchema,
}).strict();

export const nativeHarnessCustodyResultSchema = z.union([
  nativeHarnessCustodyReadAbsentResultSchema,
  nativeHarnessCustodyReadPresentResultSchema,
  nativeHarnessCustodyPreparedValidationResultSchema,
  nativeHarnessCustodyPreparedMigrationResultSchema,
  nativeHarnessCustodySetResultSchema,
  nativeHarnessCustodyDeleteResultSchema,
  nativeHarnessCustodyFailureResultSchema,
  nativeLegacyHarnessCustodyFailureResultSchema,
]);
export type NativeHarnessCustodyResult = z.infer<
  typeof nativeHarnessCustodyResultSchema
>;

export type NativeHarnessCustodyRequestEnvelope = Readonly<{
  kind: "harnessCustodyNativeRequest";
  version: 1;
  request:
    | Readonly<{
        id: string;
        binding: string;
        action: "validatePreparedAcl";
        deadlineUnixMilliseconds: number;
        expectedEnvelopeSha256: string;
      }>
    | Readonly<{
        id: string;
        binding: string;
        action: "migratePreparedAcl";
        deadlineUnixMilliseconds: number;
        expectedEnvelopeSha256: string;
      }>
    | Readonly<{
        id: string;
        binding: string;
        action: "read";
        deadlineUnixMilliseconds: number;
      }>
    | Readonly<{
        id: string;
        binding: string;
        action: "setIfAbsent";
        deadlineUnixMilliseconds: number;
        value: string;
      }>
    | Readonly<{
        id: string;
        binding: string;
        action: "deleteBoth";
        deadlineUnixMilliseconds: number;
        removalCapability: string;
        operationId: string;
        previewId: string;
      }>;
}>;

export type NativeHarnessCustodyRequestWriter = (
  request: NativeHarnessCustodyRequestEnvelope,
) => Promise<void>;

interface PendingNativeHarnessCustodyOperation {
  readonly action: NativeHarnessCustodyAction;
  readonly binding: string;
  readonly resolve: (result: NativeHarnessCustodyResult) => void;
  readonly reject: (error: HarnessKeyCustodyError) => void;
  readonly timer: ReturnType<typeof setTimeout>;
}

export interface NativeHarnessKeyCustodyOptions {
  readonly writeRequest: NativeHarnessCustodyRequestWriter;
  readonly timeoutMs?: number;
}

export type HarnessCustodyMigrationObservation = Readonly<{
  state: "absent" | "present";
  migratedFromLegacy: boolean;
  legacyPreserved: boolean;
  digest: string | null;
}>;

export type NativeHarnessEnrollmentObservation =
  | Readonly<{ state: "absent"; strictAcl: false }>
  | Readonly<{
      envelope: string;
      state: "present";
      strictAcl: true;
    }>;

export type NativeHarnessEnrollmentCreation = Readonly<{
  created: boolean;
  envelope: string;
  strictAcl: true;
}>;

export interface NativeHarnessEnrollmentKeychain {
  inspectExactNoUi(): Promise<NativeHarnessEnrollmentObservation>;
  validatePreparedAcl(
    expectedEnvelopeSha256: string,
  ): Promise<Readonly<{ envelopeSha256: string; validated: true }>>;
  migratePreparedAcl(
    expectedEnvelopeSha256: string,
  ): Promise<Readonly<{ envelopeSha256: string; strictAcl: true }>>;
  createExactIfAbsentNoUi(
    envelope: string,
  ): Promise<NativeHarnessEnrollmentCreation>;
}

const nativeFailures = new WeakMap<
  HarnessKeyCustodyError,
  Readonly<{
    stage: NativeHarnessCustodyFailureStage;
    legacySubstage: NativeLegacyHarnessCustodyFailureSubstage | null;
  }>
>();

function nativeHarnessCustodyFailure(
  stage: NativeHarnessCustodyFailureStage,
  legacySubstage: NativeLegacyHarnessCustodyFailureSubstage | null,
): HarnessKeyCustodyError {
  const error = new HarnessKeyCustodyError("custody_unavailable");
  nativeFailures.set(error, Object.freeze({ stage, legacySubstage }));
  return error;
}

export function nativeHarnessCustodyFailureStage(
  error: unknown,
): NativeHarnessCustodyFailureStage | null {
  return error instanceof HarnessKeyCustodyError
    ? nativeFailures.get(error)?.stage ?? null
    : null;
}

export function nativeHarnessCustodyFailureLegacySubstage(
  error: unknown,
): NativeLegacyHarnessCustodyFailureSubstage | null {
  return error instanceof HarnessKeyCustodyError
    ? nativeFailures.get(error)?.legacySubstage ?? null
    : null;
}

const defaultTimeoutMs = 55_000;
// deleteBoth owns three sequential signed helpers: delete, absence readback,
// and marker cleanup. Its reporter stays outside their aggregate Native fence.
const defaultDeleteTimeoutMs = 165_000;
const defaultMigrationTimeoutMs = 300_000;
const maximumTimeoutMs = 60_000;
const maximumNativeDeadlineMs = 50_000;
const maximumDeleteNativeDeadlineMs = 150_000;
const maximumMigrationNativeDeadlineMs = 270_000;

/**
 * Fixed-descriptor gateway client for the private Native custody lane.
 *
 * The Native side owns v2 Keychain access and the one-time fixed v1 migration.
 * Values cross only the inherited private JSONL pipes. They never enter a
 * renderer response, argv, environment variable, diagnostic, or filesystem.
 */
export class NativeHarnessKeyCustody implements HarnessSecretStore {
  readonly #writeRequest: NativeHarnessCustodyRequestWriter;
  readonly #timeoutMs: number;
  readonly #nativeDeadlineMs: number;
  readonly #deleteTimeoutMs: number;
  readonly #deleteNativeDeadlineMs: number;
  readonly #migrationTimeoutMs: number;
  readonly #migrationNativeDeadlineMs: number;
  readonly #pending = new Map<string, PendingNativeHarnessCustodyOperation>();
  #operationTail: Promise<void> = Promise.resolve();
  #closed = false;

  constructor(options: NativeHarnessKeyCustodyOptions) {
    this.#writeRequest = options.writeRequest;
    const timeoutMs = options.timeoutMs ?? defaultTimeoutMs;
    if (
      !Number.isSafeInteger(timeoutMs)
      || timeoutMs < 2
      || timeoutMs > maximumTimeoutMs
    ) {
      throw new HarnessKeyCustodyError("custody_unavailable");
    }
    this.#timeoutMs = timeoutMs;
    this.#deleteTimeoutMs = options.timeoutMs === undefined
      ? defaultDeleteTimeoutMs
      : timeoutMs;
    this.#migrationTimeoutMs = options.timeoutMs === undefined
      ? defaultMigrationTimeoutMs
      : timeoutMs;
    const reporterGraceMs = Math.min(
      5_000,
      Math.max(1, Math.floor(timeoutMs / 10)),
    );
    this.#nativeDeadlineMs = Math.min(
      maximumNativeDeadlineMs,
      timeoutMs - reporterGraceMs,
    );
    const deleteReporterGraceMs = Math.min(
      15_000,
      Math.max(1, Math.floor(this.#deleteTimeoutMs / 10)),
    );
    this.#deleteNativeDeadlineMs = Math.min(
      maximumDeleteNativeDeadlineMs,
      this.#deleteTimeoutMs - deleteReporterGraceMs,
    );
    const migrationReporterGraceMs = Math.min(
      30_000,
      Math.max(1, Math.floor(this.#migrationTimeoutMs / 10)),
    );
    this.#migrationNativeDeadlineMs = Math.min(
      maximumMigrationNativeDeadlineMs,
      this.#migrationTimeoutMs - migrationReporterGraceMs,
    );
  }

  async get(input: HarnessSecretDescriptor): Promise<string | null> {
    assertCurrentDescriptor(input);
    const result = await this.#enqueue(async () => await this.#request("read"));
    if (!result.ok || result.action !== "read") {
      throw new HarnessKeyCustodyError("custody_unavailable");
    }
    if (result.state === "absent") return null;
    return canonicalHarnessInstallKeyEnvelope(result.value);
  }

  async set(
    input: HarnessSecretDescriptor & { readonly value: string },
  ): Promise<void> {
    assertCurrentDescriptor(input);
    const value = canonicalHarnessInstallKeyEnvelope(input.value);
    const result = await this.#enqueue(async () =>
      await this.#request("setIfAbsent", value)
    );
    if (
      !result.ok
      || result.action !== "setIfAbsent"
      || canonicalHarnessInstallKeyEnvelope(result.value) !== value
    ) {
      throw new HarnessKeyCustodyError("custody_unavailable");
    }
  }

  async inspectEnrollment(): Promise<NativeHarnessEnrollmentObservation> {
    const result = await this.#enqueue(async () => await this.#request("read"));
    if (!result.ok || result.action !== "read") {
      throw new HarnessKeyCustodyError("custody_unavailable");
    }
    if (result.state === "absent") {
      return Object.freeze({ state: "absent", strictAcl: false });
    }
    return Object.freeze({
      envelope: canonicalHarnessInstallKeyEnvelope(result.value),
      state: "present",
      strictAcl: true,
    });
  }

  async createEnrollmentIfAbsent(
    envelopeValue: string,
  ): Promise<NativeHarnessEnrollmentCreation> {
    const envelope = canonicalHarnessInstallKeyEnvelope(envelopeValue);
    const result = await this.#enqueue(async () =>
      await this.#request("setIfAbsent", envelope)
    );
    if (
      !result.ok
      || result.action !== "setIfAbsent"
      || canonicalHarnessInstallKeyEnvelope(result.value) !== result.value
    ) {
      throw new HarnessKeyCustodyError("custody_unavailable");
    }
    return Object.freeze({
      created: result.created,
      envelope: result.value,
      strictAcl: true,
    });
  }

  async migratePreparedEnrollmentAcl(
    expectedEnvelopeSha256: string,
  ): Promise<Readonly<{ envelopeSha256: string; strictAcl: true }>> {
    const expected = envelopeSha256Schema.parse(expectedEnvelopeSha256);
    const result = await this.#enqueue(async () =>
      await this.#request(
        "migratePreparedAcl",
        undefined,
        undefined,
        expected,
      )
    );
    if (
      !result.ok
      || result.action !== "migratePreparedAcl"
      || result.envelopeSha256 !== expected
    ) {
      throw new HarnessKeyCustodyError("custody_unavailable");
    }
    return Object.freeze({
      envelopeSha256: result.envelopeSha256,
      strictAcl: true,
    });
  }

  async validatePreparedEnrollmentAcl(
    expectedEnvelopeSha256: string,
  ): Promise<Readonly<{ envelopeSha256: string; validated: true }>> {
    const expected = envelopeSha256Schema.parse(expectedEnvelopeSha256);
    const result = await this.#enqueue(async () =>
      await this.#request(
        "validatePreparedAcl",
        undefined,
        undefined,
        expected,
      )
    );
    if (
      !result.ok
      || result.action !== "validatePreparedAcl"
      || result.envelopeSha256 !== expected
    ) {
      throw new HarnessKeyCustodyError("custody_unavailable");
    }
    return Object.freeze({
      envelopeSha256: result.envelopeSha256,
      validated: true,
    });
  }

  enrollmentKeychainAdapter(): NativeHarnessEnrollmentKeychain {
    return Object.freeze({
      createExactIfAbsentNoUi: async (envelope: string) =>
        await this.createEnrollmentIfAbsent(envelope),
      inspectExactNoUi: async () => await this.inspectEnrollment(),
      validatePreparedAcl: async (expectedEnvelopeSha256: string) =>
        await this.validatePreparedEnrollmentAcl(expectedEnvelopeSha256),
      migratePreparedAcl: async (expectedEnvelopeSha256: string) =>
        await this.migratePreparedEnrollmentAcl(expectedEnvelopeSha256),
    });
  }

  establishedSecretReader(
    expectedEnvelopeSha256: string,
  ): HarnessEstablishedSecretStore {
    if (!/^[a-f0-9]{64}$/u.test(expectedEnvelopeSha256)) {
      throw new HarnessKeyCustodyError("custody_unavailable");
    }
    return Object.freeze({
      get: async (input: HarnessSecretDescriptor): Promise<string> => {
        assertCurrentDescriptor(input);
        const observation = await this.inspectEnrollment();
        if (
          observation.state !== "present"
          || createHash("sha256")
              .update(observation.envelope, "utf8")
              .digest("hex") !== expectedEnvelopeSha256
        ) {
          throw new HarnessKeyCustodyError("custody_unavailable");
        }
        return observation.envelope;
      },
    });
  }

  delete(input: HarnessSecretDescriptor): Promise<boolean> {
    // Ordinary Harness callers cannot delete custody. The authenticated whole-
    // app removal coordinator uses deleteBothForAuthenticatedRemoval() only
    // after the Harness lifecycle has quiesced every borrower and creator.
    void input;
    return Promise.reject(new HarnessKeyCustodyError("custody_unavailable"));
  }

  async ensureMigrated(): Promise<HarnessCustodyMigrationObservation> {
    const result = await this.#enqueue(async () => await this.#request("read"));
    if (!result.ok || result.action !== "read") {
      throw new HarnessKeyCustodyError("custody_unavailable");
    }
    if (result.state === "absent") {
      return Object.freeze({
        state: "absent",
        migratedFromLegacy: false,
        legacyPreserved: false,
        digest: null,
      });
    }
    const value = canonicalHarnessInstallKeyEnvelope(result.value);
    return Object.freeze({
      state: "present",
      migratedFromLegacy: result.migratedFromLegacy,
      legacyPreserved: result.legacyPreserved,
      digest: createHash("sha256").update(value, "utf8").digest("hex"),
    });
  }

  async deleteBothForAuthenticatedRemoval(
    authorization: AuthenticatedHarnessCustodyRemoval,
  ): Promise<boolean> {
    const authenticated = authenticatedRemovalSchema.parse(authorization);
    const result = await this.#enqueue(async () =>
      await this.#request("deleteBoth", undefined, authenticated)
    );
    if (!result.ok || result.action !== "deleteBoth") {
      throw new HarnessKeyCustodyError("custody_unavailable");
    }
    return result.deletedV1 || result.deletedV2;
  }

  complete(value: unknown): boolean {
    const parsed = nativeHarnessCustodyResultSchema.safeParse(value);
    if (!parsed.success) return false;
    const result = parsed.data;
    const pending = this.#pending.get(result.nativeRequestId);
    if (
      pending === undefined
      || pending.binding !== result.binding
      || pending.action !== result.action
    ) {
      return false;
    }
    this.#pending.delete(result.nativeRequestId);
    clearTimeout(pending.timer);
    if (result.ok) pending.resolve(result);
    else pending.reject(nativeHarnessCustodyFailure(
      result.failureStage,
      "legacySubstage" in result ? result.legacySubstage : null,
    ));
    return true;
  }

  close(): void {
    if (this.#closed) return;
    this.#closed = true;
    for (const pending of this.#pending.values()) {
      clearTimeout(pending.timer);
      pending.reject(new HarnessKeyCustodyError("custody_unavailable"));
    }
    this.#pending.clear();
  }

  #enqueue<T>(operation: () => Promise<T>): Promise<T> {
    const result = this.#operationTail.then(operation);
    this.#operationTail = result.then(() => undefined, () => undefined);
    return result;
  }

  async #request(
    action: NativeHarnessCustodyAction,
    value?: string,
    authenticatedRemoval?: AuthenticatedHarnessCustodyRemoval,
    expectedEnvelopeSha256?: string,
  ): Promise<NativeHarnessCustodyResult> {
    if (
      this.#closed
      || (action === "setIfAbsent") !== (value !== undefined)
      || (action === "deleteBoth") !== (authenticatedRemoval !== undefined)
      || (action === "migratePreparedAcl" || action === "validatePreparedAcl") !==
        (expectedEnvelopeSha256 !== undefined)
    ) {
      throw new HarnessKeyCustodyError("custody_unavailable");
    }
    const id = `native-harness-${randomBytes(12).toString("hex")}`;
    const binding = `binding_${randomBytes(24).toString("hex")}`;
    const isPreparedMigration = action === "migratePreparedAcl"
      || action === "validatePreparedAcl";
    const isAuthenticatedDelete = action === "deleteBoth";
    const nativeDeadlineMs = isPreparedMigration
      ? this.#migrationNativeDeadlineMs
      : isAuthenticatedDelete
      ? this.#deleteNativeDeadlineMs
      : this.#nativeDeadlineMs;
    const reporterTimeoutMs = isPreparedMigration
      ? this.#migrationTimeoutMs
      : isAuthenticatedDelete
      ? this.#deleteTimeoutMs
      : this.#timeoutMs;
    const deadlineUnixMilliseconds = Date.now() + nativeDeadlineMs;
    const result = new Promise<NativeHarnessCustodyResult>((resolve, reject) => {
      const timer = setTimeout(() => {
        if (!this.#pending.delete(id)) return;
        reject(new HarnessKeyCustodyError("custody_unavailable"));
      }, reporterTimeoutMs);
      this.#pending.set(id, { action, binding, resolve, reject, timer });
    });
    const request: NativeHarnessCustodyRequestEnvelope = {
      kind: "harnessCustodyNativeRequest",
      version: 1,
      request: action === "migratePreparedAcl" || action === "validatePreparedAcl"
        ? {
            id,
            binding,
            action,
            deadlineUnixMilliseconds,
            expectedEnvelopeSha256:
              envelopeSha256Schema.parse(expectedEnvelopeSha256),
          }
        : action === "setIfAbsent"
        ? {
            id,
            binding,
            action,
            deadlineUnixMilliseconds,
            value: value as string,
          }
        : action === "deleteBoth"
        ? {
            id,
            binding,
            action,
            deadlineUnixMilliseconds,
            removalCapability:
              (authenticatedRemoval as AuthenticatedHarnessCustodyRemoval)
                .nativeRemovalCapability,
            operationId:
              (authenticatedRemoval as AuthenticatedHarnessCustodyRemoval)
                .operationId,
            previewId:
              (authenticatedRemoval as AuthenticatedHarnessCustodyRemoval)
                .previewId,
          }
        : { id, binding, action, deadlineUnixMilliseconds },
    };
    void Promise.resolve()
      .then(() => this.#writeRequest(request))
      .catch(() => {
        const pending = this.#pending.get(id);
        if (pending === undefined) return;
        this.#pending.delete(id);
        clearTimeout(pending.timer);
        pending.reject(new HarnessKeyCustodyError("custody_unavailable"));
      });
    return await result;
  }
}

function assertCurrentDescriptor(input: HarnessSecretDescriptor): void {
  if (
    input.service !== harnessInstallKeyDescriptor.service
    || input.name !== harnessInstallKeyDescriptor.name
  ) {
    throw new HarnessKeyCustodyError("custody_unavailable");
  }
}
