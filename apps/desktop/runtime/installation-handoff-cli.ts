import { constants } from "node:fs";
import { lstat, open } from "node:fs/promises";
import { isAbsolute, join, resolve, sep } from "node:path";

import {
  InstallationHandoffV3Error,
  type InstallationHandoffV3CustodyObservation,
} from "./installation-handoff-v3";
import {
  cleanupCommittedInstallationHandoffV3,
  defaultInstallationHandoffV3DriverDependencies,
  inspectInstallationHandoffV3Status,
  installationHandoffV3CleanupConfirmation,
  installationHandoffV3Confirmation,
  InstallationHandoffV3DriverError,
  installationHandoffV3ResumeConfirmation,
  installationHandoffV3RollbackConfirmation,
  performInstallationHandoffV3,
  resumeInstallationHandoffV3,
  rollbackInstallationHandoffV3,
  type InstallationHandoffV3DriverDependencies,
  type InstallationHandoffV3Input,
  type InstallationHandoffV3RecoveryInput,
  type InstallationHandoffV3Result,
  type InstallationHandoffV3StatusInput,
} from "./installation-handoff-v3-driver";
import {
  inspectResidentEnrollmentCustodyNoUi,
} from "./resident-custody-probe-adapter";

const maximumLegacyReceiptBytes = 1_024 * 1_024;
const maximumLegacyReceiptBytesBigInt = BigInt(maximumLegacyReceiptBytes);
const legacyReceiptFileName = "handoff-receipt.json";

export const installationHandoffCliUsage =
  "Usage: installation-handoff-cli.ts handoff --candidate-app ABS --backup-directory ABS --confirm RETIRE-OPRTE-IN-FAVOR-OF-HRA | status --backup-directory ABS | resume --backup-directory ABS --confirm RESUME-HRA-INSTALLATION-HANDOFF-V3 | rollback --backup-directory ABS --confirm ROLL-BACK-HRA-TO-OPRTE | cleanup --backup-directory ABS --confirm CLEAN-COMMITTED-HRA-HANDOFF-STAGING";

export class InstallationHandoffCliError extends Error {
  readonly code: "invalid_arguments" | "schema_v2_backup";

  constructor(code: InstallationHandoffCliError["code"], message: string) {
    super(message);
    this.name = "InstallationHandoffCliError";
    this.code = code;
  }
}

export type InstallationHandoffCliCommand =
  | Readonly<{
      input: InstallationHandoffV3Input;
      name: "handoff";
    }>
  | Readonly<{
      input: InstallationHandoffV3StatusInput;
      name: "status";
    }>
  | Readonly<{
      input: InstallationHandoffV3RecoveryInput;
      name: "resume" | "rollback" | "cleanup";
    }>;

export interface InstallationHandoffCliOperations {
  readonly cleanup: (
    input: InstallationHandoffV3RecoveryInput,
  ) => Promise<InstallationHandoffV3Result>;
  readonly handoff: (
    input: InstallationHandoffV3Input,
  ) => Promise<InstallationHandoffV3Result>;
  readonly resume: (
    input: InstallationHandoffV3RecoveryInput,
  ) => Promise<InstallationHandoffV3Result>;
  readonly rollback: (
    input: InstallationHandoffV3RecoveryInput,
  ) => Promise<InstallationHandoffV3Result>;
  readonly status: (
    input: InstallationHandoffV3StatusInput,
  ) => Promise<InstallationHandoffV3Result>;
}

export interface InstallationHandoffCliIo {
  readonly writeStderr: (value: string) => void;
  readonly writeStdout: (value: string) => void;
}

export function createInstallationHandoffCliOperations(
  dependencies: InstallationHandoffV3DriverDependencies,
): InstallationHandoffCliOperations {
  return {
    async cleanup(input) {
      return await cleanupCommittedInstallationHandoffV3(input, dependencies);
    },
    async handoff(input) {
      return await performInstallationHandoffV3(input, dependencies);
    },
    async resume(input) {
      return await resumeInstallationHandoffV3(input, dependencies);
    },
    async rollback(input) {
      return await rollbackInstallationHandoffV3(input, dependencies);
    },
    async status(input) {
      return await inspectInstallationHandoffV3Status(input, dependencies);
    },
  };
}

export function parseInstallationHandoffCliArguments(
  args: readonly string[],
): InstallationHandoffCliCommand {
  const [name, ...flags] = args;
  if (name === "handoff" && flags.length === 6) {
    const values = flagValues(flags);
    const confirmation = requireFlag(values, "--confirm");
    requireConfirmation(confirmation, installationHandoffV3Confirmation);
    return {
      input: {
        backupDirectory: requireFlag(values, "--backup-directory"),
        candidateApp: requireFlag(values, "--candidate-app"),
        confirmation,
      },
      name,
    };
  }
  if (name === "status" && flags.length === 2) {
    const values = flagValues(flags);
    return {
      input: {
        backupDirectory: requireFlag(values, "--backup-directory"),
      },
      name,
    };
  }
  if (
    (name === "resume" || name === "rollback" || name === "cleanup")
    && flags.length === 4
  ) {
    const values = flagValues(flags);
    const confirmation = requireFlag(values, "--confirm");
    const expected = name === "resume"
      ? installationHandoffV3ResumeConfirmation
      : name === "rollback"
        ? installationHandoffV3RollbackConfirmation
        : installationHandoffV3CleanupConfirmation;
    requireConfirmation(confirmation, expected);
    return {
      input: {
        backupDirectory: requireFlag(values, "--backup-directory"),
        confirmation,
      },
      name,
    };
  }
  throw invalidArguments();
}

export async function executeInstallationHandoffCli(
  args: readonly string[],
  operations: InstallationHandoffCliOperations,
  schemaTwoProbe: (
    backupDirectory: string,
  ) => Promise<boolean> = containsSchemaTwoHandoffReceipt,
): Promise<InstallationHandoffV3Result> {
  const command = parseInstallationHandoffCliArguments(args);
  if (await schemaTwoProbe(command.input.backupDirectory)) {
    throw schemaTwoBackup(command.name);
  }
  switch (command.name) {
    case "handoff":
      return await operations.handoff(command.input);
    case "status":
      return await operations.status(command.input);
    case "resume":
      return await operations.resume(command.input);
    case "rollback":
      return await operations.rollback(command.input);
    case "cleanup":
      return await operations.cleanup(command.input);
  }
}

export async function runInstallationHandoffCli(
  args: readonly string[],
  operations: InstallationHandoffCliOperations,
  io: InstallationHandoffCliIo,
  schemaTwoProbe?: (backupDirectory: string) => Promise<boolean>,
): Promise<0 | 1> {
  try {
    const result = await executeInstallationHandoffCli(
      args,
      operations,
      schemaTwoProbe,
    );
    io.writeStdout(`${JSON.stringify({ schemaVersion: 3, ...result })}\n`);
    return 0;
  } catch (error: unknown) {
    const failure = cliFailure(error);
    io.writeStderr(`${JSON.stringify({
      schemaVersion: 3,
      status: "error",
      code: failure.code,
      message: failure.message,
    })}\n`);
    return 1;
  }
}

export async function inspectInstallationHandoffCliEnrollmentCustodyNoUi(
  candidateApp: string,
  authority: Parameters<typeof inspectResidentEnrollmentCustodyNoUi>[1],
  inspect: typeof inspectResidentEnrollmentCustodyNoUi =
    inspectResidentEnrollmentCustodyNoUi,
): Promise<InstallationHandoffV3CustodyObservation> {
  try {
    return await inspect(candidateApp, authority);
  } catch {
    // Process-terminal resident failures abort inside the production probe and
    // never return here. Every ordinary adapter rejection that does return is
    // an unavailable custody proof, not a transaction-continuity mismatch.
    throw new InstallationHandoffV3DriverError(
      "custody_unavailable",
      "Exact resident no-UI custody inspection failed.",
    );
  }
}

export async function containsSchemaTwoHandoffReceipt(
  backupDirectory: string,
  beforeOpenForTest?: () => Promise<void> | void,
): Promise<boolean> {
  if (
    !isAbsolute(backupDirectory)
    || resolve(backupDirectory) !== backupDirectory
    || backupDirectory === sep
    || backupDirectory.includes("\0")
  ) return false;
  const path = join(backupDirectory, legacyReceiptFileName);
  let published: Awaited<ReturnType<typeof lstat>>;
  try {
    published = await lstat(path, { bigint: true });
  } catch (error: unknown) {
    if (hasCode(error, "ENOENT")) return false;
    return false;
  }
  if (
    !published.isFile()
    || published.isSymbolicLink()
    || published.size < 1n
    || published.size > maximumLegacyReceiptBytesBigInt
  ) return false;
  const noFollow = typeof constants.O_NOFOLLOW === "number"
    ? constants.O_NOFOLLOW
    : 0;
  const closeOnExecValue: unknown = Reflect.get(constants, "O_CLOEXEC");
  const closeOnExec = typeof closeOnExecValue === "number"
    ? closeOnExecValue
    : 0;
  const nonBlockingValue: unknown = Reflect.get(constants, "O_NONBLOCK");
  if (typeof nonBlockingValue !== "number") return false;
  await beforeOpenForTest?.();
  let handle: Awaited<ReturnType<typeof open>>;
  try {
    handle = await open(
      path,
      constants.O_RDONLY | noFollow | closeOnExec | nonBlockingValue,
    );
  } catch {
    return false;
  }
  try {
    const held = await handle.stat({ bigint: true });
    if (
      !held.isFile()
      || held.isSymbolicLink()
      || held.dev !== published.dev
      || held.ino !== published.ino
      || held.size !== published.size
      || held.size < 1n
      || held.size > maximumLegacyReceiptBytesBigInt
    ) return false;
    const bytes = Buffer.alloc(maximumLegacyReceiptBytes + 1);
    let value: unknown;
    try {
      let total = 0;
      while (total < bytes.byteLength) {
        const read = await handle.read(
          bytes,
          total,
          bytes.byteLength - total,
          total,
        );
        if (read.bytesRead === 0) break;
        total += read.bytesRead;
      }
      if (total !== Number(held.size) || total > maximumLegacyReceiptBytes) {
        return false;
      }
      const [heldAfter, publishedAfter] = await Promise.all([
        handle.stat({ bigint: true }),
        lstat(path, { bigint: true }),
      ]);
      if (
        heldAfter.dev !== held.dev
        || heldAfter.ino !== held.ino
        || heldAfter.size !== held.size
        || publishedAfter.dev !== held.dev
        || publishedAfter.ino !== held.ino
        || publishedAfter.size !== held.size
        || publishedAfter.isSymbolicLink()
      ) return false;
      const text = new TextDecoder("utf-8", { fatal: true }).decode(
        bytes.subarray(0, total),
      );
      value = JSON.parse(text) as unknown;
    } catch {
      return false;
    } finally {
      bytes.fill(0);
    }
    return typeof value === "object"
      && value !== null
      && !Array.isArray(value)
      && Object.hasOwn(value, "schemaVersion")
      && (value as Record<string, unknown>)["schemaVersion"] === 2;
  } finally {
    await handle.close();
  }
}

function flagValues(args: readonly string[]): ReadonlyMap<string, string> {
  const values = new Map<string, string>();
  for (let index = 0; index < args.length; index += 2) {
    const name = args[index];
    const value = args[index + 1];
    if (
      name === undefined
      || value === undefined
      || !name.startsWith("--")
      || values.has(name)
    ) throw invalidArguments();
    values.set(name, value);
  }
  return values;
}

function requireFlag(values: ReadonlyMap<string, string>, name: string): string {
  const value = values.get(name);
  if (value === undefined || value.length === 0) throw invalidArguments();
  return value;
}

function requireConfirmation(actual: string, expected: string): void {
  if (actual !== expected) {
    throw new InstallationHandoffCliError(
      "invalid_arguments",
      `Confirmation must be ${expected}.`,
    );
  }
}

function invalidArguments(): InstallationHandoffCliError {
  return new InstallationHandoffCliError(
    "invalid_arguments",
    installationHandoffCliUsage,
  );
}

function schemaTwoBackup(
  command: InstallationHandoffCliCommand["name"],
): InstallationHandoffCliError {
  const guidance = command === "handoff"
    ? "Choose a new backup directory for the schema-v3 handoff."
    : command === "status"
      ? "Use installation:forward-status only for the exact committed v0.1.14 recovery origin."
      : command === "resume"
        ? "Use installation:forward-resume only for the exact committed v0.1.14 recovery origin."
        : command === "cleanup"
          ? "Use installation:forward-cleanup only for the exact committed v0.1.14 recovery origin."
          : "Schema-v2 rollback is retired; inspect an exact committed v0.1.14 origin with installation:forward-status.";
  return new InstallationHandoffCliError(
    "schema_v2_backup",
    `The backup directory contains a frozen schema-v2 handoff receipt. Ordinary schema-v2 mutation is retired. ${guidance}`,
  );
}

function cliFailure(error: unknown): Readonly<{
  code: string;
  message: string;
}> {
  if (
    error instanceof InstallationHandoffCliError
    || error instanceof InstallationHandoffV3Error
    || error instanceof InstallationHandoffV3DriverError
  ) return error;
  return {
    code: "continuity_failed",
    message: error instanceof Error ? error.message : String(error),
  };
}

function hasCode(error: unknown, code: string): boolean {
  return typeof error === "object"
    && error !== null
    && "code" in error
    && (error as { code?: unknown }).code === code;
}

const productionInstallationHandoffCliOperations =
  createInstallationHandoffCliOperations({
    ...defaultInstallationHandoffV3DriverDependencies,
    inspectEnrollmentKeychainNoUi:
      inspectInstallationHandoffCliEnrollmentCustodyNoUi,
  });

if (import.meta.main) {
  process.exitCode = await runInstallationHandoffCli(
    process.argv.slice(2),
    productionInstallationHandoffCliOperations,
    {
      writeStderr(value) {
        process.stderr.write(value);
      },
      writeStdout(value) {
        process.stdout.write(value);
      },
    },
  );
}
