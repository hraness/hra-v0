import { afterEach, describe, expect, test } from "bun:test";
import { mkdir, mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";

import {
  containsSchemaTwoHandoffReceipt,
  executeInstallationHandoffCli,
  inspectInstallationHandoffCliEnrollmentCustodyNoUi,
  installationHandoffCliUsage,
  parseInstallationHandoffCliArguments,
  runInstallationHandoffCli,
  type InstallationHandoffCliCommand,
  type InstallationHandoffCliOperations,
} from "../installation-handoff-cli";
import { testCustodyProbeSupervisorAuthority } from
  "./fixtures/custody-probe-authority";
import {
  InstallationHandoffV3Error,
} from "../installation-handoff-v3";
import {
  installationHandoffV3CleanupConfirmation,
  installationHandoffV3Confirmation,
  installationHandoffV3ResumeConfirmation,
  installationHandoffV3RollbackConfirmation,
  type InstallationHandoffV3Result,
} from "../installation-handoff-v3-driver";

const roots: string[] = [];

afterEach(async () => {
  for (const root of roots.splice(0)) {
    await rm(root, { force: true, recursive: true });
  }
});

describe("schema-v3 installation handoff CLI", () => {
  test("routes all five commands with their exact confirmations", async () => {
    const calls: Array<Readonly<{
      input: InstallationHandoffCliCommand["input"];
      name: InstallationHandoffCliCommand["name"];
    }>> = [];
    const operations = recordingOperations(calls);
    for (const testCase of commandCases()) {
      const parsed = parseInstallationHandoffCliArguments(testCase.args);
      expect(parsed).toEqual(testCase.command);
      expect((await executeInstallationHandoffCli(
        testCase.args,
        operations,
        () => Promise.resolve(false),
      )).backupDirectory).toBe(testCase.command.input.backupDirectory);
    }
    expect(calls).toEqual(commandCases().map(testCase => testCase.command));
  });

  test("rejects missing, duplicate, unknown, extra, and inexact arguments", () => {
    for (const args of [
      [],
      ["handoff"],
      [
        "handoff",
        "--candidate-app",
        "/tmp/HRA.app",
        "--backup-directory",
        "/tmp/backup",
        "--confirm",
        "wrong",
      ],
      [
        "status",
        "--backup-directory",
        "/tmp/backup",
        "--confirm",
        installationHandoffV3ResumeConfirmation,
      ],
      ["status", "--unknown", "/tmp/backup"],
      [
        "resume",
        "--backup-directory",
        "/tmp/backup",
        "--backup-directory",
        "/tmp/other",
      ],
      [
        "rollback",
        "--backup-directory",
        "/tmp/backup",
        "--confirm",
        installationHandoffV3CleanupConfirmation,
      ],
      [
        "cleanup",
        "--backup-directory",
        "/tmp/backup",
        "--confirm",
        installationHandoffV3RollbackConfirmation,
      ],
    ]) {
      expect(() => parseInstallationHandoffCliArguments(args)).toThrow();
    }
    expect(() => parseInstallationHandoffCliArguments([])).toThrow(
      installationHandoffCliUsage,
    );
  });

  test("gives every ordinary command a targeted schema-v2 backup error", async () => {
    const root = await mkdtemp(join(tmpdir(), "hra-v3-cli-schema2-"));
    roots.push(root);
    const backupDirectory = join(root, "backup");
    await mkdir(backupDirectory, { mode: 0o700 });
    await writeFile(
      join(backupDirectory, "handoff-receipt.json"),
      `${JSON.stringify({ schemaVersion: 2 })}\n`,
      { mode: 0o600 },
    );
    expect(await containsSchemaTwoHandoffReceipt(backupDirectory)).toBeTrue();
    const calls: Parameters<typeof recordingOperations>[0] = [];
    const operations = recordingOperations(calls);
    const guidance = {
      cleanup: "installation:forward-cleanup",
      handoff: "new backup directory",
      resume: "installation:forward-resume",
      rollback: "Schema-v2 rollback is retired",
      status: "installation:forward-status",
    } as const;
    for (const testCase of commandCases(backupDirectory)) {
      let failure: unknown;
      try {
        await executeInstallationHandoffCli(testCase.args, operations);
      } catch (error: unknown) {
        failure = error;
      }
      expect(failure).toMatchObject({ code: "schema_v2_backup" });
      expect(failure).toBeInstanceOf(Error);
      if (failure instanceof Error) {
        expect(failure.message).toContain(guidance[testCase.command.name]);
      }
    }
    expect(calls).toEqual([]);
  });

  test("does not classify malformed, unsafe, or schema-v3 leaves as schema-v2", async () => {
    const root = await mkdtemp(join(tmpdir(), "hra-v3-cli-non-v2-"));
    roots.push(root);
    const backupDirectory = join(root, "backup");
    await mkdir(backupDirectory, { mode: 0o700 });
    const receiptPath = join(backupDirectory, "handoff-receipt.json");
    await writeFile(receiptPath, "not json\n", { mode: 0o600 });
    expect(await containsSchemaTwoHandoffReceipt(backupDirectory)).toBeFalse();
    await writeFile(receiptPath, `${JSON.stringify({ schemaVersion: 3 })}\n`);
    expect(await containsSchemaTwoHandoffReceipt(backupDirectory)).toBeFalse();
    await rm(receiptPath);
    await mkdir(receiptPath);
    expect(await containsSchemaTwoHandoffReceipt(backupDirectory)).toBeFalse();
  });

  test("does not block when a regular receipt is swapped for a FIFO before open", async () => {
    const root = await mkdtemp(join(tmpdir(), "hra-v3-cli-fifo-race-"));
    roots.push(root);
    const backupDirectory = join(root, "backup");
    await mkdir(backupDirectory, { mode: 0o700 });
    const receiptPath = join(backupDirectory, "handoff-receipt.json");
    await writeFile(
      receiptPath,
      `${JSON.stringify({ schemaVersion: 2 })}\n`,
      { mode: 0o600 },
    );
    let unblockTimer: ReturnType<typeof setTimeout> | undefined;
    const started = performance.now();
    const classified = await containsSchemaTwoHandoffReceipt(
      backupDirectory,
      async () => {
        await rm(receiptPath);
        const created = Bun.spawnSync(["/usr/bin/mkfifo", receiptPath], {
          stderr: "pipe",
          stdout: "pipe",
        });
        expect(created.exitCode).toBe(0);
        // If O_NONBLOCK regresses, a delayed writer releases the test instead
        // of hanging the suite; the elapsed-time assertion still fails.
        unblockTimer = setTimeout(() => {
          void writeFile(receiptPath, "unblock\n").catch(() => undefined);
        }, 2_000);
      },
    );
    if (unblockTimer !== undefined) clearTimeout(unblockTimer);
    expect(classified).toBeFalse();
    expect(performance.now() - started).toBeLessThan(1_000);
  });

  test("emits one canonical schema-v3 JSON record for success and failure", async () => {
    const stdout: string[] = [];
    const stderr: string[] = [];
    const io = {
      writeStderr(value: string) {
        stderr.push(value);
      },
      writeStdout(value: string) {
        stdout.push(value);
      },
    };
    expect(await runInstallationHandoffCli(
      ["status", "--backup-directory", "/tmp/backup"],
      recordingOperations([]),
      io,
      () => Promise.resolve(false),
    )).toBe(0);
    expect(JSON.parse(stdout[0]!)).toMatchObject({
      backupDirectory: "/tmp/backup",
      schemaVersion: 3,
      status: "in_progress",
    });
    expect(stderr).toEqual([]);

    stdout.length = 0;
    expect(await runInstallationHandoffCli(
      [],
      recordingOperations([]),
      io,
    )).toBe(1);
    expect(stdout).toEqual([]);
    expect(JSON.parse(stderr[0]!)).toEqual({
      schemaVersion: 3,
      status: "error",
      code: "invalid_arguments",
      message: installationHandoffCliUsage,
    });
  });

  test("preserves every direct v3 storage failure code in canonical JSON", async () => {
    for (const code of [
      "backup_invalid",
      "candidate_invalid",
      "continuity_failed",
      "custody_unavailable",
      "filesystem_unsafe",
      "recovery_conflict",
    ] as const) {
      const stdout: string[] = [];
      const stderr: string[] = [];
      const message = `synthetic ${code}`;
      const operations: InstallationHandoffCliOperations = {
        ...recordingOperations([]),
        status: () => Promise.reject(new InstallationHandoffV3Error(
          code,
          message,
        )),
      };
      expect(await runInstallationHandoffCli(
        ["status", "--backup-directory", "/tmp/backup"],
        operations,
        {
          writeStderr(value) {
            stderr.push(value);
          },
          writeStdout(value) {
            stdout.push(value);
          },
        },
        () => Promise.resolve(false),
      )).toBe(1);
      expect(stdout).toEqual([]);
      expect(stderr).toHaveLength(1);
      expect(JSON.parse(stderr[0]!)).toEqual({
        schemaVersion: 3,
        status: "error",
        code,
        message,
      });
    }
  });

  test("classifies a resident adapter rejection as unavailable custody", async () => {
    const stdout: string[] = [];
    const stderr: string[] = [];
    const operations: InstallationHandoffCliOperations = {
      ...recordingOperations([]),
      async status() {
        await inspectInstallationHandoffCliEnrollmentCustodyNoUi(
          "/Applications/HRA.app",
          testCustodyProbeSupervisorAuthority,
          () => Promise.reject(new Error("synthetic adapter failure")),
        );
        throw new Error("unreachable");
      },
    };
    expect(await runInstallationHandoffCli(
      ["status", "--backup-directory", "/tmp/backup"],
      operations,
      {
        writeStderr(value) {
          stderr.push(value);
        },
        writeStdout(value) {
          stdout.push(value);
        },
      },
      () => Promise.resolve(false),
    )).toBe(1);
    expect(stdout).toEqual([]);
    expect(stderr).toHaveLength(1);
    expect(JSON.parse(stderr[0]!)).toEqual({
      schemaVersion: 3,
      status: "error",
      code: "custody_unavailable",
      message: "Exact resident no-UI custody inspection failed.",
    });
  });

  test("keeps the v2 operator out of the ordinary command surface", async () => {
    const [facade, legacy, forward, desktopPackageText, rootPackageText] =
      await Promise.all([
      readFile(join(import.meta.dir, "../installation-handoff-cli.ts"), "utf8"),
      readFile(join(import.meta.dir, "../installation-handoff.ts"), "utf8"),
      readFile(join(import.meta.dir, "../installation-forward-recovery.ts"), "utf8"),
      readFile(join(import.meta.dir, "../../package.json"), "utf8"),
      readFile(join(import.meta.dir, "../../../../package.json"), "utf8"),
    ]);
    expect(facade).toContain('from "./installation-handoff-v3-driver"');
    expect(facade).toContain('from "./resident-custody-probe-adapter"');
    expect(facade).not.toContain('from "./installation-handoff"');
    expect(facade).not.toContain('from "./macos-resident-custody-probe"');
    expect(facade).toContain(
      "inspectEnrollmentKeychainNoUi:\n      inspectInstallationHandoffCliEnrollmentCustodyNoUi",
    );
    expect(legacy).not.toContain("if (import.meta.main)");
    expect(forward).toContain("parseFrozenV0114InstallationHandoffReceipt");
    expect(forward).not.toContain("parseInstallationHandoffJournal");
    const desktopScripts = packageScripts(desktopPackageText);
    const rootScripts = packageScripts(rootPackageText);
    for (const command of [
      "handoff",
      "status",
      "resume",
      "rollback",
      "cleanup",
    ]) {
      expect(desktopScripts[`installation:${command}`]).toBe(
        `bun run runtime/installation-handoff-cli.ts ${command}`,
      );
      expect(rootScripts[`installation:${command}`]).toBe(
        `bun run --cwd apps/desktop installation:${command} --`,
      );
    }
    expect(desktopScripts["installation:forward-recovery"]).toBe(
      "bun run runtime/installation-forward-recovery.ts forward",
    );
  });
});

function commandCases(
  backupDirectory = "/tmp/backup",
): readonly Readonly<{
  args: readonly string[];
  command: InstallationHandoffCliCommand;
}>[] {
  return [
    {
      args: [
        "handoff",
        "--candidate-app",
        "/tmp/HRA.app",
        "--backup-directory",
        backupDirectory,
        "--confirm",
        installationHandoffV3Confirmation,
      ],
      command: {
        input: {
          backupDirectory,
          candidateApp: "/tmp/HRA.app",
          confirmation: installationHandoffV3Confirmation,
        },
        name: "handoff",
      },
    },
    {
      args: ["status", "--backup-directory", backupDirectory],
      command: { input: { backupDirectory }, name: "status" },
    },
    {
      args: [
        "resume",
        "--backup-directory",
        backupDirectory,
        "--confirm",
        installationHandoffV3ResumeConfirmation,
      ],
      command: {
        input: {
          backupDirectory,
          confirmation: installationHandoffV3ResumeConfirmation,
        },
        name: "resume",
      },
    },
    {
      args: [
        "rollback",
        "--backup-directory",
        backupDirectory,
        "--confirm",
        installationHandoffV3RollbackConfirmation,
      ],
      command: {
        input: {
          backupDirectory,
          confirmation: installationHandoffV3RollbackConfirmation,
        },
        name: "rollback",
      },
    },
    {
      args: [
        "cleanup",
        "--backup-directory",
        backupDirectory,
        "--confirm",
        installationHandoffV3CleanupConfirmation,
      ],
      command: {
        input: {
          backupDirectory,
          confirmation: installationHandoffV3CleanupConfirmation,
        },
        name: "cleanup",
      },
    },
  ];
}

function recordingOperations(
  calls: Array<Readonly<{
    input: InstallationHandoffCliCommand["input"];
    name: InstallationHandoffCliCommand["name"];
  }>>,
): InstallationHandoffCliOperations {
  const record = (
    name: InstallationHandoffCliCommand["name"],
    input: InstallationHandoffCliCommand["input"],
  ) => {
    calls.push({ input, name });
    return Promise.resolve(result(input.backupDirectory));
  };
  return {
    cleanup: input => record("cleanup", input),
    handoff: input => record("handoff", input),
    resume: input => record("resume", input),
    rollback: input => record("rollback", input),
    status: input => record("status", input),
  };
}

function result(backupDirectory: string): InstallationHandoffV3Result {
  return {
    backupDirectory,
    disposition: "prestage",
    keychainContinuity: "not_applicable",
    operationId: `handoff_${"a".repeat(24)}`,
    phase: "created",
    stateDigest: "b".repeat(64),
    status: "in_progress",
  };
}

function packageScripts(text: string): Readonly<Record<string, unknown>> {
  const value: unknown = JSON.parse(text);
  if (!isRecord(value) || !isRecord(value["scripts"])) {
    throw new Error("Package scripts are invalid.");
  }
  return value["scripts"];
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object"
    && value !== null
    && !Array.isArray(value);
}
