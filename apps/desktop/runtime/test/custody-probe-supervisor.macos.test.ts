import { describe, expect, test } from "bun:test";
import { constants } from "node:fs";
import {
  chmod,
  copyFile,
  mkdtemp,
  readFile,
  realpath,
  rm,
} from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";

const desktopRoot = join(import.meta.dir, "../..");
const supervisor = join(
  desktopRoot,
  "zig-out/bin/hra-custody-probe-supervisor-test",
);
const candidateSupervisor = join(
  desktopRoot,
  "zig-out/bin/hra-custody-probe-supervisor-candidate",
);
const verifierSupervisor = join(
  desktopRoot,
  "zig-out/bin/hra-custody-probe-supervisor-verifier-test",
);
const fixture = join(
  desktopRoot,
  "zig-out/bin/hra-custody-probe-fixture",
);
const signalLauncher = join(
  desktopRoot,
  "zig-out/bin/hra-custody-probe-signal-launcher",
);

function supervised(arguments_: readonly string[]): string[] {
  return [
    signalLauncher,
    "--lifetime-gate",
    supervisor,
    ...arguments_,
  ];
}

function environment(root: string): Readonly<Record<string, string>> {
  const result: Record<string, string> = {
    LANG: "C",
    LC_ALL: "C",
    PATH: "/usr/bin:/bin",
    TMPDIR: root,
  };
  for (const name of ["HOME", "LOGNAME", "USER"] as const) {
    const value = process.env[name];
    if (value !== undefined && value.length > 0 && !value.includes("\0")) {
      result[name] = value;
    }
  }
  return result;
}

async function fixtureCopy(root: string, name: string): Promise<string> {
  const target = join(root, name);
  await copyFile(fixture, target, constants.COPYFILE_EXCL);
  await chmod(target, 0o755);
  return target;
}

async function requireNoFixtureResidue(root: string): Promise<void> {
  const deadline = Date.now() + 2_000;
  while (true) {
    const result = Bun.spawnSync(
      ["/bin/ps", "-axo", "command="],
      { stderr: "pipe", stdout: "pipe" },
    );
    if (result.exitCode !== 0) {
      throw new Error("Supervisor fixture residue inspection failed.");
    }
    const matching = result.stdout.toString().split("\n")
      .filter(line => line.includes(root));
    if (matching.length === 0) return;
    if (Date.now() >= deadline) {
      throw new Error("Supervisor left an exact fixture process alive.");
    }
    await Bun.sleep(10);
  }
}

async function withFixtureRoot(
  operation: (root: string) => Promise<void>,
): Promise<void> {
  const root = await realpath(
    await mkdtemp(join(tmpdir(), "hra-package-smoke-")),
  );
  await chmod(root, 0o700);
  try {
    await operation(root);
    await requireNoFixtureResidue(root);
  } finally {
    await rm(root, { force: true, recursive: true });
  }
}

describe("native custody probe supervisor", () => {
  test("candidate-owned supervisor excludes the verifier-only rejection mode", () => {
    const result = Bun.spawnSync([
      candidateSupervisor,
      "reject-authorize",
      fixture,
    ], {
      stderr: "pipe",
      stdout: "pipe",
    });
    expect(result.exitCode).toBe(64);
    expect(result.stdout.toString()).toBe("");
    expect(result.stderr.toString()).toBe("");
  });

  test("passes exact canonical authorization and status receipts", async () => {
    await withFixtureRoot(async (root) => {
      const host = await fixtureCopy(root, "hra-success");
      const authorization = Bun.spawnSync(
        supervised(["authorize", host]),
        { env: environment(root), stderr: "pipe", stdout: "pipe" },
      );
      expect(authorization.exitCode).toBe(0);
      expect(authorization.stderr.toString()).toBe("");
      expect(authorization.stdout.toString()).toBe(
        "{\"authorization\":\"hra-parent-v1\"," +
        "\"gatewayFileSha256\":\"0000000000000000000000000000000000000000000000000000000000000000\"," +
        "\"keychainAccessed\":false,\"ok\":true," +
        "\"rendererAuthoritySha256\":\"1111111111111111111111111111111111111111111111111111111111111111\"," +
        "\"version\":1}\n",
      );
      await rm(join(root, "hra-success.pids"));
      const status = Bun.spawnSync(
        supervised(["status", host]),
        { env: environment(root), stderr: "pipe", stdout: "pipe" },
      );
      expect(status.exitCode).toBe(0);
      expect(status.stderr.toString()).toBe("");
      expect(status.stdout.toString()).toBe(
        "{\"schemaVersion\":1,\"state\":\"absent\"}\n",
      );
    });
  });

  test("charges static validation delay to the one admission phase", async () => {
    await withFixtureRoot(async (root) => {
      const host = await fixtureCopy(root, "hra-static-admission-delay");
      const started = performance.now();
      const result = Bun.spawnSync(
        supervised(["authorize", host]),
        { env: environment(root), stderr: "pipe", stdout: "pipe" },
      );
      const elapsed = performance.now() - started;
      expect(result.exitCode).toBe(70);
      expect(result.stderr.toString()).toBe("");
      expect(result.stdout.toString()).toBe("");
      expect(elapsed).toBeGreaterThanOrEqual(1_400);
      expect(elapsed).toBeLessThan(10_000);
      expect(await Bun.file(`${host}.pids`).exists()).toBe(false);
    });
  }, 15_000);

  test("rechecks the admission deadline immediately before GO", async () => {
    await withFixtureRoot(async (root) => {
      const host = await fixtureCopy(
        root,
        "hra-final-admission-delay-success",
      );
      const started = performance.now();
      const result = Bun.spawnSync(
        supervised(["authorize", host]),
        { env: environment(root), stderr: "pipe", stdout: "pipe" },
      );
      const elapsed = performance.now() - started;
      expect(result.exitCode).toBe(70);
      expect(result.stderr.toString()).toBe("");
      expect(result.stdout.toString()).toBe("");
      expect(elapsed).toBeGreaterThanOrEqual(1_400);
      expect(elapsed).toBeLessThan(10_000);
      expect(await Bun.file(`${host}.pids`).exists()).toBe(false);
    });
  }, 15_000);

  test("preserves the inner fd-3 lease when verifier pipes begin at fd 3", async () => {
    await withFixtureRoot(async (root) => {
      const host = await fixtureCopy(root, "hra-success-fd3");
      const result = Bun.spawnSync([
        signalLauncher,
        "--verifier-fd3-collision",
        verifierSupervisor,
        "authorize",
        host,
      ], {
        env: environment(root),
        stderr: "pipe",
        stdout: "pipe",
      });
      expect(result.exitCode).toBe(0);
      expect(result.stderr.toString()).toBe("");
      expect(result.stdout.toString()).toContain(
        "\"authorization\":\"hra-parent-v1\"",
      );
    });
  });

  test("rejects a queued extra byte on the outer candidate lease", async () => {
    await withFixtureRoot(async (root) => {
      const host = await fixtureCopy(root, "hra-outer-extra-byte");
      const result = Bun.spawnSync([
        signalLauncher,
        "--extra-lifetime-gate",
        supervisor,
        "authorize",
        host,
      ], {
        env: environment(root),
        stderr: "pipe",
        stdout: "pipe",
      });
      expect(result.exitCode).toBe(70);
      expect(result.stdout.toString()).toBe("");
      expect(result.stderr.toString()).toBe("");
    });
  });

  test("rejects a queued extra byte on the inner host lease", async () => {
    await withFixtureRoot(async (root) => {
      const host = await fixtureCopy(root, "hra-inner-extra-byte");
      const result = Bun.spawnSync(
        supervised(["authorize", host]),
        { env: environment(root), stderr: "pipe", stdout: "pipe" },
      );
      expect(result.exitCode).toBe(70);
      expect(result.stdout.toString()).toBe("");
      expect(result.stderr.toString()).toBe("");
    });
  });

  test("retires a timed-out host and descendant with one owned group signal", async () => {
    await withFixtureRoot(async (root) => {
      const host = await fixtureCopy(root, "hra-timeout");
      const result = Bun.spawnSync(
        supervised(["authorize", host]),
        { env: environment(root), stderr: "pipe", stdout: "pipe" },
      );
      expect(result.exitCode).toBe(70);
      expect(result.stdout.toString()).toBe("");
      expect(result.stderr.toString()).toBe("");
      expect((await readFile(join(root, "hra-timeout.pids"), "utf8"))
        .trim().split("\n")).toHaveLength(2);
    });
  });

  test("contains a host exec that inherits hostile child-process policy", async () => {
    await withFixtureRoot(async (root) => {
      const host = await fixtureCopy(root, "hra-success-hostile");
      const result = Bun.spawnSync(
        supervised([
          "authorize-hostile-signals",
          signalLauncher,
          host,
        ]),
        { env: environment(root), stderr: "pipe", stdout: "pipe" },
      );
      expect(result.exitCode).toBe(0);
      expect(result.stderr.toString()).toBe("");
      expect(result.stdout.toString()).toContain(
        "\"authorization\":\"hra-parent-v1\"",
      );
      expect((await readFile(
        join(root, "hra-success-hostile.pids"),
        "utf8",
      )).trim().split("\n")).toHaveLength(2);
    });
  });

  test("retires after bounded-output failure instead of abandoning the lease", async () => {
    await withFixtureRoot(async (root) => {
      const host = await fixtureCopy(root, "hra-overflow");
      const result = Bun.spawnSync(
        supervised(["authorize", host]),
        { env: environment(root), stderr: "pipe", stdout: "pipe" },
      );
      expect(result.exitCode).toBe(70);
      expect(result.stdout.toString()).toBe("");
      expect(result.stderr.toString()).toBe("");
    });
  });

  test("converts supervisor cancellation into the same bounded retirement", async () => {
    await withFixtureRoot(async (root) => {
      const host = await fixtureCopy(root, "hra-cancel");
      const result = Bun.spawnSync([
        signalLauncher,
        "--cancel-supervisor-after-marker",
        join(root, "hra-cancel.pids"),
        supervisor,
        "authorize",
        host,
      ], {
        env: environment(root),
        stderr: "pipe",
        stdout: "pipe",
      });
      expect(result.exitCode).toBe(70);
      expect(result.stdout.toString()).toBe("");
      expect(result.stderr.toString()).toBe("");
    });
  });

  test("retires the exact host group when its invoking parent generation exits", async () => {
    await withFixtureRoot(async (root) => {
      const host = await fixtureCopy(root, "hra-parent-exit");
      const marker = join(root, "hra-parent-exit.pids");
      const child = Bun.spawn([
        signalLauncher,
        "--parent-exit-after-marker",
        marker,
        supervisor,
        "authorize",
        host,
      ], {
        env: environment(root),
        stderr: "pipe",
        stdout: "pipe",
      });
      const [exitCode, stdout, stderr] = await Promise.all([
        child.exited,
        new Response(child.stdout).text(),
        new Response(child.stderr).text(),
      ]);
      expect(exitCode).toBe(0);
      expect(stdout).toBe("");
      expect(stderr).toBe("");
      expect((await readFile(marker, "utf8")).trim().split("\n"))
        .toHaveLength(2);
    });
  });

  test("retires when the exact live parent abandons only the outer lifetime writer", async () => {
    await withFixtureRoot(async (root) => {
      const host = await fixtureCopy(root, "hra-outer-writer-loss");
      const marker = join(root, "hra-outer-writer-loss.pids");
      const result = Bun.spawnSync([
        signalLauncher,
        "--abandon-gate-after-marker",
        marker,
        supervisor,
        "authorize",
        host,
      ], {
        env: environment(root),
        stderr: "pipe",
        stdout: "pipe",
      });
      expect(result.exitCode).toBe(70);
      expect(result.stdout.toString()).toBe("");
      expect(result.stderr.toString()).toBe("");
    });
  });

  test("host watcher retires descendants when the inner supervisor crashes", async () => {
    await withFixtureRoot(async (root) => {
      const host = await fixtureCopy(root, "hra-inner-supervisor-crash");
      const marker = join(root, "hra-inner-supervisor-crash.pids");
      const result = Bun.spawnSync([
        signalLauncher,
        "--kill-supervisor-after-marker",
        marker,
        supervisor,
        "authorize",
        host,
      ], {
        env: environment(root),
        stderr: "pipe",
        stdout: "pipe",
      });
      expect(result.exitCode).toBe(0);
      expect(result.stdout.toString()).toBe("");
      expect(result.stderr.toString()).toBe("");
    });
  });

  test("watchdog contains a supervisor stalled after observing outer loss", async () => {
    await withFixtureRoot(async (root) => {
      const host = await fixtureCopy(root, "hra-loss-retirement-stall");
      const marker = join(root, "hra-loss-retirement-stall.pids");
      const result = Bun.spawnSync([
        signalLauncher,
        "--abandon-gate-after-marker",
        marker,
        supervisor,
        "authorize",
        host,
      ], {
        env: environment(root),
        stderr: "pipe",
        stdout: "pipe",
      });
      expect(result.exitCode).toBe(70);
      expect(result.stdout.toString()).toBe("");
      expect(result.stderr.toString()).toBe("");
    });
  });

  test("does not classify a stopped leader as terminal", async () => {
    await withFixtureRoot(async (root) => {
      const host = await fixtureCopy(root, "hra-stopped-leader");
      const result = Bun.spawnSync(
        supervised(["authorize", host]),
        { env: environment(root), stderr: "pipe", stdout: "pipe" },
      );
      expect(result.exitCode).toBe(70);
      expect(result.stdout.toString()).toBe("");
      expect(result.stderr.toString()).toBe("");
    });
  });

  test("owns an intentional smoke dwell through quiescence and reap", async () => {
    await withFixtureRoot(async (root) => {
      const host = await fixtureCopy(root, "hra-success-smoke");
      const result = Bun.spawnSync(
        supervised(["smoke", host, root, "1000"]),
        { env: environment(root), stderr: "pipe", stdout: "pipe" },
      );
      expect(result.exitCode).toBe(0);
      expect(result.stdout.toString()).toBe("");
      expect(result.stderr.toString()).toBe("");
      expect(JSON.parse(
        await readFile(join(root, "gateway-ready.json"), "utf8"),
      )).toMatchObject({ schemaVersion: 1 });
    });
  });
});
