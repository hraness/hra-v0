import { describe, expect, test } from "bun:test";
import { mkdtemp, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";

import {
  anonymousLocalDeployment,
  dispatchLocalConvexCli,
  localConvexAuthorityTombstoneKeys,
  parseDotEnv,
  parseLocalConvexCommand,
  planLocalConvexLaunch,
  readBoundedLocalConvexStdin,
  runLocalConvex,
  type LocalConvexExecutor,
} from "./convex-local";

const checkedLauncherInvocation = /\bbun\s+run\s+convex-local\.ts\s+(?:dev|env|run)(?=$|[\s;&|()])/gu;
const rawConvexAuthorityInvocation = /(?:^|[\s;&|()])(?:(?:bunx|npx)(?:\s+--[^\s;&|()]+)*\s+|(?:bun|pnpm|yarn)\s+(?:x|dlx)\s+|node\s+)?[^\s;&|()]*convex[^\s;&|()]*\s+(?:codegen|deploy|dev|env|init|run)(?=$|[\s;&|()])/iu;

function containsRawConvexAuthority(script: string): boolean {
  return rawConvexAuthorityInvocation.test(
    script.replace(checkedLauncherInvocation, "checked-local-convex"),
  );
}

describe("HRA v0 anonymous local Convex boundary", () => {
  test("package scripts expose no direct Convex deploy command", async () => {
    const manifest = await Bun.file(new URL("./package.json", import.meta.url)).json() as {
      scripts?: Record<string, string>;
    };
    for (const [name, script] of Object.entries(manifest.scripts ?? {})) {
      const nameTokens = name.toLowerCase().split(/[:._-]/u);
      if (name !== "provider:create-convex-deploy-key") {
        expect(nameTokens.includes("convex") && nameTokens.includes("deploy")).toBe(false);
      }
      expect(containsRawConvexAuthority(script)).toBe(false);
    }
    expect(manifest.scripts?.["provider:create-convex-deploy-key"])
      .toBe("bun run scripts/create-convex-deploy-key.ts");
    expect(manifest.scripts?.["convex:init"]).toBeUndefined();
    expect(manifest.scripts?.dev).toContain("convex-local.ts");
    expect(manifest.scripts?.["convex:dev"]).toContain("convex-local.ts");
    expect(manifest.scripts?.["convex:dev:once"])
      .toBe("bun run convex-local.ts dev --once --tail-logs disable");
  });

  test("acceptance helpers route every local env value through checked stdin", async () => {
    for (const path of [
      "./tests/local-convex.ts",
      "./tests/human-local-runner.ts",
    ] as const) {
      const source = await Bun.file(new URL(path, import.meta.url)).text();
      expect(source.match(/["']env["']\s*,\s*["']set["']/gu) ?? []).toHaveLength(1);
      expect(source).toContain('spawnConvex(["env", "set", name]');
      expect(source).toMatch(/stdinText:\s*`\$\{value\}\\n`/u);
      expect(source).toContain("await runLocalConvex({");
    }
  });

  test("detects raw, pinned, runner-mediated, and path-based Convex authority", () => {
    expect(containsRawConvexAuthority(
      "bun run convex-local.ts dev --once --tail-logs disable",
    )).toBe(false);
    for (const script of [
      "convex dev",
      "convex@1.31.6 dev",
      "./node_modules/.bin/convex dev",
      "bunx --bun convex@latest dev",
      "npx convex deploy",
      "bun x convex@1.31.6 deploy",
      "node ./node_modules/convex/bin/main.js dev",
      "CONVEX_AGENT_MODE=anonymous ./node_modules/.bin/convex dev",
      "bun run convex-local.ts dev --once && convex deploy",
    ]) {
      expect(containsRawConvexAuthority(script)).toBe(true);
    }
  });

  test("forces the checked anonymous selector and web-local binary", () => {
    const plan = planLocalConvexLaunch({
      arguments: ["--once", "--tail-logs", "disable"],
      command: "dev",
      environment: {
        CONVEX_AGENT_MODE: "anonymous",
        CONVEX_DEPLOYMENT: anonymousLocalDeployment,
        NEXT_PUBLIC_CONVEX_URL: "http://127.0.0.1:3210",
      },
      envContents: `CONVEX_DEPLOYMENT=${anonymousLocalDeployment}\n`,
      envLocalContents: "NEXT_PUBLIC_CONVEX_SITE_URL=http://localhost:3211\n",
    });

    expect(plan.command[0]).toEndWith("/apps/web/node_modules/.bin/convex");
    expect(plan.command.slice(1)).toEqual(["dev", "--once", "--tail-logs", "disable"]);
    expect(plan.environment.CONVEX_AGENT_MODE).toBe("anonymous");
    expect(plan.environment.CONVEX_ALLOW_ANONYMOUS).toBe("true");
    expect(plan.environment.CONVEX_DEPLOYMENT).toBe(anonymousLocalDeployment);
    for (const key of localConvexAuthorityTombstoneKeys) {
      expect(plan.environment[key]).toBe("");
    }
  });

  test("pins empty authority tombstones across a dotenv rewrite after preflight", async () => {
    const directory = await mkdtemp(join(tmpdir(), "hra-v0-convex-local-race-"));
    const envPath = join(directory, ".env");
    const envLocalPath = join(directory, ".env.local");
    const targetName = "LOCAL_FIXTURE_KEY";
    await Promise.all([
      writeFile(envPath, "", "utf8"),
      writeFile(envLocalPath, "", "utf8"),
    ]);

    let launches = 0;
    const execute: LocalConvexExecutor = async (plan) => {
      launches += 1;
      const changedDotEnv = [
        ...localConvexAuthorityTombstoneKeys.map((key, index) => `${key}=takeover-${index}`),
        "CONVEX_AGENT_MODE=cloud",
        "CONVEX_ALLOW_ANONYMOUS=false",
        "CONVEX_DEPLOYMENT=prod:takeover-deployment",
        `${targetName}=takeover-target`,
        "",
      ].join("\n");
      await writeFile(envLocalPath, changedDotEnv, "utf8");

      // Convex loads .env.local again in the child without overriding keys
      // already present in process.env. Simulate that exact second read after
      // the checked parent has finished its preflight.
      const childEnvironment = { ...plan.environment };
      for (const assignment of parseDotEnv(changedDotEnv, ".env.local")) {
        if (childEnvironment[assignment.key] === undefined) {
          childEnvironment[assignment.key] = assignment.value;
        }
      }
      for (const key of localConvexAuthorityTombstoneKeys) {
        expect(childEnvironment[key]).toBe("");
      }
      expect(childEnvironment[targetName]).toBe("");
      expect(childEnvironment.CONVEX_AGENT_MODE).toBe("anonymous");
      expect(childEnvironment.CONVEX_ALLOW_ANONYMOUS).toBe("true");
      expect(childEnvironment.CONVEX_DEPLOYMENT).toBe(anonymousLocalDeployment);
      return { exitCode: 0, stderr: "", stdout: "" };
    };

    try {
      await runLocalConvex({
        arguments: ["set", targetName],
        command: "env",
        environment: {},
        envPath,
        envLocalPath,
        execute,
        stdinText: "checked-value\n",
      });
      expect(launches).toBe(1);
    } finally {
      await rm(directory, { force: true, recursive: true });
    }
  });

  for (const fileName of [".env", ".env.local"] as const) {
    test(`${fileName} cloud selection causes zero subprocesses`, async () => {
      const directory = await mkdtemp(join(tmpdir(), "hra-v0-convex-local-"));
      const envPath = join(directory, ".env");
      const envLocalPath = join(directory, ".env.local");
      await writeFile(
        fileName === ".env" ? envPath : envLocalPath,
        "CONVEX_DEPLOYMENT=dev:careful-otter-123\n",
        "utf8",
      );
      let launches = 0;
      const execute: LocalConvexExecutor = async () => {
        launches += 1;
        return { exitCode: 0, stderr: "", stdout: "" };
      };
      try {
        await expect(runLocalConvex({
          command: "dev",
          environment: {},
          envPath,
          envLocalPath,
          execute,
        })).rejects.toThrow("non-anonymous CONVEX_DEPLOYMENT");
        expect(launches).toBe(0);
      } finally {
        await rm(directory, { force: true, recursive: true });
      }
    });
  }

  test("rejects credentials, self-hosted coordinates, and remote public URLs without values", () => {
    for (const [key, value] of [
      ["CONVEX_ACCESS_TOKEN", "do-not-print"],
      [["CONVEX", "DEPLOY", "KEY"].join("_"), "prod:secret-project|do-not-print"],
      [["CONVEX", "DEPLOYMENT", "TOKEN"].join("_"), "do-not-print"],
      ["CONVEX_OVERRIDE_ACCESS_TOKEN", "do-not-print"],
      ["CONVEX_PROVISION_HOST", "https://remote.internal"],
      ["CONVEX_SELF_HOSTED_ADMIN_KEY", "do-not-print"],
      ["CONVEX_SELF_HOSTED_URL", "http://remote.internal"],
      ["CONVEX_CLOUD_URL", "https://production.convex.cloud"],
      ["CONVEX_VERSION_API_ORIGIN", "https://remote.internal"],
      ["NEXT_PUBLIC_CONVEX_URL", "https://production.convex.cloud"],
    ] as const) {
      let message = "";
      try {
        planLocalConvexLaunch({ command: "dev", environment: { [key]: value } });
      } catch (error: unknown) {
        message = String(error);
      }
      expect(message).toContain(key);
      expect(message).not.toContain(value);
    }
  });

  test("rejects cloud and alternate local selectors", () => {
    for (const selector of [
      "dev:careful-otter-123",
      "preview:feature-branch",
      "prod:benevolent-akita-439",
      "local:linked-project",
      "anonymous:another-name",
    ]) {
      expect(() => planLocalConvexLaunch({
        command: "dev",
        environment: { CONVEX_DEPLOYMENT: selector },
      })).toThrow("non-anonymous CONVEX_DEPLOYMENT");
    }
  });

  test("rejects selector-changing and future unknown arguments", () => {
    for (const argument of [
      "--configure=existing",
      "--deployment",
      "--dev-deployment=cloud",
      "--env-file=.env.production",
      "--prod",
      "--project=hra-v0",
      "--url=https://production.convex.cloud",
      "--future-cloud-target=production",
    ]) {
      expect(() => planLocalConvexLaunch({
        arguments: [argument],
        command: "dev",
        environment: {},
      })).toThrow("unsupported dev argument");
    }
  });

  test("accepts only the closed local env and fixture-run shapes", () => {
    expect(planLocalConvexLaunch({
      arguments: ["set", "LOCAL_FIXTURE_KEY"],
      command: "env",
      environment: {},
    }).command.slice(1)).toEqual([
      "env",
      "set",
      "LOCAL_FIXTURE_KEY",
    ]);
    expect(planLocalConvexLaunch({
      arguments: [
        "localFixtures:inspect",
        "{}",
        "--identity",
        "{}",
        "--typecheck",
        "disable",
        "--codegen",
        "disable",
      ],
      command: "run",
      environment: {},
    }).command.slice(1)).toEqual([
      "run",
      "localFixtures:inspect",
      "{}",
      "--identity",
      "{}",
      "--typecheck",
      "disable",
      "--codegen",
      "disable",
    ]);
    expect(() => planLocalConvexLaunch({
      arguments: ["get", "PRODUCTION_SECRET"],
      command: "env",
      environment: {},
    })).toThrow("provide the value through stdin");
    expect(() => planLocalConvexLaunch({
      arguments: ["set", "LOCAL_FIXTURE_KEY", "secret-in-argv"],
      command: "env",
      environment: {},
    })).toThrow("provide the value through stdin");
  });

  test("passes local environment values only through stdin and redacts echoes", async () => {
    const secret = "fixture-secret-that-must-not-enter-argv\n";
    let observedCapture = false;
    let observedPlan = "";
    let observedStdin: string | undefined;
    const execute: LocalConvexExecutor = async (plan, captureOutput, stdinText) => {
      observedCapture = captureOutput;
      observedPlan = JSON.stringify(plan);
      observedStdin = stdinText;
      return {
        exitCode: 0,
        stderr: `provider repeated ${secret.trimEnd()}`,
        stdout: secret,
      };
    };

    const result = await runLocalConvex({
      arguments: ["set", "LOCAL_FIXTURE_KEY"],
      command: "env",
      environment: { LOCAL_FIXTURE_KEY: secret.trimEnd() },
      execute,
      stdinText: secret,
    });

    expect(observedCapture).toBe(true);
    expect(observedStdin).toBe(secret);
    expect(observedPlan).not.toContain(secret.trimEnd());
    expect(result.stdout).toContain("[REDACTED]");
    expect(result.stderr).toContain("[REDACTED]");
    expect(result.stdout).not.toContain(secret.trimEnd());
    expect(result.stderr).not.toContain(secret.trimEnd());
  });

  test("bounds and strictly decodes stdin before forwarding an env value", async () => {
    const first = new TextEncoder().encode("split-");
    const second = new TextEncoder().encode("value\n");
    expect(await readBoundedLocalConvexStdin(new ReadableStream({
      start(controller) {
        controller.enqueue(first);
        controller.enqueue(second);
        controller.close();
      },
    }))).toBe("split-value\n");

    let cancelled = false;
    const oversized = new ReadableStream<Uint8Array>({
      start(controller) {
        controller.enqueue(new Uint8Array(65_537));
      },
      cancel() {
        cancelled = true;
      },
    });
    await expect(readBoundedLocalConvexStdin(oversized)).rejects.toThrow("oversized stdin");
    expect(cancelled).toBe(true);

    await expect(readBoundedLocalConvexStdin(new ReadableStream({
      start(controller) {
        controller.enqueue(Uint8Array.of(0xff));
        controller.close();
      },
    }))).rejects.toThrow("non-UTF-8 stdin");
  });

  test("the real CLI dispatch reads and captures only env stdin, then emits redacted output", async () => {
    const directory = await mkdtemp(join(tmpdir(), "hra-v0-convex-local-cli-"));
    const envPath = join(directory, ".env");
    const envLocalPath = join(directory, ".env.local");
    await Promise.all([
      writeFile(envPath, "", "utf8"),
      writeFile(envLocalPath, "", "utf8"),
    ]);
    const secret = "dispatch-secret-that-must-not-escape\n";
    const stdout: string[] = [];
    const stderr: string[] = [];
    let stdinReads = 0;
    let envCapture: boolean | undefined;
    let envStdin: string | undefined;
    let runCapture: boolean | undefined;
    let runStdin: string | undefined;

    const io = {
      readStdin: async () => {
        stdinReads += 1;
        return secret;
      },
      writeError: (value: string) => stderr.push(value),
      writeOutput: (value: string) => stdout.push(value),
    };

    try {
      expect(await dispatchLocalConvexCli({
        arguments: ["env", "set", "LOCAL_FIXTURE_KEY"],
        environment: {},
        envPath,
        envLocalPath,
        execute: async (plan, captureOutput, stdinText) => {
          envCapture = captureOutput;
          envStdin = stdinText;
          expect(JSON.stringify(plan)).not.toContain(secret.trimEnd());
          return {
            exitCode: 0,
            stderr: `stderr repeated ${secret.trimEnd()}\n`,
            stdout: `stdout repeated ${secret}`,
          };
        },
        io,
      })).toBe(0);
      expect(stdinReads).toBe(1);
      expect(envCapture).toBe(true);
      expect(envStdin).toBe(secret);
      expect(stdout.join("")).toContain("stdout repeated [REDACTED]");
      expect(stderr.join("")).toContain("stderr repeated [REDACTED]");
      expect(stdout.join("")).not.toContain(secret.trimEnd());
      expect(stderr.join("")).not.toContain(secret.trimEnd());

      const outputBeforeRun = [...stdout];
      const errorBeforeRun = [...stderr];
      expect(await dispatchLocalConvexCli({
        arguments: ["run", "localFixtures:inspect", "{}"],
        environment: {},
        envPath,
        envLocalPath,
        execute: async (_plan, captureOutput, stdinText) => {
          runCapture = captureOutput;
          runStdin = stdinText;
          return { exitCode: 0, stderr: "inherited-stderr", stdout: "inherited-stdout" };
        },
        io,
      })).toBe(0);
      expect(stdinReads).toBe(1);
      expect(runCapture).toBe(false);
      expect(runStdin).toBeUndefined();
      expect(stdout).toEqual(outputBeforeRun);
      expect(stderr).toEqual(errorBeforeRun);
    } finally {
      await rm(directory, { force: true, recursive: true });
    }
  });

  test("rejects non-env stdin and the removed init command before launching", async () => {
    let launches = 0;
    const execute: LocalConvexExecutor = async () => {
      launches += 1;
      return { exitCode: 0, stderr: "", stdout: "" };
    };
    await expect(runLocalConvex({
      arguments: ["localFixtures:inspect", "{}"],
      command: "run",
      environment: {},
      execute,
      stdinText: "secret-on-wrong-command",
    })).rejects.toThrow("stdin values only for checked env set operations");
    expect(() => parseLocalConvexCommand("init")).toThrow("checked local Convex arguments");
    expect(() => parseLocalConvexCommand("deploy")).toThrow("checked local Convex arguments");
    expect(launches).toBe(0);
  });
});
