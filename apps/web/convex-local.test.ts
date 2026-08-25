import { describe, expect, test } from "bun:test";
import { mkdtemp, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";

import {
  anonymousLocalDeployment,
  planLocalConvexLaunch,
  runLocalConvex,
  type LocalConvexExecutor,
} from "./convex-local";

const checkedLauncherInvocation = /\bbun\s+run\s+convex-local\.ts\s+(?:dev|env|init|run)(?=$|[\s;&|()])/gu;
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
    expect(manifest.scripts?.dev).toContain("convex-local.ts");
    expect(manifest.scripts?.["convex:dev"]).toContain("convex-local.ts");
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
      arguments: ["set", "LOCAL_FIXTURE_KEY", "fixture-value"],
      command: "env",
      environment: {},
    }).command.slice(1)).toEqual([
      "env",
      "set",
      "LOCAL_FIXTURE_KEY",
      "fixture-value",
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
    })).toThrow("only one named local set operation");
    expect(() => planLocalConvexLaunch({
      arguments: ["set", "LOCAL_FIXTURE_KEY", "--prod"],
      command: "env",
      environment: {},
    })).toThrow("only one named local set operation");
  });

  test("init cannot accept configuration arguments", () => {
    expect(() => planLocalConvexLaunch({
      arguments: ["--help"],
      command: "init",
      environment: {},
    })).toThrow("init accepts no arguments");
  });
});
