#!/usr/bin/env bun

import { readFile } from "node:fs/promises";
import { fileURLToPath } from "node:url";

const WEB_ROOT = fileURLToPath(new URL("./", import.meta.url));
const DEFAULT_ENV_PATH = fileURLToPath(new URL("./.env", import.meta.url));
const DEFAULT_ENV_LOCAL_PATH = fileURLToPath(new URL("./.env.local", import.meta.url));
const CONVEX_BINARY = fileURLToPath(new URL("./node_modules/.bin/convex", import.meta.url));

export const anonymousLocalDeployment = "anonymous:anonymous-agent" as const;

const deploymentCredentialKeys = new Set([
  "CONVEX_ACCESS_TOKEN",
  ["CONVEX", "DEPLOY", "KEY"].join("_"),
  ["CONVEX", "DEPLOYMENT", "TOKEN"].join("_"),
  "CONVEX_OVERRIDE_ACCESS_TOKEN",
  "CONVEX_PRODUCTION_DEPLOYMENT_NAME",
  "CONVEX_PROVISION_HOST",
  "CONVEX_SELF_HOSTED_ADMIN_KEY",
  "CONVEX_SELF_HOSTED_URL",
]);

const convexUrlKeys = new Set([
  "CONVEX_CLOUD_URL",
  "CONVEX_SITE_URL",
  "CONVEX_URL",
  "CONVEX_VERSION_API_ORIGIN",
  "EXPO_PUBLIC_CONVEX_SITE_URL",
  "EXPO_PUBLIC_CONVEX_URL",
  "NEXT_PUBLIC_CONVEX_SITE_URL",
  "NEXT_PUBLIC_CONVEX_URL",
  "PUBLIC_CONVEX_SITE_URL",
  "PUBLIC_CONVEX_URL",
  "REACT_APP_CONVEX_SITE_URL",
  "REACT_APP_CONVEX_URL",
  "VITE_CONVEX_SITE_URL",
  "VITE_CONVEX_URL",
]);

const safeDevFlags = new Set([
  "--help",
  "--once",
  "--typecheck-components",
  "--until-success",
  "--verbose",
  "-h",
  "-v",
]);
const safeDevStartCommands = new Set([
  "bun run dev:web",
  "bun run test:local",
]);
const safeTailLogModes = new Set(["always", "disable", "pause-on-deploy"]);
const safeTypecheckModes = new Set(["disable", "enable", "try"]);
const safeCodegenModes = new Set(["disable", "enable"]);

export type LocalConvexCommand = "dev" | "env" | "init" | "run";
export type LocalConvexEnvironment = Readonly<Record<string, string | undefined>>;

export type LocalConvexLaunchPlan = {
  readonly command: readonly string[];
  readonly cwd: string;
  readonly environment: Record<string, string | undefined>;
};

export type LocalConvexExecution = {
  readonly exitCode: number;
  readonly stderr: string;
  readonly stdout: string;
};

export type LocalConvexExecutor = (
  plan: LocalConvexLaunchPlan,
  captureOutput: boolean,
) => Promise<LocalConvexExecution>;

type EnvAssignment = {
  readonly key: string;
  readonly line: number;
  readonly value: string;
};

function parseQuotedValue(
  rawValue: string,
  quote: "\"" | "'",
  line: number,
  fileName: string,
): string {
  let value = "";
  let escaped = false;
  for (let index = 1; index < rawValue.length; index += 1) {
    const character = rawValue[index];
    if (quote === "\"" && escaped) {
      value += character === "n" ? "\n" : character === "r" ? "\r" : character;
      escaped = false;
      continue;
    }
    if (quote === "\"" && character === "\\") {
      escaped = true;
      continue;
    }
    if (character === quote) {
      const remainder = rawValue.slice(index + 1).trim();
      if (remainder !== "" && !remainder.startsWith("#")) {
        throw new Error(`HRA v0 local Convex refused malformed ${fileName} line ${line}.`);
      }
      return value;
    }
    value += character;
  }
  throw new Error(`HRA v0 local Convex refused unterminated ${fileName} line ${line}.`);
}

export function parseDotEnv(contents: string, fileName = ".env"): readonly EnvAssignment[] {
  const assignments: EnvAssignment[] = [];
  const lines = contents.replace(/^\uFEFF/u, "").split(/\r?\n/u);
  for (let index = 0; index < lines.length; index += 1) {
    const lineNumber = index + 1;
    const line = lines[index] ?? "";
    if (line.trim() === "" || line.trimStart().startsWith("#")) continue;

    const match = /^(?:\s*export\s+)?\s*([A-Za-z_][A-Za-z0-9_]*)\s*=\s*(.*)$/u.exec(line);
    if (match === null || match[1] === undefined) {
      throw new Error(`HRA v0 local Convex refused malformed ${fileName} line ${lineNumber}.`);
    }
    const rawValue = match[2] ?? "";
    const value = rawValue.startsWith("\"") || rawValue.startsWith("'")
      ? parseQuotedValue(rawValue, rawValue[0] as "\"" | "'", lineNumber, fileName)
      : rawValue.split("#", 1)[0]?.trim() ?? "";
    assignments.push({ key: match[1], line: lineNumber, value });
  }
  return assignments;
}

function isLoopbackConvexUrl(value: string): boolean {
  try {
    const url = new URL(value);
    return (
      (url.protocol === "http:" || url.protocol === "https:")
      && (url.hostname === "127.0.0.1" || url.hostname === "[::1]" || url.hostname === "localhost")
      && url.username === ""
      && url.password === ""
      && url.pathname === "/"
      && url.search === ""
      && url.hash === ""
    );
  } catch {
    return false;
  }
}

function validateEntry(key: string, value: string | undefined, source: string): void {
  if (deploymentCredentialKeys.has(key)) {
    throw new Error(`HRA v0 local Convex refused ${key} from ${source}.`);
  }
  if (key === "CONVEX_DEPLOYMENT") {
    if (value !== undefined && value !== "" && value !== anonymousLocalDeployment) {
      throw new Error(`HRA v0 local Convex refused non-anonymous CONVEX_DEPLOYMENT from ${source}.`);
    }
    return;
  }
  if (key === "CONVEX_AGENT_MODE") {
    if (value !== undefined && value !== "" && value !== "anonymous") {
      throw new Error(`HRA v0 local Convex refused non-anonymous CONVEX_AGENT_MODE from ${source}.`);
    }
    return;
  }
  if (key === "CONVEX_ALLOW_ANONYMOUS") {
    if (value !== undefined && value !== "" && value !== "true") {
      throw new Error(`HRA v0 local Convex refused disabled anonymous mode from ${source}.`);
    }
    return;
  }
  if (convexUrlKeys.has(key) && value !== undefined && value !== "" && !isLoopbackConvexUrl(value)) {
    throw new Error(`HRA v0 local Convex refused non-loopback ${key} from ${source}.`);
  }
}

function parseJsonArgument(value: string | undefined, option: string): void {
  if (value === undefined || value === "") {
    throw new Error(`HRA v0 local Convex ${option} requires a value.`);
  }
  try {
    JSON.parse(value);
  } catch {
    throw new Error(`HRA v0 local Convex ${option} requires JSON.`);
  }
}

function validateDevArguments(arguments_: readonly string[]): void {
  for (let index = 0; index < arguments_.length;) {
    const argument = arguments_[index];
    if (argument !== undefined && safeDevFlags.has(argument)) {
      index += 1;
      continue;
    }
    if (argument === "--tail-logs") {
      const mode = arguments_[index + 1];
      if (mode === undefined || !safeTailLogModes.has(mode)) {
        throw new Error("HRA v0 local Convex --tail-logs received an unsupported mode.");
      }
      index += 2;
      continue;
    }
    if (argument?.startsWith("--tail-logs=") === true) {
      const mode = argument.slice("--tail-logs=".length);
      if (!safeTailLogModes.has(mode)) {
        throw new Error("HRA v0 local Convex --tail-logs received an unsupported mode.");
      }
      index += 1;
      continue;
    }
    if (argument === "--start") {
      const startCommand = arguments_[index + 1];
      if (startCommand === undefined || !safeDevStartCommands.has(startCommand)) {
        throw new Error("HRA v0 local Convex refused an unsupported --start command.");
      }
      index += 2;
      continue;
    }
    throw new Error("HRA v0 local Convex refused an unsupported dev argument.");
  }
}

function validateEnvArguments(arguments_: readonly string[]): void {
  if (
    arguments_.length !== 3
    || arguments_[0] !== "set"
    || !/^[A-Z][A-Z0-9_]{0,127}$/u.test(arguments_[1] ?? "")
    || arguments_[2]?.startsWith("-") === true
  ) {
    throw new Error("HRA v0 local Convex env accepts only one named local set operation.");
  }
}

function validateRunArguments(arguments_: readonly string[]): void {
  if (
    arguments_.length < 2
    || !/^[A-Za-z0-9_./-]+:[A-Za-z0-9_./-]+$/u.test(arguments_[0] ?? "")
  ) {
    throw new Error("HRA v0 local Convex run requires one named function and JSON arguments.");
  }
  parseJsonArgument(arguments_[1], "run arguments");
  const seenOptions = new Set<string>();
  for (let index = 2; index < arguments_.length; index += 2) {
    const option = arguments_[index];
    const value = arguments_[index + 1];
    if (option === undefined || value === undefined || seenOptions.has(option)) {
      throw new Error("HRA v0 local Convex run received an unsupported option.");
    }
    seenOptions.add(option);
    if (option === "--identity") {
      parseJsonArgument(value, option);
      continue;
    }
    if (option === "--typecheck" && safeTypecheckModes.has(value)) continue;
    if (option === "--codegen" && safeCodegenModes.has(value)) continue;
    throw new Error("HRA v0 local Convex run received an unsupported option.");
  }
}

function validateArguments(command: LocalConvexCommand, arguments_: readonly string[]): void {
  if (command === "init") {
    if (arguments_.length > 0) {
      throw new Error("HRA v0 local Convex init accepts no arguments.");
    }
    return;
  }
  if (command === "dev") return validateDevArguments(arguments_);
  if (command === "env") return validateEnvArguments(arguments_);
  validateRunArguments(arguments_);
}

export function planLocalConvexLaunch(options: {
  readonly arguments?: readonly string[];
  readonly command: LocalConvexCommand;
  readonly envContents?: string;
  readonly envLocalContents?: string;
  readonly environment?: LocalConvexEnvironment;
}): LocalConvexLaunchPlan {
  const arguments_ = options.arguments ?? [];
  const environment = options.environment ?? process.env;
  validateArguments(options.command, arguments_);

  for (const [key, value] of Object.entries(environment)) {
    validateEntry(key, value, "the ambient environment");
  }
  for (const assignment of parseDotEnv(options.envContents ?? "", ".env")) {
    validateEntry(assignment.key, assignment.value, `.env line ${assignment.line}`);
  }
  for (const assignment of parseDotEnv(options.envLocalContents ?? "", ".env.local")) {
    validateEntry(assignment.key, assignment.value, `.env.local line ${assignment.line}`);
  }

  const childEnvironment: Record<string, string | undefined> = { ...environment };
  for (const key of deploymentCredentialKeys) delete childEnvironment[key];
  childEnvironment.CONVEX_AGENT_MODE = "anonymous";
  childEnvironment.CONVEX_ALLOW_ANONYMOUS = "true";
  childEnvironment.CONVEX_DEPLOYMENT = anonymousLocalDeployment;

  return {
    command: [CONVEX_BINARY, options.command, ...arguments_],
    cwd: WEB_ROOT,
    environment: childEnvironment,
  };
}

async function readOptionalEnvFile(path: string): Promise<string | undefined> {
  try {
    return await readFile(path, "utf8");
  } catch (error: unknown) {
    if (typeof error === "object" && error !== null && "code" in error && error.code === "ENOENT") {
      return undefined;
    }
    throw error;
  }
}

export async function prepareLocalConvexLaunch(options: {
  readonly arguments?: readonly string[];
  readonly command: LocalConvexCommand;
  readonly envPath?: string;
  readonly envLocalPath?: string;
  readonly environment?: LocalConvexEnvironment;
}): Promise<LocalConvexLaunchPlan> {
  const [envContents, envLocalContents] = await Promise.all([
    readOptionalEnvFile(options.envPath ?? DEFAULT_ENV_PATH),
    readOptionalEnvFile(options.envLocalPath ?? DEFAULT_ENV_LOCAL_PATH),
  ]);
  return planLocalConvexLaunch({
    ...(options.arguments === undefined ? {} : { arguments: options.arguments }),
    command: options.command,
    ...(envContents === undefined ? {} : { envContents }),
    ...(envLocalContents === undefined ? {} : { envLocalContents }),
    ...(options.environment === undefined ? {} : { environment: options.environment }),
  });
}

async function defaultExecutor(
  plan: LocalConvexLaunchPlan,
  captureOutput: boolean,
): Promise<LocalConvexExecution> {
  const child = Bun.spawn([...plan.command], {
    cwd: plan.cwd,
    env: plan.environment,
    stdin: "inherit",
    stdout: captureOutput ? "pipe" : "inherit",
    stderr: captureOutput ? "pipe" : "inherit",
  });
  if (!captureOutput) return { exitCode: await child.exited, stderr: "", stdout: "" };
  const [exitCode, stdout, stderr] = await Promise.all([
    child.exited,
    new Response(child.stdout).text(),
    new Response(child.stderr).text(),
  ]);
  return { exitCode, stderr, stdout };
}

export async function runLocalConvex(options: {
  readonly arguments?: readonly string[];
  readonly captureOutput?: boolean;
  readonly command: LocalConvexCommand;
  readonly envPath?: string;
  readonly envLocalPath?: string;
  readonly environment?: LocalConvexEnvironment;
  readonly execute?: LocalConvexExecutor;
}): Promise<LocalConvexExecution> {
  const plan = await prepareLocalConvexLaunch(options);
  return await (options.execute ?? defaultExecutor)(plan, options.captureOutput ?? false);
}

function parseCommand(value: string | undefined): LocalConvexCommand {
  if (value === "dev" || value === "env" || value === "init" || value === "run") return value;
  throw new Error(
    "Usage: bun run convex-local.ts <dev|env|init|run> [checked local Convex arguments]",
  );
}

if (import.meta.main) {
  try {
    const [rawCommand, ...arguments_] = process.argv.slice(2);
    const result = await runLocalConvex({
      arguments: arguments_,
      command: parseCommand(rawCommand),
    });
    process.exitCode = result.exitCode;
  } catch (error: unknown) {
    console.error(error instanceof Error ? error.message : "HRA v0 local Convex refused an invalid launch.");
    process.exitCode = 1;
  }
}
