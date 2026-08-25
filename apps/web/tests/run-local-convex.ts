#!/usr/bin/env bun
import { runLocalConvex } from "../convex-local";

const SUCCESS_MARKER = "✓ local Convex black-box acceptance passed";

async function main(): Promise<void> {
  const { exitCode, stderr, stdout } = await runLocalConvex({
    arguments: [
      "--once",
      "--tail-logs",
      "disable",
      "--start",
      "bun run test:local",
    ],
    captureOutput: true,
    command: "dev",
  });
  if (stdout.length > 0) process.stdout.write(stdout);
  if (stderr.length > 0) process.stderr.write(stderr);
  const successes = stdout.split(SUCCESS_MARKER).length - 1;
  if (exitCode !== 0) {
    throw new Error(`Convex local acceptance supervisor exited with code ${exitCode}.`);
  }
  if (successes !== 1) {
    throw new Error("Convex local acceptance child did not publish exactly one success marker.");
  }
}

try {
  await main();
} catch (error: unknown) {
  console.error(error instanceof Error ? error.message : "Convex local acceptance failed.");
  process.exitCode = 1;
}
