import { cp, lstat, mkdir, realpath, rm } from "node:fs/promises";
import { join, resolve } from "node:path";

import { macosPackage } from "./macos-package-config";
import { packageMacOS } from "./package-macos";
import { withStructuralSigningFixture } from "./structural-release-signing";

async function main(): Promise<void> {
  if (process.argv.length !== 2) {
    throw new Error("Usage: package-macos-structural.ts");
  }
  const structuralRoot = resolve(
    macosPackage.desktopRoot,
    "zig-out/structural",
  );
  const expectedPrefix = `${resolve(macosPackage.desktopRoot, "zig-out")}/`;
  if (!structuralRoot.startsWith(expectedPrefix)) {
    throw new Error("Structural package root escaped zig-out.");
  }
  const packageRoot = join(structuralRoot, "package");
  const appRoot = join(packageRoot, "HRA-structural.app");
  const source = await realpath(macosPackage.appBundlePath);
  const sourceStatus = await lstat(source);
  if (!sourceStatus.isDirectory() || sourceStatus.isSymbolicLink()) {
    throw new Error("Structural package source is not a real app directory.");
  }
  await rm(structuralRoot, { force: true, recursive: true });
  await mkdir(packageRoot, { mode: 0o700, recursive: true });
  await cp(source, appRoot, {
    force: false,
    preserveTimestamps: true,
    recursive: true,
    verbatimSymlinks: true,
  });
  await withStructuralSigningFixture(context => packageMacOS(context, {
    appRoot,
    packageRoot,
  }));
}

if (import.meta.main) await main();
