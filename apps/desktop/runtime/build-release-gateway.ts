import { rm } from "node:fs/promises";
import { join } from "node:path";

import { verifyBunCompiler } from "./verify-runtime-pins";
import { verifyReleaseGatewayCodeSignature } from "./release-gateway-code-signature";

async function main(): Promise<void> {
  const compiler = await verifyBunCompiler();
  const output = join(import.meta.dir, "dist/oprte-gateway");
  await rm(output, { force: true });
  const child = Bun.spawn([
    compiler.executable,
    "build",
    "--compile",
    "--minify",
    "--sourcemap=none",
    join(import.meta.dir, "src/main.ts"),
    "--outfile",
    output,
  ], {
    cwd: join(import.meta.dir, ".."),
    env: process.env,
    stderr: "inherit",
    stdout: "inherit",
  });
  const exitCode = await child.exited;
  if (exitCode !== 0) {
    throw new Error(`Pinned Bun gateway compilation failed with exit code ${exitCode}.`);
  }

  // The gateway has no build edge back from either Native executable. Give it
  // its final signature here, then compile the SHA-256 of these exact signed
  // bytes into both the host and custodian. Packaging must copy, not re-sign,
  // this file.
  // Bun emits an ad-hoc signature whose reserved region may be larger than the
  // final signature. Remove it first so codesign zeroes all unused bytes rather
  // than preserving an unverified tail inside LC_CODE_SIGNATURE.
  const removeSignature = Bun.spawn([
    "/usr/bin/codesign",
    "--remove-signature",
    output,
  ], {
    cwd: join(import.meta.dir, ".."),
    env: process.env,
    stderr: "inherit",
    stdout: "inherit",
  });
  const removeSignatureExitCode = await removeSignature.exited;
  if (removeSignatureExitCode !== 0) {
    throw new Error(
      `Compiler gateway signature removal failed with exit code ${removeSignatureExitCode}.`,
    );
  }
  const codesign = Bun.spawn([
    "/usr/bin/codesign",
    "--force",
    "--sign",
    "-",
    "--identifier",
    "oprte-gateway",
    "--options",
    "runtime",
    "--pagesize",
    "16384",
    "--timestamp=none",
    "--entitlements",
    join(import.meta.dir, "gateway.release.entitlements.plist"),
    output,
  ], {
    cwd: join(import.meta.dir, ".."),
    env: process.env,
    stderr: "inherit",
    stdout: "inherit",
  });
  const codesignExitCode = await codesign.exited;
  if (codesignExitCode !== 0) {
    throw new Error(
      `Final gateway signing failed with exit code ${codesignExitCode}.`,
    );
  }
  const verify = Bun.spawn([
    "/usr/bin/codesign",
    "--verify",
    "--strict",
    "--verbose=6",
    output,
  ], {
    cwd: join(import.meta.dir, ".."),
    env: process.env,
    stderr: "inherit",
    stdout: "inherit",
  });
  const verifyExitCode = await verify.exited;
  if (verifyExitCode !== 0) {
    throw new Error(
      `Final gateway signature verification failed with exit code ${verifyExitCode}.`,
    );
  }
  verifyReleaseGatewayCodeSignature(
    new Uint8Array(await Bun.file(output).arrayBuffer()),
  );
}

if (import.meta.main) await main();
