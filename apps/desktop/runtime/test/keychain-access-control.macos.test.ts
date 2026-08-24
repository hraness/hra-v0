import { expect, test } from "bun:test";
import { mkdtemp, rm } from "node:fs/promises";
import { join, resolve } from "node:path";

const exactReceipt =
  '{"created":true,"customSearchListScoped":true,"deleted":true,"duplicateCreated":false,"loginKeychainChanged":false,"noPromptQueryExact":true,"ok":true,"strictAcl":true,"untrustedSubjectExcluded":true,"version":1}\n';

async function run(
  arguments_: readonly string[],
  timeoutMilliseconds = 30_000,
): Promise<Readonly<{ exitCode: number; stderr: string; stdout: string }>> {
  const child = Bun.spawn([...arguments_], {
    cwd: "/",
    env: { PATH: "/usr/bin:/bin" },
    stderr: "pipe",
    stdout: "pipe",
  });
  const outcome = await Promise.race([
    child.exited.then(exitCode => ({ exitCode, timedOut: false as const })),
    Bun.sleep(timeoutMilliseconds).then(() => ({ exitCode: -1, timedOut: true as const })),
  ]);
  if (outcome.timedOut) child.kill("SIGKILL");
  const [stdout, stderr] = await Promise.all([
    new Response(child.stdout).text(),
    new Response(child.stderr).text(),
  ]);
  if (outcome.timedOut) throw new Error(`Timed out: ${arguments_[0]}`);
  return { exitCode: outcome.exitCode, stderr, stdout };
}

test("strict helper ACL round-trips in an isolated Keychain with an exact sole subject", async () => {
  if (process.platform !== "darwin" || process.arch !== "arm64") {
    throw new Error("The Keychain ACL integration requires Apple Silicon macOS.");
  }
  const root = await mkdtemp("/private/tmp/hra-keychain-acl-test-");
  const owner = join(root, "owner");
  const untrusted = join(root, "untrusted");
  const keychain = join(root, "isolated.keychain-db");
  const fixtureRoot = resolve(import.meta.dir, "fixtures");
  const nativeRoot = resolve(import.meta.dir, "../../src");
  try {
    const untrustedBuild = await run([
      "xcrun", "clang", "-fobjc-arc", "-Wno-deprecated-declarations",
      "-mmacosx-version-min=13.0", "-framework", "Foundation",
      "-framework", "LocalAuthentication",
      "-framework", "Security",
      join(fixtureRoot, "keychain-access-control-untrusted.m"),
      "-o", untrusted,
    ]);
    expect(untrustedBuild).toEqual({ exitCode: 0, stderr: "", stdout: "" });
    const ownerBuild = await run([
      "xcrun", "clang", "-fobjc-arc", "-Wno-deprecated-declarations",
      "-mmacosx-version-min=13.0", "-framework", "Foundation",
      "-framework", "LocalAuthentication",
      "-framework", "Security", "-I", nativeRoot,
      join(fixtureRoot, "keychain-access-control-owner.m"),
      join(nativeRoot, "macos_keychain_access_control.m"),
      "-o", owner,
    ]);
    expect(ownerBuild).toEqual({ exitCode: 0, stderr: "", stdout: "" });
    for (const executable of [owner, untrusted]) {
      const signed = await run([
        "/usr/bin/codesign", "--force", "--sign", "-",
        "--identifier", "org.hraness.hra.keychain-acl-fixture",
        executable,
      ]);
      expect(signed.exitCode).toBe(0);
      expect(signed.stdout).toBe("");
    }
    const result = await run([owner, keychain, untrusted]);
    expect(result).toEqual({ exitCode: 0, stderr: "", stdout: exactReceipt });
  } finally {
    const cleanup = Bun.spawn(["security", "delete-keychain", keychain], {
      cwd: "/",
      env: { PATH: "/usr/bin:/bin" },
      stderr: "ignore",
      stdout: "ignore",
    });
    await cleanup.exited;
    await rm(root, { force: true, recursive: true });
  }
}, 30_000);
