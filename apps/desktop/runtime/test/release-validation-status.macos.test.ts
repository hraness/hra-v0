import { expect, test } from "bun:test";
import { mkdir, mkdtemp, rm, writeFile } from "node:fs/promises";
import { join, resolve } from "node:path";

function run(
  arguments_: readonly string[],
  temporaryDirectory: string,
): Readonly<{ exitCode: number; stderr: string; stdout: string }> {
  const result = Bun.spawnSync([...arguments_], {
    cwd: "/",
    env: { PATH: "/usr/bin:/bin", TMPDIR: temporaryDirectory },
    stderr: "pipe",
    stdout: "pipe",
  });
  return {
    exitCode: result.exitCode,
    stderr: result.stderr.toString(),
    stdout: result.stdout.toString(),
  };
}

function codeSignatureEvidence(
  executable: string,
  temporaryDirectory: string,
): Readonly<{ cdHash: string; flags: number; identifier: string }> {
  const result = run([
    "/usr/bin/codesign",
    "--display",
    "--verbose=4",
    executable,
  ], temporaryDirectory);
  expect(result.exitCode).toBe(0);
  expect(result.stdout).toBe("");
  const cdHash = /^CDHash=([0-9a-f]{40})$/mu.exec(result.stderr)?.[1];
  const flags = /^CodeDirectory .+ flags=0x([0-9a-f]+)\(/mu.exec(
    result.stderr,
  )?.[1];
  const identifier = /^Identifier=([^\n]+)$/mu.exec(result.stderr)?.[1];
  expect(cdHash).toMatch(/^[0-9a-f]{40}$/u);
  expect(flags).toMatch(/^[0-9a-f]+$/u);
  expect(identifier).toBeDefined();
  return {
    cdHash: cdHash!,
    flags: Number.parseInt(flags!, 16),
    identifier: identifier!,
  };
}

async function inspectLiveExecutable(
  inspector: string,
  executable: string,
  expectedPath: string,
  evidence: Readonly<{ cdHash: string; flags: number; identifier: string }>,
  temporaryDirectory: string,
): Promise<Readonly<{ exitCode: number; stderr: string; stdout: string }>> {
  const process_ = Bun.spawn([executable], {
    cwd: "/",
    env: { PATH: "/usr/bin:/bin", TMPDIR: temporaryDirectory },
    stdin: "pipe",
    stderr: "pipe",
    stdout: "pipe",
  });
  try {
    let result = run([
      inspector,
      String(process_.pid),
      expectedPath,
      evidence.identifier,
      evidence.cdHash,
      String(evidence.flags),
    ], temporaryDirectory);
    for (let attempt = 0; result.exitCode !== 0 && attempt < 50; attempt += 1) {
      await Bun.sleep(10);
      result = run([
        inspector,
        String(process_.pid),
        expectedPath,
        evidence.identifier,
        evidence.cdHash,
        String(evidence.flags),
      ], temporaryDirectory);
    }
    return result;
  } finally {
    await process_.stdin.write("G");
    await process_.stdin.end();
    expect(await process_.exited).toBe(0);
  }
}

test.skipIf(process.platform !== "darwin")(
  "closes the private-root status and embedded certificate fallback policies",
  async () => {
    const root = await mkdtemp("/private/tmp/hra-release-validation-status-");
    const executable = join(root, "status-policy");
    const fixture = resolve(
      import.meta.dir,
      "fixtures/release-validation-status.c",
    );
    const nativeRoot = resolve(import.meta.dir, "../../src");
    try {
      const compilation = run([
        "xcrun",
        "clang",
        "-std=c17",
        "-Wall",
        "-Wextra",
        "-Werror",
        "-Wno-deprecated-declarations",
        "-mmacosx-version-min=13.0",
        "-I",
        nativeRoot,
        fixture,
        "-o",
        executable,
      ], root);
      expect({
        exitCode: compilation.exitCode,
        stdout: compilation.stdout,
      }).toEqual({ exitCode: 0, stdout: "" });
      expect(run([executable], root)).toEqual({
        exitCode: 0,
        stderr: "",
        stdout: '{"ok":true,"version":2}\n',
      });
    } finally {
      await rm(root, { force: true, recursive: true });
    }
  },
);

test.skipIf(process.platform !== "darwin")(
  "binds a signed main executable to its enclosing bundle code path",
  async () => {
    const root = await mkdtemp("/private/tmp/hra-release-bundle-path-");
    const app = join(root, "HRA.app");
    const contents = join(app, "Contents");
    const macOS = join(contents, "MacOS");
    const host = join(macOS, "hra");
    const inspector = join(root, "inspect-bundle-path");
    const dynamicInspector = join(root, "inspect-dynamic-path");
    const standalone = join(root, "standalone-helper");
    const fixture = resolve(
      import.meta.dir,
      "fixtures/release-bundle-code-path.m",
    );
    const dynamicFixture = resolve(
      import.meta.dir,
      "fixtures/release-dynamic-code-path.m",
    );
    const nativeRoot = resolve(import.meta.dir, "../../src");
    try {
      await mkdir(macOS, { mode: 0o700, recursive: true });
      await writeFile(join(contents, "Info.plist"), `<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0"><dict>
<key>CFBundleExecutable</key><string>hra</string>
<key>CFBundleIdentifier</key><string>test.hraness.bundle-path</string>
<key>CFBundlePackageType</key><string>APPL</string>
</dict></plist>
`);
      const hostCompilation = run([
        "xcrun",
        "clang",
        "-std=c17",
        "-Wall",
        "-Wextra",
        "-Werror",
        "-mmacosx-version-min=13.0",
        "-DHRA_RELEASE_BUNDLE_PATH_HOST=1",
        fixture,
        "-o",
        host,
      ], root);
      expect({
        exitCode: hostCompilation.exitCode,
        stdout: hostCompilation.stdout,
      }).toEqual({ exitCode: 0, stdout: "" });
      const standaloneCompilation = run([
        "xcrun",
        "clang",
        "-std=c17",
        "-Wall",
        "-Wextra",
        "-Werror",
        "-mmacosx-version-min=13.0",
        "-DHRA_RELEASE_BUNDLE_PATH_HOST=1",
        fixture,
        "-o",
        standalone,
      ], root);
      expect({
        exitCode: standaloneCompilation.exitCode,
        stdout: standaloneCompilation.stdout,
      }).toEqual({ exitCode: 0, stdout: "" });
      const signing = run([
        "/usr/bin/codesign",
        "--force",
        "--sign",
        "-",
        "--options",
        "runtime",
        app,
      ], root);
      expect({ exitCode: signing.exitCode, stdout: signing.stdout }).toEqual({
        exitCode: 0,
        stdout: "",
      });
      const standaloneSigning = run([
        "/usr/bin/codesign",
        "--force",
        "--sign",
        "-",
        "--options",
        "runtime",
        standalone,
      ], root);
      expect({
        exitCode: standaloneSigning.exitCode,
        stdout: standaloneSigning.stdout,
      }).toEqual({ exitCode: 0, stdout: "" });
      const inspectorCompilation = run([
        "xcrun",
        "clang",
        "-fobjc-arc",
        "-Wall",
        "-Wextra",
        "-Werror",
        "-Wno-unguarded-availability-new",
        "-mmacosx-version-min=13.0",
        fixture,
        "-framework",
        "Foundation",
        "-framework",
        "Security",
        "-o",
        inspector,
      ], root);
      expect({
        exitCode: inspectorCompilation.exitCode,
        stdout: inspectorCompilation.stdout,
      }).toEqual({ exitCode: 0, stdout: "" });
      const dynamicInspectorCompilation = run([
        "xcrun",
        "clang",
        "-fobjc-arc",
        "-fno-sanitize=builtin",
        "-Wall",
        "-Wextra",
        "-Werror",
        "-Wno-deprecated-declarations",
        "-Wno-nullability-completeness",
        "-mmacosx-version-min=13.0",
        "-I",
        nativeRoot,
        dynamicFixture,
        join(nativeRoot, "macos_self_managed_code_identity.m"),
        "-framework",
        "Foundation",
        "-framework",
        "Security",
        "-o",
        dynamicInspector,
      ], root);
      expect({
        exitCode: dynamicInspectorCompilation.exitCode,
        stdout: dynamicInspectorCompilation.stdout,
      }).toEqual({ exitCode: 0, stdout: "" });
      expect(run([inspector, host, app, host], root)).toEqual({
        exitCode: 0,
        stderr: "",
        stdout: '{"ok":true,"version":1}\n',
      });
      expect(run([inspector, host, app, inspector], root)).toEqual({
        exitCode: 70,
        stderr: "",
        stdout: "",
      });
      const hostEvidence = codeSignatureEvidence(host, root);
      expect(await inspectLiveExecutable(
        dynamicInspector,
        host,
        host,
        hostEvidence,
        root,
      )).toEqual({
        exitCode: 0,
        stderr: "",
        stdout: '{"ok":true,"version":1}\n',
      });
      expect(await inspectLiveExecutable(
        dynamicInspector,
        host,
        inspector,
        hostEvidence,
        root,
      )).toEqual({ exitCode: 70, stderr: "", stdout: "" });
      const standaloneEvidence = codeSignatureEvidence(standalone, root);
      expect(await inspectLiveExecutable(
        dynamicInspector,
        standalone,
        standalone,
        standaloneEvidence,
        root,
      )).toEqual({
        exitCode: 0,
        stderr: "",
        stdout: '{"ok":true,"version":1}\n',
      });
    } finally {
      await rm(root, { force: true, recursive: true });
    }
  },
  30_000,
);
