import { expect, test } from "bun:test";
import { mkdtemp, rm } from "node:fs/promises";
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
