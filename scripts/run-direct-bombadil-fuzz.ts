const workspaceDirectories = ["apps/desktop", "apps/web"] as const;
const argumentsToForward = process.argv.slice(2);

for (const workspace of workspaceDirectories) {
  const child = Bun.spawn(
    [
      process.execPath,
      "run",
      "--cwd",
      workspace,
      "fuzz:direct:uncoordinated",
      ...argumentsToForward,
    ],
    {
      cwd: process.cwd(),
      env: process.env,
      stderr: "inherit",
      stdin: "inherit",
      stdout: "inherit",
    },
  );
  const exitCode = await child.exited;
  if (exitCode !== 0) {
    process.exitCode = exitCode;
    break;
  }
}
