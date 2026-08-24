import { resolve } from "node:path";

import { macosPackage } from "./macos-package-config";

export const macosCustodyProbeMaximumOutputBytes = 1_024 as const;

const custodyProbeSupervisor = resolve(
  macosPackage.desktopRoot,
  "zig-out/bin/hra-custody-probe-supervisor",
);
const custodyProbeSignalLauncher = resolve(
  macosPackage.desktopRoot,
  "zig-out/bin/hra-custody-probe-signal-launcher",
);

export type MacOSCustodyProbeArguments =
  | readonly ["authorize", executable: string]
  | readonly ["reject-authorize", executable: string]
  | readonly ["status", executable: string]
  | readonly [
    "smoke",
    executable: string,
    smokeRoot: string,
    dwellMilliseconds: string,
  ];

export type MacOSCustodyProbeResult = Readonly<{
  exitCode: number;
  stderr: string;
  stdout: string;
}>;

export type MacOSCustodyStatus =
  | Readonly<{ schemaVersion: 1; state: "absent" }>
  | Readonly<{
    envelopeSha256: string;
    schemaVersion: 1;
    state: "present";
    strictAcl: true;
  }>;

function custodyProbeEnvironment(): Readonly<Record<string, string>> {
  const environment: Record<string, string> = {
    LANG: "C",
    LC_ALL: "C",
    PATH: "/usr/bin:/bin",
  };
  for (const name of ["HOME", "LOGNAME", "TMPDIR", "USER"] as const) {
    const value = process.env[name];
    if (value !== undefined && value.length > 0 && !value.includes("\0")) {
      environment[name] = value;
    }
  }
  return environment;
}

export function runMacOSCustodyProbe(
  arguments_: MacOSCustodyProbeArguments,
): MacOSCustodyProbeResult {
  const result = Bun.spawnSync(
    [custodyProbeSupervisor, ...arguments_],
    {
      cwd: macosPackage.desktopRoot,
      env: custodyProbeEnvironment(),
      stderr: "pipe",
      stdin: "ignore",
      stdout: "pipe",
    },
  );
  if (
    result.stdout.byteLength > macosCustodyProbeMaximumOutputBytes
    || result.stderr.byteLength > macosCustodyProbeMaximumOutputBytes
  ) {
    throw new Error("Native packaged-host probe exceeded its output bound.");
  }
  return Object.freeze({
    exitCode: result.exitCode,
    stderr: result.stderr.toString(),
    stdout: result.stdout.toString(),
  });
}

export function requireSuccessfulMacOSCustodyProbe(
  arguments_: MacOSCustodyProbeArguments,
): Readonly<{ stderr: ""; stdout: string }> {
  const result = runMacOSCustodyProbe(arguments_);
  if (result.exitCode !== 0 || result.stderr !== "") {
    throw new Error(
      `Native packaged-host probe failed (exit=${result.exitCode}, stdoutBytes=${Buffer.byteLength(result.stdout)}, stderrBytes=${Buffer.byteLength(result.stderr)}).`,
    );
  }
  return Object.freeze({ stderr: "", stdout: result.stdout });
}

export function requireSuccessfulMacOSCustodyProbeWithHostileInheritedSignals(
  executable: string,
): Readonly<{ stderr: ""; stdout: string }> {
  const result = Bun.spawnSync(
    [
      custodyProbeSupervisor,
      "authorize-hostile-signals",
      custodyProbeSignalLauncher,
      executable,
    ],
    {
      cwd: macosPackage.desktopRoot,
      env: custodyProbeEnvironment(),
      stderr: "pipe",
      stdin: "ignore",
      stdout: "pipe",
    },
  );
  if (
    result.stdout.byteLength > macosCustodyProbeMaximumOutputBytes
    || result.stderr.byteLength > macosCustodyProbeMaximumOutputBytes
    || result.exitCode !== 0
    || result.stderr.byteLength !== 0
  ) {
    throw new Error(
      `Native hostile-policy packaged-host probe failed (exit=${result.exitCode}, stdoutBytes=${result.stdout.byteLength}, stderrBytes=${result.stderr.byteLength}).`,
    );
  }
  return Object.freeze({ stderr: "", stdout: result.stdout.toString() });
}

export function parseCanonicalMacOSCustodyStatus(
  text: string,
): MacOSCustodyStatus {
  const absent = "{\"schemaVersion\":1,\"state\":\"absent\"}\n";
  if (text === absent) {
    return Object.freeze({ schemaVersion: 1, state: "absent" });
  }
  const match = /^\{"envelopeSha256":"([0-9a-f]{64})","schemaVersion":1,"state":"present","strictAcl":true\}\n$/u
    .exec(text);
  if (match === null) {
    throw new Error("Native custody status receipt is not canonical.");
  }
  return Object.freeze({
    envelopeSha256: match[1]!,
    schemaVersion: 1,
    state: "present",
    strictAcl: true,
  });
}
