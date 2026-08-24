import { describe, expect, test } from "bun:test";
import { readFile } from "node:fs/promises";
import { join } from "node:path";

import {
  codeSignatureHasExactRequirement,
  codeSignatureHasNoEntitlements,
  type PackageSigningContext,
  extractExactReleaseCmsCertificateChain,
  parseCodeSignatureDetails,
  releaseKeychainControlCodesignArguments,
  releaseCmsHasNoTimeAttributes,
  runBoundedSigningCommand,
  type SigningCommandProcess,
  type SigningCommandTimer,
  verifyProductionSigningUsability,
} from "../package-macos";
import {
  loadProductionReleaseAuthority,
  productionReleaseAuthorityPins,
  productionReleaseSigning,
  releaseDesignatedRequirement,
} from "../release-signing-authority";

const encoder = new TextEncoder();

function der(tag: number, ...children: readonly Buffer[]): Buffer {
  const value = Buffer.concat(children);
  const length = value.length < 128
    ? Buffer.from([value.length])
    : value.length < 256
    ? Buffer.from([0x81, value.length])
    : Buffer.from([0x82, value.length >>> 8, value.length & 0xff]);
  return Buffer.concat([Buffer.from([tag]), length, value]);
}

function releaseCmsFixture(certificates: readonly Buffer[]): Buffer {
  const signedData = der(
    0x30,
    der(0x02, Buffer.from([1])),
    der(0x31),
    der(0x30),
    der(0xa0, ...certificates),
    der(0x31),
  );
  return der(
    0x30,
    der(0x06, Buffer.from("2a864886f70d010702", "hex")),
    der(0xa0, signedData),
  );
}

const inertTimer: SigningCommandTimer = Object.freeze({
  clear: () => undefined,
  schedule: () => Symbol("inert signing-command deadline"),
});

function output(text: string): ReadableStream<Uint8Array> {
  return new ReadableStream<Uint8Array>({
    start(controller) {
      if (text.length > 0) controller.enqueue(encoder.encode(text));
      controller.close();
    },
  });
}

function completedProcess(options: Readonly<{
  exitCode: number;
  stderr?: string;
  stdout?: string;
}>): Readonly<{
  child: SigningCommandProcess;
  kills: NodeJS.Signals[];
}> {
  const kills: NodeJS.Signals[] = [];
  return {
    child: {
      exited: Promise.resolve(options.exitCode),
      killProcessGroup: signal => kills.push(signal),
      stderr: output(options.stderr ?? ""),
      stdout: output(options.stdout ?? ""),
    },
    kills,
  };
}

async function rejectionMessage(action: () => Promise<unknown>): Promise<string> {
  try {
    await action();
  } catch (error: unknown) {
    expect(error).toBeInstanceOf(Error);
    return (error as Error).message;
  }
  throw new Error("Expected the action to reject.");
}

async function fixtureContext(): Promise<PackageSigningContext> {
  return {
    authority: await loadProductionReleaseAuthority(),
    designatedRequirement: releaseDesignatedRequirement,
    identity: productionReleaseAuthorityPins.leafSha1,
    keychain: "/private/custody/release-signing.keychain-db",
    label: "production",
    manifestSigning: productionReleaseSigning,
    sign: () => Promise.resolve(),
  };
}

describe("production release-signing usability preflight", () => {
  test("rejects every CMS signing-time and timestamp-token OID", () => {
    const cms = (oid: string): Buffer => {
      const value = Buffer.from(oid, "hex");
      return Buffer.from([0x30, value.length + 2, 0x06, value.length, ...value]);
    };
    expect(releaseCmsHasNoTimeAttributes(cms("2a864886f70d010702"))).toBeTrue();
    for (const oid of [
      "2a864886f70d010905",
      "2a864886f70d0109100104",
      "2a864886f70d010910020e",
    ]) {
      expect(releaseCmsHasNoTimeAttributes(cms(oid))).toBeFalse();
    }
    expect(releaseCmsHasNoTimeAttributes(Buffer.from([0x30, 0x80, 0, 0])))
      .toBeFalse();
  });

  test("extracts only one canonical two-certificate CMS chain", () => {
    const leaf = der(0x30, der(0x02, Buffer.from([1])));
    const root = der(0x30, der(0x02, Buffer.from([2])));
    const exact = releaseCmsFixture([leaf, root]);
    const certificates = extractExactReleaseCmsCertificateChain(exact);
    expect(certificates[0]).toEqual(leaf);
    expect(certificates[1]).toEqual(root);
    expect(() => extractExactReleaseCmsCertificateChain(
      releaseCmsFixture([root, leaf]),
    )).toThrow("Release CMS certificate DER order differs.");
    expect(() => extractExactReleaseCmsCertificateChain(
      releaseCmsFixture([leaf, leaf]),
    )).toThrow("Release CMS certificate DER order differs.");
    expect(() => extractExactReleaseCmsCertificateChain(
      releaseCmsFixture([leaf, root, der(0x30)]),
    )).toThrow("Release CMS certificate inventory differs.");
    expect(() => extractExactReleaseCmsCertificateChain(
      der(0x30, der(0x06, Buffer.from("2a864886f70d010701", "hex"))),
    )).toThrow("Release CMS signed-data wrapper differs.");
    expect(() => extractExactReleaseCmsCertificateChain(Buffer.concat([
      Buffer.from([0x3f, 0x10]),
      exact.subarray(1),
    ]))).toThrow("Release CMS time posture or DER structure differs.");
    expect(() => extractExactReleaseCmsCertificateChain(
      exact.subarray(0, -1),
    )).toThrow("Release CMS time posture or DER structure differs.");
  });

  test("distinguishes bounded CMS signatures from ad hoc signatures", () => {
    expect(parseCodeSignatureDetails("Signature size=3857\n").signatureKind)
      .toBe("cms");
    expect(parseCodeSignatureDetails("Signature=adhoc\n").signatureKind)
      .toBe("adhoc");
    expect(parseCodeSignatureDetails("Signature size=0\n").signatureKind)
      .toBeNull();
    expect(parseCodeSignatureDetails("Signature size=65537\n").signatureKind)
      .toBeNull();
  });

  test("accepts only the exact no-entitlements display shape", () => {
    const path = "/private/disposable/hra-probe";
    expect(codeSignatureHasNoEntitlements({
      stderr: `Executable=${path}\n`,
      stdout: "",
    }, path)).toBeTrue();
    expect(codeSignatureHasNoEntitlements({
      stderr: `Executable=${path}\nwarning: unexpected\n`,
      stdout: "",
    }, path)).toBeFalse();
    expect(codeSignatureHasNoEntitlements({
      stderr: `Executable=${path}\n<plist><dict/></plist>\n`,
      stdout: "",
    }, path)).toBeFalse();
  });

  test("pins the release signer helper page size across macOS versions", () => {
    expect(releaseKeychainControlCodesignArguments("/private/disposable/helper"))
      .toEqual([
        "/usr/bin/codesign",
        "--force",
        "--sign",
        "-",
        "--options",
        "runtime",
        "--timestamp=none",
        "--digest-algorithm=sha256",
        "--pagesize",
        "16384",
        "--identifier",
        "hra-release-keychain-control",
        "/private/disposable/helper",
      ]);
  });

  test("uses the exact remote-signing callback ABI on macOS 15 and 26", async () => {
    const source = await readFile(
      join(import.meta.dir, "..", "release-keychain-control.c"),
      "utf8",
    );
    expect(source).toMatch(
      /typedef CFDataRef \(\^SecCodeRemoteLegacySignHandler\)\(\s*CFDataRef,\s*SecCSDigestAlgorithm\s*\);/u,
    );
    expect(source).toMatch(
      /typedef CFDataRef \(\^SecCodeRemoteModernSignHandler\)\(\s*CFDataRef,\s*SecCSDigestAlgorithm,\s*SecKeyAlgorithm\s*\);/u,
    );
    expect(source).toContain("__builtin_available(macOS 27.0, *)");
    expect(source).toContain("__builtin_available(macOS 26.0, *)");
    expect(source).toContain(
      "SecCodeSignerRemoteAddSignatureLegacyFunction legacy_add",
    );
    expect(source).toContain(
      "SecCodeSignerRemoteAddSignatureModernFunction modern_add",
    );
    expect(source.match(
      /kSecKeyAlgorithmRSASignatureDigestPKCS1v15SHA256/gu,
    )?.length).toBe(3);
  });

  test("accepts only the exact designated-requirement display channels", () => {
    const path = "/private/disposable/hra-probe";
    const requirement = "designated => identifier \"hra-probe\"";
    expect(codeSignatureHasExactRequirement({
      stderr: `Executable=${path}\n`,
      stdout: `${requirement}\n`,
    }, path, requirement)).toBeTrue();
    expect(codeSignatureHasExactRequirement({
      stderr: "",
      stdout: `Executable=${path}\n${requirement}\n`,
    }, path, requirement)).toBeFalse();
    expect(codeSignatureHasExactRequirement({
      stderr: `Executable=${path}\n`,
      stdout: `${requirement} and true\n`,
    }, path, requirement)).toBeFalse();
  });

  test("collects successful command output within one shared bound", async () => {
    const fixture = completedProcess({
      exitCode: 0,
      stderr: "verified",
      stdout: "signed",
    });
    expect(await runBoundedSigningCommand(() => fixture.child, {
      maxOutputBytes: encoder.encode("verifiedsigned").byteLength,
      timeoutMs: 1,
      timer: inertTimer,
    })).toEqual({
      exitCode: 0,
      stderr: "verified",
      stdout: "signed",
    });
    expect(fixture.kills).toEqual([]);
  });

  test("returns an explicitly accepted verification failure for exact inspection", async () => {
    const fixture = completedProcess({
      exitCode: 1,
      stderr: "bounded trust failure",
    });
    expect(await runBoundedSigningCommand(
      () => fixture.child,
      { maxOutputBytes: 1_024, timeoutMs: 1, timer: inertTimer },
      [0, 1],
    )).toEqual({
      exitCode: 1,
      stderr: "bounded trust failure",
      stdout: "",
    });
    expect(fixture.kills).toEqual([]);
  });

  test("sanitizes a nonzero signing command without retaining its output", async () => {
    const custodyPath = "/private/custody/release-signing.keychain-db";
    const fixture = completedProcess({
      exitCode: 17,
      stderr: `key unavailable in ${custodyPath}`,
      stdout: "operator-secret-output",
    });
    const message = await rejectionMessage(() => runBoundedSigningCommand(
      () => fixture.child,
      { maxOutputBytes: 1_024, timeoutMs: 1, timer: inertTimer },
    ));
    expect(message).toBe(
      "Release signing command failed without exposing signing-custody paths or output.",
    );
    expect(message).not.toContain(custodyPath);
    expect(message).not.toContain("operator-secret-output");
    expect(fixture.kills).toEqual([]);
  });

  test("kills a command whose combined output exceeds the byte budget", async () => {
    const fixture = completedProcess({
      exitCode: 0,
      stderr: "5678",
      stdout: "12345",
    });
    const message = await rejectionMessage(() => runBoundedSigningCommand(
      () => fixture.child,
      { maxOutputBytes: 8, timeoutMs: 1, timer: inertTimer },
    ));
    expect(message).toBe(
      "Release signing command exceeded its output limit without exposing signing-custody paths or output.",
    );
    expect(message).not.toContain("12345");
    expect(message).not.toContain("5678");
    expect(fixture.kills).toEqual(["SIGTERM"]);
  });

  test("lets a prompting process group clean up after TERM at the deadline", async () => {
    let stdoutController: ReadableStreamDefaultController<Uint8Array> | undefined;
    let stderrController: ReadableStreamDefaultController<Uint8Array> | undefined;
    let resolveExit: ((exitCode: number) => void) | undefined;
    const kills: NodeJS.Signals[] = [];
    const child: SigningCommandProcess = {
      exited: new Promise(resolve => {
        resolveExit = resolve;
      }),
      killProcessGroup: signal => {
        kills.push(signal);
        stdoutController?.close();
        stderrController?.close();
        resolveExit?.(143);
      },
      stderr: new ReadableStream({
        start(controller) {
          stderrController = controller;
        },
      }),
      stdout: new ReadableStream({
        start(controller) {
          stdoutController = controller;
        },
      }),
    };
    const clearedHandles: unknown[] = [];
    let scheduled = 0;
    const timer: SigningCommandTimer = {
      clear: handle => {
        clearedHandles.push(handle);
      },
      schedule: callback => {
        scheduled += 1;
        if (scheduled === 1) queueMicrotask(callback);
        return `deadline-${String(scheduled)}`;
      },
    };
    const message = await rejectionMessage(() => runBoundedSigningCommand(
      () => child,
      { maxOutputBytes: 8, timeoutMs: 1, timer },
    ));
    expect(message).toBe(
      "Release signing command timed out without exposing signing-custody paths or output.",
    );
    expect(kills).toEqual(["SIGTERM"]);
    expect(clearedHandles).toContain("deadline-1");
    expect(clearedHandles).toContain("deadline-2");
  });

  test("kills the process group after a bounded TERM cleanup grace", async () => {
    let stdoutController: ReadableStreamDefaultController<Uint8Array> | undefined;
    let stderrController: ReadableStreamDefaultController<Uint8Array> | undefined;
    let resolveExit: ((exitCode: number) => void) | undefined;
    const kills: NodeJS.Signals[] = [];
    const child: SigningCommandProcess = {
      exited: new Promise(resolve => {
        resolveExit = resolve;
      }),
      killProcessGroup: signal => {
        kills.push(signal);
        if (signal === "SIGKILL") {
          stdoutController?.close();
          stderrController?.close();
          resolveExit?.(137);
        }
      },
      stderr: new ReadableStream({
        start(controller) {
          stderrController = controller;
        },
      }),
      stdout: new ReadableStream({
        start(controller) {
          stdoutController = controller;
        },
      }),
    };
    const clearedHandles: unknown[] = [];
    let scheduled = 0;
    const timer: SigningCommandTimer = {
      clear: handle => {
        clearedHandles.push(handle);
      },
      schedule: callback => {
        scheduled += 1;
        const handle = `deadline-${String(scheduled)}`;
        queueMicrotask(callback);
        return handle;
      },
    };
    const message = await rejectionMessage(() => runBoundedSigningCommand(
      () => child,
      {
        cleanupGraceMs: 1,
        maxOutputBytes: 8,
        timeoutMs: 1,
        timer,
      },
    ));
    expect(message).toBe(
      "Release signing command timed out without exposing signing-custody paths or output.",
    );
    expect(kills).toEqual(["SIGTERM", "SIGKILL"]);
    expect(clearedHandles).toContain("deadline-1");
    expect(clearedHandles).toContain("deadline-2");
  });

  test("uses one disposable probe, the exact identifier, and always disposes it", async () => {
    const context = await fixtureContext();
    const probePath = "/temporary/disposable/hra-probe";
    let disposeCount = 0;
    let signCount = 0;
    await verifyProductionSigningUsability(context, {
      createDisposableMachO: () => Promise.resolve({
        dispose: () => {
          disposeCount += 1;
          return Promise.resolve();
        },
        path: probePath,
      }),
      signAndVerify: (path, identifier, actualContext) => {
        signCount += 1;
        expect(path).toBe(probePath);
        expect(identifier).toBe("hra-release-signing-usability-probe");
        expect(actualContext).toBe(context);
        return Promise.resolve();
      },
    });
    expect(signCount).toBe(1);
    expect(disposeCount).toBe(1);
  });

  test("sanitizes probe and cleanup failures while still attempting disposal", async () => {
    const context = await fixtureContext();
    const probePath = "/temporary/disposable/hra-probe";
    let disposed = false;
    const message = await rejectionMessage(() =>
      verifyProductionSigningUsability(context, {
        createDisposableMachO: () => Promise.resolve({
          dispose: () => {
            disposed = true;
            return Promise.reject(new Error(`cleanup exposed ${probePath}`));
          },
          path: probePath,
        }),
        signAndVerify: () => Promise.reject(
          new Error(`identity unavailable in ${context.keychain}`),
        ),
      }));
    expect(disposed).toBeTrue();
    expect(message).toBe(
      "Production release signing usability preflight failed without exposing signing-custody paths or output.",
    );
    expect(message).not.toContain(probePath);
    expect(message).not.toContain(context.keychain);
  });
});
