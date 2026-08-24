import { createHash } from "node:crypto";
import {
  mkdir,
  mkdtemp,
  lstat,
  rename,
  realpath,
  rm,
  writeFile,
} from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { describe, expect, test } from "bun:test";

import type {
  CustodyProbeSupervisorAuthorityEvidence,
} from "../custody-probe-supervisor-authority";
import { exactGatewayFileSha256 } from
  "../generate-gateway-file-authority";
import runtimeVersions from "../runtime-versions.json";
import {
  packagedRendererAuthorityEntries,
  rendererAuthorityRoot,
} from "../renderer-authority";
import {
  launchSmokeMacOSApp,
  probePackagedCustodyAuthorization,
  probePackagedCustodyStatus,
  type MacOSPackageResidentProbeDependencies,
} from "../verify-macos-package";
import { assertReleaseStrictVerification } from "../package-macos";
import { testCustodyProbeSupervisorAuthority } from
  "./fixtures/custody-probe-authority";

type PackageProbeFixture = Readonly<{
  app: string;
  frontend: string;
  gateway: string;
  root: string;
}>;

describe("release strict-verification output", () => {
  const path = "/private/release/HRA.app";

  test("accepts only silent or exact verbose success and the exact trust failure", () => {
    expect(() => assertReleaseStrictVerification(path, {
      exitCode: 0,
      stderr: "",
      stdout: "",
    })).not.toThrow();
    expect(() => assertReleaseStrictVerification(path, {
      exitCode: 0,
      stderr:
        `${path}: valid on disk\n${path}: satisfies its Designated Requirement\n`,
      stdout: "",
    })).not.toThrow();
    expect(() => assertReleaseStrictVerification(path, {
      exitCode: 1,
      stderr: `${path}: CSSMERR_TP_NOT_TRUSTED\nIn architecture: arm64\n`,
      stdout: "",
    })).not.toThrow();
    expect(() => assertReleaseStrictVerification(path, {
      exitCode: 0,
      stderr: `${path}: valid on disk\nwarning: unexpected\n`,
      stdout: "",
    })).toThrow("Release strict verification differs");
  });
});

async function packageProbeFixture(): Promise<PackageProbeFixture> {
  const root = await realpath(
    await mkdtemp(join(tmpdir(), "hra-package-resident-probe-")),
  );
  const app = join(root, "HRA.app");
  const frontend = join(app, "Contents/Resources/frontend/dist");
  const gateway = join(app, "Contents/Resources/runtime/bin/oprte-gateway");
  await mkdir(frontend, { recursive: true });
  await mkdir(join(app, "Contents/Resources/runtime/bin"), { recursive: true });
  await writeFile(gateway, "synthetic-gateway-v1\n", { mode: 0o755 });
  const payload = Buffer.from("<!doctype html><title>HRA</title>\n");
  const payloadSha256 = createHash("sha256").update(payload).digest("hex");
  await writeFile(join(frontend, "index.html"), payload, { mode: 0o644 });
  await writeFile(
    join(frontend, "asset-manifest.zon"),
    ".{ .assets = .{\n" +
      `  .{ .id = "index.html", .bundle_path = "index.html", .source_path = "frontend/dist/index.html", .byte_len = ${payload.byteLength}, .hash = "${payloadSha256}" },\n` +
      "} }\n",
    { mode: 0o644 },
  );
  return Object.freeze({ app, frontend, gateway, root });
}

function unusedResidentProbe(): never {
  throw new Error("unexpected resident probe operation");
}

function smokeMarkerText(): string {
  return JSON.stringify({
    bunVersion: "1.3.14",
    codexVersion: `codex-cli ${runtimeVersions.codex.version}`,
    gitVersion: `git version ${runtimeVersions.git.version}`,
    schemaVersion: 1,
  });
}

async function writeSmokeMarker(smokeRoot: string): Promise<void> {
  await writeFile(
    join(smokeRoot, "gateway-ready.json"),
    smokeMarkerText(),
    { mode: 0o600 },
  );
}

function delayedFifoWriter(path: string): ReturnType<typeof Bun.spawn> {
  return Bun.spawn([
    process.execPath,
    "-e",
    `setTimeout(() => require("node:fs").writeFileSync(${JSON.stringify(
      path,
    )}, "unblock\\n"), 2000)`,
  ], {
    stderr: "ignore",
    stdout: "ignore",
  });
}

describe("macOS package resident probe integration", () => {
  test("inspects signed custody status with the exact candidate authority", async () => {
    const fixture = await packageProbeFixture();
    try {
      const captured: Array<Readonly<{
        app: string;
        authority: CustodyProbeSupervisorAuthorityEvidence;
      }>> = [];
      await probePackagedCustodyStatus(
        fixture.app,
        testCustodyProbeSupervisorAuthority,
        (app, authority) => {
          captured.push({ app, authority });
          return Promise.resolve({ state: "absent" });
        },
      );
      expect(captured).toEqual([{
        app: fixture.app,
        authority: testCustodyProbeSupervisorAuthority,
      }]);
    } finally {
      await rm(fixture.root, { force: true, recursive: true });
    }
  });

  test("authorizes the exact receipt-bound candidate and rejects later package substitution", async () => {
    const fixture = await packageProbeFixture();
    try {
      const gatewaySha256 = await exactGatewayFileSha256(fixture.gateway);
      const rendererSha256 = rendererAuthorityRoot(
        await packagedRendererAuthorityEntries(fixture.frontend),
      );
      const captured: Array<Readonly<{
        app: string;
        authority: CustodyProbeSupervisorAuthorityEvidence;
        receipt: string;
      }>> = [];
      const dependencies: MacOSPackageResidentProbeDependencies = {
        authorizeCandidate(app, authority, receipt) {
          captured.push({ app, authority, receipt });
          return Promise.resolve();
        },
        smokeCandidate: unusedResidentProbe,
      };
      await probePackagedCustodyAuthorization(
        fixture.app,
        testCustodyProbeSupervisorAuthority,
        dependencies,
      );
      expect(captured).toEqual([{
        app: fixture.app,
        authority: testCustodyProbeSupervisorAuthority,
        receipt:
          `{"authorization":"hra-parent-v1","gatewayFileSha256":"${gatewaySha256}",` +
          `"keychainAccessed":false,"ok":true,"rendererAuthoritySha256":"${rendererSha256}",` +
          "\"version\":1}\n",
      }]);
      expect(captured[0]!.authority).toBe(testCustodyProbeSupervisorAuthority);

      const substitution: MacOSPackageResidentProbeDependencies = {
        async authorizeCandidate() {
          await writeFile(fixture.gateway, "substituted-gateway\n", {
            mode: 0o755,
          });
        },
        smokeCandidate: unusedResidentProbe,
      };
      expect(probePackagedCustodyAuthorization(
        fixture.app,
        testCustodyProbeSupervisorAuthority,
        substitution,
      )).rejects.toThrow("authority changed");
    } finally {
      await rm(fixture.root, { force: true, recursive: true });
    }
  });

  test.skipIf(process.platform !== "darwin")(
    "smoke uses exact resident authority and removes success and failure roots",
    async () => {
      const fixture = await packageProbeFixture();
      let successRoot = "";
      let failureRoot = "";
      try {
        const success: MacOSPackageResidentProbeDependencies = {
          authorizeCandidate: unusedResidentProbe,
          async smokeCandidate(app, authority, smokeRoot, dwellMilliseconds) {
            expect(app).toBe(fixture.app);
            expect(authority).toBe(testCustodyProbeSupervisorAuthority);
            expect(dwellMilliseconds).toBe(4_000);
            successRoot = smokeRoot;
            await writeSmokeMarker(smokeRoot);
          },
        };
        await launchSmokeMacOSApp(
          fixture.app,
          4_000,
          testCustodyProbeSupervisorAuthority,
          success,
        );
        expect(successRoot).toContain("hra-package-smoke-");
        expect(lstat(successRoot)).rejects.toMatchObject({ code: "ENOENT" });

        const failure: MacOSPackageResidentProbeDependencies = {
          authorizeCandidate: unusedResidentProbe,
          async smokeCandidate(_app, _authority, smokeRoot) {
            failureRoot = smokeRoot;
            await writeFile(join(smokeRoot, "partial-residue"), "residue\n");
            throw new Error("synthetic resident smoke failure");
          },
        };
        expect(launchSmokeMacOSApp(
          fixture.app,
          4_000,
          testCustodyProbeSupervisorAuthority,
          failure,
        )).rejects.toThrow("synthetic resident smoke failure");
        expect(lstat(failureRoot)).rejects.toMatchObject({ code: "ENOENT" });
      } finally {
        await rm(fixture.root, { force: true, recursive: true });
      }
    },
  );

  test.skipIf(process.platform !== "darwin")(
    "rejects a forged root replacement and removes only the held original vnode",
    async () => {
      const fixture = await packageProbeFixture();
      let publishedRoot = "";
      let movedOriginal = "";
      try {
        const dependencies: MacOSPackageResidentProbeDependencies = {
          afterSmokeForTest: async (smokeRoot) => {
            publishedRoot = smokeRoot;
            movedOriginal = `${smokeRoot}.held-original`;
            await rename(smokeRoot, movedOriginal);
            await mkdir(smokeRoot, { mode: 0o700 });
            await writeSmokeMarker(smokeRoot);
          },
          authorizeCandidate: unusedResidentProbe,
          async smokeCandidate(_app, _authority, smokeRoot) {
            await writeSmokeMarker(smokeRoot);
          },
        };
        expect(launchSmokeMacOSApp(
          fixture.app,
          4_000,
          testCustodyProbeSupervisorAuthority,
          dependencies,
        )).rejects.toThrow("root was replaced during cleanup");
        expect(lstat(movedOriginal)).rejects.toMatchObject({ code: "ENOENT" });
        expect((await lstat(publishedRoot)).isDirectory()).toBeTrue();
      } finally {
        if (publishedRoot !== "") {
          await rm(publishedRoot, { force: true, recursive: true });
        }
        if (movedOriginal !== "") {
          await rm(movedOriginal, { force: true, recursive: true });
        }
        await rm(fixture.root, { force: true, recursive: true });
      }
    },
  );

  test.skipIf(process.platform !== "darwin")(
    "opens a raced marker FIFO nonblocking and cleans the exact root",
    async () => {
      const fixture = await packageProbeFixture();
      let smokeRoot = "";
      const writers: Array<ReturnType<typeof Bun.spawn>> = [];
      try {
        const dependencies: MacOSPackageResidentProbeDependencies = {
          authorizeCandidate: unusedResidentProbe,
          async beforeSmokeMarkerOpenForTest(markerPath) {
            await rm(markerPath);
            const fifo = Bun.spawnSync(["/usr/bin/mkfifo", markerPath], {
              stderr: "pipe",
              stdout: "pipe",
            });
            expect(fifo.exitCode).toBe(0);
            writers.push(delayedFifoWriter(markerPath));
          },
          async smokeCandidate(_app, _authority, root) {
            smokeRoot = root;
            await writeSmokeMarker(root);
          },
        };
        const started = performance.now();
        expect(launchSmokeMacOSApp(
          fixture.app,
          4_000,
          testCustodyProbeSupervisorAuthority,
          dependencies,
        )).rejects.toThrow("marker authority changed before open");
        expect(performance.now() - started).toBeLessThan(1_000);
        expect(lstat(smokeRoot)).rejects.toMatchObject({ code: "ENOENT" });
      } finally {
        for (const writer of writers) writer.kill();
        await Promise.all(writers.map(async writer => await writer.exited));
        await rm(fixture.root, { force: true, recursive: true });
      }
    },
  );

  test.skipIf(process.platform !== "darwin")(
    "rejects a marker name replaced after its descriptor is held",
    async () => {
      const fixture = await packageProbeFixture();
      let smokeRoot = "";
      try {
        const dependencies: MacOSPackageResidentProbeDependencies = {
          authorizeCandidate: unusedResidentProbe,
          async beforeSmokeMarkerReadForTest(markerPath) {
            await rm(markerPath);
            await writeFile(markerPath, smokeMarkerText(), { mode: 0o600 });
          },
          async smokeCandidate(_app, _authority, root) {
            smokeRoot = root;
            await writeSmokeMarker(root);
          },
        };
        expect(launchSmokeMacOSApp(
          fixture.app,
          4_000,
          testCustodyProbeSupervisorAuthority,
          dependencies,
        )).rejects.toThrow("marker authority changed during read");
        expect(lstat(smokeRoot)).rejects.toMatchObject({ code: "ENOENT" });
      } finally {
        await rm(fixture.root, { force: true, recursive: true });
      }
    },
  );
});
