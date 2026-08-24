import { createHash } from "node:crypto";
import { mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { afterEach, describe, expect, test } from "bun:test";

import {
  loadReleaseSigningAuthority,
  parseReleaseSigningAuthority,
  productionReleaseAuthorityPins,
  productionReleaseSigning,
  releaseDesignatedRequirement,
} from "../release-signing-authority";

const authorityPath = new URL("../release-signing-authority-v2.json", import.meta.url);
const fixedNow = new Date("2026-08-24T00:00:00.000Z");
const temporaryDirectories: string[] = [];

async function authority(): Promise<Record<string, unknown>> {
  return JSON.parse(await readFile(authorityPath, "utf8")) as Record<string, unknown>;
}

afterEach(async () => {
  await Promise.all(temporaryDirectories.splice(0).map(async path => {
    await rm(path, { force: true, recursive: true });
  }));
});

describe("release signing authority v2", () => {
  test("accepts the exact public two-certificate production authority", async () => {
    const parsed = parseReleaseSigningAuthority(
      await authority(),
      productionReleaseAuthorityPins,
      fixedNow,
    );
    expect(parsed.leaf.sha256).toBe(productionReleaseSigning.leafCertificateSha256);
    expect(parsed.root.sha256).toBe(productionReleaseSigning.rootCertificateSha256);
    expect(parsed.root.x509.ca).toBeTrue();
    expect(parsed.leaf.x509.ca).toBeFalse();
  });

  test("rejects unknown fields and every policy drift", async () => {
    const extra = await authority();
    extra["privateKeyPath"] = "/secret";
    expect(() => parseReleaseSigningAuthority(extra, undefined, fixedNow)).toThrow(
      "fields differ",
    );

    for (const [field, value] of [
      ["architecture", "x86_64"],
      ["cmsSigningTime", "current"],
      ["codeDirectoryHash", "sha1"],
      ["hardenedRuntime", false],
      ["pageSize", 4_096],
      ["secureTimestamp", "required"],
    ] as const) {
      const changed = await authority();
      changed["policy"] = {
        ...(changed["policy"] as Record<string, unknown>),
        [field]: value,
      };
      expect(() => parseReleaseSigningAuthority(changed, undefined, fixedNow)).toThrow(
        "policy differs",
      );
    }
  });

  test("rejects a byte-mutated and repinned certificate", async () => {
    const changed = await authority();
    const leaf = { ...(changed["leaf"] as Record<string, unknown>) };
    const bytes = Buffer.from(leaf["derBase64"] as string, "base64");
    bytes[bytes.length - 1] = bytes[bytes.length - 1]! ^ 1;
    leaf["derBase64"] = bytes.toString("base64");
    leaf["sha1"] = createHash("sha1").update(bytes).digest("hex");
    leaf["sha256"] = createHash("sha256").update(bytes).digest("hex");
    changed["leaf"] = leaf;
    expect(() => parseReleaseSigningAuthority(changed, undefined, fixedNow)).toThrow();
  });

  test("rejects a repinned certificate with a changed digital-signature key usage", async () => {
    const changed = await authority();
    const leaf = { ...(changed["leaf"] as Record<string, unknown>) };
    const bytes = Buffer.from(leaf["derBase64"] as string, "base64");
    const extension = Buffer.from("040403020780", "hex");
    const offset = bytes.indexOf(extension);
    expect(offset).toBeGreaterThan(0);
    expect(bytes.indexOf(extension, offset + 1)).toBe(-1);
    bytes[offset + extension.length - 1] = 0x40;
    leaf["derBase64"] = bytes.toString("base64");
    leaf["sha1"] = createHash("sha1").update(bytes).digest("hex");
    leaf["sha256"] = createHash("sha256").update(bytes).digest("hex");
    changed["leaf"] = leaf;
    expect(() => parseReleaseSigningAuthority(changed, undefined, fixedNow)).toThrow(
      "Leaf key-usage certificate extension differs",
    );
  });

  test("enforces active validity with an inclusive thirty-day margin", async () => {
    const exact = await authority();
    const parsed = parseReleaseSigningAuthority(
      exact,
      productionReleaseAuthorityPins,
      fixedNow,
    );
    const exactMargin = new Date(
      parsed.leaf.x509.validToDate.getTime() - (30 * 24 * 60 * 60 * 1_000),
    );
    expect(() => parseReleaseSigningAuthority(
      exact,
      undefined,
      exactMargin,
    )).not.toThrow();
    expect(() => parseReleaseSigningAuthority(
      exact,
      undefined,
      new Date(exactMargin.getTime() + 1),
    )).toThrow("validity interval");
  });

  test("rejects the retired v1 authority and exposes no dual-authority fallback", async () => {
    const retiredDescription = await authority();
    retiredDescription["description"] =
      "Locally self-managed, build-isolated HRA release authority v1. These are public certificates only; the package and repository contain no private key material.";
    expect(() => parseReleaseSigningAuthority(
      retiredDescription,
      undefined,
      fixedNow,
    )).toThrow("schema is unsupported");
    expect(productionReleaseSigning.authority).toBe("hra-release-signing-v2");
    expect(productionReleaseSigning.mode).toBe("self-managed-cms-v2");
    expect(productionReleaseAuthorityPins.leafSha1).not.toBe(
      "d13e2ef2f779362ec7375e369dd65a9473d3eb24",
    );
    expect(await Bun.file(
      new URL("../release-signing-authority-v1.json", import.meta.url),
    ).exists()).toBeFalse();
  });

  test("requires canonical JSON bytes", async () => {
    const directory = await mkdtemp(join(tmpdir(), "hra-authority-test-"));
    temporaryDirectories.push(directory);
    const path = join(directory, "authority.json");
    const value = await authority();
    await writeFile(path, JSON.stringify(value));
    expect(loadReleaseSigningAuthority(path, undefined, fixedNow)).rejects.toThrow(
      "not canonical",
    );
  });

  test("renders exact role-bound designated requirements", () => {
    expect(releaseDesignatedRequirement("kitchen.hraness")).toBe(
      `designated => identifier "kitchen.hraness" and certificate root = H"${productionReleaseAuthorityPins.rootSha1}" and certificate leaf = H"${productionReleaseAuthorityPins.leafSha1}"`,
    );
    expect(() => releaseDesignatedRequirement("kitchen.hraness\nattacker")).toThrow();
  });

  test("generates native authority bytes only through the canonical pinned input", async () => {
    const directory = await mkdtemp(join(tmpdir(), "hra-authority-generator-test-"));
    temporaryDirectories.push(directory);
    const output = join(directory, "authority.c");
    const child = Bun.spawn([
      process.execPath,
      new URL("../generate-release-signing-authority.ts", import.meta.url).pathname,
      authorityPath.pathname,
      output,
    ], { stderr: "pipe", stdout: "pipe" });
    const [exitCode, stderr] = await Promise.all([
      child.exited,
      new Response(child.stderr).text(),
    ]);
    expect(exitCode, stderr).toBe(0);
    const generated = await readFile(output, "utf8");
    const input = await authority();
    const leafLength = Buffer.from(
      (input["leaf"] as Record<string, unknown>)["derBase64"] as string,
      "base64",
    ).length;
    const rootLength = Buffer.from(
      (input["root"] as Record<string, unknown>)["derBase64"] as string,
      "base64",
    ).length;
    expect(generated).toContain(`HRAReleaseLeafCertificateDER[${leafLength}]`);
    expect(generated).toContain(`HRAReleaseRootCertificateDER[${rootLength}]`);
    expect(generated).toContain(productionReleaseAuthorityPins.leafSha256);
    expect(generated).toContain(productionReleaseAuthorityPins.rootSha256);
  });
});
