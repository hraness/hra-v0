import { describe, expect, test } from "bun:test";
import { createHash } from "node:crypto";

import {
  C19_PACKAGED_CUSTODIAN_CDHASH,
  type C19CustodyBinaryPolicy,
  c19CustodyBinaryPolicies,
  normalizeC19CustodyBinaryWithPolicy,
} from "../normalize-c19-custody-binary";

const fixtureSize = 640;
const uuidOffset = 40;
const symoff = 128;
const stroff = 144;
const strsize = 160;
const signatureOffset = 512;
const signatureSize = 128;
const osoPrefix = "/fixture/repo/apps/desktop/.zig-cache/o/";
const objectSuffix = "/fixture.o";
const targetCacheKey = "0123456789abcdef0123456789abcdef";
const sourceCacheKey = "fedcba9876543210fedcba9876543210";
const targetUuid = "00112233445566778899aabbccddeeff";
const targetMtime = "78563412";

function signatureFixture(marker: number): Buffer {
  const bytes = Buffer.alloc(signatureSize);
  bytes.writeUInt32BE(0xfade0cc0, 0);
  bytes.writeUInt32BE(44, 4);
  bytes.writeUInt32BE(1, 8);
  bytes.writeUInt32BE(0, 12);
  bytes.writeUInt32BE(20, 16);
  bytes.writeUInt32BE(0xfade0c02, 20);
  bytes.writeUInt32BE(24, 24);
  bytes.writeUInt32BE(0x00020400, 28);
  bytes.writeUInt32BE(0x00020002, 32);
  bytes.writeUInt32BE(marker, 36);
  bytes.writeUInt32BE((marker ^ 0xa5a5a5a5) >>> 0, 40);
  return bytes;
}

function machoFixture(options: Readonly<{
  cacheKey: string;
  mtimeHex: string;
  root?: string;
  signature: Buffer;
  uuidHex: string;
}>): Buffer {
  const bytes = Buffer.alloc(fixtureSize);
  for (let index = 0; index < signatureOffset; index += 1) {
    bytes[index] = (index * 17 + 29) % 251;
  }
  bytes.writeUInt32LE(0xfeedfacf, 0);
  bytes.writeUInt32LE(0x0100000c, 4);
  bytes.writeUInt32LE(0, 8);
  bytes.writeUInt32LE(2, 12);
  bytes.writeUInt32LE(3, 16);
  bytes.writeUInt32LE(64, 20);
  bytes.writeUInt32LE(0, 24);
  bytes.writeUInt32LE(0, 28);

  bytes.writeUInt32LE(0x1b, 32);
  bytes.writeUInt32LE(24, 36);
  Buffer.from(options.uuidHex, "hex").copy(bytes, uuidOffset);

  bytes.writeUInt32LE(0x02, 56);
  bytes.writeUInt32LE(24, 60);
  bytes.writeUInt32LE(symoff, 64);
  bytes.writeUInt32LE(1, 68);
  bytes.writeUInt32LE(stroff, 72);
  bytes.writeUInt32LE(strsize, 76);

  bytes.writeUInt32LE(0x1d, 80);
  bytes.writeUInt32LE(16, 84);
  bytes.writeUInt32LE(signatureOffset, 88);
  bytes.writeUInt32LE(signatureSize, 92);

  bytes.writeUInt32LE(1, symoff);
  bytes[symoff + 4] = 0x66;
  bytes[symoff + 5] = 0;
  bytes.writeUInt16LE(1, symoff + 6);
  Buffer.from(options.mtimeHex, "hex").copy(bytes, symoff + 8);
  bytes.writeUInt32LE(0, symoff + 12);
  const osoPath = `${options.root ?? osoPrefix}${options.cacheKey}${objectSuffix}`;
  bytes[stroff] = 0;
  bytes.write(osoPath, stroff + 1, "ascii");
  bytes[stroff + 1 + osoPath.length] = 0;
  options.signature.copy(bytes, signatureOffset);
  return bytes;
}

function sha256(bytes: Uint8Array): string {
  return createHash("sha256").update(bytes).digest("hex");
}

function stableFixtureSha256(bytes: Buffer): string {
  const cacheOffset = stroff + 1 + osoPrefix.length;
  const ranges = [
    [uuidOffset, 16],
    [symoff + 8, 4],
    [cacheOffset, 32],
    [signatureOffset, signatureSize],
  ] as const;
  const hash = createHash("sha256");
  let cursor = 0;
  for (const [offset, length] of ranges) {
    hash.update(bytes.subarray(cursor, offset));
    cursor = offset + length;
  }
  hash.update(bytes.subarray(cursor));
  return hash.digest("hex");
}

function fixturePolicy(): Readonly<{
  policy: C19CustodyBinaryPolicy;
  source: Buffer;
  target: Buffer;
}> {
  const targetSignature = signatureFixture(0x11223344);
  const target = machoFixture({
    cacheKey: targetCacheKey,
    mtimeHex: targetMtime,
    signature: targetSignature,
    uuidHex: targetUuid,
  });
  const source = machoFixture({
    cacheKey: sourceCacheKey,
    mtimeHex: "01020304",
    signature: signatureFixture(0x55667788),
    uuidHex: "ffeeddccbbaa99887766554433221100",
  });
  return Object.freeze({
    policy: Object.freeze({
      codeSignature: Object.freeze({
        base64: targetSignature.toString("base64"),
        offset: signatureOffset,
        size: signatureSize,
      }),
      finalSha256: sha256(target),
      kind: "custodian",
      layout: Object.freeze({
        ncmds: 3,
        nsyms: 1,
        sizeofcmds: 64,
        stroff,
        strsize,
        symoff,
      }),
      oso: Object.freeze([
        Object.freeze({
          cacheKey: targetCacheKey,
          objectSuffix,
          timestampHex: targetMtime,
        }),
      ]),
      size: fixtureSize,
      stableSha256: stableFixtureSha256(target),
      uuidHex: targetUuid,
      uuidOffset,
    }),
    source,
    target,
  });
}

describe("C19 custody binary normalization", () => {
  test("pins only the three raw custody artifacts and enrolled packaged ACL hash", () => {
    expect(Object.keys(c19CustodyBinaryPolicies).sort()).toEqual([
      "candidate",
      "custodian",
      "verifier",
    ]);
    expect(Object.values(c19CustodyBinaryPolicies).map((policy) => policy.finalSha256))
      .toEqual([
        "838624f22d9fbd4a7761aca9473663f925737560a8f0d70ceb0a56bd24913d0a",
        "a2c9fee285f71861b30f32e34218d95b4305a2713b0d77c9f0d622f1c6e7c9c9",
        "a96fae9dceae4fe476bc34fdbff3f374ae654da1b38715ec13c60ebd54e54316",
      ]);
    expect(C19_PACKAGED_CUSTODIAN_CDHASH).toBe(
      "6cde8d3c2d173f8c6cb346370539b1d0e960ddaa",
    );
  });

  test("restores the complete reviewed volatile set to exact target bytes", () => {
    const { policy, source, target } = fixturePolicy();
    expect(normalizeC19CustodyBinaryWithPolicy(policy, source)).toEqual(target);
  });

  test("rejects an immutable byte even when all parsed metadata remains valid", () => {
    const { policy, source } = fixturePolicy();
    source[104] = source[104]! ^ 0xff;
    expect(() => normalizeC19CustodyBinaryWithPolicy(policy, source)).toThrow(
      "immutable bytes differ",
    );
  });

  test("rejects load-command layout drift before applying any patch", () => {
    const { policy, source } = fixturePolicy();
    source.writeUInt32LE(4, 16);
    expect(() => normalizeC19CustodyBinaryWithPolicy(policy, source)).toThrow(
      "load-command layout differs",
    );
  });

  test("rejects a different canonical checkout root as immutable provenance", () => {
    const { policy } = fixturePolicy();
    const source = machoFixture({
      cacheKey: sourceCacheKey,
      mtimeHex: "01020304",
      root: "/fixture/fork/apps/desktop/.zig-cache/o/",
      signature: signatureFixture(0x55667788),
      uuidHex: "ffeeddccbbaa99887766554433221100",
    });
    expect(() => normalizeC19CustodyBinaryWithPolicy(policy, source)).toThrow(
      "immutable bytes differ",
    );
  });

  test("keeps the high N_OSO value word outside the four-byte mtime allowlist", () => {
    const { policy, source } = fixturePolicy();
    source.writeUInt32LE(1, symoff + 12);
    expect(() => normalizeC19CustodyBinaryWithPolicy(policy, source)).toThrow(
      "timestamp width differs",
    );
  });

  test("rejects a cache key that is not exactly 32 lowercase hex bytes", () => {
    const { policy, source } = fixturePolicy();
    source.write("F", stroff + 1 + osoPrefix.length, "ascii");
    expect(() => normalizeC19CustodyBinaryWithPolicy(policy, source)).toThrow(
      "cache path is malformed",
    );
  });

  test("rejects exact N_OSO count, type, and suffix drift", () => {
    const { policy, source } = fixturePolicy();
    const extraInventory = Object.freeze({
      ...policy,
      oso: Object.freeze([
        ...policy.oso,
        Object.freeze({
          cacheKey: "11111111111111111111111111111111",
          objectSuffix: "/extra.o",
          timestampHex: "01000000",
        }),
      ]),
    });
    expect(() => normalizeC19CustodyBinaryWithPolicy(extraInventory, source)).toThrow(
      "N_OSO inventory differs",
    );

    const wrongType = Buffer.from(source);
    wrongType[symoff + 4] = 0x64;
    expect(() => normalizeC19CustodyBinaryWithPolicy(policy, wrongType)).toThrow(
      "N_OSO inventory differs",
    );

    const wrongSuffix = Buffer.from(source);
    const suffixOffset = stroff + 1 + osoPrefix.length + sourceCacheKey.length;
    wrongSuffix.write("/another.o", suffixOffset, "ascii");
    expect(() => normalizeC19CustodyBinaryWithPolicy(policy, wrongSuffix)).toThrow(
      "N_OSO inventory differs",
    );
  });

  test("rejects UUID and signature command offsets that differ from policy", () => {
    const { policy, source } = fixturePolicy();
    for (const changedPolicy of [
      Object.freeze({ ...policy, uuidOffset: policy.uuidOffset + 8 }),
      Object.freeze({
        ...policy,
        codeSignature: Object.freeze({
          ...policy.codeSignature,
          offset: policy.codeSignature.offset + 8,
        }),
      }),
    ]) {
      expect(() => normalizeC19CustodyBinaryWithPolicy(changedPolicy, source)).toThrow(
        "exact Mach-O layout differs",
      );
    }
  });

  test("rejects truncated and extended binaries before parsing metadata", () => {
    const { policy, source } = fixturePolicy();
    for (const changed of [
      source.subarray(0, source.byteLength - 1),
      Buffer.concat([source, Buffer.from([0])]),
    ]) {
      expect(() => normalizeC19CustodyBinaryWithPolicy(policy, changed)).toThrow(
        "Mach-O size differs",
      );
    }
  });
});
