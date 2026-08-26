import { createHash, randomBytes } from "node:crypto";
import { constants } from "node:fs";
import { link, lstat, open, unlink } from "node:fs/promises";
import { basename, dirname, resolve } from "node:path";

const MACH_HEADER_64_BYTES = 32;
const MACHO_64_MAGIC = 0xfeedfacf;
const CPU_TYPE_ARM64 = 0x0100000c;
const MH_EXECUTE = 2;
const LC_SYMTAB = 0x02;
const LC_UUID = 0x1b;
const LC_CODE_SIGNATURE = 0x1d;
const N_OSO = 0x66;
const NLIST_64_BYTES = 16;
const CSMAGIC_EMBEDDED_SIGNATURE = 0xfade0cc0;
const CSMAGIC_CODEDIRECTORY = 0xfade0c02;
const CS_ADHOC = 0x00000002;
const CACHE_KEY_PATTERN = /^[0-9a-f]{32}$/u;
const SHA256_PATTERN = /^[0-9a-f]{64}$/u;
const CACHE_ROOT_MARKER = "/apps/desktop/.zig-cache/o/";

export type C19CustodyBinaryKind = "candidate" | "custodian" | "verifier";

// The enrolled Keychain ACL proves this packaged production CodeDirectory.
// The raw byte oracle below is separate evidence and does not replace the ACL.
export const C19_PACKAGED_CUSTODIAN_CDHASH =
  "6cde8d3c2d173f8c6cb346370539b1d0e960ddaa" as const;

export type C19CustodyOsoPolicy = Readonly<{
  cacheKey: string;
  objectSuffix: string;
  timestampHex: string;
}>;

export type C19CustodyBinaryPolicy = Readonly<{
  codeSignature: Readonly<{
    base64: string;
    offset: number;
    size: number;
  }>;
  finalSha256: string;
  kind: C19CustodyBinaryKind;
  layout: Readonly<{
    ncmds: number;
    nsyms: number;
    sizeofcmds: number;
    stroff: number;
    strsize: number;
    symoff: number;
  }>;
  oso: readonly C19CustodyOsoPolicy[];
  size: number;
  stableSha256: string;
  uuidHex: string;
  uuidOffset: number;
}>;

type PatchRange = Readonly<{
  bytes: Buffer;
  label: string;
  length: number;
  offset: number;
}>;

type ParsedMachO = Readonly<{
  ranges: readonly PatchRange[];
  stableSha256: string;
}>;

// C21 is a deliberately historical, root-coupled bridge. It restores only the
// three C19 custody artifacts after proving that every nonvolatile byte already
// matches the C19 build. It makes no portability claim: a different checkout
// root, linker layout, compiler, or source revision fails the stable digest.
// The sparse payload contains only LC_UUID, N_OSO mtime/cache-key, and ad-hoc
// signature bytes. No historical source root or whole executable is embedded.
export const c19CustodyBinaryPolicies = Object.freeze({
  custodian: Object.freeze({
    codeSignature: Object.freeze({
      base64:
        "+t4MwAAAAeUAAAABAAAAAAAAABT63gwCAAAB0QACBAAAAgACAAAAcQAAAFgAAAAAAAAACwACqzAgAgAOAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAF1cAAAAAAAAAABb3BydGUta2V5Y2hhaW4tY3VzdG9kaWFuAEY7NXyPG1DURfZviP7+FtOnzDXam8eIOEGGI1NmhtLmuq9G0pCG02yTVrhGnj6Sf3VkBy0zmyWrDGPdwASrswBbQzEvNSi5/ozXSSaN9U1gAzRobDPfi509By/gHKPN+rkMr4llB4A+s7AmfKh3ZpWKYEc6z4kxYaLuaJPaVMsJhJTnMKX4m0Yt5dGkg5giTrGWzfJGHTZn6l9Jb28kbHJSPXVNfdfApHkK/HMNE1UJzzWEtR10itSRe9DaMqOKPw8KlCxhJXRoTnfZYxfYjhJ/QRrtfjAZ1sFxaDXGB6JeRsnos/vb/LPFHQLzDZ2xPrirdx9Z+Ex+Egf54ju/NzhZ6KP4TYjOfxnIZIeenRpKA6fvAp1AHuY6D+kp+gx31TemaZM/UpexCaeu9fS0xKU5Vxr8nyhfYXoU7R/+t+KOKnxcvU4pi6VhWRYFIIZWIAKrAZfpCHdZKtiZKB5kplIAAAA=",
      offset: 174_896,
      size: 488,
    }),
    finalSha256:
      "838624f22d9fbd4a7761aca9473663f925737560a8f0d70ceb0a56bd24913d0a",
    kind: "custodian",
    layout: Object.freeze({
      ncmds: 23,
      nsyms: 1_184,
      sizeofcmds: 2_776,
      stroff: 157_600,
      strsize: 17_296,
      symoff: 137_424,
    }),
    oso: Object.freeze([
      Object.freeze({
        cacheKey: "327037f87dd925055d87e38ab401a72f",
        objectSuffix: "/macos_keychain_custodian.o",
        timestampHex: "ca018f6a",
      }),
      Object.freeze({
        cacheKey: "5915c0e158c1ad75daf56e7bc600f5da",
        objectSuffix: "/macos_custody_probe_parent_gate.o",
        timestampHex: "c9018f6a",
      }),
      Object.freeze({
        cacheKey: "c1b70038de126804ff40152a31f6469c",
        objectSuffix: "/macos_keychain_access_control.o",
        timestampHex: "c9018f6a",
      }),
      Object.freeze({
        cacheKey: "df80345db1cacc68010f5691fff50f10",
        objectSuffix: "/macos_self_managed_code_identity.o",
        timestampHex: "c9018f6a",
      }),
      Object.freeze({
        cacheKey: "e2699268a078916cf3eb42f4798e9b49",
        objectSuffix: "/macos_gateway_attestation.o",
        timestampHex: "c9018f6a",
      }),
      Object.freeze({
        cacheKey: "b1dcdb32a65b0cd744426a31350dc83e",
        objectSuffix: "/macos_renderer_authority.o",
        timestampHex: "c9018f6a",
      }),
      Object.freeze({
        cacheKey: "d5dbcf627cecc9157cc1062aa40a73c3",
        objectSuffix: "/hra_gateway_file_authority.o",
        timestampHex: "c8018f6a",
      }),
      Object.freeze({
        cacheKey: "baa550ae6ead22fbd93edd3d0da02089",
        objectSuffix: "/hra_renderer_authority.o",
        timestampHex: "c8018f6a",
      }),
      Object.freeze({
        cacheKey: "e4faa8992371a6719c4774a3cce6a0af",
        objectSuffix: "/hra_release_signing_authority.o",
        timestampHex: "c8018f6a",
      }),
      Object.freeze({
        cacheKey: "8d79fc0853e576087a4fefa703c96349",
        objectSuffix: "/oprte-keychain-custodian_zcu.o",
        timestampHex: "ca018f6a",
      }),
    ]),
    size: 175_384,
    stableSha256:
      "8d06aead36a73bef9b37be3d26c192e74db2dea2ee6365de11b977901c65cf7a",
    uuidHex: "89adbc63b4ea317aa1785c8adf4e53f3",
    uuidOffset: 2_208,
  }),
  verifier: Object.freeze({
    codeSignature: Object.freeze({
      base64:
        "+t4MwAAAAWkAAAABAAAAAAAAABT63gwCAAABVQACBAAAAgACAAAAdQAAAFgAAAAAAAAABwABoiAgAgAOAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAC0TAAAAAAAAAABaHJhLWN1c3RvZHktcHJvYmUtc3VwZXJ2aXNvcgBccQd8bc9RdQkSKKJGaHjn0DPrGNB8nlv6CrDRaJpMVY8t5TQ8OmR5Pk4AlwwDYuCpHyOr6hR4/SZ6d4sauPxK6ZUpq8oPYYumnbvtwMMzD9g76uU+Ice3MLA59G1L9cE8L1JGSn6rfKAiD8n0SdGAJ1LaFE7WChgm/89LxdL5QH4GNoQGui9shq1qiG4Srs8y7P/7gd6STiYkttNlqR7KgZHIRHz9G6Ke4CJ/mf4Alx9AynP//LxHLbMLSwQTtXABudjNvLgVFkC59+csrPUgqmZRsM1UbWFO6OUjIwssogAAAAAAAAA=",
      offset: 107_040,
      size: 368,
    }),
    finalSha256:
      "a2c9fee285f71861b30f32e34218d95b4305a2713b0d77c9f0d622f1c6e7c9c9",
    kind: "verifier",
    layout: Object.freeze({
      ncmds: 21,
      nsyms: 646,
      sizeofcmds: 2_376,
      stroff: 97_320,
      strsize: 9_720,
      symoff: 85_984,
    }),
    oso: Object.freeze([
      Object.freeze({
        cacheKey: "7104090c02bdf241e5764453519572ba",
        objectSuffix: "/macos_custody_probe_supervisor.o",
        timestampHex: "c9018f6a",
      }),
      Object.freeze({
        cacheKey: "25cc5146bdee8888161050c68f2853aa",
        objectSuffix: "/macos_gateway_attestation.o",
        timestampHex: "c9018f6a",
      }),
      Object.freeze({
        cacheKey: "d139e5b389a2dca596983fd23cb9a536",
        objectSuffix: "/macos_renderer_authority.o",
        timestampHex: "c9018f6a",
      }),
      Object.freeze({
        cacheKey: "41bff00a25983f83b28671cafc70ffb1",
        objectSuffix: "/macos_self_managed_code_identity.o",
        timestampHex: "c9018f6a",
      }),
      Object.freeze({
        cacheKey: "634fbac6069740a60fa00dc6967ef43c",
        objectSuffix: "/hra_gateway_file_authority.o",
        timestampHex: "c8018f6a",
      }),
      Object.freeze({
        cacheKey: "0f04c70084745285e74306ab004dc605",
        objectSuffix: "/hra_renderer_authority.o",
        timestampHex: "c8018f6a",
      }),
      Object.freeze({
        cacheKey: "3b71639b3ddf0eb1880c8ec7e31c37f1",
        objectSuffix: "/hra_release_signing_authority.o",
        timestampHex: "c9018f6a",
      }),
    ]),
    size: 107_408,
    stableSha256:
      "1e1d2274d5fee120a89561e04d2612ffd6ee549d5e128e26ec005e5a59cb81ec",
    uuidHex: "3eea025a56ec3b26a1e5c18ec4cf391e",
    uuidOffset: 1_968,
  }),
  candidate: Object.freeze({
    codeSignature: Object.freeze({
      base64:
        "+t4MwAAAAXMAAAABAAAAAAAAABT63gwCAAABXwACBAAAAgACAAAAfwAAAFgAAAAAAAAABwABp7AgAgAOAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAC8LAAAAAAAAAABaHJhLWN1c3RvZHktcHJvYmUtc3VwZXJ2aXNvci1jYW5kaWRhdGUAJcMPP9KQ7wDWkcaWxeryURu8PSXYRKxQv0g8xfoco8bjinc683h5rBgi2KzpAlg/xlqWekl5cAfH5kAoX6waNs7OqGOYigLWFYD0UeiNA2njtNGdq79JfKCEozpuuzUnhTXRPl1M0I0xi+dmutTCif56CWNmmLh/Y/rGIZghuGwIFFQeF5sq8Kn7MlXESTsuyL/w+647DKy58vbN8uaHgT/LcrSDeNSmnOUTHiqzCbp25EXDwsNXHABs20YouHal8WkuNRQRJn2tghEybgQxfh6ZuEKVSHWx7Ab2t6vQc+QAAAAAAA==",
      offset: 108_464,
      size: 376,
    }),
    finalSha256:
      "a96fae9dceae4fe476bc34fdbff3f374ae654da1b38715ec13c60ebd54e54316",
    kind: "candidate",
    layout: Object.freeze({
      ncmds: 21,
      nsyms: 693,
      sizeofcmds: 2_376,
      stroff: 98_232,
      strsize: 10_217,
      symoff: 86_104,
    }),
    oso: Object.freeze([
      Object.freeze({
        cacheKey: "dff1a65f5f7c6bf678d5d4399ee5d45e",
        objectSuffix: "/macos_custody_probe_supervisor.o",
        timestampHex: "8f158f6a",
      }),
      Object.freeze({
        cacheKey: "716283a95b9305231d8bdd87a53fda46",
        objectSuffix: "/macos_gateway_attestation.o",
        timestampHex: "90158f6a",
      }),
      Object.freeze({
        cacheKey: "bbdbcbf052f3c58f286e9bac116b6219",
        objectSuffix: "/macos_renderer_authority.o",
        timestampHex: "c9018f6a",
      }),
      Object.freeze({
        cacheKey: "85272b50188e00d47c7cfc143d6845ca",
        objectSuffix: "/macos_self_managed_code_identity.o",
        timestampHex: "c9018f6a",
      }),
      Object.freeze({
        cacheKey: "f55f0053c6b339b9d053fd2a379aed69",
        objectSuffix: "/hra_gateway_file_authority.o",
        timestampHex: "c8018f6a",
      }),
      Object.freeze({
        cacheKey: "e21243794df0cc524a80cffa05cf1060",
        objectSuffix: "/hra_renderer_authority.o",
        timestampHex: "c8018f6a",
      }),
      Object.freeze({
        cacheKey: "46e77234b395c1b7302ea77c344995b8",
        objectSuffix: "/hra_release_signing_authority.o",
        timestampHex: "c8018f6a",
      }),
    ]),
    size: 108_840,
    stableSha256:
      "6f166cd16347e26f674c27e96c229be5b252e9ca0dd8b1fc2ab74fcbb30db525",
    uuidHex: "7711b79e349631ec93e6ed9f2c0f99cf",
    uuidOffset: 1_968,
  }),
} satisfies Readonly<Record<C19CustodyBinaryKind, C19CustodyBinaryPolicy>>);

export function normalizeC19CustodyBinary(
  kind: C19CustodyBinaryKind,
  source: Uint8Array,
): Buffer {
  return normalizeC19CustodyBinaryWithPolicy(c19CustodyBinaryPolicies[kind], source);
}

export function normalizeC19CustodyBinaryWithPolicy(
  policy: C19CustodyBinaryPolicy,
  source: Uint8Array,
): Buffer {
  validatePolicy(policy);
  const input = Buffer.from(source);
  const parsed = parseMachO(policy, input);
  if (parsed.stableSha256 !== policy.stableSha256) {
    throw new Error(
      `C19 ${policy.kind} immutable bytes differ from the reviewed stable digest.`,
    );
  }

  const normalized = Buffer.from(input);
  for (const range of parsed.ranges) {
    range.bytes.copy(normalized, range.offset);
  }
  const finalSha256 = sha256(normalized);
  if (finalSha256 !== policy.finalSha256) {
    throw new Error(`C19 ${policy.kind} final SHA-256 differs from policy.`);
  }
  parseMachO(policy, normalized);
  return normalized;
}

function validatePolicy(policy: C19CustodyBinaryPolicy): void {
  if (!SHA256_PATTERN.test(policy.stableSha256)
    || !SHA256_PATTERN.test(policy.finalSha256)
    || !/^[0-9a-f]{32}$/u.test(policy.uuidHex)) {
    throw new Error(`C19 ${policy.kind} policy digest is malformed.`);
  }
  if (policy.oso.length === 0) {
    throw new Error(`C19 ${policy.kind} N_OSO inventory is empty.`);
  }
  const suffixes = new Set<string>();
  for (const entry of policy.oso) {
    if (!CACHE_KEY_PATTERN.test(entry.cacheKey)
      || !/^[0-9a-f]{8}$/u.test(entry.timestampHex)
      || !/^\/[A-Za-z0-9_.-]+\.o$/u.test(entry.objectSuffix)
      || suffixes.has(entry.objectSuffix)) {
      throw new Error(`C19 ${policy.kind} N_OSO policy is malformed.`);
    }
    suffixes.add(entry.objectSuffix);
  }
}

function parseMachO(policy: C19CustodyBinaryPolicy, bytes: Buffer): ParsedMachO {
  if (bytes.byteLength !== policy.size) {
    throw new Error(`C19 ${policy.kind} Mach-O size differs from policy.`);
  }
  if (u32le(bytes, 0, "Mach-O magic") !== MACHO_64_MAGIC
    || u32le(bytes, 4, "Mach-O CPU") !== CPU_TYPE_ARM64
    || u32le(bytes, 12, "Mach-O file type") !== MH_EXECUTE) {
    throw new Error(`C19 ${policy.kind} must be one thin arm64 executable.`);
  }
  const ncmds = u32le(bytes, 16, "Mach-O command count");
  const sizeofcmds = u32le(bytes, 20, "Mach-O command size");
  if (ncmds !== policy.layout.ncmds || sizeofcmds !== policy.layout.sizeofcmds) {
    throw new Error(`C19 ${policy.kind} load-command layout differs from policy.`);
  }
  const commandsEnd = MACH_HEADER_64_BYTES + sizeofcmds;
  if (commandsEnd > bytes.byteLength || commandsEnd % 8 !== 0) {
    throw new Error(`C19 ${policy.kind} load-command region is malformed.`);
  }

  let cursor = MACH_HEADER_64_BYTES;
  let uuidPayloadOffset: number | undefined;
  let symtab: C19CustodyBinaryPolicy["layout"] | undefined;
  let signature: Readonly<{ offset: number; size: number }> | undefined;
  for (let index = 0; index < ncmds; index += 1) {
    const command = u32le(bytes, cursor, "Mach-O load command");
    const commandSize = u32le(bytes, cursor + 4, "Mach-O load command size");
    if (commandSize < 8 || commandSize % 8 !== 0 || cursor + commandSize > commandsEnd) {
      throw new Error(`C19 ${policy.kind} load command is malformed.`);
    }
    if (command === LC_UUID) {
      if (commandSize !== 24 || uuidPayloadOffset !== undefined) {
        throw new Error(`C19 ${policy.kind} LC_UUID layout is malformed.`);
      }
      uuidPayloadOffset = cursor + 8;
    } else if (command === LC_SYMTAB) {
      if (commandSize !== 24 || symtab !== undefined) {
        throw new Error(`C19 ${policy.kind} LC_SYMTAB layout is malformed.`);
      }
      symtab = Object.freeze({
        ncmds,
        nsyms: u32le(bytes, cursor + 12, "Mach-O symbol count"),
        sizeofcmds,
        stroff: u32le(bytes, cursor + 16, "Mach-O string-table offset"),
        strsize: u32le(bytes, cursor + 20, "Mach-O string-table size"),
        symoff: u32le(bytes, cursor + 8, "Mach-O symbol-table offset"),
      });
    } else if (command === LC_CODE_SIGNATURE) {
      if (commandSize !== 16 || signature !== undefined) {
        throw new Error(`C19 ${policy.kind} LC_CODE_SIGNATURE layout is malformed.`);
      }
      signature = Object.freeze({
        offset: u32le(bytes, cursor + 8, "code-signature offset"),
        size: u32le(bytes, cursor + 12, "code-signature size"),
      });
    }
    cursor += commandSize;
  }
  if (cursor !== commandsEnd
    || uuidPayloadOffset !== policy.uuidOffset
    || symtab === undefined
    || signature === undefined
    || !layoutEquals(symtab, policy.layout)
    || signature.offset !== policy.codeSignature.offset
    || signature.size !== policy.codeSignature.size
    || signature.offset + signature.size !== bytes.byteLength) {
    throw new Error(`C19 ${policy.kind} exact Mach-O layout differs from policy.`);
  }
  const symbolBytes = symtab.nsyms * NLIST_64_BYTES;
  if (!Number.isSafeInteger(symbolBytes)
    || symtab.symoff < commandsEnd
    || symtab.symoff + symbolBytes > symtab.stroff
    || symtab.stroff + symtab.strsize > signature.offset) {
    throw new Error(`C19 ${policy.kind} symbol-table layout is malformed.`);
  }

  validateAdHocSignature(bytes, signature.offset, signature.size, policy.kind);
  const targetSignature = Buffer.from(policy.codeSignature.base64, "base64");
  if (targetSignature.byteLength !== signature.size) {
    throw new Error(`C19 ${policy.kind} signature payload size differs from policy.`);
  }
  validateAdHocSignature(targetSignature, 0, targetSignature.byteLength, policy.kind);

  const ranges: PatchRange[] = [
    Object.freeze({
      bytes: exactHex(policy.uuidHex, 16, `${policy.kind} UUID`),
      label: "LC_UUID",
      length: 16,
      offset: uuidPayloadOffset,
    }),
    Object.freeze({
      bytes: targetSignature,
      label: "LC_CODE_SIGNATURE",
      length: signature.size,
      offset: signature.offset,
    }),
  ];
  parseOsoRanges(policy, bytes, symtab, ranges);
  const orderedRanges = Object.freeze(validateAndSortRanges(policy, ranges));
  return Object.freeze({
    ranges: orderedRanges,
    stableSha256: stableSha256(bytes, orderedRanges),
  });
}

function parseOsoRanges(
  policy: C19CustodyBinaryPolicy,
  bytes: Buffer,
  symtab: C19CustodyBinaryPolicy["layout"],
  ranges: PatchRange[],
): void {
  const stringEnd = symtab.stroff + symtab.strsize;
  const found: Readonly<{
    cacheOffset: number;
    objectSuffix: string;
    timestampOffset: number;
  }>[] = [];
  let canonicalPrefix: string | undefined;
  for (let index = 0; index < symtab.nsyms; index += 1) {
    const symbolOffset = symtab.symoff + index * NLIST_64_BYTES;
    if (bytes[symbolOffset + 4] !== N_OSO) continue;
    if (bytes[symbolOffset + 5] !== 0 || bytes.readUInt16LE(symbolOffset + 6) !== 1) {
      throw new Error(`C19 ${policy.kind} N_OSO symbol metadata is malformed.`);
    }
    const stringIndex = u32le(bytes, symbolOffset, "N_OSO string index");
    if (stringIndex === 0 || stringIndex >= symtab.strsize) {
      throw new Error(`C19 ${policy.kind} N_OSO string index is malformed.`);
    }
    const stringOffset = symtab.stroff + stringIndex;
    const nulOffset = bytes.subarray(stringOffset, stringEnd).indexOf(0);
    if (nulOffset < 1) {
      throw new Error(`C19 ${policy.kind} N_OSO path is unterminated.`);
    }
    const pathBytes = bytes.subarray(stringOffset, stringOffset + nulOffset);
    if (!pathBytes.every((value) => value >= 0x20 && value <= 0x7e)) {
      throw new Error(`C19 ${policy.kind} N_OSO path must be canonical ASCII.`);
    }
    const path = pathBytes.toString("ascii");
    const parsed = parseCanonicalOsoPath(policy.kind, path);
    canonicalPrefix ??= parsed.prefix;
    if (parsed.prefix !== canonicalPrefix) {
      throw new Error(`C19 ${policy.kind} N_OSO roots are inconsistent.`);
    }
    if (u32le(bytes, symbolOffset + 12, "N_OSO timestamp high word") !== 0) {
      throw new Error(`C19 ${policy.kind} N_OSO timestamp width differs from policy.`);
    }
    found.push(Object.freeze({
      cacheOffset: stringOffset + parsed.prefix.length,
      objectSuffix: parsed.objectSuffix,
      timestampOffset: symbolOffset + 8,
    }));
  }
  if (canonicalPrefix === undefined || found.length !== policy.oso.length) {
    throw new Error(`C19 ${policy.kind} N_OSO inventory differs from policy.`);
  }
  const bySuffix = new Map(found.map((entry) => [entry.objectSuffix, entry]));
  if (bySuffix.size !== found.length) {
    throw new Error(`C19 ${policy.kind} N_OSO inventory contains duplicates.`);
  }
  for (const target of policy.oso) {
    const source = bySuffix.get(target.objectSuffix);
    if (source === undefined) {
      throw new Error(`C19 ${policy.kind} N_OSO inventory differs from policy.`);
    }
    ranges.push(
      Object.freeze({
        bytes: Buffer.from(target.timestampHex, "hex"),
        label: `N_OSO mtime ${target.objectSuffix}`,
        length: 4,
        offset: source.timestampOffset,
      }),
      Object.freeze({
        bytes: Buffer.from(target.cacheKey, "ascii"),
        label: `N_OSO cache key ${target.objectSuffix}`,
        length: 32,
        offset: source.cacheOffset,
      }),
    );
  }
}

function parseCanonicalOsoPath(
  kind: C19CustodyBinaryKind,
  path: string,
): Readonly<{ prefix: string; objectSuffix: string }> {
  const markerOffset = path.indexOf(CACHE_ROOT_MARKER);
  if (markerOffset <= 0
    || markerOffset !== path.lastIndexOf(CACHE_ROOT_MARKER)
    || !path.startsWith("/")
    || path.includes("//")
    || path.includes("/./")
    || path.includes("/../")
    || path.includes("\\")) {
    throw new Error(`C19 ${kind} N_OSO root is not canonical.`);
  }
  const prefixEnd = markerOffset + CACHE_ROOT_MARKER.length;
  const prefix = path.slice(0, prefixEnd);
  const cacheKey = path.slice(prefixEnd, prefixEnd + 32);
  const objectSuffix = path.slice(prefixEnd + 32);
  if (!CACHE_KEY_PATTERN.test(cacheKey)
    || !/^\/[A-Za-z0-9_.-]+\.o$/u.test(objectSuffix)) {
    throw new Error(`C19 ${kind} N_OSO cache path is malformed.`);
  }
  return Object.freeze({ objectSuffix, prefix });
}

function validateAdHocSignature(
  bytes: Buffer,
  offset: number,
  size: number,
  kind: C19CustodyBinaryKind,
): void {
  requireRange(bytes, offset, size, "code signature");
  if (size < 44 || u32be(bytes, offset, "signature magic") !== CSMAGIC_EMBEDDED_SIGNATURE) {
    throw new Error(`C19 ${kind} ad-hoc signature is malformed.`);
  }
  const superblobLength = u32be(bytes, offset + 4, "signature length");
  const count = u32be(bytes, offset + 8, "signature slot count");
  if (superblobLength < 44 || superblobLength > size || count !== 1) {
    throw new Error(`C19 ${kind} ad-hoc signature layout is malformed.`);
  }
  const slotType = u32be(bytes, offset + 12, "signature slot type");
  const slotOffset = u32be(bytes, offset + 16, "signature slot offset");
  const codeDirectoryOffset = offset + slotOffset;
  if (slotType !== 0 || slotOffset < 20 || codeDirectoryOffset + 16 > offset + superblobLength
    || u32be(bytes, codeDirectoryOffset, "CodeDirectory magic") !== CSMAGIC_CODEDIRECTORY) {
    throw new Error(`C19 ${kind} CodeDirectory slot is malformed.`);
  }
  const codeDirectoryLength = u32be(
    bytes,
    codeDirectoryOffset + 4,
    "CodeDirectory length",
  );
  const flags = u32be(bytes, codeDirectoryOffset + 12, "CodeDirectory flags");
  if (codeDirectoryLength < 16
    || codeDirectoryOffset + codeDirectoryLength > offset + superblobLength
    || (flags & CS_ADHOC) === 0
    || !bytes.subarray(offset + superblobLength, offset + size).every((value) => value === 0)) {
    throw new Error(`C19 ${kind} ad-hoc CodeDirectory is malformed.`);
  }
}

function validateAndSortRanges(
  policy: C19CustodyBinaryPolicy,
  ranges: readonly PatchRange[],
): PatchRange[] {
  const ordered = [...ranges].sort((left, right) => left.offset - right.offset);
  let previousEnd = 0;
  for (const range of ordered) {
    if (range.length <= 0
      || range.bytes.byteLength !== range.length
      || range.offset < previousEnd
      || range.offset + range.length > policy.size) {
      throw new Error(`C19 ${policy.kind} volatile ranges overlap or escape the file.`);
    }
    previousEnd = range.offset + range.length;
  }
  return ordered;
}

function stableSha256(bytes: Buffer, ranges: readonly PatchRange[]): string {
  const hash = createHash("sha256");
  let cursor = 0;
  for (const range of ranges) {
    hash.update(bytes.subarray(cursor, range.offset));
    cursor = range.offset + range.length;
  }
  hash.update(bytes.subarray(cursor));
  return hash.digest("hex");
}

function layoutEquals(
  left: C19CustodyBinaryPolicy["layout"],
  right: C19CustodyBinaryPolicy["layout"],
): boolean {
  return left.ncmds === right.ncmds
    && left.nsyms === right.nsyms
    && left.sizeofcmds === right.sizeofcmds
    && left.stroff === right.stroff
    && left.strsize === right.strsize
    && left.symoff === right.symoff;
}

function exactHex(hex: string, length: number, label: string): Buffer {
  if (!new RegExp(`^[0-9a-f]{${length * 2}}$`, "u").test(hex)) {
    throw new Error(`${label} bytes are malformed.`);
  }
  return Buffer.from(hex, "hex");
}

function requireRange(bytes: Buffer, offset: number, length: number, label: string): void {
  if (!Number.isSafeInteger(offset)
    || !Number.isSafeInteger(length)
    || offset < 0
    || length < 0
    || offset + length > bytes.byteLength) {
    throw new Error(`${label} escapes the Mach-O file.`);
  }
}

function u32le(bytes: Buffer, offset: number, label: string): number {
  requireRange(bytes, offset, 4, label);
  return bytes.readUInt32LE(offset);
}

function u32be(bytes: Buffer, offset: number, label: string): number {
  requireRange(bytes, offset, 4, label);
  return bytes.readUInt32BE(offset);
}

function sha256(bytes: Uint8Array): string {
  return createHash("sha256").update(bytes).digest("hex");
}

async function readImmutableRegularFile(path: string): Promise<Readonly<{
  bytes: Buffer;
  mode: number;
}>> {
  const handle = await open(path, constants.O_RDONLY | constants.O_NOFOLLOW);
  try {
    const before = await handle.stat({ bigint: true });
    if (!before.isFile()) {
      throw new Error("Custody normalizer input must be a regular file.");
    }
    const bytes = await handle.readFile();
    const after = await handle.stat({ bigint: true });
    const pathStat = await lstat(path, { bigint: true });
    if (before.dev !== after.dev
      || before.ino !== after.ino
      || before.size !== after.size
      || before.mtimeNs !== after.mtimeNs
      || before.ctimeNs !== after.ctimeNs
      || pathStat.isSymbolicLink()
      || !pathStat.isFile()
      || pathStat.dev !== before.dev
      || pathStat.ino !== before.ino
      || BigInt(bytes.byteLength) !== before.size) {
      throw new Error("Custody normalizer input changed while it was read.");
    }
    return Object.freeze({ bytes, mode: Number(before.mode & 0o777n) });
  } finally {
    await handle.close();
  }
}

async function verifyCodeSignature(path: string): Promise<void> {
  const child = Bun.spawn(
    ["/usr/bin/codesign", "--verify", "--strict", path],
    { stderr: "ignore", stdout: "ignore" },
  );
  if (await child.exited !== 0) {
    throw new Error("Normalized C19 custody binary failed strict codesign verification.");
  }
}

async function publishAtomicExclusive(
  outputPath: string,
  bytes: Buffer,
  mode: number,
  expectedSha256: string,
): Promise<void> {
  const suffix = randomBytes(16).toString("hex");
  const temporaryPath = `${outputPath}.hra-c19-${suffix}.tmp`;
  const outputParent = dirname(outputPath);
  const parentHandle = await open(
    outputParent,
    constants.O_RDONLY | constants.O_NOFOLLOW | constants.O_DIRECTORY,
  );
  const parentIdentity = await parentHandle.stat({ bigint: true });
  if (!parentIdentity.isDirectory()) {
    await parentHandle.close();
    throw new Error("Custody normalization output parent is not a directory.");
  }
  const requireSameParent = async (): Promise<void> => {
    const current = await lstat(outputParent, { bigint: true });
    if (current.isSymbolicLink()
      || !current.isDirectory()
      || current.dev !== parentIdentity.dev
      || current.ino !== parentIdentity.ino) {
      throw new Error("Custody normalization output parent changed during publication.");
    }
  };
  let published = false;
  try {
    await requireSameParent();
    const handle = await open(
      temporaryPath,
      constants.O_CREAT | constants.O_EXCL | constants.O_WRONLY | constants.O_NOFOLLOW,
      mode,
    );
    try {
      await handle.writeFile(bytes);
      await handle.sync();
    } finally {
      await handle.close();
    }
    if (sha256((await readImmutableRegularFile(temporaryPath)).bytes) !== expectedSha256) {
      throw new Error("Normalized C19 custody temporary output changed after write.");
    }
    await verifyCodeSignature(temporaryPath);
    await requireSameParent();
    await link(temporaryPath, outputPath);
    published = true;
    await unlink(temporaryPath);
    await requireSameParent();
    await parentHandle.sync();
    if (sha256((await readImmutableRegularFile(outputPath)).bytes) !== expectedSha256) {
      throw new Error("Normalized C19 custody output changed after publication.");
    }
    await verifyCodeSignature(outputPath);
  } catch (error) {
    await unlink(temporaryPath).catch(() => undefined);
    if (published) await unlink(outputPath).catch(() => undefined);
    throw error;
  } finally {
    await parentHandle.close();
  }
}

function parseCliArguments(argv: readonly string[]): Readonly<{
  inputPath: string;
  kind: C19CustodyBinaryKind;
  outputPath: string;
}> {
  const usage =
    "Usage: normalize-c19-custody-binary.ts --kind <custodian|verifier|candidate> --input <path> --output <path>";
  if (argv.length !== 6) throw new Error(usage);
  const values = new Map<string, string>();
  for (let index = 0; index < argv.length; index += 2) {
    const key = argv[index];
    const value = argv[index + 1];
    if (key === undefined
      || value === undefined
      || !["--kind", "--input", "--output"].includes(key)
      || values.has(key)) {
      throw new Error(usage);
    }
    values.set(key, value);
  }
  const kind = values.get("--kind");
  const input = values.get("--input");
  const output = values.get("--output");
  if ((kind !== "custodian" && kind !== "verifier" && kind !== "candidate")
    || input === undefined
    || output === undefined) {
    throw new Error(usage);
  }
  const inputPath = resolve(input);
  const outputPath = resolve(output);
  if (inputPath === outputPath || basename(outputPath).length === 0) {
    throw new Error("Custody normalization requires a separate output path.");
  }
  return Object.freeze({ inputPath, kind, outputPath });
}

if (import.meta.main) {
  const { inputPath, kind, outputPath } = parseCliArguments(process.argv.slice(2));
  const source = await readImmutableRegularFile(inputPath);
  const policy = c19CustodyBinaryPolicies[kind];
  const normalized = normalizeC19CustodyBinary(kind, source.bytes);
  await publishAtomicExclusive(outputPath, normalized, source.mode, policy.finalSha256);
  console.log(JSON.stringify(Object.freeze({
    kind,
    schemaVersion: 1,
    sha256: policy.finalSha256,
    status: "normalized",
  })));
}
