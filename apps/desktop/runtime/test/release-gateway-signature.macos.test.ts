import { describe, expect, test } from "bun:test";
import { readFile } from "node:fs/promises";

import { verifyReleaseGatewayCodeSignature } from "../release-gateway-code-signature";

const MACH_O_HEADER_BYTES = 32;
const LC_CODE_SIGNATURE = 0x1d;

function releaseGatewaySignatureTail(
  bytes: Uint8Array,
): { readonly end: number; readonly start: number } {
  const view = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength);
  const commandCount = view.getUint32(16, true);
  let cursor = MACH_O_HEADER_BYTES;
  for (let index = 0; index < commandCount; index += 1) {
    const command = view.getUint32(cursor, true);
    const commandSize = view.getUint32(cursor + 4, true);
    if (command === LC_CODE_SIGNATURE) {
      const signatureOffset = view.getUint32(cursor + 8, true);
      const signatureLength = view.getUint32(cursor + 12, true);
      const superBlobLength = view.getUint32(signatureOffset + 4, false);
      return {
        end: signatureOffset + signatureLength,
        start: signatureOffset + superBlobLength,
      };
    }
    cursor += commandSize;
  }
  throw new Error("Built release gateway has no LC_CODE_SIGNATURE command.");
}

describe("release gateway signature", () => {
  test("zeroes every reserved byte outside the final embedded SuperBlob", async () => {
    const gateway = new Uint8Array(await readFile(
      new URL("../dist/oprte-gateway", import.meta.url),
    ));
    verifyReleaseGatewayCodeSignature(gateway);

    const tail = releaseGatewaySignatureTail(gateway);
    expect(tail.end).toBe(gateway.byteLength);
    expect(tail.start).toBeLessThan(tail.end);

    const corrupted = gateway.slice();
    corrupted[tail.start] = 0xa5;
    expect(() => verifyReleaseGatewayCodeSignature(corrupted)).toThrow(
      "nonzero bytes outside declared embedded blobs",
    );
  });
});
