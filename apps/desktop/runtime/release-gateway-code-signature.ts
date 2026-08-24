const MACH_O_64_MAGIC = 0xfeedfacf;
const CPU_TYPE_ARM64 = 0x0100000c;
const MACH_O_EXECUTE = 2;
const LC_CODE_SIGNATURE = 0x1d;
const EMBEDDED_SIGNATURE_MAGIC = 0xfade0cc0;
const MACH_O_HEADER_BYTES = 32;
const LINKEDIT_DATA_COMMAND_BYTES = 16;
const MAXIMUM_LOAD_COMMAND_COUNT = 4_096;
const MAXIMUM_LOAD_COMMAND_BYTES = 16 * 1024 * 1024;
const MAXIMUM_CODE_SIGNATURE_BYTES = 64 * 1024 * 1024;
const MAXIMUM_SUPERBLOB_COUNT = 64;

function reject(detail: string): never {
  throw new Error(`Final gateway code-signature container is not exact: ${detail}.`);
}

function bytesAreZero(
  bytes: Uint8Array,
  start: number,
  end: number,
): boolean {
  for (let index = start; index < end; index += 1) {
    if (bytes[index] !== 0) return false;
  }
  return true;
}

export function verifyReleaseGatewayCodeSignature(
  bytes: Uint8Array,
): void {
  if (bytes.byteLength < MACH_O_HEADER_BYTES) reject("truncated Mach-O header");
  const view = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength);
  if (view.getUint32(0, true) !== MACH_O_64_MAGIC ||
      view.getUint32(4, true) !== CPU_TYPE_ARM64 ||
      view.getUint32(12, true) !== MACH_O_EXECUTE ||
      view.getUint32(28, true) !== 0) {
    reject("unexpected Mach-O identity");
  }

  const commandCount = view.getUint32(16, true);
  const commandBytes = view.getUint32(20, true);
  const commandsEnd = MACH_O_HEADER_BYTES + commandBytes;
  if (commandCount === 0 || commandCount > MAXIMUM_LOAD_COMMAND_COUNT ||
      commandBytes < 8 || commandBytes > MAXIMUM_LOAD_COMMAND_BYTES ||
      commandsEnd > bytes.byteLength) {
    reject("invalid load-command envelope");
  }

  let cursor = MACH_O_HEADER_BYTES;
  let signatureOffset = -1;
  let signatureLength = -1;
  for (let index = 0; index < commandCount; index += 1) {
    if (cursor + 8 > commandsEnd) reject("truncated load command");
    const command = view.getUint32(cursor, true);
    const commandSize = view.getUint32(cursor + 4, true);
    if (commandSize < 8 || (commandSize & 7) !== 0 ||
        cursor + commandSize > commandsEnd) {
      reject("invalid load-command size");
    }
    if (command === LC_CODE_SIGNATURE) {
      if (commandSize !== LINKEDIT_DATA_COMMAND_BYTES || signatureOffset !== -1) {
        reject("duplicate or malformed LC_CODE_SIGNATURE");
      }
      signatureOffset = view.getUint32(cursor + 8, true);
      signatureLength = view.getUint32(cursor + 12, true);
    }
    cursor += commandSize;
  }
  if (cursor !== commandsEnd || signatureOffset < commandsEnd ||
      (signatureOffset & 15) !== 0 || signatureLength < 12 ||
      signatureLength > MAXIMUM_CODE_SIGNATURE_BYTES ||
      signatureOffset + signatureLength !== bytes.byteLength) {
    reject("invalid code-signature range");
  }

  if (view.getUint32(signatureOffset, false) !== EMBEDDED_SIGNATURE_MAGIC) {
    reject("missing embedded SuperBlob");
  }
  const superBlobLength = view.getUint32(signatureOffset + 4, false);
  const blobCount = view.getUint32(signatureOffset + 8, false);
  const indexEnd = 12 + blobCount * 8;
  if (superBlobLength < 12 || superBlobLength > signatureLength ||
      blobCount === 0 || blobCount > MAXIMUM_SUPERBLOB_COUNT ||
      indexEnd > superBlobLength) {
    reject("invalid SuperBlob envelope");
  }

  const blobs: Array<{ readonly offset: number; readonly length: number }> = [];
  const offsets = new Set<number>();
  const types = new Set<number>();
  for (let index = 0; index < blobCount; index += 1) {
    const entry = signatureOffset + 12 + index * 8;
    const type = view.getUint32(entry, false);
    const offset = view.getUint32(entry + 4, false);
    if (types.has(type) || offsets.has(offset) || offset < indexEnd ||
        offset + 8 > superBlobLength) {
      reject("invalid SuperBlob index");
    }
    const length = view.getUint32(signatureOffset + offset + 4, false);
    if (length < 8 || offset + length > superBlobLength) {
      reject("invalid embedded blob range");
    }
    types.add(type);
    offsets.add(offset);
    blobs.push({ length, offset });
  }

  blobs.sort((left, right) => left.offset - right.offset);
  let blobCursor = indexEnd;
  for (const blob of blobs) {
    if (blob.offset < blobCursor ||
        !bytesAreZero(
          bytes,
          signatureOffset + blobCursor,
          signatureOffset + blob.offset,
        )) {
      reject("overlapping blobs or nonzero SuperBlob padding");
    }
    blobCursor = blob.offset + blob.length;
  }
  if (!bytesAreZero(
        bytes,
        signatureOffset + blobCursor,
        signatureOffset + superBlobLength,
      ) ||
      !bytesAreZero(
        bytes,
        signatureOffset + superBlobLength,
        signatureOffset + signatureLength,
      )) {
    reject("nonzero bytes outside declared embedded blobs");
  }
}
