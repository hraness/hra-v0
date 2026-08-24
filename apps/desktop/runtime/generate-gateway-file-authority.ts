import { createHash } from "node:crypto";
import { constants } from "node:fs";
import { open, writeFile } from "node:fs/promises";

const oCloexec = (constants as typeof constants & { O_CLOEXEC?: number })
  .O_CLOEXEC ?? 0;

function renderGatewayAuthority(sha256: string): string {
  const bytes = sha256.match(/../gu);
  if (bytes === null || bytes.length !== 32) {
    throw new Error("Gateway file SHA-256 is invalid.");
  }
  const rows: string[] = [];
  for (let offset = 0; offset < bytes.length; offset += 8) {
    rows.push(`  ${bytes.slice(offset, offset + 8).map(value => `0x${value}`).join(", ")},`);
  }
  return [
    "#include <stdint.h>",
    "",
    "const uint8_t HRAExpectedGatewayFileSHA256[32] = {",
    ...rows,
    "};",
    `const char HRAExpectedGatewayFileSHA256Hex[65] = "${sha256}";`,
    "",
  ].join("\n");
}

export async function exactGatewayFileSha256(path: string): Promise<string> {
  const handle = await open(
    path,
    constants.O_RDONLY | constants.O_NOFOLLOW | oCloexec,
  );
  try {
    const before = await handle.stat({ bigint: true });
    if (!before.isFile() || before.nlink !== 1n || before.size <= 0n) {
      throw new Error("Gateway authority source must be a nonempty single-link file.");
    }
    const hasher = createHash("sha256");
    for await (const chunk of handle.readableWebStream()) {
      hasher.update(chunk as Uint8Array);
    }
    const after = await handle.stat({ bigint: true });
    if (
      before.dev !== after.dev
      || before.ino !== after.ino
      || before.mode !== after.mode
      || before.nlink !== after.nlink
      || before.size !== after.size
      || before.mtimeNs !== after.mtimeNs
      || before.ctimeNs !== after.ctimeNs
    ) {
      throw new Error("Gateway authority source changed while it was hashed.");
    }
    return hasher.digest("hex");
  } finally {
    await handle.close();
  }
}

async function main(): Promise<void> {
  const [gateway, output] = process.argv.slice(2);
  if (gateway === undefined || output === undefined || process.argv.length !== 4) {
    throw new Error("Usage: generate-gateway-file-authority.ts GATEWAY OUTPUT");
  }
  const sha256 = await exactGatewayFileSha256(gateway);
  await writeFile(output, renderGatewayAuthority(sha256), {
    flag: "wx",
    mode: 0o600,
  });
}

if (import.meta.main) await main();
