import { writeFile } from "node:fs/promises";

import {
  loadReleaseSigningAuthority,
  productionReleaseAuthorityPins,
} from "./release-signing-authority";

function renderBytes(name: string, bytes: Uint8Array): readonly string[] {
  const values = Buffer.from(bytes).toString("hex").match(/../gu);
  if (values === null) throw new Error(`${name} is empty.`);
  const rows: string[] = [];
  for (let offset = 0; offset < values.length; offset += 8) {
    rows.push(`  ${values.slice(offset, offset + 8).map(value => `0x${value}`).join(", ")},`);
  }
  return [`const uint8_t ${name}[${values.length}] = {`, ...rows, "};"];
}

async function main(): Promise<void> {
  const [input, output] = process.argv.slice(2);
  if (input === undefined || output === undefined || process.argv.length !== 4) {
    throw new Error("Usage: generate-release-signing-authority.ts INPUT OUTPUT");
  }
  const authority = await loadReleaseSigningAuthority(
    input,
    productionReleaseAuthorityPins,
  );
  const source = [
    "#include <stdint.h>",
    "",
    ...renderBytes("HRAReleaseLeafCertificateDER", authority.leaf.der),
    `const uint32_t HRAReleaseLeafCertificateDERLength = ${authority.leaf.der.length};`,
    ...renderBytes("HRAReleaseRootCertificateDER", authority.root.der),
    `const uint32_t HRAReleaseRootCertificateDERLength = ${authority.root.der.length};`,
    ...renderBytes("HRAReleaseLeafCertificateSHA1", Buffer.from(authority.leaf.sha1, "hex")),
    ...renderBytes("HRAReleaseLeafCertificateSHA256", Buffer.from(authority.leaf.sha256, "hex")),
    ...renderBytes("HRAReleaseRootCertificateSHA1", Buffer.from(authority.root.sha1, "hex")),
    ...renderBytes("HRAReleaseRootCertificateSHA256", Buffer.from(authority.root.sha256, "hex")),
    `const char HRAReleaseLeafCertificateSHA1Hex[41] = "${authority.leaf.sha1}";`,
    `const char HRAReleaseLeafCertificateSHA256Hex[65] = "${authority.leaf.sha256}";`,
    `const char HRAReleaseRootCertificateSHA1Hex[41] = "${authority.root.sha1}";`,
    `const char HRAReleaseRootCertificateSHA256Hex[65] = "${authority.root.sha256}";`,
    "",
  ].join("\n");
  await writeFile(output, source, { flag: "wx", mode: 0o600 });
}

if (import.meta.main) await main();
