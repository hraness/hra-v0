import { writeFile } from "node:fs/promises";
import { rendererAuthorityC, rendererAuthorityEntries } from "./renderer-authority";

const [frontendRoot, output] = process.argv.slice(2);
if (frontendRoot === undefined || output === undefined || process.argv.length !== 4) {
  throw new Error("Usage: generate-renderer-authority.ts <frontend-dist> <output.c>");
}
await writeFile(output, rendererAuthorityC(await rendererAuthorityEntries(frontendRoot)), {
  encoding: "utf8",
  flag: "wx",
});
