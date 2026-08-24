import { describe, expect, test } from "bun:test";
import { createHash } from "node:crypto";
import {
  mkdir,
  mkdtemp,
  readFile,
  rm,
  writeFile,
} from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";

import {
  packagedRendererAuthorityEntries,
  rendererAuthorityRoot,
} from "../renderer-authority";
import {
  escapeExtendedRegularExpression,
  mutateRendererIndexFixture,
} from "../verify-macos-package-adversarial";

function rendererManifest(index: Buffer): string {
  const hash = createHash("sha256").update(index).digest("hex");
  return ".{ .assets = .{\n" +
    `  .{ .id = "index.html", .bundle_path = "index.html", .source_path = "frontend/dist/index.html", .byte_len = ${index.byteLength}, .hash = "${hash}" },\n` +
    "} }\n";
}

async function writeRendererFixture(root: string, index: Buffer): Promise<void> {
  await mkdir(root);
  await Promise.all([
    writeFile(join(root, "index.html"), index),
    writeFile(join(root, "asset-manifest.zon"), rendererManifest(index)),
  ]);
}

describe("macOS package adversarial renderer fixture", () => {
  test("quotes a fixture root as one literal extended regular expression", () => {
    expect(escapeExtendedRegularExpression(
      String.raw`/private/tmp/hra.[x]+(y)?^$|{z}\\fixture`,
    )).toBe(
      String.raw`/private/tmp/hra\.\[x\]\+\(y\)\?\^\$\|\{z\}\\\\fixture`,
    );
  });

  test("keeps a mutated renderer coherent before exercising native authority", async () => {
    const root = await mkdtemp(join(tmpdir(), "hra-renderer-adversarial-test-"));
    const coherentRoot = join(root, "coherent");
    const staleRoot = join(root, "stale");
    const index = Buffer.from("<!doctype html><title>HRA</title>\n", "utf8");
    try {
      await Promise.all([
        writeRendererFixture(coherentRoot, index),
        writeRendererFixture(staleRoot, index),
      ]);
      const baselineRoot = rendererAuthorityRoot(
        await packagedRendererAuthorityEntries(coherentRoot),
      );
      await writeFile(
        join(staleRoot, "index.html"),
        Buffer.concat([index, Buffer.from("stale", "utf8")]),
      );
      let staleError: unknown;
      try {
        await packagedRendererAuthorityEntries(staleRoot);
      } catch (error) {
        staleError = error;
      }
      expect(staleError).toBeInstanceOf(Error);
      if (!(staleError instanceof Error)) {
        throw new Error("Stale renderer fixture was not rejected with an Error.");
      }
      expect(staleError.message).toBe(
        "Packaged renderer asset manifest differs from its exact payload tree.",
      );

      const before = await Promise.all([
        readFile(join(coherentRoot, "asset-manifest.zon")),
        readFile(join(coherentRoot, "index.html")),
      ]);
      await mutateRendererIndexFixture(coherentRoot);
      const after = await Promise.all([
        readFile(join(coherentRoot, "asset-manifest.zon")),
        readFile(join(coherentRoot, "index.html")),
      ]);
      expect(after[0].equals(before[0])).toBe(false);
      expect(after[1].equals(before[1])).toBe(false);
      expect(rendererAuthorityRoot(
        await packagedRendererAuthorityEntries(coherentRoot),
      )).not.toBe(baselineRoot);
    } finally {
      await rm(root, { force: true, recursive: true });
    }
  });
});
