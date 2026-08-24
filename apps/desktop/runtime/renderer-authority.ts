import { createHash } from "node:crypto";
import { lstat, readdir, readFile } from "node:fs/promises";
import { join, posix, relative, resolve, sep } from "node:path";

export type RendererAuthorityEntry = Readonly<{
  relativePath: string;
  sha256: string | null;
  size: number;
  type: "directory" | "file";
}>;

const manifestName = "asset-manifest.zon";
const viteProofDirectory = ".vite";
const maximumEntries = 4_096;
const maximumFileBytes = 16 * 1024 * 1024;
const maximumTotalBytes = 128 * 1024 * 1024;

function mediaType(path: string): string | null {
  const extension = posix.extname(path).slice(1).toLowerCase();
  return new Map<string, string>([
    ["png", "image/png"], ["jpg", "image/jpeg"], ["jpeg", "image/jpeg"],
    ["webp", "image/webp"], ["gif", "image/gif"], ["svg", "image/svg+xml"],
    ["bmp", "image/bmp"], ["ttf", "font/ttf"], ["otf", "font/otf"],
    ["woff", "font/woff"], ["woff2", "font/woff2"], ["txt", "text/plain"],
    ["md", "text/markdown"], ["csv", "text/csv"], ["json", "application/json"],
    ["strings", "text/plain"], ["ftl", "text/plain"], ["po", "text/plain"],
    ["mo", "application/octet-stream"], ["mp3", "audio/mpeg"],
    ["wav", "audio/wav"], ["ogg", "audio/ogg"], ["flac", "audio/flac"],
    ["m4a", "audio/mp4"], ["mp4", "video/mp4"], ["webm", "video/webm"],
    ["mov", "video/quicktime"], ["mkv", "video/x-matroska"],
  ]).get(extension) ?? null;
}

function canonicalRelative(root: string, absolute: string): string {
  const value = relative(root, absolute).split(sep).join("/");
  if (value.length === 0 || value.startsWith("/") || value.includes("\\") ||
      value.split("/").some((component) => component.length === 0 || component === "." || component === "..") ||
      Buffer.byteLength(value, "utf8") > 1_024) {
    throw new Error(`Renderer authority path is not canonical: ${value}`);
  }
  return value;
}

async function rendererAuthorityEntriesForShape(
  frontendRoot: string,
  packaged: boolean,
): Promise<readonly RendererAuthorityEntry[]> {
  const root = resolve(frontendRoot);
  const rootStat = await lstat(root);
  if (!rootStat.isDirectory() || rootStat.isSymbolicLink()) {
    throw new Error("Renderer authority root must be a real directory.");
  }
  const directories = new Set<string>();
  const files: Array<RendererAuthorityEntry & { bytes: Buffer }> = [];
  let totalBytes = 0;
  async function visit(directory: string): Promise<void> {
    const children = await readdir(directory, { withFileTypes: true });
    children.sort((left, right) => Buffer.from(left.name).compare(Buffer.from(right.name)));
    for (const child of children) {
      if (!packaged && directory === root && child.name === viteProofDirectory) continue;
      const absolute = join(directory, child.name);
      const path = canonicalRelative(root, absolute);
      const stat = await lstat(absolute);
      if (stat.isSymbolicLink()) {
        throw new Error(`Renderer authority rejects linked entry: ${path}`);
      }
      if (stat.isDirectory()) {
        directories.add(path);
        await visit(absolute);
        continue;
      }
      if (!stat.isFile() || stat.nlink !== 1 || stat.size > maximumFileBytes) {
        throw new Error(`Renderer authority rejects special or oversized entry: ${path}`);
      }
      const bytes = await readFile(absolute);
      const after = await lstat(absolute);
      if (bytes.byteLength !== stat.size || after.dev !== stat.dev || after.ino !== stat.ino ||
          after.size !== stat.size || after.mtimeMs !== stat.mtimeMs || after.ctimeMs !== stat.ctimeMs) {
        throw new Error(`Renderer authority entry changed while reading: ${path}`);
      }
      totalBytes += bytes.byteLength;
      if (totalBytes > maximumTotalBytes) throw new Error("Renderer authority tree is oversized.");
      files.push({
        bytes,
        relativePath: path,
        sha256: createHash("sha256").update(bytes).digest("hex"),
        size: bytes.byteLength,
        type: "file",
      });
    }
  }
  await visit(root);
  const manifests = files.filter(file => file.relativePath === manifestName);
  const payloadFiles = files.filter(file => file.relativePath !== manifestName);
  if (payloadFiles.length === 0 || files.length > maximumEntries ||
      (packaged ? manifests.length !== 1 : manifests.length !== 0)) {
    throw new Error("Renderer authority source inventory is invalid.");
  }
  payloadFiles.sort((left, right) => Buffer.from(left.relativePath).compare(Buffer.from(right.relativePath)));
  let manifest = ".{ .assets = .{\n";
  for (const file of payloadFiles) {
    const sourcePath = `frontend/dist/${file.relativePath}`;
    const contentType = mediaType(file.relativePath);
    manifest += `  .{ .id = "${file.relativePath}", .bundle_path = "${file.relativePath}", .source_path = "${sourcePath}", .byte_len = ${file.size}, .hash = "${file.sha256}"${contentType === null ? "" : `, .media_type = "${contentType}"`} },\n`;
  }
  manifest += "} }\n";
  const manifestBytes = Buffer.from(manifest, "utf8");
  if (packaged) {
    if (!manifests[0]!.bytes.equals(manifestBytes)) {
      throw new Error("Packaged renderer asset manifest differs from its exact payload tree.");
    }
  } else {
    files.push({
      bytes: manifestBytes,
      relativePath: manifestName,
      sha256: createHash("sha256").update(manifestBytes).digest("hex"),
      size: manifestBytes.byteLength,
      type: "file",
    });
  }
  for (const file of files) {
    const components = file.relativePath.split("/");
    for (let index = 1; index < components.length; index += 1) {
      directories.add(components.slice(0, index).join("/"));
    }
  }
  const entries: RendererAuthorityEntry[] = [
    ...[...directories].map((path): RendererAuthorityEntry => ({
      relativePath: path,
      sha256: null,
      size: 0,
      type: "directory",
    })),
    ...files.map((file): RendererAuthorityEntry => ({
      relativePath: file.relativePath,
      sha256: file.sha256,
      size: file.size,
      type: file.type,
    })),
  ];
  entries.sort((left, right) => Buffer.from(left.relativePath).compare(Buffer.from(right.relativePath)));
  if (entries.length > maximumEntries) throw new Error("Renderer authority has too many entries.");
  return Object.freeze(entries);
}

export async function rendererAuthorityEntries(
  frontendRoot: string,
): Promise<readonly RendererAuthorityEntry[]> {
  return rendererAuthorityEntriesForShape(frontendRoot, false);
}

export async function packagedRendererAuthorityEntries(
  frontendRoot: string,
): Promise<readonly RendererAuthorityEntry[]> {
  return rendererAuthorityEntriesForShape(frontendRoot, true);
}

export function rendererAuthorityRoot(entries: readonly RendererAuthorityEntry[]): string {
  const hash = createHash("sha256");
  hash.update("hra-renderer-authority-v1\0", "utf8");
  for (const entry of entries) {
    hash.update(entry.type === "directory" ? "d" : "f", "ascii");
    const path = Buffer.from(entry.relativePath, "utf8");
    const header = Buffer.alloc(4 + 8);
    header.writeUInt32BE(path.length, 0);
    header.writeBigUInt64BE(BigInt(entry.size), 4);
    hash.update(header);
    hash.update(path);
    if (entry.sha256 !== null) hash.update(Buffer.from(entry.sha256, "hex"));
  }
  return hash.digest("hex");
}

export function rendererAuthorityC(entries: readonly RendererAuthorityEntry[]): string {
  const root = rendererAuthorityRoot(entries);
  const rows = entries.map((entry) => {
    const pathBytes = [...Buffer.from(entry.relativePath, "utf8"), 0].map((value) => `0x${value.toString(16).padStart(2, "0")}`).join(", ");
    const digest = entry.sha256 === null ? "{0}" : `{${entry.sha256.match(/../gu)?.map((value) => `0x${value}`).join(", ")}}`;
    return `  { (const char[]){${pathBytes}}, ${Buffer.byteLength(entry.relativePath)}, ${entry.type === "directory" ? 1 : 2}, ${entry.type === "directory" ? "0755" : "0644"}, UINT64_C(${entry.size}), ${digest} },`;
  }).join("\n");
  const rootBytes = root.match(/../gu)?.map((value) => `0x${value}`).join(", ");
  return `#include <stddef.h>\n#include <stdint.h>\n\ntypedef struct {\n  const char *relative_path;\n  size_t relative_path_length;\n  uint8_t type;\n  uint32_t permissions;\n  uint64_t byte_length;\n  uint8_t sha256[32];\n} HRAMacOSRendererAuthorityEntry;\n\nconst HRAMacOSRendererAuthorityEntry HRAExpectedRendererAuthorityEntries[] = {\n${rows}\n};\nconst size_t HRAExpectedRendererAuthorityEntryCount = ${entries.length};\nconst uint8_t HRAExpectedRendererAuthorityRootSHA256[32] = {${rootBytes}};\nconst char HRAExpectedRendererAuthorityRootSHA256Hex[65] = "${root}";\n`;
}
