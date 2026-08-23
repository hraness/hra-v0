import { z } from "@hra-internal/schema";

import releaseHistory from "../../../release-history.json";

const objectIdSchema = z.string().regex(/^[0-9a-f]{40}$/u);
const digestSchema = z.string().regex(/^[0-9a-f]{64}$/u);
const assetSchema = z.object({
  bytes: z.number().int().positive().safe(),
  id: z.number().int().positive().safe(),
  name: z.string().min(1).max(200),
  sha256: digestSchema,
}).strict();
const publishedReleaseSchema = z.object({
  assets: z.array(assetSchema).length(7),
  id: z.number().int().positive().safe(),
  immutable: z.literal(true),
  prerelease: z.literal(true),
  publishedAt: z.string().regex(/^2026-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z$/u),
}).strict();
const tagSchema = z.object({
  build: z.number().int().positive().safe(),
  commit: objectIdSchema,
  objectKind: z.literal("annotated"),
  release: publishedReleaseSchema.nullable(),
  tag: z.string().regex(/^v0\.1\.(?:7|8|9|10|11|12|13|14)$/u),
  tagObject: objectIdSchema,
  version: z.string().regex(/^0\.1\.(?:7|8|9|10|11|12|13|14)$/u),
}).strict();
const releaseHistorySchema = z.object({
  generation: z.literal(0),
  publicationCommit: z.literal("6221f79b745f154882080936b961ff431569f33e"),
  repository: z.literal("https://github.com/hraness/hra-v0"),
  repositoryId: z.literal(1_334_876_494),
  schemaVersion: z.literal(1),
  tags: z.array(tagSchema).length(8),
}).strict().superRefine((history, context) => {
  const expectedVersions = ["0.1.7", "0.1.8", "0.1.9", "0.1.10", "0.1.11", "0.1.12", "0.1.13", "0.1.14"] as const;
  for (const [index, version] of expectedVersions.entries()) {
    const entry = history.tags[index];
    if (
      entry === undefined
      || entry.version !== version
      || entry.tag !== `v${version}`
      || entry.build !== index + 8
      || (entry.release === null) !== (version === "0.1.11")
    ) {
      context.addIssue({
        code: "custom",
        message: "Release history must contain the exact ordered v0.1.7–v0.1.14 tag and release sequence.",
      });
      break;
    }
    if (entry.release !== null) {
      const assetIds = new Set(entry.release.assets.map(({ id }) => id));
      const assetNames = entry.release.assets.map(({ name }) => name);
      const expectedProductAssets = [
        `HRA-${version}-${entry.build}-macos-arm64.dmg`,
        `HRA-${version}-${entry.build}-macos-arm64.dmg.sha256`,
        `HRA-${version}-${entry.build}-release-manifest.json`,
      ];
      if (
        assetIds.size !== entry.release.assets.length
        || new Set(assetNames).size !== assetNames.length
        || !expectedProductAssets.every((name) => assetNames.includes(name))
        || assetNames.toSorted().join("\0") !== assetNames.join("\0")
      ) {
        context.addIssue({
          code: "custom",
          message: `Release ${entry.tag} must contain one sorted, unique seven-asset inventory.`,
        });
      }
    }
  }
});

export type HraReleaseHistory = z.infer<typeof releaseHistorySchema>;
export type HraReleaseHistoryTag = HraReleaseHistory["tags"][number];
export type HraReleaseHistoryAsset = NonNullable<HraReleaseHistoryTag["release"]>["assets"][number];

export const HRA_RELEASE_HISTORY = releaseHistorySchema.parse(releaseHistory);

export function hraReleaseTagUrl(entry: HraReleaseHistoryTag): string {
  return `${HRA_RELEASE_HISTORY.repository}/releases/tag/${entry.tag}`;
}

export function hraReleaseAssetUrl(
  entry: HraReleaseHistoryTag,
  asset: HraReleaseHistoryAsset,
): string {
  return `${HRA_RELEASE_HISTORY.repository}/releases/download/${entry.tag}/${asset.name}`;
}

export function hraTagObjectUrl(entry: HraReleaseHistoryTag): string {
  return `https://api.github.com/repos/hraness/hra-v0/git/tags/${entry.tagObject}`;
}

export function hraCommitUrl(entry: HraReleaseHistoryTag): string {
  return `${HRA_RELEASE_HISTORY.repository}/commit/${entry.commit}`;
}

export function formatReleaseBytes(bytes: number): string {
  if (bytes < 1_000) return `${bytes} B`;
  if (bytes < 1_000_000) return `${(bytes / 1_000).toFixed(1)} kB`;
  if (bytes < 1_000_000_000) return `${(bytes / 1_000_000).toFixed(1)} MB`;
  return `${(bytes / 1_000_000_000).toFixed(2)} GB`;
}
