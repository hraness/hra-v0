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
  tag: z.string().regex(/^v0\.1\.(?:7|8|9|10|11|12|13|14|15|16)$/u),
  tagObject: objectIdSchema,
  version: z.string().regex(/^0\.1\.(?:7|8|9|10|11|12|13|14|15|16)$/u),
}).strict();
const generationZeroVersions = [
  "0.1.7",
  "0.1.8",
  "0.1.9",
  "0.1.10",
  "0.1.11",
  "0.1.12",
  "0.1.13",
  "0.1.14",
] as const;
const generationOneVersions = [...generationZeroVersions, "0.1.15"] as const;
const generationTwoVersions = [...generationOneVersions, "0.1.16"] as const;
const releaseHistoryBaseSchema = {
  repository: z.literal("https://github.com/hraness/hra-v0"),
  repositoryId: z.literal(1_334_876_494),
  schemaVersion: z.literal(1),
};
const generationZeroReleaseHistorySchema = z.object({
  generation: z.literal(0),
  publicationCommit: z.literal("6221f79b745f154882080936b961ff431569f33e"),
  ...releaseHistoryBaseSchema,
  tags: z.array(tagSchema).length(8),
}).strict();
const generationOneReleaseHistorySchema = z.object({
  generation: z.literal(1),
  publicationCommit: z.literal("d96173c3556799cb203a4d659f29856180838029"),
  ...releaseHistoryBaseSchema,
  tags: z.array(tagSchema).length(9),
}).strict();
const generationTwoReleaseHistorySchema = z.object({
  generation: z.literal(2),
  publicationCommit: z.literal("67e89e7909a56f5bfad1e16bb73801c9cd41503e"),
  ...releaseHistoryBaseSchema,
  tags: z.array(tagSchema).length(10),
}).strict();
const releaseHistorySchema = z.discriminatedUnion("generation", [
  generationZeroReleaseHistorySchema,
  generationOneReleaseHistorySchema,
  generationTwoReleaseHistorySchema,
]).superRefine((history, context) => {
  const expectedVersions = history.generation === 0
    ? generationZeroVersions
    : history.generation === 1
      ? generationOneVersions
      : generationTwoVersions;
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
        message: `Release history must contain the exact ordered v0.1.7–v0.1.${history.generation === 0 ? "14" : history.generation === 1 ? "15" : "16"} tag and release sequence.`,
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

export function parseHraReleaseHistory(value: unknown): HraReleaseHistory {
  return releaseHistorySchema.parse(value);
}

export const HRA_RELEASE_HISTORY = parseHraReleaseHistory(releaseHistory);

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
