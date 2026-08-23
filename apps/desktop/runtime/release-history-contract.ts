import { isDeepStrictEqual } from "node:util";

import { z } from "@hra-internal/schema";

import releaseHistory from "../../../release-history.json";

const repository = "https://github.com/hraness/hra-v0" as const;
const apiRepository = "https://api.github.com/repos/hraness/hra-v0" as const;
const objectIdSchema = z.string().regex(/^[0-9a-f]{40}$/u);
const digestSchema = z.string().regex(/^[0-9a-f]{64}$/u);
const assetSchema = z.object({
  bytes: z.number().int().positive().safe(),
  id: z.number().int().positive().safe(),
  name: z.string().min(1).max(200),
  sha256: digestSchema,
}).strict();
const releaseSchema = z.object({
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
  release: releaseSchema.nullable(),
  tag: z.string().regex(/^v0\.1\.(?:7|8|9|10|11|12|13|14)$/u),
  tagObject: objectIdSchema,
  version: z.string().regex(/^0\.1\.(?:7|8|9|10|11|12|13|14)$/u),
}).strict();
const releaseHistorySchema = z.object({
  generation: z.literal(0),
  publicationCommit: z.literal("6221f79b745f154882080936b961ff431569f33e"),
  repository: z.literal(repository),
  repositoryId: z.literal(1_334_876_494),
  schemaVersion: z.literal(1),
  tags: z.array(tagSchema).length(8),
}).strict().superRefine((history, context) => {
  const expected = ["0.1.7", "0.1.8", "0.1.9", "0.1.10", "0.1.11", "0.1.12", "0.1.13", "0.1.14"] as const;
  for (const [index, version] of expected.entries()) {
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
        message: "Release history must contain the exact ordered v0.1.7–v0.1.14 sequence.",
      });
      break;
    }
    if (entry.release !== null) {
      const names = entry.release.assets.map(({ name }) => name);
      const expectedNames = [
        `HRA-${version}-${entry.build}-macos-arm64.dmg`,
        `HRA-${version}-${entry.build}-macos-arm64.dmg.sha256`,
        `HRA-${version}-${entry.build}-release-manifest.json`,
      ];
      if (
        new Set(names).size !== names.length
        || new Set(entry.release.assets.map(({ id }) => id)).size !== entry.release.assets.length
        || names.join("\0") !== names.toSorted().join("\0")
        || !expectedNames.every((name) => names.includes(name))
      ) {
        context.addIssue({
          code: "custom",
          message: `Release ${entry.tag} must have one sorted, unique seven-asset inventory.`,
        });
      }
    }
  }
});

export type ReleaseHistoryContract = z.infer<typeof releaseHistorySchema>;
export type ReleaseHistoryFetcher = (url: string, init: RequestInit) => Promise<Response>;
export type RemoteReleaseHistoryEvidence = Readonly<{
  assetCount: 49;
  releaseCount: 7;
  repository: typeof repository;
  status: "verified_exact_remote_release_history";
  tagCount: 8;
  tagOnly: readonly ["v0.1.11"];
}>;

export function parseReleaseHistoryContract(value: unknown): ReleaseHistoryContract {
  return releaseHistorySchema.parse(value);
}

export function readReleaseHistoryContract(): ReleaseHistoryContract {
  return parseReleaseHistoryContract(releaseHistory);
}

export async function verifyRemoteReleaseHistory(
  fetcher: ReleaseHistoryFetcher = fetch,
): Promise<RemoteReleaseHistoryEvidence> {
  return await verifyRemoteReleaseHistoryState(readReleaseHistoryContract(), fetcher);
}

export async function verifyRemoteReleaseHistoryState(
  contract: ReleaseHistoryContract,
  fetcher: ReleaseHistoryFetcher,
): Promise<RemoteReleaseHistoryEvidence> {
  const [releaseResponse, refsResponse] = await Promise.all([
    fetchJson(fetcher, `${apiRepository}/releases?per_page=100`, "GitHub release history", 8 * 1_024 * 1_024),
    fetchJson(fetcher, `${apiRepository}/git/matching-refs/tags/v0.1`, "GitHub release tags", 1_048_576),
  ]);
  if (releaseResponse.response.headers.get("link")?.includes('rel="next"') === true) {
    throw new Error("GitHub release history exceeds one bounded page.");
  }
  const remoteReleases = requireArray(releaseResponse.value, "GitHub release history", 100);
  const expectedPublished = contract.tags.filter((entry) => entry.release !== null);
  if (remoteReleases.length !== expectedPublished.length) {
    throw new Error("GitHub has a different exact HRA v0 release set.");
  }
  const releasesByTag = uniqueRecordsByString(remoteReleases, "tag_name", "GitHub release");
  if (!isDeepStrictEqual(
    [...releasesByTag.keys()].toSorted(),
    expectedPublished.map(({ tag }) => tag).toSorted(),
  )) {
    throw new Error("GitHub has a different exact HRA v0 release tag set.");
  }
  for (const entry of expectedPublished) {
    const expectedRelease = entry.release;
    if (expectedRelease === null) throw new Error("Published release evidence is missing.");
    verifyReleaseMetadata(entry, expectedRelease, releasesByTag.get(entry.tag));
  }

  const remoteRefs = requireArray(refsResponse.value, "GitHub release tags", 64);
  const refsByName = uniqueRecordsByString(remoteRefs, "ref", "GitHub tag ref");
  const expectedRefs = contract.tags.map(({ tag }) => `refs/tags/${tag}`).toSorted();
  if (!isDeepStrictEqual([...refsByName.keys()].toSorted(), expectedRefs)) {
    throw new Error("GitHub has a different exact HRA v0 tag-ref set.");
  }
  await Promise.all(contract.tags.map(async (entry) => {
    const ref = refsByName.get(`refs/tags/${entry.tag}`);
    const refObject = requireRecord(ref?.["object"], `GitHub tag ref ${entry.tag} object`);
    if (
      refObject["type"] !== "tag"
      || refObject["sha"] !== entry.tagObject
      || refObject["url"] !== `${apiRepository}/git/tags/${entry.tagObject}`
    ) {
      throw new Error(`GitHub tag ref ${entry.tag} differs from annotated tag evidence.`);
    }
    const { value } = await fetchJson(
      fetcher,
      `${apiRepository}/git/tags/${entry.tagObject}`,
      `GitHub tag object ${entry.tag}`,
      262_144,
    );
    const tagObject = requireRecord(value, `GitHub tag object ${entry.tag}`);
    const target = requireRecord(tagObject["object"], `GitHub tag object ${entry.tag} target`);
    if (
      tagObject["sha"] !== entry.tagObject
      || tagObject["tag"] !== entry.tag
      || target["type"] !== "commit"
      || target["sha"] !== entry.commit
      || target["url"] !== `${apiRepository}/git/commits/${entry.commit}`
    ) {
      throw new Error(`GitHub tag object ${entry.tag} differs from peeled commit evidence.`);
    }
  }));

  return Object.freeze({
    assetCount: 49,
    releaseCount: 7,
    repository,
    status: "verified_exact_remote_release_history",
    tagCount: 8,
    tagOnly: Object.freeze(["v0.1.11"] as const),
  });
}

function verifyReleaseMetadata(
  entry: ReleaseHistoryContract["tags"][number],
  expected: NonNullable<ReleaseHistoryContract["tags"][number]["release"]>,
  raw: Record<string, unknown> | undefined,
): void {
  const release = requireRecord(raw, `GitHub release ${entry.tag}`);
  if (
    release["id"] !== expected.id
    || release["tag_name"] !== entry.tag
    || release["draft"] !== false
    || release["prerelease"] !== expected.prerelease
    || release["immutable"] !== expected.immutable
    || release["published_at"] !== expected.publishedAt
    || release["html_url"] !== `${repository}/releases/tag/${entry.tag}`
  ) {
    throw new Error(`GitHub release ${entry.tag} differs from the checked release ledger.`);
  }
  const rawAssets = requireArray(release["assets"], `GitHub release ${entry.tag} assets`, 64);
  if (rawAssets.length !== expected.assets.length) {
    throw new Error(`GitHub release ${entry.tag} has a different exact asset set.`);
  }
  const assetsByName = uniqueRecordsByString(rawAssets, "name", `GitHub release ${entry.tag} asset`);
  if (!isDeepStrictEqual(
    [...assetsByName.keys()].toSorted(),
    expected.assets.map(({ name }) => name).toSorted(),
  )) {
    throw new Error(`GitHub release ${entry.tag} has a different exact asset-name set.`);
  }
  for (const asset of expected.assets) {
    const remote = assetsByName.get(asset.name);
    if (
      remote?.["id"] !== asset.id
      || remote["state"] !== "uploaded"
      || remote["size"] !== asset.bytes
      || remote["digest"] !== `sha256:${asset.sha256}`
      || remote["browser_download_url"] !== `${repository}/releases/download/${entry.tag}/${asset.name}`
      || remote["url"] !== `${apiRepository}/releases/assets/${asset.id}`
    ) {
      throw new Error(`GitHub release asset ${entry.tag}/${asset.name} differs from the checked ledger.`);
    }
  }
}

async function fetchJson(
  fetcher: ReleaseHistoryFetcher,
  url: string,
  label: string,
  maximumBytes: number,
): Promise<Readonly<{ response: Response; value: unknown }>> {
  const response = await fetcher(url, {
    headers: {
      Accept: "application/vnd.github+json",
      "User-Agent": "hraness-hra-release-history-verifier",
      "X-GitHub-Api-Version": "2026-03-10",
    },
    redirect: "error",
    signal: AbortSignal.timeout(30_000),
  });
  if (!response.ok) throw new Error(`${label} returned HTTP ${response.status}.`);
  const bytes = await readBoundedResponse(response, maximumBytes, label);
  try {
    return { response, value: JSON.parse(new TextDecoder("utf-8", { fatal: true }).decode(bytes)) as unknown };
  } catch {
    throw new Error(`${label} is not valid UTF-8 JSON.`);
  }
}

async function readBoundedResponse(
  response: Response,
  maximumBytes: number,
  label: string,
): Promise<Uint8Array> {
  if (response.body === null) throw new Error(`${label} has no response body.`);
  const declared = response.headers.get("content-length");
  if (declared !== null) {
    const length = Number(declared);
    if (!Number.isSafeInteger(length) || length < 0 || length > maximumBytes) {
      throw new Error(`${label} has an invalid or oversized Content-Length.`);
    }
  }
  const chunks: Uint8Array[] = [];
  let total = 0;
  const reader = response.body.getReader();
  try {
    while (true) {
      const result = await reader.read();
      if (result.done) break;
      total += result.value.byteLength;
      if (total > maximumBytes) throw new Error(`${label} exceeds its byte limit.`);
      chunks.push(result.value);
    }
  } finally {
    reader.releaseLock();
  }
  const output = new Uint8Array(total);
  let offset = 0;
  for (const chunk of chunks) {
    output.set(chunk, offset);
    offset += chunk.byteLength;
  }
  return output;
}

function requireArray(value: unknown, label: string, maximumLength: number): readonly unknown[] {
  if (!Array.isArray(value) || value.length > maximumLength) {
    throw new Error(`${label} must be one bounded array.`);
  }
  return value;
}

function requireRecord(value: unknown, label: string): Record<string, unknown> {
  if (typeof value !== "object" || value === null || Array.isArray(value)) {
    throw new Error(`${label} must be an object.`);
  }
  return value as Record<string, unknown>;
}

function uniqueRecordsByString(
  values: readonly unknown[],
  key: string,
  label: string,
): ReadonlyMap<string, Record<string, unknown>> {
  const records = new Map<string, Record<string, unknown>>();
  for (const [index, value] of values.entries()) {
    const record = requireRecord(value, `${label} ${index}`);
    const identity = record[key];
    if (typeof identity !== "string" || identity.length === 0 || records.has(identity)) {
      throw new Error(`${label} identities must be unique nonempty strings.`);
    }
    records.set(identity, record);
  }
  return records;
}
