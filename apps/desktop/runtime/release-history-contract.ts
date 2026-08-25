import { isDeepStrictEqual } from "node:util";

import { z } from "@hra-internal/schema";

import releaseHistory from "../../../release-history.json";

const repository = "https://github.com/hraness/hra-v0" as const;
const apiRepository = "https://api.github.com/repos/hraness/hra-v0" as const;
const canonicalGitRepository = `${repository}.git` as const;
const maximumRemoteTagListingBytes = 262_144;
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
  tag: z.string().regex(/^v0\.1\.(?:7|8|9|10|11|12|13|14|15)$/u),
  tagObject: objectIdSchema,
  version: z.string().regex(/^0\.1\.(?:7|8|9|10|11|12|13|14|15)$/u),
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
const releaseHistoryBaseSchema = {
  repository: z.literal(repository),
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
const releaseHistorySchema = z.discriminatedUnion("generation", [
  generationZeroReleaseHistorySchema,
  generationOneReleaseHistorySchema,
]).superRefine((history, context) => {
  const expected = history.generation === 0
    ? generationZeroVersions
    : generationOneVersions;
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
        message: `Release history must contain the exact ordered v0.1.7–v0.1.${history.generation === 0 ? "14" : "15"} sequence.`,
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
export type ReleaseHistoryTagEvidence = Readonly<{
  commit: string;
  tag: string;
  tagObject: string;
}>;
export type ReleaseHistoryTagVerifier = (
  expected: readonly ReleaseHistoryTagEvidence[],
) => Promise<void>;
export type ReleaseHistoryTagLister = () => Promise<string>;
export type FrozenRemoteReleaseHistoryEvidence = Readonly<{
  assetCount: 49;
  releaseCount: 7;
  repository: typeof repository;
  status: "verified_exact_candidate_remote_release_history";
  tagCount: 8;
  tagOnly: readonly ["v0.1.11"];
}>;
export type PublishedRemoteReleaseHistoryEvidence = Readonly<{
  assetCount: 56;
  releaseCount: 8;
  repository: typeof repository;
  status: "verified_exact_published_remote_release_history";
  tagCount: 9;
  tagOnly: readonly ["v0.1.11"];
}>;
export type RemoteReleaseHistoryEvidence =
  | FrozenRemoteReleaseHistoryEvidence
  | PublishedRemoteReleaseHistoryEvidence;

export type CurrentRemoteReleaseHistoryEntry = Readonly<{
  assets: readonly Readonly<{
    bytes: number;
    id: number;
    name: string;
    sha256: string;
  }>[];
  commit: string;
  publishedAt: string;
  releaseId: number;
  tag: "v0.1.15";
  tagObject: string;
}>;

const currentRemoteReleaseHistoryEntrySchema = z.object({
  assets: z.array(assetSchema).length(7),
  commit: objectIdSchema,
  publishedAt: z.string().regex(/^2026-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z$/u),
  releaseId: z.number().int().positive().safe(),
  tag: z.literal("v0.1.15"),
  tagObject: objectIdSchema,
}).strict().superRefine((entry, context) => {
  const names = entry.assets.map(({ name }) => name);
  if (
    new Set(names).size !== names.length
    || new Set(entry.assets.map(({ id }) => id)).size !== entry.assets.length
    || names.join("\0") !== names.toSorted().join("\0")
  ) {
    context.addIssue({
      code: "custom",
      message: "The current release must have one sorted, unique seven-asset inventory.",
    });
  }
});

export function parseReleaseHistoryContract(value: unknown): ReleaseHistoryContract {
  return releaseHistorySchema.parse(value);
}

export function readReleaseHistoryContract(): ReleaseHistoryContract {
  return parseReleaseHistoryContract(releaseHistory);
}

export async function verifyRemoteReleaseHistory(
  fetcher: ReleaseHistoryFetcher = fetch,
  currentEntry?: CurrentRemoteReleaseHistoryEntry,
  tagVerifier?: ReleaseHistoryTagVerifier,
): Promise<RemoteReleaseHistoryEvidence> {
  return await verifyRemoteReleaseHistoryState(
    readReleaseHistoryContract(),
    fetcher,
    currentEntry,
    tagVerifier,
  );
}

export async function verifyRemoteReleaseHistoryState(
  contract: ReleaseHistoryContract,
  fetcher: ReleaseHistoryFetcher,
  currentEntryValue?: CurrentRemoteReleaseHistoryEntry,
  tagVerifier?: ReleaseHistoryTagVerifier,
): Promise<RemoteReleaseHistoryEvidence> {
  const currentEntry = currentEntryValue === undefined
    ? undefined
    : currentRemoteReleaseHistoryEntrySchema.parse(currentEntryValue);
  if (contract.generation === 1 && currentEntry !== undefined) {
    throw new Error(
      "Generation 1 release history already contains v0.1.15; a current-release overlay is forbidden.",
    );
  }
  if (currentEntry !== undefined && contract.tags.some(
    ({ tag, tagObject }) =>
      tag === currentEntry.tag || tagObject === currentEntry.tagObject,
  )) {
    throw new Error("The current release collides with the frozen release ledger.");
  }
  const [releaseResponse, refsResponse] = await Promise.all([
    fetchJson(fetcher, `${apiRepository}/releases?per_page=100`, "GitHub release history", 8 * 1_024 * 1_024),
    fetchJson(fetcher, `${apiRepository}/git/matching-refs/tags/v0.1`, "GitHub release tags", 1_048_576),
  ]);
  if (releaseResponse.response.headers.get("link")?.includes('rel="next"') === true) {
    throw new Error("GitHub release history exceeds one bounded page.");
  }
  const remoteReleases = requireArray(releaseResponse.value, "GitHub release history", 100);
  const expectedPublished = contract.tags.filter((entry) => entry.release !== null);
  const overlaysCurrentRelease = contract.generation === 0 && currentEntry !== undefined;
  if (
    remoteReleases.length
      !== expectedPublished.length + (overlaysCurrentRelease ? 1 : 0)
  ) {
    throw new Error("GitHub has a different exact HRA v0 release set.");
  }
  const releasesByTag = uniqueRecordsByString(remoteReleases, "tag_name", "GitHub release");
  const expectedReleaseTags = [
    ...expectedPublished.map(({ tag }) => tag),
    ...(overlaysCurrentRelease && currentEntry !== undefined ? [currentEntry.tag] : []),
  ];
  if (!isDeepStrictEqual(
    [...releasesByTag.keys()].toSorted(),
    expectedReleaseTags.toSorted(),
  )) {
    throw new Error("GitHub has a different exact HRA v0 release tag set.");
  }
  for (const entry of expectedPublished) {
    const expectedRelease = entry.release;
    if (expectedRelease === null) throw new Error("Published release evidence is missing.");
    verifyReleaseMetadata(entry, expectedRelease, releasesByTag.get(entry.tag));
  }
  if (overlaysCurrentRelease && currentEntry !== undefined) {
    verifyCurrentReleaseMetadata(
      currentEntry,
      releasesByTag.get(currentEntry.tag),
    );
  }

  const remoteRefs = requireArray(refsResponse.value, "GitHub release tags", 64);
  const refsByName = uniqueRecordsByString(remoteRefs, "ref", "GitHub tag ref");
  const expectedRefs = [
    ...contract.tags.map(({ tag }) => `refs/tags/${tag}`),
    ...(overlaysCurrentRelease && currentEntry !== undefined
      ? [`refs/tags/${currentEntry.tag}`]
      : []),
  ].toSorted();
  if (!isDeepStrictEqual([...refsByName.keys()].toSorted(), expectedRefs)) {
    throw new Error("GitHub has a different exact HRA v0 tag-ref set.");
  }
  const expectedTags = [
    ...contract.tags.map((entry) => ({
      commit: entry.commit,
      tag: entry.tag,
      tagObject: entry.tagObject,
    })),
    ...(overlaysCurrentRelease && currentEntry !== undefined
      ? [{
          commit: currentEntry.commit,
          tag: currentEntry.tag,
          tagObject: currentEntry.tagObject,
        }]
      : []),
  ];
  verifyGitHubTagRefs(expectedTags, refsByName);
  if (tagVerifier === undefined) {
    await verifyGitHubTagObjects(fetcher, expectedTags);
  } else {
    await tagVerifier(expectedTags);
  }

  return contract.generation === 0 && !overlaysCurrentRelease
    ? Object.freeze({
        assetCount: 49,
        releaseCount: 7,
        repository,
        status: "verified_exact_candidate_remote_release_history",
        tagCount: 8,
        tagOnly: Object.freeze(["v0.1.11"] as const),
      })
    : Object.freeze({
        assetCount: 56,
        releaseCount: 8,
        repository,
        status: "verified_exact_published_remote_release_history",
        tagCount: 9,
        tagOnly: Object.freeze(["v0.1.11"] as const),
      });
}

function verifyCurrentReleaseMetadata(
  expected: CurrentRemoteReleaseHistoryEntry,
  raw: Record<string, unknown> | undefined,
): void {
  const release = requireRecord(raw, `GitHub release ${expected.tag}`);
  if (
    release["id"] !== expected.releaseId
    || release["tag_name"] !== expected.tag
    || release["draft"] !== false
    || release["prerelease"] !== true
    || release["immutable"] !== true
    || release["published_at"] !== expected.publishedAt
    || release["html_url"] !== `${repository}/releases/tag/${expected.tag}`
  ) {
    throw new Error(
      `GitHub release ${expected.tag} differs from the verified current release.`,
    );
  }
  const rawAssets = requireArray(
    release["assets"],
    `GitHub release ${expected.tag} assets`,
    64,
  );
  if (rawAssets.length !== expected.assets.length) {
    throw new Error(
      `GitHub release ${expected.tag} has a different exact asset set.`,
    );
  }
  const assetsByName = uniqueRecordsByString(
    rawAssets,
    "name",
    `GitHub release ${expected.tag} asset`,
  );
  if (!isDeepStrictEqual(
    [...assetsByName.keys()].toSorted(),
    expected.assets.map(({ name }) => name).toSorted(),
  )) {
    throw new Error(
      `GitHub release ${expected.tag} has a different exact asset-name set.`,
    );
  }
  for (const asset of expected.assets) {
    const remote = assetsByName.get(asset.name);
    if (
      remote?.["id"] !== asset.id
      || remote["state"] !== "uploaded"
      || remote["size"] !== asset.bytes
      || remote["digest"] !== `sha256:${asset.sha256}`
      || remote["browser_download_url"]
        !== `${repository}/releases/download/${expected.tag}/${asset.name}`
      || remote["url"] !== `${apiRepository}/releases/assets/${asset.id}`
    ) {
      throw new Error(
        `GitHub current release asset ${expected.tag}/${asset.name} differs from verified evidence.`,
      );
    }
  }
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

function verifyGitHubTagRefs(
  expected: readonly ReleaseHistoryTagEvidence[],
  refsByName: ReadonlyMap<string, Record<string, unknown>>,
): void {
  for (const entry of expected) {
    const ref = refsByName.get(`refs/tags/${entry.tag}`);
    const refObject = requireRecord(ref?.["object"], `GitHub tag ref ${entry.tag} object`);
    if (
      refObject["type"] !== "tag"
      || refObject["sha"] !== entry.tagObject
      || refObject["url"] !== `${apiRepository}/git/tags/${entry.tagObject}`
    ) {
      throw new Error(`GitHub tag ref ${entry.tag} differs from annotated tag evidence.`);
    }
  }
}

async function verifyGitHubTagObjects(
  fetcher: ReleaseHistoryFetcher,
  expected: readonly ReleaseHistoryTagEvidence[],
): Promise<void> {
  for (const entry of expected) {
    const { value } = await fetchJson(
      fetcher,
      `${apiRepository}/git/tags/${entry.tagObject}`,
      `GitHub tag object ${entry.tag}`,
      maximumRemoteTagListingBytes,
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
  }
}

export async function verifyCanonicalRemoteReleaseTags(
  expected: readonly ReleaseHistoryTagEvidence[],
): Promise<void> {
  await verifyCanonicalRemoteReleaseTagsWithLister(
    expected,
    listCanonicalRemoteReleaseTags,
  );
}

export async function verifyCanonicalRemoteReleaseTagsWithLister(
  expected: readonly ReleaseHistoryTagEvidence[],
  lister: ReleaseHistoryTagLister,
): Promise<void> {
  const output = await lister();
  const byteLength = new TextEncoder().encode(output).byteLength;
  if (
    byteLength === 0
    || byteLength > maximumRemoteTagListingBytes
    || !output.endsWith("\n")
    || output.includes("\r")
    || output.includes("\0")
  ) {
    throw new Error("Canonical Git tag evidence has invalid bounded text framing.");
  }
  const refs = new Map<string, string>();
  for (const line of output.slice(0, -1).split("\n")) {
    const match = /^([0-9a-f]{40})\t(refs\/tags\/v0\.1\.[0-9]+)(\^\{\})?$/u.exec(line);
    if (match === null) {
      throw new Error("Canonical Git tag evidence contains an unexpected ref line.");
    }
    const objectId = match[1];
    const ref = match[2];
    if (objectId === undefined || ref === undefined) {
      throw new Error("Canonical Git tag evidence contains an incomplete ref line.");
    }
    const peeled = match[3] ?? "";
    const key = `${ref}${peeled}`;
    if (refs.has(key)) {
      throw new Error("Canonical Git tag evidence contains a duplicate ref line.");
    }
    refs.set(key, objectId);
  }
  const expectedRefs = expected.flatMap(({ tag }) => [
    `refs/tags/${tag}`,
    `refs/tags/${tag}^{}`,
  ]).toSorted();
  if (!isDeepStrictEqual([...refs.keys()].toSorted(), expectedRefs)) {
    throw new Error("Canonical Git has a different exact HRA v0 annotated tag set.");
  }
  for (const entry of expected) {
    if (
      refs.get(`refs/tags/${entry.tag}`) !== entry.tagObject
      || refs.get(`refs/tags/${entry.tag}^{}`) !== entry.commit
    ) {
      throw new Error(`Canonical Git tag ${entry.tag} differs from peeled commit evidence.`);
    }
  }
}

async function listCanonicalRemoteReleaseTags(): Promise<string> {
  let timedOut = false;
  const child = Bun.spawn([
    "/usr/bin/git",
    "--no-optional-locks",
    "-c",
    "credential.helper=",
    "-c",
    "protocol.version=2",
    "ls-remote",
    "--tags",
    canonicalGitRepository,
    "refs/tags/v0.1.*",
  ], {
    env: {
      GIT_CONFIG_COUNT: "0",
      GIT_CONFIG_GLOBAL: "/dev/null",
      GIT_CONFIG_NOSYSTEM: "1",
      GIT_OPTIONAL_LOCKS: "0",
      GIT_TERMINAL_PROMPT: "0",
      LANG: "C",
      LC_ALL: "C",
      PATH: "/usr/bin:/bin",
    },
    stdin: "ignore",
    stderr: "pipe",
    stdout: "pipe",
  });
  const timeout = setTimeout(() => {
    timedOut = true;
    child.kill(9);
  }, 30_000);
  try {
    const [stdout, stderr, exitCode] = await Promise.all([
      new Response(child.stdout).arrayBuffer(),
      new Response(child.stderr).arrayBuffer(),
      child.exited,
    ]);
    if (
      timedOut
      || exitCode !== 0
      || stdout.byteLength > maximumRemoteTagListingBytes
      || stderr.byteLength > 16_384
    ) {
      throw new Error("Credential-free canonical Git tag inspection failed.");
    }
    try {
      return new TextDecoder("utf-8", { fatal: true }).decode(stdout);
    } catch {
      throw new Error("Canonical Git tag evidence is not valid UTF-8.");
    }
  } finally {
    clearTimeout(timeout);
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
