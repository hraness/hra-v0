import { describe, expect, test } from "bun:test";

import {
  parseReleaseHistoryContract,
  readReleaseHistoryContract,
  verifyCanonicalRemoteReleaseTagsWithLister,
  verifyRemoteReleaseHistoryState,
  type CurrentRemoteReleaseHistoryEntry,
  type ReleaseHistoryContract,
  type ReleaseHistoryFetcher,
} from "../release-history-contract";

const repository = "https://github.com/hraness/hra-v0" as const;
const apiRepository = "https://api.github.com/repos/hraness/hra-v0" as const;

describe("HRA v0 remote release history", () => {
  test("verifies all nine annotated tags and all 56 immutable release assets from generation 1", async () => {
    const fixture = createRemoteHistoryFixture();
    expect(await verifyRemoteReleaseHistoryState(fixture.contract, fixture.fetcher)).toEqual({
      assetCount: 56,
      releaseCount: 8,
      repository,
      status: "verified_exact_published_remote_release_history",
      tagCount: 9,
      tagOnly: ["v0.1.11"],
    });
    expect(fixture.requests).toHaveLength(11);
    expect(fixture.requests).toContain(`${apiRepository}/releases?per_page=100`);
    expect(fixture.requests).toContain(`${apiRepository}/git/matching-refs/tags/v0.1`);
    for (const entry of fixture.contract.tags) {
      expect(fixture.requests).toContain(`${apiRepository}/git/tags/${entry.tagObject}`);
    }
    expect(fixture.requests.some((url) => url.includes("/releases/download/"))).toBeFalse();
  });

  test("reads annotated tag objects sequentially to avoid public API burst throttling", async () => {
    const fixture = createRemoteHistoryFixture();
    let tagObjectRequestInFlight = false;
    const serializedFetcher: ReleaseHistoryFetcher = async (url, init) => {
      if (!url.startsWith(`${apiRepository}/git/tags/`)) {
        return await fixture.fetcher(url, init);
      }
      if (tagObjectRequestInFlight) {
        throw new Error("Concurrent public tag-object request.");
      }
      tagObjectRequestInFlight = true;
      try {
        await new Promise<void>((resolve) => setTimeout(resolve, 1));
        return await fixture.fetcher(url, init);
      } finally {
        tagObjectRequestInFlight = false;
      }
    };

    expect(await verifyRemoteReleaseHistoryState(
      fixture.contract,
      serializedFetcher,
    )).toMatchObject({ status: "verified_exact_published_remote_release_history" });
  });

  test("proves every annotated tag and peeled commit from one canonical Git listing", async () => {
    const contract = readReleaseHistoryContract();
    const expected = contract.tags.map(({ commit, tag, tagObject }) => ({
      commit,
      tag,
      tagObject,
    }));
    const listing = expected.flatMap(({ commit, tag, tagObject }) => [
      `${tagObject}\trefs/tags/${tag}`,
      `${commit}\trefs/tags/${tag}^{}`,
    ]).join("\n") + "\n";
    await verifyCanonicalRemoteReleaseTagsWithLister(expected, () => Promise.resolve(listing));

    const moved = listing.replace(expected[0]!.commit, "0".repeat(40));
    await expectRejects(
      verifyCanonicalRemoteReleaseTagsWithLister(
        expected,
        () => Promise.resolve(moved),
      ),
      "differs from peeled commit evidence",
    );
    await expectRejects(
      verifyCanonicalRemoteReleaseTagsWithLister(
        expected,
        () => Promise.resolve(`${listing}${"1".repeat(40)}\trefs/tags/v0.1.99\n`),
      ),
      "different exact HRA v0 annotated tag set",
    );
  });

  test("allows only the next exact release overlay for each frozen generation", async () => {
    const current = currentReleaseEntry();
    const frozen = createRemoteHistoryFixture(generationZeroContract());
    expect(await verifyRemoteReleaseHistoryState(
      frozen.contract,
      frozen.fetcher,
    )).toEqual({
      assetCount: 49,
      releaseCount: 7,
      repository,
      status: "verified_exact_candidate_remote_release_history",
      tagCount: 8,
      tagOnly: ["v0.1.11"],
    });

    const fixture = createRemoteHistoryFixture(generationZeroContract(), current);
    expect(await verifyRemoteReleaseHistoryState(
      fixture.contract,
      fixture.fetcher,
      current,
    )).toEqual({
      assetCount: 56,
      releaseCount: 8,
      repository,
      status: "verified_exact_published_remote_release_history",
      tagCount: 9,
      tagOnly: ["v0.1.11"],
    });
    expect(fixture.requests).toHaveLength(11);

    const generationOne = createRemoteHistoryFixture();
    await expectRejects(
      verifyRemoteReleaseHistoryState(
        generationOne.contract,
        generationOne.fetcher,
        current,
      ),
      "accepts only a v0.1.16 current-release overlay",
    );
    expect(generationOne.requests).toHaveLength(0);

    const hotfix = currentHotfixReleaseEntry();
    const hotfixFixture = createRemoteHistoryFixture(
      frozenGenerationOneContract(),
      hotfix,
    );
    expect(await verifyRemoteReleaseHistoryState(
      hotfixFixture.contract,
      hotfixFixture.fetcher,
      hotfix,
    )).toEqual({
      assetCount: 63,
      releaseCount: 9,
      repository,
      status: "verified_exact_published_remote_release_history",
      tagCount: 10,
      tagOnly: ["v0.1.11"],
    });
    expect(hotfixFixture.requests).toHaveLength(12);

    const promoted = generationTwoContract(hotfix);
    const promotedFixture = createRemoteHistoryFixture(promoted);
    expect(await verifyRemoteReleaseHistoryState(
      promotedFixture.contract,
      promotedFixture.fetcher,
    )).toEqual({
      assetCount: 63,
      releaseCount: 9,
      repository,
      status: "verified_exact_published_remote_release_history",
      tagCount: 10,
      tagOnly: ["v0.1.11"],
    });
    await expectRejects(
      verifyRemoteReleaseHistoryState(
        promotedFixture.contract,
        promotedFixture.fetcher,
        hotfix,
      ),
      "current-release overlay is forbidden",
    );

    const drift = createRemoteHistoryFixture(generationZeroContract(), current);
    const currentRelease = drift.releases.find(
      (release) => release["tag_name"] === current.tag,
    );
    requireRecord(currentRelease, "current release")["published_at"] =
      "2026-08-23T00:00:01Z";
    await expectRejects(
      verifyRemoteReleaseHistoryState(
        drift.contract,
        drift.fetcher,
        current,
      ),
      "differs from the verified current release",
    );
  });

  test("rejects an additional v0.1.11 release, asset drift, and a moved tag", async () => {
    const extraRelease = createRemoteHistoryFixture();
    extraRelease.releases.push({
      assets: [],
      draft: false,
      html_url: `${repository}/releases/tag/v0.1.11`,
      id: 1,
      immutable: true,
      prerelease: true,
      published_at: "2026-08-20T00:00:00Z",
      tag_name: "v0.1.11",
    });
    await expectRejects(
      verifyRemoteReleaseHistoryState(extraRelease.contract, extraRelease.fetcher),
      "different exact HRA v0 release set",
    );

    const digestDrift = createRemoteHistoryFixture();
    const assets = requireRecord(digestDrift.releases[0], "release")["assets"];
    if (!Array.isArray(assets) || assets[0] === undefined) {
      throw new Error("Expected fixture asset.");
    }
    requireRecord(assets[0], "asset")["digest"] = `sha256:${"0".repeat(64)}`;
    await expectRejects(
      verifyRemoteReleaseHistoryState(digestDrift.contract, digestDrift.fetcher),
      "differs from the checked ledger",
    );

    const movedTag = createRemoteHistoryFixture();
    const finalEntry = movedTag.contract.tags.at(-1);
    if (finalEntry === undefined) throw new Error("Expected final history entry.");
    const target = movedTag.tagObjects.get(finalEntry.tagObject);
    if (target === undefined) throw new Error("Expected final tag object.");
    requireRecord(target["object"], "tag target")["sha"] = "0".repeat(40);
    await expectRejects(
      verifyRemoteReleaseHistoryState(movedTag.contract, movedTag.fetcher),
      "differs from peeled commit evidence",
    );
  });

  test("parses only the exact ordered generation-0 through generation-2 sequences", () => {
    const current = readReleaseHistoryContract();
    expect(current.generation).toBe(2);
    expect(current.publicationCommit).toBe(
      "67e89e7909a56f5bfad1e16bb73801c9cd41503e",
    );
    expect(current.tags).toHaveLength(10);
    expect(current.tags.at(-1)).toMatchObject({
      build: 17,
      tag: "v0.1.16",
      version: "0.1.16",
    });

    const contract = frozenGenerationOneContract();
    expect(contract.generation).toBe(1);
    expect(contract.publicationCommit).toBe("d96173c3556799cb203a4d659f29856180838029");
    expect(contract.tags.map(({ tag }) => tag)).toEqual([
      "v0.1.7",
      "v0.1.8",
      "v0.1.9",
      "v0.1.10",
      "v0.1.11",
      "v0.1.12",
      "v0.1.13",
      "v0.1.14",
      "v0.1.15",
    ]);
    expect(contract.tags.map(({ commit, release, tagObject }) => ({
      commit,
      releaseId: release?.id ?? null,
      tagObject,
    }))).toEqual([
      { commit: "4fa78a8c6141446be343be13df056381c3b5a224", releaseId: 371487477, tagObject: "b9789e1104b6943a36edcc7d61b28635141e3be0" },
      { commit: "a3a142452921b9b9299d880f251d66dbe51c823b", releaseId: 371977411, tagObject: "0b3d3aa7e88e5537cc4b6f85b2dbf3969dd12c60" },
      { commit: "531eb23e165852e2921282862c019770bb3eb914", releaseId: 372074589, tagObject: "1b62548881f190272d0095f3900d683f43c34a69" },
      { commit: "2457962b31b873b9b0521ca5606b9ad3746404de", releaseId: 372110643, tagObject: "9abeb033d6d965bf214b062c3c6266bc600ec76b" },
      { commit: "5a2a9842cacc75fee42ab8e23ca8c215a643e21e", releaseId: null, tagObject: "e4c171e33e414d74a36791fc8577cbfbcef8e52e" },
      { commit: "9ab991d08d1507fd73c9e7ef5fb4a37baee9c014", releaseId: 374867227, tagObject: "626be494d24733d12e53d09932cb5cc6218bc2fe" },
      { commit: "9ba06a441c9b12b448cfe34784432592dbeccb19", releaseId: 374920071, tagObject: "44f00fd5c5e00bc8dcded0c9b176a8e37ada90f3" },
      { commit: "7b39c459827b2acf45aa2d911c94fdb5d4f37860", releaseId: 374980441, tagObject: "37ed37afb39cacfd6a51044cf7f3c1b873571aa3" },
      { commit: "0c7764da0dea0a71bbccca817539a02d8e4284d0", releaseId: 376100700, tagObject: "e5bcf5c919e8a7ffcdccc337b8940b60a70f0489" },
    ]);
    expect(contract.tags[4]?.release).toBeNull();
    const reordered = structuredClone(contract);
    [reordered.tags[0], reordered.tags[1]] = [reordered.tags[1]!, reordered.tags[0]!];
    expect(() => parseReleaseHistoryContract(reordered)).toThrow(
      "exact ordered v0.1.7–v0.1.15 sequence",
    );

    const generationZero = generationZeroContract();
    expect(generationZero.tags).toHaveLength(8);
    expect(generationZero.tags.at(-1)?.tag).toBe("v0.1.14");
    expect(generationZero.publicationCommit).toBe("6221f79b745f154882080936b961ff431569f33e");
    expect(() => parseReleaseHistoryContract({
      ...structuredClone(generationZero),
      tags: [...generationZero.tags, contract.tags.at(-1)],
    })).toThrow();

    const generationTwo = generationTwoContract();
    expect(generationTwo.generation).toBe(2);
    expect(generationTwo.tags).toHaveLength(10);
    expect(generationTwo.tags.at(-1)).toMatchObject({
      build: 17,
      tag: "v0.1.16",
      version: "0.1.16",
    });
    expect(() => parseReleaseHistoryContract({
      ...structuredClone(generationTwo),
      tags: generationTwo.tags.slice(0, 9),
    })).toThrow();
  });
});

function createRemoteHistoryFixture(
  contract: ReleaseHistoryContract = frozenGenerationOneContract(),
  current?: CurrentRemoteReleaseHistoryEntry,
) {
  const releases: Record<string, unknown>[] = contract.tags.flatMap((entry) => {
    if (entry.release === null) return [];
    return [{
      assets: entry.release.assets.map((asset) => ({
        browser_download_url: `${repository}/releases/download/${entry.tag}/${asset.name}`,
        digest: `sha256:${asset.sha256}`,
        id: asset.id,
        name: asset.name,
        size: asset.bytes,
        state: "uploaded",
        url: `${apiRepository}/releases/assets/${asset.id}`,
      })),
      draft: false,
      html_url: `${repository}/releases/tag/${entry.tag}`,
      id: entry.release.id,
      immutable: entry.release.immutable,
      prerelease: entry.release.prerelease,
      published_at: entry.release.publishedAt,
      tag_name: entry.tag,
    }];
  });
  const refs = contract.tags.map((entry) => ({
    object: {
      sha: entry.tagObject,
      type: "tag",
      url: `${apiRepository}/git/tags/${entry.tagObject}`,
    },
    ref: `refs/tags/${entry.tag}`,
  }));
  const tagObjects = new Map(contract.tags.map((entry) => [entry.tagObject, {
    object: {
      sha: entry.commit,
      type: "commit",
      url: `${apiRepository}/git/commits/${entry.commit}`,
    },
    sha: entry.tagObject,
    tag: entry.tag,
  }]));
  if (current !== undefined) {
    releases.push({
      assets: current.assets.map((asset) => ({
        browser_download_url:
          `${repository}/releases/download/${current.tag}/${asset.name}`,
        digest: `sha256:${asset.sha256}`,
        id: asset.id,
        name: asset.name,
        size: asset.bytes,
        state: "uploaded",
        url: `${apiRepository}/releases/assets/${asset.id}`,
      })),
      draft: false,
      html_url: `${repository}/releases/tag/${current.tag}`,
      id: current.releaseId,
      immutable: true,
      prerelease: true,
      published_at: current.publishedAt,
      tag_name: current.tag,
    });
    refs.push({
      object: {
        sha: current.tagObject,
        type: "tag",
        url: `${apiRepository}/git/tags/${current.tagObject}`,
      },
      ref: `refs/tags/${current.tag}`,
    });
    tagObjects.set(current.tagObject, {
      object: {
        sha: current.commit,
        type: "commit",
        url: `${apiRepository}/git/commits/${current.commit}`,
      },
      sha: current.tagObject,
      tag: current.tag,
    });
  }
  const requests: string[] = [];
  const fetcher: ReleaseHistoryFetcher = (url, init) => {
    requests.push(url);
    if (new Headers(init.headers).has("authorization")) {
      return Promise.reject(new Error("History verification must remain credential-free."));
    }
    if (url === `${apiRepository}/releases?per_page=100`) return Promise.resolve(jsonResponse(releases));
    if (url === `${apiRepository}/git/matching-refs/tags/v0.1`) return Promise.resolve(jsonResponse(refs));
    const prefix = `${apiRepository}/git/tags/`;
    if (url.startsWith(prefix)) {
      const value = tagObjects.get(url.slice(prefix.length));
      if (value !== undefined) return Promise.resolve(jsonResponse(value));
    }
    return Promise.reject(new Error(`Unexpected history request: ${url}`));
  };
  return { contract, fetcher, releases, requests, tagObjects };
}

function generationZeroContract(): ReleaseHistoryContract {
  const current = frozenGenerationOneContract();
  return parseReleaseHistoryContract({
    ...structuredClone(current),
    generation: 0,
    publicationCommit: "6221f79b745f154882080936b961ff431569f33e",
    tags: current.tags.slice(0, -1),
  });
}

function currentReleaseEntry(): CurrentRemoteReleaseHistoryEntry {
  return Object.freeze({
    assets: Object.freeze([
      "HRA-0.1.15-16-macos-arm64.dmg",
      "HRA-0.1.15-16-macos-arm64.dmg.sha256",
      "HRA-0.1.15-16-release-manifest.json",
      "bun-source.tar.gz",
      "libarchive-source.tar.gz",
      "native-sdk-source.tar.gz",
      "zig-source.tar.gz",
    ].toSorted().map((name, index) => Object.freeze({
      bytes: 1_000 + index,
      id: 900_000 + index,
      name,
      sha256: String(index + 1).repeat(64),
    }))),
    commit: "a".repeat(40),
    publishedAt: "2026-08-23T00:00:00Z",
    releaseId: 900_100,
    tag: "v0.1.15",
    tagObject: "b".repeat(40),
  });
}

function currentHotfixReleaseEntry(): CurrentRemoteReleaseHistoryEntry {
  return Object.freeze({
    assets: Object.freeze([
      "HRA-0.1.16-17-macos-arm64.dmg",
      "HRA-0.1.16-17-macos-arm64.dmg.sha256",
      "HRA-0.1.16-17-release-manifest.json",
      "bun-source.tar.gz",
      "libarchive-source.tar.gz",
      "native-sdk-source.tar.gz",
      "zig-source.tar.gz",
    ].toSorted().map((name, index) => Object.freeze({
      bytes: 2_000 + index,
      id: 910_000 + index,
      name,
      sha256: String(index + 1).repeat(64),
    }))),
    commit: "c".repeat(40),
    publishedAt: "2026-08-25T00:00:00Z",
    releaseId: 910_100,
    tag: "v0.1.16",
    tagObject: "d".repeat(40),
  });
}

function generationTwoContract(
  current: CurrentRemoteReleaseHistoryEntry = currentHotfixReleaseEntry(),
): ReleaseHistoryContract {
  const generationOne = frozenGenerationOneContract();
  return parseReleaseHistoryContract({
    ...generationOne,
    generation: 2,
    publicationCommit: "e".repeat(40),
    tags: [
      ...generationOne.tags,
      {
        build: 17,
        commit: current.commit,
        objectKind: "annotated",
        release: {
          assets: current.assets,
          id: current.releaseId,
          immutable: true,
          prerelease: true,
          publishedAt: current.publishedAt,
        },
        tag: current.tag,
        tagObject: current.tagObject,
        version: "0.1.16",
      },
    ],
  });
}

function frozenGenerationOneContract(): ReleaseHistoryContract {
  const current = readReleaseHistoryContract();
  return parseReleaseHistoryContract({
    ...structuredClone(current),
    generation: 1,
    publicationCommit: "d96173c3556799cb203a4d659f29856180838029",
    tags: current.tags.slice(0, 9),
  });
}

function jsonResponse(value: unknown): Response {
  const body = JSON.stringify(value);
  return new Response(body, {
    headers: { "content-length": String(new TextEncoder().encode(body).byteLength) },
    status: 200,
  });
}

function requireRecord(value: unknown, label: string): Record<string, unknown> {
  if (typeof value !== "object" || value === null || Array.isArray(value)) {
    throw new Error(`Expected ${label}.`);
  }
  return value as Record<string, unknown>;
}

async function expectRejects(promise: Promise<unknown>, message: string): Promise<void> {
  try {
    await promise;
  } catch (error) {
    expect(error).toBeInstanceOf(Error);
    expect((error as Error).message).toContain(message);
    return;
  }
  throw new Error(`Expected rejection containing ${message}.`);
}
