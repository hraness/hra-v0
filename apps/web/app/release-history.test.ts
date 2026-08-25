import { describe, expect, test } from "bun:test";
import { renderToStaticMarkup } from "react-dom/server";

import { GET as getDeploymentIdentity, HEAD as headDeploymentIdentity } from "./.well-known/hra.json/route";
import {
  HRA_DEPLOYMENT_IDENTITY,
  HRA_DEPLOYMENT_IDENTITY_PATH,
} from "./deployment-identity";
import { createReleaseHistoryMarkdown } from "./public-markdown";
import {
  HRA_RELEASE_HISTORY,
  hraReleaseAssetUrl,
  parseHraReleaseHistory,
} from "./release-history";
import ReleasesPage from "./releases/page";

describe("HRA v0 public release history", () => {
  test("binds the exact generation-1 nine tags, tag-only candidate, and 56 published assets", () => {
    expect(HRA_RELEASE_HISTORY.generation).toBe(1);
    expect(HRA_RELEASE_HISTORY.publicationCommit).toBe(
      "d96173c3556799cb203a4d659f29856180838029",
    );
    expect(HRA_RELEASE_HISTORY.tags.map(({ tag }) => tag)).toEqual([
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
    expect(HRA_RELEASE_HISTORY.tags[4]?.release).toBeNull();
    expect(HRA_RELEASE_HISTORY.tags.reduce(
      (total, entry) => total + (entry.release?.assets.length ?? 0),
      0,
    )).toBe(56);
    const finalEntry = HRA_RELEASE_HISTORY.tags.at(-1);
    expect(finalEntry).toMatchObject({
      build: 16,
      commit: "0c7764da0dea0a71bbccca817539a02d8e4284d0",
      tag: "v0.1.15",
      tagObject: "e5bcf5c919e8a7ffcdccc337b8940b60a70f0489",
    });
    const finalDmg = finalEntry?.release?.assets.find(({ name }) =>
      name === "HRA-0.1.15-16-macos-arm64.dmg"
    );
    expect(finalDmg?.sha256).toBe(
      "120b600d7cc11df260836198601cba91db33efc7b600dd2b601bde686c9ea028",
    );

    const generationZero = parseHraReleaseHistory({
      ...structuredClone(HRA_RELEASE_HISTORY),
      generation: 0,
      publicationCommit: "6221f79b745f154882080936b961ff431569f33e",
      tags: HRA_RELEASE_HISTORY.tags.slice(0, -1),
    });
    expect(generationZero.tags).toHaveLength(8);
    expect(generationZero.tags.at(-1)?.tag).toBe("v0.1.14");
    expect(() => parseHraReleaseHistory({
      ...structuredClone(generationZero),
      tags: HRA_RELEASE_HISTORY.tags,
    })).toThrow();
  });

  test("renders every exact asset link, byte count, and digest from the checked ledger", () => {
    const html = renderToStaticMarkup(ReleasesPage());
    const markdown = createReleaseHistoryMarkdown();
    expect(html).toContain("Final archived prerelease");
    expect(html).toContain("v0.1.11 was a tagged candidate only");
    for (const entry of HRA_RELEASE_HISTORY.tags) {
      expect(html).toContain(entry.tagObject);
      expect(markdown).toContain(entry.commit);
      for (const asset of entry.release?.assets ?? []) {
        const url = hraReleaseAssetUrl(entry, asset);
        expect(html).toContain(url);
        expect(html).toContain(asset.sha256);
        expect(markdown).toContain(`${asset.bytes} bytes`);
        expect(markdown).toContain(url);
      }
    }
  });

  test("serves the stable generation-1 publication identity without request state", async () => {
    expect(HRA_DEPLOYMENT_IDENTITY_PATH).toBe("/.well-known/hra.json");
    expect(HRA_DEPLOYMENT_IDENTITY).toMatchObject({
      generation: 1,
      product: "HRA",
      publication: {
        build: 16,
        publicationCommit: "d96173c3556799cb203a4d659f29856180838029",
        releaseId: 376100700,
        sourceCommit: "0c7764da0dea0a71bbccca817539a02d8e4284d0",
        tag: "v0.1.15",
        tagObject: "e5bcf5c919e8a7ffcdccc337b8940b60a70f0489",
      },
      repository: { id: 1_334_876_494, path: "hraness/hra-v0" },
      schemaVersion: 2,
      source: { commit: "local" },
    });
    const response = getDeploymentIdentity();
    expect(response.status).toBe(200);
    expect(response.headers.get("content-type")).toBe("application/json; charset=utf-8");
    expect(await response.json()).toEqual(HRA_DEPLOYMENT_IDENTITY);
    const head = headDeploymentIdentity();
    expect(head.status).toBe(200);
    expect(await head.text()).toBe("");
  });
});
