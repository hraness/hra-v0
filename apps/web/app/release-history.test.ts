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
} from "./release-history";
import ReleasesPage from "./releases/page";
import { HRA_RELEASE } from "./site";

describe("HRA v0 public release history", () => {
  test("binds the exact eight tags, tag-only candidate, and 49 published assets", () => {
    expect(HRA_RELEASE_HISTORY.tags.map(({ tag }) => tag)).toEqual([
      "v0.1.7",
      "v0.1.8",
      "v0.1.9",
      "v0.1.10",
      "v0.1.11",
      "v0.1.12",
      "v0.1.13",
      "v0.1.14",
    ]);
    expect(HRA_RELEASE_HISTORY.tags[4]?.release).toBeNull();
    expect(HRA_RELEASE_HISTORY.tags.reduce(
      (total, entry) => total + (entry.release?.assets.length ?? 0),
      0,
    )).toBe(49);
    const finalEntry = HRA_RELEASE_HISTORY.tags.at(-1);
    expect(finalEntry).toMatchObject({
      build: HRA_RELEASE.build,
      commit: HRA_RELEASE.source.commit,
      tag: HRA_RELEASE.tag,
      tagObject: HRA_RELEASE.source.tagObject,
    });
    const finalDmg = finalEntry?.release?.assets.find(({ name }) => name === HRA_RELEASE.asset);
    expect(finalDmg?.sha256).toBe(HRA_RELEASE.sha256);
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

  test("serves a stable generation-0 cutover identity without request state", async () => {
    expect(HRA_DEPLOYMENT_IDENTITY_PATH).toBe("/.well-known/hra.json");
    expect(HRA_DEPLOYMENT_IDENTITY).toMatchObject({
      generation: 0,
      product: "HRA",
      publication: {
        build: 15,
        releaseId: 374980441,
        sourceCommit: "7b39c459827b2acf45aa2d911c94fdb5d4f37860",
        tag: "v0.1.14",
        tagObject: "37ed37afb39cacfd6a51044cf7f3c1b873571aa3",
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
