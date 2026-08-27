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
  test("binds the exact generation-2 ten tags, tag-only candidate, and 63 published assets", () => {
    expect(HRA_RELEASE_HISTORY.generation).toBe(2);
    expect(HRA_RELEASE_HISTORY.publicationCommit).toBe(
      "67e89e7909a56f5bfad1e16bb73801c9cd41503e",
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
      "v0.1.16",
    ]);
    expect(HRA_RELEASE_HISTORY.tags[4]?.release).toBeNull();
    expect(HRA_RELEASE_HISTORY.tags.reduce(
      (total, entry) => total + (entry.release?.assets.length ?? 0),
      0,
    )).toBe(63);
    const finalEntry = HRA_RELEASE_HISTORY.tags.at(-1);
    expect(finalEntry).toMatchObject({
      build: 17,
      commit: "2947402efe6363bf3bb41aef55c70a2823580c68",
      release: {
        id: 377_567_675,
        immutable: true,
        prerelease: true,
        publishedAt: "2026-08-27T04:43:36Z",
      },
      tag: "v0.1.16",
      tagObject: "188d8638b8d0cdf7ccaa73e2a0b07a2814f3782a",
    });
    expect(finalEntry?.release?.assets).toEqual([
      {
        bytes: 214_060_564,
        id: 531_751_216,
        name: "HRA-0.1.16-17-macos-arm64.dmg",
        sha256: "89ca90a73c29f3fef8a6b0dd349464a42f30f9c9b279951de3eff7b7186833cd",
      },
      {
        bytes: 96,
        id: 531_751_219,
        name: "HRA-0.1.16-17-macos-arm64.dmg.sha256",
        sha256: "51fd23071d084ac19ca391068af141fac29ec6afd9dc433481eebd06c6763b55",
      },
      {
        bytes: 33_790,
        id: 531_751_220,
        name: "HRA-0.1.16-17-release-manifest.json",
        sha256: "80f1ce1e9b43a2a9ae396b39cacfdb69ea11a406a5bf5037b408f79bb7726468",
      },
      {
        bytes: 168_162_466,
        id: 531_751_221,
        name: "bun-0d9b296af33f2b851fcbf4df3e9ec89751734ba4-source.tar.gz",
        sha256: "3c349132dee8226d33ec169062064e66cc292a1bcb05ccb19fed84f435eac529",
      },
      {
        bytes: 1_975_795_848,
        id: 531_751_217,
        name: "bun-webkit-5488984d20e0dbfe4be2c3ba8fb18eb81a5e0e8b-source.tar.gz",
        sha256: "797d0f9dd1ba58325e198359a1d55f3070b792d2e70069fbac5c97e784e9a05c",
      },
      {
        bytes: 44_387,
        id: 531_751_229,
        name: "dugite-native-f49d0098409aa243de8b9162127025ab0bb07a88-source.tar.gz",
        sha256: "9467050831b32aa3086f8fcb76990f99f081e819c54518cb4cb5e44f3bdd796e",
      },
      {
        bytes: 12_659_571,
        id: 531_751_228,
        name: "git-67ad42147a7acc2af6074753ebd03d904476118f-source.tar.gz",
        sha256: "cc7f69bb55dbfad74a7914a3616a2dd1d50779a6ed483f3e823127a3b6a92977",
      },
    ]);
    const finalDmg = finalEntry?.release?.assets.find(({ name }) =>
      name === "HRA-0.1.16-17-macos-arm64.dmg"
    );
    expect(finalDmg?.sha256).toBe(
      "89ca90a73c29f3fef8a6b0dd349464a42f30f9c9b279951de3eff7b7186833cd",
    );

    const generationOne = parseHraReleaseHistory({
      ...structuredClone(HRA_RELEASE_HISTORY),
      generation: 1,
      publicationCommit: "d96173c3556799cb203a4d659f29856180838029",
      tags: HRA_RELEASE_HISTORY.tags.slice(0, -1),
    });
    expect(generationOne.tags).toHaveLength(9);
    expect(generationOne.tags.at(-1)?.tag).toBe("v0.1.15");
    const generationZero = parseHraReleaseHistory({
      ...structuredClone(generationOne),
      generation: 0,
      publicationCommit: "6221f79b745f154882080936b961ff431569f33e",
      tags: generationOne.tags.slice(0, -1),
    });
    expect(generationZero.tags).toHaveLength(8);
    expect(generationZero.tags.at(-1)?.tag).toBe("v0.1.14");
    expect(() => parseHraReleaseHistory({
      ...structuredClone(generationZero),
      tags: HRA_RELEASE_HISTORY.tags,
    })).toThrow();
    expect(() => parseHraReleaseHistory({
      ...structuredClone(HRA_RELEASE_HISTORY),
      publicationCommit: "d96173c3556799cb203a4d659f29856180838029",
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

  test("serves the stable generation-2 publication identity without request state", async () => {
    expect(HRA_DEPLOYMENT_IDENTITY_PATH).toBe("/.well-known/hra.json");
    expect(HRA_DEPLOYMENT_IDENTITY).toMatchObject({
      generation: 2,
      product: "HRA",
      publication: {
        build: 17,
        publicationCommit: "67e89e7909a56f5bfad1e16bb73801c9cd41503e",
        releaseId: 377567675,
        sourceCommit: "2947402efe6363bf3bb41aef55c70a2823580c68",
        tag: "v0.1.16",
        tagObject: "188d8638b8d0cdf7ccaa73e2a0b07a2814f3782a",
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
