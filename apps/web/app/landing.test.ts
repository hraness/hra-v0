import { describe, expect, test } from "bun:test";

import {
  HRA_BRAND_EMOJI,
  HRA_RELEASE,
  HRA_RELEASE_CHECKSUM_URL,
  HRA_RELEASE_MANIFEST_URL,
  HRA_RELEASE_URL,
} from "./site";

async function source(name: string): Promise<string> {
  return Bun.file(new URL(name, import.meta.url)).text();
}

describe("HRA public landing", () => {
  test("uses the phoenix across product marks and generated icons", async () => {
    const [page, download, adminShell, openGraphImage, site] = await Promise.all([
      source("./page.tsx"),
      source("./download/page.tsx"),
      source("./admin-shell.tsx"),
      source("./opengraph-image.tsx"),
      source("./site.ts"),
    ]);
    const sha256 = async (name: string) => {
      const hasher = new Bun.CryptoHasher("sha256");
      hasher.update(await Bun.file(new URL(name, import.meta.url)).arrayBuffer());
      return hasher.digest("hex");
    };

    expect(HRA_BRAND_EMOJI).toBe("🐦‍🔥");
    expect(site).toContain('HRA_BRAND_EMOJI = "🐦‍🔥"');
    expect(site).toContain('HRA_BRAND_ICON_PATH = "/icon.png"');
    expect(page).toContain("HRA_BRAND_ICON_PATH");
    expect(download).toContain("HRA_BRAND_ICON_PATH");
    expect(adminShell).toContain("HRA_BRAND_ICON_PATH");
    expect(openGraphImage).toContain('join(process.cwd(), "app", "icon.png")');
    expect(openGraphImage).toContain('"base64"');
    expect(openGraphImage).toContain("const phoenixIconSource =");
    expect(openGraphImage).toContain("data:image/png;base64,");
    expect(openGraphImage).not.toContain("phoenixIcon.src");
    for (const brandedSurface of [page, download, adminShell]) {
      expect(brandedSurface).not.toContain("{HRA_BRAND_EMOJI}");
    }
    expect(page).toContain('aria-label="HRA v0 home"');
    expect(download).toContain('aria-label="HRA v0 download"');
    expect(adminShell).not.toContain('className="brand-mark" aria-hidden="true">OP');
    expect(await sha256("./icon.png")).toBe(
      "17f58b8c253691f5302d5a742f540e04e7b8105bad1032cd1f1320a9388029e1",
    );
    expect(await sha256("./apple-icon.png")).toBe(
      "b9d3d18a3375f026afca7a82c222ce961187e3383714a8f600a5dc9692e98520",
    );
    expect(await sha256("../../desktop/assets/icon.png")).toBe(
      "451bf4681fe1ac0b1210e0d53668d13ea47405df41f29bb8998e40fa401e8320",
    );
  });

  test("leads with the outcome and exposes the complete public decision path", async () => {
    const page = await source("./page.tsx");

    expect(page).toContain("Archived HRA v0 · final prerelease");
    expect(page).toContain("HRA v0 is preserved here.");
    expect(page).toContain("The current HRA is a separate project");
    expect(page).toContain("Delegate work with structure");
    expect(page).toContain("Spend reasoning deliberately");
    expect(page).toContain("Recover the work, not just the window");
    expect(page.match(/<h1\b/gu)).toHaveLength(1);
    expect(page).toContain('href="/download">Download HRA v0</Link>');
    expect(page).toContain("href={CURRENT_HRA_SITE}>Go to current HRA</a>");
    expect(page).toContain("href={HRA_V0_REPOSITORY}");
    expect(page).toContain("Let the Mac keep the authority.");
    expect(page).toContain("HRA is intentionally narrower than an AI IDE.");
    expect(page).toContain("A provider limit ends the affected turn.");
    expect(page).toContain("Before you give it a repository.");
    expect(page).toContain("The public repository includes the product source");
  });

  test("pins the exact honest native prerelease contract", async () => {
    const download = await source("./download/page.tsx");

    expect(HRA_RELEASE).toMatchObject({
      architecture: "Apple Silicon",
      asset: "HRA-0.1.14-15-macos-arm64.dmg",
      build: 15,
      checksumAsset: "HRA-0.1.14-15-macos-arm64.dmg.sha256",
      manifestAsset: "HRA-0.1.14-15-release-manifest.json",
      minimumMacOS: "13",
      historicalPublicationRepository: "https://github.com/hraness/hra",
      repository: "https://github.com/hraness/hra-v0",
      tag: "v0.1.14",
      version: "0.1.14",
    });
    expect(HRA_RELEASE.availability).toBe("published");
    expect(HRA_RELEASE.source.commit).toMatch(/^[0-9a-f]{40}$/u);
    expect(HRA_RELEASE.source.runtimeTreeSha256).toMatch(/^[0-9a-f]{64}$/u);
    expect(HRA_RELEASE.source.tagObject).toMatch(/^[0-9a-f]{40}$/u);
    expect(HRA_RELEASE_URL).toBe(
      "https://github.com/hraness/hra-v0/releases/download/v0.1.14/HRA-0.1.14-15-macos-arm64.dmg",
    );
    expect(HRA_RELEASE_CHECKSUM_URL).toBe(`${HRA_RELEASE_URL}.sha256`);
    expect(HRA_RELEASE_MANIFEST_URL).toBe(
      "https://github.com/hraness/hra-v0/releases/download/v0.1.14/HRA-0.1.14-15-release-manifest.json",
    );
    expect(download).toContain("Unknown developer.");
    expect(download).toContain("not Developer ID signed or notarized");
    expect(download).toContain("HRA_RELEASE_MANIFEST_URL");
    expect(download).not.toContain("Candidate verification in progress.");
    expect(download).not.toContain("Do not install an unpublished draft asset.");
  });

  test("keeps navigation, sections, disclosure, and structured data semantic", async () => {
    const page = await source("./page.tsx");

    expect(page).toContain('href="#main-content">Skip to content</a>');
    expect(page).toContain('aria-label="Primary navigation"');
    expect(page).toContain('<main id="main-content">');
    expect(page).toContain('<figure className="landing-authority-card">');
    expect(page).toContain("<figcaption>");
    expect(page).toContain('<ul aria-label="Control plane authority">');
    expect(page).toContain('<ul aria-label="Paired Mac authority">');
    expect(page).not.toContain('role="img"');
    expect(page.match(/<section aria-labelledby=/gu)?.length).toBeGreaterThanOrEqual(6);
    expect(page.match(/question:/gu)).toHaveLength(5);
    expect(page.match(/<details/gu)).toHaveLength(2);
    expect(page.match(/type="application\/ld\+json"/gu)).toHaveLength(2);
    expect(page).toContain("websiteJsonLd(hraSearchSite)");
    expect(page).toContain("webApplicationJsonLd(hraSearchSite");
  });

  test("discloses the bounded public analytics and residual hosting boundary", async () => {
    const page = await source("./page.tsx");

    expect(page).toContain("HRA uses cookieless, personless PostHog analytics on public pages");
    expect(page).toContain("only the canonical public route");
    expect(page).toContain("Analytics do not run inside the authenticated control plane");
    expect(page).toContain("HRA adds no advertising trackers");
    expect(page).toContain("Hosting providers may retain operational request logs");
    expect(page).not.toContain("data-analytics-");
  });

  test("positions the repository around concrete outcomes and boundaries", async () => {
    const readme = await source("../../../README.md");

    expect(readme).toContain("# HRA v0");
    expect(readme).toContain("**The original metaharness for Codex.**");
    expect(readme).toContain("one durable system for planning work, delegating it, running it in parallel");
    expect(readme).toContain("[Website](https://hra-weld.vercel.app)");
    expect(readme).toContain("[![HRA](https://hra-weld.vercel.app/opengraph-image)](https://hra-weld.vercel.app)");
    expect(readme).toContain("[Download for macOS](https://hra-weld.vercel.app/download)");
    expect(readme).toContain("[Historical comparisons](https://hra-weld.vercel.app/alternatives)");
    expect(readme).toContain("[Current HRA](https://hra.sh)");
    expect(readme).toContain("## Why HRA exists");
    expect(readme).toContain("Several authorized accounts, kept separate.");
    expect(readme).toContain("HRA does not combine subscriptions or bypass provider limits.");
    expect(readme).toContain("See [Security architecture](SECURITY_ARCHITECTURE.md)");
    expect(readme).toContain("HRA v0 is archived.");
  });
});
