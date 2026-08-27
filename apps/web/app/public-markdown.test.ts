import { describe, expect, test } from "bun:test";

import { MARKDOWN_CONTENT_TYPE } from "./accept-negotiation";
import { hraComparisons } from "./alternatives/comparisons";
import { GET as getLlmsTxt, HEAD as headLlmsTxt } from "./llms.txt/route";
import {
  createDownloadMarkdown,
  createHeadlongReadingMarkdown,
  createLandingMarkdown,
  createNotACodexTuiReadingMarkdown,
  createNotFoundMarkdown,
  createPrivacyMarkdown,
  createReleaseHistoryMarkdown,
  HRA_LLMS_TXT,
  HRA_LLMS_TXT_PATH,
  isAuthProtectedTree,
  isPublicHtmlDocumentPath,
  publicDocumentMarkdown,
  resolvePublicDiscovery,
} from "./public-markdown";
import {
  HRA_HEADLONG_READING_PATH,
  HRA_HEADLONG_READING_TITLE,
  HRA_NOT_A_CODEX_TUI_READING_PATH,
  HRA_NOT_A_CODEX_TUI_READING_TITLE,
} from "./reading";
import { HRA_RELEASE, hraSearchSite } from "./site";

describe("HRA public markdown representations", () => {
  test("publishes an llms.txt with when-to-use guidance and public page lists", () => {
    expect(HRA_LLMS_TXT.startsWith("# HRA v0 archive\n")).toBeTrue();
    expect(HRA_LLMS_TXT).toContain(`> ${hraSearchSite.description}`);
    expect(HRA_LLMS_TXT).toContain("maintained archive for HRA v0");
    expect(HRA_LLMS_TXT).toContain("frozen v0.1.7–v0.1.16 compatibility ledger");
    expect(HRA_LLMS_TXT).toContain("How an agent should use this archive:");
    expect(HRA_LLMS_TXT).toContain("Accept: text/markdown");
    expect(HRA_LLMS_TXT).not.toContain("OAuth client");
    expect(HRA_LLMS_TXT).toContain("https://hra-weld.vercel.app/");
    expect(HRA_LLMS_TXT).toContain("https://hra-weld.vercel.app/download");
    expect(HRA_LLMS_TXT).toContain("https://hra-weld.vercel.app/releases");
    expect(HRA_LLMS_TXT).toContain("https://hra-weld.vercel.app/privacy");
    expect(HRA_LLMS_TXT).toContain("https://hra-weld.vercel.app/.well-known/security.txt");
    expect(HRA_LLMS_TXT).toContain("https://hra-weld.vercel.app/.well-known/hra.json");
    expect(HRA_LLMS_TXT).toContain("https://hra-weld.vercel.app/alternatives");
    expect(HRA_LLMS_TXT).toContain(`https://hra-weld.vercel.app${HRA_HEADLONG_READING_PATH}`);
    expect(HRA_LLMS_TXT).toContain(`https://hra-weld.vercel.app${HRA_NOT_A_CODEX_TUI_READING_PATH}`);
    expect(HRA_LLMS_TXT).toContain("https://hra-weld.vercel.app/llms.txt");
    expect(HRA_LLMS_TXT).toContain("https://hra-weld.vercel.app/sitemap.xml");
    for (const comparison of hraComparisons) {
      expect(HRA_LLMS_TXT).toContain(`https://hra-weld.vercel.app/alternatives/${comparison.slug}`);
    }
    expect(HRA_LLMS_TXT_PATH).toBe("/llms.txt");
  });

  test("keeps landing markdown aligned with the public product copy", () => {
    const markdown = createLandingMarkdown();
    expect(markdown).toContain("# HRA v0 is preserved here.");
    expect(markdown).toContain("## When to use HRA");
    expect(markdown).toContain("Delegate work with structure");
    expect(markdown).toContain("A provider limit ends the affected turn.");
    expect(markdown).toContain("https://hra-weld.vercel.app/llms.txt");
    expect(markdown).toContain("https://hra-weld.vercel.app/sitemap.xml");
    expect(markdown).toContain(`https://hra-weld.vercel.app${HRA_NOT_A_CODEX_TUI_READING_PATH}`);
  });

  test("keeps download markdown honest about the current release contract", () => {
    const markdown = createDownloadMarkdown();
    expect(markdown).toContain("# Download HRA v0 for your Mac.");
    expect(markdown).toContain(`macOS ${HRA_RELEASE.minimumMacOS}`);
    expect(markdown).toContain("Neither signing boundary is Developer ID signed or notarized");
    expect(markdown).toContain("https://hra-weld.vercel.app/llms.txt");
    if (HRA_RELEASE.availability === "candidate") {
      expect(markdown).toContain("Do not install an unpublished draft asset.");
    } else {
      expect(markdown).toContain(HRA_RELEASE.asset);
    }
  });

  test("renders every comparison from the existing first-party rows", () => {
    expect(publicDocumentMarkdown("/alternatives")).toContain(
      "Choose the layer you actually need.",
    );
    for (const comparison of hraComparisons) {
      const markdown = publicDocumentMarkdown(`/alternatives/${comparison.slug}`);
      expect(markdown, comparison.slug).toContain(`# HRA v0 vs ${comparison.shortName}`);
      expect(markdown, comparison.slug).toContain(comparison.meaningfulDifference);
      expect(markdown, comparison.slug).toContain(comparison.rows[0]?.hra ?? "");
    }
  });

  test("serves the checked compatibility ledger as Markdown", () => {
    const markdown = createReleaseHistoryMarkdown();
    expect(markdown).toContain("# HRA v0 release history");
    expect(markdown).toContain("v0.1.11 was a tagged candidate only");
    expect(markdown).toContain("generation-2 compatibility ledger");
    expect(markdown).toContain("v0.1.16 is the final archived prerelease");
    expect(markdown).toContain("188d8638b8d0cdf7ccaa73e2a0b07a2814f3782a");
    expect(markdown).toContain("89ca90a73c29f3fef8a6b0dd349464a42f30f9c9b279951de3eff7b7186833cd");
    expect(markdown).toContain("37ed37afb39cacfd6a51044cf7f3c1b873571aa3");
    expect(publicDocumentMarkdown("/releases")).toBe(markdown);
  });

  test("serves the Headlong reading take as a complete Markdown document", () => {
    const markdown = createHeadlongReadingMarkdown();
    expect(markdown).toContain(`# ${HRA_HEADLONG_READING_TITLE}.`);
    expect(markdown).toContain("never asleep");
    expect(markdown).toContain("A harness runs an agent.");
    expect(markdown).toContain("https://hraness.com/reading/headlong-a-microharness-for-persistent-agents");
    expect(markdown).toContain("https://hraness.com/writing/what-is-an-agent-harness");
    expect(publicDocumentMarkdown(`${HRA_HEADLONG_READING_PATH}/`)).toBe(markdown);
    expect(publicDocumentMarkdown("/reading")).toBeNull();
    expect(publicDocumentMarkdown("/reading/missing")).toBeNull();
  });

  test("serves the not-a-Codex-TUI reading take as a complete Markdown document", () => {
    const markdown = createNotACodexTuiReadingMarkdown();
    expect(markdown).toContain(`# ${HRA_NOT_A_CODEX_TUI_READING_TITLE}.`);
    expect(markdown).toContain("A metaharness is not ASCII chrome");
    expect(markdown).toContain("https://sockpuppet.org/blog/2026/08/20/stop-making-tuis/");
    expect(markdown).toContain("https://hraness.com/reading/stop-making-tuis");
    expect(markdown).toContain("https://hraness.com/writing/what-is-an-agent-harness");
    expect(markdown).toContain(`https://hra-weld.vercel.app${HRA_HEADLONG_READING_PATH}`);
    expect(publicDocumentMarkdown(`${HRA_NOT_A_CODEX_TUI_READING_PATH}/`)).toBe(markdown);
  });

  test("serves the privacy boundary as a complete Markdown document", () => {
    const markdown = createPrivacyMarkdown();
    expect(markdown).toContain("# Privacy at the HRA v0 archive");
    expect(markdown).toContain("cookieless, personless PostHog pageview");
    expect(markdown).toContain("Hosted data is coordination data");
    expect(markdown).toContain("WorkOS subject, human name and email when supplied");
    expect(markdown).toContain("Execution authority stays local");
    expect(markdown).toContain("device names and public keys, enrollment state and one-time pairing metadata");
    expect(markdown).toContain("session lifecycle event kinds and revisions");
    expect(markdown).toContain("does not publish one fixed retention period");
    expect(markdown).toContain("generation-2 compatibility ledger ends at the immutable v0.1.16 prerelease");
    expect(markdown).toContain("https://hra-weld.vercel.app/.well-known/security.txt");
    expect(publicDocumentMarkdown("/privacy/private")).toBeNull();
    expect(publicDocumentMarkdown("/privacy/")).toBe(markdown);
  });

  test("gives unmatched public paths a markdown 404 with recovery links", () => {
    const markdown = createNotFoundMarkdown();
    expect(markdown).toContain("# Not found");
    expect(markdown).toContain("https://hra-weld.vercel.app/sitemap.xml");
    expect(markdown).toContain("https://hra-weld.vercel.app/llms.txt");
    expect(markdown).toContain("https://hra-weld.vercel.app/");
  });
});

describe("HRA public discovery decisions", () => {
  test("classifies only the existing public HTML documents", () => {
    expect(isPublicHtmlDocumentPath("/")).toBeTrue();
    expect(isPublicHtmlDocumentPath("/download/")).toBeTrue();
    expect(isPublicHtmlDocumentPath("/releases")).toBeTrue();
    expect(isPublicHtmlDocumentPath("/privacy/")).toBeTrue();
    expect(isPublicHtmlDocumentPath("/alternatives/codex-app")).toBeTrue();
    expect(isPublicHtmlDocumentPath(`${HRA_HEADLONG_READING_PATH}/`)).toBeTrue();
    expect(isPublicHtmlDocumentPath(`${HRA_NOT_A_CODEX_TUI_READING_PATH}/`)).toBeTrue();
    expect(isPublicHtmlDocumentPath("/alternatives/missing")).toBeFalse();
    expect(isPublicHtmlDocumentPath("/reading")).toBeFalse();
    expect(isPublicHtmlDocumentPath("/reading/missing")).toBeFalse();
    expect(isPublicHtmlDocumentPath("/app")).toBeFalse();
    expect(isPublicHtmlDocumentPath("/llms.txt")).toBeFalse();
    expect(isAuthProtectedTree("/app/private")).toBeTrue();
    expect(isAuthProtectedTree("/this-path-does-not-exist")).toBeFalse();
  });

  test("serves markdown for Accept: text/markdown on public pages", () => {
    const home = resolvePublicDiscovery({
      accept: "text/markdown",
      method: "GET",
      nextInternalNavigation: false,
      pathname: "/",
    });
    expect(home).toMatchObject({
      action: "markdown",
      contentType: MARKDOWN_CONTENT_TYPE,
      status: 200,
    });
    if (home.action === "markdown") {
      expect(home.body).toContain("HRA v0 is preserved here.");
    }
  });

  test("returns 406 only when a public page cannot satisfy Accept", () => {
    expect(resolvePublicDiscovery({
      accept: "application/pdf",
      method: "GET",
      nextInternalNavigation: false,
      pathname: "/",
    })).toEqual({ action: "not_acceptable" });
    expect(resolvePublicDiscovery({
      accept: "application/pdf",
      method: "GET",
      nextInternalNavigation: false,
      pathname: "/this-path-does-not-exist",
    })).toEqual({ action: "passthrough" });
  });

  test("returns a markdown 404 for unknown public paths", () => {
    const missing = resolvePublicDiscovery({
      accept: "text/markdown",
      method: "GET",
      nextInternalNavigation: false,
      pathname: "/this-path-does-not-exist",
    });
    expect(missing).toMatchObject({ action: "markdown", status: 404 });
    if (missing.action === "markdown") {
      expect(missing.body).toContain("https://hra-weld.vercel.app/sitemap.xml");
    }
  });

  test("does not negotiate private trees, machine files, or Next internals", () => {
    for (const [pathname, accept] of [
      ["/app", "text/markdown"],
      ["/auth/sign-in", "text/markdown"],
      ["/api/suite-auth/session", "text/markdown"],
      ["/design", "text/markdown"],
      ["/robots.txt", "text/markdown"],
      ["/sitemap.xml", "text/markdown"],
      ["/llms.txt", "text/markdown"],
      ["/.well-known/hra.json", "text/markdown"],
      ["/.well-known/security.txt", "text/markdown"],
      ["/icon.png", "text/markdown"],
    ] as const) {
      expect(resolvePublicDiscovery({
        accept,
        method: "GET",
        nextInternalNavigation: false,
        pathname,
      }), pathname).toEqual({ action: "passthrough" });
    }
    expect(resolvePublicDiscovery({
      accept: "text/markdown",
      method: "POST",
      nextInternalNavigation: false,
      pathname: "/",
    })).toEqual({ action: "passthrough" });
    expect(resolvePublicDiscovery({
      accept: "text/markdown",
      method: "GET",
      nextInternalNavigation: true,
      pathname: "/",
    })).toEqual({ action: "passthrough" });
  });
});

describe("llms.txt route", () => {
  test("serves the same markdown body for GET and headers-only HEAD", async () => {
    const response = getLlmsTxt();
    expect(response.status).toBe(200);
    expect(response.headers.get("content-type")).toBe(MARKDOWN_CONTENT_TYPE);
    expect(await response.text()).toBe(HRA_LLMS_TXT);

    const head = headLlmsTxt();
    expect(head.status).toBe(200);
    expect(head.headers.get("content-type")).toBe(MARKDOWN_CONTENT_TYPE);
    expect(await head.text()).toBe("");
  });
});
