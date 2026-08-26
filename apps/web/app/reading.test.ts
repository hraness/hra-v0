import { describe, expect, test } from "bun:test";

import { classifyHraAnalyticsRoute } from "./analytics";
import {
  createHeadlongReadingMarkdown,
  createNotACodexTuiReadingMarkdown,
} from "./public-markdown";
import { metadata as readingMetadata } from "./reading/headlong-always-on-loop/page";
import { metadata as tuiReadingMetadata } from "./reading/not-a-codex-tui/page";
import {
  HRA_DIRECT_SOURCE,
  HRA_HARNESS_WRITING_SOURCE,
  HRA_HEADLONG_ORIGINAL_SOURCE,
  HRA_HEADLONG_READING_DESCRIPTION,
  HRA_HEADLONG_READING_PATH,
  HRA_HEADLONG_READING_SOURCE,
  HRA_HEADLONG_READING_TITLE,
  HRA_NOT_A_CODEX_TUI_READING_DESCRIPTION,
  HRA_NOT_A_CODEX_TUI_READING_PATH,
  HRA_NOT_A_CODEX_TUI_READING_TITLE,
  HRA_PTACEK_TUI_ORIGINAL_SOURCE,
  HRA_PTACEK_TUI_READING_SOURCE,
  HRA_READING_REVIEW_LABEL,
  createHeadlongReadingMarkdown as createReadingMarkdownFromCopy,
  createNotACodexTuiReadingMarkdown as createTuiReadingMarkdownFromCopy,
  isHraPublicReadingPath,
} from "./reading";
import { hraSearchSite } from "./site";

async function source(name: string): Promise<string> {
  return Bun.file(new URL(name, import.meta.url)).text();
}

describe("HRA v0 Headlong reading take", () => {
  test("publishes one crawlable path with a single H1 and fetched-source interlinks", async () => {
    const [page, copy] = await Promise.all([
      source("./reading/headlong-always-on-loop/page.tsx"),
      source("./reading.ts"),
    ]);

    expect(readingMetadata).toMatchObject({
      alternates: { canonical: `https://hra-weld.vercel.app${HRA_HEADLONG_READING_PATH}` },
      description: HRA_HEADLONG_READING_DESCRIPTION,
      robots: { follow: true, index: true },
      title: { default: HRA_HEADLONG_READING_TITLE, template: "%s · HRA v0" },
    });
    expect(readingMetadata.openGraph?.title).toBe(`${HRA_HEADLONG_READING_TITLE} · HRA v0`);
    expect(readingMetadata.twitter?.title).toBe(`${HRA_HEADLONG_READING_TITLE} · HRA v0`);
    expect(page.match(/<h1\b/gu)).toHaveLength(1);
    expect(page.match(/<ThemeMenuButton\b/gu)).toHaveLength(1);
    expect(page).toContain("HRA_HEADLONG_READING_SOURCE");
    expect(page).toContain("HRA_HEADLONG_ORIGINAL_SOURCE");
    expect(page).toContain("HRA_HARNESS_WRITING_SOURCE");
    expect(page).toContain('href="/"');
    expect(page).toContain('href="/alternatives"');
    expect(copy).toContain(HRA_HEADLONG_READING_SOURCE);
    expect(copy).toContain(HRA_HEADLONG_ORIGINAL_SOURCE);
    expect(copy).toContain(HRA_HARNESS_WRITING_SOURCE);
    expect(copy).toContain("never asleep");
    expect(copy).toContain("A harness runs an agent.");
    expect(copy).toContain("Hra is the loop");
    expect(copy).toContain("This page does not claim");
    expect(copy).not.toContain("revolutionary");
    expect(`${page}\n${copy}`).not.toContain("—");
  });

  test("keeps the exact reading leaf public and near misses private", () => {
    expect(isHraPublicReadingPath(HRA_HEADLONG_READING_PATH)).toBeTrue();
    expect(isHraPublicReadingPath(`${HRA_HEADLONG_READING_PATH}/`)).toBeTrue();
    expect(isHraPublicReadingPath(HRA_NOT_A_CODEX_TUI_READING_PATH)).toBeTrue();
    expect(isHraPublicReadingPath(`${HRA_NOT_A_CODEX_TUI_READING_PATH}/`)).toBeTrue();
    expect(isHraPublicReadingPath("/reading")).toBeFalse();
    expect(isHraPublicReadingPath("/reading/")).toBeFalse();
    expect(isHraPublicReadingPath("/reading/missing")).toBeFalse();
    expect(isHraPublicReadingPath(`${HRA_HEADLONG_READING_PATH}/private`)).toBeFalse();
    expect(isHraPublicReadingPath(`${HRA_NOT_A_CODEX_TUI_READING_PATH}/private`)).toBeFalse();
  });

  test("serves the same fetched-claim body as Markdown and stays off analytics", () => {
    const markdown = createHeadlongReadingMarkdown();
    expect(markdown).toBe(createReadingMarkdownFromCopy(hraSearchSite.origin));
    expect(markdown).toContain(`# ${HRA_HEADLONG_READING_TITLE}.`);
    expect(markdown).toContain(HRA_HEADLONG_READING_DESCRIPTION);
    expect(markdown).toContain(`Sources fetched ${HRA_READING_REVIEW_LABEL}.`);
    expect(markdown).toContain(HRA_HEADLONG_READING_SOURCE);
    expect(markdown).toContain("https://hra-weld.vercel.app/");
    expect(markdown).toContain("https://hra-weld.vercel.app/alternatives");
    expect(classifyHraAnalyticsRoute(HRA_HEADLONG_READING_PATH)).toBeNull();
    expect(classifyHraAnalyticsRoute(`${HRA_HEADLONG_READING_PATH}/`)).toBeNull();
  });
});

describe("HRA v0 not-a-Codex-TUI reading take", () => {
  test("publishes one crawlable path with a single H1 and fetched-source interlinks", async () => {
    const [page, copy] = await Promise.all([
      source("./reading/not-a-codex-tui/page.tsx"),
      source("./reading.ts"),
    ]);

    expect(tuiReadingMetadata).toMatchObject({
      alternates: { canonical: `https://hra-weld.vercel.app${HRA_NOT_A_CODEX_TUI_READING_PATH}` },
      description: HRA_NOT_A_CODEX_TUI_READING_DESCRIPTION,
      robots: { follow: true, index: true },
      title: { default: HRA_NOT_A_CODEX_TUI_READING_TITLE, template: "%s · HRA v0" },
    });
    expect(tuiReadingMetadata.openGraph?.title).toBe(
      `${HRA_NOT_A_CODEX_TUI_READING_TITLE} · HRA v0`,
    );
    expect(tuiReadingMetadata.twitter?.title).toBe(
      `${HRA_NOT_A_CODEX_TUI_READING_TITLE} · HRA v0`,
    );
    expect(page.match(/<h1\b/gu)).toHaveLength(1);
    expect(page.match(/<ThemeMenuButton\b/gu)).toHaveLength(1);
    expect(page).toContain("HRA_PTACEK_TUI_ORIGINAL_SOURCE");
    expect(page).toContain("HRA_PTACEK_TUI_READING_SOURCE");
    expect(page).toContain("HRA_HARNESS_WRITING_SOURCE");
    expect(page).toContain("HRA_HEADLONG_READING_PATH");
    expect(page).toContain("HRA_DIRECT_SOURCE");
    expect(page).toContain('href="/"');
    expect(page).toContain('href="/alternatives"');
    expect(copy).toContain(HRA_PTACEK_TUI_ORIGINAL_SOURCE);
    expect(copy).toContain(HRA_PTACEK_TUI_READING_SOURCE);
    expect(copy).toContain(HRA_HARNESS_WRITING_SOURCE);
    expect(copy).toContain(HRA_HEADLONG_READING_PATH);
    expect(copy).toContain(HRA_DIRECT_SOURCE);
    expect(copy).toContain("We build terminal interfaces because we have to");
    expect(copy).toContain("A metaharness is not ASCII chrome");
    expect(copy).toContain("does not mention HRA");
    expect(copy).toContain("does not claim that HRA cannot have a UI");
    expect(copy).toContain("Ptacek wrote about HRA");
    expect(copy).not.toContain("revolutionary");
    expect(copy).not.toContain("Thomas Ptacek argues that agents have made native desktop UI cheap enough");
    expect(`${page}\n${copy}`).not.toContain("—");
  });

  test("serves the same fetched-claim body as Markdown and stays off analytics", () => {
    const markdown = createNotACodexTuiReadingMarkdown();
    expect(markdown).toBe(createTuiReadingMarkdownFromCopy(hraSearchSite.origin));
    expect(markdown).toContain(`# ${HRA_NOT_A_CODEX_TUI_READING_TITLE}.`);
    expect(markdown).toContain(HRA_NOT_A_CODEX_TUI_READING_DESCRIPTION);
    expect(markdown).toContain(`Sources fetched ${HRA_READING_REVIEW_LABEL}.`);
    expect(markdown).toContain(HRA_PTACEK_TUI_ORIGINAL_SOURCE);
    expect(markdown).toContain(HRA_PTACEK_TUI_READING_SOURCE);
    expect(markdown).toContain(`https://hra-weld.vercel.app${HRA_HEADLONG_READING_PATH}`);
    expect(markdown).toContain("https://hra-weld.vercel.app/");
    expect(classifyHraAnalyticsRoute(HRA_NOT_A_CODEX_TUI_READING_PATH)).toBeNull();
    expect(classifyHraAnalyticsRoute(`${HRA_NOT_A_CODEX_TUI_READING_PATH}/`)).toBeNull();
  });
});
