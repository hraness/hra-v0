import { describe, expect, test } from "bun:test";

import {
  GET as getSecurityTxt,
  HEAD as headSecurityTxt,
  HRA_SECURITY_TXT,
} from "./.well-known/security.txt/route";
import { metadata as privacyMetadata } from "./privacy/page";
import {
  HRA_PRIVACY_LAST_UPDATED,
  HRA_SECURITY_CONTACT_URL,
  HRA_SECURITY_POLICY_URL,
  HRA_SECURITY_TXT_EXPIRES_AT,
  HRA_SECURITY_TXT_PATH,
} from "./site";

async function source(name: string): Promise<string> {
  return Bun.file(new URL(name, import.meta.url)).text();
}

describe("HRA v0 privacy surface", () => {
  test("publishes a canonical, indexable notice tied to implemented boundaries", async () => {
    const page = await source("./privacy/page.tsx");

    expect(privacyMetadata).toMatchObject({
      alternates: { canonical: "https://hra-weld.vercel.app/privacy" },
      robots: { follow: true, index: true },
      title: { default: "HRA v0 privacy", template: "%s · HRA v0" },
    });
    expect(page.match(/<h1\b/gu)).toHaveLength(1);
    expect(page.match(/<ThemeMenuButton\b/gu)).toHaveLength(1);
    expect(page).toContain(`Last updated {HRA_PRIVACY_LAST_UPDATED}`);
    expect(HRA_PRIVACY_LAST_UPDATED).toBe("August 23, 2026");
    expect(page).toContain("cookieless, personless PostHog pageview");
    expect(page).toContain("every signed-in route are outside the analytics allowlist");
    expect(page).toContain("WorkOS subject, human name and email when supplied");
    expect(page).toContain("device names and public keys, enrollment state and one-time pairing metadata");
    expect(page).toContain("session lifecycle event kinds and revisions");
    expect(page).toContain("Codex credentials, provider sessions, raw transcripts");
    expect(page).toContain("does not publish one fixed retention period");
    expect(page).toContain("ask a maintainer to establish a private contact channel");
    expect(page).toContain("https://vercel.com/legal/privacy-notice");
    expect(page).toContain("https://posthog.com/privacy");
    expect(page).toContain("https://workos.com/legal/privacy");
    expect(page).toContain("https://www.convex.dev/legal/privacy");
  });
});

describe("HRA v0 security.txt", () => {
  test("publishes the RFC 9116 contact contract at the canonical archive origin", () => {
    expect(HRA_SECURITY_TXT).toBe([
      `Contact: ${HRA_SECURITY_CONTACT_URL}`,
      `Expires: ${HRA_SECURITY_TXT_EXPIRES_AT}`,
      `Canonical: https://hra-weld.vercel.app${HRA_SECURITY_TXT_PATH}`,
      `Policy: ${HRA_SECURITY_POLICY_URL}`,
      "Preferred-Languages: en",
      "",
    ].join("\n"));
    expect(HRA_SECURITY_CONTACT_URL).toBe(
      "https://github.com/hraness/hra-v0/security/advisories/new",
    );
    expect(HRA_SECURITY_POLICY_URL).toBe(
      "https://github.com/hraness/hra-v0/security/policy",
    );
    expect(HRA_SECURITY_TXT_EXPIRES_AT).toBe("2027-08-22T23:59:59Z");
    expect(Number.isNaN(Date.parse(HRA_SECURITY_TXT_EXPIRES_AT))).toBeFalse();
  });

  test("serves exact plain text for GET and headers-only HEAD", async () => {
    const response = getSecurityTxt();
    expect(response.status).toBe(200);
    expect(response.headers.get("content-type")).toBe("text/plain; charset=utf-8");
    expect(response.headers.get("cache-control")).toBe(
      "public, max-age=0, must-revalidate",
    );
    expect(await response.text()).toBe(HRA_SECURITY_TXT);

    const head = headSecurityTxt();
    expect(head.status).toBe(200);
    expect(head.headers.get("content-type")).toBe("text/plain; charset=utf-8");
    expect(await head.text()).toBe("");
  });
});
