import { HranessBrand } from "@hra-internal/brand-ui";
import { ThemeMenuButton } from "@hra-internal/design-kit/react";
import { createPublicSiteMetadata } from "@hraness/web-discovery";
import type { Metadata } from "next";
import Link from "next/link";

import {
  HRA_DIRECT_SOURCE,
  HRA_HARNESS_WRITING_SOURCE,
  HRA_HEADLONG_READING_PATH,
  HRA_NOT_A_CODEX_TUI_READING_DESCRIPTION,
  HRA_NOT_A_CODEX_TUI_READING_PATH,
  HRA_NOT_A_CODEX_TUI_READING_TITLE,
  HRA_PTACEK_TUI_ORIGINAL_SOURCE,
  HRA_PTACEK_TUI_READING_SOURCE,
  notACodexTuiReadingCopy,
} from "../../reading";
import {
  CURRENT_HRA_SITE,
  hraSearchSite,
  hraSocialPageTitle,
} from "../../site";

export const metadata = createPublicSiteMetadata({
  ...hraSearchSite,
  description: HRA_NOT_A_CODEX_TUI_READING_DESCRIPTION,
  socialTitle: hraSocialPageTitle(HRA_NOT_A_CODEX_TUI_READING_TITLE),
  title: HRA_NOT_A_CODEX_TUI_READING_TITLE,
}, { canonicalPath: HRA_NOT_A_CODEX_TUI_READING_PATH }) satisfies Metadata;

export default function NotACodexTuiPage() {
  return (
    <div className="alternatives-page privacy-page">
      <a className="landing-skip-link" href="#main-content">Skip to content</a>
      <header className="alternatives-header">
        <Link aria-label="HRA v0 home" className="landing-wordmark" href="/">
          <strong>HRA v0</strong>
        </Link>
        <div className="alternatives-header-actions">
          <nav aria-label="Reading navigation">
            <Link href="/">Archive</Link>
            <Link href="/alternatives">Compare</Link>
            <a href={CURRENT_HRA_SITE}>Current HRA</a>
          </nav>
          <ThemeMenuButton />
        </div>
      </header>

      <main className="alternatives-shell" id="main-content">
        <section aria-labelledby="reading-title" className="alternatives-hero privacy-hero">
          <p className="landing-eyebrow">{notACodexTuiReadingCopy.eyebrow}</p>
          <h1 id="reading-title">{notACodexTuiReadingCopy.heading}</h1>
          <p className="alternatives-lede">{notACodexTuiReadingCopy.lede}</p>
          <p className="alternatives-reviewed">{notACodexTuiReadingCopy.reviewed}</p>
        </section>

        <section aria-labelledby="tui-job-title" className="alternatives-section privacy-section">
          <div>
            <p className="landing-eyebrow">Stop Making TUIs</p>
            <h2 id="tui-job-title">{notACodexTuiReadingCopy.tuiHeading}</h2>
          </div>
          <div className="privacy-copy">
            {notACodexTuiReadingCopy.tuiBody.map((paragraph) => (
              <p key={paragraph}>{paragraph}</p>
            ))}
          </div>
        </section>

        <section aria-labelledby="hra-job-title" className="alternatives-section privacy-section">
          <div>
            <p className="landing-eyebrow">HRA v0</p>
            <h2 id="hra-job-title">{notACodexTuiReadingCopy.hraHeading}</h2>
          </div>
          <div className="privacy-copy">
            {notACodexTuiReadingCopy.hraBody.map((paragraph) => (
              <p key={paragraph}>{paragraph}</p>
            ))}
          </div>
        </section>

        <section aria-labelledby="contrast-title" className="alternatives-section privacy-section">
          <div>
            <p className="landing-eyebrow">TUI habit vs published job</p>
            <h2 id="contrast-title">{notACodexTuiReadingCopy.contrastHeading}</h2>
          </div>
          <div className="privacy-copy">
            {notACodexTuiReadingCopy.contrastBody.map((paragraph) => (
              <p key={paragraph}>{paragraph}</p>
            ))}
          </div>
        </section>

        <section aria-labelledby="sources-title" className="alternatives-section privacy-section">
          <div>
            <p className="landing-eyebrow">Fetched pages</p>
            <h2 id="sources-title">Sources</h2>
          </div>
          <div className="privacy-copy">
            <ul>
              <li><a href={HRA_PTACEK_TUI_ORIGINAL_SOURCE}>Stop Making TUIs</a></li>
              <li><a href={HRA_PTACEK_TUI_READING_SOURCE}>Hraness reading note</a></li>
              <li><a href={HRA_HARNESS_WRITING_SOURCE}>What is an agent harness?</a></li>
              <li>
                <Link href={HRA_HEADLONG_READING_PATH}>
                  Headlong always-on loop next to HRA v0
                </Link>
              </li>
              <li><a href={HRA_DIRECT_SOURCE}>Direct</a></li>
              <li><Link href="/">HRA v0 archive</Link></li>
            </ul>
          </div>
        </section>
      </main>

      <footer className="alternatives-footer privacy-footer">
        <HranessBrand />
        <p>
          HRA v0 archive · <Link href="/">Archive</Link> · <Link href="/alternatives">Compare</Link> · <Link href="/privacy">Privacy</Link>
        </p>
      </footer>
    </div>
  );
}
