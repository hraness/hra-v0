import { HranessBrand } from "@hra-internal/brand-ui";
import { ThemeMenuButton } from "@hra-internal/design-kit/react";
import { createPublicSiteMetadata } from "@hraness/web-discovery";
import type { Metadata } from "next";
import Link from "next/link";

import {
  HRA_HARNESS_WRITING_SOURCE,
  HRA_HEADLONG_ORIGINAL_SOURCE,
  HRA_HEADLONG_READING_DESCRIPTION,
  HRA_HEADLONG_READING_PATH,
  HRA_HEADLONG_READING_SOURCE,
  HRA_HEADLONG_READING_TITLE,
  headlongReadingCopy,
} from "../../reading";
import {
  CURRENT_HRA_SITE,
  hraSearchSite,
  hraSocialPageTitle,
} from "../../site";

export const metadata = createPublicSiteMetadata({
  ...hraSearchSite,
  description: HRA_HEADLONG_READING_DESCRIPTION,
  socialTitle: hraSocialPageTitle(HRA_HEADLONG_READING_TITLE),
  title: HRA_HEADLONG_READING_TITLE,
}, { canonicalPath: HRA_HEADLONG_READING_PATH }) satisfies Metadata;

export default function HeadlongAlwaysOnLoopPage() {
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
          <p className="landing-eyebrow">{headlongReadingCopy.eyebrow}</p>
          <h1 id="reading-title">{headlongReadingCopy.heading}</h1>
          <p className="alternatives-lede">{headlongReadingCopy.lede}</p>
          <p className="alternatives-reviewed">{headlongReadingCopy.reviewed}</p>
        </section>

        <section aria-labelledby="headlong-job-title" className="alternatives-section privacy-section">
          <div>
            <p className="landing-eyebrow">Headlong</p>
            <h2 id="headlong-job-title">{headlongReadingCopy.headlongHeading}</h2>
          </div>
          <div className="privacy-copy">
            {headlongReadingCopy.headlongBody.map((paragraph) => (
              <p key={paragraph}>{paragraph}</p>
            ))}
          </div>
        </section>

        <section aria-labelledby="hra-job-title" className="alternatives-section privacy-section">
          <div>
            <p className="landing-eyebrow">HRA v0</p>
            <h2 id="hra-job-title">{headlongReadingCopy.hraHeading}</h2>
          </div>
          <div className="privacy-copy">
            {headlongReadingCopy.hraBody.map((paragraph) => (
              <p key={paragraph}>{paragraph}</p>
            ))}
          </div>
        </section>

        <section aria-labelledby="contrast-title" className="alternatives-section privacy-section">
          <div>
            <p className="landing-eyebrow">Jobs, not invented features</p>
            <h2 id="contrast-title">{headlongReadingCopy.contrastHeading}</h2>
          </div>
          <div className="privacy-copy">
            {headlongReadingCopy.contrastBody.map((paragraph) => (
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
              <li><a href={HRA_HEADLONG_READING_SOURCE}>Headlong reading digest</a></li>
              <li><a href={HRA_HEADLONG_ORIGINAL_SOURCE}>Headlong: a microharness for persistent agents</a></li>
              <li><a href={HRA_HARNESS_WRITING_SOURCE}>What is an agent harness?</a></li>
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
