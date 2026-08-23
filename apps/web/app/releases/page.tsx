import { ThemeMenuButton } from "@hra-internal/design-kit/react";
import { createPublicSiteMetadata } from "@hraness/web-discovery";
import type { Metadata } from "next";
import Link from "next/link";

import {
  formatReleaseBytes,
  HRA_RELEASE_HISTORY,
  hraCommitUrl,
  hraReleaseAssetUrl,
  hraReleaseTagUrl,
  hraTagObjectUrl,
  type HraReleaseHistoryTag,
} from "../release-history";
import {
  CURRENT_HRA_SITE,
  hraSearchSite,
  hraSocialPageTitle,
} from "../site";

export const metadata = createPublicSiteMetadata({
  ...hraSearchSite,
  description:
    "Exact HRA v0 tags, source commits, immutable GitHub releases, asset sizes, checksums, and download links.",
  socialTitle: hraSocialPageTitle("HRA v0 release history"),
  title: "HRA v0 release history",
}, { canonicalPath: "/releases" }) satisfies Metadata;

function ReleaseEntry({ entry }: { readonly entry: HraReleaseHistoryTag }) {
  const finalRelease = entry.tag === "v0.1.14";
  return (
    <article className={finalRelease ? "release-history-entry release-history-entry--final" : "release-history-entry"}>
      <header>
        <div>
          <p className="landing-eyebrow">
            {finalRelease ? "Final archived prerelease" : entry.release === null ? "Tag only" : "Immutable prerelease"}
          </p>
          <h2>{entry.tag} <span>build {entry.build}</span></h2>
        </div>
        {entry.release === null ? (
          <span className="release-history-state release-history-state--tag">No GitHub release</span>
        ) : (
          <a className="release-history-state" href={hraReleaseTagUrl(entry)}>
            GitHub release #{entry.release.id}
          </a>
        )}
      </header>

      <dl className="release-history-git">
        <div>
          <dt>Tag object</dt>
          <dd>Annotated · <a href={hraTagObjectUrl(entry)}><code>{entry.tagObject}</code></a></dd>
        </div>
        <div>
          <dt>Peeled commit</dt>
          <dd><a href={hraCommitUrl(entry)}><code>{entry.commit}</code></a></dd>
        </div>
      </dl>

      {entry.release === null ? (
        <p className="release-history-tag-only">
          v0.1.11 was a tagged candidate only. It has no GitHub release or downloadable assets and is not prior installed authority.
        </p>
      ) : (
        <details className="release-history-assets" open={finalRelease}>
          <summary>
            {entry.release.assets.length} assets · published {entry.release.publishedAt.slice(0, 10)}
          </summary>
          <div className="release-history-asset-scroll">
            <table>
              <thead>
                <tr>
                  <th scope="col">Asset</th>
                  <th scope="col">Size</th>
                  <th scope="col">SHA-256</th>
                </tr>
              </thead>
              <tbody>
                {entry.release.assets.map((asset) => (
                  <tr key={asset.id}>
                    <th scope="row"><a href={hraReleaseAssetUrl(entry, asset)}>{asset.name}</a></th>
                    <td>{formatReleaseBytes(asset.bytes)} <span>({asset.bytes.toLocaleString("en-US")} bytes)</span></td>
                    <td><code>{asset.sha256}</code></td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </details>
      )}
    </article>
  );
}

export default function ReleasesPage() {
  return (
    <div className="alternatives-page release-history-page">
      <a className="landing-skip-link" href="#main-content">Skip to content</a>
      <header className="alternatives-header">
        <Link aria-label="HRA v0 home" className="landing-wordmark" href="/">
          <strong>HRA v0</strong>
        </Link>
        <nav aria-label="Release navigation">
          <Link href="/">Archive</Link>
          <Link href="/download">Download</Link>
          <a href={CURRENT_HRA_SITE}>Current HRA</a>
        </nav>
        <div className="alternatives-header-actions">
          <ThemeMenuButton />
        </div>
      </header>

      <main className="alternatives-shell" id="main-content">
        <section className="alternatives-hero release-history-hero" aria-labelledby="release-history-title">
          <p className="landing-eyebrow">Compatibility ledger · v0.1.7–v0.1.14</p>
          <h1 id="release-history-title">HRA v0 release history</h1>
          <p className="alternatives-lede">
            This ledger records every preserved tag from v0.1.7 through v0.1.14, every GitHub release that exists, and every attached asset. The checked archive manifest supplies the object IDs, byte counts, checksums, and links below.
          </p>
          <p className="alternatives-reviewed">
            Seven immutable prereleases · eight annotated tags · v0.1.11 tag only
          </p>
        </section>

        <section className="release-history-list" aria-label="HRA v0 tags and releases">
          {HRA_RELEASE_HISTORY.tags.toReversed().map((entry) => (
            <ReleaseEntry entry={entry} key={entry.tag} />
          ))}
        </section>

        <section className="alternatives-section release-history-method" aria-labelledby="release-history-method-title">
          <div className="alternatives-section-heading">
            <p className="landing-eyebrow">Verification boundary</p>
            <h2 id="release-history-method-title">The archive checks the remote objects.</h2>
            <p>
              The credential-free remote release gate reads the renamed repository, verifies the exact tag objects and peeled commits, requires v0.1.11 to remain release-free, and compares every immutable release and asset with the checked ledger. The final v0.1.14 gate also checks its checksum and release manifest contents.
            </p>
          </div>
        </section>
      </main>

      <footer className="alternatives-footer">
        <p>HRA v0 archive · exact Git and GitHub evidence</p>
        <Link href="/privacy">Privacy</Link>
        <a href="https://github.com/hraness/hra-v0/security/policy">Security</a>
        <a href={HRA_RELEASE_HISTORY.repository}>github.com/hraness/hra-v0</a>
      </footer>
    </div>
  );
}
