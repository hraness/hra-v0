import { HranessBrand } from "@hra-internal/brand-ui";
import { ThemeMenuButton } from "@hra-internal/design-kit/react";
import { createPublicSiteMetadata } from "@hraness/web-discovery";
import type { Metadata } from "next";
import Link from "next/link";

import {
  CURRENT_HRA_SITE,
  HRA_PRIVACY_LAST_UPDATED,
  HRA_PRIVACY_PATH,
  HRA_SECURITY_CONTACT_URL,
  HRA_SECURITY_POLICY_URL,
  HRA_SECURITY_TXT_PATH,
  hraSearchSite,
  hraSocialPageTitle,
} from "../site";

export const metadata = createPublicSiteMetadata({
  ...hraSearchSite,
  description:
    "How the HRA v0 archive handles public analytics, hosted coordination data, local execution data, and service-provider boundaries.",
  socialTitle: hraSocialPageTitle("HRA v0 privacy"),
  title: "HRA v0 privacy",
}, { canonicalPath: HRA_PRIVACY_PATH }) satisfies Metadata;

export default function PrivacyPage() {
  return (
    <div className="alternatives-page privacy-page">
      <a className="landing-skip-link" href="#main-content">Skip to content</a>
      <header className="alternatives-header">
        <Link aria-label="HRA v0 home" className="landing-wordmark" href="/">
          <strong>HRA v0</strong>
        </Link>
        <div className="alternatives-header-actions">
          <nav aria-label="Privacy navigation">
            <Link href="/">Archive</Link>
            <Link href="/releases">Release history</Link>
            <a href={CURRENT_HRA_SITE}>Current HRA</a>
          </nav>
          <ThemeMenuButton />
        </div>
      </header>

      <main className="alternatives-shell" id="main-content">
        <section aria-labelledby="privacy-title" className="alternatives-hero privacy-hero">
          <p className="landing-eyebrow">Archived product notice</p>
          <h1 id="privacy-title">Privacy at the HRA v0 archive.</h1>
          <p className="alternatives-lede">
            The archive separates public browsing, signed-in coordination data, and local Mac authority. This notice describes what each boundary can process and where the archived product has no universal retention promise.
          </p>
          <p className="alternatives-reviewed">Last updated {HRA_PRIVACY_LAST_UPDATED}</p>
        </section>

        <section aria-labelledby="public-browsing-title" className="alternatives-section privacy-section">
          <div>
            <p className="landing-eyebrow">Public archive</p>
            <h2 id="public-browsing-title">Public browsing stays narrow.</h2>
          </div>
          <div className="privacy-copy">
            <h3>Route-only analytics</h3>
            <p>
              On the exact Production archive origin, HRA v0 can send a cookieless, personless PostHog pageview from <code>/</code>, <code>/download</code>, <code>/alternatives</code>, and the exact published comparison pages. The event contains the canonical route, page kind, archive site ID, and comparison slug when applicable. It excludes query text, URL fragments, referrers, account and task data, commands, provider sessions, and custom events.
            </p>
            <p>
              The analytics client uses memory-only persistence, creates no person profile, disables autocapture, replay, surveys, feature flags, exception capture, and performance capture, and respects the browser&apos;s Do Not Track setting. This privacy page, the release ledger, machine-readable files, and every signed-in route are outside the analytics allowlist.
            </p>
            <h3>Hosting requests</h3>
            <p>
              Vercel serves the archive and may process operational request data such as network and browser metadata under its <a href="https://vercel.com/legal/privacy-notice">privacy notice</a>. PostHog processes allowed pageview requests under its <a href="https://posthog.com/privacy">privacy policy</a>. HRA v0 adds no advertising tracker.
            </p>
          </div>
        </section>

        <section aria-labelledby="control-plane-title" className="alternatives-section privacy-section">
          <div>
            <p className="landing-eyebrow">Signed-in control plane</p>
            <h2 id="control-plane-title">Hosted data is coordination data.</h2>
          </div>
          <div className="privacy-copy">
            <p>
              WorkOS authenticates humans and organization membership. Convex stores the WorkOS subject, human name and email when supplied, organization and membership provider identifiers, role claims, and the authorized task graph with its related workspaces, agents, runner state, dependencies, claims, submissions, reviews, bounded display events, and human decisions. Those providers process data under the <a href="https://workos.com/legal/privacy">WorkOS privacy notice</a> and <a href="https://www.convex.dev/legal/privacy">Convex privacy policy</a>.
            </p>
            <p>
              The service can read accepted task descriptions, comments, reasoning summaries, assistant messages, and remote question text and choices. Structural validation limits their size and shape but cannot detect every secret in ordinary prose. Do not put credentials, private keys, sensitive local data, or personal data that the work does not require into those fields.
            </p>
            <p>
              An optional Hraness suite-account link adds a bounded account and entitlement status to the signed-in human. It does not identify a Codex account, agent credential, local session, runner, or repository, and it does not grant an HRA role or task capability.
            </p>
          </div>
        </section>

        <section aria-labelledby="local-authority-title" className="alternatives-section privacy-section">
          <div>
            <p className="landing-eyebrow">Paired Mac</p>
            <h2 id="local-authority-title">Execution authority stays local.</h2>
          </div>
          <div className="privacy-copy">
            <p>
              Codex credentials, provider sessions, raw transcripts, raw reasoning, tool names and arguments, environment values, commands, diffs, command output, canonical filesystem paths, local repositories, worktrees, and local SQLite state remain on the paired Mac. Credential and key material uses macOS Keychain-backed custody where the feature requires it.
            </p>
            <p>
              Optional cross-device session sync sends an end-to-end encrypted summary projection rather than prompts or transcripts. The relay still stores or observes traffic timing, bounded ciphertext sizes, opaque vault, device, and session identifiers, device names and public keys, enrollment state and one-time pairing metadata, boot and heartbeat presence, membership epochs and device membership, and session lifecycle event kinds and revisions. Accepted remote answers are encrypted to a boot-scoped desktop key and deleted from the relay after acknowledgement or expiry.
            </p>
          </div>
        </section>

        <section aria-labelledby="retention-title" className="alternatives-section privacy-section">
          <div>
            <p className="landing-eyebrow">Retention and choices</p>
            <h2 id="retention-title">The archive does not invent a retention promise.</h2>
          </div>
          <div className="privacy-copy">
            <p>
              Durable task and authorization records remain available for history, review, fencing, and recovery. Hosted data residency, backup retention, request-log retention, and incident handling depend on the deployed provider configuration. HRA v0 does not publish one fixed retention period that overrides those systems.
            </p>
            <ul>
              <li>Use Do Not Track to suppress the optional HRA pageview on analytics-eligible public routes.</li>
              <li>Do not use the signed-in control plane for content you do not want sent to the hosted service.</li>
              <li>Sign out and revoke task credentials when a human or agent should no longer have access.</li>
              <li>For a private data-access or deletion request, <a href="https://github.com/hraness/hra-v0/issues/new">ask a maintainer to establish a private contact channel</a>. Do not include personal data, credentials, or task content in the public issue.</li>
            </ul>
          </div>
        </section>

        <section aria-labelledby="security-title" className="alternatives-section privacy-section">
          <div>
            <p className="landing-eyebrow">Security and changes</p>
            <h2 id="security-title">Report sensitive defects privately.</h2>
          </div>
          <div className="privacy-copy">
            <p>
              Read the archived <a href={HRA_SECURITY_POLICY_URL}>security policy</a> and <a href="https://github.com/hraness/hra-v0/blob/main/SECURITY_ARCHITECTURE.md">security architecture</a>. Report a vulnerability through <a href={HRA_SECURITY_CONTACT_URL}>GitHub private vulnerability reporting</a>. The standard contact file is available at <a href={HRA_SECURITY_TXT_PATH}>{HRA_SECURITY_TXT_PATH}</a>.
            </p>
            <p>
              HRA v0 is archived. Its generation-1 compatibility ledger ends at the immutable v0.1.15 prerelease. A material correction to this notice will update its date and the checked public source. Privacy information for the current HRA belongs at <a href={CURRENT_HRA_SITE}>hra.sh</a>.
            </p>
          </div>
        </section>
      </main>

      <footer className="alternatives-footer privacy-footer">
        <HranessBrand />
        <p>
          HRA v0 archive · <Link href="/">Archive</Link> · <a href={HRA_SECURITY_POLICY_URL}>Security</a>
        </p>
      </footer>
    </div>
  );
}
