import {
  HTML_MEDIA_TYPE,
  MARKDOWN_CONTENT_TYPE,
  MARKDOWN_MEDIA_TYPE,
  preferredPublicDocumentType,
} from "./accept-negotiation";
import {
  COMPARISON_REVIEW_LABEL,
  comparisonForSlug,
  hraComparisons,
  sourceNumber,
  type HraComparison,
} from "./alternatives/comparisons";
import { isHraPublicComparisonPath } from "./alternatives/slugs";
import {
  HRA_DEPLOYMENT_IDENTITY_PATH,
} from "./deployment-identity";
import {
  HRA_RELEASE_HISTORY,
  hraCommitUrl,
  hraReleaseAssetUrl,
  hraReleaseTagUrl,
  hraTagObjectUrl,
} from "./release-history";
import {
  CURRENT_HRA_REPOSITORY,
  CURRENT_HRA_SITE,
  HRA_PRIVACY_LAST_UPDATED,
  HRA_PRIVACY_PATH,
  HRA_RELEASE,
  HRA_RELEASE_CHECKSUM_URL,
  HRA_RELEASE_MANIFEST_URL,
  HRA_RELEASE_URL,
  HRA_SECURITY_CONTACT_URL,
  HRA_SECURITY_POLICY_URL,
  HRA_SECURITY_TXT_PATH,
  hraSearchSite,
} from "./site";

export const HRA_LLMS_TXT_PATH = "/llms.txt" as const;

const origin = hraSearchSite.origin;

function absoluteUrl(path: `/${string}`): string {
  return `${origin}${path}`;
}

function citationMarks(
  comparison: HraComparison,
  sourceIds: readonly string[],
): string {
  if (sourceIds.length === 0) return "";
  const marks = sourceIds.map((sourceId) => {
    const source = comparison.sources.find((candidate) => candidate.id === sourceId);
    if (source === undefined) {
      throw new Error(`Unknown source ${sourceId} for ${comparison.slug}`);
    }
    return `[${sourceNumber(comparison, source)}]`;
  });
  return ` ${marks.join("")}`;
}

export function canonicalPublicPath(pathname: string): string | null {
  if (pathname.includes("//") || pathname.includes("\\")) return null;
  if (!pathname.startsWith("/")) return null;
  return pathname.length > 1 && pathname.endsWith("/")
    ? pathname.slice(0, -1)
    : pathname;
}

export function isPublicHtmlDocumentPath(pathname: string): boolean {
  const canonicalPath = canonicalPublicPath(pathname);
  if (canonicalPath === null) return false;
  return canonicalPath === "/"
    || canonicalPath === "/download"
    || canonicalPath === HRA_PRIVACY_PATH
    || canonicalPath === "/releases"
    || isHraPublicComparisonPath(canonicalPath);
}

export function isAgentDiscoveryPath(pathname: string): boolean {
  const canonicalPath = canonicalPublicPath(pathname);
  return canonicalPath === HRA_LLMS_TXT_PATH
    || canonicalPath === HRA_SECURITY_TXT_PATH
    || canonicalPath === "/robots.txt"
    || canonicalPath === "/sitemap.xml";
}

export function isAuthProtectedTree(pathname: string): boolean {
  const canonicalPath = canonicalPublicPath(pathname);
  if (canonicalPath === null) return true;
  return canonicalPath === "/api"
    || canonicalPath.startsWith("/api/")
    || canonicalPath === "/app"
    || canonicalPath.startsWith("/app/")
    || canonicalPath === "/auth"
    || canonicalPath.startsWith("/auth/")
    || canonicalPath === "/design"
    || canonicalPath.startsWith("/design/");
}

function lastPathSegment(pathname: string): string {
  const segments = pathname.split("/").filter((segment) => segment.length > 0);
  return segments.at(-1) ?? "";
}

export function pathLooksLikeStaticAsset(pathname: string): boolean {
  const segment = lastPathSegment(pathname);
  return segment.includes(".");
}

export function createHraLlmsTxt(): string {
  const pages = [
    `- [HRA v0 archive](${absoluteUrl("/")}): Archive status, current-HRA handoff, and original product overview`,
    `- [HRA v0 download](${absoluteUrl("/download")}): Current Apple Silicon release status and source-build guidance`,
    `- [HRA v0 release history](${absoluteUrl("/releases")}): Exact tags, commits, releases, assets, sizes, checksums, and download links`,
    `- [HRA v0 privacy](${absoluteUrl(HRA_PRIVACY_PATH)}): Public analytics, hosted coordination data, local execution data, retention, and provider boundaries`,
    `- [HRA v0 alternatives](${absoluteUrl("/alternatives")}): Historical first-party-sourced comparisons`,
    ...hraComparisons.map((comparison) =>
      `- [HRA vs ${comparison.shortName}](${absoluteUrl(`/alternatives/${comparison.slug}`)}): ${comparison.description}`),
  ];
  return [
    "# HRA v0 archive",
    "",
    `> ${hraSearchSite.description}`,
    "",
    `This is the maintained archive for HRA v0. New users should start with [current HRA](${CURRENT_HRA_SITE}) and its [current source](${CURRENT_HRA_REPOSITORY}). Use this site for HRA v0 macOS release status, the frozen v0.1.7–v0.1.15 compatibility ledger, historical source, and v0 documentation.`,
    "",
    "Choose something simpler when you want the first-party Codex experience for a few independent sessions, your team needs one desktop for many model providers, the main problem is remote access from a phone, or a worktree launcher and diff viewer already solve the job.",
    "",
    "How an agent should use this archive: request `Accept: text/markdown` on the public pages below, or start from this file. Point new users at https://hra.sh. Point v0 users at `/download` and https://github.com/hraness/hra-v0. Do not treat hra-weld.vercel.app as an execution, OAuth, GraphQL, MCP, or commerce API.",
    "",
    "## Pages",
    "",
    ...pages,
    "",
    "## Optional",
    "",
    `- [Agent guide](${absoluteUrl(HRA_LLMS_TXT_PATH)}): This file`,
    `- [XML sitemap](${absoluteUrl("/sitemap.xml")}): Indexable public HTML pages`,
    `- [Robots](${absoluteUrl("/robots.txt")}): Crawler allow and deny rules`,
    `- [Deployment identity](${absoluteUrl(HRA_DEPLOYMENT_IDENTITY_PATH)}): Stable generation and publication marker for cutover checks`,
    `- [Security contact](${absoluteUrl(HRA_SECURITY_TXT_PATH)}): Standard vulnerability-reporting contact and policy links`,
    "- [HRA v0 source](https://github.com/hraness/hra-v0): Archived product source, security architecture, and build checks",
    `- [Current HRA](${CURRENT_HRA_SITE}): Current product and documentation`,
    `- [Current HRA source](${CURRENT_HRA_REPOSITORY}): Current repository`,
    "",
  ].join("\n");
}

export const HRA_LLMS_TXT = createHraLlmsTxt();

export function createLandingMarkdown(): string {
  const releaseSummary = HRA_RELEASE.availability === "published"
    ? `The current archived download is the published v${HRA_RELEASE.version} prerelease.`
    : `HRA v${HRA_RELEASE.version} is still a candidate in this source and has no direct download.`;
  return [
    "# HRA v0 is preserved here.",
    "",
    hraSearchSite.description,
    "",
    `This site and repository preserve the original HRA macOS metaharness and its source. ${releaseSummary}`,
    "",
    `New users should start with [current HRA](${CURRENT_HRA_SITE}) or its [current source](${CURRENT_HRA_REPOSITORY}). Existing v0 users can use this archive and its release-status page.`,
    "",
    "## When to use HRA",
    "",
    "- one project needs several coordinated Codex sessions",
    "- you have separate authorized Codex accounts to keep isolated",
    "- child work must rejoin a durable parent task",
    "- restarts and ambiguous effects need explicit recovery",
    "",
    "## Choose something simpler when",
    "",
    "- you want the first-party Codex experience for a few independent sessions",
    "- your team needs one desktop for many model providers",
    "- the main problem is remote access from a phone",
    "- a worktree launcher and diff viewer already solve the job",
    "",
    "## Why HRA exists",
    "",
    "Parallel is the beginning, not the product. A row of sessions can do more work. It cannot decide which work belongs together, preserve ownership after a restart, or tell a bounded helper how to return to its parent.",
    "",
    "1. Coordinate the accounts you already use. Pair separate Codex accounts that you own or are authorized to use. Credentials and provider sessions remain isolated on your Mac.",
    "2. Delegate work with structure. Turn one outcome into durable parent and child tasks with dependencies, bounded ownership, and an explicit path back to review.",
    "3. Spend reasoning deliberately. Give wide work more room, bounded work a lighter lane, and follow-ups the same conversation when continuity is still safe.",
    "4. Recover the work, not just the window. Persist who owned each effect, what was observed, and what still needs review so a restart does not turn uncertainty into a duplicate action.",
    "",
    "## How it works",
    "",
    "1. Connect the Mac. Choose the repositories and Codex accounts this installation is allowed to use.",
    "2. Describe the outcome. HRA keeps the plan, dependencies, ownership, and review state outside any one agent conversation.",
    "3. Let the work divide. Codex sessions run in managed worktrees; bounded child work can proceed in parallel without becoming unrelated tabs.",
    "4. Review and continue. Accept the result, answer a question, redirect a branch, or resume the same durable task after an interruption.",
    "",
    "## Questions",
    "",
    "### What is a metaharness?",
    "",
    "A harness runs an agent. A metaharness decides how several harnesses divide work, share bounded context, choose a lane, recover interrupted effects, and bring results back to one review path. Codex does the coding; HRA coordinates the system around it.",
    "",
    "### Does HRA bypass Codex limits?",
    "",
    "No. A provider limit ends the affected turn. HRA does not move that work to another account. Every account remains subject to its own plan, limits, organization policy, and OpenAI terms. Use only accounts you own or are authorized to use, and group them only when each is allowed to access the same repository and data.",
    "",
    "### How is this different from the Codex app?",
    "",
    "The Codex app is the first-party place to run and review parallel Codex sessions. HRA is for the layer above them: several isolated account identities, a durable parent-and-child task graph, work-aware routing, human gates, and crash recovery across sessions.",
    "",
    "### Where does execution authority live?",
    "",
    "On the paired Mac. Provider credentials, local repositories, commands, raw transcripts, and provider session identifiers do not become browser authority. The hosted surface receives bounded coordination and review state.",
    "",
    "### What can I install today?",
    "",
    HRA_RELEASE.availability === "published"
      ? `The archived v${HRA_RELEASE.version} Apple Silicon macOS prerelease. The outer app, native host, and custody-authorizing helpers use a self-managed HRA certificate. Other HRA-owned nested executables retain pinned ad-hoc signatures, including the runtime/JIT gateway. The package is not Developer ID signed or notarized, so macOS will identify it as coming from an unknown developer. The download page explains that limitation before installation.`
      : `HRA v${HRA_RELEASE.version} is still a candidate in this source, so its direct download is disabled until its exact release evidence is published.`,
    "",
    "## Public pages",
    "",
    `- [Download for macOS](${absoluteUrl("/download")})`,
    `- [Release history](${absoluteUrl("/releases")})`,
    `- [Compare HRA](${absoluteUrl("/alternatives")})`,
    `- [Agent guide](${absoluteUrl(HRA_LLMS_TXT_PATH)})`,
    `- [XML sitemap](${absoluteUrl("/sitemap.xml")})`,
    `- [Privacy](${absoluteUrl(HRA_PRIVACY_PATH)})`,
    `- [Security contact](${absoluteUrl(HRA_SECURITY_TXT_PATH)})`,
    "- [HRA v0 source](https://github.com/hraness/hra-v0)",
    `- [Current HRA](${CURRENT_HRA_SITE})`,
    "",
  ].join("\n");
}

export function createDownloadMarkdown(): string {
  const published = HRA_RELEASE_URL !== null
    && HRA_RELEASE_CHECKSUM_URL !== null
    && HRA_RELEASE_MANIFEST_URL !== null;
  const statusLines = published
    ? [
        `Download the DMG: ${HRA_RELEASE_URL}`,
        `SHA-256 file: ${HRA_RELEASE_CHECKSUM_URL}`,
        `Release manifest: ${HRA_RELEASE_MANIFEST_URL}`,
        "",
        "Unknown developer. The outer app, native host, and custody-authorizing helpers use HRA's self-managed certificate chain. Other HRA-owned nested executables retain pinned ad-hoc signatures, including the exact runtime/JIT gateway. Neither signing boundary is Developer ID signed or notarized by Apple. The published SHA-256 verifies the exact release bytes; macOS will still ask you to approve the app manually.",
        "",
        "## Install the prerelease",
        "",
        `1. Download both files. Save the DMG and its SHA-256 file in the same folder.`,
        `2. Check the bytes. In Terminal, run \`shasum -a 256 -c ${HRA_RELEASE.asset}.sha256\`. Continue only when it prints \`OK\`.`,
        "3. Copy HRA to Applications. Open the DMG and drag HRA into the Applications folder.",
        "4. Approve the unknown developer. Control-click HRA in Finder and choose Open. If macOS still blocks it, use System Settings → Privacy & Security → Open Anyway.",
      ]
    : [
        "Candidate verification in progress. Do not install an unpublished draft asset.",
        "",
        "Unknown developer. The outer app, native host, and custody-authorizing helpers use HRA's self-managed certificate chain. Other HRA-owned nested executables retain pinned ad-hoc signatures, including the exact runtime/JIT gateway. Neither signing boundary is Developer ID signed or notarized by Apple. Its release commit, tag, manifest, and artifact hashes are still awaiting publication.",
        "",
        `HRA ${HRA_RELEASE.version} (${HRA_RELEASE.build}) is a checked source candidate. Do not drag a second app beside an installed OPRTE predecessor, and do not install an unpublished draft asset.`,
        "",
        `You can inspect or build the candidate from ${HRA_RELEASE.repository} while release evidence is completed.`,
      ];

  return [
    "# Download HRA v0 for your Mac.",
    "",
    published
      ? `This archived v${HRA_RELEASE.version} prerelease bundles HRA v0, Codex, and Git for Apple Silicon Macs running macOS ${HRA_RELEASE.minimumMacOS} or newer. New users should start with ${CURRENT_HRA_SITE}.`
      : `HRA v${HRA_RELEASE.version} is the checked forward-recovery candidate for the archived product. Its direct download remains disabled while publication evidence is completed. New users should start with ${CURRENT_HRA_SITE}.`,
    "",
    `Version ${HRA_RELEASE.version} (${HRA_RELEASE.build}) · Apple Silicon · macOS ${HRA_RELEASE.minimumMacOS}+ · ${published ? "Published prerelease" : "Candidate"} · Self-managed CMS · pinned ad-hoc nested code · not notarized.`,
    "",
    ...statusLines,
    "",
    "HRA can run coding agents with local filesystem and process authority. Pair only repositories and Codex accounts you intend it to use.",
    "",
    "## Build it yourself",
    "",
    "The public repository pins Bun, Zig, Codex, Git, native build inputs, and the package verifier. Build the same app locally if the self-managed release-signing boundary is not right for you: https://github.com/hraness/hra-v0#develop-hra",
    "",
    `HRA v0 is archived and will not gain a new update channel. The current HRA continues separately at ${CURRENT_HRA_SITE}.`,
    "",
    "## Public pages",
    "",
    `- [HRA v0 archive](${absoluteUrl("/")})`,
    `- [Release history](${absoluteUrl("/releases")})`,
    `- [Current HRA](${CURRENT_HRA_SITE})`,
    `- [Agent guide](${absoluteUrl(HRA_LLMS_TXT_PATH)})`,
    `- [XML sitemap](${absoluteUrl("/sitemap.xml")})`,
    `- [Privacy](${absoluteUrl(HRA_PRIVACY_PATH)})`,
    `- [Security contact](${absoluteUrl(HRA_SECURITY_TXT_PATH)})`,
    "",
  ].join("\n");
}

export function createReleaseHistoryMarkdown(): string {
  const entries = HRA_RELEASE_HISTORY.tags.toReversed().flatMap((entry) => {
    const identity = [
      `## ${entry.tag} (build ${entry.build})`,
      "",
      `- Tag object: annotated [\`${entry.tagObject}\`](${hraTagObjectUrl(entry)})`,
      `- Peeled commit: [\`${entry.commit}\`](${hraCommitUrl(entry)})`,
    ];
    if (entry.release === null) {
      return [
        ...identity,
        "- Publication: tag only; no GitHub release or downloadable assets",
        "",
        "v0.1.11 was a tagged candidate only. It is not prior installed authority.",
        "",
      ];
    }
    return [
      ...identity,
      `- Publication: [immutable GitHub prerelease #${entry.release.id}](${hraReleaseTagUrl(entry)})`,
      `- Published: ${entry.release.publishedAt}`,
      "",
      "### Assets",
      "",
      ...entry.release.assets.map((asset) =>
        `- [${asset.name}](${hraReleaseAssetUrl(entry, asset)}); ${asset.bytes} bytes; SHA-256 \`${asset.sha256}\``),
      "",
    ];
  });
  return [
    "# HRA v0 release history",
    "",
    "This generation-1 compatibility ledger records every HRA v0 tag from v0.1.7 through v0.1.15, every GitHub release that exists, and all 56 attached assets. v0.1.15 is the final archived prerelease.",
    "",
    ...entries,
    "## Public pages",
    "",
    `- [HRA v0 archive](${absoluteUrl("/")})`,
    `- [Download for macOS](${absoluteUrl("/download")})`,
    `- [Agent guide](${absoluteUrl(HRA_LLMS_TXT_PATH)})`,
    `- [Deployment identity](${absoluteUrl(HRA_DEPLOYMENT_IDENTITY_PATH)})`,
    `- [Privacy](${absoluteUrl(HRA_PRIVACY_PATH)})`,
    `- [Security contact](${absoluteUrl(HRA_SECURITY_TXT_PATH)})`,
    "",
  ].join("\n");
}

export function createPrivacyMarkdown(): string {
  return [
    "# Privacy at the HRA v0 archive",
    "",
    `Last updated ${HRA_PRIVACY_LAST_UPDATED}.`,
    "",
    "The archive separates public browsing, signed-in coordination data, and local Mac authority. This notice describes what each boundary can process and where the archived product has no universal retention promise.",
    "",
    "## Public browsing stays narrow",
    "",
    "On the exact Production archive origin, HRA v0 can send a cookieless, personless PostHog pageview from `/`, `/download`, `/alternatives`, and the exact published comparison pages. The event contains the canonical route, page kind, archive site ID, and comparison slug when applicable. It excludes query text, URL fragments, referrers, account and task data, commands, provider sessions, and custom events.",
    "",
    "The analytics client uses memory-only persistence, creates no person profile, disables autocapture, replay, surveys, feature flags, exception capture, and performance capture, and respects the browser's Do Not Track setting. This privacy page, the release ledger, machine-readable files, and every signed-in route are outside the analytics allowlist.",
    "",
    "Vercel serves the archive and may process operational request data under its [privacy notice](https://vercel.com/legal/privacy-notice). PostHog processes allowed pageview requests under its [privacy policy](https://posthog.com/privacy). HRA v0 adds no advertising tracker.",
    "",
    "## Hosted data is coordination data",
    "",
    "WorkOS authenticates humans and organization membership. Convex stores the WorkOS subject, human name and email when supplied, organization and membership provider identifiers, role claims, and the authorized task graph with its related workspaces, agents, runner state, dependencies, claims, submissions, reviews, bounded display events, and human decisions. Those providers process data under the [WorkOS privacy notice](https://workos.com/legal/privacy) and [Convex privacy policy](https://www.convex.dev/legal/privacy).",
    "",
    "The service can read accepted task descriptions, comments, reasoning summaries, assistant messages, and remote question text and choices. Structural validation cannot detect every secret in ordinary prose. Do not put credentials, private keys, sensitive local data, or personal data that the work does not require into those fields.",
    "",
    "An optional Hraness suite-account link adds bounded account and entitlement status to the signed-in human. It does not identify a Codex account, agent credential, local session, runner, or repository, and it does not grant an HRA role or task capability.",
    "",
    "## Execution authority stays local",
    "",
    "Codex credentials, provider sessions, raw transcripts, raw reasoning, tool names and arguments, environment values, commands, diffs, command output, canonical filesystem paths, local repositories, worktrees, and local SQLite state remain on the paired Mac. Credential and key material uses macOS Keychain-backed custody where the feature requires it.",
    "",
    "Optional cross-device session sync sends an end-to-end encrypted summary projection rather than prompts or transcripts. The relay still stores or observes traffic timing, bounded ciphertext sizes, opaque vault, device, and session identifiers, device names and public keys, enrollment state and one-time pairing metadata, boot and heartbeat presence, membership epochs and device membership, and session lifecycle event kinds and revisions. Accepted remote answers are encrypted to a boot-scoped desktop key and deleted from the relay after acknowledgement or expiry.",
    "",
    "## Retention and choices",
    "",
    "Durable task and authorization records remain available for history, review, fencing, and recovery. Hosted data residency, backup retention, request-log retention, and incident handling depend on the deployed provider configuration. HRA v0 does not publish one fixed retention period that overrides those systems.",
    "",
    "- Use Do Not Track to suppress the optional HRA pageview on analytics-eligible public routes.",
    "- Do not use the signed-in control plane for content you do not want sent to the hosted service.",
    "- Sign out and revoke task credentials when a human or agent should no longer have access.",
    "- For a private data-access or deletion request, [ask a maintainer to establish a private contact channel](https://github.com/hraness/hra-v0/issues/new). Do not include personal data, credentials, or task content in the public issue.",
    "",
    "## Security and changes",
    "",
    `Read the archived [security policy](${HRA_SECURITY_POLICY_URL}) and [security architecture](https://github.com/hraness/hra-v0/blob/main/SECURITY_ARCHITECTURE.md). Report a vulnerability through [GitHub private vulnerability reporting](${HRA_SECURITY_CONTACT_URL}). The standard contact file is available at ${absoluteUrl(HRA_SECURITY_TXT_PATH)}.`,
    "",
    `HRA v0 is archived. Its generation-1 compatibility ledger ends at the immutable v0.1.15 prerelease. Privacy information for the current HRA belongs at ${CURRENT_HRA_SITE}.`,
    "",
    "## Public pages",
    "",
    `- [HRA v0 archive](${absoluteUrl("/")})`,
    `- [Release history](${absoluteUrl("/releases")})`,
    `- [Agent guide](${absoluteUrl(HRA_LLMS_TXT_PATH)})`,
    `- [Security contact](${absoluteUrl(HRA_SECURITY_TXT_PATH)})`,
    "",
  ].join("\n");
}

export function createAlternativesIndexMarkdown(): string {
  return [
    "# Choose the layer you actually need.",
    "",
    "Coding-agent tools now overlap. Most can run work in parallel. The useful question is whether you need a first-party Codex app, a multi-provider workspace, a remote client, or a durable metaharness around Codex.",
    "",
    `Sources last reviewed ${COMPARISON_REVIEW_LABEL}.`,
    "",
    "## Comparisons",
    "",
    ...hraComparisons.flatMap((comparison) => [
      `### [HRA vs ${comparison.shortName}](${absoluteUrl(`/alternatives/${comparison.slug}`)})`,
      "",
      comparison.meaningfulDifference,
      "",
    ]),
    "## Four different jobs hide behind “agent orchestration.”",
    "",
    "- First-party Codex: Codex app is the default answer when you want OpenAI's supported parallel Codex experience.",
    "- Multi-provider workspace: Paseo, Conductor, Superset, OpenCode, and OpenChamber offer broader agent or provider surfaces.",
    "- Remote control: Happy Coder is centered on reaching coding sessions from a phone or browser.",
    "- Codex metaharness: HRA goes narrower and deeper on authorized account custody, durable delegation, continuity, and recovery around Codex.",
    "",
    "Positive claims link to current first-party documentation where possible. “Not documented” means only that we did not find the feature in the reviewed official sources. It is not proof that a product lacks it. HRA is an independent project and is not affiliated with any compared product.",
    "",
    "## Public pages",
    "",
    `- [HRA home](${absoluteUrl("/")})`,
    `- [Download for macOS](${absoluteUrl("/download")})`,
    `- [Release history](${absoluteUrl("/releases")})`,
    `- [Agent guide](${absoluteUrl(HRA_LLMS_TXT_PATH)})`,
    `- [XML sitemap](${absoluteUrl("/sitemap.xml")})`,
    `- [Privacy](${absoluteUrl(HRA_PRIVACY_PATH)})`,
    `- [Security contact](${absoluteUrl(HRA_SECURITY_TXT_PATH)})`,
    "",
  ].join("\n");
}

export function createComparisonMarkdown(comparison: HraComparison): string {
  const rows = comparison.rows.flatMap((row) => [
    `### ${row.label}`,
    "",
    `- HRA: ${row.hra}${citationMarks(comparison, row.hraSourceIds)}`,
    `- ${comparison.shortName}: ${row.alternative}${citationMarks(comparison, row.alternativeSourceIds)}`,
    "",
  ]);
  const sources = comparison.sources.map((source, index) =>
    `${index + 1}. [${source.label}](${source.url})`);
  const related = hraComparisons
    .filter((candidate) => candidate.slug !== comparison.slug)
    .slice(0, 3)
    .map((candidate) =>
      `- [HRA vs ${candidate.shortName}](${absoluteUrl(`/alternatives/${candidate.slug}`)})`);

  return [
    `# HRA v0 vs ${comparison.shortName}`,
    "",
    `Last verified ${COMPARISON_REVIEW_LABEL}.`,
    "",
    `${comparison.commonGround}${citationMarks(comparison, [
      ...comparison.hraSummarySourceIds,
      ...comparison.alternativeSummarySourceIds,
    ])}`,
    "",
    "## Short answer",
    "",
    `### Choose ${comparison.shortName}`,
    "",
    `${comparison.alternativeFit}${citationMarks(comparison, comparison.alternativeSummarySourceIds)}`,
    "",
    "### Choose HRA",
    "",
    `${comparison.hraFit}${citationMarks(comparison, comparison.hraSummarySourceIds)}`,
    "",
    "## The meaningful difference",
    "",
    `${comparison.meaningfulDifference}${citationMarks(comparison, [
      ...comparison.hraSummarySourceIds,
      ...comparison.alternativeSummarySourceIds,
    ])}`,
    "",
    "## The decisions that matter",
    "",
    ...rows,
    "## Current HRA limitations",
    "",
    "- HRA's native host currently supports Apple Silicon Macs only.",
    "- The downloadable app uses self-managed CMS and pinned ad-hoc nested-code signatures, including the runtime/JIT gateway. It is not Developer ID signed or notarized.",
    "- The recursive harness is experimental, and the adaptive optimizer cannot activate policy.",
    "- HRA is Codex-only; it is the wrong choice when provider breadth is the requirement.",
    "- Multiple accounts must be owned or authorized by you and permitted to access the same work.",
    "",
    "## Current first-party sources",
    "",
    ...sources,
    "",
    `“Not documented” means only that a capability was not found in these sources on ${COMPARISON_REVIEW_LABEL}. It does not prove the product lacks it. HRA is independent and unaffiliated with ${comparison.name}. Report a correction: https://github.com/hraness/hra-v0/issues`,
    "",
    "## More comparisons",
    "",
    ...related,
    "",
    `- [All HRA comparisons](${absoluteUrl("/alternatives")})`,
    `- [Agent guide](${absoluteUrl(HRA_LLMS_TXT_PATH)})`,
    `- [XML sitemap](${absoluteUrl("/sitemap.xml")})`,
    `- [Privacy](${absoluteUrl(HRA_PRIVACY_PATH)})`,
    `- [Security contact](${absoluteUrl(HRA_SECURITY_TXT_PATH)})`,
    "",
  ].join("\n");
}

export function createNotFoundMarkdown(): string {
  return [
    "# Not found",
    "",
    "The requested HRA page does not exist or is no longer available.",
    "",
    "## Where to look next",
    "",
    `- [HRA home](${absoluteUrl("/")})`,
    `- [Download for macOS](${absoluteUrl("/download")})`,
    `- [Release history](${absoluteUrl("/releases")})`,
    `- [Comparisons](${absoluteUrl("/alternatives")})`,
    `- [Privacy](${absoluteUrl(HRA_PRIVACY_PATH)})`,
    `- [Agent guide](${absoluteUrl(HRA_LLMS_TXT_PATH)})`,
    `- [XML sitemap](${absoluteUrl("/sitemap.xml")})`,
    "",
  ].join("\n");
}

export function publicDocumentMarkdown(pathname: string): string | null {
  const canonicalPath = canonicalPublicPath(pathname);
  if (canonicalPath === null) return null;
  if (canonicalPath === "/") return createLandingMarkdown();
  if (canonicalPath === "/download") return createDownloadMarkdown();
  if (canonicalPath === "/releases") return createReleaseHistoryMarkdown();
  if (canonicalPath === HRA_PRIVACY_PATH) return createPrivacyMarkdown();
  if (canonicalPath === "/alternatives") return createAlternativesIndexMarkdown();
  if (canonicalPath.startsWith("/alternatives/")) {
    const comparison = comparisonForSlug(canonicalPath.slice("/alternatives/".length));
    return comparison === undefined ? null : createComparisonMarkdown(comparison);
  }
  return null;
}

export type PublicDiscoveryDecision =
  | {
    readonly action: "markdown";
    readonly body: string;
    readonly contentType: typeof MARKDOWN_CONTENT_TYPE;
    readonly status: 200 | 404;
  }
  | {
    readonly action: "not_acceptable";
  }
  | {
    readonly action: "html";
  }
  | {
    readonly action: "passthrough";
  };

export function isNextInternalNavigation(headers: Headers): boolean {
  return headers.has("rsc")
    || headers.has("next-router-state-tree")
    || headers.has("next-router-prefetch")
    || headers.has("next-router-segment-prefetch")
    || headers.has("next-url");
}

export function resolvePublicDiscovery(input: {
  readonly accept: string | null;
  readonly method: string;
  readonly nextInternalNavigation: boolean;
  readonly pathname: string;
}): PublicDiscoveryDecision {
  const method = input.method.toUpperCase();
  if (method !== "GET" && method !== "HEAD") return { action: "passthrough" };
  if (input.nextInternalNavigation) return { action: "passthrough" };

  const canonicalPath = canonicalPublicPath(input.pathname);
  if (canonicalPath === null) return { action: "passthrough" };
  if (isAuthProtectedTree(canonicalPath)) return { action: "passthrough" };
  if (isAgentDiscoveryPath(canonicalPath) || pathLooksLikeStaticAsset(canonicalPath)) {
    return { action: "passthrough" };
  }

  const preferred = preferredPublicDocumentType(input.accept);
  const document = publicDocumentMarkdown(canonicalPath);

  if (document !== null) {
    if (preferred === MARKDOWN_MEDIA_TYPE) {
      return {
        action: "markdown",
        body: document,
        contentType: MARKDOWN_CONTENT_TYPE,
        status: 200,
      };
    }
    if (preferred === null) return { action: "not_acceptable" };
    return { action: "html" };
  }

  if (preferred === MARKDOWN_MEDIA_TYPE) {
    return {
      action: "markdown",
      body: createNotFoundMarkdown(),
      contentType: MARKDOWN_CONTENT_TYPE,
      status: 404,
    };
  }
  return { action: "passthrough" };
}

export { HTML_MEDIA_TYPE, MARKDOWN_CONTENT_TYPE, MARKDOWN_MEDIA_TYPE };
