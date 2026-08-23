import { z } from "@hra-internal/schema";
import {
  LARGE_SOCIAL_IMAGE,
  absoluteWebUrl,
  type SearchSite,
} from "@hraness/web-discovery";
import type { Metadata } from "next";

import releaseDownload from "../../../release-download.json";

const publishedArtifactSchema = z.object({
  bytes: z.number().int().positive().safe(),
  name: z.string().min(1),
  sha256: z.string().regex(/^[0-9a-f]{64}$/u),
}).strict();
const commonReleaseShape = {
  architecture: z.literal("Apple Silicon"),
  build: z.number().int().positive().safe(),
  minimumMacOS: z.string().regex(/^[1-9][0-9]*(?:\.[0-9]+)?$/u),
  tag: z.string().regex(/^v[0-9]+\.[0-9]+\.[0-9]+$/u),
  version: z.string().regex(/^[0-9]+\.[0-9]+\.[0-9]+$/u),
} as const;
const releaseDownloadSchema = z.object({
  release: z.object({
    ...commonReleaseShape,
    artifacts: z.object({
      checksum: publishedArtifactSchema,
      dmg: publishedArtifactSchema,
      manifest: publishedArtifactSchema,
    }).strict(),
    availability: z.literal("published"),
    source: z.object({
      commit: z.string().regex(/^[0-9a-f]{40}$/u),
      runtimeTreeSha256: z.string().regex(/^[0-9a-f]{64}$/u),
      tagObject: z.string().regex(/^[0-9a-f]{40}$/u),
    }).strict(),
  }).strict(),
  repository: z.literal("https://github.com/hraness/hra-v0"),
  schemaVersion: z.literal(1),
}).strict().superRefine((contract, context) => {
  const { release } = contract;
  const dmg = `HRA-${release.version}-${release.build}-macos-arm64.dmg`;
  if (
    release.tag !== `v${release.version}`
    || release.artifacts.dmg.name !== dmg
    || release.artifacts.checksum.name !== `${dmg}.sha256`
    || release.artifacts.manifest.name
      !== `HRA-${release.version}-${release.build}-release-manifest.json`
  ) {
    context.addIssue({
      code: "custom",
      message: "Release tag and artifact names must derive from version and build.",
    });
  }
});

export const HRA_BRAND_EMOJI = "🐦‍🔥" as const;
export const HRA_BRAND_ICON_PATH = "/icon.png" as const;
export const HRA_V0_REPOSITORY =
  "https://github.com/hraness/hra-v0" as const;
export const HRA_V0_HISTORICAL_PUBLICATION_REPOSITORY =
  "https://github.com/hraness/hra" as const;
export const CURRENT_HRA_REPOSITORY =
  "https://github.com/hraness/hra" as const;
export const CURRENT_HRA_SITE = "https://hra.sh" as const;
export const HRA_V0_ARCHIVE_ORIGIN =
  "https://hra-weld.vercel.app" as const;
export const HRA_PRIVACY_PATH = "/privacy" as const;
export const HRA_PRIVACY_LAST_UPDATED = "August 23, 2026" as const;
export const HRA_SECURITY_TXT_PATH = "/.well-known/security.txt" as const;
export const HRA_SECURITY_CONTACT_URL =
  `${HRA_V0_REPOSITORY}/security/advisories/new` as const;
export const HRA_SECURITY_POLICY_URL =
  `${HRA_V0_REPOSITORY}/security/policy` as const;
export const HRA_SECURITY_TXT_EXPIRES_AT =
  "2027-08-22T23:59:59Z" as const;

export function createHraSecurityTxt(): string {
  return [
    `Contact: ${HRA_SECURITY_CONTACT_URL}`,
    `Expires: ${HRA_SECURITY_TXT_EXPIRES_AT}`,
    `Canonical: ${HRA_V0_ARCHIVE_ORIGIN}${HRA_SECURITY_TXT_PATH}`,
    `Policy: ${HRA_SECURITY_POLICY_URL}`,
    "Preferred-Languages: en",
    "",
  ].join("\n");
}

const releaseContract = releaseDownloadSchema.parse(releaseDownload);
export const HRA_RELEASE = Object.freeze({
  architecture: releaseContract.release.architecture,
  asset: releaseContract.release.artifacts.dmg.name,
  availability: releaseContract.release.availability,
  build: releaseContract.release.build,
  checksumAsset: releaseContract.release.artifacts.checksum.name,
  manifestAsset: releaseContract.release.artifacts.manifest.name,
  minimumMacOS: releaseContract.release.minimumMacOS,
  historicalPublicationRepository: HRA_V0_HISTORICAL_PUBLICATION_REPOSITORY,
  repository: releaseContract.repository,
  sha256: releaseContract.release.artifacts.dmg.sha256,
  source: releaseContract.release.source,
  tag: releaseContract.release.tag,
  version: releaseContract.release.version,
});
export const HRA_RELEASE_URL =
  `${HRA_RELEASE.repository}/releases/download/${HRA_RELEASE.tag}/${HRA_RELEASE.asset}`;
export const HRA_RELEASE_CHECKSUM_URL =
  `${HRA_RELEASE.repository}/releases/download/${HRA_RELEASE.tag}/${HRA_RELEASE.checksumAsset}`;
export const HRA_RELEASE_MANIFEST_URL =
  `${HRA_RELEASE.repository}/releases/download/${HRA_RELEASE.tag}/${HRA_RELEASE.manifestAsset}`;

export const hraSearchSite = {
  description:
    "The archived HRA v0 metaharness for Codex, preserved with its final macOS prerelease and public source.",
  applicationName: "HRA v0",
  category: "DeveloperApplication",
  creator: "Hraness",
  name: "HRA v0",
  origin: HRA_V0_ARCHIVE_ORIGIN,
  publisher: "Hraness",
  socialImage: {
    alt: "HRA v0: the archived Codex metaharness",
    path: "/opengraph-image",
  },
  title: "HRA v0: archived Codex metaharness",
  titleTemplate: "%s · HRA v0",
} as const satisfies SearchSite;

const rootSocialImage = {
  alt: hraSearchSite.socialImage.alt,
  height: LARGE_SOCIAL_IMAGE.height,
  url: absoluteWebUrl(hraSearchSite.origin, hraSearchSite.socialImage.path),
  width: LARGE_SOCIAL_IMAGE.width,
} as const;

export const hraHomepageKeywords = [
  "Codex metaharness",
  "multiple Codex accounts",
  "Codex orchestration",
  "coding agents",
  "parallel agents",
  "human in the loop",
  "AI task orchestration",
  "local-first developer tools",
] as const;

export const hraRootMetadata = {
  applicationName: hraSearchSite.applicationName,
  category: hraSearchSite.category,
  creator: hraSearchSite.creator,
  metadataBase: new URL(hraSearchSite.origin),
  openGraph: {
    images: [rootSocialImage],
    locale: "en_US",
    siteName: hraSearchSite.name,
    type: "website",
  },
  publisher: hraSearchSite.publisher,
  title: {
    default: hraSearchSite.applicationName,
    template: hraSearchSite.titleTemplate,
  },
  twitter: {
    card: "summary_large_image",
    images: [{ alt: rootSocialImage.alt, url: rootSocialImage.url }],
  },
} as const satisfies Metadata;

export function hraSocialPageTitle(pageTitle: string): string {
  return hraSearchSite.titleTemplate.replaceAll("%s", pageTitle);
}
