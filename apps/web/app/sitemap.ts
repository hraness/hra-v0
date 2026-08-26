import { createSitemap } from "@hraness/web-discovery";

import { hraComparisons } from "./alternatives/comparisons";
import { HRA_PUBLIC_READING_PATHS } from "./reading";
import { hraSearchSite } from "./site";

export default function sitemap() {
  return createSitemap(hraSearchSite.origin, [
    {
      changeFrequency: "weekly",
      path: "/",
      priority: 1,
    },
    {
      changeFrequency: "weekly",
      path: "/download",
      priority: 0.8,
    },
    {
      changeFrequency: "monthly",
      path: "/releases",
      priority: 0.8,
    },
    {
      changeFrequency: "yearly",
      path: "/privacy",
      priority: 0.5,
    },
    {
      changeFrequency: "monthly",
      path: "/alternatives",
      priority: 0.8,
    },
    ...HRA_PUBLIC_READING_PATHS.map((path) => ({
      changeFrequency: "monthly" as const,
      path,
      priority: 0.6,
    })),
    ...hraComparisons.map(({ slug }) => ({
      changeFrequency: "monthly" as const,
      path: `/alternatives/${slug}` as `/${string}`,
      priority: 0.7,
    })),
  ]);
}
