import { isDeepStrictEqual } from "node:util";

import { z } from "@hra-internal/schema";

import {
  custodyProbeSupervisorPackageContract,
} from "./macos-package-config";
import {
  productionReleaseAuthorityPins,
  productionReleaseSigning,
  releaseDesignatedRequirement,
} from "./release-signing-authority";

export type CustodyProbeSupervisorAuthorityEvidence = Readonly<{
  architecture: "arm64";
  cdHash: string;
  codeDirectoryFlags: readonly ["runtime"];
  designatedRequirement: string;
  entitlements: Readonly<Record<string, never>>;
  identifier: "hra-custody-probe-supervisor";
  pageSize: 16_384;
  runtimeRelativePath: "bin/hra-custody-probe-supervisor";
  sha256: string;
  signing: Readonly<Record<string, unknown>>;
  timestamp: null;
}>;

export const productionCustodyProbeSupervisorDesignatedRequirement =
  releaseDesignatedRequirement(
    custodyProbeSupervisorPackageContract.identifier,
    {
      leafSha1: productionReleaseAuthorityPins.leafSha1,
      rootSha1: productionReleaseAuthorityPins.rootSha1,
    },
  );

export const productionCustodyProbeSupervisorAuthoritySchema = z.object({
  architecture: z.literal("arm64"),
  cdHash: z.string().regex(/^[0-9a-f]{40}$/u),
  codeDirectoryFlags: z.tuple([z.literal("runtime")]),
  designatedRequirement: z.literal(
    productionCustodyProbeSupervisorDesignatedRequirement,
  ),
  entitlements: z.object({}).strict(),
  identifier: z.literal(custodyProbeSupervisorPackageContract.identifier),
  pageSize: z.literal(16_384),
  runtimeRelativePath: z.literal(
    custodyProbeSupervisorPackageContract.runtimeRelativePath,
  ),
  sha256: z.string().regex(/^[0-9a-f]{64}$/u),
  signing: z.custom<typeof productionReleaseSigning>(
    value => isDeepStrictEqual(value, productionReleaseSigning),
    "custody probe supervisor signing authority differs",
  ),
  timestamp: z.null(),
}).strict();

export function parseProductionCustodyProbeSupervisorAuthority(
  value: unknown,
): CustodyProbeSupervisorAuthorityEvidence {
  return productionCustodyProbeSupervisorAuthoritySchema.parse(value);
}
