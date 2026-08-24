import {
  custodyProbeSupervisorPackageContract,
} from "../../macos-package-config";
import {
  productionReleaseAuthorityPins,
  productionReleaseSigning,
  releaseDesignatedRequirement,
} from "../../release-signing-authority";
import type {
  CustodyProbeSupervisorAuthorityEvidence,
} from "../../custody-probe-supervisor-authority";

export const testCustodyProbeSupervisorAuthority = Object.freeze({
  architecture: "arm64",
  cdHash: "7".repeat(40),
  codeDirectoryFlags: Object.freeze(["runtime"] as const),
  designatedRequirement: releaseDesignatedRequirement(
    custodyProbeSupervisorPackageContract.identifier,
    {
      leafSha1: productionReleaseAuthorityPins.leafSha1,
      rootSha1: productionReleaseAuthorityPins.rootSha1,
    },
  ),
  entitlements: Object.freeze({}),
  identifier: custodyProbeSupervisorPackageContract.identifier,
  pageSize: 16_384,
  runtimeRelativePath:
    custodyProbeSupervisorPackageContract.runtimeRelativePath,
  sha256: "8".repeat(64),
  signing: productionReleaseSigning,
  timestamp: null,
} satisfies CustodyProbeSupervisorAuthorityEvidence);
