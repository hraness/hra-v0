import { HRA_RELEASE_HISTORY } from "./release-history";
import { HRA_RELEASE } from "./site";

const finalHistoryEntry = HRA_RELEASE_HISTORY.tags.at(-1);
if (
  finalHistoryEntry === undefined
  || finalHistoryEntry.release === null
  || finalHistoryEntry.tag !== HRA_RELEASE.tag
  || finalHistoryEntry.build !== HRA_RELEASE.build
  || finalHistoryEntry.commit !== HRA_RELEASE.source.commit
  || finalHistoryEntry.tagObject !== HRA_RELEASE.source.tagObject
) {
  throw new Error("The archive deployment identity differs from the final release history.");
}
const finalDmg = finalHistoryEntry.release.assets.find(({ name }) =>
  name === HRA_RELEASE.asset
);
if (finalDmg === undefined || finalDmg.sha256 !== HRA_RELEASE.sha256) {
  throw new Error("The archive deployment identity differs from the final DMG evidence.");
}

export const HRA_DEPLOYMENT_IDENTITY_PATH = "/.well-known/hra.json" as const;
const providerSourceCommit = process.env.VERCEL_GIT_COMMIT_SHA;
if (
  process.env.VERCEL === "1"
  && (providerSourceCommit === undefined || !/^[0-9a-f]{40}$/u.test(providerSourceCommit))
) {
  throw new Error("The archive deployment requires an exact source commit marker.");
}
const deploymentSourceCommit = providerSourceCommit ?? "local";
if (deploymentSourceCommit !== "local" && !/^[0-9a-f]{40}$/u.test(deploymentSourceCommit)) {
  throw new Error("The archive deployment source commit marker is invalid.");
}
export const HRA_DEPLOYMENT_IDENTITY = Object.freeze({
  generation: HRA_RELEASE_HISTORY.generation,
  product: "HRA",
  publication: Object.freeze({
    build: finalHistoryEntry.build,
    dmgSha256: finalDmg.sha256,
    publicationCommit: HRA_RELEASE_HISTORY.publicationCommit,
    releaseId: finalHistoryEntry.release.id,
    sourceCommit: finalHistoryEntry.commit,
    tag: finalHistoryEntry.tag,
    tagObject: finalHistoryEntry.tagObject,
    version: finalHistoryEntry.version,
  }),
  repository: Object.freeze({
    id: HRA_RELEASE_HISTORY.repositoryId,
    path: "hraness/hra-v0",
  }),
  schemaVersion: 2,
  source: Object.freeze({
    commit: deploymentSourceCommit,
  }),
});
