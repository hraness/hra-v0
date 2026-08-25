import { HRA_RELEASE_HISTORY } from "./release-history";

const finalHistoryEntry = HRA_RELEASE_HISTORY.tags.at(-1);
if (
  finalHistoryEntry === undefined
  || finalHistoryEntry.release === null
  || HRA_RELEASE_HISTORY.generation !== 1
  || HRA_RELEASE_HISTORY.publicationCommit !== "d96173c3556799cb203a4d659f29856180838029"
  || finalHistoryEntry.tag !== "v0.1.15"
  || finalHistoryEntry.version !== "0.1.15"
  || finalHistoryEntry.build !== 16
  || finalHistoryEntry.commit !== "0c7764da0dea0a71bbccca817539a02d8e4284d0"
  || finalHistoryEntry.tagObject !== "e5bcf5c919e8a7ffcdccc337b8940b60a70f0489"
  || finalHistoryEntry.release.id !== 376_100_700
) {
  throw new Error("The generation-1 deployment identity differs from frozen v0.1.15 history.");
}
const finalDmg = finalHistoryEntry.release.assets.find(({ name }) =>
  name === "HRA-0.1.15-16-macos-arm64.dmg"
);
if (
  finalDmg === undefined
  || finalDmg.sha256 !== "120b600d7cc11df260836198601cba91db33efc7b600dd2b601bde686c9ea028"
) {
  throw new Error("The generation-1 deployment identity differs from frozen v0.1.15 DMG evidence.");
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
