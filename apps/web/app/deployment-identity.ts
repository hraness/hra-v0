import { HRA_RELEASE_HISTORY } from "./release-history";

const finalHistoryEntry = HRA_RELEASE_HISTORY.tags.at(-1);
if (
  finalHistoryEntry === undefined
  || finalHistoryEntry.release === null
  || finalHistoryEntry.tag !== "v0.1.14"
  || finalHistoryEntry.version !== "0.1.14"
  || finalHistoryEntry.build !== 15
  || finalHistoryEntry.commit !== "7b39c459827b2acf45aa2d911c94fdb5d4f37860"
  || finalHistoryEntry.tagObject !== "37ed37afb39cacfd6a51044cf7f3c1b873571aa3"
  || finalHistoryEntry.release.id !== 374_980_441
) {
  throw new Error("The generation-0 deployment identity differs from frozen v0.1.14 history.");
}
const finalDmg = finalHistoryEntry.release.assets.find(({ name }) =>
  name === "HRA-0.1.14-15-macos-arm64.dmg"
);
if (
  finalDmg === undefined
  || finalDmg.sha256 !== "7ff49500de3d1fc768c17454ef7642c51f6662dfa5bf0e2ba183a85bb67fcd03"
) {
  throw new Error("The generation-0 deployment identity differs from frozen v0.1.14 DMG evidence.");
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
