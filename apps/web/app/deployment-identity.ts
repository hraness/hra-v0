import { HRA_RELEASE_HISTORY } from "./release-history";

const finalHistoryEntry = HRA_RELEASE_HISTORY.tags.at(-1);
if (
  finalHistoryEntry === undefined
  || finalHistoryEntry.release === null
  || HRA_RELEASE_HISTORY.generation !== 2
  || HRA_RELEASE_HISTORY.publicationCommit !== "67e89e7909a56f5bfad1e16bb73801c9cd41503e"
  || finalHistoryEntry.tag !== "v0.1.16"
  || finalHistoryEntry.version !== "0.1.16"
  || finalHistoryEntry.build !== 17
  || finalHistoryEntry.commit !== "2947402efe6363bf3bb41aef55c70a2823580c68"
  || finalHistoryEntry.tagObject !== "188d8638b8d0cdf7ccaa73e2a0b07a2814f3782a"
  || finalHistoryEntry.release.id !== 377_567_675
) {
  throw new Error("The generation-2 deployment identity differs from frozen v0.1.16 history.");
}
const finalDmg = finalHistoryEntry.release.assets.find(({ name }) =>
  name === "HRA-0.1.16-17-macos-arm64.dmg"
);
if (
  finalDmg === undefined
  || finalDmg.sha256 !== "89ca90a73c29f3fef8a6b0dd349464a42f30f9c9b279951de3eff7b7186833cd"
) {
  throw new Error("The generation-2 deployment identity differs from frozen v0.1.16 DMG evidence.");
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
