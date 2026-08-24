import {
  lstat,
  mkdtemp,
  realpath,
  rm,
} from "node:fs/promises";
import { tmpdir } from "node:os";
import { isAbsolute, join, resolve } from "node:path";

/** The repository that owns the maintained HRA v0 archive surface. */
export const HRA_V0_CURRENT_REPOSITORY =
  "https://github.com/hraness/hra-v0" as const;

/**
 * The repository spelling recorded in the immutable v0.1.14 publication
 * contract. It is historical evidence, not the maintained source location.
 */
export const HRA_HISTORICAL_PUBLICATION_REPOSITORY =
  "https://github.com/hraness/hra" as const;

/** Canonical repository recorded by the maintained archive contract. */
export const HRA_CANONICAL_REPOSITORY =
  HRA_V0_CURRENT_REPOSITORY;

/** Final reviewed HRA v0.1.14 archive/privacy/security surface (Q14). */
export const HRA_V0_Q14_SURFACE_COMMIT =
  "ceb647f7a4a68546fc68ce5e70e770b73c8863eb" as const;

const fullObjectIdPattern = /^[0-9a-f]{40}$/u;
const archiveHistoryCommitLimit = 1_024;
const releaseContractByteLimit = 32_768;
const productionRepositoryRoot = resolve(import.meta.dir, "../../..");
const canonicalGitRepository = `${HRA_V0_CURRENT_REPOSITORY}.git` as const;
const hermeticGitEnvironment = Object.freeze({
  GIT_CONFIG_COUNT: "0",
  GIT_CONFIG_GLOBAL: "/dev/null",
  GIT_CONFIG_NOSYSTEM: "1",
  GIT_NO_REPLACE_OBJECTS: "1",
  GIT_OPTIONAL_LOCKS: "0",
  GIT_TERMINAL_PROMPT: "0",
  LANG: "C",
  LC_ALL: "C",
  PATH: "/usr/bin:/bin",
});

export interface ReleaseRepositoryEvidence {
  readonly commit: string;
  readonly gitDirectory: string;
  readonly repository: typeof HRA_V0_CURRENT_REPOSITORY;
  readonly repositoryRoot: string;
  readonly status: "clean_canonical_source";
  readonly tree: string;
}

export interface ReleaseTagEvidence {
  readonly commit: string;
  readonly object: string;
  readonly objectType: "tag";
  readonly tag: string;
}

export interface ReleasePublicationEvidence {
  readonly candidateCommit: string;
  readonly candidateContract: string;
  readonly changedPath: "release-download.json";
  readonly publicationCommit: string;
  readonly publicationContract: string;
  readonly status: "exact_candidate_publication_transition";
}

export interface ReleaseCandidateLineageEvidence {
  readonly candidateCommit: string;
  readonly parentCommit: string;
  readonly status: "exact_q14_candidate_child";
}

export interface CanonicalReleasePublicationEvidence {
  readonly publication: ReleasePublicationEvidence;
  readonly tag: ReleaseTagEvidence;
}

export interface ArchiveReleaseSurfaceEvidence {
  readonly publicationCommit: string;
  readonly repositoryMigrationCommit: string;
  readonly status: "verified_descendant_archive_surface";
  readonly surfaceCommit: string;
}

export interface CanonicalArchiveReleaseEvidence
  extends CanonicalReleasePublicationEvidence {
  readonly surface: ArchiveReleaseSurfaceEvidence;
}

type ReleaseGitRunner = Readonly<{
  run: (args: readonly string[]) => Promise<string>;
  runAllowNoMatch: (args: readonly string[]) => Promise<string>;
}>;

type InspectRepositoryOptions = Readonly<{
  environment?: Readonly<Record<string, string | undefined>>;
  repositoryRoot?: string;
}>;

/**
 * Verify the source checkout used for release work. The operational entry point
 * supplies no repository or commit arguments; tests may inject an isolated
 * repository to exercise the same fail-closed boundary.
 */
export async function inspectReleaseSourceRepository(
  options: InspectRepositoryOptions = {},
): Promise<ReleaseRepositoryEvidence> {
  rejectAmbientGitSteering(options.environment ?? process.env);
  const repositoryRoot = await requireCanonicalDirectory(
    options.repositoryRoot ?? productionRepositoryRoot,
    "Release repository root",
  );
  const gitDirectory = join(repositoryRoot, ".git");
  await requireRealDirectory(gitDirectory, "Release Git directory");
  await Promise.all([
    requireRealDirectory(join(gitDirectory, "objects"), "Git object directory"),
    requireRealDirectory(join(gitDirectory, "refs"), "Git refs directory"),
    requireRegularFile(join(gitDirectory, "HEAD"), "Git HEAD"),
    requireRegularFile(join(gitDirectory, "config"), "Git local config"),
    requireRegularFile(join(gitDirectory, "index"), "Git index"),
  ]);
  await rejectForbiddenGitMetadata(gitDirectory);

  const runner = releaseGitRunner(repositoryRoot, gitDirectory);
  const [
    reportedRoot,
    reportedGitDirectory,
    localIncludes,
    worktreeConfiguration,
    replacementRefs,
  ] =
    await Promise.all([
      runner.run(["rev-parse", "--show-toplevel"]),
      runner.run(["rev-parse", "--absolute-git-dir"]),
      runner.runAllowNoMatch([
        "config",
        "--local",
        "--get-regexp",
        "^(include\\.path|includeif\\..*\\.path|extensions\\.partialclone|remote\\..*\\.promisor)$",
      ]),
      runner.runAllowNoMatch([
        "config",
        "--local",
        "--get-regexp",
        "^extensions\\.worktreeconfig$",
      ]),
      runner.run(["for-each-ref", "--format=%(refname)", "refs/replace"]),
    ]);
  if (await canonicalOutputPath(reportedRoot) !== repositoryRoot) {
    throw new Error("Git reported a different repository top-level.");
  }
  if (await canonicalOutputPath(reportedGitDirectory) !== gitDirectory) {
    throw new Error("Git reported a different metadata directory.");
  }
  if (worktreeConfiguration.trim().length > 0) {
    throw new Error("Release provenance refuses active Git worktree configuration.");
  }
  if (localIncludes.trim().length > 0) {
    throw new Error("Release Git config may not include configuration from another path.");
  }
  if (replacementRefs.trim().length > 0) {
    throw new Error("Release provenance refuses Git replacement refs.");
  }

  const [gitlinks, fileFlags, status, commit, tree] = await Promise.all([
    runner.run(["ls-files", "--stage"]),
    runner.run(["ls-files", "-v"]),
    runner.run([
      "status",
      "--porcelain=v2",
      "--untracked-files=all",
      "--ignore-submodules=none",
    ]),
    runner.run(["rev-parse", "--verify", "HEAD^{commit}"]),
    runner.run(["rev-parse", "--verify", "HEAD^{tree}"]),
  ]);
  const hasGitlink = gitlinks.split("\n").some((line) => line.startsWith("160000 "));
  if (hasGitlink || await pathExists(join(repositoryRoot, ".gitmodules"))) {
    throw new Error(
      "Release source may not contain Git submodules; submodule presence or drift is rejected.",
    );
  }
  if (fileFlags.split("\n").some((line) => line.length > 0 && !line.startsWith("H "))) {
    throw new Error(
      "Release provenance refuses assume-unchanged, skip-worktree, or unresolved index entries.",
    );
  }
  if (status.trim().length > 0) {
    throw new Error("Release provenance requires a clean source tree.");
  }
  const normalizedCommit = requireObjectId(commit, "Git HEAD commit");
  const normalizedTree = requireObjectId(tree, "Git HEAD tree");
  return Object.freeze({
    commit: normalizedCommit,
    gitDirectory,
    repository: HRA_V0_CURRENT_REPOSITORY,
    repositoryRoot,
    status: "clean_canonical_source",
    tree: normalizedTree,
  });
}

export async function inspectReleaseTag(
  repository: ReleaseRepositoryEvidence,
  tag: string,
): Promise<ReleaseTagEvidence | null> {
  const runner = releaseGitRunner(
    repository.repositoryRoot,
    repository.gitDirectory,
  );
  return await inspectReleaseTagWithRunner(runner, tag);
}

/**
 * Find the unique C15 commit on the path from Q14 to HEAD. HEAD may be C15 or
 * a later descendant; packaging still requires a standalone C15 checkout.
 */
export async function resolveReleaseCandidateCommit(
  repository: ReleaseRepositoryEvidence,
  options: Readonly<{
    expectedParentCommit?: string;
  }> = {},
): Promise<string> {
  const expectedParentCommit = requireObjectId(
    options.expectedParentCommit ?? HRA_V0_Q14_SURFACE_COMMIT,
    "HRA v0.1.15 Q14 parent commit",
  );
  const runner = releaseGitRunner(
    repository.repositoryRoot,
    repository.gitDirectory,
  );
  let mergeBase: string;
  try {
    mergeBase = requireObjectId(
      await runner.run(["merge-base", expectedParentCommit, repository.commit]),
      "HRA v0.1.15 Q14 merge base",
    );
  } catch {
    throw new Error(
      "The HRA v0.1.15 candidate must have exact Q14 as its only direct parent.",
    );
  }
  if (mergeBase !== expectedParentCommit) {
    throw new Error(
      "The HRA v0.1.15 candidate must have exact Q14 as its only direct parent.",
    );
  }
  const historyOutput = (await runner.run([
    "rev-list",
    "--parents",
    "--ancestry-path",
    `${expectedParentCommit}..${repository.commit}`,
  ])).trim();
  const q14Children: string[] = [];
  for (const line of historyOutput.length === 0 ? [] : historyOutput.split("\n")) {
    const objectIds = line.trim().split(/\s+/u);
    const commit = objectIds[0] ?? "";
    const parents = objectIds.slice(1);
    if (parents.length === 1 && parents[0] === expectedParentCommit) {
      q14Children.push(requireObjectId(commit, "HRA v0.1.15 candidate commit"));
    }
  }
  if (q14Children.length !== 1) {
    throw new Error(
      "The HRA v0.1.15 candidate must have exact Q14 as its only direct parent.",
    );
  }
  return q14Children[0] ?? "";
}

/**
 * Bind C15 to the final reviewed Q14 archive surface. The optional expected
 * parent is a focused-test seam; production callers always use the pinned Q14
 * object above.
 */
export async function inspectReleaseCandidateLineage(
  repository: ReleaseRepositoryEvidence,
  options: Readonly<{
    candidateCommit?: string;
    expectedParentCommit?: string;
  }> = {},
): Promise<ReleaseCandidateLineageEvidence> {
  const candidateCommit = requireObjectId(
    options.candidateCommit ?? repository.commit,
    "HRA v0.1.15 candidate commit",
  );
  const expectedParentCommit = requireObjectId(
    options.expectedParentCommit ?? HRA_V0_Q14_SURFACE_COMMIT,
    "HRA v0.1.15 Q14 parent commit",
  );
  const runner = releaseGitRunner(
    repository.repositoryRoot,
    repository.gitDirectory,
  );
  return await inspectReleaseCandidateLineageWithRunner(
    runner,
    candidateCommit,
    expectedParentCommit,
  );
}

async function inspectReleaseCandidateLineageWithRunner(
  runner: ReleaseGitRunner,
  candidateCommit: string,
  expectedParentCommit: string,
): Promise<ReleaseCandidateLineageEvidence> {
  const ancestry = (await runner.run([
    "rev-list",
    "--parents",
    "-n",
    "1",
    candidateCommit,
  ])).trim().split(/\s+/u);
  if (
    ancestry.length !== 2
    || ancestry[0] !== candidateCommit
    || ancestry[1] !== expectedParentCommit
  ) {
    throw new Error(
      "The HRA v0.1.15 candidate must have exact Q14 as its only direct parent.",
    );
  }
  return Object.freeze({
    candidateCommit,
    parentCommit: expectedParentCommit,
    status: "exact_q14_candidate_child",
  });
}

async function inspectReleaseTagWithRunner(
  runner: ReleaseGitRunner,
  tag: string,
): Promise<ReleaseTagEvidence | null> {
  if (!/^v[0-9]+\.[0-9]+\.[0-9]+$/u.test(tag)) {
    throw new Error("Release tag is invalid.");
  }
  const tagRef = `refs/tags/${tag}`;
  const ref = await runner.run([
    "for-each-ref",
    "--format=%(objectname)",
    tagRef,
  ]);
  if (ref.trim().length === 0) return null;
  const [objectType, objectBody, commit] = await Promise.all([
    runner.run(["cat-file", "-t", tagRef]),
    runner.run(["cat-file", "-p", tagRef]),
    runner.run(["rev-parse", "--verify", `${tagRef}^{commit}`]),
  ]);
  if (objectType.trim() !== "tag") {
    throw new Error("A release tag must be one annotated tag object.");
  }
  const directTargetMatch = /^object ([0-9a-f]{40})\n/u.exec(objectBody);
  if (directTargetMatch === null) {
    throw new Error("The annotated release tag has no canonical direct target.");
  }
  const directTarget = requireObjectId(
    directTargetMatch[1] ?? "",
    "Release tag direct target",
  );
  const directTargetType = await runner.run(["cat-file", "-t", directTarget]);
  const peeledCommit = requireObjectId(commit, "Release tag commit");
  if (directTargetType.trim() !== "commit" || directTarget !== peeledCommit) {
    throw new Error(
      "The annotated release tag must point directly to the candidate commit.",
    );
  }
  return Object.freeze({
    commit: peeledCommit,
    object: requireObjectId(ref, "Release tag object"),
    objectType: "tag",
    tag,
  });
}

/**
 * Publication is a separate commit because a source commit cannot contain its
 * own object ID. The clean publication checkout must be the sole child of the
 * tagged candidate and may change exactly release-download.json.
 */
export async function inspectReleasePublicationTransition(
  repository: ReleaseRepositoryEvidence,
  candidateCommitValue: string,
): Promise<ReleasePublicationEvidence> {
  const candidateCommit = requireObjectId(
    candidateCommitValue,
    "Published candidate commit",
  );
  if (candidateCommit === repository.commit) {
    throw new Error(
      "The publication commit must be distinct from the tagged candidate commit.",
    );
  }
  const runner = releaseGitRunner(
    repository.repositoryRoot,
    repository.gitDirectory,
  );
  return await inspectReleasePublicationWithRunner(
    runner,
    candidateCommit,
    repository.commit,
  );
}

/**
 * Verify the immutable C-to-P transition at an explicit historical commit.
 * The maintained archive checkout may be a later descendant, so P must not be
 * inferred from its HEAD.
 */
export async function inspectReleasePublicationAtCommit(
  repository: ReleaseRepositoryEvidence,
  candidateCommitValue: string,
  publicationCommitValue: string,
): Promise<ReleasePublicationEvidence> {
  const candidateCommit = requireObjectId(
    candidateCommitValue,
    "Published candidate commit",
  );
  const publicationCommit = requireObjectId(
    publicationCommitValue,
    "Published publication commit",
  );
  const runner = releaseGitRunner(
    repository.repositoryRoot,
    repository.gitDirectory,
  );
  return await inspectReleasePublicationWithRunner(
    runner,
    candidateCommit,
    publicationCommit,
  );
}

/**
 * Bind a maintained archive surface to the immutable publication while
 * allowing exactly one reviewed repository-coordinate migration. Every other
 * byte of release-download.json remains fixed at P.
 */
export async function inspectArchiveReleaseSurface(
  repository: ReleaseRepositoryEvidence,
  publicationCommitValue: string,
): Promise<ArchiveReleaseSurfaceEvidence> {
  const publicationCommit = requireObjectId(
    publicationCommitValue,
    "Published publication commit",
  );
  const runner = releaseGitRunner(
    repository.repositoryRoot,
    repository.gitDirectory,
  );
  return await inspectArchiveReleaseSurfaceWithRunner(
    runner,
    publicationCommit,
    repository.commit,
  );
}

async function inspectArchiveReleaseSurfaceWithRunner(
  runner: ReleaseGitRunner,
  publicationCommit: string,
  surfaceCommit: string,
): Promise<ArchiveReleaseSurfaceEvidence> {
  if (publicationCommit === surfaceCommit) {
    throw new Error(
      "The HRA v0 archive surface must descend from the publication commit.",
    );
  }
  const mergeBase = requireObjectId(
    await runner.run(["merge-base", publicationCommit, surfaceCommit]),
    "Archive publication merge base",
  );
  if (mergeBase !== publicationCommit) {
    throw new Error(
      "The HRA v0 archive surface must descend from the publication commit.",
    );
  }
  const [publicationContract, surfaceContract] = await Promise.all([
    runner.run(["show", `${publicationCommit}:release-download.json`]),
    runner.run(["show", `${surfaceCommit}:release-download.json`]),
  ]);
  const historicalCoordinate =
    `"repository": "${HRA_HISTORICAL_PUBLICATION_REPOSITORY}"`;
  const currentCoordinate =
    `"repository": "${HRA_V0_CURRENT_REPOSITORY}"`;
  if (
    publicationContract.split(historicalCoordinate).length !== 2
    || publicationContract.includes(currentCoordinate)
  ) {
    throw new Error(
      "The immutable publication must contain exactly one historical repository coordinate.",
    );
  }
  const expectedSurfaceContract = publicationContract.replace(
    historicalCoordinate,
    currentCoordinate,
  );
  if (surfaceContract !== expectedSurfaceContract) {
    throw new Error(
      "The HRA v0 archive surface may change only the reviewed release repository coordinate.",
    );
  }
  for (const [label, value] of [
    ["publication", publicationContract],
    ["surface", surfaceContract],
  ] as const) {
    if (new TextEncoder().encode(value).byteLength > releaseContractByteLimit) {
      throw new Error(`The archive ${label} release contract is oversized.`);
    }
  }

  // Do not add a pathspec here. Git history simplification may hide a rewrite
  // followed by a restore on a merged side branch. The bounded, unpruned DAG
  // is the evidence: every commit and every direct parent visible from P..S
  // must carry exactly historical H or archive A bytes.
  const historyOutput = (await runner.run([
    "rev-list",
    "--full-history",
    "--topo-order",
    "--parents",
    `--max-count=${String(archiveHistoryCommitLimit + 1)}`,
    `${publicationCommit}..${surfaceCommit}`,
  ])).trim();
  const historyLines = historyOutput.length === 0
    ? []
    : historyOutput.split("\n");
  if (historyLines.length > archiveHistoryCommitLimit) {
    throw new Error(
      `The HRA v0 archive history exceeds ${String(archiveHistoryCommitLimit)} commits.`,
    );
  }
  if (historyLines.length === 0) {
    throw new Error(
      "The HRA v0 archive history contains no descendant commits.",
    );
  }

  const history = historyLines.map((line, index) => {
    const objectIds = line.trim().split(/\s+/u);
    const commit = requireObjectId(
      objectIds[0] ?? "",
      `Archive history commit ${String(index)}`,
    );
    const parents = objectIds.slice(1).map((value, parentIndex) =>
      requireObjectId(
        value,
        `Archive history commit ${String(index)} parent ${String(parentIndex)}`,
      )
    );
    if (parents.length === 0) {
      throw new Error("Every HRA v0 archive commit must have a direct parent.");
    }
    return Object.freeze({ commit, parents });
  });
  if (new Set(history.map(({ commit }) => commit)).size !== history.length) {
    throw new Error("The HRA v0 archive history contains a duplicate commit.");
  }

  type ArchiveContractState = "archive" | "historical";
  const contracts = new Map<string, string>([
    [publicationCommit, publicationContract],
    [surfaceCommit, surfaceContract],
  ]);
  const relevantCommits = new Set<string>([publicationCommit]);
  for (const { commit, parents } of history) {
    relevantCommits.add(commit);
    for (const parent of parents) relevantCommits.add(parent);
  }
  for (const commit of relevantCommits) {
    if (contracts.has(commit)) continue;
    contracts.set(
      commit,
      await readBoundedReleaseContractAtCommit(runner, commit),
    );
  }
  const states = new Map<string, ArchiveContractState>();
  for (const [commit, contract] of contracts) {
    const state = contract === publicationContract
      ? "historical"
      : contract === expectedSurfaceContract
        ? "archive"
        : null;
    if (state === null) {
      throw new Error(
        `Every HRA v0 archive commit and parent must preserve exact historical H or archive A release contract bytes; ${commit} does not.`,
      );
    }
    states.set(commit, state);
  }

  const frontierCommits: string[] = [];
  for (const { commit, parents } of history) {
    const state = states.get(commit);
    if (state === undefined) {
      throw new Error("Archive release contract state is incomplete.");
    }
    const parentStates = parents.map((parent) => {
      const parentState = states.get(parent);
      if (parentState === undefined) {
        throw new Error("Archive parent release contract state is incomplete.");
      }
      return parentState;
    });
    if (
      state === "historical"
      && parentStates.some((parentState) => parentState === "archive")
    ) {
      throw new Error(
        "The HRA v0 archive history may not contain an archive A to historical H edge.",
      );
    }
    if (
      state === "archive"
      && !parentStates.some((parentState) => parentState === "archive")
    ) {
      if (parents.length !== 1 || parentStates[0] !== "historical") {
        throw new Error(
          "A merge commit may not invent archive A without an archive A parent.",
        );
      }
      frontierCommits.push(commit);
    }
  }
  if (frontierCommits.length !== 1) {
    throw new Error(
      "The HRA v0 archive history must contain exactly one single-parent historical H to archive A frontier.",
    );
  }
  const repositoryMigrationCommit = requireObjectId(
    frontierCommits[0] ?? "",
    "Archive repository migration commit",
  );
  const migrationParent = history.find(
    ({ commit }) => commit === repositoryMigrationCommit,
  )?.parents[0];
  if (migrationParent === undefined) {
    throw new Error("The archive repository migration parent is missing.");
  }
  const migrationChangedPath = await runner.run([
    "diff-tree",
    "--no-commit-id",
    "--name-status",
    "-r",
    "-z",
    "--no-renames",
    migrationParent,
    repositoryMigrationCommit,
    "--",
    "release-download.json",
  ]);
  if (
    contracts.get(migrationParent) !== publicationContract
    || contracts.get(repositoryMigrationCommit) !== expectedSurfaceContract
    || migrationChangedPath !== "M\0release-download.json\0"
  ) {
    throw new Error(
      "The reviewed release repository migration must be the exact historical-to-archive coordinate change.",
    );
  }
  return Object.freeze({
    publicationCommit,
    repositoryMigrationCommit,
    status: "verified_descendant_archive_surface",
    surfaceCommit,
  });
}

async function readBoundedReleaseContractAtCommit(
  runner: ReleaseGitRunner,
  commit: string,
): Promise<string> {
  const object = `${commit}:release-download.json`;
  const sizeText = (await runner.run(["cat-file", "-s", object])).trim();
  if (!/^(?:0|[1-9][0-9]*)$/u.test(sizeText)) {
    throw new Error("Git reported an invalid archive release contract size.");
  }
  const size = Number(sizeText);
  if (
    !Number.isSafeInteger(size)
    || size <= 0
    || size > releaseContractByteLimit
  ) {
    throw new Error("An archive release contract is empty or oversized.");
  }
  const contract = await runner.run(["cat-file", "-p", object]);
  if (new TextEncoder().encode(contract).byteLength !== size) {
    throw new Error("Git emitted inconsistent archive release contract bytes.");
  }
  return contract;
}

async function inspectReleasePublicationWithRunner(
  runner: ReleaseGitRunner,
  candidateCommit: string,
  publicationCommit: string,
): Promise<ReleasePublicationEvidence> {
  const parents = (await runner.run([
    "rev-list",
    "--parents",
    "-n",
    "1",
    publicationCommit,
  ])).trim().split(/\s+/u);
  if (
    parents.length !== 2
    || parents[0] !== publicationCommit
    || parents[1] !== candidateCommit
  ) {
    throw new Error(
      "The publication commit must have the tagged candidate as its only direct parent.",
    );
  }
  const changed = await runner.run([
    "diff-tree",
    "--no-commit-id",
    "--name-status",
    "-r",
    "-z",
    "--no-renames",
    candidateCommit,
    publicationCommit,
  ]);
  if (changed !== "M\0release-download.json\0") {
    throw new Error(
      "The publication transition may modify only release-download.json.",
    );
  }
  const [candidateContract, publicationContract] = await Promise.all([
    runner.run(["show", `${candidateCommit}:release-download.json`]),
    runner.run(["show", `${publicationCommit}:release-download.json`]),
  ]);
  for (const [label, value] of [
    ["candidate", candidateContract],
    ["publication", publicationContract],
  ] as const) {
    if (new TextEncoder().encode(value).byteLength > 32_768) {
      throw new Error(`The ${label} release contract is oversized.`);
    }
  }
  return Object.freeze({
    candidateCommit,
    candidateContract,
    changedPath: "release-download.json",
    publicationCommit,
    publicationContract,
    status: "exact_candidate_publication_transition",
  });
}

/**
 * Verify the release objects in an isolated normal or bare Git object store.
 * This core is intentionally independent of checkout depth and worktree state;
 * callers must bind publicationCommit to their trusted provider identity.
 */
export async function inspectReleasePublicationObjectStore(options: Readonly<{
  candidateCommit: string;
  gitDirectory: string;
  publicationCommit: string;
  tag: string;
}>): Promise<CanonicalReleasePublicationEvidence> {
  const candidateCommit = requireObjectId(
    options.candidateCommit,
    "Published candidate commit",
  );
  const publicationCommit = requireObjectId(
    options.publicationCommit,
    "Provider publication commit",
  );
  if (candidateCommit === publicationCommit) {
    throw new Error(
      "The publication commit must be distinct from the tagged candidate commit.",
    );
  }
  const gitDirectory = await requireCanonicalDirectory(
    options.gitDirectory,
    "Fetched release Git directory",
  );
  await Promise.all([
    requireRealDirectory(join(gitDirectory, "objects"), "Fetched Git object directory"),
    requireRealDirectory(join(gitDirectory, "refs"), "Fetched Git refs directory"),
    requireRegularFile(join(gitDirectory, "HEAD"), "Fetched Git HEAD"),
    requireRegularFile(join(gitDirectory, "config"), "Fetched Git config"),
  ]);
  const runner = releaseGitObjectRunner(gitDirectory);
  const [publication, tag] = await Promise.all([
    inspectReleasePublicationWithRunner(
      runner,
      candidateCommit,
      publicationCommit,
    ),
    inspectReleaseTagWithRunner(runner, options.tag),
  ]);
  if (tag === null) {
    throw new Error("The canonical release repository has no annotated release tag.");
  }
  return Object.freeze({ publication, tag });
}

/**
 * Fetch only the exact provider commit, its parent, and the release tag from
 * the fixed public HRA repository. Vercel's ambient shallow checkout is never
 * trusted or inspected.
 */
export async function inspectCanonicalReleasePublication(options: Readonly<{
  candidateCommit: string;
  publicationCommit: string;
  tag: string;
}>): Promise<CanonicalReleasePublicationEvidence> {
  const candidateCommit = requireObjectId(
    options.candidateCommit,
    "Published candidate commit",
  );
  const publicationCommit = requireObjectId(
    options.publicationCommit,
    "Provider publication commit",
  );
  if (!/^v[0-9]+\.[0-9]+\.[0-9]+$/u.test(options.tag)) {
    throw new Error("Release tag is invalid.");
  }
  const temporaryRoot = await realpath(
    await mkdtemp(join(tmpdir(), "hra-release-fetch-")),
  );
  const gitDirectory = join(temporaryRoot, "publication.git");
  try {
    await runHermeticGit(
      ["init", "--bare", "--initial-branch=main", gitDirectory],
      temporaryRoot,
    );
    const runner = releaseGitObjectRunner(gitDirectory);
    await runner.run(["remote", "add", "canonical", canonicalGitRepository]);
    await runner.run([
      "fetch",
      "--quiet",
      "--force",
      "--no-tags",
      "--depth=3",
      "--filter=blob:limit=32768",
      "canonical",
      publicationCommit,
    ]);
    const tagRef = `refs/tags/${options.tag}`;
    await runner.run([
      "fetch",
      "--quiet",
      "--force",
      "--no-tags",
      "--depth=2",
      "--filter=blob:limit=32768",
      "canonical",
      `${tagRef}:${tagRef}`,
    ]);
    const evidence = await inspectReleasePublicationObjectStore({
      candidateCommit,
      gitDirectory,
      publicationCommit,
      tag: options.tag,
    });
    await inspectReleaseCandidateLineageWithRunner(
      runner,
      candidateCommit,
      HRA_V0_Q14_SURFACE_COMMIT,
    );
    return evidence;
  } finally {
    await rm(temporaryRoot, { force: true, recursive: true });
  }
}

/**
 * Fetch and verify both immutable release history and an allowlisted archive
 * surface from the maintained HRA v0 repository. P retains the historical
 * repository spelling; the archive surface contains its one reviewed
 * coordinate migration.
 */
export async function inspectCanonicalArchiveRelease(options: Readonly<{
  candidateCommit: string;
  publicationCommit: string;
  surfaceCommit: string;
  tag: string;
}>): Promise<CanonicalArchiveReleaseEvidence> {
  const candidateCommit = requireObjectId(
    options.candidateCommit,
    "Published candidate commit",
  );
  const publicationCommit = requireObjectId(
    options.publicationCommit,
    "Published publication commit",
  );
  const surfaceCommit = requireObjectId(
    options.surfaceCommit,
    "Archive surface commit",
  );
  if (!/^v[0-9]+\.[0-9]+\.[0-9]+$/u.test(options.tag)) {
    throw new Error("Release tag is invalid.");
  }
  const temporaryRoot = await realpath(
    await mkdtemp(join(tmpdir(), "hra-v0-release-fetch-")),
  );
  const gitDirectory = join(temporaryRoot, "publication.git");
  try {
    await runHermeticGit(
      ["init", "--bare", "--initial-branch=main", gitDirectory],
      temporaryRoot,
    );
    const runner = releaseGitObjectRunner(gitDirectory);
    await runner.run(["remote", "add", "canonical", canonicalGitRepository]);
    await runner.run([
      "fetch",
      "--quiet",
      "--force",
      "--no-tags",
      "--depth=64",
      "--filter=blob:limit=32768",
      "canonical",
      surfaceCommit,
    ]);
    await runner.run([
      "fetch",
      "--quiet",
      "--force",
      "--no-tags",
      "--depth=2",
      "--filter=blob:limit=32768",
      "canonical",
      publicationCommit,
    ]);
    const tagRef = `refs/tags/${options.tag}`;
    await runner.run([
      "fetch",
      "--quiet",
      "--force",
      "--no-tags",
      "--depth=2",
      "--filter=blob:limit=32768",
      "canonical",
      `${tagRef}:${tagRef}`,
    ]);
    const [publication, tag, surface] = await Promise.all([
      inspectReleasePublicationWithRunner(
        runner,
        candidateCommit,
        publicationCommit,
      ),
      inspectReleaseTagWithRunner(runner, options.tag),
      inspectArchiveReleaseSurfaceWithRunner(
        runner,
        publicationCommit,
        surfaceCommit,
      ),
    ]);
    if (tag === null) {
      throw new Error(
        "The canonical HRA v0 repository has no annotated release tag.",
      );
    }
    return Object.freeze({ publication, surface, tag });
  } finally {
    await rm(temporaryRoot, { force: true, recursive: true });
  }
}

export function rejectAmbientGitSteering(
  environment: Readonly<Record<string, string | undefined>>,
): void {
  const keys = Object.keys(environment)
    .filter((key) => key.startsWith("GIT_"))
    .sort();
  if (keys.length > 0) {
    throw new Error(
      `Release provenance refuses ambient Git steering: ${keys.join(", ")}.`,
    );
  }
}

async function rejectForbiddenGitMetadata(gitDirectory: string): Promise<void> {
  // actions/checkout can leave config.worktree behind after unsetting the
  // extension that makes it influential. The local-config check above rejects
  // any activation while permitting that ignored residue.
  const forbidden = [
    [join(gitDirectory, "objects/info/alternates"), "object alternates"],
    [join(gitDirectory, "info/grafts"), "grafts"],
    [join(gitDirectory, "info/sparse-checkout"), "sparse checkout"],
    [join(gitDirectory, "shallow"), "shallow history"],
  ] as const;
  for (const [path, label] of forbidden) {
    if (await pathExists(path)) {
      throw new Error(`Release provenance refuses Git ${label}.`);
    }
  }
}

function releaseGitRunner(
  repositoryRoot: string,
  gitDirectory: string,
): ReleaseGitRunner {
  return createReleaseGitRunner(repositoryRoot, [
    "/usr/bin/git",
    `--git-dir=${gitDirectory}`,
    `--work-tree=${repositoryRoot}`,
    ...hermeticGitOptions(),
  ]);
}

function releaseGitObjectRunner(gitDirectory: string): ReleaseGitRunner {
  return createReleaseGitRunner(gitDirectory, [
    "/usr/bin/git",
    `--git-dir=${gitDirectory}`,
    ...hermeticGitOptions(),
  ]);
}

function hermeticGitOptions(): readonly string[] {
  return [
    "--no-optional-locks",
    "-c",
    "core.fsmonitor=false",
    "-c",
    "core.hooksPath=/dev/null",
    "-c",
    "credential.helper=",
    "-c",
    "protocol.file.allow=never",
  ];
}

function createReleaseGitRunner(
  cwd: string,
  prefix: readonly string[],
): ReleaseGitRunner {
  const execute = async (args: readonly string[]) => {
    const child = Bun.spawn([...prefix, ...args], {
      cwd,
      env: hermeticGitEnvironment,
      stdin: "ignore",
      stderr: "pipe",
      stdout: "pipe",
    });
    const [stdout, stderr, exitCode] = await Promise.all([
      new Response(child.stdout).text(),
      new Response(child.stderr).text(),
      child.exited,
    ]);
    return { exitCode, stderr, stdout } as const;
  };
  return Object.freeze({
    async run(args: readonly string[]): Promise<string> {
      const result = await execute(args);
      if (result.exitCode !== 0) {
        throw new Error(
          `Hermetic git ${args[0] ?? "command"} failed: ${result.stderr.trim()}`,
        );
      }
      return result.stdout;
    },
    async runAllowNoMatch(args: readonly string[]): Promise<string> {
      const result = await execute(args);
      if (result.exitCode === 1) return "";
      if (result.exitCode !== 0) {
        throw new Error(
          `Hermetic git ${args[0] ?? "command"} failed: ${result.stderr.trim()}`,
        );
      }
      return result.stdout;
    },
  });
}

async function runHermeticGit(
  args: readonly string[],
  cwd: string,
): Promise<string> {
  return await createReleaseGitRunner(
    cwd,
    ["/usr/bin/git", ...hermeticGitOptions()],
  ).run(args);
}

async function requireCanonicalDirectory(path: string, label: string): Promise<string> {
  if (!isAbsolute(path) || resolve(path) !== path) {
    throw new Error(`${label} must be an absolute normalized path.`);
  }
  const canonical = await realpath(path);
  if (canonical !== path) {
    throw new Error(`${label} must use its exact canonical spelling.`);
  }
  await requireRealDirectory(path, label);
  return path;
}

async function canonicalOutputPath(output: string): Promise<string> {
  const path = output.trim();
  if (!isAbsolute(path)) throw new Error("Git emitted a non-absolute path.");
  return realpath(path);
}

async function requireRealDirectory(path: string, label: string): Promise<void> {
  const status = await lstat(path);
  if (!status.isDirectory() || status.isSymbolicLink()) {
    throw new Error(`${label} must be a real directory.`);
  }
}

async function requireRegularFile(path: string, label: string): Promise<void> {
  const status = await lstat(path);
  if (!status.isFile() || status.isSymbolicLink()) {
    throw new Error(`${label} must be a regular file.`);
  }
}

async function pathExists(path: string): Promise<boolean> {
  try {
    await lstat(path);
    return true;
  } catch (error) {
    if (error instanceof Error && "code" in error && error.code === "ENOENT") {
      return false;
    }
    throw error;
  }
}

function requireObjectId(value: string, label: string): string {
  const normalized = value.trim();
  if (!fullObjectIdPattern.test(normalized)) {
    throw new Error(`${label} is not one full SHA-1 object ID.`);
  }
  return normalized;
}
