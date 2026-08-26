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

/** Original merged HRA v0.1.15 candidate whose repaired child is released. */
export const HRA_V0_C15_BASE_COMMIT =
  "a2948a21eb524e89960cfcbd7b68d7c52ab028b4" as const;

/** Reviewed public surface immediately before the repaired release candidate. */
export const HRA_V0_C15_REVIEWED_SURFACE_COMMIT =
  "fd33c4561ea161367f2c516d502f1e88d0998f29" as const;

/** Merged custody repair immediately before the reviewed host-trust repair. */
export const HRA_V0_C15_CUSTODY_REPAIR_COMMIT =
  "045ee7b4b23ea1b61392d0a782f619f2d946eeaf" as const;

/** Reviewed host-trust repair immediately before bundle-code authority. */
export const HRA_V0_C15_HOST_TRUST_COMMIT =
  "7d284b48577b5747a247cef31952de3c7f7338cd" as const;

/** Reviewed bundle-code authority immediately before the final release candidate. */
export const HRA_V0_C15_BUNDLE_CODE_AUTHORITY_COMMIT =
  "22f6f21985af4a000f51e2acf8747501fa12536c" as const;

/** Reviewed signed-release-probe repair immediately before the final release candidate. */
export const HRA_V0_C15_SIGNED_RELEASE_PROBE_REPAIR_COMMIT =
  "8b84baf7ebc80cc5e2b63365900454a7446f7479" as const;

/** Final C15 candidate tagged and released as HRA v0.1.15. */
export const HRA_V0_C15_CANDIDATE_COMMIT =
  "0c7764da0dea0a71bbccca817539a02d8e4284d0" as const;

/** Exact evidence-only P15 child of the tagged C15 candidate. */
export const HRA_V0_P15_PUBLICATION_COMMIT =
  "d96173c3556799cb203a4d659f29856180838029" as const;

/** Concurrent main child of C15 that did not alter the candidate contract. */
export const HRA_V0_P15_CONCURRENT_MAIN_COMMIT =
  "559c272f1bd7a2f1195f1af3c493b4f73a8fb3d2" as const;

/** Ordered P15/U integration merge that reconnects the immutable publication to main. */
export const HRA_V0_P15_INTEGRATION_BRIDGE_COMMIT =
  "af3296e59e2173e1e7737dee7a3194592de1105e" as const;

/** Reviewed generation-1 HRA v0.1.15 archive surface (Q15). */
export const HRA_V0_Q15_SURFACE_COMMIT =
  "443448b79e9016e00d52501f047fce3a408de092" as const;

/** Reviewed C16 Keychain ACL compatibility commit immediately before C17. */
export const HRA_V0_C16_COMPATIBILITY_COMMIT =
  "4766793434e59cfe3fb3e8bf5fe57e2a28e72aeb" as const;

/** Canonical C17 native timeout-cap correction immediately before C18. */
export const HRA_V0_C17_TIMEOUT_CAP_COMMIT =
  "112175bfdbcd6be0e3cca7ed43dd57e79453c00a" as const;

/** Canonical C18 cold-custody timeout correction immediately before C19. */
export const HRA_V0_C18_COLD_CUSTODY_TIMEOUT_COMMIT =
  "14904f1fc60b254455b7089f32e9764d67fffd95" as const;

/** Shallow depths that retain Q15 across the sequential Q16 and C19 fetches. */
export const HRA_V0_PUBLICATION_SURFACE_FETCH_DEPTHS = Object.freeze({
  surface: 7,
  tag: 5,
});

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
  readonly baseCommit: string;
  readonly bundleCodeAuthorityCommit: string;
  readonly candidateCommit: string;
  readonly custodyRepairCommit: string;
  readonly hostTrustCommit: string;
  readonly q14Commit: string;
  readonly reviewedSurfaceCommit: string;
  readonly signedReleaseProbeRepairCommit: string;
  readonly status: "exact_q14_base_c15_reviewed_surface_custody_repair_host_trust_bundle_code_authority_signed_release_probe_repair_final_candidate_chain";
}

export interface ReleaseHotfixCandidateLineageEvidence {
  readonly c16Commit: string;
  readonly c17Commit: string;
  readonly c18Commit: string;
  readonly candidateCommit: string;
  readonly q15Commit: string;
  readonly status: "exact_q15_c16_c17_c18_c19_candidate_chain";
}

/** A Q16 surface that is the sole direct child of exact publication P16. */
export interface ReleasePublicationSurfaceEvidence {
  readonly publication: ReleasePublicationEvidence;
  readonly status: "verified_linear_publication_surface";
  readonly surfaceCommit: string;
}

export interface CanonicalReleasePublicationEvidence {
  readonly publication: ReleasePublicationEvidence;
  readonly tag: ReleaseTagEvidence;
}

/** Canonical remote evidence for the linear Q15/C16/C17/C18/C19/P16/Q16 topology. */
export interface CanonicalReleasePublicationSurfaceEvidence
  extends CanonicalReleasePublicationEvidence {
  readonly surface: ReleasePublicationSurfaceEvidence;
}

/**
 * The normal mainline merge that reconnects the standalone P15 publication
 * after main advanced concurrently from C15. It is integration evidence, not
 * a second publication transition.
 */
export interface ReleasePublicationIntegrationBridgeEvidence {
  readonly concurrentMainCommit: string;
  readonly integrationBridgeCommit: string;
  readonly publication: ReleasePublicationEvidence;
  readonly status: "exact_candidate_publication_concurrent_main_integration_bridge";
}

/** A Q surface directly descended from the exact P15 integration bridge. */
export interface ReleasePublicationIntegrationSurfaceEvidence {
  readonly bridge: ReleasePublicationIntegrationBridgeEvidence;
  readonly status: "verified_publication_integration_bridge_surface";
  readonly surfaceCommit: string;
}

/**
 * Canonical remote evidence for the fixed C15/P15/U/M/Q topology. The
 * top-level publication field keeps release-contract callers aligned with the
 * pre-bridge canonical publication proof.
 */
export interface CanonicalReleasePublicationIntegrationSurfaceEvidence {
  readonly bridge: ReleasePublicationIntegrationBridgeEvidence;
  readonly publication: ReleasePublicationEvidence;
  readonly surface: ReleasePublicationIntegrationSurfaceEvidence;
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
 * Find the unique final C15 candidate on the path from the reviewed
 * signed-release-probe repair to HEAD. HEAD may be the candidate or a later
 * descendant; packaging still requires a standalone candidate checkout.
 */
export async function resolveReleaseCandidateCommit(
  repository: ReleaseRepositoryEvidence,
  options: Readonly<{
    expectedSignedReleaseProbeRepairCommit?: string;
  }> = {},
): Promise<string> {
  const expectedSignedReleaseProbeRepairCommit = requireObjectId(
    options.expectedSignedReleaseProbeRepairCommit ??
      HRA_V0_C15_SIGNED_RELEASE_PROBE_REPAIR_COMMIT,
    "HRA v0.1.15 signed-release-probe repair commit",
  );
  const runner = releaseGitRunner(
    repository.repositoryRoot,
    repository.gitDirectory,
  );
  let mergeBase: string;
  try {
    mergeBase = requireObjectId(
      await runner.run([
        "merge-base",
        expectedSignedReleaseProbeRepairCommit,
        repository.commit,
      ]),
      "HRA v0.1.15 signed-release-probe repair merge base",
    );
  } catch {
    throw new Error(
      "The final HRA v0.1.15 candidate must have exact signed-release-probe repair commit as its only direct parent.",
    );
  }
  if (mergeBase !== expectedSignedReleaseProbeRepairCommit) {
    throw new Error(
      "The final HRA v0.1.15 candidate must have exact signed-release-probe repair commit as its only direct parent.",
    );
  }
  const historyOutput = (await runner.run([
    "rev-list",
    "--parents",
    "--ancestry-path",
    `${expectedSignedReleaseProbeRepairCommit}..${repository.commit}`,
  ])).trim();
  const signedReleaseProbeRepairChildren: string[] = [];
  for (const line of historyOutput.length === 0 ? [] : historyOutput.split("\n")) {
    const objectIds = line.trim().split(/\s+/u);
    const commit = objectIds[0] ?? "";
    const parents = objectIds.slice(1);
    if (
      parents.length === 1
      && parents[0] === expectedSignedReleaseProbeRepairCommit
    ) {
      signedReleaseProbeRepairChildren.push(
        requireObjectId(commit, "HRA v0.1.15 final candidate commit"),
      );
    }
  }
  if (signedReleaseProbeRepairChildren.length !== 1) {
    throw new Error(
      "The final HRA v0.1.15 candidate must have exact signed-release-probe repair commit as its only direct parent.",
    );
  }
  return signedReleaseProbeRepairChildren[0] ?? "";
}

/**
 * Find the unique C19 candidate on the linear path from exact C18 to HEAD.
 * HEAD may be the candidate or a later CI descendant. The fixed Q15-to-C16-to-
 * C17-to-C18 chain must remain exact, and the candidate must be C18's
 * sole-parent child.
 */
export async function resolveReleaseHotfixCandidateCommit(
  repository: ReleaseRepositoryEvidence,
  options: Readonly<{
    expectedC16Commit?: string;
    expectedC17Commit?: string;
    expectedC18Commit?: string;
    expectedQ15Commit?: string;
  }> = {},
): Promise<string> {
  const expectedQ15Commit = requireObjectId(
    options.expectedQ15Commit ?? HRA_V0_Q15_SURFACE_COMMIT,
    "HRA v0.1.15 Q15 surface commit",
  );
  const expectedC16Commit = requireObjectId(
    options.expectedC16Commit ?? HRA_V0_C16_COMPATIBILITY_COMMIT,
    "HRA v0.1.16 C16 compatibility commit",
  );
  const expectedC17Commit = requireObjectId(
    options.expectedC17Commit ?? HRA_V0_C17_TIMEOUT_CAP_COMMIT,
    "HRA v0.1.16 C17 timeout-cap commit",
  );
  const expectedC18Commit = requireObjectId(
    options.expectedC18Commit ?? HRA_V0_C18_COLD_CUSTODY_TIMEOUT_COMMIT,
    "HRA v0.1.16 C18 cold-custody timeout commit",
  );
  const runner = releaseGitRunner(
    repository.repositoryRoot,
    repository.gitDirectory,
  );
  await inspectReleaseC18LineageWithRunner(
    runner,
    expectedC18Commit,
    expectedC17Commit,
    expectedC16Commit,
    expectedQ15Commit,
  );
  let mergeBase: string;
  try {
    mergeBase = requireObjectId(
      await runner.run(["merge-base", expectedC18Commit, repository.commit]),
      "HRA v0.1.16 C18 merge base",
    );
  } catch {
    throw new Error(
      "The HRA v0.1.16 C19 candidate must have exact C18 as its only direct parent.",
    );
  }
  if (mergeBase !== expectedC18Commit) {
    throw new Error(
      "The HRA v0.1.16 C19 candidate must have exact C18 as its only direct parent.",
    );
  }
  const historyOutput = (await runner.run([
    "rev-list",
    "--parents",
    "--ancestry-path",
    `${expectedC18Commit}..${repository.commit}`,
  ])).trim();
  const c18Children: string[] = [];
  for (const line of historyOutput.length === 0 ? [] : historyOutput.split("\n")) {
    const objectIds = line.trim().split(/\s+/u);
    const commit = objectIds[0] ?? "";
    const parents = objectIds.slice(1);
    if (parents.length === 1 && parents[0] === expectedC18Commit) {
      c18Children.push(
        requireObjectId(commit, "HRA v0.1.16 C19 candidate commit"),
      );
    }
  }
  if (c18Children.length !== 1) {
    throw new Error(
      "The HRA v0.1.16 C19 candidate must have exact C18 as its only direct parent.",
    );
  }
  return c18Children[0] ?? "";
}

export async function inspectReleaseHotfixCandidateLineage(
  repository: ReleaseRepositoryEvidence,
  options: Readonly<{
    candidateCommit?: string;
    expectedC16Commit?: string;
    expectedC17Commit?: string;
    expectedC18Commit?: string;
    expectedQ15Commit?: string;
  }> = {},
): Promise<ReleaseHotfixCandidateLineageEvidence> {
  const candidateCommit = requireObjectId(
    options.candidateCommit ?? repository.commit,
    "HRA v0.1.16 candidate commit",
  );
  const expectedQ15Commit = requireObjectId(
    options.expectedQ15Commit ?? HRA_V0_Q15_SURFACE_COMMIT,
    "HRA v0.1.15 Q15 surface commit",
  );
  const expectedC16Commit = requireObjectId(
    options.expectedC16Commit ?? HRA_V0_C16_COMPATIBILITY_COMMIT,
    "HRA v0.1.16 C16 compatibility commit",
  );
  const expectedC17Commit = requireObjectId(
    options.expectedC17Commit ?? HRA_V0_C17_TIMEOUT_CAP_COMMIT,
    "HRA v0.1.16 C17 timeout-cap commit",
  );
  const expectedC18Commit = requireObjectId(
    options.expectedC18Commit ?? HRA_V0_C18_COLD_CUSTODY_TIMEOUT_COMMIT,
    "HRA v0.1.16 C18 cold-custody timeout commit",
  );
  const runner = releaseGitRunner(
    repository.repositoryRoot,
    repository.gitDirectory,
  );
  return await inspectReleaseHotfixCandidateLineageWithRunner(
    runner,
    candidateCommit,
    expectedC18Commit,
    expectedC17Commit,
    expectedC16Commit,
    expectedQ15Commit,
  );
}

async function inspectReleaseC16LineageWithRunner(
  runner: ReleaseGitRunner,
  expectedC16Commit: string,
  expectedQ15Commit: string,
): Promise<void> {
  const ancestry = (await runner.run([
    "rev-list",
    "--parents",
    "-n",
    "1",
    expectedC16Commit,
  ])).trim().split(/\s+/u);
  if (
    ancestry.length !== 2
    || ancestry[0] !== expectedC16Commit
    || ancestry[1] !== expectedQ15Commit
  ) {
    throw new Error(
      "The HRA v0.1.16 C16 compatibility commit must have exact Q15 as its only direct parent.",
    );
  }
}

async function inspectReleaseC17LineageWithRunner(
  runner: ReleaseGitRunner,
  expectedC17Commit: string,
  expectedC16Commit: string,
  expectedQ15Commit: string,
): Promise<void> {
  const ancestry = (await runner.run([
    "rev-list",
    "--parents",
    "-n",
    "1",
    expectedC17Commit,
  ])).trim().split(/\s+/u);
  if (
    ancestry.length !== 2
    || ancestry[0] !== expectedC17Commit
    || ancestry[1] !== expectedC16Commit
  ) {
    throw new Error(
      "The HRA v0.1.16 C17 timeout-cap commit must have exact C16 as its only direct parent.",
    );
  }
  await inspectReleaseC16LineageWithRunner(
    runner,
    expectedC16Commit,
    expectedQ15Commit,
  );
}

async function inspectReleaseC18LineageWithRunner(
  runner: ReleaseGitRunner,
  expectedC18Commit: string,
  expectedC17Commit: string,
  expectedC16Commit: string,
  expectedQ15Commit: string,
): Promise<void> {
  const ancestry = (await runner.run([
    "rev-list",
    "--parents",
    "-n",
    "1",
    expectedC18Commit,
  ])).trim().split(/\s+/u);
  if (
    ancestry.length !== 2
    || ancestry[0] !== expectedC18Commit
    || ancestry[1] !== expectedC17Commit
  ) {
    throw new Error(
      "The HRA v0.1.16 C18 cold-custody timeout commit must have exact C17 as its only direct parent.",
    );
  }
  await inspectReleaseC17LineageWithRunner(
    runner,
    expectedC17Commit,
    expectedC16Commit,
    expectedQ15Commit,
  );
}

async function inspectReleaseHotfixCandidateLineageWithRunner(
  runner: ReleaseGitRunner,
  candidateCommit: string,
  expectedC18Commit: string,
  expectedC17Commit: string,
  expectedC16Commit: string,
  expectedQ15Commit: string,
): Promise<ReleaseHotfixCandidateLineageEvidence> {
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
    || ancestry[1] !== expectedC18Commit
  ) {
    throw new Error(
      "The HRA v0.1.16 C19 candidate must have exact C18 as its only direct parent.",
    );
  }
  await inspectReleaseC18LineageWithRunner(
    runner,
    expectedC18Commit,
    expectedC17Commit,
    expectedC16Commit,
    expectedQ15Commit,
  );
  return Object.freeze({
    c16Commit: expectedC16Commit,
    c17Commit: expectedC17Commit,
    c18Commit: expectedC18Commit,
    candidateCommit,
    q15Commit: expectedQ15Commit,
    status: "exact_q15_c16_c17_c18_c19_candidate_chain",
  });
}

/**
 * Bind final C15 to the reviewed signed-release-probe repair,
 * bundle-code authority, host-trust repair, merged custody repair, reviewed
 * public surface, original merged C15 base, and final reviewed Q14 archive
 * surface. Optional expected objects are focused-test seams; production
 * callers use the pinned objects above.
 */
export async function inspectReleaseCandidateLineage(
  repository: ReleaseRepositoryEvidence,
  options: Readonly<{
    candidateCommit?: string;
    expectedBaseCommit?: string;
    expectedBundleCodeAuthorityCommit?: string;
    expectedCustodyRepairCommit?: string;
    expectedHostTrustCommit?: string;
    expectedQ14Commit?: string;
    expectedSignedReleaseProbeRepairCommit?: string;
    expectedSurfaceCommit?: string;
  }> = {},
): Promise<ReleaseCandidateLineageEvidence> {
  const candidateCommit = requireObjectId(
    options.candidateCommit ?? repository.commit,
    "HRA v0.1.15 candidate commit",
  );
  const expectedBundleCodeAuthorityCommit = requireObjectId(
    options.expectedBundleCodeAuthorityCommit ??
      HRA_V0_C15_BUNDLE_CODE_AUTHORITY_COMMIT,
    "HRA v0.1.15 bundle-code-authority commit",
  );
  const expectedSignedReleaseProbeRepairCommit = requireObjectId(
    options.expectedSignedReleaseProbeRepairCommit ??
      HRA_V0_C15_SIGNED_RELEASE_PROBE_REPAIR_COMMIT,
    "HRA v0.1.15 signed-release-probe repair commit",
  );
  const expectedCustodyRepairCommit = requireObjectId(
    options.expectedCustodyRepairCommit ?? HRA_V0_C15_CUSTODY_REPAIR_COMMIT,
    "HRA v0.1.15 custody repair commit",
  );
  const expectedHostTrustCommit = requireObjectId(
    options.expectedHostTrustCommit ?? HRA_V0_C15_HOST_TRUST_COMMIT,
    "HRA v0.1.15 host-trust commit",
  );
  const expectedSurfaceCommit = requireObjectId(
    options.expectedSurfaceCommit ?? HRA_V0_C15_REVIEWED_SURFACE_COMMIT,
    "HRA v0.1.15 reviewed public surface commit",
  );
  const expectedBaseCommit = requireObjectId(
    options.expectedBaseCommit ?? HRA_V0_C15_BASE_COMMIT,
    "HRA v0.1.15 base commit",
  );
  const expectedQ14Commit = requireObjectId(
    options.expectedQ14Commit ?? HRA_V0_Q14_SURFACE_COMMIT,
    "HRA v0.1.15 Q14 commit",
  );
  const runner = releaseGitRunner(
    repository.repositoryRoot,
    repository.gitDirectory,
  );
  return await inspectReleaseCandidateLineageWithRunner(
    runner,
    candidateCommit,
    expectedSignedReleaseProbeRepairCommit,
    expectedBundleCodeAuthorityCommit,
    expectedHostTrustCommit,
    expectedCustodyRepairCommit,
    expectedSurfaceCommit,
    expectedBaseCommit,
    expectedQ14Commit,
  );
}

async function inspectReleaseCandidateLineageWithRunner(
  runner: ReleaseGitRunner,
  candidateCommit: string,
  expectedSignedReleaseProbeRepairCommit: string,
  expectedBundleCodeAuthorityCommit: string,
  expectedHostTrustCommit: string,
  expectedCustodyRepairCommit: string,
  expectedSurfaceCommit: string,
  expectedBaseCommit: string,
  expectedQ14Commit: string,
): Promise<ReleaseCandidateLineageEvidence> {
  const candidateAncestry = (await runner.run([
    "rev-list",
    "--parents",
    "-n",
    "1",
    candidateCommit,
  ])).trim().split(/\s+/u);
  if (
    candidateAncestry.length !== 2
    || candidateAncestry[0] !== candidateCommit
    || candidateAncestry[1] !== expectedSignedReleaseProbeRepairCommit
  ) {
    throw new Error(
      "The final HRA v0.1.15 candidate must have exact signed-release-probe repair commit as its only direct parent.",
    );
  }
  const signedReleaseProbeRepairAncestry = (await runner.run([
    "rev-list",
    "--parents",
    "-n",
    "1",
    expectedSignedReleaseProbeRepairCommit,
  ])).trim().split(/\s+/u);
  if (
    signedReleaseProbeRepairAncestry.length !== 2
    || signedReleaseProbeRepairAncestry[0] !== expectedSignedReleaseProbeRepairCommit
    || signedReleaseProbeRepairAncestry[1] !== expectedBundleCodeAuthorityCommit
  ) {
    throw new Error(
      "The HRA v0.1.15 signed-release-probe repair must have exact bundle-code-authority commit as its only direct parent.",
    );
  }
  const bundleCodeAuthorityAncestry = (await runner.run([
    "rev-list",
    "--parents",
    "-n",
    "1",
    expectedBundleCodeAuthorityCommit,
  ])).trim().split(/\s+/u);
  if (
    bundleCodeAuthorityAncestry.length !== 2
    || bundleCodeAuthorityAncestry[0] !== expectedBundleCodeAuthorityCommit
    || bundleCodeAuthorityAncestry[1] !== expectedHostTrustCommit
  ) {
    throw new Error(
      "The HRA v0.1.15 bundle-code-authority commit must have exact host-trust repair as its only direct parent.",
    );
  }
  const hostTrustAncestry = (await runner.run([
    "rev-list",
    "--parents",
    "-n",
    "1",
    expectedHostTrustCommit,
  ])).trim().split(/\s+/u);
  if (
    hostTrustAncestry.length !== 2
    || hostTrustAncestry[0] !== expectedHostTrustCommit
    || hostTrustAncestry[1] !== expectedCustodyRepairCommit
  ) {
    throw new Error(
      "The HRA v0.1.15 host-trust commit must have exact custody repair as its only direct parent.",
    );
  }
  const custodyRepairAncestry = (await runner.run([
    "rev-list",
    "--parents",
    "-n",
    "1",
    expectedCustodyRepairCommit,
  ])).trim().split(/\s+/u);
  if (
    custodyRepairAncestry.length !== 2
    || custodyRepairAncestry[0] !== expectedCustodyRepairCommit
    || custodyRepairAncestry[1] !== expectedSurfaceCommit
  ) {
    throw new Error(
      "The HRA v0.1.15 custody repair must have exact reviewed public surface as its only direct parent.",
    );
  }
  const surfaceAncestry = (await runner.run([
    "rev-list",
    "--parents",
    "-n",
    "1",
    expectedSurfaceCommit,
  ])).trim().split(/\s+/u);
  if (
    surfaceAncestry.length !== 2
    || surfaceAncestry[0] !== expectedSurfaceCommit
    || surfaceAncestry[1] !== expectedBaseCommit
  ) {
    throw new Error(
      "The reviewed HRA v0.1.15 public surface must have exact base C15 as its only direct parent.",
    );
  }
  const baseAncestry = (await runner.run([
    "rev-list",
    "--parents",
    "-n",
    "1",
    expectedBaseCommit,
  ])).trim().split(/\s+/u);
  if (
    baseAncestry.length !== 2
    || baseAncestry[0] !== expectedBaseCommit
    || baseAncestry[1] !== expectedQ14Commit
  ) {
    throw new Error(
      "The HRA v0.1.15 base commit must have exact Q14 as its only direct parent.",
    );
  }
  return Object.freeze({
    baseCommit: expectedBaseCommit,
    bundleCodeAuthorityCommit: expectedBundleCodeAuthorityCommit,
    candidateCommit,
    custodyRepairCommit: expectedCustodyRepairCommit,
    hostTrustCommit: expectedHostTrustCommit,
    q14Commit: expectedQ14Commit,
    reviewedSurfaceCommit: expectedSurfaceCommit,
    signedReleaseProbeRepairCommit: expectedSignedReleaseProbeRepairCommit,
    status: "exact_q14_base_c15_reviewed_surface_custody_repair_host_trust_bundle_code_authority_signed_release_probe_repair_final_candidate_chain",
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
 * Verify the linear P16-to-Q16 surface. Q16 must be P16's sole direct child
 * and must preserve the published release-download contract byte for byte.
 */
export async function inspectReleasePublicationSurface(
  repository: ReleaseRepositoryEvidence,
  options: Readonly<{
    candidateCommit: string;
    publicationCommit: string;
    surfaceCommit?: string;
  }>,
): Promise<ReleasePublicationSurfaceEvidence> {
  const candidateCommit = requireObjectId(
    options.candidateCommit,
    "Published candidate commit",
  );
  const publicationCommit = requireObjectId(
    options.publicationCommit,
    "Published publication commit",
  );
  const surfaceCommit = requireObjectId(
    options.surfaceCommit ?? repository.commit,
    "Publication surface commit",
  );
  const runner = releaseGitRunner(
    repository.repositoryRoot,
    repository.gitDirectory,
  );
  return await inspectReleasePublicationSurfaceWithRunner(
    runner,
    candidateCommit,
    publicationCommit,
    surfaceCommit,
  );
}

async function inspectReleasePublicationSurfaceWithRunner(
  runner: ReleaseGitRunner,
  candidateCommit: string,
  publicationCommit: string,
  surfaceCommit: string,
): Promise<ReleasePublicationSurfaceEvidence> {
  const publication = await inspectReleasePublicationWithRunner(
    runner,
    candidateCommit,
    publicationCommit,
  );
  const surfaceAncestry = (await runner.run([
    "rev-list",
    "--parents",
    "-n",
    "1",
    surfaceCommit,
  ])).trim().split(/\s+/u);
  if (
    surfaceAncestry.length !== 2
    || surfaceAncestry[0] !== surfaceCommit
    || surfaceAncestry[1] !== publicationCommit
  ) {
    throw new Error(
      "The v0.1.16 publication surface must have P16 as its only direct parent.",
    );
  }
  const surfaceContract = await readBoundedReleaseContractAtCommit(
    runner,
    surfaceCommit,
  );
  if (surfaceContract !== publication.publicationContract) {
    throw new Error(
      "The v0.1.16 publication surface must preserve the P16 release contract exactly.",
    );
  }
  return Object.freeze({
    publication,
    status: "verified_linear_publication_surface",
    surfaceCommit,
  });
}

/**
 * Verify the fixed C-to-P evidence commit and the later normal integration
 * merge. U is an independently authored main child of C and must retain C's
 * release contract; M must merge P before U and retain P's exact contract.
 * M is deliberately not accepted as a publication commit.
 */
export async function inspectReleasePublicationIntegrationBridge(
  repository: ReleaseRepositoryEvidence,
  options: Readonly<{
    candidateCommit: string;
    concurrentMainCommit: string;
    integrationBridgeCommit: string;
    publicationCommit: string;
  }>,
): Promise<ReleasePublicationIntegrationBridgeEvidence> {
  const candidateCommit = requireObjectId(
    options.candidateCommit,
    "Published candidate commit",
  );
  const publicationCommit = requireObjectId(
    options.publicationCommit,
    "Published publication commit",
  );
  const concurrentMainCommit = requireObjectId(
    options.concurrentMainCommit,
    "Concurrent main commit",
  );
  const integrationBridgeCommit = requireObjectId(
    options.integrationBridgeCommit,
    "Publication integration bridge commit",
  );
  const runner = releaseGitRunner(
    repository.repositoryRoot,
    repository.gitDirectory,
  );
  return await inspectReleasePublicationIntegrationBridgeWithRunner(
    runner,
    candidateCommit,
    publicationCommit,
    concurrentMainCommit,
    integrationBridgeCommit,
  );
}

/**
 * Verify a Q archive surface after the P15 integration bridge. The surface
 * is intentionally restricted to one direct M parent and cannot rewrite the
 * P15 release contract while it adds the archive surface.
 */
export async function inspectReleasePublicationIntegrationSurface(
  repository: ReleaseRepositoryEvidence,
  options: Readonly<{
    candidateCommit: string;
    concurrentMainCommit: string;
    integrationBridgeCommit: string;
    publicationCommit: string;
    surfaceCommit?: string;
  }>,
): Promise<ReleasePublicationIntegrationSurfaceEvidence> {
  const candidateCommit = requireObjectId(
    options.candidateCommit,
    "Published candidate commit",
  );
  const publicationCommit = requireObjectId(
    options.publicationCommit,
    "Published publication commit",
  );
  const concurrentMainCommit = requireObjectId(
    options.concurrentMainCommit,
    "Concurrent main commit",
  );
  const integrationBridgeCommit = requireObjectId(
    options.integrationBridgeCommit,
    "Publication integration bridge commit",
  );
  const surfaceCommit = requireObjectId(
    options.surfaceCommit ?? repository.commit,
    "Publication integration surface commit",
  );
  const runner = releaseGitRunner(
    repository.repositoryRoot,
    repository.gitDirectory,
  );
  return await inspectReleasePublicationIntegrationSurfaceWithRunner(
    runner,
    candidateCommit,
    publicationCommit,
    concurrentMainCommit,
    integrationBridgeCommit,
    surfaceCommit,
  );
}

async function inspectReleasePublicationIntegrationBridgeWithRunner(
  runner: ReleaseGitRunner,
  candidateCommit: string,
  publicationCommit: string,
  concurrentMainCommit: string,
  integrationBridgeCommit: string,
): Promise<ReleasePublicationIntegrationBridgeEvidence> {
  const publication = await inspectReleasePublicationWithRunner(
    runner,
    candidateCommit,
    publicationCommit,
  );
  const [concurrentMainAncestry, integrationBridgeAncestry] = await Promise.all([
    runner.run([
      "rev-list",
      "--parents",
      "-n",
      "1",
      concurrentMainCommit,
    ]),
    runner.run([
      "rev-list",
      "--parents",
      "-n",
      "1",
      integrationBridgeCommit,
    ]),
  ]);
  const concurrentMainParents = concurrentMainAncestry.trim().split(/\s+/u);
  if (
    concurrentMainParents.length !== 2
    || concurrentMainParents[0] !== concurrentMainCommit
    || concurrentMainParents[1] !== candidateCommit
  ) {
    throw new Error(
      "The concurrent main commit must have the tagged candidate as its only direct parent.",
    );
  }
  const integrationBridgeParents = integrationBridgeAncestry
    .trim()
    .split(/\s+/u);
  if (
    integrationBridgeParents.length !== 3
    || integrationBridgeParents[0] !== integrationBridgeCommit
    || integrationBridgeParents[1] !== publicationCommit
    || integrationBridgeParents[2] !== concurrentMainCommit
  ) {
    throw new Error(
      "The publication integration bridge must have ordered direct parents [publication, concurrent main].",
    );
  }
  const [concurrentMainContract, integrationBridgeContract] = await Promise.all([
    readBoundedReleaseContractAtCommit(runner, concurrentMainCommit),
    readBoundedReleaseContractAtCommit(runner, integrationBridgeCommit),
  ]);
  if (concurrentMainContract !== publication.candidateContract) {
    throw new Error(
      "The concurrent main commit must preserve the candidate release contract exactly.",
    );
  }
  if (integrationBridgeContract !== publication.publicationContract) {
    throw new Error(
      "The publication integration bridge must preserve the publication release contract exactly.",
    );
  }
  return Object.freeze({
    concurrentMainCommit,
    integrationBridgeCommit,
    publication,
    status: "exact_candidate_publication_concurrent_main_integration_bridge",
  });
}

async function inspectReleasePublicationIntegrationSurfaceWithRunner(
  runner: ReleaseGitRunner,
  candidateCommit: string,
  publicationCommit: string,
  concurrentMainCommit: string,
  integrationBridgeCommit: string,
  surfaceCommit: string,
): Promise<ReleasePublicationIntegrationSurfaceEvidence> {
  const bridge = await inspectReleasePublicationIntegrationBridgeWithRunner(
    runner,
    candidateCommit,
    publicationCommit,
    concurrentMainCommit,
    integrationBridgeCommit,
  );
  const surfaceAncestry = (await runner.run([
    "rev-list",
    "--parents",
    "-n",
    "1",
    surfaceCommit,
  ])).trim().split(/\s+/u);
  if (
    surfaceAncestry.length !== 2
    || surfaceAncestry[0] !== surfaceCommit
    || surfaceAncestry[1] !== integrationBridgeCommit
  ) {
    throw new Error(
      "The publication integration surface must have the integration bridge as its only direct parent.",
    );
  }
  const surfaceContract = await readBoundedReleaseContractAtCommit(
    runner,
    surfaceCommit,
  );
  if (surfaceContract !== bridge.publication.publicationContract) {
    throw new Error(
      "The publication integration surface must preserve the publication release contract exactly.",
    );
  }
  return Object.freeze({
    bridge,
    status: "verified_publication_integration_bridge_surface",
    surfaceCommit,
  });
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
 * Fetch only the exact P15 publication, final C15 candidate,
 * signed-release-probe repair, bundle-code authority, host-trust repair,
 * custody repair, reviewed public surface, base C15, and Q14 ancestry plus
 * the release tag from the fixed public HRA repository. Vercel's ambient
 * shallow checkout is never trusted or inspected.
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
      "--depth=9",
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
      "--depth=8",
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
      HRA_V0_C15_SIGNED_RELEASE_PROBE_REPAIR_COMMIT,
      HRA_V0_C15_BUNDLE_CODE_AUTHORITY_COMMIT,
      HRA_V0_C15_HOST_TRUST_COMMIT,
      HRA_V0_C15_CUSTODY_REPAIR_COMMIT,
      HRA_V0_C15_REVIEWED_SURFACE_COMMIT,
      HRA_V0_C15_BASE_COMMIT,
      HRA_V0_Q14_SURFACE_COMMIT,
    );
    return evidence;
  } finally {
    await rm(temporaryRoot, { force: true, recursive: true });
  }
}

/**
 * Fetch and verify the exact linear Q15/C16/C17/C18/C19/P16/Q16 publication
 * topology from the canonical HRA v0 repository without trusting a provider
 * checkout.
 */
export async function inspectCanonicalReleasePublicationSurface(
  options: Readonly<{
    candidateCommit: string;
    expectedC16Commit?: string;
    expectedC17Commit?: string;
    expectedC18Commit?: string;
    expectedQ15Commit?: string;
    publicationCommit: string;
    surfaceCommit: string;
    tag: string;
  }>,
): Promise<CanonicalReleasePublicationSurfaceEvidence> {
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
    "Publication surface commit",
  );
  const expectedQ15Commit = requireObjectId(
    options.expectedQ15Commit ?? HRA_V0_Q15_SURFACE_COMMIT,
    "HRA v0.1.15 Q15 surface commit",
  );
  const expectedC16Commit = requireObjectId(
    options.expectedC16Commit ?? HRA_V0_C16_COMPATIBILITY_COMMIT,
    "HRA v0.1.16 C16 compatibility commit",
  );
  const expectedC17Commit = requireObjectId(
    options.expectedC17Commit ?? HRA_V0_C17_TIMEOUT_CAP_COMMIT,
    "HRA v0.1.16 C17 timeout-cap commit",
  );
  const expectedC18Commit = requireObjectId(
    options.expectedC18Commit ?? HRA_V0_C18_COLD_CUSTODY_TIMEOUT_COMMIT,
    "HRA v0.1.16 C18 cold-custody timeout commit",
  );
  if (!/^v[0-9]+\.[0-9]+\.[0-9]+$/u.test(options.tag)) {
    throw new Error("Release tag is invalid.");
  }
  const temporaryRoot = await realpath(
    await mkdtemp(join(tmpdir(), "hra-release-surface-fetch-")),
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
      `--depth=${HRA_V0_PUBLICATION_SURFACE_FETCH_DEPTHS.surface}`,
      "--filter=blob:limit=32768",
      "canonical",
      surfaceCommit,
    ]);
    const tagRef = `refs/tags/${options.tag}`;
    await runner.run([
      "fetch",
      "--quiet",
      "--force",
      "--no-tags",
      `--depth=${HRA_V0_PUBLICATION_SURFACE_FETCH_DEPTHS.tag}`,
      "--filter=blob:limit=32768",
      "canonical",
      `${tagRef}:${tagRef}`,
    ]);
    const [surface, tag] = await Promise.all([
      inspectReleasePublicationSurfaceWithRunner(
        runner,
        candidateCommit,
        publicationCommit,
        surfaceCommit,
      ),
      inspectReleaseTagWithRunner(runner, options.tag),
    ]);
    if (tag === null) {
      throw new Error(
        "The canonical release repository has no annotated release tag.",
      );
    }
    await inspectReleaseHotfixCandidateLineageWithRunner(
      runner,
      candidateCommit,
      expectedC18Commit,
      expectedC17Commit,
      expectedC16Commit,
      expectedQ15Commit,
    );
    return Object.freeze({
      publication: surface.publication,
      surface,
      tag,
    });
  } finally {
    await rm(temporaryRoot, { force: true, recursive: true });
  }
}

/**
 * Fetch and verify the exact fixed C15/P15/U/M/Q publication topology from the
 * canonical HRA v0 repository. The provider checkout is not consulted: Q and
 * the annotated tag are fetched into a new bare object store, then every
 * parent edge and every release-contract byte boundary is inspected there.
 */
export async function inspectCanonicalReleasePublicationIntegrationSurface(
  options: Readonly<{
    candidateCommit: string;
    concurrentMainCommit: string;
    integrationBridgeCommit: string;
    publicationCommit: string;
    surfaceCommit: string;
    tag: string;
  }>,
): Promise<CanonicalReleasePublicationIntegrationSurfaceEvidence> {
  const candidateCommit = requireObjectId(
    options.candidateCommit,
    "Published candidate commit",
  );
  const publicationCommit = requireObjectId(
    options.publicationCommit,
    "Published publication commit",
  );
  const concurrentMainCommit = requireObjectId(
    options.concurrentMainCommit,
    "Concurrent main commit",
  );
  const integrationBridgeCommit = requireObjectId(
    options.integrationBridgeCommit,
    "Publication integration bridge commit",
  );
  const surfaceCommit = requireObjectId(
    options.surfaceCommit,
    "Publication integration surface commit",
  );
  if (!/^v[0-9]+\.[0-9]+\.[0-9]+$/u.test(options.tag)) {
    throw new Error("Release tag is invalid.");
  }
  const temporaryRoot = await realpath(
    await mkdtemp(join(tmpdir(), "hra-release-integration-fetch-")),
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
      "--depth=12",
      "--filter=blob:limit=32768",
      "canonical",
      surfaceCommit,
    ]);
    const tagRef = `refs/tags/${options.tag}`;
    await runner.run([
      "fetch",
      "--quiet",
      "--force",
      "--no-tags",
      "--depth=9",
      "--filter=blob:limit=32768",
      "canonical",
      `${tagRef}:${tagRef}`,
    ]);
    const [surface, tag] = await Promise.all([
      inspectReleasePublicationIntegrationSurfaceWithRunner(
        runner,
        candidateCommit,
        publicationCommit,
        concurrentMainCommit,
        integrationBridgeCommit,
        surfaceCommit,
      ),
      inspectReleaseTagWithRunner(runner, options.tag),
    ]);
    if (tag === null) {
      throw new Error(
        "The canonical release repository has no annotated release tag.",
      );
    }
    await inspectReleaseCandidateLineageWithRunner(
      runner,
      candidateCommit,
      HRA_V0_C15_SIGNED_RELEASE_PROBE_REPAIR_COMMIT,
      HRA_V0_C15_BUNDLE_CODE_AUTHORITY_COMMIT,
      HRA_V0_C15_HOST_TRUST_COMMIT,
      HRA_V0_C15_CUSTODY_REPAIR_COMMIT,
      HRA_V0_C15_REVIEWED_SURFACE_COMMIT,
      HRA_V0_C15_BASE_COMMIT,
      HRA_V0_Q14_SURFACE_COMMIT,
    );
    return Object.freeze({
      bridge: surface.bridge,
      publication: surface.bridge.publication,
      surface,
      tag,
    });
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
