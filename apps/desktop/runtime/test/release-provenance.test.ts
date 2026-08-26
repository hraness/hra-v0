import { afterEach, describe, expect, test } from "bun:test";
import {
  mkdir,
  mkdtemp,
  realpath,
  rm,
  symlink,
  writeFile,
} from "node:fs/promises";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";

import {
  HRA_V0_C15_BASE_COMMIT,
  HRA_V0_C15_BUNDLE_CODE_AUTHORITY_COMMIT,
  HRA_V0_C15_CANDIDATE_COMMIT,
  HRA_V0_C15_CUSTODY_REPAIR_COMMIT,
  HRA_V0_C15_HOST_TRUST_COMMIT,
  HRA_V0_C15_REVIEWED_SURFACE_COMMIT,
  HRA_V0_C15_SIGNED_RELEASE_PROBE_REPAIR_COMMIT,
  HRA_V0_C16_COMPATIBILITY_COMMIT,
  HRA_V0_C17_TIMEOUT_CAP_COMMIT,
  HRA_V0_CURRENT_REPOSITORY,
  HRA_V0_P15_CONCURRENT_MAIN_COMMIT,
  HRA_V0_P15_INTEGRATION_BRIDGE_COMMIT,
  HRA_V0_P15_PUBLICATION_COMMIT,
  HRA_V0_Q14_SURFACE_COMMIT,
  HRA_V0_Q15_SURFACE_COMMIT,
  inspectArchiveReleaseSurface,
  inspectReleaseCandidateLineage,
  inspectReleaseHotfixCandidateLineage,
  inspectReleasePublicationIntegrationBridge,
  inspectReleasePublicationIntegrationSurface,
  inspectReleasePublicationSurface,
  inspectReleasePublicationTransition,
  inspectReleaseSourceRepository,
  inspectReleaseTag,
  resolveReleaseCandidateCommit,
  resolveReleaseHotfixCandidateCommit,
} from "../release-provenance";
import type { ReleaseRepositoryEvidence } from "../release-provenance";

const temporaryRoots: string[] = [];
const setupEnvironment = Object.freeze({
  GIT_CONFIG_GLOBAL: "/dev/null",
  GIT_CONFIG_NOSYSTEM: "1",
  HOME: "/var/empty",
  LANG: "C",
  LC_ALL: "C",
  PATH: "/usr/bin:/bin",
});

afterEach(async () => {
  await Promise.all(
    temporaryRoots.splice(0).map((root) => rm(root, { force: true, recursive: true })),
  );
});

describe("hermetic release provenance", () => {
  test("derives a clean canonical top-level without trusting origin", async () => {
    const repositoryRoot = await createRepository();
    await runSetupGit(repositoryRoot, [
      "remote",
      "add",
      "origin",
      "https://example.invalid/not-hra.git",
    ]);

    const evidence = await inspectReleaseSourceRepository({
      environment: {},
      repositoryRoot,
    });

    expect(evidence).toMatchObject({
      gitDirectory: join(repositoryRoot, ".git"),
      repository: HRA_V0_CURRENT_REPOSITORY,
      repositoryRoot,
      status: "clean_canonical_source",
    });
    expect(evidence.commit).toMatch(/^[0-9a-f]{40}$/u);
    expect(evidence.tree).toMatch(/^[0-9a-f]{40}$/u);
  });

  test("refuses every ambient Git steering namespace before execution", async () => {
    const repositoryRoot = await createRepository();
    const steeringKeys = [
      "GIT_ALTERNATE_OBJECT_DIRECTORIES",
      "GIT_CEILING_DIRECTORIES",
      "GIT_CONFIG_COUNT",
      "GIT_CONFIG_GLOBAL",
      "GIT_DIR",
      "GIT_INDEX_FILE",
      "GIT_OBJECT_DIRECTORY",
      "GIT_PAGER",
      "GIT_REPLACE_REF_BASE",
      "GIT_WORK_TREE",
    ] as const;

    for (const key of steeringKeys) {
      await expectRejection(inspectReleaseSourceRepository({
        environment: { [key]: "attacker-controlled" },
        repositoryRoot,
      }), key);
    }
  });

  test("refuses alternate objects, grafts, and replacement refs", async () => {
    const alternateRepository = await createRepository();
    const alternates = join(alternateRepository, ".git/objects/info/alternates");
    await mkdir(dirname(alternates), { recursive: true });
    await writeFile(alternates, "/attacker/objects\n");
    await expectRejection(inspectReleaseSourceRepository({
      environment: {},
      repositoryRoot: alternateRepository,
    }), "object alternates");

    const graftRepository = await createRepository();
    const grafts = join(graftRepository, ".git/info/grafts");
    await mkdir(dirname(grafts), { recursive: true });
    await writeFile(grafts, "0".repeat(40));
    await expectRejection(inspectReleaseSourceRepository({
      environment: {},
      repositoryRoot: graftRepository,
    }), "grafts");

    const replacementRepository = await createRepository();
    const original = await runSetupGit(replacementRepository, ["rev-parse", "HEAD"]);
    await writeFile(join(replacementRepository, "source.txt"), "second\n");
    await runSetupGit(replacementRepository, ["add", "source.txt"]);
    await runSetupGit(replacementRepository, ["commit", "-m", "second"]);
    const replacement = await runSetupGit(replacementRepository, ["rev-parse", "HEAD"]);
    await runSetupGit(replacementRepository, [
      "replace",
      replacement.trim(),
      original.trim(),
    ]);
    await expectRejection(inspectReleaseSourceRepository({
      environment: {},
      repositoryRoot: replacementRepository,
    }), "replacement refs");
  });

  test("refuses local config includes and every submodule boundary", async () => {
    const includeRepository = await createRepository();
    await runSetupGit(includeRepository, [
      "config",
      "--local",
      "include.path",
      "/attacker/release.gitconfig",
    ]);
    await expectRejection(inspectReleaseSourceRepository({
      environment: {},
      repositoryRoot: includeRepository,
    }), "include configuration");

    const conditionalIncludeRepository = await createRepository();
    await runSetupGit(conditionalIncludeRepository, [
      "config",
      "--local",
      "includeIf.gitdir:/attacker/.path",
      "/attacker/release.gitconfig",
    ]);
    await expectRejection(inspectReleaseSourceRepository({
      environment: {},
      repositoryRoot: conditionalIncludeRepository,
    }), "include configuration");

    const submoduleRepository = await createRepository();
    await writeFile(
      join(submoduleRepository, ".gitmodules"),
      "[submodule \"steered\"]\n\tpath = steered\n\turl = /attacker/repository\n",
    );
    await runSetupGit(submoduleRepository, ["add", ".gitmodules"]);
    await runSetupGit(submoduleRepository, ["commit", "-m", "submodule drift"]);
    await expectRejection(inspectReleaseSourceRepository({
      environment: {},
      repositoryRoot: submoduleRepository,
    }), "submodule presence or drift");
  });

  test("accepts checkout's inactive residual worktree configuration", async () => {
    const repositoryRoot = await createRepository();
    await writeFile(
      join(repositoryRoot, ".git/config.worktree"),
      [
        "[core]",
        "\tsparseCheckout = false",
        "\tsparseCheckoutCone = false",
        "[index]",
        "\tsparse = false",
        "",
      ].join("\n"),
    );

    const evidence = await inspectReleaseSourceRepository({
      environment: {},
      repositoryRoot,
    });

    expect(evidence.repositoryRoot).toBe(repositoryRoot);
  });

  test("refuses active worktree configuration that can conceal source", async () => {
    const repositoryRoot = await createRepository();
    const excludesFile = join(
      await createTemporaryDirectory("hra-worktree-config-"),
      "ignore",
    );
    await writeFile(excludesFile, "concealed.txt\n");
    await writeFile(
      join(repositoryRoot, ".git/config.worktree"),
      `[core]\n\texcludesFile = ${excludesFile}\n`,
    );
    await runSetupGit(repositoryRoot, [
      "config",
      "--local",
      "extensions.worktreeConfig",
      "true",
    ]);
    await writeFile(
      join(repositoryRoot, "concealed.txt"),
      "untracked release input\n",
    );

    await expectRejection(inspectReleaseSourceRepository({
      environment: {},
      repositoryRoot,
    }), "active Git worktree configuration");
  });

  test("refuses index flags that can conceal changed release source", async () => {
    for (const flag of ["--assume-unchanged", "--skip-worktree"] as const) {
      const repositoryRoot = await createRepository();
      await runSetupGit(repositoryRoot, ["update-index", flag, "source.txt"]);
      await writeFile(join(repositoryRoot, "source.txt"), `concealed by ${flag}\n`);
      await expectRejection(inspectReleaseSourceRepository({
        environment: {},
        repositoryRoot,
      }), "skip-worktree");
    }
  });

  test("does not read caller HOME or global Git configuration", async () => {
    const repositoryRoot = await createRepository();
    const hostileHome = await createTemporaryDirectory("hra-hostile-git-home-");
    await writeFile(
      join(hostileHome, ".gitconfig"),
      "[core]\n\tbare = true\n\tworktree = /attacker/worktree\n[include]\n\tpath = /attacker/config\n",
    );

    const evidence = await inspectReleaseSourceRepository({
      environment: { HOME: hostileHome },
      repositoryRoot,
    });
    expect(evidence.repositoryRoot).toBe(repositoryRoot);
  });

  test("refuses linked metadata and noncanonical root aliases", async () => {
    const linkedMetadataRoot = await createTemporaryDirectory("hra-git-file-");
    await writeFile(join(linkedMetadataRoot, ".git"), "gitdir: /attacker/git\n");
    await expectRejection(inspectReleaseSourceRepository({
      environment: {},
      repositoryRoot: linkedMetadataRoot,
    }), "Git directory must be a real directory");

    const repositoryRoot = await createRepository();
    const aliasRoot = await createTemporaryDirectory("hra-root-alias-");
    const aliasPath = join(aliasRoot, "repository");
    await symlink(repositoryRoot, aliasPath);
    await expectRejection(inspectReleaseSourceRepository({
      environment: {},
      repositoryRoot: aliasPath,
    }), "exact canonical spelling");
  });

  test("accepts only an annotated tag and derives its peeled commit", async () => {
    const repositoryRoot = await createRepository();
    const repository = await inspectReleaseSourceRepository({
      environment: {},
      repositoryRoot,
    });
    expect(await inspectReleaseTag(repository, "v9.8.7")).toBeNull();

    await runSetupGit(repositoryRoot, ["tag", "-a", "v9.8.7", "-m", "candidate"]);
    const taggedRepository = await inspectReleaseSourceRepository({
      environment: {},
      repositoryRoot,
    });
    const tag = await inspectReleaseTag(taggedRepository, "v9.8.7");
    expect(tag).toMatchObject({
      commit: taggedRepository.commit,
      objectType: "tag",
      tag: "v9.8.7",
    });
    expect(tag?.object).toMatch(/^[0-9a-f]{40}$/u);
  });

  test("resolves final C15 when HEAD is the candidate or a later descendant", async () => {
    const repositoryRoot = await createRepository();
    const signedReleaseProbeRepairCommit = (await runSetupGit(
      repositoryRoot,
      ["rev-parse", "HEAD"],
    )).trim();
    const candidateCommit = await commitFixture(
      repositoryRoot,
      "candidate.txt",
      "repaired C15",
    );
    const candidateRepository = await inspectReleaseSourceRepository({
      environment: {},
      repositoryRoot,
    });
    expect(await resolveReleaseCandidateCommit(candidateRepository, {
      expectedSignedReleaseProbeRepairCommit: signedReleaseProbeRepairCommit,
    })).toBe(candidateCommit);

    await commitFixture(repositoryRoot, "follow-up.txt", "archive follow-up");
    const descendantRepository = await inspectReleaseSourceRepository({
      environment: {},
      repositoryRoot,
    });
    expect(descendantRepository.commit).not.toBe(candidateCommit);
    expect(await resolveReleaseCandidateCommit(descendantRepository, {
      expectedSignedReleaseProbeRepairCommit: signedReleaseProbeRepairCommit,
    })).toBe(candidateCommit);
  });

  test("resolves and binds the unique linear C18 child of exact C17, C16, and Q15", async () => {
    const repositoryRoot = await createRepository();
    const q15Commit = (await runSetupGit(
      repositoryRoot,
      ["rev-parse", "HEAD"],
    )).trim();
    await writeFile(join(repositoryRoot, "hotfix.txt"), "macOS ACL hotfix\n");
    await runSetupGit(repositoryRoot, ["add", "hotfix.txt"]);
    await runSetupGit(repositoryRoot, ["commit", "-m", "compatibility C16"]);
    const c16Commit = (await runSetupGit(
      repositoryRoot,
      ["rev-parse", "HEAD"],
    )).trim();
    await writeFile(
      join(repositoryRoot, "timeout-cap.txt"),
      "native timeout-cap correction\n",
    );
    await runSetupGit(repositoryRoot, ["add", "timeout-cap.txt"]);
    await runSetupGit(repositoryRoot, ["commit", "-m", "timeout cap C17"]);
    const c17Commit = (await runSetupGit(
      repositoryRoot,
      ["rev-parse", "HEAD"],
    )).trim();
    await writeFile(
      join(repositoryRoot, "latency.txt"),
      "native custody latency correction\n",
    );
    await runSetupGit(repositoryRoot, ["add", "latency.txt"]);
    await runSetupGit(repositoryRoot, ["commit", "-m", "candidate C18"]);
    const candidateCommit = (await runSetupGit(
      repositoryRoot,
      ["rev-parse", "HEAD"],
    )).trim();

    let repository = await inspectReleaseSourceRepository({
      environment: {},
      repositoryRoot,
    });
    expect(await resolveReleaseHotfixCandidateCommit(repository, {
      expectedC16Commit: c16Commit,
      expectedC17Commit: c17Commit,
      expectedQ15Commit: q15Commit,
    })).toBe(candidateCommit);
    expect(await inspectReleaseHotfixCandidateLineage(repository, {
      candidateCommit,
      expectedC16Commit: c16Commit,
      expectedC17Commit: c17Commit,
      expectedQ15Commit: q15Commit,
    })).toEqual({
      c16Commit,
      c17Commit,
      candidateCommit,
      q15Commit,
      status: "exact_q15_c16_c17_c18_candidate_chain",
    });

    await writeFile(join(repositoryRoot, "publication.txt"), "descendant\n");
    await runSetupGit(repositoryRoot, ["add", "publication.txt"]);
    await runSetupGit(repositoryRoot, ["commit", "-m", "later descendant"]);
    repository = await inspectReleaseSourceRepository({
      environment: {},
      repositoryRoot,
    });
    expect(await resolveReleaseHotfixCandidateCommit(repository, {
      expectedC16Commit: c16Commit,
      expectedC17Commit: c17Commit,
      expectedQ15Commit: q15Commit,
    })).toBe(candidateCommit);
  }, 10_000);

  test("binds Q16 as P16's sole direct child with the exact published contract", async () => {
    const topology = await createLinearPublicationTopology();
    expect(await inspectReleasePublicationSurface(topology.repository, {
      candidateCommit: topology.candidateCommit,
      publicationCommit: topology.publicationCommit,
    })).toMatchObject({
      publication: {
        candidateCommit: topology.candidateCommit,
        publicationCommit: topology.publicationCommit,
        status: "exact_candidate_publication_transition",
      },
      status: "verified_linear_publication_surface",
      surfaceCommit: topology.surfaceCommit,
    });
  });

  test("rejects a non-direct Q16 and any Q16 release-contract rewrite", async () => {
    const nonDirect = await createLinearPublicationTopology({
      surfaceIntermediate: true,
    });
    await expectRejection(
      inspectReleasePublicationSurface(nonDirect.repository, {
        candidateCommit: nonDirect.candidateCommit,
        publicationCommit: nonDirect.publicationCommit,
      }),
      "must have P16 as its only direct parent",
    );

    const rewritten = await createLinearPublicationTopology({
      rewriteSurfaceContract: true,
    });
    await expectRejection(
      inspectReleasePublicationSurface(rewritten.repository, {
        candidateCommit: rewritten.candidateCommit,
        publicationCommit: rewritten.publicationCommit,
      }),
      "must preserve the P16 release contract exactly",
    );
  });

  test("rejects a C16 whose sole parent is not exact Q15", async () => {
    const wrongC16Root = await createRepository();
    const wrongC16Q15 = (await runSetupGit(
      wrongC16Root,
      ["rev-parse", "HEAD"],
    )).trim();
    await commitFixture(wrongC16Root, "intermediate.txt", "intermediate");
    const wrongC16 = await commitFixture(
      wrongC16Root,
      "compatibility.txt",
      "compatibility C16",
    );
    const wrongC16C17 = await commitFixture(
      wrongC16Root,
      "timeout-cap.txt",
      "timeout cap C17",
    );
    const wrongC16Candidate = await commitFixture(
      wrongC16Root,
      "candidate.txt",
      "candidate C18",
    );
    const wrongC16Repository = await inspectReleaseSourceRepository({
      environment: {},
      repositoryRoot: wrongC16Root,
    });
    await expectRejection(
      inspectReleaseHotfixCandidateLineage(wrongC16Repository, {
        candidateCommit: wrongC16Candidate,
        expectedC16Commit: wrongC16,
        expectedC17Commit: wrongC16C17,
        expectedQ15Commit: wrongC16Q15,
      }),
      "C16 compatibility commit must have exact Q15 as its only direct parent",
    );
  });

  test("rejects a C17 whose sole parent is not exact C16", async () => {
    const wrongC17Root = await createRepository();
    const wrongC17Q15 = (await runSetupGit(
      wrongC17Root,
      ["rev-parse", "HEAD"],
    )).trim();
    const wrongC17C16 = await commitFixture(
      wrongC17Root,
      "compatibility.txt",
      "compatibility C16",
    );
    await commitFixture(wrongC17Root, "intermediate.txt", "intermediate");
    const wrongC17 = await commitFixture(
      wrongC17Root,
      "timeout-cap.txt",
      "timeout cap C17",
    );
    const wrongC17Candidate = await commitFixture(
      wrongC17Root,
      "candidate.txt",
      "candidate C18",
    );
    const wrongC17Repository = await inspectReleaseSourceRepository({
      environment: {},
      repositoryRoot: wrongC17Root,
    });
    await expectRejection(
      inspectReleaseHotfixCandidateLineage(wrongC17Repository, {
        candidateCommit: wrongC17Candidate,
        expectedC16Commit: wrongC17C16,
        expectedC17Commit: wrongC17,
        expectedQ15Commit: wrongC17Q15,
      }),
      "C17 timeout-cap commit must have exact C16 as its only direct parent",
    );
  });

  test("rejects a C18 whose sole parent is not exact C17", async () => {
    const wrongC18Root = await createRepository();
    const wrongC18Q15 = (await runSetupGit(
      wrongC18Root,
      ["rev-parse", "HEAD"],
    )).trim();
    const wrongC18C16 = await commitFixture(
      wrongC18Root,
      "compatibility.txt",
      "compatibility C16",
    );
    const wrongC18C17 = await commitFixture(
      wrongC18Root,
      "timeout-cap.txt",
      "timeout cap C17",
    );
    await commitFixture(wrongC18Root, "intermediate.txt", "intermediate");
    const wrongC18Candidate = await commitFixture(
      wrongC18Root,
      "candidate.txt",
      "candidate C18",
    );
    const wrongC18Repository = await inspectReleaseSourceRepository({
      environment: {},
      repositoryRoot: wrongC18Root,
    });
    await expectRejection(
      inspectReleaseHotfixCandidateLineage(wrongC18Repository, {
        candidateCommit: wrongC18Candidate,
        expectedC16Commit: wrongC18C16,
        expectedC17Commit: wrongC18C17,
        expectedQ15Commit: wrongC18Q15,
      }),
      "C18 candidate must have exact C17 as its only direct parent",
    );
  });

  test("rejects merge-child and multiple-child C18 topologies", async () => {
    const forkedRoot = await createRepository();
    const forkQ15 = (await runSetupGit(
      forkedRoot,
      ["rev-parse", "HEAD"],
    )).trim();
    const forkC16 = await commitFixture(
      forkedRoot,
      "compatibility.txt",
      "compatibility C16",
    );
    const forkC17 = await commitFixture(
      forkedRoot,
      "timeout-cap.txt",
      "timeout cap C17",
    );
    await runSetupGit(forkedRoot, ["switch", "-c", "other-c18"]);
    await commitFixture(forkedRoot, "other.txt", "other C18 child");
    await runSetupGit(forkedRoot, ["switch", "main"]);
    await commitFixture(forkedRoot, "candidate.txt", "candidate C18 child");
    await runSetupGit(forkedRoot, [
      "merge",
      "--no-ff",
      "other-c18",
      "-m",
      "merge two C18 children",
    ]);
    const forkedRepository = await inspectReleaseSourceRepository({
      environment: {},
      repositoryRoot: forkedRoot,
    });
    await expectRejection(
      resolveReleaseHotfixCandidateCommit(forkedRepository, {
        expectedC16Commit: forkC16,
        expectedC17Commit: forkC17,
        expectedQ15Commit: forkQ15,
      }),
      "C18 candidate must have exact C17 as its only direct parent",
    );
    await expectRejection(
      inspectReleaseHotfixCandidateLineage(forkedRepository, {
        candidateCommit: forkedRepository.commit,
        expectedC16Commit: forkC16,
        expectedC17Commit: forkC17,
        expectedQ15Commit: forkQ15,
      }),
      "C18 candidate must have exact C17 as its only direct parent",
    );
  }, 10_000);

  test("rejects resolving final C15 when signed release probes have two children on the path to HEAD", async () => {
    const repositoryRoot = await createRepository();
    const signedReleaseProbeRepairCommit = (await runSetupGit(
      repositoryRoot,
      ["rev-parse", "HEAD"],
    )).trim();
    await runSetupGit(repositoryRoot, ["switch", "-c", "other-child"]);
    await commitFixture(repositoryRoot, "other.txt", "other repaired C15");
    await runSetupGit(repositoryRoot, ["switch", "main"]);
    await commitFixture(repositoryRoot, "candidate.txt", "repaired C15");
    await runSetupGit(repositoryRoot, [
      "merge",
      "--no-ff",
      "other-child",
      "-m", "merge two signed-release-probe children",
    ]);
    const repository = await inspectReleaseSourceRepository({
      environment: {},
      repositoryRoot,
    });

    await expectRejection(
      resolveReleaseCandidateCommit(repository, {
      expectedSignedReleaseProbeRepairCommit: signedReleaseProbeRepairCommit,
      }),
      "exact signed-release-probe repair commit as its only direct parent",
    );
  });

  test("binds final C15 to exact signed-release-probe, bundle-authority, host-trust, custody-repair, reviewed-surface, base-C15, and Q14 edges", async () => {
    expect(HRA_V0_C15_BASE_COMMIT).toBe(
      "a2948a21eb524e89960cfcbd7b68d7c52ab028b4",
    );
    expect(HRA_V0_C15_BUNDLE_CODE_AUTHORITY_COMMIT).toBe(
      "22f6f21985af4a000f51e2acf8747501fa12536c",
    );
    expect(HRA_V0_C15_SIGNED_RELEASE_PROBE_REPAIR_COMMIT).toBe(
      "8b84baf7ebc80cc5e2b63365900454a7446f7479",
    );
    expect(HRA_V0_C15_CUSTODY_REPAIR_COMMIT).toBe(
      "045ee7b4b23ea1b61392d0a782f619f2d946eeaf",
    );
    expect(HRA_V0_C15_HOST_TRUST_COMMIT).toBe(
      "7d284b48577b5747a247cef31952de3c7f7338cd",
    );
    expect(HRA_V0_C15_REVIEWED_SURFACE_COMMIT).toBe(
      "fd33c4561ea161367f2c516d502f1e88d0998f29",
    );
    expect(HRA_V0_Q14_SURFACE_COMMIT).toBe(
      "ceb647f7a4a68546fc68ce5e70e770b73c8863eb",
    );
    const repositoryRoot = await createRepository();
    const q14Commit = (await runSetupGit(
      repositoryRoot,
      ["rev-parse", "HEAD"],
    )).trim();
    const baseCommit = await commitFixture(repositoryRoot, "base.txt", "base C15");
    const reviewedSurfaceCommit = await commitFixture(
      repositoryRoot,
      "reviewed-surface.txt",
      "reviewed C15 public surface",
    );
    const custodyRepairCommit = await commitFixture(
      repositoryRoot,
      "custody-repair.txt",
      "C15 custody repair",
    );
    const hostTrustCommit = await commitFixture(
      repositoryRoot,
      "host-trust.txt",
      "C15 host trust",
    );
    const bundleCodeAuthorityCommit = await commitFixture(
      repositoryRoot,
      "bundle-code-authority.txt",
      "C15 bundle code authority",
    );
    const signedReleaseProbeRepairCommit = await commitFixture(
      repositoryRoot,
      "signed-release-probe-repair.txt",
      "C15 signed release-probe repair",
    );
    const candidateCommit = await commitFixture(
      repositoryRoot,
      "candidate.txt",
      "repaired C15",
    );
    const repository = await inspectReleaseSourceRepository({
      environment: {},
      repositoryRoot,
    });

    expect(await inspectReleaseCandidateLineage(repository, {
      expectedBaseCommit: baseCommit,
      expectedBundleCodeAuthorityCommit: bundleCodeAuthorityCommit,
      expectedCustodyRepairCommit: custodyRepairCommit,
      expectedHostTrustCommit: hostTrustCommit,
      expectedQ14Commit: q14Commit,
      expectedSignedReleaseProbeRepairCommit: signedReleaseProbeRepairCommit,
      expectedSurfaceCommit: reviewedSurfaceCommit,
    })).toEqual({
      baseCommit,
      bundleCodeAuthorityCommit,
      candidateCommit,
      custodyRepairCommit,
      hostTrustCommit,
      q14Commit,
      reviewedSurfaceCommit,
      signedReleaseProbeRepairCommit,
      status: "exact_q14_base_c15_reviewed_surface_custody_repair_host_trust_bundle_code_authority_signed_release_probe_repair_final_candidate_chain",
    });
  });

  test("rejects a final candidate with the wrong signed-release-probe-repair parent", async () => {
    const repositoryRoot = await createRepository();
    const q14Commit = (await runSetupGit(
      repositoryRoot,
      ["rev-parse", "HEAD"],
    )).trim();
    const baseCommit = await commitFixture(repositoryRoot, "base.txt", "base C15");
    const reviewedSurfaceCommit = await commitFixture(
      repositoryRoot,
      "reviewed-surface.txt",
      "reviewed C15 public surface",
    );
    const custodyRepairCommit = await commitFixture(
      repositoryRoot,
      "custody-repair.txt",
      "C15 custody repair",
    );
    const hostTrustCommit = await commitFixture(
      repositoryRoot,
      "host-trust.txt",
      "C15 host trust",
    );
    const bundleCodeAuthorityCommit = await commitFixture(
      repositoryRoot,
      "bundle-code-authority.txt",
      "C15 bundle code authority",
    );
    const signedReleaseProbeRepairCommit = await commitFixture(
      repositoryRoot,
      "signed-release-probe-repair.txt",
      "C15 signed release-probe repair",
    );
    await commitFixture(repositoryRoot, "wrong-parent.txt", "wrong candidate parent");
    await commitFixture(repositoryRoot, "candidate.txt", "repaired C15");
    const repository = await inspectReleaseSourceRepository({
      environment: {},
      repositoryRoot,
    });

    await expectRejection(
      inspectReleaseCandidateLineage(repository, {
        expectedBaseCommit: baseCommit,
        expectedBundleCodeAuthorityCommit: bundleCodeAuthorityCommit,
        expectedCustodyRepairCommit: custodyRepairCommit,
        expectedHostTrustCommit: hostTrustCommit,
        expectedQ14Commit: q14Commit,
        expectedSignedReleaseProbeRepairCommit: signedReleaseProbeRepairCommit,
        expectedSurfaceCommit: reviewedSurfaceCommit,
      }),
      "exact signed-release-probe repair commit as its only direct parent",
    );
  });

  test("rejects a merge commit as the repaired candidate", async () => {
    const repositoryRoot = await createRepository();
    const q14Commit = (await runSetupGit(
      repositoryRoot,
      ["rev-parse", "HEAD"],
    )).trim();
    const baseCommit = await commitFixture(repositoryRoot, "base.txt", "base C15");
    const reviewedSurfaceCommit = await commitFixture(
      repositoryRoot,
      "reviewed-surface.txt",
      "reviewed C15 public surface",
    );
    const custodyRepairCommit = await commitFixture(
      repositoryRoot,
      "custody-repair.txt",
      "C15 custody repair",
    );
    const hostTrustCommit = await commitFixture(
      repositoryRoot,
      "host-trust.txt",
      "C15 host trust",
    );
    const bundleCodeAuthorityCommit = await commitFixture(
      repositoryRoot,
      "bundle-code-authority.txt",
      "C15 bundle code authority",
    );
    const signedReleaseProbeRepairCommit = await commitFixture(
      repositoryRoot,
      "signed-release-probe-repair.txt",
      "C15 signed release-probe repair",
    );
    await runSetupGit(repositoryRoot, ["switch", "-c", "candidate-side"]);
    await commitFixture(repositoryRoot, "candidate-side.txt", "candidate side");
    await runSetupGit(repositoryRoot, ["switch", "main"]);
    await runSetupGit(repositoryRoot, [
      "merge",
      "--no-ff",
      "candidate-side",
      "-m",
      "merge repaired C15",
    ]);
    const repository = await inspectReleaseSourceRepository({
      environment: {},
      repositoryRoot,
    });

    await expectRejection(
      inspectReleaseCandidateLineage(repository, {
        expectedBaseCommit: baseCommit,
        expectedBundleCodeAuthorityCommit: bundleCodeAuthorityCommit,
        expectedCustodyRepairCommit: custodyRepairCommit,
        expectedHostTrustCommit: hostTrustCommit,
        expectedQ14Commit: q14Commit,
        expectedSignedReleaseProbeRepairCommit: signedReleaseProbeRepairCommit,
        expectedSurfaceCommit: reviewedSurfaceCommit,
      }),
      "exact signed-release-probe repair commit as its only direct parent",
    );
  });

  test("rejects a multi-commit signed-release-probe-repair-to-candidate range", async () => {
    const repositoryRoot = await createRepository();
    const q14Commit = (await runSetupGit(
      repositoryRoot,
      ["rev-parse", "HEAD"],
    )).trim();
    const baseCommit = await commitFixture(repositoryRoot, "base.txt", "base C15");
    const reviewedSurfaceCommit = await commitFixture(
      repositoryRoot,
      "reviewed-surface.txt",
      "reviewed C15 public surface",
    );
    const custodyRepairCommit = await commitFixture(
      repositoryRoot,
      "custody-repair.txt",
      "C15 custody repair",
    );
    const hostTrustCommit = await commitFixture(
      repositoryRoot,
      "host-trust.txt",
      "C15 host trust",
    );
    const bundleCodeAuthorityCommit = await commitFixture(
      repositoryRoot,
      "bundle-code-authority.txt",
      "C15 bundle code authority",
    );
    const signedReleaseProbeRepairCommit = await commitFixture(
      repositoryRoot,
      "signed-release-probe-repair.txt",
      "C15 signed release-probe repair",
    );
    await commitFixture(repositoryRoot, "intermediate.txt", "candidate intermediate");
    await commitFixture(repositoryRoot, "candidate.txt", "repaired C15");
    const repository = await inspectReleaseSourceRepository({
      environment: {},
      repositoryRoot,
    });

    await expectRejection(
      inspectReleaseCandidateLineage(repository, {
        expectedBaseCommit: baseCommit,
        expectedBundleCodeAuthorityCommit: bundleCodeAuthorityCommit,
        expectedCustodyRepairCommit: custodyRepairCommit,
        expectedHostTrustCommit: hostTrustCommit,
        expectedQ14Commit: q14Commit,
        expectedSignedReleaseProbeRepairCommit: signedReleaseProbeRepairCommit,
        expectedSurfaceCommit: reviewedSurfaceCommit,
      }),
      "exact signed-release-probe repair commit as its only direct parent",
    );
  });

  test("rejects a signed-release-probe repair with the wrong bundle-code-authority parent", async () => {
    const repositoryRoot = await createRepository();
    const q14Commit = (await runSetupGit(
      repositoryRoot,
      ["rev-parse", "HEAD"],
    )).trim();
    const baseCommit = await commitFixture(repositoryRoot, "base.txt", "base C15");
    const reviewedSurfaceCommit = await commitFixture(
      repositoryRoot,
      "reviewed-surface.txt",
      "reviewed C15 public surface",
    );
    const custodyRepairCommit = await commitFixture(
      repositoryRoot,
      "custody-repair.txt",
      "C15 custody repair",
    );
    const hostTrustCommit = await commitFixture(
      repositoryRoot,
      "host-trust.txt",
      "C15 host trust",
    );
    const bundleCodeAuthorityCommit = await commitFixture(
      repositoryRoot,
      "bundle-code-authority.txt",
      "C15 bundle code authority",
    );
    await commitFixture(repositoryRoot, "wrong-parent.txt", "wrong signed-probe parent");
    const signedReleaseProbeRepairCommit = await commitFixture(
      repositoryRoot,
      "signed-release-probe-repair.txt",
      "C15 signed release-probe repair",
    );
    await commitFixture(repositoryRoot, "candidate.txt", "repaired C15");
    const repository = await inspectReleaseSourceRepository({
      environment: {},
      repositoryRoot,
    });

    await expectRejection(
      inspectReleaseCandidateLineage(repository, {
        expectedBaseCommit: baseCommit,
        expectedBundleCodeAuthorityCommit: bundleCodeAuthorityCommit,
        expectedCustodyRepairCommit: custodyRepairCommit,
        expectedHostTrustCommit: hostTrustCommit,
        expectedQ14Commit: q14Commit,
        expectedSignedReleaseProbeRepairCommit: signedReleaseProbeRepairCommit,
        expectedSurfaceCommit: reviewedSurfaceCommit,
      }),
      "signed-release-probe repair must have exact bundle-code-authority commit as its only direct parent",
    );
  });

  test("rejects a bundle-code-authority commit with the wrong host-trust parent", async () => {
    const repositoryRoot = await createRepository();
    const q14Commit = (await runSetupGit(
      repositoryRoot,
      ["rev-parse", "HEAD"],
    )).trim();
    const baseCommit = await commitFixture(repositoryRoot, "base.txt", "base C15");
    const reviewedSurfaceCommit = await commitFixture(
      repositoryRoot,
      "reviewed-surface.txt",
      "reviewed C15 public surface",
    );
    const custodyRepairCommit = await commitFixture(
      repositoryRoot,
      "custody-repair.txt",
      "C15 custody repair",
    );
    const hostTrustCommit = await commitFixture(
      repositoryRoot,
      "host-trust.txt",
      "C15 host trust",
    );
    await commitFixture(repositoryRoot, "wrong-parent.txt", "wrong bundle parent");
    const bundleCodeAuthorityCommit = await commitFixture(
      repositoryRoot,
      "bundle-code-authority.txt",
      "C15 bundle code authority",
    );
    const signedReleaseProbeRepairCommit = await commitFixture(
      repositoryRoot,
      "signed-release-probe-repair.txt",
      "C15 signed release-probe repair",
    );
    await commitFixture(repositoryRoot, "candidate.txt", "repaired C15");
    const repository = await inspectReleaseSourceRepository({
      environment: {},
      repositoryRoot,
    });

    await expectRejection(
      inspectReleaseCandidateLineage(repository, {
        expectedBaseCommit: baseCommit,
        expectedBundleCodeAuthorityCommit: bundleCodeAuthorityCommit,
        expectedCustodyRepairCommit: custodyRepairCommit,
        expectedHostTrustCommit: hostTrustCommit,
        expectedQ14Commit: q14Commit,
        expectedSignedReleaseProbeRepairCommit: signedReleaseProbeRepairCommit,
        expectedSurfaceCommit: reviewedSurfaceCommit,
      }),
      "bundle-code-authority commit must have exact host-trust repair as its only direct parent",
    );
  });

  test("rejects a merge commit as bundle code authority", async () => {
    const repositoryRoot = await createRepository();
    const q14Commit = (await runSetupGit(
      repositoryRoot,
      ["rev-parse", "HEAD"],
    )).trim();
    const baseCommit = await commitFixture(repositoryRoot, "base.txt", "base C15");
    const reviewedSurfaceCommit = await commitFixture(
      repositoryRoot,
      "reviewed-surface.txt",
      "reviewed C15 public surface",
    );
    const custodyRepairCommit = await commitFixture(
      repositoryRoot,
      "custody-repair.txt",
      "C15 custody repair",
    );
    const hostTrustCommit = await commitFixture(
      repositoryRoot,
      "host-trust.txt",
      "C15 host trust",
    );
    await runSetupGit(repositoryRoot, ["switch", "-c", "bundle-authority-side"]);
    await commitFixture(repositoryRoot, "bundle-authority-side.txt", "bundle authority side");
    await runSetupGit(repositoryRoot, ["switch", "main"]);
    await runSetupGit(repositoryRoot, [
      "merge",
      "--no-ff",
      "bundle-authority-side",
      "-m",
      "merge bundle code authority",
    ]);
    const bundleCodeAuthorityCommit = (await runSetupGit(
      repositoryRoot,
      ["rev-parse", "HEAD"],
    )).trim();
    const signedReleaseProbeRepairCommit = await commitFixture(
      repositoryRoot,
      "signed-release-probe-repair.txt",
      "C15 signed release-probe repair",
    );
    await commitFixture(repositoryRoot, "candidate.txt", "repaired C15");
    const repository = await inspectReleaseSourceRepository({
      environment: {},
      repositoryRoot,
    });

    await expectRejection(
      inspectReleaseCandidateLineage(repository, {
        expectedBaseCommit: baseCommit,
        expectedBundleCodeAuthorityCommit: bundleCodeAuthorityCommit,
        expectedCustodyRepairCommit: custodyRepairCommit,
        expectedHostTrustCommit: hostTrustCommit,
        expectedQ14Commit: q14Commit,
        expectedSignedReleaseProbeRepairCommit: signedReleaseProbeRepairCommit,
        expectedSurfaceCommit: reviewedSurfaceCommit,
      }),
      "bundle-code-authority commit must have exact host-trust repair as its only direct parent",
    );
  });

  test("rejects a multi-commit host-trust-to-bundle-code-authority range", async () => {
    const repositoryRoot = await createRepository();
    const q14Commit = (await runSetupGit(
      repositoryRoot,
      ["rev-parse", "HEAD"],
    )).trim();
    const baseCommit = await commitFixture(repositoryRoot, "base.txt", "base C15");
    const reviewedSurfaceCommit = await commitFixture(
      repositoryRoot,
      "reviewed-surface.txt",
      "reviewed C15 public surface",
    );
    const custodyRepairCommit = await commitFixture(
      repositoryRoot,
      "custody-repair.txt",
      "C15 custody repair",
    );
    const hostTrustCommit = await commitFixture(
      repositoryRoot,
      "host-trust.txt",
      "C15 host trust",
    );
    await commitFixture(repositoryRoot, "intermediate.txt", "bundle authority intermediate");
    const bundleCodeAuthorityCommit = await commitFixture(
      repositoryRoot,
      "bundle-code-authority.txt",
      "C15 bundle code authority",
    );
    const signedReleaseProbeRepairCommit = await commitFixture(
      repositoryRoot,
      "signed-release-probe-repair.txt",
      "C15 signed release-probe repair",
    );
    await commitFixture(repositoryRoot, "candidate.txt", "repaired C15");
    const repository = await inspectReleaseSourceRepository({
      environment: {},
      repositoryRoot,
    });

    await expectRejection(
      inspectReleaseCandidateLineage(repository, {
        expectedBaseCommit: baseCommit,
        expectedBundleCodeAuthorityCommit: bundleCodeAuthorityCommit,
        expectedCustodyRepairCommit: custodyRepairCommit,
        expectedHostTrustCommit: hostTrustCommit,
        expectedQ14Commit: q14Commit,
        expectedSignedReleaseProbeRepairCommit: signedReleaseProbeRepairCommit,
        expectedSurfaceCommit: reviewedSurfaceCommit,
      }),
      "bundle-code-authority commit must have exact host-trust repair as its only direct parent",
    );
  });

  test("rejects a host-trust commit with the wrong custody-repair parent", async () => {
    const repositoryRoot = await createRepository();
    const q14Commit = (await runSetupGit(
      repositoryRoot,
      ["rev-parse", "HEAD"],
    )).trim();
    const baseCommit = await commitFixture(repositoryRoot, "base.txt", "base C15");
    const reviewedSurfaceCommit = await commitFixture(
      repositoryRoot,
      "reviewed-surface.txt",
      "reviewed C15 public surface",
    );
    const custodyRepairCommit = await commitFixture(
      repositoryRoot,
      "custody-repair.txt",
      "C15 custody repair",
    );
    await commitFixture(repositoryRoot, "wrong-parent.txt", "wrong host-trust parent");
    const hostTrustCommit = await commitFixture(
      repositoryRoot,
      "host-trust.txt",
      "C15 host trust",
    );
    const { bundleCodeAuthorityCommit, signedReleaseProbeRepairCommit } =
      await commitBundleCodeAuthorityAndCandidate(repositoryRoot, "final C15");
    const repository = await inspectReleaseSourceRepository({
      environment: {},
      repositoryRoot,
    });

    await expectRejection(
      inspectReleaseCandidateLineage(repository, {
        expectedBaseCommit: baseCommit,
        expectedBundleCodeAuthorityCommit: bundleCodeAuthorityCommit,
        expectedCustodyRepairCommit: custodyRepairCommit,
        expectedHostTrustCommit: hostTrustCommit,
        expectedQ14Commit: q14Commit,
        expectedSignedReleaseProbeRepairCommit: signedReleaseProbeRepairCommit,
        expectedSurfaceCommit: reviewedSurfaceCommit,
      }),
      "host-trust commit must have exact custody repair as its only direct parent",
    );
  });

  test("rejects a merge commit as host trust", async () => {
    const repositoryRoot = await createRepository();
    const q14Commit = (await runSetupGit(
      repositoryRoot,
      ["rev-parse", "HEAD"],
    )).trim();
    const baseCommit = await commitFixture(repositoryRoot, "base.txt", "base C15");
    const reviewedSurfaceCommit = await commitFixture(
      repositoryRoot,
      "reviewed-surface.txt",
      "reviewed C15 public surface",
    );
    const custodyRepairCommit = await commitFixture(
      repositoryRoot,
      "custody-repair.txt",
      "C15 custody repair",
    );
    await runSetupGit(repositoryRoot, ["switch", "-c", "host-trust-side"]);
    await commitFixture(repositoryRoot, "host-trust-side.txt", "host-trust side");
    await runSetupGit(repositoryRoot, ["switch", "main"]);
    await runSetupGit(repositoryRoot, [
      "merge",
      "--no-ff",
      "host-trust-side",
      "-m",
      "merge host trust",
    ]);
    const hostTrustCommit = (await runSetupGit(
      repositoryRoot,
      ["rev-parse", "HEAD"],
    )).trim();
    const { bundleCodeAuthorityCommit, signedReleaseProbeRepairCommit } =
      await commitBundleCodeAuthorityAndCandidate(repositoryRoot, "final C15");
    const repository = await inspectReleaseSourceRepository({
      environment: {},
      repositoryRoot,
    });

    await expectRejection(
      inspectReleaseCandidateLineage(repository, {
        expectedBaseCommit: baseCommit,
        expectedBundleCodeAuthorityCommit: bundleCodeAuthorityCommit,
        expectedCustodyRepairCommit: custodyRepairCommit,
        expectedHostTrustCommit: hostTrustCommit,
        expectedQ14Commit: q14Commit,
        expectedSignedReleaseProbeRepairCommit: signedReleaseProbeRepairCommit,
        expectedSurfaceCommit: reviewedSurfaceCommit,
      }),
      "host-trust commit must have exact custody repair as its only direct parent",
    );
  });

  test("rejects a multi-commit custody-repair-to-host-trust range", async () => {
    const repositoryRoot = await createRepository();
    const q14Commit = (await runSetupGit(
      repositoryRoot,
      ["rev-parse", "HEAD"],
    )).trim();
    const baseCommit = await commitFixture(repositoryRoot, "base.txt", "base C15");
    const reviewedSurfaceCommit = await commitFixture(
      repositoryRoot,
      "reviewed-surface.txt",
      "reviewed C15 public surface",
    );
    const custodyRepairCommit = await commitFixture(
      repositoryRoot,
      "custody-repair.txt",
      "C15 custody repair",
    );
    await commitFixture(repositoryRoot, "intermediate.txt", "host-trust intermediate");
    const hostTrustCommit = await commitFixture(
      repositoryRoot,
      "host-trust.txt",
      "C15 host trust",
    );
    const { bundleCodeAuthorityCommit, signedReleaseProbeRepairCommit } =
      await commitBundleCodeAuthorityAndCandidate(repositoryRoot, "final C15");
    const repository = await inspectReleaseSourceRepository({
      environment: {},
      repositoryRoot,
    });

    await expectRejection(
      inspectReleaseCandidateLineage(repository, {
        expectedBaseCommit: baseCommit,
        expectedBundleCodeAuthorityCommit: bundleCodeAuthorityCommit,
        expectedCustodyRepairCommit: custodyRepairCommit,
        expectedHostTrustCommit: hostTrustCommit,
        expectedQ14Commit: q14Commit,
        expectedSignedReleaseProbeRepairCommit: signedReleaseProbeRepairCommit,
        expectedSurfaceCommit: reviewedSurfaceCommit,
      }),
      "host-trust commit must have exact custody repair as its only direct parent",
    );
  });

  test("rejects a custody repair with the wrong reviewed-surface parent", async () => {
    const repositoryRoot = await createRepository();
    const q14Commit = (await runSetupGit(
      repositoryRoot,
      ["rev-parse", "HEAD"],
    )).trim();
    const baseCommit = await commitFixture(repositoryRoot, "base.txt", "base C15");
    const reviewedSurfaceCommit = await commitFixture(
      repositoryRoot,
      "reviewed-surface.txt",
      "reviewed C15 public surface",
    );
    await commitFixture(repositoryRoot, "wrong-parent.txt", "wrong custody parent");
    const custodyRepairCommit = await commitFixture(
      repositoryRoot,
      "custody-repair.txt",
      "C15 custody repair",
    );
    const hostTrustCommit = await commitFixture(
      repositoryRoot,
      "host-trust.txt",
      "C15 host trust",
    );
    const { bundleCodeAuthorityCommit, signedReleaseProbeRepairCommit } =
      await commitBundleCodeAuthorityAndCandidate(repositoryRoot, "final C15");
    const repository = await inspectReleaseSourceRepository({
      environment: {},
      repositoryRoot,
    });

    await expectRejection(
      inspectReleaseCandidateLineage(repository, {
        expectedBaseCommit: baseCommit,
        expectedBundleCodeAuthorityCommit: bundleCodeAuthorityCommit,
        expectedCustodyRepairCommit: custodyRepairCommit,
        expectedHostTrustCommit: hostTrustCommit,
        expectedQ14Commit: q14Commit,
        expectedSignedReleaseProbeRepairCommit: signedReleaseProbeRepairCommit,
        expectedSurfaceCommit: reviewedSurfaceCommit,
      }),
      "custody repair must have exact reviewed public surface as its only direct parent",
    );
  }, 10_000);

  test("rejects a merge commit as the custody repair", async () => {
    const repositoryRoot = await createRepository();
    const q14Commit = (await runSetupGit(
      repositoryRoot,
      ["rev-parse", "HEAD"],
    )).trim();
    const baseCommit = await commitFixture(repositoryRoot, "base.txt", "base C15");
    const reviewedSurfaceCommit = await commitFixture(
      repositoryRoot,
      "reviewed-surface.txt",
      "reviewed C15 public surface",
    );
    await runSetupGit(repositoryRoot, ["switch", "-c", "custody-side"]);
    await commitFixture(repositoryRoot, "custody-side.txt", "custody side");
    await runSetupGit(repositoryRoot, ["switch", "main"]);
    await runSetupGit(repositoryRoot, [
      "merge",
      "--no-ff",
      "custody-side",
      "-m",
      "merge custody repair",
    ]);
    const custodyRepairCommit = (await runSetupGit(
      repositoryRoot,
      ["rev-parse", "HEAD"],
    )).trim();
    const hostTrustCommit = await commitFixture(
      repositoryRoot,
      "host-trust.txt",
      "C15 host trust",
    );
    const { bundleCodeAuthorityCommit, signedReleaseProbeRepairCommit } =
      await commitBundleCodeAuthorityAndCandidate(repositoryRoot, "final C15");
    const repository = await inspectReleaseSourceRepository({
      environment: {},
      repositoryRoot,
    });

    await expectRejection(
      inspectReleaseCandidateLineage(repository, {
        expectedBaseCommit: baseCommit,
        expectedBundleCodeAuthorityCommit: bundleCodeAuthorityCommit,
        expectedCustodyRepairCommit: custodyRepairCommit,
        expectedHostTrustCommit: hostTrustCommit,
        expectedQ14Commit: q14Commit,
        expectedSignedReleaseProbeRepairCommit: signedReleaseProbeRepairCommit,
        expectedSurfaceCommit: reviewedSurfaceCommit,
      }),
      "custody repair must have exact reviewed public surface as its only direct parent",
    );
  }, 10_000);

  test("rejects a multi-commit reviewed-surface-to-custody-repair range", async () => {
    const repositoryRoot = await createRepository();
    const q14Commit = (await runSetupGit(
      repositoryRoot,
      ["rev-parse", "HEAD"],
    )).trim();
    const baseCommit = await commitFixture(repositoryRoot, "base.txt", "base C15");
    const reviewedSurfaceCommit = await commitFixture(
      repositoryRoot,
      "reviewed-surface.txt",
      "reviewed C15 public surface",
    );
    await commitFixture(repositoryRoot, "intermediate.txt", "custody intermediate");
    const custodyRepairCommit = await commitFixture(
      repositoryRoot,
      "custody-repair.txt",
      "C15 custody repair",
    );
    const hostTrustCommit = await commitFixture(
      repositoryRoot,
      "host-trust.txt",
      "C15 host trust",
    );
    const { bundleCodeAuthorityCommit, signedReleaseProbeRepairCommit } =
      await commitBundleCodeAuthorityAndCandidate(repositoryRoot, "final C15");
    const repository = await inspectReleaseSourceRepository({
      environment: {},
      repositoryRoot,
    });

    await expectRejection(
      inspectReleaseCandidateLineage(repository, {
        expectedBaseCommit: baseCommit,
        expectedBundleCodeAuthorityCommit: bundleCodeAuthorityCommit,
        expectedCustodyRepairCommit: custodyRepairCommit,
        expectedHostTrustCommit: hostTrustCommit,
        expectedQ14Commit: q14Commit,
        expectedSignedReleaseProbeRepairCommit: signedReleaseProbeRepairCommit,
        expectedSurfaceCommit: reviewedSurfaceCommit,
      }),
      "custody repair must have exact reviewed public surface as its only direct parent",
    );
  });

  test("rejects a reviewed surface with the wrong base-C15 parent", async () => {
    const repositoryRoot = await createRepository();
    const q14Commit = (await runSetupGit(
      repositoryRoot,
      ["rev-parse", "HEAD"],
    )).trim();
    const baseCommit = await commitFixture(repositoryRoot, "base.txt", "base C15");
    await commitFixture(repositoryRoot, "wrong-parent.txt", "wrong surface parent");
    const reviewedSurfaceCommit = await commitFixture(
      repositoryRoot,
      "reviewed-surface.txt",
      "reviewed C15 public surface",
    );
    const custodyRepairCommit = await commitFixture(
      repositoryRoot,
      "custody-repair.txt",
      "C15 custody repair",
    );
    const hostTrustCommit = await commitFixture(
      repositoryRoot,
      "host-trust.txt",
      "C15 host trust",
    );
    const { bundleCodeAuthorityCommit, signedReleaseProbeRepairCommit } =
      await commitBundleCodeAuthorityAndCandidate(repositoryRoot, "repaired C15");
    const repository = await inspectReleaseSourceRepository({
      environment: {},
      repositoryRoot,
    });

    await expectRejection(
      inspectReleaseCandidateLineage(repository, {
        expectedBaseCommit: baseCommit,
        expectedBundleCodeAuthorityCommit: bundleCodeAuthorityCommit,
        expectedCustodyRepairCommit: custodyRepairCommit,
        expectedHostTrustCommit: hostTrustCommit,
        expectedQ14Commit: q14Commit,
        expectedSignedReleaseProbeRepairCommit: signedReleaseProbeRepairCommit,
        expectedSurfaceCommit: reviewedSurfaceCommit,
      }),
      "reviewed HRA v0.1.15 public surface must have exact base C15 as its only direct parent",
    );
  });

  test("rejects a merge commit as the reviewed surface", async () => {
    const repositoryRoot = await createRepository();
    const q14Commit = (await runSetupGit(
      repositoryRoot,
      ["rev-parse", "HEAD"],
    )).trim();
    const baseCommit = await commitFixture(repositoryRoot, "base.txt", "base C15");
    await runSetupGit(repositoryRoot, ["switch", "-c", "surface-side"]);
    await commitFixture(repositoryRoot, "surface-side.txt", "surface side");
    await runSetupGit(repositoryRoot, ["switch", "main"]);
    await runSetupGit(repositoryRoot, [
      "merge",
      "--no-ff",
      "surface-side",
      "-m",
      "merge reviewed surface",
    ]);
    const reviewedSurfaceCommit = (await runSetupGit(
      repositoryRoot,
      ["rev-parse", "HEAD"],
    )).trim();
    const custodyRepairCommit = await commitFixture(
      repositoryRoot,
      "custody-repair.txt",
      "C15 custody repair",
    );
    const hostTrustCommit = await commitFixture(
      repositoryRoot,
      "host-trust.txt",
      "C15 host trust",
    );
    const { bundleCodeAuthorityCommit, signedReleaseProbeRepairCommit } =
      await commitBundleCodeAuthorityAndCandidate(repositoryRoot, "repaired C15");
    const repository = await inspectReleaseSourceRepository({
      environment: {},
      repositoryRoot,
    });

    await expectRejection(
      inspectReleaseCandidateLineage(repository, {
        expectedBaseCommit: baseCommit,
        expectedBundleCodeAuthorityCommit: bundleCodeAuthorityCommit,
        expectedCustodyRepairCommit: custodyRepairCommit,
        expectedHostTrustCommit: hostTrustCommit,
        expectedQ14Commit: q14Commit,
        expectedSignedReleaseProbeRepairCommit: signedReleaseProbeRepairCommit,
        expectedSurfaceCommit: reviewedSurfaceCommit,
      }),
      "reviewed HRA v0.1.15 public surface must have exact base C15 as its only direct parent",
    );
  });

  test("rejects a multi-commit base-C15-to-reviewed-surface range", async () => {
    const repositoryRoot = await createRepository();
    const q14Commit = (await runSetupGit(
      repositoryRoot,
      ["rev-parse", "HEAD"],
    )).trim();
    const baseCommit = await commitFixture(repositoryRoot, "base.txt", "base C15");
    await commitFixture(repositoryRoot, "intermediate.txt", "surface intermediate");
    const reviewedSurfaceCommit = await commitFixture(
      repositoryRoot,
      "reviewed-surface.txt",
      "reviewed C15 public surface",
    );
    const custodyRepairCommit = await commitFixture(
      repositoryRoot,
      "custody-repair.txt",
      "C15 custody repair",
    );
    const hostTrustCommit = await commitFixture(
      repositoryRoot,
      "host-trust.txt",
      "C15 host trust",
    );
    const { bundleCodeAuthorityCommit, signedReleaseProbeRepairCommit } =
      await commitBundleCodeAuthorityAndCandidate(repositoryRoot, "repaired C15");
    const repository = await inspectReleaseSourceRepository({
      environment: {},
      repositoryRoot,
    });

    await expectRejection(
      inspectReleaseCandidateLineage(repository, {
        expectedBaseCommit: baseCommit,
        expectedBundleCodeAuthorityCommit: bundleCodeAuthorityCommit,
        expectedCustodyRepairCommit: custodyRepairCommit,
        expectedHostTrustCommit: hostTrustCommit,
        expectedQ14Commit: q14Commit,
        expectedSignedReleaseProbeRepairCommit: signedReleaseProbeRepairCommit,
        expectedSurfaceCommit: reviewedSurfaceCommit,
      }),
      "reviewed HRA v0.1.15 public surface must have exact base C15 as its only direct parent",
    );
  });

  test("rejects a base C15 with the wrong Q14 parent", async () => {
    const repositoryRoot = await createRepository();
    const q14Commit = (await runSetupGit(
      repositoryRoot,
      ["rev-parse", "HEAD"],
    )).trim();
    await commitFixture(repositoryRoot, "wrong-parent.txt", "wrong Q14 parent");
    const baseCommit = await commitFixture(repositoryRoot, "base.txt", "base C15");
    const reviewedSurfaceCommit = await commitFixture(
      repositoryRoot,
      "reviewed-surface.txt",
      "reviewed C15 public surface",
    );
    const custodyRepairCommit = await commitFixture(
      repositoryRoot,
      "custody-repair.txt",
      "C15 custody repair",
    );
    const hostTrustCommit = await commitFixture(
      repositoryRoot,
      "host-trust.txt",
      "C15 host trust",
    );
    const { bundleCodeAuthorityCommit, signedReleaseProbeRepairCommit } =
      await commitBundleCodeAuthorityAndCandidate(repositoryRoot, "repaired C15");
    const repository = await inspectReleaseSourceRepository({
      environment: {},
      repositoryRoot,
    });

    await expectRejection(
      inspectReleaseCandidateLineage(repository, {
        expectedBaseCommit: baseCommit,
        expectedBundleCodeAuthorityCommit: bundleCodeAuthorityCommit,
        expectedCustodyRepairCommit: custodyRepairCommit,
        expectedHostTrustCommit: hostTrustCommit,
        expectedQ14Commit: q14Commit,
        expectedSignedReleaseProbeRepairCommit: signedReleaseProbeRepairCommit,
        expectedSurfaceCommit: reviewedSurfaceCommit,
      }),
      "base commit must have exact Q14 as its only direct parent",
    );
  });

  test("rejects a merge commit as base C15", async () => {
    const repositoryRoot = await createRepository();
    const q14Commit = (await runSetupGit(
      repositoryRoot,
      ["rev-parse", "HEAD"],
    )).trim();
    await runSetupGit(repositoryRoot, ["switch", "-c", "base-side"]);
    await commitFixture(repositoryRoot, "base-side.txt", "base side");
    await runSetupGit(repositoryRoot, ["switch", "main"]);
    await runSetupGit(repositoryRoot, [
      "merge",
      "--no-ff",
      "base-side",
      "-m",
      "merge base C15",
    ]);
    const baseCommit = (await runSetupGit(
      repositoryRoot,
      ["rev-parse", "HEAD"],
    )).trim();
    const reviewedSurfaceCommit = await commitFixture(
      repositoryRoot,
      "reviewed-surface.txt",
      "reviewed C15 public surface",
    );
    const custodyRepairCommit = await commitFixture(
      repositoryRoot,
      "custody-repair.txt",
      "C15 custody repair",
    );
    const hostTrustCommit = await commitFixture(
      repositoryRoot,
      "host-trust.txt",
      "C15 host trust",
    );
    const { bundleCodeAuthorityCommit, signedReleaseProbeRepairCommit } =
      await commitBundleCodeAuthorityAndCandidate(repositoryRoot, "repaired C15");
    const repository = await inspectReleaseSourceRepository({
      environment: {},
      repositoryRoot,
    });

    await expectRejection(
      inspectReleaseCandidateLineage(repository, {
        expectedBaseCommit: baseCommit,
        expectedBundleCodeAuthorityCommit: bundleCodeAuthorityCommit,
        expectedCustodyRepairCommit: custodyRepairCommit,
        expectedHostTrustCommit: hostTrustCommit,
        expectedQ14Commit: q14Commit,
        expectedSignedReleaseProbeRepairCommit: signedReleaseProbeRepairCommit,
        expectedSurfaceCommit: reviewedSurfaceCommit,
      }),
      "base commit must have exact Q14 as its only direct parent",
    );
  });

  test("rejects a multi-commit Q14-to-base-C15 range", async () => {
    const repositoryRoot = await createRepository();
    const q14Commit = (await runSetupGit(
      repositoryRoot,
      ["rev-parse", "HEAD"],
    )).trim();
    await commitFixture(repositoryRoot, "intermediate.txt", "base intermediate");
    const baseCommit = await commitFixture(repositoryRoot, "base.txt", "base C15");
    const reviewedSurfaceCommit = await commitFixture(
      repositoryRoot,
      "reviewed-surface.txt",
      "reviewed C15 public surface",
    );
    const custodyRepairCommit = await commitFixture(
      repositoryRoot,
      "custody-repair.txt",
      "C15 custody repair",
    );
    const hostTrustCommit = await commitFixture(
      repositoryRoot,
      "host-trust.txt",
      "C15 host trust",
    );
    const { bundleCodeAuthorityCommit, signedReleaseProbeRepairCommit } =
      await commitBundleCodeAuthorityAndCandidate(repositoryRoot, "repaired C15");
    const repository = await inspectReleaseSourceRepository({
      environment: {},
      repositoryRoot,
    });

    await expectRejection(
      inspectReleaseCandidateLineage(repository, {
        expectedBaseCommit: baseCommit,
        expectedBundleCodeAuthorityCommit: bundleCodeAuthorityCommit,
        expectedCustodyRepairCommit: custodyRepairCommit,
        expectedHostTrustCommit: hostTrustCommit,
        expectedQ14Commit: q14Commit,
        expectedSignedReleaseProbeRepairCommit: signedReleaseProbeRepairCommit,
        expectedSurfaceCommit: reviewedSurfaceCommit,
      }),
      "base commit must have exact Q14 as its only direct parent",
    );
  });

  test("rejects an annotated release tag that targets another tag object", async () => {
    const repositoryRoot = await createRepository();
    await runSetupGit(repositoryRoot, [
      "tag",
      "-a",
      "candidate-object",
      "-m",
      "candidate",
    ]);
    await runSetupGit(repositoryRoot, [
      "tag",
      "-a",
      "v9.8.7",
      "candidate-object",
      "-m",
      "nested release tag",
    ]);
    const repository = await inspectReleaseSourceRepository({
      environment: {},
      repositoryRoot,
    });
    await expectRejection(
      inspectReleaseTag(repository, "v9.8.7"),
      "point directly to the candidate commit",
    );
  });

  test("rejects a publication commit that changes any extra path", async () => {
    const repositoryRoot = await createRepository();
    await writeFile(join(repositoryRoot, "release-download.json"), "candidate\n");
    await runSetupGit(repositoryRoot, ["add", "release-download.json"]);
    await runSetupGit(repositoryRoot, ["commit", "-m", "candidate C"]);
    const candidateCommit = (
      await runSetupGit(repositoryRoot, ["rev-parse", "HEAD"])
    ).trim();
    await writeFile(join(repositoryRoot, "release-download.json"), "published\n");
    await writeFile(join(repositoryRoot, "source.txt"), "changed too\n");
    await runSetupGit(repositoryRoot, ["add", "release-download.json", "source.txt"]);
    await runSetupGit(repositoryRoot, ["commit", "-m", "invalid publication P"]);
    const repository = await inspectReleaseSourceRepository({
      environment: {},
      repositoryRoot,
    });
    await expectRejection(
      inspectReleasePublicationTransition(repository, candidateCommit),
      "only release-download.json",
    );
  });

  test("rejects a merge commit as the publication transition", async () => {
    const repositoryRoot = await createRepository();
    await writeFile(join(repositoryRoot, "release-download.json"), "candidate\n");
    await runSetupGit(repositoryRoot, ["add", "release-download.json"]);
    await runSetupGit(repositoryRoot, ["commit", "-m", "candidate C"]);
    const candidateCommit = (
      await runSetupGit(repositoryRoot, ["rev-parse", "HEAD"])
    ).trim();
    await runSetupGit(repositoryRoot, ["switch", "-c", "side"]);
    await writeFile(join(repositoryRoot, "side.txt"), "side\n");
    await runSetupGit(repositoryRoot, ["add", "side.txt"]);
    await runSetupGit(repositoryRoot, ["commit", "-m", "side parent"]);
    await runSetupGit(repositoryRoot, ["switch", "main"]);
    await writeFile(join(repositoryRoot, "release-download.json"), "published\n");
    await runSetupGit(repositoryRoot, ["add", "release-download.json"]);
    await runSetupGit(repositoryRoot, ["commit", "-m", "publication-shaped parent"]);
    await runSetupGit(repositoryRoot, ["merge", "--no-ff", "side", "-m", "merge publication"]);
    const repository = await inspectReleaseSourceRepository({
      environment: {},
      repositoryRoot,
    });
    await expectRejection(
      inspectReleasePublicationTransition(repository, candidateCommit),
      "only direct parent",
    );
  });

  test("pins the fixed C15/P15/U/M/Q15/C16/C17 release objects", () => {
    expect(HRA_V0_C15_CANDIDATE_COMMIT).toBe(
      "0c7764da0dea0a71bbccca817539a02d8e4284d0",
    );
    expect(HRA_V0_P15_PUBLICATION_COMMIT).toBe(
      "d96173c3556799cb203a4d659f29856180838029",
    );
    expect(HRA_V0_P15_CONCURRENT_MAIN_COMMIT).toBe(
      "559c272f1bd7a2f1195f1af3c493b4f73a8fb3d2",
    );
    expect(HRA_V0_P15_INTEGRATION_BRIDGE_COMMIT).toBe(
      "af3296e59e2173e1e7737dee7a3194592de1105e",
    );
    expect(HRA_V0_Q15_SURFACE_COMMIT).toBe(
      "443448b79e9016e00d52501f047fce3a408de092",
    );
    expect(HRA_V0_C16_COMPATIBILITY_COMMIT).toBe(
      "4766793434e59cfe3fb3e8bf5fe57e2a28e72aeb",
    );
    expect(HRA_V0_C17_TIMEOUT_CAP_COMMIT).toBe(
      "112175bfdbcd6be0e3cca7ed43dd57e79453c00a",
    );
  });

  test("accepts the ordered C/P and C/U to M bridge followed by one direct Q surface", async () => {
    const topology = await createPublicationIntegrationTopology();

    const bridge = await inspectReleasePublicationIntegrationBridge(
      topology.repository,
      {
        candidateCommit: topology.candidateCommit,
        concurrentMainCommit: topology.concurrentMainCommit,
        integrationBridgeCommit: topology.integrationBridgeCommit,
        publicationCommit: topology.publicationCommit,
      },
    );
    expect(bridge).toMatchObject({
      concurrentMainCommit: topology.concurrentMainCommit,
      integrationBridgeCommit: topology.integrationBridgeCommit,
      publication: {
        candidateCommit: topology.candidateCommit,
        candidateContract: topology.candidateContract,
        publicationCommit: topology.publicationCommit,
        publicationContract: topology.publicationContract,
        status: "exact_candidate_publication_transition",
      },
      status: "exact_candidate_publication_concurrent_main_integration_bridge",
    });

    const surface = await inspectReleasePublicationIntegrationSurface(
      topology.repository,
      {
        candidateCommit: topology.candidateCommit,
        concurrentMainCommit: topology.concurrentMainCommit,
        integrationBridgeCommit: topology.integrationBridgeCommit,
        publicationCommit: topology.publicationCommit,
      },
    );
    expect(surface).toMatchObject({
      bridge,
      status: "verified_publication_integration_bridge_surface",
      surfaceCommit: topology.surfaceCommit,
    });
  });

  test("rejects U unless it is a sole child of C with C's exact release contract", async () => {
    const wrongParent = await createPublicationIntegrationTopology({
      concurrentIntermediate: true,
    });
    await expectRejection(
      inspectReleasePublicationIntegrationBridge(
        wrongParent.repository,
        integrationOptions(wrongParent),
      ),
      "concurrent main commit must have the tagged candidate as its only direct parent",
    );

    const rewrittenContract = await createPublicationIntegrationTopology({
      concurrentContract: "publication",
    });
    await expectRejection(
      inspectReleasePublicationIntegrationBridge(
        rewrittenContract.repository,
        integrationOptions(rewrittenContract),
      ),
      "concurrent main commit must preserve the candidate release contract exactly",
    );
  });

  test("rejects M unless its ordered parents are [P, U] and its contract is P", async () => {
    const reversedParents = await createPublicationIntegrationTopology({
      reverseBridgeParents: true,
    });
    await expectRejection(
      inspectReleasePublicationIntegrationBridge(
        reversedParents.repository,
        integrationOptions(reversedParents),
      ),
      "ordered direct parents [publication, concurrent main]",
    );

    const rewrittenContract = await createPublicationIntegrationTopology({
      bridgeContract: "candidate",
    });
    await expectRejection(
      inspectReleasePublicationIntegrationBridge(
        rewrittenContract.repository,
        integrationOptions(rewrittenContract),
      ),
      "integration bridge must preserve the publication release contract exactly",
    );
  });

  test("rejects Q unless it is a sole child of M with P's exact release contract", async () => {
    const wrongParent = await createPublicationIntegrationTopology({
      surfaceIntermediate: true,
    });
    await expectRejection(
      inspectReleasePublicationIntegrationSurface(
        wrongParent.repository,
        integrationOptions(wrongParent),
      ),
      "integration surface must have the integration bridge as its only direct parent",
    );

    const rewrittenContract = await createPublicationIntegrationTopology({
      surfaceContract: "candidate",
    });
    await expectRejection(
      inspectReleasePublicationIntegrationSurface(
        rewrittenContract.repository,
        integrationOptions(rewrittenContract),
      ),
      "integration surface must preserve the publication release contract exactly",
    );
  });

  test("accepts one single-parent migration followed by a normal H/A to A merge", async () => {
    const repositoryRoot = await createRepository();
    await writeFile(
      join(repositoryRoot, "release-download.json"),
      '{\n  "repository": "https://github.com/hraness/hra"\n}\n',
    );
    await runSetupGit(repositoryRoot, ["add", "release-download.json"]);
    await runSetupGit(repositoryRoot, ["commit", "-m", "publication P"]);
    const publicationCommit = (
      await runSetupGit(repositoryRoot, ["rev-parse", "HEAD"])
    ).trim();

    await runSetupGit(repositoryRoot, ["switch", "-c", "archive-pr"]);
    await writeFile(
      join(repositoryRoot, "release-download.json"),
      '{\n  "repository": "https://github.com/hraness/hra-v0"\n}\n',
    );
    await runSetupGit(repositoryRoot, ["add", "release-download.json"]);
    await runSetupGit(repositoryRoot, ["commit", "-m", "migrate archive coordinate"]);
    const repositoryMigrationCommit = (
      await runSetupGit(repositoryRoot, ["rev-parse", "HEAD"])
    ).trim();
    await writeFile(join(repositoryRoot, "side.txt"), "archive branch\n");
    await runSetupGit(repositoryRoot, ["add", "side.txt"]);
    await runSetupGit(repositoryRoot, ["commit", "-m", "archive branch work"]);

    await runSetupGit(repositoryRoot, ["switch", "main"]);
    await writeFile(join(repositoryRoot, "main.txt"), "main branch\n");
    await runSetupGit(repositoryRoot, ["add", "main.txt"]);
    await runSetupGit(repositoryRoot, ["commit", "-m", "main archive work"]);
    await runSetupGit(repositoryRoot, [
      "merge",
      "--no-ff",
      "archive-pr",
      "-m",
      "merge archive PR",
    ]);
    const repository = await inspectReleaseSourceRepository({
      environment: {},
      repositoryRoot,
    });

    expect(
      await inspectArchiveReleaseSurface(repository, publicationCommit),
    ).toEqual({
      publicationCommit,
      repositoryMigrationCommit,
      status: "verified_descendant_archive_surface",
      surfaceCommit: repository.commit,
    });
  });

  test("rejects a repository-coordinate migration made by a merge commit", async () => {
    const repositoryRoot = await createRepository();
    await writeFile(
      join(repositoryRoot, "release-download.json"),
      '{\n  "repository": "https://github.com/hraness/hra"\n}\n',
    );
    await runSetupGit(repositoryRoot, ["add", "release-download.json"]);
    await runSetupGit(repositoryRoot, ["commit", "-m", "publication P"]);
    const publicationCommit = (
      await runSetupGit(repositoryRoot, ["rev-parse", "HEAD"])
    ).trim();

    await runSetupGit(repositoryRoot, ["switch", "-c", "migration-side"]);
    await writeFile(join(repositoryRoot, "side.txt"), "side\n");
    await runSetupGit(repositoryRoot, ["add", "side.txt"]);
    await runSetupGit(repositoryRoot, ["commit", "-m", "side archive work"]);
    await runSetupGit(repositoryRoot, ["switch", "main"]);
    await writeFile(join(repositoryRoot, "main.txt"), "main\n");
    await runSetupGit(repositoryRoot, ["add", "main.txt"]);
    await runSetupGit(repositoryRoot, ["commit", "-m", "main archive work"]);
    await runSetupGit(repositoryRoot, [
      "merge",
      "--no-ff",
      "--no-commit",
      "migration-side",
    ]);
    await writeFile(
      join(repositoryRoot, "release-download.json"),
      '{\n  "repository": "https://github.com/hraness/hra-v0"\n}\n',
    );
    await runSetupGit(repositoryRoot, ["add", "release-download.json"]);
    await runSetupGit(repositoryRoot, ["commit", "-m", "merge migration"]);
    const repository = await inspectReleaseSourceRepository({
      environment: {},
      repositoryRoot,
    });

    await expectRejection(
      inspectArchiveReleaseSurface(repository, publicationCommit),
      "may not invent archive A without an archive A parent",
    );
  });

  test("rejects a rewrite and restore hidden on a merged side branch", async () => {
    const repositoryRoot = await createRepository();
    const historicalContract =
      '{\n  "repository": "https://github.com/hraness/hra"\n}\n';
    const archiveContract =
      '{\n  "repository": "https://github.com/hraness/hra-v0"\n}\n';
    await writeFile(
      join(repositoryRoot, "release-download.json"),
      historicalContract,
    );
    await runSetupGit(repositoryRoot, ["add", "release-download.json"]);
    await runSetupGit(repositoryRoot, ["commit", "-m", "publication P"]);
    const publicationCommit = (
      await runSetupGit(repositoryRoot, ["rev-parse", "HEAD"])
    ).trim();

    await runSetupGit(repositoryRoot, ["switch", "-c", "rewrite-side"]);
    await writeFile(
      join(repositoryRoot, "release-download.json"),
      '{\n  "repository": "https://github.com/attacker/hra"\n}\n',
    );
    await runSetupGit(repositoryRoot, ["add", "release-download.json"]);
    await runSetupGit(repositoryRoot, ["commit", "-m", "rewrite contract"]);
    await writeFile(
      join(repositoryRoot, "release-download.json"),
      historicalContract,
    );
    await runSetupGit(repositoryRoot, ["add", "release-download.json"]);
    await runSetupGit(repositoryRoot, ["commit", "-m", "restore contract"]);

    await runSetupGit(repositoryRoot, ["switch", "main"]);
    await writeFile(
      join(repositoryRoot, "release-download.json"),
      archiveContract,
    );
    await runSetupGit(repositoryRoot, ["add", "release-download.json"]);
    await runSetupGit(repositoryRoot, ["commit", "-m", "migrate archive coordinate"]);
    await runSetupGit(repositoryRoot, [
      "merge",
      "--no-ff",
      "rewrite-side",
      "-m",
      "merge restored side branch",
    ]);
    const repository = await inspectReleaseSourceRepository({
      environment: {},
      repositoryRoot,
    });

    await expectRejection(
      inspectArchiveReleaseSurface(repository, publicationCommit),
      "must preserve exact historical H or archive A release contract bytes",
    );
  });

  test("rejects every archive A to historical H edge", async () => {
    const repositoryRoot = await createRepository();
    const historicalContract =
      '{\n  "repository": "https://github.com/hraness/hra"\n}\n';
    const archiveContract =
      '{\n  "repository": "https://github.com/hraness/hra-v0"\n}\n';
    await writeFile(
      join(repositoryRoot, "release-download.json"),
      historicalContract,
    );
    await runSetupGit(repositoryRoot, ["add", "release-download.json"]);
    await runSetupGit(repositoryRoot, ["commit", "-m", "publication P"]);
    const publicationCommit = (
      await runSetupGit(repositoryRoot, ["rev-parse", "HEAD"])
    ).trim();

    for (const [contract, message] of [
      [archiveContract, "migrate archive coordinate"],
      [historicalContract, "downgrade archive coordinate"],
      [archiveContract, "restore archive coordinate"],
    ] as const) {
      await writeFile(
        join(repositoryRoot, "release-download.json"),
        contract,
      );
      await runSetupGit(repositoryRoot, ["add", "release-download.json"]);
      await runSetupGit(repositoryRoot, ["commit", "-m", message]);
    }
    const repository = await inspectReleaseSourceRepository({
      environment: {},
      repositoryRoot,
    });

    await expectRejection(
      inspectArchiveReleaseSurface(repository, publicationCommit),
      "may not contain an archive A to historical H edge",
    );
  });
});

type LinearPublicationTopology = Readonly<{
  candidateCommit: string;
  publicationCommit: string;
  repository: ReleaseRepositoryEvidence;
  surfaceCommit: string;
}>;

async function createLinearPublicationTopology(
  options: Readonly<{
    rewriteSurfaceContract?: boolean;
    surfaceIntermediate?: boolean;
  }> = {},
): Promise<LinearPublicationTopology> {
  const candidateContract = '{\n  "status": "candidate"\n}\n';
  const publicationContract = '{\n  "status": "published"\n}\n';
  const repositoryRoot = await createRepository();
  await writeFile(
    join(repositoryRoot, "release-download.json"),
    candidateContract,
  );
  await runSetupGit(repositoryRoot, ["add", "release-download.json"]);
  await runSetupGit(repositoryRoot, ["commit", "-m", "compatibility C16"]);
  await commitFixture(
    repositoryRoot,
    "timeout-cap.txt",
    "timeout cap C17",
  );
  await commitFixture(
    repositoryRoot,
    "latency.txt",
    "candidate C18",
  );
  const candidateCommit = (
    await runSetupGit(repositoryRoot, ["rev-parse", "HEAD"])
  ).trim();
  await writeFile(
    join(repositoryRoot, "release-download.json"),
    publicationContract,
  );
  await runSetupGit(repositoryRoot, ["add", "release-download.json"]);
  await runSetupGit(repositoryRoot, ["commit", "-m", "publication P16"]);
  const publicationCommit = (
    await runSetupGit(repositoryRoot, ["rev-parse", "HEAD"])
  ).trim();
  if (options.surfaceIntermediate === true) {
    await commitFixture(
      repositoryRoot,
      "surface-intermediate.txt",
      "surface intermediate",
    );
  }
  await writeFile(join(repositoryRoot, "surface.txt"), "surface Q16\n");
  await runSetupGit(repositoryRoot, ["add", "surface.txt"]);
  if (options.rewriteSurfaceContract === true) {
    await writeFile(
      join(repositoryRoot, "release-download.json"),
      candidateContract,
    );
    await runSetupGit(repositoryRoot, ["add", "release-download.json"]);
  }
  await runSetupGit(repositoryRoot, ["commit", "-m", "surface Q16"]);
  const surfaceCommit = (
    await runSetupGit(repositoryRoot, ["rev-parse", "HEAD"])
  ).trim();
  const repository = await inspectReleaseSourceRepository({
    environment: {},
    repositoryRoot,
  });
  return Object.freeze({
    candidateCommit,
    publicationCommit,
    repository,
    surfaceCommit,
  });
}

type PublicationIntegrationTopology = Readonly<{
  candidateCommit: string;
  candidateContract: string;
  concurrentMainCommit: string;
  integrationBridgeCommit: string;
  publicationCommit: string;
  publicationContract: string;
  repository: ReleaseRepositoryEvidence;
  repositoryRoot: string;
  surfaceCommit: string;
}>;

async function createPublicationIntegrationTopology(
  options: Readonly<{
    bridgeContract?: "candidate";
    concurrentContract?: "publication";
    concurrentIntermediate?: boolean;
    reverseBridgeParents?: boolean;
    surfaceContract?: "candidate";
    surfaceIntermediate?: boolean;
  }> = {},
): Promise<PublicationIntegrationTopology> {
  const candidateContract = '{\n  "status": "candidate"\n}\n';
  const publicationContract = '{\n  "status": "published"\n}\n';
  const repositoryRoot = await createRepository();
  await writeFile(
    join(repositoryRoot, "release-download.json"),
    candidateContract,
  );
  await runSetupGit(repositoryRoot, ["add", "release-download.json"]);
  await runSetupGit(repositoryRoot, ["commit", "-m", "candidate C"]);
  const candidateCommit = (
    await runSetupGit(repositoryRoot, ["rev-parse", "HEAD"])
  ).trim();
  await runSetupGit(repositoryRoot, [
    "tag",
    "-a",
    "v9.8.7",
    "-m",
    "candidate",
  ]);

  await runSetupGit(repositoryRoot, ["switch", "-c", "publication"]);
  await writeFile(
    join(repositoryRoot, "release-download.json"),
    publicationContract,
  );
  await runSetupGit(repositoryRoot, ["add", "release-download.json"]);
  await runSetupGit(repositoryRoot, ["commit", "-m", "publication P"]);
  const publicationCommit = (
    await runSetupGit(repositoryRoot, ["rev-parse", "HEAD"])
  ).trim();

  await runSetupGit(repositoryRoot, ["switch", "main"]);
  if (options.concurrentIntermediate === true) {
    await commitFixture(
      repositoryRoot,
      "concurrent-intermediate.txt",
      "concurrent intermediate",
    );
  }
  await writeFile(join(repositoryRoot, "concurrent.txt"), "concurrent main\n");
  await runSetupGit(repositoryRoot, ["add", "concurrent.txt"]);
  if (options.concurrentContract === "publication") {
    await writeFile(
      join(repositoryRoot, "release-download.json"),
      publicationContract,
    );
    await runSetupGit(repositoryRoot, ["add", "release-download.json"]);
  }
  await runSetupGit(repositoryRoot, ["commit", "-m", "concurrent main U"]);
  const concurrentMainCommit = (
    await runSetupGit(repositoryRoot, ["rev-parse", "HEAD"])
  ).trim();

  if (options.reverseBridgeParents !== true) {
    await runSetupGit(repositoryRoot, ["switch", "publication"]);
    await runSetupGit(repositoryRoot, [
      "merge",
      "--no-ff",
      "--no-commit",
      "main",
    ]);
  } else {
    await runSetupGit(repositoryRoot, [
      "merge",
      "--no-ff",
      "--no-commit",
      "publication",
    ]);
  }
  if (options.bridgeContract === "candidate") {
    await writeFile(
      join(repositoryRoot, "release-download.json"),
      candidateContract,
    );
    await runSetupGit(repositoryRoot, ["add", "release-download.json"]);
  }
  await runSetupGit(repositoryRoot, ["commit", "-m", "integration bridge M"]);
  const integrationBridgeCommit = (
    await runSetupGit(repositoryRoot, ["rev-parse", "HEAD"])
  ).trim();

  if (options.surfaceIntermediate === true) {
    await commitFixture(
      repositoryRoot,
      "surface-intermediate.txt",
      "surface intermediate",
    );
  }
  await writeFile(join(repositoryRoot, "surface.txt"), "archive surface Q\n");
  await runSetupGit(repositoryRoot, ["add", "surface.txt"]);
  if (options.surfaceContract === "candidate") {
    await writeFile(
      join(repositoryRoot, "release-download.json"),
      candidateContract,
    );
    await runSetupGit(repositoryRoot, ["add", "release-download.json"]);
  }
  await runSetupGit(repositoryRoot, ["commit", "-m", "archive surface Q"]);
  const surfaceCommit = (
    await runSetupGit(repositoryRoot, ["rev-parse", "HEAD"])
  ).trim();
  const repository = await inspectReleaseSourceRepository({
    environment: {},
    repositoryRoot,
  });
  return Object.freeze({
    candidateCommit,
    candidateContract,
    concurrentMainCommit,
    integrationBridgeCommit,
    publicationCommit,
    publicationContract,
    repository,
    repositoryRoot,
    surfaceCommit,
  });
}

function integrationOptions(
  topology: PublicationIntegrationTopology,
): Readonly<{
  candidateCommit: string;
  concurrentMainCommit: string;
  integrationBridgeCommit: string;
  publicationCommit: string;
}> {
  return Object.freeze({
    candidateCommit: topology.candidateCommit,
    concurrentMainCommit: topology.concurrentMainCommit,
    integrationBridgeCommit: topology.integrationBridgeCommit,
    publicationCommit: topology.publicationCommit,
  });
}

async function createRepository(): Promise<string> {
  const root = await createTemporaryDirectory("hra-release-repository-");
  await runSetupGit(root, ["init", "--initial-branch=main"]);
  await runSetupGit(root, ["config", "user.email", "release-test@hraness.com"]);
  await runSetupGit(root, ["config", "user.name", "HRA release test"]);
  await writeFile(join(root, "source.txt"), "canonical\n");
  await runSetupGit(root, ["add", "source.txt"]);
  await runSetupGit(root, ["commit", "-m", "initial"]);
  return root;
}

async function commitFixture(
  repositoryRoot: string,
  path: string,
  message: string,
): Promise<string> {
  await writeFile(join(repositoryRoot, path), `${message}\n`);
  await runSetupGit(repositoryRoot, ["add", path]);
  await runSetupGit(repositoryRoot, ["commit", "-m", message]);
  return (await runSetupGit(repositoryRoot, ["rev-parse", "HEAD"])).trim();
}

async function commitBundleCodeAuthorityAndCandidate(
  repositoryRoot: string,
  candidateMessage: string,
): Promise<Readonly<{
  bundleCodeAuthorityCommit: string;
  signedReleaseProbeRepairCommit: string;
}>> {
  const bundleCodeAuthorityCommit = await commitFixture(
    repositoryRoot,
    "bundle-code-authority.txt",
    "C15 bundle code authority",
  );
  const signedReleaseProbeRepairCommit = await commitFixture(
    repositoryRoot,
    "signed-release-probe-repair.txt",
    "C15 signed release-probe repair",
  );
  await commitFixture(repositoryRoot, "candidate.txt", candidateMessage);
  return Object.freeze({
    bundleCodeAuthorityCommit,
    signedReleaseProbeRepairCommit,
  });
}

async function createTemporaryDirectory(prefix: string): Promise<string> {
  const root = await realpath(await mkdtemp(join(tmpdir(), prefix)));
  temporaryRoots.push(root);
  return root;
}

async function runSetupGit(
  repositoryRoot: string,
  args: readonly string[],
): Promise<string> {
  const child = Bun.spawn(["/usr/bin/git", ...args], {
    cwd: repositoryRoot,
    env: setupEnvironment,
    stdin: "ignore",
    stderr: "pipe",
    stdout: "pipe",
  });
  const [stdout, stderr, exitCode] = await Promise.all([
    new Response(child.stdout).text(),
    new Response(child.stderr).text(),
    child.exited,
  ]);
  if (exitCode !== 0) {
    throw new Error(`git ${args[0] ?? "command"} failed: ${stderr.trim()}`);
  }
  return stdout;
}

async function expectRejection(
  promise: Promise<unknown>,
  expectedMessage: string,
): Promise<void> {
  let rejection: unknown;
  try {
    await promise;
  } catch (error) {
    rejection = error;
  }
  expect(rejection).toBeInstanceOf(Error);
  expect((rejection as Error).message).toContain(expectedMessage);
}
