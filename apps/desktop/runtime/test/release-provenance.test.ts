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
  HRA_V0_CURRENT_REPOSITORY,
  HRA_V0_Q14_SURFACE_COMMIT,
  inspectArchiveReleaseSurface,
  inspectReleaseCandidateLineage,
  inspectReleasePublicationTransition,
  inspectReleaseSourceRepository,
  inspectReleaseTag,
} from "../release-provenance";

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

  test("binds C15 to exact Q14 as its sole direct parent", async () => {
    expect(HRA_V0_Q14_SURFACE_COMMIT).toBe(
      "ceb647f7a4a68546fc68ce5e70e770b73c8863eb",
    );
    const repositoryRoot = await createRepository();
    const q14Commit = (await runSetupGit(
      repositoryRoot,
      ["rev-parse", "HEAD"],
    )).trim();
    await writeFile(join(repositoryRoot, "candidate.txt"), "C15\n");
    await runSetupGit(repositoryRoot, ["add", "candidate.txt"]);
    await runSetupGit(repositoryRoot, ["commit", "-m", "candidate C15"]);
    const repository = await inspectReleaseSourceRepository({
      environment: {},
      repositoryRoot,
    });

    expect(await inspectReleaseCandidateLineage(repository, {
      expectedParentCommit: q14Commit,
    })).toEqual({
      candidateCommit: repository.commit,
      parentCommit: q14Commit,
      status: "exact_q14_candidate_child",
    });
  });

  test("rejects a C15 candidate with the wrong direct parent", async () => {
    const repositoryRoot = await createRepository();
    await writeFile(join(repositoryRoot, "candidate.txt"), "C15\n");
    await runSetupGit(repositoryRoot, ["add", "candidate.txt"]);
    await runSetupGit(repositoryRoot, ["commit", "-m", "candidate C15"]);
    const repository = await inspectReleaseSourceRepository({
      environment: {},
      repositoryRoot,
    });

    await expectRejection(
      inspectReleaseCandidateLineage(repository, {
        expectedParentCommit: "a".repeat(40),
      }),
      "exact Q14 as its only direct parent",
    );
  });

  test("rejects a merge commit as C15", async () => {
    const repositoryRoot = await createRepository();
    const q14Commit = (await runSetupGit(
      repositoryRoot,
      ["rev-parse", "HEAD"],
    )).trim();
    await runSetupGit(repositoryRoot, ["switch", "-c", "candidate-side"]);
    await writeFile(join(repositoryRoot, "candidate.txt"), "side\n");
    await runSetupGit(repositoryRoot, ["add", "candidate.txt"]);
    await runSetupGit(repositoryRoot, ["commit", "-m", "candidate side"]);
    await runSetupGit(repositoryRoot, ["switch", "main"]);
    await runSetupGit(repositoryRoot, [
      "merge",
      "--no-ff",
      "candidate-side",
      "-m",
      "merge candidate C15",
    ]);
    const repository = await inspectReleaseSourceRepository({
      environment: {},
      repositoryRoot,
    });

    await expectRejection(
      inspectReleaseCandidateLineage(repository, {
        expectedParentCommit: q14Commit,
      }),
      "exact Q14 as its only direct parent",
    );
  });

  test("rejects a multi-commit Q14-to-C15 range", async () => {
    const repositoryRoot = await createRepository();
    const q14Commit = (await runSetupGit(
      repositoryRoot,
      ["rev-parse", "HEAD"],
    )).trim();
    for (const [path, message] of [
      ["intermediate.txt", "intermediate"],
      ["candidate.txt", "candidate C15"],
    ] as const) {
      await writeFile(join(repositoryRoot, path), `${message}\n`);
      await runSetupGit(repositoryRoot, ["add", path]);
      await runSetupGit(repositoryRoot, ["commit", "-m", message]);
    }
    const repository = await inspectReleaseSourceRepository({
      environment: {},
      repositoryRoot,
    });

    await expectRejection(
      inspectReleaseCandidateLineage(repository, {
        expectedParentCommit: q14Commit,
      }),
      "exact Q14 as its only direct parent",
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
