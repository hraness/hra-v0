# HRA v0

[![HRA](https://hra-weld.vercel.app/opengraph-image)](https://hra-weld.vercel.app)

> [!IMPORTANT]
> This repository preserves HRA v0. Its generation-2 release ledger ends at the
> immutable v0.1.16 build 17 native compatibility release. The current HRA is
> at [hra.sh](https://hra.sh) with
> source at [github.com/hraness/hra](https://github.com/hraness/hra).

**The original metaharness for Codex.** HRA v0 turns the Codex accounts you already use into
one durable system for planning work, delegating it, running it in parallel,
and bringing it back for review.

[Download for macOS](https://hra-weld.vercel.app/download) · [Release history](https://hra-weld.vercel.app/releases) · [Website](https://hra-weld.vercel.app) ·
[Historical comparisons](https://hra-weld.vercel.app/alternatives) · [Current HRA](https://hra.sh)

> The checked release contract publishes HRA 0.1.16 build 17 for Apple Silicon
> Macs. The download page exposes only the exact source commit, annotated tag,
> runtime tree, manifest, checksum, and artifact hashes recorded by the
> contract. The outer
> app, native host, and custody-authorizing helpers use HRA's self-managed
> certificate chain. Other HRA-owned nested executables, including the exact
> runtime/JIT gateway, retain pinned ad-hoc signatures. The package is not Developer ID
> signed or notarized.

## Why HRA exists

Codex can already run several agents in parallel. HRA handles what happens
between those sessions: which work belongs together, which account may run it,
what a child task owes its parent, how a follow-up keeps continuity, and what to
do after a process stops at an uncertain moment.

HRA adds five things:

- **Several authorized accounts, kept separate.** Pair Codex accounts you own
  or are allowed to use without merging their credentials or provider sessions.
- **A durable task graph.** Parent work, bounded children, dependencies,
  ownership, questions, submissions, and review survive any one agent window.
- **Work-aware routing.** Wide work gets more reasoning room; bounded work can
  use a lighter lane; safe follow-ups stay on their owned conversation.
- **Recovery with evidence.** Durable receipts distinguish work that happened,
  work that did not, and work that must be contained instead of guessed or
  replayed.
- **Local execution authority.** Repositories, commands, raw transcripts,
  provider sessions, and Codex credentials stay on the paired Mac.

HRA does not combine subscriptions or bypass provider limits. Every account
remains subject to its own plan, organization policy, and
[OpenAI terms](https://openai.com/policies/terms-of-use/). Only group accounts
that are authorized for the same repository and data.

## Is HRA the right tool?

Choose HRA when one project needs several coordinated Codex sessions and the
coordination itself must be durable. The first-party Codex app is usually the
better starting point for a few independent sessions. A multi-provider IDE or
worktree manager may be a better fit when model choice or workspace isolation
is the main problem, and a remote client may be better when the main job is
checking an agent from your phone.

The [comparison pages](https://hra-weld.vercel.app/alternatives) explain those tradeoffs
using current first-party sources, including Codex app, OpenCode Desktop,
Paseo, Conductor, Superset, OpenChamber, and Happy Coder.

## How it works

The web control plane keeps bounded task and review state. The paired desktop
app keeps Codex account custody and runs work inside managed Git worktrees. A
renewable lease and generation-bound fences prevent an old runner or stale
claim from continuing to mutate task state.

```text
one outcome
    │
    ├── durable root task ──┬── bounded child
    │                      └── bounded child
    │
    └── review, recovery, and continuation
             │
             └── authorized Codex accounts on the paired Mac
```

See [Security architecture](SECURITY_ARCHITECTURE.md) for the complete trust
and data boundary.

## Install the prerelease

The native app targets Apple Silicon and macOS 13 or newer. The
[download page](https://hra-weld.vercel.app/download) publishes the exact HRA
v0.1.16 build 17 DMG, checksum, and manifest. Verify the SHA-256 and follow the
unknown-developer instructions before installing it.

The generation-2 [release history](https://hra-weld.vercel.app/releases)
records every tag from v0.1.7 through v0.1.16, all nine immutable GitHub
prereleases, and all 63 assets with their exact byte counts, SHA-256 digests,
and archive download links. v0.1.11 remains tag-only. Candidate C21 is
`2947402efe6363bf3bb41aef55c70a2823580c68`; annotated tag object
`188d8638b8d0cdf7ccaa73e2a0b07a2814f3782a` points directly to it. Publication
P16 `67e89e7909a56f5bfad1e16bb73801c9cd41503e` and independently accepted U16
`ce00d829f2097c071766b30cbcb4400e0a4c6be8` are C21's direct children.
Integration bridge M16 `f5e46ed6c27bcf96c4b13821398a53813505c297`
has ordered parents `[P16, U16]` and preserves P16's published download contract
byte for byte. Q16 is M16's single direct archive-surface child and promotes
the generation-2 ledger without changing that contract.

## Develop HRA v0

Repository development uses Bun 1.3.14 and Node.js 24. Native work additionally
requires Zig 0.16.0, Xcode Command Line Tools, and an Apple Silicon Mac.

```sh
bun install --frozen-lockfile
bun hra
```

Start the web control plane and its Convex development process with:

```sh
bun run web:hra
```

The web workspace needs a local Convex project before its first run. See the
[web guide](apps/web/README.md), [desktop guide](apps/desktop/README.md), and
[`taskctl` guide](apps/cli/README.md) for setup and architecture details.

## Verify a change

```sh
bun run check
bun run check:complete
```

On a supported Mac, also run:

```sh
bun run --cwd apps/desktop test:macos
bun run --cwd apps/desktop build:macos
bun run --cwd apps/desktop package:macos:structural
```

The structural package command uses an isolated ephemeral CMS identity and
places its signed result under `apps/desktop/zig-out/structural`. It does not
create a release DMG and cannot satisfy a production release gate. The
production command, signing-custody requirements, and corresponding-source
artifacts are documented in the
[desktop guide](apps/desktop/README.md#verification).

## Project and license

HRA v0 is archived. Security reports and narrowly scoped archival corrections
remain welcome, but feature development continues in the separate
[current HRA repository](https://github.com/hraness/hra). HRA v0 is an independent project and is not
affiliated with, endorsed by, or sponsored by OpenAI. “OpenAI” and “Codex” are
used only to identify the product HRA interoperates with.

Read [CONTRIBUTING.md](CONTRIBUTING.md) before opening a pull request. Report a
suspected vulnerability through [SECURITY.md](SECURITY.md), not a public issue.
HRA-authored source is licensed under [Apache License 2.0](LICENSE). Bundled and
vendored components retain their own terms in
[THIRD_PARTY_NOTICES.md](THIRD_PARTY_NOTICES.md). See
[TRADEMARKS.md](TRADEMARKS.md) for mark use.
