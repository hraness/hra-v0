# HRA v0

[![HRA](https://hra-weld.vercel.app/opengraph-image)](https://hra-weld.vercel.app)

> [!IMPORTANT]
> This repository preserves HRA v0 and its final v0.1.14 prerelease. The
> current HRA is at [hra.sh](https://hra.sh) with source at
> [github.com/hraness/hra](https://github.com/hraness/hra).

**The original metaharness for Codex.** HRA v0 turns the Codex accounts you already use into
one durable system for planning work, delegating it, running it in parallel,
and bringing it back for review.

[Download for macOS](https://hra-weld.vercel.app/download) · [Website](https://hra-weld.vercel.app) ·
[Historical comparisons](https://hra-weld.vercel.app/alternatives) · [Current HRA](https://hra.sh)

> HRA v0.1.14 build 15 is the final archived prerelease for Apple Silicon Macs.
> Its exact source commit, annotated tag, runtime tree, manifest, checksum, and
> artifact hashes are published. The app uses an ad-hoc code seal; it is not
> Developer ID signed or notarized.

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
[download page](https://hra-weld.vercel.app/download) exposes the immutable
v0.1.14 build 15 prerelease from the HRA v0 archive. Download the DMG and
checksum there, verify the SHA-256, and follow the unknown-developer
instructions. The tagged candidate source and complete corresponding-source
archives remain attached to that release.

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
bun run --cwd apps/desktop package:macos:adhoc
```

The package command creates the self-contained DMG and checksum under
`apps/desktop/zig-out/release/macos/arm64`. The full release command and its
corresponding-source artifacts are documented in the
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
