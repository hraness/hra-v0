# HRA v0 (archived)

> [!IMPORTANT]
> HRA v0 was the retired desktop and hosted-web generation of HRA. This
> repository is retained as a read-only historical archive. Its Vercel site
> and Convex backend were shut down on August 27, 2026. Do not deploy or
> install HRA v0.
>
> The current HRA is a CLI maintained at
> [github.com/hraness/hra](https://github.com/hraness/hra), with documentation
> at [hra.sh](https://hra.sh).

The source, tags, GitHub prereleases, checksums, and release assets remain
available only as historical reference. v0.1.16 build 17 was the final HRA v0
release.

**The original metaharness for Codex.** HRA v0 turned the Codex accounts its users already had into
one durable system for planning work, delegating it, running it in parallel,
and bringing it back for review.

[Historical GitHub releases](https://github.com/hraness/hra-v0/releases) · [Current HRA](https://hra.sh)

> The final checked release contract recorded HRA 0.1.16 build 17 for Apple
> Silicon Macs. Its outer app, native host, and custody-authorizing helpers used
> HRA's self-managed certificate chain. Other HRA-owned nested executables,
> including the runtime/JIT gateway, retained pinned ad-hoc signatures. The
> package was not Developer ID signed or notarized and is no longer supported.

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

The archived source includes comparison pages that recorded those tradeoffs
using first-party sources available at the time.

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

## Historical release artifacts

The [GitHub Releases archive](https://github.com/hraness/hra-v0/releases)
retains tags v0.1.7 through v0.1.16 and the associated historical assets.
v0.1.11 remains tag-only. These packages are unsupported and are preserved for
provenance and compatibility research. Do not install or redistribute them as
a current HRA release.

The checked source retains the final release ledger, artifact hashes, and
architecture documentation. Provider-bound instructions and identifiers in
the source describe the retired system. They are not deployment instructions.

## Project and license

HRA v0 is read-only and receives no fixes, releases, or operational support.
Development continues in the separate
[current HRA repository](https://github.com/hraness/hra). HRA v0 was an independent project and was not
affiliated with, endorsed by, or sponsored by OpenAI. “OpenAI” and “Codex” are
used only to identify the product HRA interoperates with.

Read [CONTRIBUTING.md](CONTRIBUTING.md) and [SECURITY.md](SECURITY.md) for the
archive status. HRA-authored source is licensed under
[Apache License 2.0](LICENSE). Bundled and vendored components retain their own terms in
[THIRD_PARTY_NOTICES.md](THIRD_PARTY_NOTICES.md). See
[TRADEMARKS.md](TRADEMARKS.md) for mark use.
