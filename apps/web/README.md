# HRA v0 web control plane

This archived workspace owns HRA v0's Convex task backend and human control
plane. `taskctl` consumes its versioned HTTP API from the sibling CLI
workspace. The canonical HRA v0 origin is `https://hra-weld.vercel.app`. The
current HRA lives at `https://hra.sh` in `https://github.com/hraness/hra`.

The task workspace also owns desktop-runner presence and dispatch. A task created from the web surface is committed atomically with its queued run only when a non-expired HRA gateway advertises the selected repository and free capacity. The browser subscribes to server-authenticated readiness and a bounded public display stream: reasoning summaries, assistant messages, content-free tool activity, and lifecycle state. It never connects directly to a desktop app and never receives raw reasoning, tool details, local paths, command output, or Codex credentials.

The same Convex deployment exposes a separate optional session-sync relay for
the desktop. It stores signed membership evidence, wrapped keys, opaque
routing coordinates, bounded encrypted `session_summary` records, replay
defenses, and paged cursors. It never receives a vault root, private key,
prompt, response, transcript, reasoning, tool data, account identity,
provider identifier, or filesystem path. Remote summaries are view-only and a
relay outage cannot block local desktop chat.

The control plane uses the shared System-first design system. A first visit follows the operating-system appearance, while explicit Light, Dark, and System choices persist under the shared browser preference. The authenticated UI keeps its navigation rail and bars mounted while the selected workspace and `Tasks`/`Access` stage changes. Those selections are addressable with the `workspace` and `surface` query parameters; they do not change WorkOS organization authority or Convex task ownership. On compact viewports the same rail becomes a focus-trapped left drawer.

## Local development

Use Bun 1.3.14 and Node 24. From this directory:

```sh
CONVEX_AGENT_MODE=anonymous bun x convex init
bun run convex:dev
```

In a second terminal, run `bun run dev:web`. The first command creates ignored `.convex/` state and `.env.local`; commit neither. Set the credential pepper through `convex env set` before exercising enrollment or agent authentication. Set the hosted mutation fingerprint key before exercising browser writes.

From the repository root, `bun run web:hra` runs this workspace's combined
Convex and Next.js development command. It serves the hosted control plane with
browser hot reloading and does not start the Zig host or private desktop
gateway. A browser cannot itself spawn Codex or receive arbitrary filesystem
authority; it can only delegate work to a separately running, authenticated
local helper. Use `bun hra` for the product-development loop with the real
Native bridge, Codex/filesystem authority, and Vite hot reloading.

The four `HRA_HOSTED_MUTATION_FINGERPRINT_KEY_*` variables belong only in the Convex deployment. The current key is required for hosted browser mutations and must be a canonical unpadded base64url encoding of exactly 32 random bytes; its version is a portable identifier of at most 64 characters. Existing deployments may keep the corresponding `OPRTE_*` names with their exact values. HRA names take over only when absent or byte-for-byte equal to the old names; a disagreement fails closed. The rename does not rotate keys or change the persisted HMAC namespaces. Convex HMACs the browser's semantic digest with the organization, workspace, principal, source, and key version before the generic mutation journal sees it. The browser digest, raw intent, title, comment, answer, transcript, and provider data are never stored or returned by the backend.

Rotation is two-phase. Install a new current key and version while moving the former pair to `PREVIOUS`, then retain both until every open attempt bearing the previous version has settled. Only one previous version is accepted. Missing, malformed, duplicated, or half-configured key pairs fail closed. Removing the previous pair while one of its attempts remains open also makes new fingerprint resolution fail closed, preventing a replay under the new key.

After the backend, WorkOS fixture, and web app are running, enroll the desktop with a dispatcher-scoped taskctl agent and map a returned `repo_...` identifier to a local repository as described in [`../desktop/README.md`](../desktop/README.md). The runner uses the same local HTTP origin during development. The web readiness strip remains offline or blocked until the gateway's first accepted heartbeat; this is expected and does not prevent read-only task supervision.

WorkOS is optional for the provider-neutral agent-domain tests. Human HTTP routes always require a signed WorkOS access token. Configure `WORKOS_API_KEY`, `WORKOS_CLIENT_ID`, `WORKOS_COOKIE_PASSWORD`, and `NEXT_PUBLIC_WORKOS_REDIRECT_URI` in the Next.js environment, and configure the matching API key and client ID in the Convex deployment environment. Convex derives the two supported production issuers from that client ID: `https://api.workos.com/` and `https://api.workos.com/user_management/<client-id>`. An environment-provided issuer override is not accepted. AuthKit exposes `/auth/sign-in`, `/auth/sign-up`, and `/auth/callback`; the browser access token is forwarded to Convex through `ConvexProviderWithAuth` and is not persisted by the app.

The signed local acceptance harness may replace WorkOS with an exact-loopback server. Before pushing Convex functions, set `TASKCTL_LOCAL_FIXTURES_ENABLED=true`, `TASKCTL_LOCAL_FIXTURE_ISSUER`, and `TASKCTL_LOCAL_FIXTURE_JWKS_URL` in the deployment environment so `auth.config.ts` can register its RS256 provider. The issuer and JWKS URL must both be loopback URLs. Set `WORKOS_API_HOSTNAME=127.0.0.1`, `WORKOS_API_HTTPS=false`, and `WORKOS_API_PORT` to route the WorkOS SDK to the same fake server. This changes the provider endpoint only: `/v1/organizations`, `/v1/workspaces`, and `/v1/agents` still reject missing, unsigned, wrong-issuer, and incorrectly organization-bound JWTs.

`POST /v1/auth/refresh` accepts the refresh token only in `Authorization: Bearer ...`, optionally selects a WorkOS organization from its JSON body, rotates the returned refresh token, and deliberately disables SDK retries so an ambiguous refresh cannot consume a token twice.

Organization provisioning leases the owner-membership step and durably marks the one allowed membership create before sending its zero-retry WorkOS request. Once marked, every retry is poll-only, including after an indeterminate response or an eventually consistent empty list. This prevents duplicate memberships; the deliberate tradeoff is that a crash after the marker commits but before the request is sent requires operator recovery instead of an automatic second create.

Configure `WORKOS_WEBHOOK_SECRET` in the Convex deployment and send WorkOS webhooks to `POST /webhooks/workos`. The route verifies the signature over the exact raw body before WorkOS parses JSON. It projects `organization.created`, `organization.updated`, `organization.deleted`, `organization_membership.created`, `organization_membership.updated`, and `organization_membership.deleted`; other valid signed events receive an idempotent ignored receipt. Receipts use the WorkOS event ID and remain for 30 days.

Two leased, paginated Convex jobs run every 15 minutes. One rechecks projected membership IDs, including provider-side deletion; the other enumerates active, inactive, and pending provider memberships for every projected WorkOS organization so a missed create webhook is recoverable. Bounded runs schedule immediate cursor-based continuations instead of waiting for the next interval. Provider calls remain in actions, and projection writes remain in transactions.

The workspace serves the canonical `hra-weld.vercel.app` origin. Local `bun run build`
compiles the application without provider mutation. Vercel uses the separate
checked build entry in `vercel.json`: only its exact Production target may
deploy Convex functions to `benevolent-akita-439`. A generated Preview skips
Convex deployment and builds an anonymous app-only client of the exact
`benevolent-akita-439.convex.cloud` and `benevolent-akita-439.convex.site`
public endpoints. Custom staging and every unrecognized provider target fail
closed. The Next.js configuration binds every verified Vercel deployment to
the registered `hra-v0` project and exact Git object through
`X-Hraness-Delivery-Proof`. It preserves HRA v0's security and private-cache
headers, and adds `X-Robots-Tag: noindex, nofollow, noarchive` to generated
Preview responses. Session sync remains fail-closed while
`HRA_SESSION_SYNC_ENABLED` is absent or `false`; the unchanged
`OPRTE_SESSION_SYNC_ENABLED` value remains a fallback, and conflicting names
fail closed. Enable it only after the
exact WorkOS application, Convex environment, desktop public coordinates, and
production HTTP route readbacks pass for the same source revision.

## Archived production continuity

HRA v0 stays available at `https://hra-weld.vercel.app` while current HRA uses
`https://hra.sh`. Keep the old deployment, data, credentials, storage
identifiers, release assets, and runtime protocol identities in place. Do not
copy any of them into current HRA.

The immutable v0.1.14 build 15 publication has three fixed Git identities:

- Candidate C is `7b39c459827b2acf45aa2d911c94fdb5d4f37860`.
- Publication P is `6221f79b745f154882080936b961ff431569f33e`.
- Annotated tag object `37ed37afb39cacfd6a51044cf7f3c1b873571aa3`
  points directly to C.

The seven-asset GitHub prerelease and P's release evidence are immutable in
`hraness/hra-v0`. While v0.1.15 is a candidate, `release-download.json` names
the new version and build but carries null publication evidence. The web app
therefore exposes no candidate DMG, checksum, or manifest URL. Keep
`HRA_RELEASE_PUBLICATION_COMMIT_ALLOWLIST` fixed at P in Vercel Production and
Preview through C15. The C15/P15 provider gate consumes only that publication
allowlist. It strips both publication and archive-surface allowlist records
before the Next.js child build, and does not require or consume
`HRA_V0_SURFACE_COMMIT_ALLOWLIST`. Archive-ledger and surface-authority
promotion belong to a later, separately reviewed Q15 contract.

Rename the existing Vercel project in place from `hra` to `hra-v0`. Preserve
the existing project identity, READY deployment, and `hra-weld.vercel.app`
fallback. Connect it to `hraness/hra-v0`. Keep automatic Vercel system
variables enabled because the source gate requires Vercel's own target, Git
provider, repository, branch, and full commit SHA evidence.

The public `/releases` page is generated from the checked root
`release-history.json` ledger. The remote gate verifies its eight annotated
tags, seven immutable releases, 49 assets, and v0.1.11 tag-only state against
GitHub after the repository rename. It is credential-free outside GitHub
Actions; Required CI uses only its automatic read-only installation token for
the three fixed HRA v0 API reads. The public
`/.well-known/hra.json` marker binds archive generation 0 to the checked
numeric GitHub repository ID and final v0.1.14 publication identity for domain
cutover and rollback checks.

Keep the public `NEXT_PUBLIC_CONVEX_URL` and
`NEXT_PUBLIC_CONVEX_SITE_URL` records scoped to Production and Preview with the
exact `benevolent-akita-439` URLs. Keep the Convex deploy key,
`SUITE_IDENTITY_RECEIPT_KEY_VERSION`, `SUITE_OIDC_COOKIE_SECRET`,
`NEXT_PUBLIC_SITE_URL=https://hra-weld.vercel.app`, and optional PostHog token
scoped to Production only. Preview must remain free of production capability.
Do not place Convex-only keyrings, session flags, hosted-mutation keys, taskctl
peppers, WorkOS webhook secrets, or local fixture settings in Vercel.

The existing Convex project has immutable project ID `2680173`, team ID
`513923`, team slug `cclrte`, and current name and slug `HRA` / `hra`. Rename
that project in place to `HRA v0` / `hra-v0` before current HRA claims the clean
name. Preserve Production deployment ID `4677913`, name
`benevolent-akita-439`, reference `production`, region `aws-us-east-1`, and the
public `.convex.cloud` and `.convex.site` URLs.

Bind the rename to the immutable project ID. The Management API operation is
`PATCH /v1/projects/2680173` with body
`{"name":"HRA v0","slug":"hra-v0"}`. Perform it in the signed-in Convex
dashboard or through a reviewed client that reads its personal token from a
mode-0600 file and redacts foreign errors. Never put that token in argv, an
environment variable, shell history, or terminal output.

Before and after the rename, read only these non-secret records:

- `GET /v1/projects/2680173`.
- `GET /v1/deployments/benevolent-akita-439`.
- `GET /v1/deployments/benevolent-akita-439/list_deploy_keys`.
- Environment variable names from
  `bun x convex env list --names-only --deployment benevolent-akita-439`.

Require unchanged team, project ID, Production deployment identity and URL,
environment-name set, and deploy-key IDs, names, permissions, expiry, and
last-used timestamps. Update confirmed operator selectors from `cclrte:hra` to
`cclrte:hra-v0`; source selects the deployment by name and needs no selector
change. Do not rotate keys, rewrite environment values, move data, or delete a
deployment as part of the rename.

Verify the fallback root, `/download`, authentication callback, release asset
links, and security headers before removing `hra.sh` from the v0 Vercel
project. Update the external OIDC redirect allowlist to the fallback callback
before exercising authentication. Once current HRA has claimed the GitHub,
Vercel, Convex, and domain names, rollback must preserve the `hra-v0` names.
It must never evict the current product.

### v0.1.15 recovery publication

The create-only deploy-key and shared-authority procedures above are initialization
and recovery guidance. They are not v0.1.15 publication steps. Preserve the
verified v0.1.14 authorities throughout C15, P15, provider readback, installed-app
acceptance, and the bounded recovery window. Do not create or rotate the HRA
deploy key, cookie or identity-link secret, Accounts entry, HRA keyring, or
receipt-key selector for this recovery release.

Use this order for the v0.1.15 recovery publication:

1. Read back that the archived HRA v0 Vercel project remains publication-frozen,
   has no deployment in flight, and retains its unchanged READY rollback
   anchor. Preserve its bounded rollback key without rotating or recreating it.
2. Read back the existing HRA v0 project, its `hraness/hra-v0` Git link, exact build commands,
   environment-name inventory, and environment scoping. Preserve every existing
   deploy, cookie, Suite identity, WorkOS, and Convex selector authority without
   exposing or rewriting its value. Preview must remain free of production-only
   authority.
3. Read back the existing Accounts HRA entry, HRA-only identity-link keyring,
   and receipt-key selector with the checked audits. Treat any drift as a stop;
   do not repair it by generating or appending a replacement during release.
4. From exact candidate commit C15 in `hraness/hra-v0`, the sole direct child
   of the reviewed signed-release-probe repair, complete the full package, then
   follow the desktop release runbook to create and push the
   direct annotated `v0.1.15` tag and
   publish the exact seven-asset immutable GitHub prerelease. Fill the
   working-tree publication contract from C15's emitted evidence and require
   `bun run verify:remote-release` to read back exact remote names, byte counts,
   SHA-256 digests, checksum, manifest, DMG binding, and corresponding-source
   binding before committing P15. Create P15 as the exact contract-only child,
   push it, and require the green Required CI source-and-remote readback for
   that exact P15. P15 changes only `release-download.json`. Preserve the
   v0.1.14 publication allowlist throughout C15. A Git
   build of candidate C15 may proceed against the unchanged backend authority;
   it must not create or rotate provider authority. The automatic build of
   published P15 must then refuse against the retained v0.1.14 allowlist.
5. Only after Required succeeds for exact P15, replace
   `HRA_RELEASE_PUBLICATION_COMMIT_ALLOWLIST` with P15 in Production and Preview.
   This allowlist update is the only environment write for v0.1.15. Redeploy
   exact P15, then read back its canonical Git SHA, complete build commands,
   unchanged environment inventory and scoping, READY state, production routes,
   release delivery, discovery, and OIDC endpoints before enabling or exercising
   the installation handoff.
6. Preserve all predecessor and HRA backend authorities through installed-app
   acceptance and the bounded rollback window. Their later disposition is a
   separate handoff decision, not part of v0.1.15 publication.

Throughout C15 and P15, keep `release-history.json`, `/releases`, and
`/.well-known/hra.json` anchored to the exact v0.1.14 generation-0 evidence.
The staged download contract is not archive deployment identity. Adding
v0.1.15 to the compatibility ledger or changing archive surface authority is a
future Q15 review, never an implicit side effect of publishing P15.

The existing annotated `v0.1.11` tag object
`e4c171e33e414d74a36791fc8577cbfbcef8e52e` points directly to
`5a2a9842cacc75fee42ab8e23ca8c215a643e21e`, but has no GitHub release or
assets. Treat it as retired tag-only evidence, never as publication or
installation authority.

The immutable v0.1.14 build 15 prerelease remains the current published
predecessor while v0.1.15 is a candidate, and remains the frozen forward-recovery
origin after v0.1.15 publication. Its direct annotated tag object
`37ed37afb39cacfd6a51044cf7f3c1b873571aa3` points to
`7b39c459827b2acf45aa2d911c94fdb5d4f37860`, and publication commit
`6221f79b745f154882080936b961ff431569f33e` records the release evidence. Preserve
its exact assets and original handoff backup. Do not retire, replace, relabel,
or launch that app while the v0.1.14-to-v0.1.15 forward recovery is pending.

## Public product pages

`/download` links to the exact Apple Silicon GitHub prerelease named in
`app/site.ts` only when the release contract is published. A candidate exposes
no download, checksum, or manifest URL. The published surface discloses that the outer app,
native host, and custody-authorizing helpers use HRA's self-managed CMS authority.
Other HRA-owned nested executables retain pinned ad-hoc signatures, including
the exact runtime/JIT gateway. The package is not Developer ID
signed or notarized. The web workspace never holds signing custody or release
authority.

`/alternatives` and its static child routes compare HRA with adjacent tools.
Every positive competitor claim must cite a current first-party source, every
page carries a review date, and “not documented” must never be presented as
proof of absence. These routes remain public when WorkOS is configured; exact
near-miss and control-plane routes remain protected.

## Hraness suite account

The authenticated rail includes an optional Hraness account status beside the human controls. This is additive subscription identity only. WorkOS remains authoritative for the human, organization, membership, and organization role; Convex remains authoritative for workspace roles and task state. A suite alias never identifies an agent, credential, session, desktop runner, or repository, and suite features do not gate an HRA capability.

`/api/suite-auth/[...all]` is HRA's OAuth 2.1/OIDC relying-party route for the canonical `account.hraness.com` service. Access and refresh tokens remain encrypted in server-only `HttpOnly` cookies. The browser receives only the bounded suite session view and short-lived signed receipts; it does not persist provider tokens or send them to Convex.

Linking requires both a live Hraness session and a currently authorized WorkOS human with an active projected organization membership. Convex mints a four-minute HMAC proof bound to that WorkOS subject, persists the challenge, verifies the returned link receipt, and atomically rejects both local-human-to-second-account and account-to-second-human conflicts. Entitlement receipts are verified with the same environment-scoped keyring before a monotonic revision/observation projection is stored. The public query labels that projection `fresh`, `stale`, or `unverified` and returns no receipt signature or secret.

Product-local identity linking fails closed until the HRA runtimes are configured:

- The web host needs `NEXT_PUBLIC_SITE_URL=https://hra-weld.vercel.app`, a distinct `SUITE_OIDC_COOKIE_SECRET`, and `SUITE_IDENTITY_RECEIPT_KEY_VERSION`. Missing or mismatched values make the suite route return `503 SUITE_OIDC_UNAVAILABLE`.
- Deploy exact Suite Accounts v0.3.0 overlap support before changing either receipt keyring. Generate a fresh independent secret as the canonical unpadded base64url encoding of at least 32 random bytes. The HRA Convex `SUITE_IDENTITY_LINK_KEYS` keyring contains only the `hra:production:v1` entry. Accounts appends that same HRA entry alongside its unrelated existing entry. Never copy the unrelated Accounts key into HRA. Both environments use `SUITE_IDENTITY_RECEIPT_KEY_VERSION=v1`.
- The archived deployment admits exactly one HRA production/v1 key. Extra HRA versions, development entries, non-HRA entries, a selector other than `v1`, and malformed configuration make proof and receipt actions return `unavailable`. Rotate only through a later reviewed contract that restores bounded multi-key verification. No predecessor OPRTE/Kitchen receipt key is expected to exist, and the predecessor receipt authority being unavailable or invalid is not a rollout health gate.
- The ordinary hosted WorkOS and HRA Convex configuration described above must also be live, because suite linking reuses the existing WorkOS human and active organization-membership authorization rather than creating another product principal.

WorkOS-to-Hraness identity linking remains unavailable until the web session
and HRA receipt keyring are configured. Missing suite configuration does not
block WorkOS sign-in or any HRA task capability.

## Deterministic browser lab

HRA web has a credential-free Direct composition that renders the real task workspace through the same app-owned props and action port used by the live Convex adapter. It does not mount WorkOS, construct a Convex client, import generated APIs, or claim to simulate provider sessions and database transaction semantics.

The workbench also mounts the shared System-first appearance provider with a concrete light pre-bootstrap fallback. Its final toolbar action is the same one-trigger Light/Dark/System menu used by production, so the deterministic surface exercises persisted preference, keyboard operation, and theme-relative task presentation without importing any production identity or transport adapter.

Start the scenario workbench or run its bounded Chromium evidence pass from the repository root:

```sh
bun run direct:hra:web
bun run verify:hra:web:direct
```

From this directory, `bun run test:direct` checks the strict world parser, inferred definition, session-owned exact action scripts and deterministic backend, canonical probe/coverage wire parsing, verifier policy, and production-exclusion boundary. `bun run build:direct` compiles only the isolated Vite lab. `bun run build` compiles the Next.js application and rejects any resolved or emitted Hugeicons module. Run `bun run check:direct-boundary` as a separate production-boundary check.

The browser verifier exercises representative read, mutation, failure, and retry paths at wide, stacked, and compact viewports. It waits for identical canonical probes, rejects console, page, request, pending-work, and script-drain failures, then writes ignored screenshots and an atomic manifest below `artifacts/direct/hra-web`.

These scenarios are deterministic UI evidence. WorkOS authentication and organization switching, real Convex subscriptions and transactions, HTTP/CLI interoperability, and hosted deployment remain direct or mixed-evidence gates and are not relabeled as Direct coverage.
