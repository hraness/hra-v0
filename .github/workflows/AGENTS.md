# Contents

- `ci.yml` – frozen dependency installation, source verification, native macOS tests, and isolated structural package verification without production signing custody or large corresponding-source downloads.

# Guidelines

- Run on pull requests, pushes to `main`, and explicit manual dispatch.
- Keep `permissions` read-only, persist no checkout credential, and consume no repository secret. Only the immutable remote-release step may receive the job's automatic `github.token`, and only for fixed HRA v0 API reads.
- Pin Bun 1.3.14, Node 24 through `.node-version`, the Apple Silicon Zig archive by URL and SHA-256, and every third-party action by a full commit SHA.
- Do not use `pull_request_target`, provider or release commands, production signing custody, publication, or artifact upload. Structural package verification may create only its isolated ephemeral CMS identity and must remain ineligible for release.
- Verify the pinned Bun, WebKit, Git, and Dugite Native source boundary in CI without downloading their release archives. Full clean-tree release assembly fetches and verifies those archives locally.
- Keep CI output free of credentials, account data, provider coordinates, local source paths, and unpublished provenance.
