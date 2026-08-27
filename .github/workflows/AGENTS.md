# Contents

- `ci.yml` – frozen dependency installation and bounded archive policy, manifest, and documentation verification.

# Guidelines

- Run on pull requests, pushes to `main`, and explicit manual dispatch.
- Keep `permissions` read-only, persist no checkout credential, and consume no repository secret.
- Pin Bun 1.3.14, Node 24 through `.node-version`, and every third-party action by a full commit SHA.
- Do not use `pull_request_target`, provider or release commands, production signing custody, publication, or artifact upload.
- Verify only the retained archive's source policies, manifests, agent guides, brand assets, repository scripts, and root README contract. Do not build or package the retired applications.
- Keep CI output free of credentials, account data, provider coordinates, local source paths, and unpublished provenance.
