# Contents

- `workflows/` – credential-free source, test, build, and structural package verification for pull requests, `main`, and manual runs.

# Guidelines

- Keep default permissions read-only and make unspecified permissions unavailable.
- Pin every third-party action by a full commit SHA and disable persisted checkout credentials.
- Do not use repository secrets, `pull_request_target`, production signing custody, release publication, provider mutation, or artifact upload. Structural package verification may use only its isolated ephemeral nonrelease CMS fixture.
- Treat workflow names, commands, logs, and outputs as public data.
