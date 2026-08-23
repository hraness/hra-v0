# HRA v0 security policy

## Report a vulnerability

Report suspected vulnerabilities through [GitHub private vulnerability
reporting](https://github.com/hraness/hra-v0/security/advisories/new). Do not put
an exploit, secret, personal data, or other sensitive detail in a public issue
or discussion.

Include the affected commit or version, the component and configuration, steps
to reproduce the problem, its likely impact, and any known mitigation. Use
placeholder credentials and remove local paths, account identifiers, and
personal data from screenshots or logs.

If private vulnerability reporting is unavailable, open a public issue that
asks a maintainer to establish a private contact channel. Do not include
vulnerability details in that issue.

## Supported versions

HRA v0 is archived at v0.1.14. Maintainers assess reports against the archived
`main` branch and state any available mitigation in the advisory. No new
feature release or automatic update channel is promised. Reports about the
current HRA belong in the separate
[current repository](https://github.com/hraness/hra).

## Disclosure

Please allow maintainers time to investigate, reproduce, and prepare a fix
before public disclosure. Maintainers will coordinate disclosure through the
private advisory when the report is accepted.

The product trust boundaries and known limits are documented in
[SECURITY_ARCHITECTURE.md](SECURITY_ARCHITECTURE.md).
