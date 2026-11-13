# Security policy

Report a vulnerability in Limbowatch privately through GitHub: [Security → Report a vulnerability](https://github.com/limbowatch/limbowatch/security/advisories/new). Please don't open a public issue.

Supported: the latest release on PyPI and the matching GitLab CI/CD component version.

The CI integrations download OSV-Scanner from Google's GitHub releases and check it against the published SHA-256 sums, and install Limbowatch from a pinned release. Advisory data comes from GitHub and OSV; a wrong range in a repository advisory is the maintainers' to fix, and Limbowatch reports such ranges as possible findings rather than passing them.

What the scan reads, which hosts it contacts with what, and how to verify or restrict that yourself: [Security and data](docs/WATCHER.md#security-and-data).
