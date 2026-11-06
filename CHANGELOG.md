# Changelog

Versions follow [semantic versioning](https://semver.org). The PyPI packages `limbowatch` and `limbowatch-cli`, the GitLab CI/CD component and the Actions action share one version number.

## 0.1.0 (2026-11-06)

First release: the watcher (Phase 4).

- `limbowatch scan` checks a project's lockfiles (read offline by OSV-Scanner 2.7.0) or a CycloneDX/SPDX SBOM against the [limbo feed](https://limbo.watch/feed/), and polls on GitHub the source repos the live tracker doesn't watch.
- Dependencies that can't be checked (range-only requirements, git and path installs, local packages, unreadable lockfiles, no known source repo) are reported with the reason, never dropped.
- Outputs: table, JSON, Markdown, SARIF 2.1.0 and GitLab Code Quality, with the CC BY 4.0 attribution. Exit 1 when a finding meets `--fail-on`.
- `--state` reports what's new, changed, now visible to scanners, or no longer affected.
- `--issues gitlab|gitea` keeps one issue per finding: confidential on GitLab, none opened in public Gitea/Forgejo repos unless allowed.
- GitLab CI/CD component (`gitlab.com/limbowatch/limbowatch-component`) and a composite action for GitHub, Gitea and Forgejo Actions.
- `limbowatch inventory` lists what would be checked and what can't.

The tracker commands (`track`, `publish`, `report`) that run [limbo.watch](https://limbo.watch) ship in the same package.
