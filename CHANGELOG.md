# Changelog

Versions follow [semantic versioning](https://semver.org). The PyPI packages `limbowatch` and `limbowatch-cli`, the GitLab CI/CD component and the Actions action share one version number.

## 0.1.0 (2026-11-06)

First release: the watcher (Phase 4).

- `limbowatch scan` checks a project's lockfiles (read offline by OSV-Scanner 2.7.0) or a CycloneDX/SPDX SBOM against the [limbo feed](https://limbo.watch/feed/), and polls on GitHub the source repos the live tracker doesn't watch.
- Dependencies that can't be checked (range-only requirements, git and path installs, local packages, unreadable lockfiles, no known source repo) are reported with the reason, never dropped.
- Ten output formats from one scan (`-o FORMAT=FILE`, repeatable): a table grouped by lockfile with the upgrade that clears each package and a PASSED/FAILED verdict; JSON (`schema_version` 1, with summary and gate); Markdown; standalone HTML; SARIF 2.1.0; GitLab Code Quality; JUnit; CSV; CycloneDX 1.6 with vulnerabilities; GitHub Actions annotations. All carry the CC BY 4.0 attribution.
- Exit codes: 0 passed, 1 a finding meets `--fail-on`, 2 the scan couldn't run. `--quiet`, `--color`, `NO_COLOR`, `--version`.
- `--state` reports what's new, changed, now visible to scanners, or no longer affected.
- `--issues gitlab|gitea` keeps one issue per finding: confidential on GitLab, none opened in public Gitea/Forgejo repos unless allowed.
- GitLab CI/CD component (`gitlab.com/limbowatch/limbowatch-component`): Code Quality, a JUnit test summary and a report link in merge requests, on every tier.
- Composite action for GitHub, Gitea and Forgejo Actions: annotations, SARIF, job summary, a reports directory, and `findings`/`failing`/`failed`/`report` outputs.
- Packages are typed (`py.typed`), tested on Python 3.12 to 3.14, and published with PyPI trusted publishing, PEP 740 attestations and GitHub build provenance.
- `limbowatch inventory` lists what would be checked and what can't.

The tracker commands (`track`, `publish`, `report`) that run [limbo.watch](https://limbo.watch) ship in the same package.
