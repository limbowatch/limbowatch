# Changelog

Versions follow [semantic versioning](https://semver.org). The PyPI packages `limbowatch` and `limbowatch-cli`, the GitLab CI/CD component and the Actions action share one version number.

## Unreleased

## 0.1.0a2 (2026-11-08)

Still an **alpha**. On PyPI it's `0.1.0a2`; the GitHub tag and the action's ref are `v0.1.0a2`; the image is `ghcr.io/limbowatch/limbowatch:0.1.0a2`; the GitLab CI/CD component is `0.1.0-alpha.2`.

- Source repos for Composer (Packagist), Hex and Pub (ecosyste.ms) and Swift (the package URL); for Maven, the POM's `<scm>`, following parent POMs, when deps.dev names none. Version comparison for Hex, Pub and Swift. On an Elixir project (Mobilizon), dependencies checked by name only fell from 162 to 7: 16 "possibly affected" findings turned out to be fixed versions, and 10 real advisories in limbo were found (F-103).
- The tracker checks a repo after its package releases (docs/RELEASE_CHECKS.md), watches the top packages of eight ecosystems, and caps first-time polls per run (`--max-new`).
- Repos without advisories are re-checked every 30 days instead of weekly, plus about a day and about three days after each release of their package; on the last month's advisories that finds them sooner on average (3.5 → 2.6 days, F-104).
- **Image:** `ghcr.io/limbowatch/limbowatch` for linux/amd64 and linux/arm64, with Limbowatch and OSV-Scanner. Base images are pinned by digest and dependencies are installed from the lockfile with hashes. Every build has an SBOM, build provenance and a GitHub attestation.
- **GitLab component:**
  - The job runs the image, pinned by digest and copied to the component's GitLab registry, so nothing is installed at run time.
  - New inputs: `job_name`, `rules`, `needs` and `security_report`. `security_report` puts findings in Ultimate's Security tab and vulnerability report, with a `-gate` job applying `fail_on`.
  - `allow_failure` turns findings into a warning but still fails a scan that couldn't run.
  - Setup is folded in the job log, and the cache is per branch.
  - **Breaking:** `osv_scanner_version`, `limbowatch_source` and `limbowatch_ref` are gone; set `image` instead.
- `limbowatch` exits 2, not 1, on an unexpected error, so a crash never reads as a finding.
- SARIF rules carry `cve-YYYY-N` tags, so GitLab files findings that have a CVE as dependency scanning (F-106).

## 0.1.0a1 (2026-11-07)

First release, an **alpha**: the watcher (Phase 4). Options, output formats and the JSON schema may still change before 0.1.0. On PyPI it's `0.1.0a1`; the GitHub tag and the action's ref are `v0.1.0a1`; the GitLab CI/CD component is `0.1.0-alpha.1` (the Catalog requires semantic versions).

- `limbowatch scan` checks a project's lockfiles (read offline by OSV-Scanner 2.7.0) or a CycloneDX/SPDX SBOM against the [limbo feed](https://limbo.watch/feed/), and polls on GitHub the source repos the live tracker doesn't watch.
- Dependencies that can't be checked (range-only requirements, git and path installs, local packages, unreadable lockfiles, no known source repo) are reported with the reason, never dropped.
- Ten output formats from one scan (`-o FORMAT=FILE`, repeatable): a table grouped by lockfile with the upgrade that clears each package and a PASSED/FAILED verdict; JSON (`schema_version` 1, with summary and gate); Markdown; standalone HTML; SARIF 2.1.0; GitLab Code Quality; JUnit; CSV; CycloneDX 1.6 with vulnerabilities; GitHub Actions annotations. All carry the CC BY 4.0 attribution.
- Exit codes: 0 passed, 1 a finding meets `--fail-on`, 2 the scan couldn't run. `--quiet`, `--color`, `NO_COLOR`, `--version`.
- The table folds a package with many advisories to the ones that matter (every critical, high and build-failing one); GitHub annotations are one per package, because GitHub keeps only 10 of each level per step. A CycloneDX report from an earlier scan is skipped, not read as an SBOM.
- `--state` reports what's new, changed, now visible to scanners, or no longer affected.
- `--issues gitlab|gitea` keeps one issue per finding: confidential on GitLab, none opened in public Gitea/Forgejo repos unless allowed.
- GitLab CI/CD component (`gitlab.com/limbowatch/limbowatch-component`): Code Quality, a JUnit test summary and a report link in merge requests, on every tier.
- Composite action for GitHub, Gitea and Forgejo Actions: annotations, SARIF, job summary, a reports directory, and `findings`/`failing`/`failed`/`report` outputs.
- Packages are typed (`py.typed`), tested on Python 3.12 to 3.14, and published with PyPI trusted publishing, PEP 740 attestations and GitHub build provenance.
- `limbowatch inventory` lists what would be checked and what can't.

The tracker commands (`track`, `publish`, `report`) that run [limbo.watch](https://limbo.watch) ship in the same package.
