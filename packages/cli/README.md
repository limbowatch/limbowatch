# limbowatch-cli

[![PyPI](https://img.shields.io/pypi/v/limbowatch-cli)](https://pypi.org/project/limbowatch-cli/)
[![Python](https://img.shields.io/pypi/pyversions/limbowatch-cli)](https://pypi.org/project/limbowatch-cli/)
[![CI](https://github.com/limbowatch/limbowatch/actions/workflows/ci.yml/badge.svg)](https://github.com/limbowatch/limbowatch/actions/workflows/ci.yml)
[![License](https://img.shields.io/pypi/l/limbowatch-cli)](https://github.com/limbowatch/limbowatch/blob/main/LICENSE)

`limbowatch scan` finds the dependencies in your project that are affected by security advisories **in limbo**: published by maintainers on GitHub, often with a fix, but not yet in GitHub's reviewed Advisory Database or OSV. Dependabot, npm audit, pip-audit and OSV-Scanner read those databases, so they don't report these advisories yet. [limbo.watch](https://limbo.watch) tracks them every day.

## Install

```sh
pipx install limbowatch-cli==0.1.0a9   # the current alpha; or: uv tool install limbowatch-cli==0.1.0a9
```

It reads lockfiles with [OSV-Scanner](https://google.github.io/osv-scanner/installation/) 2.7.0, which must be on `PATH`. Python 3.12 or later.

## Use

```sh
limbowatch scan .                     # a table per lockfile, what to upgrade, and PASSED or FAILED
limbowatch scan . --fail-on high      # fail only for high and critical findings
limbowatch scan . -o table -o sarif=limbowatch.sarif -o junit=junit.xml -o html=report.html
limbowatch scan --sbom bom.cdx.json -f json
limbowatch inventory .                # what would be checked, and what can't be
```

```
web/package-lock.json
  SEVERITY  PACKAGE  INSTALLED  FIXED IN  ADVISORY             CVE
  HIGH      undici   7.30.1     7.30.2    GHSA-mqg3-3v4r-cm32  CVE-2026-116592

To fix: upgrade 1 package
  undici  7.30.1 → 7.30.2  clears 1 advisory  web/package-lock.json:879

FAILED  1 finding at or above low (--fail-on low): 1 high.
```

## Output formats

One scan can write any number of reports: `-o FORMAT=FILE`, repeated.

| Format | For |
|---|---|
| `table` | Terminals and CI logs (coloured; `--color`, `NO_COLOR`) |
| `json` | Automation: findings, upgrades, summary and gate result (`schema_version` 1) |
| `markdown`, `html` | Pull request comments, job summaries, CI artifacts |
| `sarif` | GitHub code scanning and other SARIF 2.1.0 tools |
| `codequality` | GitLab Code Quality in merge requests (every tier) |
| `junit` | Test summaries in GitLab, Jenkins, Azure DevOps, CircleCI |
| `csv` | Spreadsheets |
| `cyclonedx` | CycloneDX 1.6 with vulnerabilities |
| `github` | GitHub Actions annotations, no code scanning needed |

## Exit codes

| Code | |
|---|---|
| 0 | Passed: nothing meets `--fail-on` |
| 1 | Failed: a finding meets `--fail-on` (default `low`) |
| 2 | Error: the scan couldn't run |

## In CI

- **GitLab:** the [CI/CD component](https://gitlab.com/limbowatch/limbowatch-component): Code Quality, a test summary and a report link in every merge request.
- **GitHub, Gitea, Forgejo:** the [action](https://github.com/limbowatch/limbowatch/tree/main/integrations/action): annotations, SARIF, job summary and outputs.

Both can open and update one issue per finding (`--issues gitlab|gitea`). Guide: [docs/WATCHER.md](https://github.com/limbowatch/limbowatch/blob/main/docs/WATCHER.md).

## Good to know

- Nothing about your project is sent to limbo.watch: the feed is downloaded whole.
- Dependencies that can't be checked (range-only requirements, git installs, unreadable lockfiles) are listed with the reason, never dropped.
- Ranges are as entered by maintainers and haven't been reviewed; a range that can't be evaluated exactly is reported as "possibly affected".
- It's a head start: once GitHub reviews an advisory, your usual scanner reports it too.

Advisory data: GitHub repository security advisories and the GitHub Advisory Database (CC BY 4.0), via the limbo feed (CC BY 4.0). Code: Apache-2.0.
