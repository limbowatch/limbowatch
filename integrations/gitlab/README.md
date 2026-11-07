# Limbowatch CI/CD component

Checks your dependencies against security advisories **in limbo**: published by maintainers on GitHub, but not yet in GitHub's reviewed Advisory Database or OSV, so the scanners that read those databases don't report them.

The job reads your lockfiles with OSV-Scanner (offline, so nothing about the project leaves the job). It matches them against the [limbo feed](https://limbo.watch/feed/), and against the source repos the feed doesn't cover. In a merge request, on every GitLab tier, you get:
- **Code Quality**: each finding on its lockfile line ("Code Quality scans found 51 new findings");
- **Test summary**: one failed test per finding at or above `fail_on` (JUnit);
- **Limbowatch report**: a link to the `limbowatch/` artifacts, with `report.html`, `report.md`, `report.json` (schema 1), `report.csv` and `cyclonedx.json` (CycloneDX 1.6 with the vulnerabilities).

The job log shows a table per lockfile, what to upgrade, and why the job passed or failed. It fails when a finding meets `fail_on` (exit 1); exit 2 means the scan itself couldn't run.

```yaml
include:
  - component: $CI_SERVER_FQDN/limbowatch/limbowatch-component/limbowatch@0.1.0
    inputs:
      fail_on: high
      issues: true          # confidential issues from the default branch and schedules
```

Without the CI/CD Catalog, include the file directly with `include: remote:` and the same `inputs`.

## Inputs

| Input | Default | |
|---|---|---|
| `stage` | `test` | |
| `path` | `.` | Project directory to scan |
| `fail_on` | `low` | `critical`, `high`, `medium`, `low` or `none` |
| `fail_on_unknown` | `true` | Also fail for findings with no severity |
| `allow_failure` | `false` | Let the pipeline pass even when the job fails |
| `issues` | `false` | Open and update confidential issues (default branch and schedules only) |
| `issues_min_severity` | `low` | |
| `extra_args` | | More `limbowatch scan` options, e.g. `--ignore GHSA-xxxx-xxxx-xxxx` |
| `image` | `python:3.12-slim` | Any image with Python 3.12 |
| `osv_scanner_version` | `2.7.0` | Downloaded from Google's releases and checked against their SHA-256 sums |
| `limbowatch_source`, `limbowatch_ref` | GitHub archive, the matching release | Each component version installs the Limbowatch release of the same number |

## GitHub token

To check source repos the live tracker doesn't watch, the job polls the GitHub API. Without a token GitHub allows 60 requests an hour. Add a masked CI/CD variable `LIMBOWATCH_GITHUB_TOKEN` holding any GitHub token that can read public repositories. Repos that can't be polled are reported as checked by name only, never skipped.

## Issues

Set `issues: true` and a masked, protected CI/CD variable `LIMBOWATCH_ISSUES_TOKEN`: a project access token with `api` scope and at least the Reporter role. On gitlab.com, project access tokens need Premium or Ultimate; on the Free tier, use a personal access token with `api` scope, ideally of a separate bot account added to the project. You get:
- one confidential issue per advisory and package;
- a comment when a CVE is assigned, or when the advisory reaches the scanners' databases;
- the issue closed once you've upgraded past it.

Merge request pipelines never open issues.

A weekly scheduled pipeline is worth adding. Advisories are published after you merge, and the review gap lasts weeks.

## Contribute

This project is published from [`integrations/gitlab/`](https://github.com/limbowatch/limbowatch/tree/main/integrations/gitlab) in the Limbowatch repository on GitHub. Issues and pull requests go there.

Advisory data: GitHub repository security advisories and the GitHub Advisory Database (CC BY 4.0), via limbo.watch.
