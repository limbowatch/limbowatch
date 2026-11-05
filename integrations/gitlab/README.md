# Limbowatch CI/CD component

Checks your dependencies against security advisories **in limbo**: published by maintainers on GitHub, but not yet in GitHub's reviewed Advisory Database or OSV, so the scanners that read those databases don't report them.

The job reads your lockfiles with OSV-Scanner (offline, so nothing about the project leaves the job). It matches them against the [limbo feed](https://limbo.watch/feed/), and against the source repos the feed doesn't cover. It writes:
- a **Code Quality** report, which works on every GitLab tier and shows in merge requests;
- `limbowatch.md` and `limbowatch.json`.

It fails the pipeline when a finding meets `fail_on`.

```yaml
include:
  - component: $CI_SERVER_FQDN/limbowatch/limbowatch-component/limbowatch@<version>
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
| `issues` | `false` | Open and update confidential issues (default branch and schedules only) |
| `issues_min_severity` | `low` | |
| `extra_args` | | More `limbowatch scan` options, e.g. `--ignore GHSA-xxxx-xxxx-xxxx` |
| `image` | `python:3.12-slim` | Any image with Python 3.12 |
| `osv_scanner_version` | `2.7.0` | Downloaded from Google's releases and checked against their SHA-256 sums |
| `limbowatch_source`, `limbowatch_ref` | GitHub archive, `main` | Pin `limbowatch_ref` to a release tag |

## GitHub token

To check source repos the live tracker doesn't watch, the job polls the GitHub API. Without a token GitHub allows 60 requests an hour. Add a masked CI/CD variable `LIMBOWATCH_GITHUB_TOKEN` holding any GitHub token that can read public repositories. Repos that can't be polled are reported as checked by name only, never skipped.

## Issues

Set `issues: true` and a masked CI/CD variable `LIMBOWATCH_ISSUES_TOKEN`: a project access token with `api` scope. You get:
- one confidential issue per advisory and package;
- a comment when a CVE is assigned, or when the advisory reaches the scanners' databases;
- the issue closed once you've upgraded past it.

Merge request pipelines never open issues.

A weekly scheduled pipeline is worth adding. Advisories are published after you merge, and the review gap lasts weeks.

Advisory data: GitHub repository security advisories and the GitHub Advisory Database (CC BY 4.0), via limbo.watch.
