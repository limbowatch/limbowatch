# The Limbowatch watcher

`limbowatch scan` checks a project's dependencies against security advisories **in limbo**: advisories that maintainers have published on GitHub, but that aren't yet in GitHub's reviewed Advisory Database or in OSV. Dependabot, OSV-Scanner and other scanners that read those databases don't report them yet.

It runs on any host, in any CI that has Python 3.12:
- a GitLab CI/CD component ([integrations/gitlab](../integrations/gitlab/));
- an Actions composite action for Gitea, Forgejo and GitHub ([integrations/action](../integrations/action/)).

It can keep one issue per finding up to date in GitLab or Gitea/Forgejo.

## How it works

1. **Inventory.** OSV-Scanner reads the lockfiles; it supports about 25 formats. It runs offline, against empty databases, so it sends nothing anywhere. CycloneDX and SPDX JSON SBOMs work too (`--sbom`). Limbowatch then re-reads the lockfiles for what OSV-Scanner gets wrong without saying so (FINDINGS F-078), and reports each such dependency as **can't be checked**, with the reason:
   - range-only requirements (`flask>=2`);
   - git and path installs;
   - local packages;
   - empty versions;
   - unreadable lockfiles.

   Nothing is dropped.
2. **Matching.** Each dependency is matched against the [limbo feed](https://limbo.watch/feed/):
   - **By package and version.** If the advisory's range can't be evaluated exactly, or contradicts its own fixed version, the finding is *possible*, never a silent pass.
   - **By source repository,** when the advisory's package name is unusable. In a monorepo the name has to mention the package.
3. **Upstream check.** Each dependency's source repo comes from the Go module path, rubygems.org or deps.dev. Repos the live tracker doesn't watch, or hasn't checked in 10 days, are polled on GitHub directly. Dependencies with no known repo, or whose repo couldn't be polled, are reported as **checked by name only**.
4. **Change detection** (`--state FILE`). Each finding is keyed by ecosystem, package and advisory, so upgrading within the affected range keeps the same key. Each run reports what's:
   - **new**;
   - **changed** (CVE, severity, versions);
   - **now visible to scanners** (the advisory reached OSV);
   - **no longer affected**.

**What leaves the machine.** The feed and the tracker's watchlist are downloaded whole, so limbo.watch learns nothing about the project. Package names and versions go to deps.dev and rubygems.org, to find source repos. Source repo names go to GitHub, to poll their advisories, and advisory IDs go to OSV. With `--issues`, findings go to your own tracker.

## Use it

```sh
pipx install limbowatch-cli     # or: uv tool install limbowatch-cli, or pip install limbowatch-cli
# before 0.1.0 is on PyPI:
# uv tool install "limbowatch-cli @ git+https://github.com/limbowatch/limbowatch#subdirectory=packages/cli" \
#   --with "limbowatch @ git+https://github.com/limbowatch/limbowatch#subdirectory=packages/core"
# needs OSV-Scanner 2.7.0 on PATH: https://google.github.io/osv-scanner/installation/

limbowatch inventory .                       # what would be checked, and what can't be
limbowatch scan .                            # table on stdout; exit 1 if a finding meets --fail-on
limbowatch scan . -o table -o sarif=limbowatch.sarif -o junit=junit.xml -o html=report.html   # one scan, many reports
limbowatch scan --sbom bom.cdx.json -f json
```

The table groups findings by lockfile, lists the upgrade that clears each package's advisories, and ends with one line saying whether the scan passed or failed, and why:

```
web/package-lock.json
  SEVERITY  PACKAGE  INSTALLED  FIXED IN  ADVISORY             CVE
  HIGH      undici   7.30.1     7.30.2    GHSA-mqg3-3v4r-cm32  CVE-2026-116592
  MEDIUM    undici   7.30.1     7.30.2    GHSA-3g9m-rv3r-w5w2  CVE-2026-120222

To fix: upgrade 1 package
  undici  7.30.1 → 7.30.2  clears 2 advisories  web/package-lock.json:879

FAILED  2 findings at or above low (--fail-on low): 1 high, 1 medium.
```

### Output formats

| Format | What it's for |
|---|---|
| `table` | People: the terminal and CI logs. Coloured on a terminal and in GitHub Actions and GitLab CI logs |
| `json` | Machines: findings, upgrades, unchecked dependencies, a summary and the gate result. `schema_version` 1; new fields may be added, breaking changes bump it |
| `markdown` | Pull request comments and job summaries |
| `html` | A standalone report (no scripts, no external files) to keep as a CI artifact |
| `sarif` | SARIF 2.1.0, for GitHub code scanning and other SARIF tools |
| `codequality` | GitLab Code Quality: findings on the lockfile line in merge requests, every tier |
| `junit` | JUnit XML: test summaries in GitLab merge requests (every tier), Jenkins, Azure DevOps, CircleCI. A finding at or above `--fail-on` is a failed test; one below it, or accepted, is skipped |
| `csv` | Spreadsheets: one row per finding, UTF-8 with a byte-order mark; cells that could run as a formula start with `'` |
| `cyclonedx` | CycloneDX 1.6 JSON with the affected components and their vulnerabilities, for tools that ingest CycloneDX |
| `github` | GitHub Actions annotations on the lockfile line, without code scanning (GitHub shows up to 10 of each level per step) |

Every format carries the CC BY 4.0 attribution for the advisory data. SARIF 2.1.0 and CycloneDX 1.6 output are checked against the official schemas (FINDINGS F-093).

| Option | |
|---|---|
| `-o`, `--output FORMAT[=FILE]` | Repeatable. `FORMAT=FILE` writes a file; `FORMAT` alone (or `FILE` `-`) writes to stdout. One scan, every report |
| `-f`, `--format FORMAT` | The format on stdout (default `table`) |
| `-q`, `--quiet` | Nothing on stdout; files and the exit code only (the verdict still goes to stderr) |
| `--color auto\|always\|never` | `auto` colours a terminal and GitHub Actions and GitLab CI logs; `NO_COLOR` turns it off, `FORCE_COLOR` on |
| `--fail-on` | `critical`, `high`, `medium`, `low` (default) or `none` |
| `--fail-on-unknown` / `--no-fail-on-unknown` | Fail on findings with no severity (default: fail) |
| `--ignore ID`, `--ignore-file` | Accept an advisory by GHSA or CVE ID; it's listed, but doesn't fail the build |
| `--state FILE` | Report what changed since the last run |
| `--no-upstream` | Only check against the feed by name; no deps.dev or GitHub calls |
| `--scan-ignored` | Also read lockfiles a `.gitignore` excludes, including an enclosing repo's (F-085) |
| `-v` | Show the evidence for every finding, and every dependency checked by name only |

| Exit code | Meaning |
|---|---|
| **0** | Passed: nothing meets `--fail-on` |
| **1** | Failed: at least one finding meets `--fail-on` |
| **2** | Error: the scan couldn't run (no OSV-Scanner, no network, a bad option), so nothing was judged |

When stdout isn't the table (`-f json`, `-q`), a one-line verdict goes to stderr, so CI logs still say why the job passed or failed.

**GitHub token.** Polling source repos uses the GitHub API. Without a token GitHub allows 60 requests an hour, and a large project can need hundreds (GitLab needed 356 in F-085). Set `LIMBOWATCH_GITHUB_TOKEN`, or `GITHUB_TOKEN`, to any token that can read public repos. Repos that can't be polled are reported, not skipped.

## In CI

GitLab, with the [CI/CD component](https://gitlab.com/limbowatch/limbowatch-component) (inputs in [its README](../integrations/gitlab/README.md)):

```yaml
include:
  - component: $CI_SERVER_FQDN/limbowatch/limbowatch-component/limbowatch@0.1.0
    inputs:
      fail_on: high
```

In the merge request, on every tier: Code Quality findings on the lockfile lines, a test summary with one failed test per finding at or above `fail_on`, and a **Limbowatch report** link to the `limbowatch/` artifacts (HTML, Markdown, JSON, CSV and CycloneDX). The job log has the table.

On a GitLab instance other than gitlab.com, mirror the component project first (GitLab's docs: "Use a GitLab.com component on GitLab Self-Managed").

GitHub, Gitea or Forgejo Actions, with the [composite action](../integrations/action/action.yml). The runner needs Python 3.12 or later.

```yaml
permissions:
  contents: read
  security-events: write   # only for the SARIF upload
  actions: read            # the upload action needs it in private repos
steps:
  - uses: actions/checkout@v4
  - uses: actions/setup-python@v5      # if the runner image has no Python 3.12
    with: { python-version: "3.12" }
  - uses: limbowatch/limbowatch/integrations/action@v0.1.0   # Gitea/Forgejo: https://github.com/limbowatch/limbowatch/integrations/action@v0.1.0
    with:
      fail-on: high
      sarif: limbowatch.sarif
  - if: always()                       # GitHub code scanning: public repos, or private ones with GitHub Code Security
    uses: github/codeql-action/upload-sarif@v4
    with: { sarif_file: limbowatch.sarif, category: limbowatch }
```

The action annotates each finding on its lockfile line in the pull request (`annotations: true`, no code scanning needed), adds the Markdown report to the job summary, and writes every report into `limbowatch-report/` (`reports:` input). Its outputs `findings`, `failing`, `failed` and `report` let later steps act on the result:

```yaml
  - uses: limbowatch/limbowatch/integrations/action@v0.1.0
    id: limbo
    with: { fail-on: none }
  - if: steps.limbo.outputs.findings != '0'
    uses: actions/upload-artifact@v4
    with: { name: limbowatch-report, path: limbowatch-report/ }
```

## Issues

```sh
LIMBOWATCH_ISSUES_TOKEN=… limbowatch scan . --state state.json --issues gitlab \
  --issues-url https://gitlab.example.com --issues-project group/app
```

- **One issue per finding.** Issues are found again by the `limbowatch` label and a hidden marker in the body. The body carries facts and links only, never advisory text.
- **New finding:** open an issue. On GitLab it's confidential by default. Gitea has no confidential issues, so no new issue is opened in a public Gitea or Forgejo repo unless you pass `--issues-public`.
- **Changed:** a comment, e.g. a CVE was assigned.
- **Now visible to scanners:** a comment and the `limbowatch:visible` label. The issue stays open while the installed version is still affected; OSV is asked.
- **No longer affected:** a comment, then the issue is closed. Found again later: the same issue is reopened.
- **`--issues-dry-run`** prints the plan without making changes. **`--issues-min-severity`** sets which findings get issues.

In CI, `--issues-url` and `--issues-project` default to `CI_SERVER_URL` / `GITHUB_SERVER_URL` and `CI_PROJECT_PATH` / `GITHUB_REPOSITORY`. The integrations only open issues from the default branch or a schedule, never from merge requests. They were tested end to end against a local Gitea (F-083) and in a container (F-084).

## Limits

- **Only as fresh as the tracker** for watched repos: quiet repos are checked weekly. Advisories published since the tracker's last check of a repo are missed until its next run.
- **Only what the lockfiles list.** The inventory runs offline, so a `requirements.txt` gives its direct entries only; plain OSV-Scanner resolves Python's transitive dependencies online (F-088). Pin them with `pip-compile` or `uv pip compile` to have them checked.
- **Ranges are as entered by maintainers** and haven't been reviewed. Unreadable ranges give *possible* findings.
- **Upstream polling is GitHub only.** Off-GitHub upstreams, and vanity Go paths deps.dev can't map, are checked by name only.
- **Polled upstream repos get fewer CVE facts.** Uncited CVEs and duplicates need the CVE List, so they're only detected for repos the tracker watches.

Advisory data: GitHub repository security advisories and the GitHub Advisory Database (CC BY 4.0), via the limbo feed (CC BY 4.0).
