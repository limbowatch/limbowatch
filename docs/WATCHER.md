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
# needs OSV-Scanner 2.7.0 on PATH: https://google.github.io/osv-scanner/installation/

limbowatch inventory .                       # what would be checked, and what can't be
limbowatch scan .                            # table on stdout; exit 1 if a finding meets --fail-on
limbowatch scan . --state .limbowatch/state.json \
  --output codequality=gl-code-quality-report.json --output sarif=limbowatch.sarif
limbowatch scan --sbom bom.cdx.json --format json
```

| Option | |
|---|---|
| `--format` | `table` (default), `json`, `markdown`, `sarif`, `codequality` on stdout |
| `--output FORMAT=FILE` | Also write a format to a file; repeatable |
| `--fail-on` | `critical`, `high`, `medium`, `low` (default) or `none` |
| `--fail-on-unknown` / `--no-fail-on-unknown` | Fail on findings with no severity (default: fail) |
| `--ignore ID`, `--ignore-file` | Accept an advisory by GHSA or CVE ID; it's listed, but doesn't fail the build |
| `--state FILE` | Report what changed since the last run |
| `--no-upstream` | Only check against the feed by name; no deps.dev or GitHub calls |
| `--scan-ignored` | Also read lockfiles a `.gitignore` excludes, including an enclosing repo's (F-085) |
| `-v` | Show the evidence for every finding, and every dependency checked by name only |

Exit codes: **0** means nothing meets `--fail-on`; **1** means something does; **2** means an error.

**GitHub token.** Polling source repos uses the GitHub API. Without a token GitHub allows 60 requests an hour, and a large project can need hundreds (GitLab needed 356 in F-085). Set `LIMBOWATCH_GITHUB_TOKEN`, or `GITHUB_TOKEN`, to any token that can read public repos. Repos that can't be polled are reported, not skipped.

## In CI

GitLab, with the [CI/CD component](https://gitlab.com/limbowatch/limbowatch-component) (inputs in [its README](../integrations/gitlab/README.md)):

```yaml
include:
  - component: $CI_SERVER_FQDN/limbowatch/limbowatch-component/limbowatch@0.1.0
    inputs:
      fail_on: high
```

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

The Markdown report also goes to the job summary.

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
