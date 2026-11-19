# The Limbowatch watcher

`limbowatch scan` checks a project's dependencies against security advisories **in limbo**: advisories that maintainers have published on GitHub, but that aren't yet in GitHub's reviewed Advisory Database or in OSV. Dependabot, OSV-Scanner and other scanners that read those databases don't report them yet.

It runs on any host, in any CI that has Python 3.12:
- a GitLab CI/CD component ([integrations/gitlab](../integrations/gitlab/));
- an Actions composite action for Gitea, Forgejo and GitHub ([integrations/action](../integrations/action/)).

It can keep one issue per finding up to date in GitLab, Gitea/Forgejo or GitHub.

## How it works

1. **Inventory.** OSV-Scanner reads the lockfiles; it supports about 25 formats. It runs offline, against empty databases, so it sends nothing anywhere. CycloneDX and SPDX JSON SBOMs work too (`--sbom`). Limbowatch then re-reads the lockfiles for what OSV-Scanner gets wrong without saying so (FINDINGS F-078), and reports each such dependency as **can't be checked**, with the reason:
   - range-only requirements (`flask>=2`);
   - git and path installs;
   - local packages;
   - empty versions;
   - unreadable lockfiles;
   - a `pom.xml` whose transitive dependencies couldn't be resolved, and a Gradle build without a lockfile.

   **Maven has no lockfile.** Offline, a `pom.xml` gives only its direct dependencies, and only those with a literal version: 3 of the 171 that Maven resolves for spring-petclinic. So when the tree has a `pom.xml`, a second OSV-Scanner run, limited to `pom.xml` and its resolver, resolves the whole tree as Maven does (BOMs, parents, properties, mediation) through deps.dev and Maven Central. On two Spring Boot projects it matched `mvn dependency:list` exactly (FINDINGS F-132). `--no-resolve-maven` keeps the inventory offline; each `pom.xml` is then reported as not fully resolved. **Gradle** resolves at build time, so only a `gradle.lockfile` (or `gradle/verification-metadata.xml`) says what a build uses.

   **C/C++ and other source taken in by git or archive** (*upstream sources*). OSV-Scanner, run offline, reads none of it (FINDINGS F-135), so Limbowatch reads it from the project's own files:
   - **git submodules:** `.gitmodules`, each at the commit in the git index, so a submodule doesn't need to be checked out;
   - **CMake:** `FetchContent_Declare`, `ExternalProject_Add` and CPM (`CPMAddPackage`), with variables from the project's own `set()` calls filled in;
   - **Bazel:** `bazel_dep` in `MODULE.bazel` (and its overrides), and `http_archive` / `git_repository` in MODULE.bazel, WORKSPACE and `.bzl` files, including wrappers such as `tf_http_archive` and `maybe(http_archive, ...)`;
   - **vcpkg:** `vcpkg.json` with its `builtin-baseline` (or `vcpkg-configuration.json`), overrides and the ports' own dependencies; ports the project defines itself are read from their portfile;
   - **Conan:** `conan.lock`, else `conanfile.txt` / `conanfile.py`;
   - **meson:** `subprojects/*.wrap`.

   Each gives the upstream repo and the commit or tag it builds from. Registry names are looked up when scanning: a Bazel module's source archive in the Bazel Central Registry, a vcpkg port's version in the baseline and its repo and tag in the port's portfile, and a Conan package's source URL in its ConanCenter recipe. On 85 popular C/C++ projects, 763 of the 857 upstream sources found end with a repo and a tag or commit (FINDINGS F-137). Directories copied into `third_party/`, `3rdparty/`, `vendor/`, `external/` and the like, recognised by a license file, are reported as **vendored**: nothing says which version was copied. A C/C++ project that declares no dependency this way (libraries from the system, through `find_package` or pkg-config) is reported as such; an SBOM (`--sbom`) covers it.

   Nothing is dropped.
2. **Matching.** Each dependency is matched against the [limbo feed](https://limbo.watch/feed/) (or, with `--feed none`, only against what step 3 reads from GitHub: [No feed](#no-feed)):
   - **By package and version.** If the advisory's range can't be evaluated exactly, or contradicts its own fixed version, the finding is *possible*, never a silent pass.
   - **Go: by module.** A Go advisory can name a module, or a package inside one. The feed says which module contains the path, as the Go module proxy reports it, so `go.opentelemetry.io/otel/baggage` matches the `go.opentelemetry.io/otel` module, and `github.com/aws/aws-sdk-go-v2/service/kinesis` (a module of its own) never matches `github.com/aws/aws-sdk-go-v2`. Where the module isn't known, as for advisories polled directly from a repo, a path below the dependency's module is a *possible* finding (F-113).
   - **By source repository,** when the advisory's package name is unusable. In a monorepo the name has to mention the package.
   - **Upstream sources, by repository.** Most advisories in limbo name no package OSV has an ecosystem for (C/C++ and `other`: 60% of the feed, F-135); they're about the repo's own code, so they're matched to every upstream source built from that repo. Advisories that name a registry package (an npm binding of the same repo) are left to that package. Whether the pinned version is affected comes from the repo's history: a commits-only clone (`git clone --bare --filter=tree:0`, 0.4 MB for zlib, 22 MB for gRPC) says whether the commit contains the fix release's tag for its own line (fixed), is in the history of a release that's in the affected range (affected, unless the range's lower bound says it's older still), lies between the last affected release and the fix release (*possible*: the fix commit may be in it), or is on a branch with neither (*possible*). Where the commit can't be placed, its version (the tag's, the registry's, or the nearest tag's) is compared with the advisory's range. OSV is also asked which of its records include the commit; when it lists one under a CVE the advisory cites, the source is affected (F-138).
3. **Upstream check.** Each dependency's source repo comes from the Go module path or Swift package URL, rubygems.org (RubyGems), Packagist (Composer), ecosyste.ms (Hex, Pub) or deps.dev; for Maven, when deps.dev names none, from the POM's `<scm>`, following parent POMs (F-103). Repos the live tracker doesn't watch, or hasn't checked in 10 days, are polled on GitHub directly; with `--feed none`, every repo is. Dependencies with no known repo, or whose repo couldn't be polled, are reported as **checked by name only** (with `--feed none`, as **not checked**: there's no feed to check names against).
4. **Change detection** (`--state FILE`). Each finding is keyed by ecosystem, package and advisory, so upgrading within the affected range keeps the same key. Each run reports what's:
   - **new**;
   - **changed** (CVE, severity, versions);
   - **now visible to scanners** (the advisory reached OSV);
   - **no longer affected**.

**What leaves the machine:** package names and versions, never files or source code. See [Security and data](#security-and-data) for every host and how to turn each off.

## Use it

```sh
pipx install limbowatch-cli==0.1.0a22   # the current alpha; or: uv tool install limbowatch-cli==0.1.0a22
# needs OSV-Scanner 2.7.1 on PATH: https://google.github.io/osv-scanner/installation/

limbowatch inventory .                       # what would be checked, and what can't be
limbowatch scan .                            # table on stdout; exit 1 if a finding meets --fail-on
limbowatch scan . -o table -o sarif=limbowatch.sarif -o junit=junit.xml -o html=report.html   # one scan, many reports
limbowatch scan --sbom bom.cdx.json -f json
```

The table groups findings by lockfile and package, lists the upgrade that clears each package's advisories, and ends with one line saying whether the scan passed or failed, and why. A package with many advisories shows every critical, high and build-failing one, and a count of the rest (`-v` shows all). An earlier scan's CycloneDX report in the project is skipped, not read as an SBOM.

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
| `github` | GitHub Actions annotations on the lockfile line, without code scanning. One per affected package, because GitHub keeps only 10 of each level per step (F-096) |

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
| `--no-upstream` | Only check against the feed by name: no package lookups, GitHub, CVE or OSV calls ([Security and data](#security-and-data)) |
| `--no-resolve-maven` | Don't send a `pom.xml`'s dependencies to deps.dev and Maven Central to resolve its transitive ones |
| `--no-osv-commits` | Don't ask OSV about the commits the project pins for its upstream sources |
| `--scan-ignored` | Also read lockfiles a `.gitignore` excludes, including an enclosing repo's (F-085) |
| `--feed limbo.watch\|URL\|DIR\|none` | Where advisories in limbo come from (`LIMBOWATCH_FEED`): the limbo feed (default); a feed you build and host yourself, by https URL or directory ([OWN_FEED.md](OWN_FEED.md)); or `none`, no feed: every dependency's source repo is read on GitHub during the scan ([No feed](#no-feed)) |
| `--verify-feed auto\|require\|off` | Check the feed against its signed build attestation before using it (default `auto`; `LIMBOWATCH_VERIFY_FEED`). [Security and data](#security-and-data) |
| `--allow-insecure-http` | Allow plain `http://` to the tracker URL you name on another machine, and send the issues token there. Refused by default: everything is https only ([Security and data](#security-and-data)); `LIMBOWATCH_ALLOW_INSECURE_HTTP=1` |
| `--audit-log FILE` | Record every network call as JSON Lines in `FILE` (`-` for stderr; `LIMBOWATCH_AUDIT_LOG`): what it is, URL, method, status or error, duration, and the name of any credential header sent. Never a secret ([Security and data](#security-and-data)) |
| `--show-network` | Print every network call on stderr as it's made, and the hosts contacted at the end (`LIMBOWATCH_SHOW_NETWORK=1`) |
| `-v` | Show the evidence for every finding, and every dependency checked by name only |

| Exit code | Meaning |
|---|---|
| **0** | Passed: nothing meets `--fail-on` |
| **1** | Failed: at least one finding meets `--fail-on` |
| **2** | Error: the scan couldn't run (no OSV-Scanner, no network, a bad option, a feed that failed verification), so nothing was judged |

When stdout isn't the table (`-f json`, `-q`), a one-line verdict goes to stderr, so CI logs still say why the job passed or failed.

**GitHub token.** Polling source repos uses the GitHub API. Without a token GitHub allows 60 requests an hour, and a large project can need hundreds (GitLab needed 356 in F-085). Set `LIMBOWATCH_GITHUB_TOKEN`, or `GITHUB_TOKEN`, to any token that can read public repos. Repos that can't be polled are reported, not skipped.

## In CI

GitLab, with the [CI/CD component](https://gitlab.com/limbowatch/limbowatch-component), listed in the [GitLab CI/CD Catalog](https://gitlab.com/explore/catalog/limbowatch/limbowatch-component) (inputs in [its README](../integrations/gitlab/README.md)):

```yaml
include:
  - component: $CI_SERVER_FQDN/limbowatch/limbowatch-component/limbowatch@0.1.0-alpha.22
    inputs:
      fail_on: high
```

In the merge request, on every tier: Code Quality findings on the lockfile lines, a test summary with one failed test per finding at or above `fail_on`, and a **Limbowatch report** link to the `limbowatch/` artifacts (HTML, Markdown, JSON, SARIF, CSV and CycloneDX). The job log has the table, with setup folded away. On GitLab Ultimate, `security_report: true` also puts the findings in the Security tab and the vulnerability report. GitLab reads that report only from a job that succeeds, so a second job, `limbowatch-gate`, applies `fail_on` (F-106).

The job runs the Limbowatch image, pinned by digest, so nothing is installed at run time. `rules`, `needs` and `job_name` inputs place it in your pipeline. `allow_failure: true` turns findings into a warning, but a scan that couldn't run still fails.

On a GitLab instance other than gitlab.com, mirror the component project first (GitLab's docs: "Use a GitLab.com component on GitLab Self-Managed").

Any other CI, or locally, with the image (linux/amd64 and linux/arm64; verify it with `gh attestation verify oci://ghcr.io/limbowatch/limbowatch:<tag> --owner limbowatch`):

```sh
docker run --rm -v "$PWD:/src" ghcr.io/limbowatch/limbowatch:0.1.0a22 limbowatch scan . -o sarif=limbowatch.sarif   # a release tag: there's no `latest` while releases are alphas
```

GitHub, Gitea or Forgejo Actions, with the composite action [limbowatch/limbowatch-action](https://github.com/limbowatch/limbowatch-action), listed in [GitHub Marketplace](https://github.com/marketplace/actions/limbowatch) (its source is [`integrations/action/`](../integrations/action/action.yml), copied there at each release; `limbowatch/limbowatch/integrations/action@<tag>` still works). On a Linux runner with Docker it runs the same pinned, attested image as the GitLab component. On macOS or Windows, or when the job itself runs in a container (common on Gitea and Forgejo runners), it installs Limbowatch with pip instead, which needs Python 3.12 or later. The `install` input (`auto`, `image`, `python`) picks one explicitly.

```yaml
permissions:
  contents: read
  security-events: write   # only for the SARIF upload
  actions: read            # the upload action needs it in private repos
steps:
  - uses: actions/checkout@v4
  - uses: limbowatch/limbowatch-action@v0.1.0a22   # Gitea/Forgejo: https://github.com/limbowatch/limbowatch-action@v0.1.0a22
    with:
      fail-on: high
      sarif: limbowatch.sarif
  - if: always()                       # GitHub code scanning: public repos, or private ones with GitHub Code Security
    uses: github/codeql-action/upload-sarif@v4
    with: { sarif_file: limbowatch.sarif, category: limbowatch }
```

**Issues on GitHub.** `issues: github` keeps one issue per finding up to date in the repo, on a push to the default branch, a schedule or a manual run (never from a pull request, including `pull_request_target`), with the job's own token: add `issues: write` to `permissions`, no secret needed. It never opens issues in a public repo (GitHub has no confidential issues) unless `extra-args` has `--issues-public`; public repos have the annotations and code scanning instead. Give the workflow a `concurrency` group, because GitHub lists a new issue a few seconds late and two overlapping runs could open it twice (F-147):

```yaml
on: { push: { branches: [main] }, schedule: [{ cron: "17 6 * * *" }] }
permissions: { contents: read, issues: write }
concurrency: limbowatch
jobs:
  limbowatch:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: limbowatch/limbowatch-action@v0.1.0a22
        with: { fail-on: none, issues: github }
```

The action annotates each finding on its lockfile line in the pull request (`annotations: true`, no code scanning needed), adds the Markdown report to the job summary, and writes every report into `limbowatch-report/` (`reports:` input). `allow-failure: true` passes the step with a warning when findings meet `fail-on`; a scan that couldn't run still fails. Its outputs `findings`, `failing`, `failed` and `report` let later steps act on the result:

```yaml
  - uses: limbowatch/limbowatch-action@v0.1.0a22
    id: limbo
    with: { fail-on: none }
  - if: steps.limbo.outputs.findings != '0'
    uses: actions/upload-artifact@v4
    with: { name: limbowatch-report, path: limbowatch-report/ }
```

## Org-wide mode

`limbowatch watch` checks every project of some GitLab groups (subgroups included), Gitea or Forgejo organizations, GitHub organizations or users, or git URLs, in one run. Run it on a schedule from one place, for example a scheduled pipeline in a dedicated project, instead of adding a job to each project.

```sh
LIMBOWATCH_SOURCE_TOKEN=… limbowatch watch \
  --gitlab-group https://gitlab.example.com/acme --exclude 'acme/sandbox/*' \
  --state limbowatch-state -o markdown=limbowatch.md -o json=limbowatch.json
limbowatch watch --gitea-org https://codeberg.org/some-org --git https://git.example.org/team/tool.git
```

1. **List.** GitLab: the group's own projects and its subgroups' (projects shared into the group from elsewhere aren't included). Gitea and Forgejo: the organization's repos, or a user's. GitHub: the organization's repos (forks included), or a user's: all of them when the token is that user's, else their public ones. Archived, disabled and empty projects, projects marked for deletion and `--exclude` matches are listed as **not checked**, with the reason; `--include-archived` checks archived ones. A project in two groups is checked once. An empty repo is found when it's cloned (GitHub has no reliable flag for one, F-147).
2. **Clone and inventory.** Each project's default branch is cloned with `--depth 1` into a temporary directory, inventoried exactly as `scan` does, and deleted. `--jobs` (default 4) sets how many at a time. No submodules, no LFS files, no tags; symlinks come out as plain files, so a lockfile can't point OSV-Scanner outside the clone.
3. **Check.** Source repos are mapped and polled **once for all projects**: on 49 projects of one GitLab group, 465 repos were polled instead of 784 (F-130).
4. **Report.** One line per project, then each affected project's findings in the same layout as `scan`.

| Option | |
|---|---|
| `--gitlab-group URL` | `https://host/group/subgroup`, or a path with `--gitlab-url` (default `$CI_SERVER_URL`, else gitlab.com). Repeatable |
| `--gitea-org URL` | `https://host/org` (or a user). Repeatable |
| `--github-org NAME` | A GitHub organization or user: `acme`, or `https://github.com/acme`. Repeatable. `--github-url` names an Enterprise Server (default `$GITHUB_SERVER_URL`, else github.com; Enterprise Server is untested) |
| `--git URL` | Any https git URL (http without a token, or with `--allow-insecure-http`). Repeatable. No issues for these: there's no tracker to open them in |
| `--exclude GLOB` | Skip projects whose path (`acme/legacy-*`) or host/path matches. Repeatable |
| `--include-archived` | Also check archived projects |
| `--state DIR` | One state file per project, `DIR/<host>/<path>.json`, to report what changed since the last run |
| `-o`, `-f` | `table`, `json` or `markdown` for the whole run. The JSON nests each project's `scan` JSON unchanged |
| `--issues` | Open and update issues in each GitLab, Gitea or GitHub project, as `scan --issues` does (`LIMBOWATCH_ISSUES_TOKEN`) |
| `--jobs N` | Projects cloned and inventoried at a time (default 4) |

`--fail-on`, `--fail-on-unknown`, `--ignore`, `--ignore-file`, `--no-upstream`, `--osv-scanner`, `--allow-insecure-http` and `-v` work as for `scan`.

| Exit code | Meaning |
|---|---|
| **0** | Passed: no project has a finding that meets `--fail-on` |
| **1** | Failed: at least one project does |
| **2** | Error: a source couldn't be listed, so projects may be missing, or no project could be checked |

A project that can't be cloned or inventoried is listed under **couldn't be checked** with the error; the other projects are still checked.

**Tokens.**
- `LIMBOWATCH_SOURCE_TOKEN` lists private groups and clones their projects. On GitLab, a group access token with `read_api` and `read_repository` (Reporter role); on Gitea and Forgejo, a token that can read the organization and its repositories; on GitHub, a fine-grained token with Metadata and Contents read on the org's repos (a classic one with `repo`), or a GitHub App's token. It defaults to `LIMBOWATCH_ISSUES_TOKEN`.
- GitHub lists only what the token can see and doesn't say more exists (F-147). The report notes a listing that may be partial: without a token (public repos only), with a classic token without `repo` scope, with a fine-grained token (it sees the repos it was given), or with an app installation token in Actions, such as the job's `GITHUB_TOKEN`, which sees public repos and its own repo only.
- In Actions, the job's own server uses the job's `GITHUB_API_URL`, so Enterprise Server and GHE.com work from their own Actions; elsewhere `--github-url` takes github.com or an Enterprise Server address (`/api/v3`).
- A token is sent only to its own host (for GitHub, github.com and its API host api.github.com). When the sources span several hosts, run `limbowatch watch` once per host; with a token set, a run that names two hosts is refused.
- Clones get the token from git's environment, never from the command line or the URL. A clone URL a host's API returns is used only if it's on that host, with the same scheme; otherwise the clone URL is built from the host's address.
- Nothing goes over plain `http://` to another machine. A run that names an `http://` source or tracker is refused before anything is sent (exit 2), with a token or without: anyone on the network could read a token, or change what comes back. `http://` to this machine (localhost, 127.0.0.1, ::1) is fine. For a self-managed instance that only serves http, `--allow-insecure-http` (or the CI/CD variable `LIMBOWATCH_ALLOW_INSECURE_HTTP=1`) allows the hosts you named, and only those: anyone on that network can then read the token. Every other request stays https only ([Security and data](#security-and-data)).
- Gitea and Forgejo show a private organization as empty to a request without access (F-129). So a source that lists no projects at all is an error, not a pass.

**Scheduled GitLab pipeline.** The image includes git. In a project of its own, with `LIMBOWATCH_SOURCE_TOKEN` and `LIMBOWATCH_GITHUB_TOKEN` as masked CI/CD variables and a pipeline schedule:

```yaml
limbowatch-watch:
  image: ghcr.io/limbowatch/limbowatch:<release>   # a release that includes `watch`
  rules: [{ if: $CI_PIPELINE_SOURCE == "schedule" }]
  cache: { key: limbowatch-state, paths: [limbowatch-state/] }
  script:
    - limbowatch watch --gitlab-group "$CI_SERVER_URL/acme" --state limbowatch-state -o markdown=limbowatch.md -o json=limbowatch.json
  artifacts: { when: always, paths: [limbowatch.md, limbowatch.json] }
```

A CI cache can be evicted, and then the next run reports every finding as new. Keep the state somewhere durable (a branch, a package registry, an object store) if that matters, as with `scan --state`.

## Issues

```sh
LIMBOWATCH_ISSUES_TOKEN=… limbowatch scan . --state state.json --issues gitlab \
  --issues-url https://gitlab.example.com --issues-project group/app
```

- **One issue per finding.** Issues are found again by the `limbowatch` label and a hidden marker in the body. The body carries facts and links only, never advisory text.
- **New finding:** open an issue. On GitLab it's confidential by default. Gitea and GitHub have no confidential issues, so no new issue is opened in a public Gitea, Forgejo or GitHub repo unless you pass `--issues-public` (GitHub internal repos count as private).
- **At most 50 new issues a run** per project (`--issues-max-new`), certain findings before possible ones and the most severe first; the rest open on the next runs. A first run on a large project doesn't file hundreds at once, and stays inside GitHub's limit of about 500 new issues and comments an hour (F-146).
- **Changed:** a comment, e.g. a CVE was assigned.
- **Now visible to scanners:** a comment and the `limbowatch:visible` label. The issue stays open while the installed version is still affected; OSV is asked.
- **No longer affected:** a comment, then the issue is closed. Found again later: the same issue is reopened.
- **`--issues-dry-run`** prints the plan without making changes. **`--issues-min-severity`** sets which findings get issues.
- **Rate limits.** On GitHub, writes are a second apart and GitHub's rate limits are waited out. When a limit outlasts the wait, the run stops writing: issues still to open, close, reopen or label are done by the next run, and a "changed" comment that wasn't made is printed, so nothing is lost silently. A request that creates something (an issue, a comment) isn't retried once the server may have received it, so a timeout can't open an issue twice.
- **When issues can't be updated** (a read-only token, issues disabled, a missing project), `scan` still writes every report and then exits 2, naming the error and the comments it couldn't make. GitHub drops a new issue's labels when the token's user has no push access to the repo, and later runs find issues by that label. A personal token's repo permissions show this up front, so nothing new is opened: a dry run prints a `warning:` line, and a real run makes its other changes (comments, closes) and then exits 2 saying which token to use (the job's `GITHUB_TOKEN` with `issues: write`, or a token of a user with write access). The job's `GITHUB_TOKEN` can't be checked that way, so if GitHub ever opens an issue without the `limbowatch` label, Limbowatch closes that issue and stops; in `watch`, that host gets no more issue writes in the run.

**Trackers and tokens** (`LIMBOWATCH_ISSUES_TOKEN`):

| `--issues` | Token |
|---|---|
| `gitlab` | `api` scope (a project, group or personal token) |
| `gitea` | Gitea or Forgejo, a token that can write the repo's issues |
| `github` | Issues write: the job's `GITHUB_TOKEN` with `permissions: issues: write`, a fine-grained token, or a classic one with `repo` |

```sh
LIMBOWATCH_ISSUES_TOKEN=… limbowatch scan . --state state.json --issues github --issues-project acme/app
```

In CI, `--issues-url` and `--issues-project` default to `CI_SERVER_URL` / `GITHUB_SERVER_URL` and `CI_PROJECT_PATH` / `GITHUB_REPOSITORY`; for `github`, the URL defaults to `GITHUB_API_URL`, else api.github.com (github.com and an Enterprise Server's address are also taken). The integrations only write issues on a push to the default branch, a schedule or a manual run, never from merge or pull requests. They were tested end to end against a local Gitea (F-083), in a container (F-084), on gitlab.com (F-087) and on GitHub in a private repo, from the command line and from the action with the job's token (F-148).

## No feed

`--feed none` (or `LIMBOWATCH_FEED=none`) is for teams that can't, or won't, take advisory data from limbo.watch. The other way is to build the feed yourself, with the same tracker, on your own CI: [OWN_FEED.md](OWN_FEED.md). The scan downloads nothing from limbo.watch. Instead it reads every dependency's source repository's published advisories on GitHub, from your runner, and checks each one as the tracker does: not withdrawn, not in OSV (so scanners don't see it yet), and the state of a CVE it cites. In the action, set `LIMBOWATCH_FEED: none` in the step's `env` (or `extra-args: --feed none`); on GitLab, as a CI/CD variable or in `extra_args`.

On four projects it found every advisory the feed found (F-214). What it costs, and what it can't do:
- **Time and requests.** About twice as long (34 to 51 s instead of 22 to 29 s on Gitea, Mastodon and Open WebUI), one GitHub request per source repository (800 to 1,200 on those projects) and one OSV lookup per advisory they have. Set a GitHub token: without one, GitHub allows 60 requests an hour. In org-wide mode each repository is read once for all projects.
- **No name-only check.** A dependency whose source repository isn't known can't be checked by name, so it's reported as **not checked** (56 of 1,993 on Open WebUI).
- **No CVE List facts.** A CVE the advisory doesn't cite isn't found (3 of 210 findings showed "no CVE anywhere" instead), and an advisory whose CVE is already reviewed under another ID isn't recognised as a duplicate, so it can show as a finding the feed leaves out (1 *possible* finding on Mastodon).
- **Only GitHub.** As with the feed, advisories are read from GitHub repositories; dependencies whose code is elsewhere are reported as not checked.

Reports say which way they were made: the table's header reads "no feed", the JSON's `feed` is `null`, and the attribution says the advisories were read from GitHub. With `--state`, a finding from an earlier run is kept while its package is still installed and this scan couldn't have seen it: the package's source repository is unknown or couldn't be read, or the advisory's repository wasn't read (an earlier run with a feed matched it there by name). So switching between modes doesn't report findings as fixed, while a package you removed is still reported as no longer affected.

## Sealed scan

For companies that want the scan to see as little as possible and send nothing: [`deploy/sealed/github/limbowatch.yml`](../deploy/sealed/github/limbowatch.yml), one GitHub Actions workflow. Copy it to `.github/workflows/`. It needs no secrets and no settings, and uses only GitHub's own actions, pinned by commit.

- **collect** (`contents: read`). No Limbowatch code runs in this job.
  - It checks out only the dependency files, by name: every file OSV-Scanner's lockfile and SBOM readers and Limbowatch's own read, and nothing else. A sparse checkout fetches no other file's contents, so the code never reaches the runner. The job summary lists every file that leaves the job, and a test keeps the list in step with what Limbowatch reads.
  - It downloads the [limbo feed](https://limbo.watch/feed/) whole, which tells limbo.watch nothing about the project.
  - With GitHub's `gh`, it checks that the feed was built by this repository's `site.yml` on `main`, with both files from one build, and that the image was built by `image.yml`.
- **scan** (`permissions: {}`, no secrets, no repository, no token used). It runs the image pinned by digest with `--network none`, a read-only root, no capabilities and no new privileges, as `nobody`. The image sees only the dependency files and the feed, both read-only. Even a compromised image can send nothing anywhere: its only way out is the report.
- **Reports:** the job summary and a `limbowatch-report` artifact (JSON, Markdown, HTML, SARIF).
  - To post to Slack or open tickets, add a job that holds the secret and treats the report as untrusted input: parse it with `jq`, send only fields you've checked, and never put its values into `${{ }}` expressions, `GITHUB_ENV` or `GITHUB_OUTPUT`.
  - Never restore an Actions cache in a job that holds secrets, since the scan job's runner can write to it.

**What it costs.** It's the feed-only mode (`--no-upstream --no-resolve-maven`), so:
- **Freshness.** An advisory is found once the tracker has checked its repository: daily for active repositories, weekly for quiet ones. On Open WebUI's and Gitea's lockfiles on 2026-11-19 it found 75 findings, against 77 with the default scan and 81 with [no feed](#no-feed). Every finding it missed was 0 to 2 days old.
- **Not checked, and reported so:** C/C++ sources taken in by git or archive, copies under `third_party/` and the like, and Maven's transitive dependencies (commit a lockfile, or pass an SBOM).

On Open WebUI (7 of its 5,383 files), Gitea (4 of 6,431) and FreeRDP (506 of 3,170, mostly CMake files), scanning only the files it checks out gave the same dependencies, findings and unchecked entries as scanning the whole checkout. A scan takes seconds. Bump the image line with each release.

### With your own feed

To take nothing from limbo.watch and still send nothing, build [your own feed](OWN_FEED.md) and point the sealed scan at it. Popular mode reads only public data and never sees your repositories. Set these at the top of the file:

| Your feed | Set |
|---|---|
| Served over https (GitHub Pages) | `FEED_URL: https://acme.github.io/limbo-feed/feed/` |
| On a `limbo-feed` branch of this repository | `FEED_BRANCH: limbo-feed` |
| On a branch of another repository | `FEED_BRANCH: limbo-feed`, `FEED_REPOSITORY: acme/limbo-feed`; if it's private, a `LIMBO_FEED_READ_TOKEN` secret, which only the collect job uses |

`FEED_SIGNER` names the workflow whose attestation the feed must carry, such as `acme/limbo-feed/.github/workflows/limbo-feed.yml@refs/heads/main`. The own-feed pipeline attests its feed in public repositories and on plans with attestations for private ones. Set `FEED_SIGNER: ""` for a feed that isn't attested: the run then warns, and the job summary says the feed wasn't checked. The scan treats an own feed as it does the limbo feed: it warns when the feed is more than 3 days old.

With no network, the scan can't fill gaps in your feed at scan time, as other scans do. So it finds only what your feed watches, and matches other dependencies by package name only. Build the feed for these projects:
- **Focused mode**, listing your projects' dependencies (it needs a read token for that);
- or **popular mode**, after its first full pass, about four weeks.

On a test repository, a small focused feed built for other projects gave 35 findings at high or above, against 52 with the limbo feed.

### Without a feed, the same day

[`deploy/sealed/github/limbowatch-no-feed.yml`](../deploy/sealed/github/limbowatch-no-feed.yml) has the same collect job and file list, but its image reads every dependency's source repository on GitHub itself ([no feed](#no-feed)). That finds the same day's advisories and takes nothing from limbo.watch. The image needs network for it, so the dependency list goes out:
- source repository names to api.github.com;
- package names and versions to deps.dev and the package registries;
- advisory and CVE IDs to OSV and CVE Services.

The code still never leaves. The image is read-only, runs as `nobody` and gets only the dependency files, plus the job's token. With `permissions: {}`, that token reads public data only, not your repository.

GitHub allows the job token 1,000 requests an hour (15,000 on Enterprise Cloud). The scan makes one per source repository (1,261 for Open WebUI's and Gitea's lockfiles), and reports any it couldn't read as not checked.

| | Sealed, limbo feed | Sealed, your feed | No feed |
|---|---|---|---|
| The image's network | none | none | yes |
| Takes from limbo.watch | the feed, attestation checked | nothing | nothing |
| What leaves about the project | nothing | nothing | the dependency list |
| Advisories found | once the tracker checked their repository | once your tracker did | the same day |
| C/C++ upstream sources, Maven transitive dependencies | reported as not checked | reported as not checked | checked |

## Security and data

The scan runs where your code already is, in your CI job or on your machine. It doesn't upload files or source code, and nothing here asks you to take that on trust: every point below is something you can check or enforce yourself.

**What it reads.** Lockfiles and SBOMs, through OSV-Scanner run offline. For C/C++ and other source taken in by git or archive, also the build files that declare it: `.gitmodules`, `CMakeLists.txt` and `*.cmake`, `MODULE.bazel`, `WORKSPACE` and `.bzl` files, `vcpkg.json`, Conan and meson files. It lists directories to find these, and to spot vendored copies by their license files; it doesn't read your source code.

**What it sends, and where.** Only package names, versions, repository names, commit hashes and advisory IDs, to public services, to find out whether a dependency is affected. Every lookup can be turned off:

| Host | What it receives | Turn it off |
|---|---|---|
| limbo.watch | Nothing about the project: the feed and the watchlist are downloaded whole | `--feed none` ([No feed](#no-feed)), or `--feed` with a feed of your own ([OWN_FEED.md](OWN_FEED.md)) |
| api.deps.dev, rubygems.org, repo.packagist.org, packages.ecosyste.ms, repo1.maven.org | Package names and versions, to find each package's source repository | `--no-upstream` |
| api.deps.dev, repo.maven.apache.org, repo1.maven.org (from OSV-Scanner) | A `pom.xml`'s dependencies, to resolve the transitive ones | `--no-resolve-maven` |
| bcr.bazel.build, raw.githubusercontent.com, center2.conan.io | Bazel module, vcpkg port and Conan package names (and the vcpkg baseline commit) | `--no-upstream` |
| api.github.com | The SHA-256 of the feed and watchlist just downloaded, to check their build attestation (once per new feed) | `--verify-feed off` |
| api.github.com | Names of source repositories the tracker hasn't checked in 10 days (with `--feed none`, of every one), to read their published advisories | `--no-upstream` |
| github.com | Clones, commits and tags only, of upstream repositories that have advisories in limbo | `--no-upstream` |
| cveawg.mitre.org | CVE IDs those repositories' advisories cite, to read their state | `--no-upstream` |
| api.osv.dev | Advisory IDs; the commits the project pins for its upstream sources; with `--state`, IDs of findings that went away since the last run; with `--issues`, the package name and installed versions of an open issue whose advisory is now in OSV, to decide whether to close it | `--no-upstream`, `--no-osv-commits`; no `--state`, no `--issues` |
| Your own GitLab, GitHub, Gitea or Forgejo | Findings, as issues | Leave out `--issues` |

A GitHub token, when there is one, goes only to api.github.com; a tracker token only to your tracker. Names, versions and the vcpkg baseline taken from your build files go into those registries' URLs only as plain path segments (a full commit hash for the baseline), so a `../` in a build file can't point a lookup at another repository. Every request carries the user agent `limbowatch/<version> (+https://limbo.watch)`, and no cookies: one a server sets is neither kept nor sent back (F-226).

**Where URLs come from.** Every host in the table is fixed in the code, with `https://`. URLs that come from somewhere else are checked before anything is sent:
- **Next-page links:** must stay on the host that was listed, and are requested with that host's own scheme.
- **Clone URLs from a host's API:** must match the listed host and scheme, or the clone URL is built from the host's address.
- **CVE record links:** must point into the CVE List repository.
- **Repository URLs a registry returns:** read only for the owner and repository name, which then go into the fixed GitHub URLs.

Nothing from your build files is ever fetched: a `URL` in a `CMakeLists.txt` or a submodule's `url` is read for its repository name only.

**https only.** Every request uses https, or goes to this machine. This is enforced where requests are made, not left to each caller:
- **HTTP:** plain `http://` to another machine is refused before it's sent, and so is a redirect from https to http. The only exception is the self-managed hosts you name with `http://` and `--allow-insecure-http`.
- **git:** runs with `protocol.allow=never` and `protocol.https.allow=always`, and git applies the same list to redirects (F-226), so a clone can't be redirected to http. ssh, `git://` and `ext::` are never allowed, including after an `insteadOf` rewrite in your git config: a rule that turns `https://github.com/` into ssh makes those clones fail, so run Limbowatch without it (`GIT_CONFIG_GLOBAL=/dev/null`).

**Without limbo.watch.** `--feed none` contacts every host in the table except limbo.watch, and api.github.com only to read repositories' advisories ([No feed](#no-feed)).

**Feed only.** `--no-upstream --no-resolve-maven` (without `--state` or `--issues`) contacts limbo.watch, and api.github.com to verify the feed (add `--verify-feed off` for limbo.watch alone), and nothing else: measured through a logging proxy on a project with npm, Go, Cargo, Python, Maven, Gradle and CMake dependencies (FINDINGS F-166). The price: a `pom.xml` gives only its direct dependencies, upstream sources and repositories the tracker doesn't watch aren't checked, and each is reported as such. Install time is separate: the image comes from ghcr.io (registry.gitlab.com for the GitLab component); `install: python` uses pypi.org and files.pythonhosted.org for the pinned dependencies, and github.com for OSV-Scanner and Limbowatch's own source.

**What it can change.** Nothing, unless you turn on issues. It needs no token and no secrets; in GitHub Actions, `permissions: contents: read` is enough, and the action passes the scan a token only with `issues:` set (or one you set yourself). It writes reports where you point it, and its cache (the feed and upstream clones) under `~/.cache/limbowatch` or `--cache`.

**How to verify it.**
- **Read it.** The code is open source (Apache-2.0). Limbowatch's own requests all go through one module, `limbowatch.http`, the only one that imports an HTTP client; OSV-Scanner and git run as separate programs, with the options above.
- **Pin what you read.** Pin the action to a commit SHA rather than a tag. Its default image is pinned by digest and attested by this repository: `gh attestation verify oci://ghcr.io/limbowatch/limbowatch:<tag> --owner limbowatch`. The PyPI packages are published with trusted publishing and carry build attestations: `gh attestation verify <file> -R limbowatch/limbowatch`.
- **Check what it downloads.** The feed comes from limbo.watch over HTTPS only. Each build's `feed/all.zip`, `feed/watchlist.json`, `feed/index.json` and OSV zips carry a build attestation, signed through GitHub and Sigstore by the workflow that made them. That proof doesn't depend on the website, its host or Cloudflare.
  - **The scan checks it before using the feed.** It looks up the SHA-256 of `all.zip` in GitHub's attestation API and uses the feed only if an attestation from `limbowatch/limbowatch`'s `.github/workflows/site.yml` on `main` names it, together with the `watchlist.json` downloaded with it. Both must come from the same build, so an older genuine feed served next to a newer watchlist is refused too (F-194).
    - A feed GitHub doesn't vouch for is refused, and the scan stops (exit 2), saying so. The refused copy is removed from the cache, so the next run downloads it again.
    - If GitHub can't be reached or its answer can't be read, the scan warns and goes on. The lookup is one request with a 10-second timeout; it never waits on a rate limit.
    - `--verify-feed require` refuses in that case too; `--verify-feed off` (or `LIMBOWATCH_VERIFY_FEED=off`) skips the check.
    - A feed verified once isn't looked up again, so an unchanged feed costs no request.
    - A feed more than 3 days old gets a warning (refused with `require`): the site rebuilds it daily, so an old one means it stopped updating, or someone is serving an old build, which would still verify.
    - During a deploy, the two files can briefly come from different builds. The scan then downloads them again after 5 seconds, and if they still don't match, uses its cached pair verified before (with a warning), or stops and says to try again in a few minutes.
  - **It never reads more than a real feed's size.** Downloads stop at 500 MB, the zip's own listing is checked before anything is unpacked (at most 500,000 records, 5 MB each, 1 GB in all), and a feed over those limits is refused (F-192).
  - **To check a copy yourself**, including the one the scan cached under `~/.cache/limbowatch`, with the Sigstore signature checked too: `gh attestation verify all.zip --repo limbowatch/limbowatch --signer-workflow limbowatch/limbowatch/.github/workflows/site.yml --source-ref refs/heads/main --deny-self-hosted-runners` (F-191).
- **Record it.** `--audit-log FILE` writes one JSON line per network call, and keep the file as a build artifact. `--show-network` prints the same calls in the job log. Each entry has the time, what made the call, the full URL, the method, the status or error, the duration and the bytes sent. A request that sends a body has the body in the entry as sent: OSV queries and issues are the only ones. So the URL and the body are everything a request sends, apart from its standard headers. If a credential header went with the request, the entry names it (`authorization` to api.github.com, `private-token` to GitLab). The header's value is never recorded, nor is a user name, password or credential-like query value in a URL. The file ends with a summary of calls per host. Where it comes from:
  - **HTTP requests:** every attempt, retry and redirect hop, through `limbowatch.http`.
  - **git:** clones, fetches and `ls-remote` calls.
  - **OSV-Scanner:** its `pom.xml` resolution run. Its URLs are visible only to OSV-Scanner, so the run is recorded with the hosts it can contact (`--no-resolve-maven` turns it off).

  `track`, `inventory`, `repos` and `watch` take the same options. In the action, add `--audit-log limbowatch-report/network.jsonl` to `extra-args` (the reports directory is the one place in the checkout the scan can write) and upload that directory; on GitLab, `extra_args: "--audit-log limbowatch/network.jsonl"` keeps it with the job's other artifacts. Checked against a logging proxy: every host the proxy saw is in the record (F-225).
- **Watch it.** Run it once behind a logging proxy (`HTTPS_PROXY`; Limbowatch, OSV-Scanner and git all honour it) and compare the hosts with the table above.

**How to lock it down.**
- **Don't give it your code.** It needs only the dependency files: check out just those with a sparse checkout, or build an SBOM yourself and pass `--sbom`.
- **Allow only the hosts you chose.** On a self-hosted runner with a firewall, or with an egress filter on hosted runners, allow the hosts above for the mode you run (only limbo.watch for feed only). Anything else is blocked and shows up.
- **Give it nothing to write with.** No secrets, `contents: read`, no `issues:`, and run it in a job of its own.
- **Contain the image.** The action runs it isolated: the checkout read-only; no access to the runner's temp directory, where `GITHUB_ENV`, `GITHUB_PATH` and `GITHUB_OUTPUT` live; a read-only root filesystem, no capabilities, no new privileges; and workflow commands off while it prints. The scan writes only to directories of its own. The action copies regular files out of them, never following a symlink, never a dotfile and never over a file git tracks, and lets only well-formed values through to its outputs. So even a compromised image can't change the files or environment of the job's later steps. The one place in the checkout it can write is the `reports` directory, so files that `extra-args` writes (`--state`, `--audit-log`, more `-o`) go there, directly in it. They're copied only when the directory is the reports' own, with no files from the repository and no symlink leading to it; otherwise, as with `reports: .`, only the report files are, and the step warns. To keep `--state` between runs, restore its file into that directory (from a cache or a branch) before the step, rather than committing it there. The image sees nothing outside the checkout, so an `--sbom` file or feed directory must be inside it.
- **Or keep the repository out of reach entirely**, with the [sealed scan](#sealed-scan): only the dependency files reach a job with no permissions, and the image runs there with no network.

Report a security problem in Limbowatch itself as [SECURITY.md](../SECURITY.md) says.

## Limits

- **Only as fresh as the tracker** for watched repos: quiet repos are checked weekly. Advisories published since the tracker's last check of a repo are missed until its next run. With `--feed none` every repo is read during the scan, at the cost described in [No feed](#no-feed).
- **Only what the lockfiles list.** The inventory runs offline, so a `requirements.txt` gives its direct entries only; plain OSV-Scanner resolves Python's transitive dependencies online (F-088). Pin them with `pip-compile` or `uv pip compile` to have them checked.
- **Maven resolution is close to Maven's, not identical** (F-132):
  - profiles that activate by JDK version, OS or property aren't evaluated, so their dependencies are missed (9 test dependencies of commons-text);
  - a module that depends on an unreleased sibling module (`1.0-SNAPSHOT` from the same build) can't be resolved; it's reported, with its direct dependencies still checked;
  - only Maven Central and deps.dev are used, so artifacts from a private registry fail resolution the same way.

  For an exact inventory, pass an SBOM from `cyclonedx-maven-plugin` with `--sbom`.
- **Upstream sources are read from the declarations, not from a build:**
  - CMake variables set outside the project (on the command line, by a toolchain file) or computed (`string(REPLACE ...)`) can't be filled in; the dependency is reported with the variable's name;
  - vcpkg: a port's dependencies are taken with its default features and on every platform, so a few may not be built on yours; ports from a registry other than vcpkg's own aren't mapped;
  - a submodule's own submodules and build files are read only when it's checked out;
  - vendored code is reported, not identified.
- **Upstream verdicts are as good as the advisories' ranges.** Against OSV's own version ranges for the same CVEs, 95% agree and 1.6% disagree, where the advisory and the CVE record say different things (F-139). A range that lists only exact versions (`3.26.0`, fixed in 3.27.0) or can't be read gives a *possible* finding for older pins, never a pass.
- **Upstream verdicts follow tags.** A fix is found by its version among the repo's tags (`v1.2.3`, `name-1.2.3`, `release-1_2_3`): 83% of the versions advisories without a package name have a tag (F-138). Advisories give versions, not commits, so a commit after the last affected release and before the fix release is only *possible*.
- **Ranges are as entered by maintainers** and haven't been reviewed. Unreadable ranges give *possible* findings.
- **Upstream polling is GitHub only.** Off-GitHub upstreams, and vanity Go paths deps.dev can't map, are checked by name only.
- **Org-wide mode reads the default branch only,** at its tip. Release branches aren't checked; run `scan` in their pipelines.
- **Polled upstream repos get fewer CVE facts.** Uncited CVEs and duplicates need the CVE List, so they're only detected for repos the tracker watches.

Advisory data: GitHub repository security advisories and the GitHub Advisory Database (CC BY 4.0), via the limbo feed (CC BY 4.0).
