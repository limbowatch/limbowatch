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
2. **Matching.** Each dependency is matched against the [limbo feed](https://limbo.watch/feed/):
   - **By package and version.** If the advisory's range can't be evaluated exactly, or contradicts its own fixed version, the finding is *possible*, never a silent pass.
   - **Go: by module.** A Go advisory can name a module, or a package inside one. The feed says which module contains the path, as the Go module proxy reports it, so `go.opentelemetry.io/otel/baggage` matches the `go.opentelemetry.io/otel` module, and `github.com/aws/aws-sdk-go-v2/service/kinesis` (a module of its own) never matches `github.com/aws/aws-sdk-go-v2`. Where the module isn't known, as for advisories polled directly from a repo, a path below the dependency's module is a *possible* finding (F-113).
   - **By source repository,** when the advisory's package name is unusable. In a monorepo the name has to mention the package.
   - **Upstream sources, by repository.** Most advisories in limbo name no package OSV has an ecosystem for (C/C++ and `other`: 60% of the feed, F-135); they're about the repo's own code, so they're matched to every upstream source built from that repo. Advisories that name a registry package (an npm binding of the same repo) are left to that package. Whether the pinned version is affected comes from the repo's history: a commits-only clone (`git clone --bare --filter=tree:0`, 0.4 MB for zlib, 22 MB for gRPC) says whether the commit contains the fix release's tag (fixed), is older than it on the same history (affected, unless the range's lower bound says it's older still), or is on a branch with neither (*possible*). Where the commit can't be placed, its version (the tag's, the registry's, or the nearest tag's) is compared with the advisory's range. OSV is also asked which of its records include the commit; when it lists one under a CVE the advisory cites, the source is affected (F-138).
3. **Upstream check.** Each dependency's source repo comes from the Go module path or Swift package URL, rubygems.org (RubyGems), Packagist (Composer), ecosyste.ms (Hex, Pub) or deps.dev; for Maven, when deps.dev names none, from the POM's `<scm>`, following parent POMs (F-103). Repos the live tracker doesn't watch, or hasn't checked in 10 days, are polled on GitHub directly. Dependencies with no known repo, or whose repo couldn't be polled, are reported as **checked by name only**.
4. **Change detection** (`--state FILE`). Each finding is keyed by ecosystem, package and advisory, so upgrading within the affected range keeps the same key. Each run reports what's:
   - **new**;
   - **changed** (CVE, severity, versions);
   - **now visible to scanners** (the advisory reached OSV);
   - **no longer affected**.

**What leaves the machine.** The feed and the tracker's watchlist are downloaded whole, so limbo.watch learns nothing about the project. Package names and versions go to deps.dev, rubygems.org, Packagist, ecosyste.ms and Maven Central, to find source repos; a `pom.xml`'s dependencies go to deps.dev and Maven Central to resolve its transitive ones (`--no-resolve-maven` keeps them local). Bazel module, vcpkg port and Conan package names (with the vcpkg baseline commit) go to bcr.bazel.build, raw.githubusercontent.com and center2.conan.io, to find their upstream repos. Upstream repos with advisories in limbo are cloned from GitHub (commits and tags only), and the commits the project pins go to OSV (`--no-osv-commits` keeps them local). Source repo names go to GitHub, to poll their advisories, and advisory IDs go to OSV. With `--issues`, findings go to your own tracker.

## Use it

```sh
pipx install limbowatch-cli==0.1.0a6   # the current alpha; or: uv tool install limbowatch-cli==0.1.0a6
# needs OSV-Scanner 2.7.0 on PATH: https://google.github.io/osv-scanner/installation/

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

GitLab, with the [CI/CD component](https://gitlab.com/limbowatch/limbowatch-component), listed in the [GitLab CI/CD Catalog](https://gitlab.com/explore/catalog/limbowatch/limbowatch-component) (inputs in [its README](../integrations/gitlab/README.md)):

```yaml
include:
  - component: $CI_SERVER_FQDN/limbowatch/limbowatch-component/limbowatch@0.1.0-alpha.6
    inputs:
      fail_on: high
```

In the merge request, on every tier: Code Quality findings on the lockfile lines, a test summary with one failed test per finding at or above `fail_on`, and a **Limbowatch report** link to the `limbowatch/` artifacts (HTML, Markdown, JSON, SARIF, CSV and CycloneDX). The job log has the table, with setup folded away. On GitLab Ultimate, `security_report: true` also puts the findings in the Security tab and the vulnerability report. GitLab reads that report only from a job that succeeds, so a second job, `limbowatch-gate`, applies `fail_on` (F-106).

The job runs the Limbowatch image, pinned by digest, so nothing is installed at run time. `rules`, `needs` and `job_name` inputs place it in your pipeline. `allow_failure: true` turns findings into a warning, but a scan that couldn't run still fails.

On a GitLab instance other than gitlab.com, mirror the component project first (GitLab's docs: "Use a GitLab.com component on GitLab Self-Managed").

Any other CI, or locally, with the image (linux/amd64 and linux/arm64; verify it with `gh attestation verify oci://ghcr.io/limbowatch/limbowatch:<tag> --owner limbowatch`):

```sh
docker run --rm -v "$PWD:/src" ghcr.io/limbowatch/limbowatch:0.1.0a6 limbowatch scan . -o sarif=limbowatch.sarif   # a release tag: there's no `latest` while releases are alphas
```

GitHub, Gitea or Forgejo Actions, with the composite action [limbowatch/limbowatch-action](https://github.com/limbowatch/limbowatch-action), listed in [GitHub Marketplace](https://github.com/marketplace/actions/limbowatch) (its source is [`integrations/action/`](../integrations/action/action.yml), copied there at each release; `limbowatch/limbowatch/integrations/action@<tag>` still works). On a Linux runner with Docker it runs the same pinned, attested image as the GitLab component. On macOS or Windows, or when the job itself runs in a container (common on Gitea and Forgejo runners), it installs Limbowatch with pip instead, which needs Python 3.12 or later. The `install` input (`auto`, `image`, `python`) picks one explicitly.

```yaml
permissions:
  contents: read
  security-events: write   # only for the SARIF upload
  actions: read            # the upload action needs it in private repos
steps:
  - uses: actions/checkout@v4
  - uses: limbowatch/limbowatch-action@v0.1.0a6   # Gitea/Forgejo: https://github.com/limbowatch/limbowatch-action@v0.1.0a6
    with:
      fail-on: high
      sarif: limbowatch.sarif
  - if: always()                       # GitHub code scanning: public repos, or private ones with GitHub Code Security
    uses: github/codeql-action/upload-sarif@v4
    with: { sarif_file: limbowatch.sarif, category: limbowatch }
```

The action annotates each finding on its lockfile line in the pull request (`annotations: true`, no code scanning needed), adds the Markdown report to the job summary, and writes every report into `limbowatch-report/` (`reports:` input). `allow-failure: true` passes the step with a warning when findings meet `fail-on`; a scan that couldn't run still fails. Its outputs `findings`, `failing`, `failed` and `report` let later steps act on the result:

```yaml
  - uses: limbowatch/limbowatch-action@v0.1.0a6
    id: limbo
    with: { fail-on: none }
  - if: steps.limbo.outputs.findings != '0'
    uses: actions/upload-artifact@v4
    with: { name: limbowatch-report, path: limbowatch-report/ }
```

## Org-wide mode

`limbowatch watch` checks every project of some GitLab groups (subgroups included), Gitea or Forgejo organizations, or git URLs, in one run. Run it on a schedule from one place, for example a scheduled pipeline in a dedicated project, instead of adding a job to each project.

```sh
LIMBOWATCH_SOURCE_TOKEN=… limbowatch watch \
  --gitlab-group https://gitlab.example.com/acme --exclude 'acme/sandbox/*' \
  --state limbowatch-state -o markdown=limbowatch.md -o json=limbowatch.json
limbowatch watch --gitea-org https://codeberg.org/some-org --git https://git.example.org/team/tool.git
```

1. **List.** GitLab: the group's own projects and its subgroups' (projects shared into the group from elsewhere aren't included). Gitea and Forgejo: the organization's repos, or a user's. Archived and empty projects, projects marked for deletion and `--exclude` matches are listed as **not checked**, with the reason; `--include-archived` checks archived ones. A project in two groups is checked once.
2. **Clone and inventory.** Each project's default branch is cloned with `--depth 1` into a temporary directory, inventoried exactly as `scan` does, and deleted. `--jobs` (default 4) sets how many at a time. No submodules, no LFS files, no tags; symlinks come out as plain files, so a lockfile can't point OSV-Scanner outside the clone.
3. **Check.** Source repos are mapped and polled **once for all projects**: on 49 projects of one GitLab group, 465 repos were polled instead of 784 (F-130).
4. **Report.** One line per project, then each affected project's findings in the same layout as `scan`.

| Option | |
|---|---|
| `--gitlab-group URL` | `https://host/group/subgroup`, or a path with `--gitlab-url` (default `$CI_SERVER_URL`, else gitlab.com). Repeatable |
| `--gitea-org URL` | `https://host/org` (or a user). Repeatable |
| `--git URL` | Any https git URL. Repeatable. No issues for these: there's no tracker to open them in |
| `--exclude GLOB` | Skip projects whose path (`acme/legacy-*`) or host/path matches. Repeatable |
| `--include-archived` | Also check archived projects |
| `--state DIR` | One state file per project, `DIR/<host>/<path>.json`, to report what changed since the last run |
| `-o`, `-f` | `table`, `json` or `markdown` for the whole run. The JSON nests each project's `scan` JSON unchanged |
| `--issues` | Open and update issues in each GitLab or Gitea project, as `scan --issues` does (`LIMBOWATCH_ISSUES_TOKEN`) |
| `--jobs N` | Projects cloned and inventoried at a time (default 4) |

`--fail-on`, `--fail-on-unknown`, `--ignore`, `--ignore-file`, `--no-upstream`, `--osv-scanner` and `-v` work as for `scan`.

| Exit code | Meaning |
|---|---|
| **0** | Passed: no project has a finding that meets `--fail-on` |
| **1** | Failed: at least one project does |
| **2** | Error: a source couldn't be listed, so projects may be missing, or no project could be checked |

A project that can't be cloned or inventoried is listed under **couldn't be checked** with the error; the other projects are still checked.

**Tokens.**
- `LIMBOWATCH_SOURCE_TOKEN` lists private groups and clones their projects. On GitLab, a group access token with `read_api` and `read_repository` (Reporter role); on Gitea and Forgejo, a token that can read the organization and its repositories. It defaults to `LIMBOWATCH_ISSUES_TOKEN`.
- A token is sent only to its own host. When the sources span several hosts, run `limbowatch watch` once per host; with a token set, a run that names two hosts is refused.
- Clones get the token from git's environment, never from the command line or the URL.
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
- **New finding:** open an issue. On GitLab it's confidential by default. Gitea has no confidential issues, so no new issue is opened in a public Gitea or Forgejo repo unless you pass `--issues-public`.
- **Changed:** a comment, e.g. a CVE was assigned.
- **Now visible to scanners:** a comment and the `limbowatch:visible` label. The issue stays open while the installed version is still affected; OSV is asked.
- **No longer affected:** a comment, then the issue is closed. Found again later: the same issue is reopened.
- **`--issues-dry-run`** prints the plan without making changes. **`--issues-min-severity`** sets which findings get issues.

In CI, `--issues-url` and `--issues-project` default to `CI_SERVER_URL` / `GITHUB_SERVER_URL` and `CI_PROJECT_PATH` / `GITHUB_REPOSITORY`. The integrations only open issues from the default branch or a schedule, never from merge requests. They were tested end to end against a local Gitea (F-083) and in a container (F-084).

## Limits

- **Only as fresh as the tracker** for watched repos: quiet repos are checked weekly. Advisories published since the tracker's last check of a repo are missed until its next run.
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
- **Upstream verdicts follow tags.** A fix is found by its version among the repo's tags (`v1.2.3`, `name-1.2.3`, `release-1_2_3`): 83% of the versions advisories without a package name have a tag (F-138). A commit between the fix commit and the fix release is reported as affected, since advisories give versions, not commits.
- **Ranges are as entered by maintainers** and haven't been reviewed. Unreadable ranges give *possible* findings.
- **Upstream polling is GitHub only.** Off-GitHub upstreams, and vanity Go paths deps.dev can't map, are checked by name only.
- **Org-wide mode reads the default branch only,** at its tip. Release branches aren't checked; run `scan` in their pipelines.
- **Polled upstream repos get fewer CVE facts.** Uncited CVEs and duplicates need the CVE List, so they're only detected for repos the tracker watches.

Advisory data: GitHub repository security advisories and the GitHub Advisory Database (CC BY 4.0), via the limbo feed (CC BY 4.0).
