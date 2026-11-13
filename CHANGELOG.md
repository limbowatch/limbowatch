# Changelog

Versions follow [semantic versioning](https://semver.org). The PyPI packages `limbowatch` and `limbowatch-cli`, the GitLab CI/CD component and the Actions action share one version number.

## Unreleased

- **limbo.watch, redesigned around the story** (Phase 8): "Fixed upstream. Still clean in your scanner." The home page leads with how many advisories waiting for review already name a fix, shows real packages in limbo right now (each pinned in the public proof repository, [limbowatch/limbo-poc](https://github.com/limbowatch/limbo-poc), whose daily run shows Limbowatch reporting them while OSV-Scanner, npm audit, pip-audit and Dependabot stay silent), and moves the compliance section to a new page, `/compliance/` (SOC 2, PCI DSS and CISA BOD 26-04, with sources). Advisory pages lead with the fixed version. The navigation is down to five items, with a Learn menu.
- **The rest of the redesign:** one design system across the site ([docs/redesign/DESIGN.md](docs/redesign/DESIGN.md)): colour tokens for light and dark, all text at WCAG AA contrast (three colours were below it and are fixed), and one type scale, radii and spacing. The tracker has a **Fix** filter ("Fix released" or "No fixed version"; `/tracker/?fix=yes` links to it from the home page). The scan page has tabs for GitHub, GitLab, Gitea and Forgejo, and the command line, and its screenshots come from 0.1.0a13. The release audit (`scripts/audit.py`) checks that every example on the home page is still in limbo and that no scanner database has another advisory for its version.
- **Fixed: the home page's advisory count ran past its column** once it reached five digits ("10,239"): into the text beside it on desktop and to the edge on narrow phones. It's now sized from its column's width, with room for "100,000".
- **Fixed: advisory fields could break or inject Markdown in issues and reports** (FINDINGS F-164). Maintainers type version ranges and fixed versions freely: 164 ranges in the tracker contain `||`, and some contain backticks or link syntax. In an issue's table a `|` ended the cell, so a range like `>=4.1.0, <=4.1.13 || >=5.0.0, <5.1.1` showed as only `>=4.1.0, <=4.1.13`; a backtick could end the code span and render a link or an @mention in an issue your own bot opened. Every field from an advisory or a lockfile is now a code span in issues, comments, the Markdown report (job summary, merge request) and the tracker's daily report, advisory links are used only when they point at that advisory on GitHub, and the hidden issue marker can't be cut short by `-->`. Issues opened by earlier releases are still recognized.
- **The action's `install: python` pins every dependency with hashes.** It installed Limbowatch's dependencies from PyPI at whatever version was newest; it now installs exactly `uv.lock`'s, from `integrations/action/requirements.txt` with `pip --require-hashes`, and builds Limbowatch from the release's source with the pinned build backend, so nothing unpinned is downloaded. The image (`install: image`) was already pinned by digest.
- **Security and data, documented** in the guide ([docs/WATCHER.md](docs/WATCHER.md#security-and-data)), the README, the action and component READMEs, and on limbo.watch/scan: what the scan reads, every host it can contact and what each receives, the option that turns each off, and how to verify and lock it down. `--no-upstream --no-resolve-maven` contacts limbo.watch and nothing else (FINDINGS F-166). The guide now also lists CVE Services (cveawg.mitre.org), which receives the CVE IDs cited by advisories in polled repositories, and documents `--no-resolve-maven` and `--no-osv-commits` among the options. A test fails if a host the scan can contact, or an option the section names, drifts from the code. Also fixed: the scan page's "Try it" card was 12px wider than a 375px phone screen.

## 0.1.0a13 (2026-11-12)

Still an **alpha**. On PyPI it's `0.1.0a13`; the GitHub tag and the action's ref are `v0.1.0a13`; the image is `ghcr.io/limbowatch/limbowatch:0.1.0a13`; the GitLab CI/CD component is `0.1.0-alpha.13`. A fix to how advisory ranges are read; upgrade from 0.1.0a12 and earlier.

- **Fixed: ranges with several upper bounds hid affected versions.** Maintainers often write one bound per release line, such as `<= 2.12.6, <= 2.11.15`. Read as GitHub's syntax says (a comma is AND), that meant `<= 2.11.15`, so 2.12.6 was reported clean although the advisory's own fix list says it's affected. Such a range is now read one bound per line; a version on a line the range doesn't name is "possibly affected". On the 2026-11-12 feed this affects 431 package entries, and nats-server 2.12.6 goes from 9 to 11 advisories in limbo (FINDINGS F-159, F-160).
- **The limbo feed converts those ranges** when the fixed versions confirm a fix per line, so OSV-Scanner reading the feed can match 413 more entries.
- **Fixed: findings in a `pom.xml` pointed at line 1.** They're now on the dependency's `<artifactId>` line, so annotations land where the dependency is.

## 0.1.0a12 (2026-11-12)

Still an **alpha**. On PyPI it's `0.1.0a12`; the GitHub tag and the action's ref are `v0.1.0a12`; the image is `ghcr.io/limbowatch/limbowatch:0.1.0a12`; the GitLab CI/CD component is `0.1.0-alpha.12`. Dependency upgrades, and a fix found while testing them.

- **OSV-Scanner 2.7.1** reads the lockfiles (the image, the action's `install: python`, and the version `scan` expects). It checks npm packages whose lockfile entry has no `resolved` field itself, which Limbowatch had worked around; across 111 real projects it reads the same dependencies as 2.7.0, less one false yarn `patch:` entry (FINDINGS F-153).
- **Fixed: a linked local npm package could be checked as the npm package of the same name.** A `file:` dependency whose target sits under another directory's `node_modules` is local code; OSV-Scanner 2.7.1, and Limbowatch's own workaround with 2.7.0, took it for a registry package. The dependency's spec in the lockfile now decides; pnpm-installed packages stay checked (F-153).
- **The image runs Python 3.14** (was 3.12), on a refreshed Go build image. Python 3.12 or later is still supported everywhere else.
- Dependencies updated to their latest releases, among them typer 0.29, pydantic 2.14.3 and anyio 4.16.

## 0.1.0a11 (2026-11-12)

Still an **alpha**. On PyPI it's `0.1.0a11`; the GitHub tag and the action's ref are `v0.1.0a11`; the image is `ghcr.io/limbowatch/limbowatch:0.1.0a11`; the GitLab CI/CD component is `0.1.0-alpha.11`. A fix to GitHub issues; nothing else changes.

- **A token whose user can't push to the repo opens no GitHub issues**, and says so before anything is created. GitHub silently drops a new issue's labels without push access, and later runs find issues by that label. A dry run prints a warning; a real run makes its other changes, then exits 2 naming the token to use. In `watch`, other repos of the org still get their issues.

## 0.1.0a10 (2026-11-12)

Still an **alpha**. On PyPI it's `0.1.0a10`; the GitHub tag and the action's ref are `v0.1.0a10`; the image is `ghcr.io/limbowatch/limbowatch:0.1.0a10`; the GitLab CI/CD component is `0.1.0-alpha.10`. **GitHub becomes a full host:** issues and org-wide mode work on GitHub as on GitLab and Gitea.

- **Issues on GitHub.** `scan --issues github` keeps one issue per finding up to date in a GitHub repo, as on GitLab and Gitea: opened, commented on when a CVE is assigned or the advisory reaches scanners, closed when you upgrade, reopened if it comes back. In the action, `issues: github` uses the job's own token (`permissions: issues: write`). GitHub has no confidential issues, so nothing is opened in a public repo unless `--issues-public` is given. Tested live in a private repo, from the command line and from the action.
- **Org-wide mode for GitHub.** `limbowatch watch --github-org acme` checks every repo of a GitHub organization, or a user's (`--github-url` for Enterprise Server, untested). The report says when a listing may be partial: GitHub lists only what the token can see, and the job's `GITHUB_TOKEN` sees public repos and its own.
- **At most 50 new issues a run** per project, certain and most severe first (`--issues-max-new`); the rest open on later runs. On every tracker.
- **GitHub's rate limits are waited out** when writing issues, and writes are spaced a second apart. A limit that outlasts the wait stops the run's writes; what's left is done next run, and a "changed" comment that couldn't be made is printed.
- **When issues can't be updated, `scan` still writes its reports**, then exits 2 with the error; "changed" comments that couldn't be made are printed, on every path. A token that can't label issues no longer leaves an issue later runs can't find: it's closed and the run stops.
- **A request that creates an issue or a comment isn't retried** once the server may have received it (a timeout, a 5xx), so it can't be made twice. On every tracker.
- **The action writes issues only on a push to the default branch, a schedule or a manual run**, not on `pull_request_target`, `issue_comment` or `workflow_run`, which run on the default branch but may scan a fork's files. Also for `issues: gitea`.
- **Fixed: org-wide mode took an empty repository for a checked one** (git prints `HEAD` for an empty repo's commit). It's reported as empty.
- A dry run without a token reads a public tracker anonymously instead of failing; `--issues` with an unknown tracker is refused before the scan runs, and the action fails on an unknown `issues` value instead of ignoring it.

## 0.1.0a9 (2026-11-11)

Still an **alpha**. On PyPI it's `0.1.0a9`; the GitHub tag and the action's ref are `v0.1.0a9`; the image is `ghcr.io/limbowatch/limbowatch:0.1.0a9`; the GitLab CI/CD component is `0.1.0-alpha.9`. **Replaces 0.1.0a8:** a second independent review found that a rate-limited upstream source could pass unchecked, and that a filename that isn't UTF-8 could end any scan (below).

- **Fixed: a rate-limited upstream source passed silently.** When GitHub's rate limit stopped polling, the source wasn't matched against the feed either; it is now, and it's reported as partly checked.
- **Fixed: a filename that isn't UTF-8 in the git index ended every scan** (exit 2), C/C++ or not. Upstream detection can't end a scan any more.
- **Fixed: issues for upstream findings were closed when the source wasn't checked** (`--no-upstream`, rate limit, a failed clone). They're closed only when the source was checked in full or removed, and labelled when the advisory reaches OSV.
- **Fixed:** a vcpkg port pulled in twice was reported twice, and `overrides` didn't apply to ports pulled in; an untagged fix on one release line could clear a pin on that line; virtualenvs and caches were read for upstream sources; the tracker lost its tag listings when a run hit its time limit; huge CMake files were slow; `--no-upstream` was misnamed in a message.
- **Tests:** end-to-end tests run the CLI on local repos and a recorded feed; coverage is 92% and CI fails below 90%. `scripts/e2e_upstream.py` checks upstream sources against real repos.
- **Audit:** also checks that no GIT range is missing, that every feed entry has a package naming its repo, and that the oldest and newest releases read the live feed.
- **0.1.0a7 is yanked on PyPI.** README badges; repository topics for C/C++.
## 0.1.0a8 (2026-11-11)

Still an **alpha**. On PyPI it's `0.1.0a8`; the GitHub tag and the action's ref are `v0.1.0a8`; the image is `ghcr.io/limbowatch/limbowatch:0.1.0a8`; the GitLab CI/CD component is `0.1.0-alpha.8`. **Replaces 0.1.0a7, which could pass upstream sources that are affected** (four cases found by an independent review, below). Upgrade if you use 0.1.0a7.

- **Fixed: upstream sources could be passed when affected** (found by an independent review, F-141): a fix release of an older line in a pin's history cleared a newer affected line (`< 1.2.5 || >= 2.0.0, < 2.0.3` at 2.0.1); tag versions were read from the last digits (`v1.2.3-r2` as 2, `pcre2-10.44` as `2-10.44`); a trailing letter counted as a pre-release (`1.1.1a` before `1.1.1`); an advisory naming a registry package and the C code was skipped for upstream sources.
- **A commit between the last affected release and the fix release is *possible*,** not certain: the fix commit may already be in it. It's certain when a release in the affected range contains it.
- **Fixed: a malformed `vcpkg.json` or `conan.lock` ended the scan**; it's reported as unreadable, and the rest is checked.
- **Security: a scanned tree's git config can't run commands** (`core.fsmonitor`); every git call on it disables fsmonitor.
- **Also:** `*.MODULE.bazel` includes are read; relative submodule URLs under `git@host:` remotes resolve to the right repo; `www.github.com` is GitHub; renamed repos are matched under their new name; two unresolved sources with one name in different files are both reported; a vcpkg graph cut at 500 ports says so; exact-only ranges get no GIT range in the feed (67% of the entries for advisories without a package have one, down from 73%).
- **Fixed: the feed broke watchers before 0.1.0a7** from 09:21 to 10:14 UTC on 2026-11-11: its new entries for advisories without a package had no `package`, which those releases require, so they exited 2. The entries now name the repository as a `GIT` package; every release reads the feed again, and the release audit checks it.
- **Feed:** advisories that name a registry ecosystem but no package (153, mostly Composer, Go and GitHub Actions) are kept, so dependencies from the same repo match them by repository as *possible*, as they already did for repos polled directly.

## 0.1.0a7 (2026-11-11)

Still an **alpha**. On PyPI it's `0.1.0a7`; the GitHub tag and the action's ref are `v0.1.0a7`; the image is `ghcr.io/limbowatch/limbowatch:0.1.0a7`; the GitLab CI/CD component is `0.1.0-alpha.7`. **C/C++ projects get findings:** git submodules, CMake fetches, Bazel, vcpkg and Conan dependencies are checked against the advisories in limbo that name no package, 60% of the feed. New outbound requests: Bazel Central Registry, vcpkg's and ConanCenter's recipes, commits-only clones of upstreams with advisories in limbo, and the pinned commits to OSV (`--no-osv-commits` to keep those local). Also: `scripts/check_integrations.py` works again.

- **C/C++ and other upstream sources are checked against advisories in limbo.** 60% of the feed's advisories name no package OSV knows (C/C++, `other`); they're now matched to the upstream sources built from their repo. A commits-only clone of the upstream says whether the pinned commit contains the fix release: a FreeRDP submodule at 3.10.0 is affected by 228 advisories in limbo (12 more *possible*), at 3.33.1 by none (3 *possible*, with ranges in free text). Against OSV's own version ranges for the same CVEs, 95% of verdicts agree and 1.6% disagree, where the advisory's range and the CVE record differ. OSV is asked about pinned commits too (`--no-osv-commits` to opt out). Findings point at the `.gitmodules`, `CMakeLists.txt`, `MODULE.bazel` or `vcpkg.json` line, and "To fix" names the release to move to.
- **The feed covers advisories without a package.** Each entry keeps the versions as entered, and where every version is a tag in the repo, carries OSV `GIT` ranges with the tags' commits (73% of such entries), so OSV tools can use them too. Records with only such entries go in `GIT/all.zip`. The tracker looks the tags up with `git ls-remote` (no API quota).
- **The tracker watches C/C++ upstreams:** the 3,603 GitHub repos that vcpkg ports, Bazel modules and ConanCenter recipes build from (`tracker/seeds/cpp-upstreams.txt`), 3,358 of them new.
- **The release audit checks the GIT ranges** against the repos' tags as they are now.
- **Ranges with a "Version" label** (`Version > v9.1.0425 and Version < v9.1.0689`) are read.
- **C/C++ and other upstream sources are listed** (Phase 6, step 1): git submodules (at the commit in the git index), CMake `FetchContent` / `ExternalProject` / CPM, Bazel `bazel_dep` and `http_archive` / `git_repository` (with wrappers), `vcpkg.json` (baseline, overrides, the ports' own dependencies, the project's own ports), Conan (`conan.lock`, `conanfile.txt`/`.py`) and meson wraps. Bazel modules, vcpkg ports and Conan packages are mapped to their upstream repo and tag through the Bazel Central Registry, the vcpkg baseline and ConanCenter. On 85 popular C/C++ projects, 89% of the 857 upstream sources found end with a repo and a tag or commit. Vendored copies (a license file under `third_party/`, `vendor/`, ...) are reported. They're checked against the repo's advisories in limbo (below).
- **A C/C++ project with nothing to read says so,** naming its build files, instead of suggesting the files were ignored by `.gitignore`.
- **Fixed: a `conan.lock` made the whole inventory fail** ("no offline version of the OSV database is available"): offline, OSV-Scanner needs a database for ConanCenter, which isn't in OSV's ecosystem list. The watcher's empty databases and the feed's per-ecosystem zips now include it.
- **limbo.watch home page, redesigned.** It opens with the question ("Your scan came back clean. Is it?") and shows the demo app's result: 0 Dependabot alerts, 16 advisories in limbo. Next comes one advisory's first 60 days: drag a slider or press play to see what the maintainer, GitHub's review, your scanner and Limbowatch each show on each day. Then the live numbers and GitHub's own words on its review goals. A new section explains what this means for SOC 2 (CC7.1) and PCI DSS (6.3.3) deadlines, with sources (F-134). Last comes the CI step for GitHub Actions and GitLab CI, in tabs. The live lists, the ecosystem and CVE tables and the package checker are still there.

## 0.1.0a6 (2026-11-10)

Still an **alpha**. On PyPI it's `0.1.0a6`; the GitHub tag and the action's ref are `v0.1.0a6`; the image is `ghcr.io/limbowatch/limbowatch:0.1.0a6`; the GitLab CI/CD component is `0.1.0-alpha.6`. **Maven projects get more findings:** `pom.xml` dependencies are now resolved through deps.dev and Maven Central (`--no-resolve-maven` to keep the inventory offline).

- **Org-wide mode: `limbowatch watch`** checks every project of GitLab groups (with subgroups), Gitea or Forgejo organizations, or git URLs, in one run. Each project is cloned shallowly and inventoried like `scan`; each source repo is polled once for all projects. It reports one line per project, with archived, empty and excluded projects listed as not checked, and keeps state and issues per project. Formats: table, JSON, Markdown. A source that can't be listed exits 2 (docs/WATCHER.md, F-129, F-130).
- **Maven: transitive dependencies are checked.** Offline, a `pom.xml` gives only its direct dependencies with a literal version (3 of spring-petclinic's 171). When the tree has a `pom.xml`, a second OSV-Scanner run, limited to `pom.xml` and its resolver, now resolves the whole tree through deps.dev and Maven Central; on two Spring Boot projects it matched `mvn dependency:list` exactly, and it found 37 advisories in limbo that the offline inventory couldn't see. `--no-resolve-maven` keeps the inventory offline (`scan`, `watch`, `inventory`) (F-132).
- **Never silent about what isn't resolved:** a `pom.xml` whose transitive dependencies weren't resolved (a module that needs an unreleased sibling, a private registry, `--no-resolve-maven`), and a Gradle build without a lockfile, are reported as unchecked, with the reason.
- **Image:** includes git, for `limbowatch watch` (about 100 MB more).
- **Fix: several unreadable lockfiles of one kind no longer stop the inventory.** OSV-Scanner lists them on indented lines under one error line, which the parser didn't read, so the scan exited 2 instead of reporting each file as unreadable (F-131).
- **The GitHub Action has its own repository, [limbowatch/limbowatch-action](https://github.com/limbowatch/limbowatch-action)**, so it can be listed in GitHub Marketplace: `uses: limbowatch/limbowatch-action@v0.1.0a5`. It's a copy of `integrations/action/`, made at each release, and `limbowatch/limbowatch/integrations/action@<tag>` keeps working.

## 0.1.0a5 (2026-11-10)

Still an **alpha**. On PyPI it's `0.1.0a5`; the GitHub tag and the action's ref are `v0.1.0a5`; the image is `ghcr.io/limbowatch/limbowatch:0.1.0a5`; the GitLab CI/CD component is `0.1.0-alpha.5`.

- **limbo.watch package checker** (`/check/`): type a package and the site checks it and its whole dependency tree, resolved by deps.dev, against the advisories in limbo, for npm, PyPI, crates.io and Maven. It runs in the browser with the watcher's own range parsing (done at publish time) and ports of its version orderings, tested against the Python code (F-118). `limbowatch publish` writes `check/index.json`.
- **Fix: a CVE record no longer links an advisory it only mentions.** The tracker took GHSA IDs from anywhere in a CVE record, so a description such as "distinct from GHSA-…" counted that advisory as having an uncited CVE, or as a duplicate if the CVE was reviewed under another ID. It now links only through the record's references and `source`, and re-reads records it stored under the old rule (F-120).
- **Fix: version ranges are read the way maintainers wrote them** (F-123). Commas re-read as "or" keep each interval whole (`>= 2.2.0, < 2.2.10, >= 2.3.0, < 2.3.7` no longer covers every version), `>= 3.8.8, <= 3.8.8` is one version, `2.16.*` and `11.0.0-11.5.50` are intervals, and Packagist versions with four parts order correctly (`6.7.13.0 < 6.7.13.1`). A range that still contradicts itself is reported as possibly affected, never as affected or clean.

## 0.1.0a4 (2026-11-08)

Still an **alpha**. On PyPI it's `0.1.0a4`; the GitHub tag and the action's ref are `v0.1.0a4`; the image is `ghcr.io/limbowatch/limbowatch:0.1.0a4`; the GitLab CI/CD component is `0.1.0-alpha.4`.

- **Fix: Go advisories that name a separate module below another module's path no longer match the parent module.** For example, `github.com/aws/aws-sdk-go-v2/service/kinesis` is a module of its own with its own versions, and 0.1.0a1 to 0.1.0a3 compared it against `github.com/aws/aws-sdk-go-v2`'s version. The tracker now asks the Go module proxy which module contains each Go path. The feed names that module, the way OSV's Go records do: `package.name` is the module and `ecosystem_specific.imports` is the package. The watcher matches by module. Where the module isn't known, a path below the dependency's module is reported as possible (F-113).

## 0.1.0a3 (2026-11-08)

Still an **alpha**. On PyPI it's `0.1.0a3`; the GitHub tag and the action's ref are `v0.1.0a3`; the image is `ghcr.io/limbowatch/limbowatch:0.1.0a3`; the GitLab CI/CD component is `0.1.0-alpha.3`.

- **GitHub Action:** runs the pinned, attested image on Linux runners with Docker, the same one the GitLab component runs. It falls back to pip on macOS, Windows and container jobs, or you can choose with `install: auto | image | python`. New `allow-failure` input: findings pass with a warning, a scan that couldn't run still fails. `report.sarif` is added to the reports folder.
- Maven releases come from Maven Central: the tracker polls the top 10,000 Maven packages' `maven-metadata.xml` once a day with ETags, because ecosyste.ms's Maven data lags by weeks and Maven Central has no current bulk feed (F-108).

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
