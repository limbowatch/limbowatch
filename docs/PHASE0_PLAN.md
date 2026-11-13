# Phase 0 Plan

| Rev | Date | Status | Change |
|---|---|---|---|
| 1 | 2026-10-19 | superseded | Initial plan |
| 2 | 2026-10-20 | superseded | Fact-vector model and new classes; cvelistV5 feed and all-CNA CVE ingestion; ecosystem plugin tiers (goal: all languages); run-anywhere and org-wide mode; open-source licensing; Phases 6–7 |
| 3 | 2026-10-20 | superseded | Build-vs-reuse (§1a): OSV-Scanner is the inventory backend and OSV the source of reviewed matching; our own range evaluation only for repo-advisory ranges; Phase 1/3/6 scope reduced accordingly |
| 4 | 2026-10-21 | superseded | Renamed **Limbowatch** ("Ghost CVE" already means *reserved but public*, F-037); classes `GHOST_*` → `LIMBO_*`; `RBP` state added; **phase order changed for awareness: public report → live tracker → scanner** (§10); scanner phases renumbered 3–8 |
| 5 | 2026-10-21 | **approved 2026-10-21**; Phase 1 draft complete; Phase 2 approved 2026-10-26, built and reviewed 2026-10-31; Phase 3 approved 2026-10-31, closed 2026-11-05 without outreach (F-072 to F-077; unsent drafts in docs/outreach/); Phase 4 approved 2026-11-05 (org-wide mode moved to Phase 5; issue creation tested against a local Gitea in Docker), built 2026-11-05, reviewed and approved 2026-11-06; released 2026-11-07 as 0.1.0a1, an alpha (PyPI `limbowatch`, `limbowatch-cli`; GitLab CI/CD Catalog `limbowatch/limbowatch-component`, F-086) (F-078 to F-085; docs/WATCHER.md); Phase 4 closed 2026-11-07 (FINDINGS summarized through F-098); **Phase 5 approved 2026-11-07**, re-scoped in §13.11; steps 1, 2 and 4 done; step 3 (org-wide mode) built 2026-11-10, §13.16; Maven/Gradle resolution checked 2026-11-10, §13.17; FINDINGS summarized through F-132; released as 0.1.0a6 (F-133); Phase 5 reviewed and closed 2026-11-10; **Phase 6 approved 2026-11-10**, re-scoped in §13.18; built 2026-11-11, released as 0.1.0a7 and, after two independent reviews, 0.1.0a8 and 0.1.0a9 (F-135 to F-144; 0.1.0a7 and 0.1.0a8 yanked); FINDINGS summarized through F-144; closed 2026-11-11. **Phase 7 (GitHub as a host) approved 2026-11-11 (§13.19), built 2026-11-12 (F-145 to F-148), released as 0.1.0a10 (F-149); a recheck found labels dropped for tokens without push access, fixed and released as 0.1.0a11 (F-150 to F-152); dependencies upgraded (OSV-Scanner 2.7.1, Python 3.14 image) and released as 0.1.0a12 (F-153, F-154); FINDINGS summarized through F-155; reviewed and closed 2026-11-12. **Phase 8 (website redesign) approved 2026-11-12 (§13.21)**; steps 0 and 1 done (F-158, docs/redesign/); a range bug found on the way fixed and released as 0.1.0a13 (F-159 to F-161); the public proof repository limbowatch/limbo-poc (F-162); step 3 shipped for home, compliance, the advisory template, the scan page's proof and the navigation (2026-11-12, the maintainer's go-ahead to update the site); then (2026-11-12, the maintainer's go-ahead) the design-system pass (docs/redesign/DESIGN.md), the tracker's fix filter, the scan page's tabs and screenshots refreshed on 0.1.0a13, the audit's examples check and the checks of step 5 (F-163); then a security review and its fixes (F-164), the scan's data and hosts documented (F-166), the daily report (F-167) and search visibility (F-168); FINDINGS summarized through F-168; **reviewed and closed 2026-11-13** | No duplicate scanner: the npm/PyPI/Go scan-time CI check is blindspot's (F-036), so we **contribute** to it instead. The tracker also publishes an open **limbo feed** (OSV schema) others can consume. Tracker coverage defined (§7a). Phases: report → tracker + feed → upstream contributions → watcher → ecosystems → upstream-watch |

Inputs: [SPEC.md](SPEC.md) (requirements) and [FINDINGS.md](FINDINGS.md) (verified facts, cited as F-NNN).

## 1. Goal and scope

**Primary goal:** make the review gap visible. Show, with reproducible public data, how many published advisories sit in limbo (published, not reviewed, invisible to scanners) and for how long.

**End goal:** detect advisories in limbo for **any repo** (GitLab, Gitea/Forgejo, GitHub, plain git) in **any language**.

**Order:** a public report (Phase 1) and a live tracker with an open limbo feed (Phase 2) come first, to make the case. Then upstream contributions (Phase 3), so existing tools benefit instead of being duplicated. Then the Limbowatch watcher (Phase 4): stateful GitLab/Gitea workflow that no tool provides. Every interface is built for the end goal from the start, so adding an ecosystem or host means adding a plugin, not reworking the core.

**Product principle:** never silently skip. If a dependency can't be fully checked, the specific check that couldn't run is reported with a reason.

## 1a. Build vs reuse (verified 2026-10-20)

Limbowatch builds **only what no existing tool does**. Everything else is consumed (F-032 to F-035).

| Capability | Who already does it | Decision |
|---|---|---|
| Lockfile/manifest inventory, about 25 formats incl. pnpm, uv, Gradle, Maven `pom.xml` with transitive resolution | OSV-Scanner / OSV-Scalibr (Apache-2.0) | **Reuse:** `osv-scanner scan source --format json --all-packages` as the default backend; CycloneDX/SPDX input as the alternative |
| Matching *reviewed* advisories to versions | OSV API (querybatch) | **Reuse:** OSV results are the `osv` fact; no re-implementation |
| Aggregating reviewed GHSA plus ecosystem DBs | OSV | **Reuse;** GitHub global API only for states OSV lacks (unreviewed / absent) |
| Package→repo mapping | deps.dev (7 systems, provenance), ecosyste.ms | **Reuse** as mapper-chain tiers; build only the URL normalizer, overrides and recipe-repo blocklist |
| Version comparators | univers | **Reuse;** custom only for pub and swift |
| Measuring the gap for a list of repos | Safeguard `advisory_gap.py` (repo list → OSV check) | Prior art for research; credit its data |
| Stateless scan-time CI check for npm/PyPI/Go (lockfile → repo advisories → OSV → SARIF/gate, GitHub Action) | blindspot (F-036) | **Contribute, don't rebuild:** GitLab CI template, Code Quality output, global-DB check, duplicate detection, RBP flag, reading the limbo feed |
| Live, continuously updated measurement of the gap, plus an open machine-readable feed of advisories in limbo | nobody (F-034, F-036, F-037) | **Build** (Phase 2) |
| Joining a real inventory to unreviewed repo advisories with version matching | blindspot for npm/PyPI/Go (F-036) | **Build only inside the stateful watcher** (Phase 4), using the feed and OSV-Scanner inventory, for hosts and ecosystems blindspot doesn't cover |
| **Tolerant evaluation of maintainer-entered ranges, duplicate-GHSA detection, repo vs reviewed drift** | nobody | **Build** |
| **Reserved / pre-review CVE detection; cvelistV5 feed matching by repo** | nobody | **Build** |
| **Fact vector, scanner-family visibility, limbo age, permanence** | nobody | **Build** |
| **GitLab/Gitea workflow: CI component, issues with lifecycle comments, org-wide watch** | nobody for limbo advisories | **Build** |

**Accepted risks of reuse:**
- An external Go binary: bundled in the OCI image; for `pip`/`uvx` installs it must be on PATH, otherwise users fall back to SBOM input.
- Its handling of unresolvable dependencies must be checked in Phase 4. If it silently drops them, Limbowatch adds its own `UNRESOLVED` detection for those manifests.

## 2. Facts the design rests on

- Advisories wait a median of **55 days** between repo publication and GitHub review (F-010). Until then they're absent from the global DB and OSV package data (F-012).
- CVE publication is delayed too, but in every sampled case it came before review (F-011).
- Events occur in any order. 11.7% of reviewed advisories have no CVE (F-016). Other-CNA CVEs are almost never reviewed, and their unreviewed records carry no package data (F-017).
- The cvelistV5 delta log is a global feed of GitHub-CNA CVEs. `vendor`/`product` equal the repo `owner`/`repo` in 251 of 254 (F-013).
- Package names in repo advisories can be wrong (F-014). Ecosystems outside GHSA's enum are never reviewed (F-015, F-023).
- NVD now defers non-priority CVEs immediately (F-005, F-018). GitLab SARIF ingestion is Ultimate-only and treats findings without a CVE as SAST (F-008).

## 3. Domain model: a fact vector per vulnerability

Sources are merged into one **vulnerability** through an alias graph (union-find over GHSA ↔ CVE ↔ GO/PYSEC/RUSTSEC/OSV IDs). Each vulnerability carries independent facts. These are snapshots that can change in any order:

```
repo_advisory : none | published | withdrawn             (+ published_at, repo, packages, ranges)
cve           : none | reserved(RBP) | published(cna)     (+ datePublished, CNA score; RBP via cveawg /api/cve-id, F-029)
ghsa_global   : absent | unreviewed | reviewed | withdrawn (+ has_package_data, ranges)
osv           : none | cve_only(GIT ranges) | ecosystem_record(source id)
nvd           : absent | {vulnStatus, nist_primary_cvss?, cpe_configurations?}
```

### Classifications (flags derived from facts; a finding can carry several)

| Class | Condition (for an affected dependency version) | Priority |
|---|---|---|
| `LIMBO_ADVISORY` | repo advisory published, no public CVE, GHSA not reviewed (+ `RBP` flag when its CVE ID is *reserved but public*, the CVE Program term, F-037) | 1 |
| `LIMBO_CVE` | CVE published (repo advisory or GitHub CNA), GHSA not reviewed | 2 |
| `ORPHAN_CVE` | CVE from another CNA, no repo advisory, GHSA not reviewed | 3 |
| `NO_CVE` | GHSA reviewed, no CVE | 4 |
| `OSV_MISSING` | GHSA reviewed, no OSV ecosystem record (usually brief) | 5 |
| `RANGE_DRIFT` | repo advisory / GHSA / OSV disagree on whether this version is affected | 5 |
| `NVD_UNENRICHED` | CVE exists, no NIST `Primary` CVSS and/or no CPE configurations | info |
| `UNRESOLVED(check, reason)` | a specific check couldn't run (no resolved version, no repo mapping, upstream not on GitHub, no comparator…) | always shown |

`primary_class` is the highest-priority flag and is used for sorting and gating. Flags implied by a higher one are hidden: a LIMBO_* finding implies OSV_MISSING, so that flag isn't shown separately.

### Visibility per scanner family (modeled, not measured)

Each finding states who **can't** see it:

| Family | Example tools | Sees the vuln when |
|---|---|---|
| `github_native` | Dependabot, npm audit | GHSA reviewed with package data |
| `osv` | OSV-Scanner, pip-audit, govulncheck*, Trivy*/Grype* | OSV ecosystem record exists |
| `gitlab_ds` | GitLab dependency scanning | Unknown. Its DB must not be queried; modeled as "no earlier than `github_native`" and labeled as modeled |
| `nvd_cpe` | Dependency-Check, VM tools | NVD CPE configurations exist |
| `cve_keyed` | compliance/SLA tracking | CVE published |

\* These tools aggregate their own DBs, so the mapping is approximate and labeled that way.

Config `scanners: [...]` (default `gitlab_ds`) sets how loud each class is. For example, `NO_CVE` is loud for `nvd_cpe`/`cve_keyed` shops and quiet for `osv` ones.

### Lifecycle, age and permanence

- **Events** are any change in a fact (hash diff of snapshots): CVE assigned, reviewed, reached OSV, range changed, withdrawn. Order doesn't matter.
- **Limbo age** runs from the earliest public evidence (min of repo `published_at` and CVE `datePublished`) until the vulnerability becomes visible to the configured scanners.
- **Permanence:** `likely_permanent` when the ecosystem isn't in GHSA's enum (F-023) or the class is `ORPHAN_CVE`; otherwise `pending`. Report text differs between the two ("probably never" vs. "not yet").

### Severity

Order: GHSA-reviewed → repo advisory → CNA score (CVE record) → NVD NIST `Primary`. The source is always recorded. If nothing is available, severity is `unknown`, gated by `--fail-on-unknown`.

## 4. Data sources

| Source | Used for | Access | License / terms |
|---|---|---|---|
| GitHub repo advisories `GET /repos/{o}/{r}/security-advisories` | LIMBO_ADVISORY/LIMBO_CVE (earliest signal) | token recommended; ETag (304 free only when authenticated, F-003) | GHSA: CC-BY 4.0, attribution in reports |
| GitHub global `GET /advisories`, `/advisories/{ghsa}` | reviewed/unreviewed status | must pass `type` explicitly (F-002) | CC-BY 4.0 |
| OSV `querybatch` + `/v1/vulns/{id}` | OSV coverage, ecosystem DB records, GIT ranges | no auth; per-query pagination (F-004) | per-source licenses, verify in Phase 2 |
| NVD API 2.0 | enrichment status, NIST score | optional API key | verify terms in Phase 2 |
| CVE Services `cveawg.mitre.org/api/cve/{id}` | CVE existence, CNA, CNA score | no auth (F-006) | CVE terms of use, verify in Phase 2 |
| **cvelistV5 `deltaLog.json`** (new) | global feed of new and updated CVEs from all CNAs; triggers re-polls | raw.githubusercontent, not the API rate limit (F-013) | as CVE |
| Registries (npm, PyPI, Go proxy Origin / go-get) | package→repo, first-tier | per registry | — |
| **deps.dev v3** (new) | package→repo with provenance, 7 systems (F-020) | no auth; caching permitted | Google API ToS |
| **ecosyste.ms** (new, Phase 6) | package→repo for ~100 registries (F-021) | 5,000/hr anonymous | data CC BY-SA 4.0, see §11 |
| GitLab Advisory DB | — | **never used** | terms prohibit third-party tools |

## 5. Matching an advisory to a dependency

Ranked by confidence; every match records the method and evidence.

1. **Package and repo agree:** advisory package (ecosystem + name) equals our purl **and** the advisory repo equals our mapped repo. High confidence.
2. **Repo only:** the advisory's repo equals our mapped repo, but its package data is missing, wrong (F-014) or `other`. Medium confidence, shown with the advisory's package data quoted.
3. **CVE record:** a GHSA link, a `repo` field or github.com/{owner}/{repo} reference equal to our mapped repo, or `packageName` + `collectionURL` matching our purl. Medium to high confidence. Fuzzy `vendor`/`product` matching is out of scope (too many false positives).
4. **Package only:** the advisory package equals our purl, but the advisory repo differs from our mapping. Low confidence, flagged as a "mapping conflict" for review.

Monorepos: one repo maps to many packages; within a repo, matching uses `vulnerabilities[].package`.

## 6. Any language: ecosystem plugins and tiers

An `EcosystemPlugin` declares its capabilities:
- purl type, GHSA ecosystem ID, OSV ecosystem name
- inventory parsers (file patterns)
- version comparator
- repo mappers

A missing capability produces `UNRESOLVED(check, reason)` for that check only. Plugins register through Python entry points, so third parties can add ecosystems. `limbowatch ecosystems` prints the live coverage matrix, and the README embeds it.

| Tier | Ecosystems | Inventory | Mapping chain | Versions |
|---|---|---|---|---|
| **1 Full** | npm, PyPI, Go (MVP) → **Maven/Gradle next**, then Cargo, RubyGems, Composer, NuGet | OSV-Scanner `--all-packages` (§1a) or SBOM | registry-native → deps.dev → overrides | univers (F-022) |
| **2 Extended** | Hex/Erlang, Pub, Swift, CocoaPods, Conan, R, Haskell, … | OSV-Scanner where supported (mix.lock, pubspec.lock, conan.lock, renv.lock, cabal/stack) or CycloneDX/SPDX | ecosyste.ms → overrides | univers; small custom comparators for pub and swift |
| **3 Upstream-watch** | C/C++, git submodules, vendored code, CMake FetchContent, vcpkg, Bazel, CPAN, CRAN, Hackage | `.gitmodules`, `vcpkg.json`, `conan.lock`, `MODULE.bazel`, … | the repo URL itself | commit vs. OSV GIT ranges where known, else "version unknown" |

**Mapping confidence by provenance:** SLSA / PyPI / RubyGems publish attestation and Go Origin, then registry metadata, then deps.dev `UNVERIFIED_METADATA`, then ecosyste.ms. Overrides win. A blocklist of packaging/recipe repos (e.g. `conan-center-index`, F-021, Q7) keeps those from being treated as upstream.

**Maven/Gradle (first post-MVP ecosystem):**
- Maven has no lockfile. `pom.xml` gives only declared versions, and real versions depend on property interpolation, parent POMs, BOM imports and mediation, so parsing `pom.xml` alone yields `UNRESOLVED(no_resolved_version)`.
- Resolved inventory: OSV-Scanner resolves `pom.xml` transitively via deps.dev's resolver and reads `gradle.lockfile` (F-032). Alternatives are CycloneDX SBOMs from `cyclonedx-maven-plugin` / `cyclonedx-gradle-plugin`. Phase 5 checks OSV-Scanner's resolution against the build tool's output on a real project.
- Mapping uses the POM `<scm>`, following parent POMs, because deps.dev missed `commons-text` (F-020).

## 7. Any repo: running anywhere

- **Distribution:** PyPI (`uvx limbowatch`) plus an OCI image bundling osv-scanner (Phase 5).
- **Per-repo CI:** GitLab CI/CD Catalog component (Phase 4), plus a Gitea/Forgejo/GitHub Action, all from one Actions-compatible definition. Jenkins, Woodpecker and cron run the container.
- **Org-wide central mode (Phase 5):**
  - `watch` reads a list of sources: GitLab groups, Gitea orgs, git URLs.
  - Manifests are fetched through host APIs, or a shallow clone for plain git.
  - **Each upstream repo is polled once for all projects**, so cost grows with unique upstreams, not with the number of repos.
  - The cvelistV5 feed triggers immediate re-polls of matching upstreams.
- **Trackers:** an `IssueTracker` protocol with GitLab first, then Gitea/Forgejo (both Phase 4), GitHub and a generic webhook. Issues are deduplicated by finding key and receive event comments ("CVE assigned", "has now reached scanners").
- **Output formats:** table, json, markdown, sarif (GitLab Ultimate ≥ 19.2), codequality (all GitLab tiers, MR widget).

## 7a. Live tracker: what it covers (and what it can't)

GitHub has no global list of repository advisories (SPEC), so the tracker can't see *all* of them. It covers a defined, published watchlist and states its coverage. **Every number is a floor.**

**Watchlist (repos polled daily, ETag-conditional so unchanged repos cost nothing, F-001/F-003):**
1. Every repo that has had a reviewed advisory originate from it (`repository_advisory_url` in the global DB; 98.8% of recent reviews, F-016). These are the repos that use the feature.
2. Upstream repos of the top-N packages per ecosystem (by dependents, via deps.dev / ecosyste.ms).
3. Every repo referenced by a new GitHub-CNA CVE in the cvelistV5 delta feed (F-013).
4. Snowball: any repo found publishing an advisory through sources 1–3 stays on the list.

**Blind spot:** a repo whose *first* advisory has no CVE, isn't reviewed yet, and isn't a popular upstream. It appears once a CVE or review reveals it. Watchlist size is measured in Phase 2.

**Tracked per advisory (fact snapshots, §3):** repo publication → CVE reserved (RBP) / published → GitHub review (or a duplicate under another ID) → in OSV → NVD status. Each transition is timestamped.

**Published metrics:**
- in limbo now, by ecosystem, severity, age bucket and CNA
- completed review lag (median and p90)
- likely-permanent limbo (unsupported ecosystems)
- RBP count and age vs the 72-hour policy
- suspected duplicates
- NVD-unenriched share
- popular packages currently in limbo, with fix version

**Not covered:** commercial DBs, the GitLab Advisory DB (terms), silently fixed vulnerabilities without an advisory (Aikido's domain), and projects that don't use GitHub repository advisories.

**Open data:** daily snapshots (CC BY 4.0) plus a **limbo feed** in OSV schema: IDs, packages, ranges, fixed versions, links and lifecycle timestamps. Full advisory text is excluded until its redistribution terms are verified (Phase 2). OSV-Scanner can't load custom DBs today (F-039), so we propose that upstream in Phase 3.

## 8. Repo layout and module boundaries

```
Limbowatch/
├─ pyproject.toml                 # uv workspace root; ruff, mypy --strict, pytest, import-linter
├─ packages/
│  ├─ core/src/limbowatch/
│  │  ├─ models/                  # pydantic v2: Dependency, PackageRef(purl), UpstreamRepo, SourceRecord,
│  │  │                           #   Vulnerability, Facts, Finding, Visibility, Evidence, Severity
│  │  ├─ ecosystems/              # EcosystemPlugin protocol, registry, capability model
│  │  │  ├─ npm/ pypi/ golang/    # comparator + mappers + ID mappings per ecosystem (Tier 1); no lockfile parsers
│  │  ├─ inventory/               # backends: osv_scanner (subprocess, pinned), cyclonedx, spdx; UNRESOLVED detection
│  │  ├─ mapping/                 # chain runner, url_normalize, deps_dev, ecosystems_ms (Phase 5), overrides, blocklist
│  │  ├─ http/                    # async client: limits, backoff, Retry-After/X-RateLimit, ETag cache, redaction
│  │  ├─ sources/                 # github_repo, github_global, osv, nvd, cve_record, cve_feed → SourceRecord
│  │  ├─ versions/                # comparator adapters; github_range + osv_events evaluators
│  │  ├─ diff/                    # PURE: alias graph, facts, match, classify, visibility, severity, permanence
│  │  ├─ report/                  # table, json, markdown, sarif, codequality (+ attribution)
│  │  ├─ trackers/                # IssueTracker protocol; gitlab, gitea (Phase 4)
│  │  ├─ hosts/                   # project sources for org-wide mode: gitlab, gitea, git (Phase 4)
│  │  ├─ store/                   # SQLAlchemy 2.0 models, repositories, alembic/
│  │  ├─ watch/
│  │  ├─ config.py                # limbowatch.yml schema; secrets from env
│  │  └─ pipeline.py              # scan(): public API surface a future FastAPI wraps
│  └─ cli/src/limbowatch_cli/       # typer: scan, watch, ecosystems; formats; exit codes; --verbose evidence
├─ tests/{fixtures,scenarios}/    # recorded real responses; one scenario per class
├─ scripts/                       # record_fixture.py, measure_gap.py: the only code that touches the network
├─ templates/                     # GitLab CI/CD component, Actions definition
└─ README.md
```

**Rules, enforced with import-linter:**
- `diff/` and `versions/` do no I/O.
- `sources/` never classifies.
- Only `http/` builds requests (one place for token redaction).
- Core never imports cli.
- Ecosystem-specific code lives only in `ecosystems/`.

## 9. DB schema (SQLite now; Postgres-safe)

| Table | Key columns |
|---|---|
| `http_cache` | `key` (unique), `etag`, `last_modified`, `status`, `body`, `fetched_at`, `expires_at` |
| `upstream_repos` | `id`, `host`, `owner`, `name`, unique(`host`,`owner`,`name`), `on_github`, `last_polled_at`, `poll_etag`, `poll_status` (shared across projects) |
| `packages` | `id`, `ecosystem`, `name`, `purl_base` (unique) |
| `repo_mappings` | `package_id`, `upstream_repo_id`, `subdir`, `confidence`, `provenance`, `method`, `evidence`, `is_override`, `resolved_at` |
| `projects` | `id`, `name`, `locator`, `host_kind`, `host_project_ref` |
| `scans` | `id`, `project_id`, `started_at`, `finished_at`, `input_kind`, `input_ref`, `tool_version` |
| `scan_dependencies` | `scan_id`, `package_id`, `version`, `declared_spec`, `resolution`, `direct`, `dev`, `source_file`, `inventory_backend` |
| `source_records` | unique(`source`,`source_id`), `cna`, `modified_at`, `fetched_at`, `raw`, `normalized` |
| `record_aliases` | `record_id`, `alias` (indexed) |
| `record_affected` | `record_id`, `ecosystem`, `package_name`, `repo`, `range_kind` (github_range / osv_events / versions / git_commits / cpe), `range_data` |
| `vulnerabilities` | `id` (UUID, stable when alias clusters merge: the older ID is kept), `display_id`, `first_seen` |
| `vulnerability_records` | `vulnerability_id`, `record_id` |
| `vuln_fact_snapshots` | `vulnerability_id`, `observed_at`, `facts`, `facts_hash` (change detection) |
| `findings` | `finding_key` (unique: sha256(project, purl_base, vulnerability_id)), `version`, `flags`, `primary_class`, `visibility`, `permanence`, `limbo_since`, `severity`, `severity_source`, `match_confidence`, `status`, `first_seen`, `last_seen`, `evidence` |
| `finding_events` | `finding_id`, `scan_id`, `event`, `diff`, `at` |
| `feed_cursors` | `feed`, `cursor`, `updated_at` (cvelistV5 position) |
| `tracker_issues` | `finding_id`, `tracker`, `base_url`, `project_ref`, `issue_ref`, `last_synced_at` |

The finding key uses the internal vulnerability UUID (not an alias string) and leaves out the version. When a GHSA appears later for a CVE-keyed finding, or the user upgrades between affected versions, the existing issue is updated instead of a new one being opened.

## 10. Phases and order of work

Each phase ends with a review stop and a cleanup of the findings report.

| Phase | Scope |
|---|---|
| **1 "State of the Gap" report** | Public write-up from existing data (FINDINGS F-010 to F-039). Framed as an independent replication of Safeguard and munim's census, plus new angles: popular projects shipping affected versions that OSV-Scanner reports clean, RBP CVEs, NVD enrichment, duplicate GHSA IDs. Neutral; cites GitHub's throughput statement (F-035); credits prior work. Reproducible research scripts under `research/`; README v1. |
| **2 Live Limbo Tracker + feed** | Scaffold (uv workspace, ruff, mypy --strict, pytest, import-linter, GitHub Actions CI). Core models, `http/` (ETag cache, rate limits, retries), `store/`. Mapper chain (registry-native, Go Origin → go-get, deps.dev, overrides, recipe-repo blocklist). Collectors: GitHub repo + global, OSV, NVD, CVE record + `cve-id` (RBP), **cvelistV5 delta feed**. Watchlist and coverage per §7a. **Tolerant evaluator for repo-advisory ranges** (F-030) and **duplicate-GHSA detection** (F-028). Fact snapshots and transitions. Daily scheduled run → static site (GitHub Pages) + CC BY 4.0 snapshots + **limbo feed (OSV schema)**. Recorded fixtures for every source; most thorough tests on range evaluation and dedup. Verify data-source and advisory-text licenses. |
| **3 Upstream contributions** | Re-check blindspot's scope first (it's evolving fast). Offer PRs: GitLab CI template, Code Quality output, global-DB check (not reviewed vs OSV lag), duplicate detection, RBP flag, consuming the limbo feed. OSV-Scanner: feature request for custom/extra local DBs (F-039). Coordinate with RogoLabs on RBP data rather than duplicating it. |
| **4 Limbowatch watcher** | Stateful layer no tool provides. Inventory via OSV-Scanner `--all-packages` + CycloneDX/SPDX (`EcosystemPlugin` capability → `UNRESOLVED`; verify OSV-Scanner's unresolved handling). Matching against the feed, plus on-demand polling for long-tail upstreams. Fact-snapshot change detection, `scan --state` for CI. GitLab CI/CD component; GitLab and Gitea/Forgejo issues with lifecycle comments ("CVE assigned", "has now reached scanners"). Outputs: table/json/markdown/sarif/codequality, `--fail-on`, `--fail-on-unknown`. |
| **5 Ecosystem expansion** | Org-wide sources (GitLab group, Gitea org, git URLs) with shared polling (moved from Phase 4, §13.7). Mapping and comparators (inventory already comes from OSV-Scanner): **Maven/Gradle first** (POM `<scm>` with parents), then Cargo, RubyGems, Composer, NuGet. Tier 2 via ecosyste.ms + pub/swift comparators. Tracker watchlist extended to the same ecosystems. OCI image bundling osv-scanner. |
| **6 Upstream-watch** | Tier 3 detectors (submodules, vcpkg, conan, FetchContent, Bazel, vendored dirs); commit evaluation against OSV GIT ranges. |
| **7 GitHub as a host** | The watcher's issues and org-wide mode on GitHub, as on GitLab and Gitea: a GitHub issue tracker (`--issues github`, the action's `issues: github` with the job's `GITHUB_TOKEN`) and `limbowatch watch --github-org`. GitHub-aware writes (secondary limits). Live e2e in a private test repo. §13.19. |
| **8 Website redesign** | The whole of limbo.watch around one story: a fixed, public advisory that scanners stay silent about, so no alert, no remediation clock and no upgrade. Live examples of popular packages in limbo, a page for security and compliance leads, a scan page generated from the current release, a lighter navigation and a refreshed design system across all pages. §13.21. |

## 11. Licensing (open source)

- **Limbowatch code:** **Apache-2.0 (decided 2026-10-21; see [LICENSE](../LICENSE)).** It includes a patent grant, is common for security tooling, and matches univers and OSV-Scanner. Other dependencies to check: python-gitlab is LGPL-3.0, which is fine as a dependency.
- **Data obligations:**
  - GHSA (CC-BY 4.0): attribution in every report.
  - deps.dev: Google API ToS (caching permitted).
  - OSV, NVD and CVE terms: verify in Phase 2.
- **ecosyste.ms (CC BY-SA 4.0, Q6):** use it only at runtime with a local cache, credit it in output when a mapping came from it, and **never bundle or redistribute** datasets derived from it (for example, a shipped default mapping file). Shipped override files are written by hand or built from non-SA sources. This isn't legal advice; revisit it before 1.0.

## 12. Deviations from SPEC

1. Classifications are flags with a primary, derived from a fact vector. `REPO_ONLY` is split into `LIMBO_ADVISORY`/`LIMBO_CVE`; `ORPHAN_CVE` is new.
2. `UNRESOLVED` applies per check, not per dependency.
3. `go.sum` is not an inventory source (only a cross-check); `go.mod` is the source.
4. `NVD_UNENRICHED` is based on NIST `Primary` metrics and/or CPE configurations, and is informational by default.
5. `RANGE_DRIFT` compares repo advisory, GHSA and OSV; NVD CPE ranges are shown as context only.
6. `OSV_MISSING` checks aliases.
7. Registry metadata is fetched per version.
8. Severity order puts GHSA-reviewed ahead of the repo advisory; `unknown` severity is gated explicitly.
9. CVE records come from CVE Services plus the cvelistV5 delta, not a full clone.
10. New sources: cvelistV5 feed, deps.dev, ecosyste.ms.
11. Scope extends to all languages and hosts (Phases 5–6, Gitea, org-wide mode), with a `codequality` output.
12. Added: SPDX input, Alembic, withdrawn handling, `scan --state` for CI.
13. Native lockfile parsers (`package-lock.json`, `requirements.txt`/`poetry.lock`/`uv.lock`, `go.mod`) are replaced by OSV-Scanner as the inventory backend (§1a). The SPEC's intent (resolved versions, never silently skip) is kept and verified in Phase 4.
14. No standalone scan-time CLI for npm/PyPI/Go: that's blindspot's job, and we contribute to it (§1a). The spec's CLI and CI requirements are met by the Phase 4 watcher, for GitLab/Gitea and other ecosystems.

## 13. Decisions needed for approval

Recommended defaults are in bold.

1. ~~Code license~~ **Decided: Apache-2.0** (2026-10-21).
2. **Decided: yes.** Add `codequality` output (Phase 3 as a blindspot contribution; Phase 4 in the watcher) (2026-10-21).
3. **Decided: defer** malware advisories past MVP (2026-10-21).
4. **Decided: yes.** Unscored LIMBO_* findings fail CI by default (`--fail-on-unknown=true`) (2026-10-21).
5. **Decided: `gitlab_ds`** is the default `scanners:` profile when unset (2026-10-21).
6. **Approved 2026-10-21.** Plan rev 5, including the phase order (§10), tracker coverage (§7a), Phases 5–6 and the §12 deviations, so Phase 1 can start.
7. **Decided 2026-11-05:** org-wide mode (watching a GitLab group or Gitea org with shared polling) is Phase 5, not Phase 4; Phase 4 watches one project at a time. This resolves the conflict between §7 and §10.
8. **Decided 2026-11-05:** end-to-end tests of issue creation run against a local Gitea in Docker; nothing is posted to a public host. Unit tests use recorded responses.
9. **Decided 2026-11-05:** the tracker publishes its watchlist with last-checked times, so the watcher polls only repos the tracker doesn't cover or hasn't checked recently. Nothing the watcher sees is sent back to limbo.watch.
10. **Decided 2026-11-05:** the repository is public, so the CI integrations' default source archive URL works without credentials. Before the switch, a scan of every commit found no tokens or keys, and no committed research data other than the aggregate `summary.json` and `followup-*.json` files.
11. **Decided 2026-11-07: Phase 5 approved, re-scoped.** Since §10 was written, the watcher already compares versions for npm, PyPI, Go, Cargo, Composer, RubyGems, Maven and NuGet, and maps packages to repos for seven ecosystems (deps.dev, RubyGems). Order, with a review stop after each step:
    0. Close Phase 4: summarize FINDINGS (done 2026-11-07).
    1. **Coverage** (FINDINGS F-098, Q20–Q22): measure how many repos the top packages per ecosystem map to and what polling them costs; extend the tracker watchlist in stages; test release-triggered checks; publish coverage per ecosystem.
    2. **Watcher completeness:** repo mapping for Composer (Packagist), Hex, Pub and Swift (ecosyste.ms), a Maven `<scm>` fallback, and the missing comparators.
    3. **Org-wide mode** (§13.7): a GitLab group or Gitea org with shared polling.
    4. **A container image** with OSV-Scanner built in.
12. **Decided 2026-11-07 (step 1):** the watchlist grows by the source repos of the most-used packages per ecosystem (F-099): the top 1,000 now (`tracker/seeds/top-packages.txt`, 5,797 repos, 3,342 new), the top 10,000 next, the top 50,000 only if the 10,000 prove worth it. The ranking is ecosyste.ms data (CC BY-SA 4.0): the seed file and the published watchlist (`feed/repos.txt`, `feed/watchlist.json`) are licensed CC BY-SA 4.0 with attribution; the feed and other advisory data stay CC BY 4.0. A run polls at most 2,500 never-checked repos (`--max-new`), so the daily re-checks aren't starved. Top 1,000 done 2026-11-07 (153 unreviewed advisories in the new repos, F-100); the steady-state re-check cost measured the same day was about 1,600 counted requests a run, leaving room for 2,500 new a day. Wave one of the top 10,000 (NuGet, Packagist, Maven, RubyGems; 22,422 new repos, about 9 daily runs) started 2026-11-07; npm, PyPI, Go and crates.io follow. Wave two (top 10,000 in all eight ecosystems, 53,999 repos in the seed) started 2026-11-09 with 19,330 repos not yet watched, plus 5,120 left from wave one: about 10 runs at `--max-new 2500`, sped up with manual runs spaced at least 75 minutes apart so each fits the PAT's hourly limit.
13. **Decided 2026-11-07:** release-triggered checks (docs/RELEASE_CHECKS.md) are built in the order collect → trigger → measure a week → relax the routine schedule, and releases of unwatched packages with at least 100 dependent repositories add their repos to the watchlist. Built the same day. The week's measurement was replaced by a backtest on the last month's advisories (F-104): **decided 2026-11-07**, repos without advisories are re-checked every 30 days instead of weekly, plus the release checks; repos with advisories and repos answering 404 keep their schedule. The watcher still checks a dependency's repo itself when the tracker's check is more than 10 days old.
14. **Step 2 (watcher completeness) started 2026-11-07, in parallel with step 1's week of measurement (approved):** repo mapping for Composer (Packagist), Hex and Pub (ecosyste.ms) and Swift (package URL), the Maven `<scm>` fallback with parent POMs, and comparators for Hex, Pub and Swift (F-103).
15. **Decided 2026-11-08:** the container image (step 4) is pulled forward for the GitLab component: built and attested in GitHub Actions (`ghcr.io/limbowatch/limbowatch`), copied by digest to the component project's registry, and pinned by digest in each component release. GitLab Ultimate's security features are opt-in (`security_report`), with a separate gate job, because GitLab reads SARIF only from a job that succeeds (F-106).
16. **Step 3 built 2026-11-10 (awaiting review):** `limbowatch watch` lists GitLab groups (with subgroups), Gitea/Forgejo orgs and git URLs, clones each project's default branch with `--depth 1`, inventories it like `scan`, maps and polls source repos once for all projects, and keeps state and issues per project (docs/WATCHER.md, F-129 to F-131). It reports archived, empty and excluded projects as not checked, and exits 2 when a source can't be listed. A token is scoped to one host, so a run with a token covers one host. Not built: re-polls triggered by the cvelistV5 feed (§7); the tracker's release checks and daily runs cover that for watched repos.
17. **Maven/Gradle resolution checked 2026-11-10 (F-132), the last open Phase 5 item (§9 "Phase 5 checks OSV-Scanner's resolution against the build tool's output").** Offline, OSV-Scanner gives a `pom.xml`'s direct dependencies with literal versions only (3 of 171 on spring-petclinic), and nothing said the rest were missing. Its online resolver matches `mvn dependency:list` exactly on two Spring Boot projects. Decided (approved scope, reversible): the inventory resolves `pom.xml` by default in a second OSV-Scanner run limited to the pom.xml extractor and resolver (only deps.dev and Maven Central are contacted), `--no-resolve-maven` turns it off, and every unresolved `pom.xml` or unlocked Gradle build is reported. Gradle lockfiles are read completely; Gradle without a lockfile can't be resolved without running the build.
18. **Decided 2026-11-10: Phase 5 closed; Phase 6 (upstream-watch) approved, re-scoped by F-135.** OSV-Scanner already checks submodules and vendored C/C++ against OSV's commit ranges (online), so we reuse it rather than rebuild it. The gap is ours: 60% of the limbo feed (14,785 of 24,561 records) has no package a scanner can match, and the watcher reads no C/C++ dependency files. Order, with a review stop after each step:
    0. **Measure:** which of the 1,858 repos behind package-less records are libraries (vcpkg ports, Bazel Central Registry modules, conan-center recipes); how often a patched version maps to an upstream tag (Q26); how ~30 real C/C++ projects consume dependencies; the API cost.
    1. **Detectors** (watcher inventory): git submodules (gitlink from the tree, no submodule fetch), CMake FetchContent/ExternalProject/CPM, `vcpkg.json` (builtin baseline → port → upstream), `MODULE.bazel` (BCR) and `http_archive`/`git_repository`, `conan.lock` (the recipe's source URL, never `conan-center-index`), vendored directories reported as "version unknown". The inventory names the dependency files it found and couldn't read.
    2. **Affected or not:** a version is compared with the advisory's range; a commit is compared with the fix tag through GitHub's compare API (identical/ahead: fixed; behind: affected; diverged: possibly affected), with method and evidence recorded.
    3. **OSV by commit:** each submodule or FetchContent commit is queried at OSV (`/v1/query` by commit), which evaluates OSV's GIT ranges on its side.
    4. **Feed:** package-less records carry the repo and the versions as entered, plus OSV `GIT` ranges where the fix version maps to a tag; the browser checker gains a repo + version/commit lookup.
    5. **Tracker coverage:** upstreams of vcpkg ports, BCR modules and conan-center recipes join the watchlist in stages.
    6. **Wrap-up:** annotations on the manifest line, docs, FINDINGS cleanup, audit, release.

    Decisions (all as recommended): (A) detectors in the order submodules, CMake, vcpkg; then Bazel, Conan, vendored; (B) commit hashes go to OSV by default, with an opt-out flag; (C) vendored code is reported as unchecked by default, identification through OSV's `determineversion` (file hashes) only on opt-in; (D) the feed gets `GIT` ranges where the tag resolves, raw versions kept beside them; (E) applications among the 1,858 repos stay as feed records and aren't a detector target. Not in scope: re-polls triggered by the cvelistV5 feed.

    **Step 0 done 2026-11-11 (F-136); two changes approved:** commits are checked against fixes with a commits-only clone of the upstream (`git clone --bare --filter=tree:0`, `merge-base --is-ancestor`) instead of GitHub's compare API, and Bazel moves up beside vcpkg (order: submodules, CMake, Bazel and vcpkg, Conan, vendored). **Step 1 built 2026-11-11 (awaiting review, F-137):** `limbowatch.inventory.upstream` detects the upstream sources, `limbowatch.watch.registries` maps Bazel modules (BCR `source.json`), vcpkg ports (baseline, portfile, ports' dependencies, overlay ports) and Conan packages (the ConanCenter remote's recipe) to repo and tag; the scan lists each as not yet checked. Fixed on the way: a `conan.lock` failed the whole offline inventory (no empty ConanCenter database).

    **Steps 2-5 built 2026-11-11 (F-138), with the user's go-ahead to finish the phase:** the watcher matches upstream sources to their repo's advisories without a package, deciding by the commit graph (commits-only clone), by version, and by OSV's commit lookup (`--no-osv-commits`); the feed keeps those advisories' versions and adds OSV GIT ranges from the tags the tracker looks up (`git_tags` table); the tracker seeds the 3,603 C/C++ upstreams of vcpkg, BCR and ConanCenter (`tracker/seeds/cpp-upstreams.txt`); the audit rebuilds a sample of GIT ranges from live tags. The browser checker is unchanged: it works from registry packages, and upstream sources need the project's files.

19. **Decided 2026-11-11: Phase 6 closed; Phase 7 approved: GitHub becomes a full host** (F-145, F-146). Today the action scans one repo per run (annotations, job summary, SARIF), but `--issues` takes only `gitlab` or `gitea` and `limbowatch watch` lists only GitLab groups, Gitea orgs and git URLs. Order, with a review stop after each step:
    0. **Probe** (Q29, in a private test repo): whether issue creation creates a missing label; whether labels set with `GITHUB_TOKEN` (`issues: write`) stick; how listing by label treats pull requests; how a private repo clones with a PAT and with `GITHUB_TOKEN` as the Basic-auth password; what an empty repo looks like when listed (`size`) and cloned. Results go into FINDINGS.
    1. **GitHub tracker** (`watch/trackers.py`, `GitHub` beside `GitLab` and `Gitea`):
        - finds its issues by the `limbowatch` label and the body marker, skipping pull requests;
        - creates its labels before using them, and stops if a new issue comes back without the `limbowatch` label (a dropped label would mean a duplicate issue every run);
        - closes with `state_reason: completed` and reopens with `reopened`;
        - reports 410 as "issues are disabled in this repo";
        - `public` is true only for `visibility == "public"`.
    2. **GitHub-aware writes** (`http.py`): `HttpClient.request` handles GitHub's 403/429 secondary limits as the advisory path does (`retry-after`, then `x-ratelimit-reset`, else a minute and backoff), and spaces content-creating requests to GitHub at least one second apart. When a limit outlasts the wait, the run stops writing and lists what it didn't do. Opening, closing, reopening and labelling follow from the state, so the next run does them. A "changed" comment comes from a one-time event, so comments go first and new issues last, and a comment that was still missed is printed in the run's output.
    3. **CLI and action:**
        - `scan --issues github`, defaulting to `GITHUB_API_URL` (or `https://api.github.com`) and `GITHUB_REPOSITORY`;
        - the token is `LIMBOWATCH_ISSUES_TOKEN`; the action passes the job's `GITHUB_TOKEN` when `issues: github` is set and no `issues-token` is given, so it needs only `permissions: issues: write`;
        - as now, issues are written only from the default branch or a schedule, never from pull requests.
    4. **Org-wide mode** (`hosts/github.py`):
        - `limbowatch watch --github-org NAME` (repeatable, also a user name) and `--github-url` for Enterprise Server;
        - lists `GET /orgs/{org}/repos?type=all`; for a user, `GET /user/repos?affiliation=owner` when the token is that user's, otherwise their public repos with a note saying so;
        - reports archived, disabled and empty repos as not checked; forks are checked, as on Gitea, and `--exclude` skips them;
        - private repos clone with the source token, scoped to the GitHub host and its API host (github.com and api.github.com count as one host).
    5. **Tests and e2e:**
        - recorded fixtures for every new path (pagination, pull requests in the list, 410, a dropped label, secondary limits, an org versus a user, empty and archived repos), with coverage kept at or above 90%;
        - `scripts/e2e_github.py`: the issue lifecycle (open, comment, visible label, close, reopen) and `watch --github-org` in a private test repo;
        - the action's self-test runs `issues: github` with `--issues-dry-run`.
    6. **Wrap-up:** docs (WATCHER.md, the action README), CHANGELOG, FINDINGS cleanup, audit, release 0.1.0a10 with the checklist.

    Not in this phase: GitHub App packaging, GitHub code scanning beyond today's SARIF upload, Bitbucket. Enterprise Server is supported by URL but untested (Q30).

    Decisions (approved 2026-11-11, A, B and C as recommended):
    - (A) **Public repos:** GitHub has no confidential issues, so no new issues are opened in a public repo unless `--issues-public` is given, as on Gitea (recommended). Public repos keep the SARIF upload to code scanning.
    - (B) **Test repo:** create a private repo `limbowatch/limbowatch-e2e` on GitHub for step 0 and the e2e script, using the maintainer's `gh` login (recommended). It holds no real code: a lockfile with known findings, and the issues the tests open and close.
    - (C) **New issues per run:** cap new issues at 50 per project per run, on every tracker, reporting the rest as "opened on a later run". This keeps a first run from filing hundreds of issues at once, and stays under GitHub's 500-an-hour limit (recommended). `--issues-max-new` changes it.

    **Step 0 done 2026-11-12 (F-147, Q29 answered):** labels work with a PAT and with `GITHUB_TOKEN`, and a missing label is created. Changes to steps 1-5:
    - the tracker reads `has_issues` up front (a disabled tracker still lists with 200);
    - the issue list lags 3-7 seconds, so the integrations' docs set a `concurrency` group and the e2e waits between runs;
    - `watch --github-org` with the job's `GITHUB_TOKEN` warns that only public repos and its own are visible;
    - an empty clone (no HEAD) is reported as an empty repository on every host, because GitHub's `size` can't tell one.

    **Steps 1-6 built 2026-11-12 (F-148), with the user's go-ahead to finish the phase and report:** the GitHub tracker, GitHub-aware writes, `scan --issues github` and the action's `issues: github`, `watch --github-org`, tests (coverage 93%), `scripts/e2e_github.py` and the action run live in the private test repo. Changed on the way:
    - an independent review found 12 bugs, all fixed (F-148);
    - labels aren't created up front, because GitHub creates a missing label with the issue (F-147);
    - a dropped label closes the issue it opened and stops;
    - the action writes issues only on a push to the default branch, a schedule or a manual run;
    - a POST isn't retried once the server may have taken it;
    - Enterprise Server and GHE.com use the job's `GITHUB_API_URL` and stay untested (Q30).

    **After release (2026-11-12):** a recheck found that GitHub drops a new issue's labels for a token whose user can't push, so such a repo now gets no new issues and the run says why (F-150, 0.1.0a11). Dependencies were then upgraded to their latest releases, among them OSV-Scanner 2.7.1 and a Python 3.14 image; comparing the two OSV-Scanner versions on 111 projects found linked local npm packages checked as registry ones, fixed (F-153, 0.1.0a12). GitHub Marketplace lists only v0.1.0a10 to a12, because it picks "latest" by comparing tags as text (F-151, F-155).

20. **Decided 2026-11-12: Phase 7 closed** after the maintainer's review. Released as 0.1.0a10, 0.1.0a11 and 0.1.0a12 (F-145 to F-155). Open: Enterprise Server and GHE.com (Q30), and labels with fine-grained and GitHub App tokens (Q31). The next phase isn't chosen.

21. **Decided 2026-11-12: Phase 8, website redesign, approved with A, B and C as recommended.** The maintainer asked for the whole site, built around this point: teams upgrade dependencies when an alert makes them, so a scanner that stays silent while a fixed advisory waits for review delays the fix, and the compliance clock with it.

    **What we know** (F-055, F-064, F-112, F-134, F-156, F-157):
    - Advisories wait weeks to months for review: a median of 23 days in October, 55 days so far for the 10,059 waiting on 2026-11-12, and 15,045 more likely never.
    - Remediation clocks mostly start at detection: SOC 2 leaves the deadline to the company's policy, usually counted from the scanner's alert; CISA's BOD 26-04 counts from identification or a KEV listing. A team can meet every deadline and still run a public, fixed vulnerability for weeks. PCI DSS counts one month from the fix's release, so limbo uses up the deadline itself.
    - Dependabot raised 0 alerts for 1,080 confirmed findings in limbo (F-112).
    - Real examples exist: jackson-core, netty-handler, @sinclair/typebox, mistune, vm2, nats-server, go-openapi/spec, go-toml, mustache, rubyntlm and scapy have high or critical advisories, fixed for 41 to 212 days, that no scanner database has (F-157).

    **The story every page follows:**
    1. Day 0: the maintainer publishes the advisory and the fix. It's public: anyone, attackers included, can read what's broken.
    2. Your scanner is silent for weeks. No alert, so no ticket, no deadline and no upgrade.
    3. Limbowatch alerts on the next build, so the clock starts when the risk does.

    **Order, with a review stop after steps 1 and 3:**
    0. **Proof for the examples** (decision B): a private repository pinning the F-157 versions, with one control package per ecosystem that has a reviewed advisory, to show Dependabot alerting on the controls and not on the examples. Results go into FINDINGS.
    1. **Content and wireframes:** a site map, the copy of each page, and wireframes for home, compliance and scan, at desktop and phone width, as images to review. No code.
    2. **Design system:** type scale, colour tokens (dark and light), spacing, components (stat, timeline, example card, code block, table), from the current brand: hourglass mark, amber accent.
    3. **Pages:**
       - **Home:** the story above, the live count, live examples, the compliance clock (today's slider, corrected with BOD 26-04 and F-134), how it works in three steps, and two actions (add to CI, check a package).
       - **Examples, generated:** `limbowatch publish` picks them from the tracker state each run with the F-157 rules (pending review, high or critical, fixed, at least 60 days, filed by the package's own repository), ranked by usage, and skip a version for which a reviewed advisory already asks for an upgrade to the limbo fix or past it, because Dependabot would lead there anyway (F-158), and do the same with OSV's package query (F-159). That needs dependent counts per package, from ecosyste.ms, which the tracker already reads. Nothing is hard-coded, so examples leave the page when GitHub reviews them. Advisory text isn't shown (F-047); each example links to the advisory.
       - **Security and compliance (new):** the clock under SOC 2, PCI DSS and BOD 26-04, quoted from the sources, with "not audit advice".
       - **Scan:** the terminal, pull-request and merge-request views regenerated from the current release (today's show 0.1.0a5 and OSV-Scanner 2.7.0), and tabs for GitHub, GitLab, Gitea and the CLI.
       - **Tracker and Check a package:** restyled; a "fixed upstream" filter on the tracker.
       - **About 25,000 advisory pages:** a new template that leads with the fix: "fixed in X, released N days ago, not yet in scanner databases".
       - **Why, Methodology, Press, Feed, Data quality:** restyled, the navigation cut from 8 items to 5 (Scan, Tracker, Check, Learn, GitHub).
    4. **Also fixed:** the `pom.xml` line number (F-157), so annotations land on the dependency; ranges made of several upper bounds, read one per release line in the watcher and converted per line in the feed (F-159: 506 entries, 36 critical), then a release.
    5. **Checks:** tests for every generated number and example; a link check; screenshots at desktop and phone width, dark and light; accessibility (contrast, keyboard, screen-reader labels); page weight no heavier than today. The audit (`scripts/audit.py`) gains a check that every example shown is still in limbo.
    6. **Wrap-up:** docs, CHANGELOG, FINDINGS cleanup, deploy (the site deploys from main; no package release unless the watcher changes, which step 4 does).

    **Deviation (2026-11-12):** the examples come from a short curated list (`publish/examples.json`), each checked against GitHub's reviewed database, OSV, ruby-advisory-db and Dependabot (F-157 to F-162), not picked automatically: the tracker's state doesn't hold reviewed advisories' ranges, so the check for a reviewed advisory that already leads past the fix (F-158) can't run at publish time. Everything shown stays live: an example leaves the page when the tracker sees its advisory reviewed or in OSV, the day counts are computed at each build, and the proof repository re-runs every tool daily. Generating them needs the tracker to record reviewed ranges, a later step. The scan page's outputs are screenshots refreshed on each release that changes them (docs/SCREENSHOTS.md), not generated at build time: the pull request and merge request views need a signed-in browser. The audit checks the examples live before each release (check 10).

    Not in this phase: a new domain or name, new analytics, outreach.

    **Decisions needed:**
    - (A) **Name real packages on the home page?** Recommended: yes, generated and re-checked every run, framed as "the maintainers fixed it; the review queue is the delay", never as blame.
    - (B) **The Dependabot proof:** create the private repository `limbowatch/limbo-examples` (dependency files only) and push to it. Recommended: yes; the permission check needs the maintainer's explicit go-ahead.
    - (C) **Design direction:** evolve the current dark, amber look (recommended: the brand and screenshots are recent), or start a new visual identity.

22. **Decided 2026-11-13: Phase 8 closed** after the maintainer's review, with a release of the watcher changes made along the way (F-164's Markdown escaping and the hash-pinned `install: python`). Left to the maintainer: Cloudflare's "Always Use HTTPS" and a `www` redirect (F-168), and the repository settings from the security review (immutable releases and tag rules, `main` protection, a required reviewer for PyPI, secret scanning). The next phase isn't chosen.
