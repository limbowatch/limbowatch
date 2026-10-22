# Phase 0 Plan

| Rev | Date | Status | Change |
|---|---|---|---|
| 1 | 2026-10-19 | superseded | Initial plan |
| 2 | 2026-10-20 | superseded | Fact-vector model and new classes; cvelistV5 feed and all-CNA CVE ingestion; ecosystem plugin tiers (goal: all languages); run-anywhere and org-wide mode; open-source licensing; Phases 6–7 |
| 3 | 2026-10-20 | superseded | Build-vs-reuse (§1a): OSV-Scanner is the inventory backend and OSV the source of reviewed matching; our own range evaluation only for repo-advisory ranges; Phase 1/3/6 scope reduced accordingly |
| 4 | 2026-10-21 | superseded | Renamed **Limbowatch** ("Ghost CVE" already means *reserved but public*, F-037); classes `GHOST_*` → `LIMBO_*`; `RBP` state added; **phase order changed for awareness: public report → live tracker → scanner** (§10); scanner phases renumbered 3–8 |
| 5 | 2026-10-21 | **approved 2026-10-21**; Phase 1 draft complete, awaiting review | No duplicate scanner: the npm/PyPI/Go scan-time CI check is blindspot's (F-036), so we **contribute** to it instead. The tracker also publishes an open **limbo feed** (OSV schema) others can consume. Tracker coverage defined (§7a). Phases: report → tracker + feed → upstream contributions → watcher → ecosystems → upstream-watch |

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
| **4 Limbowatch watcher** | Stateful layer no tool provides. Inventory via OSV-Scanner `--all-packages` + CycloneDX/SPDX (`EcosystemPlugin` capability → `UNRESOLVED`; verify OSV-Scanner's unresolved handling). Matching against the feed, plus on-demand polling for long-tail upstreams. Fact-snapshot change detection, `scan --state` for CI. GitLab CI/CD component; GitLab and Gitea/Forgejo issues with lifecycle comments ("CVE assigned", "has now reached scanners"). Org-wide sources (GitLab group, Gitea org, git URLs) with shared polling. Outputs: table/json/markdown/sarif/codequality, `--fail-on`, `--fail-on-unknown`. |
| **5 Ecosystem expansion** | Mapping and comparators (inventory already comes from OSV-Scanner): **Maven/Gradle first** (POM `<scm>` with parents), then Cargo, RubyGems, Composer, NuGet. Tier 2 via ecosyste.ms + pub/swift comparators. Tracker watchlist extended to the same ecosystems. OCI image bundling osv-scanner. |
| **6 Upstream-watch** | Tier 3 detectors (submodules, vcpkg, conan, FetchContent, Bazel, vendored dirs); commit evaluation against OSV GIT ranges. |

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
