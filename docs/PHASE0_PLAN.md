# Phase 0 Plan

| Rev | Date | Status | Change |
|---|---|---|---|
| 1 | 2026-10-19 | superseded | Initial plan |
| 2 | 2026-10-20 | superseded | Fact-vector model and new classes; cvelistV5 feed and all-CNA CVE ingestion; ecosystem plugin tiers (goal: all languages); run-anywhere and org-wide mode; open-source licensing; Phases 6–7 |
| 3 | 2026-10-20 | **proposed, awaiting approval** | Build-vs-reuse (§1a): OSV-Scanner is the inventory backend and OSV the source of reviewed matching; our own range evaluation only for repo-advisory ranges; Phase 1/3/6 scope reduced accordingly |

Inputs: [SPEC.md](SPEC.md) (requirements) and [FINDINGS.md](FINDINGS.md) (verified facts, cited as F-NNN).

## 1. Goal and scope

**End goal:** detect ghost vulnerabilities for **any repo** (GitLab, Gitea/Forgejo, GitHub, plain git) in **any language**.

**MVP (Phases 1–5):** npm, PyPI and Go; GitLab first. Every interface is built for the end goal from the start, so adding an ecosystem or host means adding a plugin, not reworking the core.

**Product principle:** never silently skip. If a dependency can't be fully checked, the specific check that couldn't run is reported with a reason.

## 1a. Build vs reuse (verified 2026-10-20)

GhostCVE builds **only what no existing tool does**. Everything else is consumed (F-032 to F-035).

| Capability | Who already does it | Decision |
|---|---|---|
| Lockfile/manifest inventory, about 25 formats incl. pnpm, uv, Gradle, Maven `pom.xml` with transitive resolution | OSV-Scanner / OSV-Scalibr (Apache-2.0) | **Reuse:** `osv-scanner scan source --format json --all-packages` as the default backend; CycloneDX/SPDX input as the alternative |
| Matching *reviewed* advisories to versions | OSV API (querybatch) | **Reuse:** OSV results are the `osv` fact; no re-implementation |
| Aggregating reviewed GHSA plus ecosystem DBs | OSV | **Reuse;** GitHub global API only for states OSV lacks (unreviewed / absent) |
| Package→repo mapping | deps.dev (7 systems, provenance), ecosyste.ms | **Reuse** as mapper-chain tiers; build only the URL normalizer, overrides and recipe-repo blocklist |
| Version comparators | univers | **Reuse;** custom only for pub and swift |
| Measuring the gap for a list of repos | Safeguard `advisory_gap.py` (repo list → OSV check) | Prior art for research; credit its data |
| **Joining a real inventory to unreviewed repo advisories with version matching** | nobody (F-034) | **Build:** the core |
| **Tolerant evaluation of maintainer-entered ranges, duplicate-GHSA detection, repo vs reviewed drift** | nobody | **Build** |
| **Reserved / pre-review CVE detection; cvelistV5 feed matching by repo** | nobody | **Build** |
| **Fact vector, scanner-family visibility, ghost age, permanence** | nobody | **Build** |
| **GitLab/Gitea workflow: CI component, issues with lifecycle comments, org-wide watch** | nobody for ghosts | **Build** |

**Accepted risks of reuse:**
- An external Go binary: bundled in the OCI image; for `pip`/`uvx` installs it must be on PATH, otherwise users fall back to SBOM input.
- Its handling of unresolvable dependencies must be checked in Phase 1. If it silently drops them, GhostCVE adds its own `UNRESOLVED` detection for those manifests.

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
cve           : none | published(cna)                     (+ datePublished, CNA score)
ghsa_global   : absent | unreviewed | reviewed | withdrawn (+ has_package_data, ranges)
osv           : none | cve_only(GIT ranges) | ecosystem_record(source id)
nvd           : absent | {vulnStatus, nist_primary_cvss?, cpe_configurations?}
```

### Classifications (flags derived from facts; a finding can carry several)

| Class | Condition (for an affected dependency version) | Priority |
|---|---|---|
| `GHOST_ADVISORY` | repo advisory published, no public CVE, GHSA not reviewed | 1 |
| `GHOST_CVE` | CVE published (repo advisory or GitHub CNA), GHSA not reviewed | 2 |
| `ORPHAN_CVE` | CVE from another CNA, no repo advisory, GHSA not reviewed | 3 |
| `NO_CVE` | GHSA reviewed, no CVE | 4 |
| `OSV_MISSING` | GHSA reviewed, no OSV ecosystem record (usually brief) | 5 |
| `RANGE_DRIFT` | repo advisory / GHSA / OSV disagree on whether this version is affected | 5 |
| `NVD_UNENRICHED` | CVE exists, no NIST `Primary` CVSS and/or no CPE configurations | info |
| `UNRESOLVED(check, reason)` | a specific check couldn't run (no resolved version, no repo mapping, upstream not on GitHub, no comparator…) | always shown |

`primary_class` is the highest-priority flag and is used for sorting and gating. Flags implied by a higher one are hidden: a GHOST_* finding implies OSV_MISSING, so that flag isn't shown separately.

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
- **Ghost age** runs from the earliest public evidence (min of repo `published_at` and CVE `datePublished`) until the vulnerability becomes visible to the configured scanners.
- **Permanence:** `likely_permanent` when the ecosystem isn't in GHSA's enum (F-023) or the class is `ORPHAN_CVE`; otherwise `pending`. Report text differs between the two ("probably never" vs. "not yet").

### Severity

Order: GHSA-reviewed → repo advisory → CNA score (CVE record) → NVD NIST `Primary`. The source is always recorded. If nothing is available, severity is `unknown`, gated by `--fail-on-unknown`.

## 4. Data sources

| Source | Used for | Access | License / terms |
|---|---|---|---|
| GitHub repo advisories `GET /repos/{o}/{r}/security-advisories` | GHOST_ADVISORY/GHOST_CVE (earliest signal) | token recommended; ETag (304 free only when authenticated, F-003) | GHSA: CC-BY 4.0, attribution in reports |
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

A missing capability produces `UNRESOLVED(check, reason)` for that check only. Plugins register through Python entry points, so third parties can add ecosystems. `ghostcve ecosystems` prints the live coverage matrix, and the README embeds it.

| Tier | Ecosystems | Inventory | Mapping chain | Versions |
|---|---|---|---|---|
| **1 Full** | npm, PyPI, Go (MVP) → **Maven/Gradle next**, then Cargo, RubyGems, Composer, NuGet | OSV-Scanner `--all-packages` (§1a) or SBOM | registry-native → deps.dev → overrides | univers (F-022) |
| **2 Extended** | Hex/Erlang, Pub, Swift, CocoaPods, Conan, R, Haskell, … | OSV-Scanner where supported (mix.lock, pubspec.lock, conan.lock, renv.lock, cabal/stack) or CycloneDX/SPDX | ecosyste.ms → overrides | univers; small custom comparators for pub and swift |
| **3 Upstream-watch** | C/C++, git submodules, vendored code, CMake FetchContent, vcpkg, Bazel, CPAN, CRAN, Hackage | `.gitmodules`, `vcpkg.json`, `conan.lock`, `MODULE.bazel`, … | the repo URL itself | commit vs. OSV GIT ranges where known, else "version unknown" |

**Mapping confidence by provenance:** SLSA / PyPI / RubyGems publish attestation and Go Origin, then registry metadata, then deps.dev `UNVERIFIED_METADATA`, then ecosyste.ms. Overrides win. A blocklist of packaging/recipe repos (e.g. `conan-center-index`, F-021, Q7) keeps those from being treated as upstream.

**Maven/Gradle (first post-MVP ecosystem):**
- Maven has no lockfile. `pom.xml` gives only declared versions, and real versions depend on property interpolation, parent POMs, BOM imports and mediation, so parsing `pom.xml` alone yields `UNRESOLVED(no_resolved_version)`.
- Resolved inventory: OSV-Scanner resolves `pom.xml` transitively via deps.dev's resolver and reads `gradle.lockfile` (F-032). Alternatives are CycloneDX SBOMs from `cyclonedx-maven-plugin` / `cyclonedx-gradle-plugin`. Phase 6 checks OSV-Scanner's resolution against the build tool's output on a real project.
- Mapping uses the POM `<scm>`, following parent POMs, because deps.dev missed `commons-text` (F-020).

## 7. Any repo: running anywhere

- **Distribution:** PyPI (`uvx ghostcve`) plus an OCI image (with syft bundled from Phase 6).
- **Per-repo CI:** GitLab CI/CD Catalog component (Phase 4), plus a Gitea/Forgejo/GitHub Action, all from one Actions-compatible definition. Jenkins, Woodpecker and cron run the container.
- **Org-wide central mode (Phase 5):**
  - `watch` reads a list of sources: GitLab groups, Gitea orgs, git URLs.
  - Manifests are fetched through host APIs, or a shallow clone for plain git.
  - **Each upstream repo is polled once for all projects**, so cost grows with unique upstreams, not with the number of repos.
  - The cvelistV5 feed triggers immediate re-polls of matching upstreams.
- **Trackers:** an `IssueTracker` protocol with GitLab first (Phase 4), then Gitea/Forgejo (Phase 5), GitHub and a generic webhook. Issues are deduplicated by finding key and receive event comments ("CVE assigned", "has now reached scanners").
- **Output formats:** table, json, markdown, sarif (GitLab Ultimate ≥ 19.2), codequality (all GitLab tiers, MR widget).

## 8. Repo layout and module boundaries

```
GhostCVE/
├─ pyproject.toml                 # uv workspace root; ruff, mypy --strict, pytest, import-linter
├─ packages/
│  ├─ core/src/ghostcve/
│  │  ├─ models/                  # pydantic v2: Dependency, PackageRef(purl), UpstreamRepo, SourceRecord,
│  │  │                           #   Vulnerability, Facts, Finding, Visibility, Evidence, Severity
│  │  ├─ ecosystems/              # EcosystemPlugin protocol, registry, capability model
│  │  │  ├─ npm/ pypi/ golang/    # comparator + mappers + ID mappings per ecosystem (Tier 1); no lockfile parsers
│  │  ├─ inventory/               # backends: osv_scanner (subprocess, pinned), cyclonedx, spdx; UNRESOLVED detection
│  │  ├─ mapping/                 # chain runner, url_normalize, deps_dev, ecosystems_ms (Phase 6), overrides, blocklist
│  │  ├─ http/                    # async client: limits, backoff, Retry-After/X-RateLimit, ETag cache, redaction
│  │  ├─ sources/                 # github_repo, github_global, osv, nvd, cve_record, cve_feed → SourceRecord
│  │  ├─ versions/                # comparator adapters; github_range + osv_events evaluators
│  │  ├─ diff/                    # PURE: alias graph, facts, match, classify, visibility, severity, permanence
│  │  ├─ report/                  # table, json, markdown, sarif, codequality (+ attribution)
│  │  ├─ trackers/                # IssueTracker protocol; gitlab (Phase 4), gitea (Phase 5)
│  │  ├─ hosts/                   # project sources for org-wide mode: gitlab, gitea, git (Phase 5)
│  │  ├─ store/                   # SQLAlchemy 2.0 models, repositories, alembic/
│  │  ├─ watch/
│  │  ├─ config.py                # ghostcve.yml schema; secrets from env
│  │  └─ pipeline.py              # scan(): public API surface a future FastAPI wraps
│  └─ cli/src/ghostcve_cli/       # typer: scan, watch, ecosystems; formats; exit codes; --verbose evidence
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
| `findings` | `finding_key` (unique: sha256(project, purl_base, vulnerability_id)), `version`, `flags`, `primary_class`, `visibility`, `permanence`, `ghost_since`, `severity`, `severity_source`, `match_confidence`, `status`, `first_seen`, `last_seen`, `evidence` |
| `finding_events` | `finding_id`, `scan_id`, `event`, `diff`, `at` |
| `feed_cursors` | `feed`, `cursor`, `updated_at` (cvelistV5 position) |
| `tracker_issues` | `finding_id`, `tracker`, `base_url`, `project_ref`, `issue_ref`, `last_synced_at` |

The finding key uses the internal vulnerability UUID (not an alias string) and leaves out the version. When a GHSA appears later for a CVE-keyed finding, or the user upgrades between affected versions, the existing issue is updated instead of a new one being opened.

## 10. Phases and order of work

Each phase ends with a review stop and a cleanup of the findings report.

| Phase | Scope |
|---|---|
| **1 Inventory + mapping** | Scaffold (uv workspace, ruff, mypy --strict, pytest, import-linter, GitHub Actions CI for this repo). Models. `EcosystemPlugin` + capability → `UNRESOLVED`. **Inventory backends: OSV-Scanner `--all-packages` adapter (pinned version) + CycloneDX + SPDX. No custom lockfile parsers.** Verify and test OSV-Scanner's behavior on unresolved/range-only deps, direct/dev flags, monorepos; add our own `UNRESOLVED` detection only where it falls short. URL normalizer, mapper chain (registry-native, Go proxy Origin → go-get, deps.dev), overrides, recipe-repo blocklist. Minimal `http/`. |
| **2 Collectors** | GitHub repo + global, OSV, NVD, CVE record, **cvelistV5 delta feed**. ETag cache, rate limits, retries. Recorded fixtures, including real GHOST_ADVISORY/GHOST_CVE/ORPHAN_CVE cases. `scripts/measure_gap.py` (repeat measurements for Q1/Q2). Verify data-source licenses. |
| **3 Diff engine** | Alias graph; **tolerant evaluator for repo-advisory ranges** (canonical GHSA, npm-semver, hyphen, common typos → else `UNRESOLVED(range_unparseable)`, F-030); reviewed matching taken from OSV; **duplicate-GHSA detection** (F-028); repo-vs-reviewed drift; matching rules, fact vector, classes, visibility, severity, permanence. Most thorough tests: table-driven scenarios, per-ecosystem edge cases (prereleases, Go pseudo-versions/`+incompatible`, PEP 440 epochs/local versions, npm build metadata), and hypothesis property tests on comparators. |
| **4 Reporting + CI + GitLab** | table/json/markdown/sarif/codequality, exit codes (`--fail-on`, `--fail-on-unknown`), GitLab CI/CD component + Actions definition, GitLab issue tracker. |
| **5 Watch + org-wide** | Fact-snapshot change detection, events, `scan --state` for CI. Multi-project sources (GitLab group, Gitea org, git URLs), shared upstream polling, feed-triggered re-polls, Gitea/Forgejo tracker. |
| **6 Ecosystem expansion** | Inventory already comes from OSV-Scanner, so this phase covers mapping and comparators: **Maven/Gradle first** (POM `<scm>` with parents), then Cargo, RubyGems, Composer, NuGet. Tier 2 via ecosyste.ms + pub/swift comparators. OCI image bundling osv-scanner. |
| **7 Upstream-watch** | Tier 3 detectors (submodules, vcpkg, conan, FetchContent, Bazel, vendored dirs); commit evaluation against OSV GIT ranges. |

## 11. Licensing (open source)

- **GhostCVE code:** **Apache-2.0 (decided 2026-10-21; see [LICENSE](../LICENSE)).** It includes a patent grant, is common for security tooling, and matches univers and OSV-Scanner. Other dependencies to check: python-gitlab is LGPL-3.0, which is fine as a dependency.
- **Data obligations:**
  - GHSA (CC-BY 4.0): attribution in every report.
  - deps.dev: Google API ToS (caching permitted).
  - OSV, NVD and CVE terms: verify in Phase 2.
- **ecosyste.ms (CC BY-SA 4.0, Q6):** use it only at runtime with a local cache, credit it in output when a mapping came from it, and **never bundle or redistribute** datasets derived from it (for example, a shipped default mapping file). Shipped override files are written by hand or built from non-SA sources. This isn't legal advice; revisit it before 1.0.

## 12. Deviations from SPEC

1. Classifications are flags with a primary, derived from a fact vector. `REPO_ONLY` is split into `GHOST_ADVISORY`/`GHOST_CVE`; `ORPHAN_CVE` is new.
2. `UNRESOLVED` applies per check, not per dependency.
3. `go.sum` is not an inventory source (only a cross-check); `go.mod` is the source.
4. `NVD_UNENRICHED` is based on NIST `Primary` metrics and/or CPE configurations, and is informational by default.
5. `RANGE_DRIFT` compares repo advisory, GHSA and OSV; NVD CPE ranges are shown as context only.
6. `OSV_MISSING` checks aliases.
7. Registry metadata is fetched per version.
8. Severity order puts GHSA-reviewed ahead of the repo advisory; `unknown` severity is gated explicitly.
9. CVE records come from CVE Services plus the cvelistV5 delta, not a full clone.
10. New sources: cvelistV5 feed, deps.dev, ecosyste.ms.
11. Scope extends to all languages and hosts (Phases 6–7, Gitea, org-wide mode), with a `codequality` output.
12. Added: SPDX input, Alembic, withdrawn handling, `scan --state` for CI.
13. Native lockfile parsers (`package-lock.json`, `requirements.txt`/`poetry.lock`/`uv.lock`, `go.mod`) are replaced by OSV-Scanner as the inventory backend (§1a). The SPEC's intent (resolved versions, never silently skip) is kept and verified in Phase 1.

## 13. Decisions needed for approval

Recommended defaults are in bold.

1. ~~Code license~~ **Decided: Apache-2.0** (2026-10-21).
2. Add `codequality` output in Phase 4: **yes**.
3. Malware advisories: **defer** past MVP.
4. Unscored GHOST_* findings fail CI by default (`--fail-on-unknown=true`): **yes**.
5. Default `scanners:` profile when unset: **`gitlab_ds`**.
6. Approve this plan, including Phases 6–7 and the §12 deviations, so Phase 1 can start.
