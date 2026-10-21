# GhostCVE Findings Report

What we've verified or measured while building GhostCVE. Maintenance rules are in [CLAUDE.md](../CLAUDE.md#findings-report-docsfindingsmd).

Last summarized: 2026-10-20 (Phase 0, after popular-repo experiment)

## Summary

Current understanding, with entries linked:

1. **The ghost window is real and large.** In a sample of 40 advisories GitHub reviewed on Oct 15–16, 2026, the time from repo publication to GitHub review was at least 3 days, **median 55 days**, and up to 114 days ([F-010](#f-010)). GitHub's docs say review takes up to 72 hours ([F-019](#f-019)).
2. **Before review, the advisory is absent from the global DB.** It doesn't appear even as `unreviewed` ([F-012](#f-012)). OSV has at most a `CVE-*` record with GIT ranges and no package ([F-012](#f-012)), so lockfile-based scanners can't match it.
3. **The CVE record is also delayed.** It is published before review in 38 of 38 cases, but a median of about 47 days after the repo advisory ([F-011](#f-011)). The repo advisory API is often the *only* early signal.
4. **The lifecycle is not linear.** Events happen in any order: published with no CVE then reviewed (11.7% of reviewed advisories have no CVE, [F-016](#f-016)); CVE before repo advisory ([F-011](#f-011)); other-CNA CVEs that almost never get reviewed ([F-017](#f-017)). Model each vulnerability as a vector of independent facts, not a pipeline stage.
5. **Other-CNA CVEs are near-permanent ghosts for GitHub-native tools.** Only 4 of 1,000 advisories reviewed in a month carried another CNA's CVE. Unreviewed advisories carry **no package info** (0 of 500, [F-017](#f-017)).
6. **The cvelistV5 delta log is a usable global feed** for GitHub-CNA CVEs. 254 GitHub_M CVEs in 5 days; all link the GHSA; `vendor`/`product` equal repo `owner`/`repo` in 251 of 254 ([F-013](#f-013)).
7. **Package names in repo advisories can't be trusted.** One named a PyPI project that doesn't exist ([F-014](#f-014)). Match through our own package→repo mapping.
8. **NVD now defers new non-priority CVEs immediately** ([F-005](#f-005), [F-018](#f-018)). In NVD, CNA scores appear as `Secondary` metrics; NIST's own are `Primary`.
9. **GitLab's native SARIF ingestion is Ultimate-only (GA 19.2)** and classifies findings without a CVE as SAST ([F-008](#f-008)). That affects how GHOST/NO_CVE findings show up in GitLab.
10. **Multi-language support is feasible in layers.** Repo-keyed matching is language-agnostic. Package→repo mapping chains registry-native → deps.dev (7 systems, with provenance, [F-020](#f-020)) → ecosyste.ms (~100 registries, unverified, CC BY-SA, [F-021](#f-021)). univers covers every GHSA ecosystem except pub and swift ([F-022](#f-022)). Languages outside GHSA's enum are never reviewed, so repo matching is the only signal there ([F-023](#f-023)).
11. **On real projects, ghosts are common.** Across the 3,246 upstreams of 5 popular projects, 18% of published advisories (350 of 1,928) are absent from the global DB. All 5 projects ship versions affected by ghost advisories: gitea 2, kubernetes 3, n8n 89, open-webui 95, langchain 122 findings ([F-026](#f-026), [F-027](#f-027)). The mapper chain reached 97.4% of packages ([F-025](#f-025)).
12. **Raw ghost counts overstate the problem somewhat.** About 14% of ghost candidates look like duplicates reviewed under another GHSA ID ([F-028](#f-028)). 27% of maintainer-entered ranges aren't canonical GHSA syntax, and repo ranges often differ from reviewed ones ([F-030](#f-030)). Dedup and tolerant range parsing are core diff-engine work.
13. **Reserved CVEs are observable.** Repo advisories expose CVE IDs that `cveawg /api/cve-id/` shows as `RESERVED`, sometimes for 100+ days ([F-029](#f-029)). About 40% of reviewed CVEs on real dependencies are still unenriched in NVD ([F-031](#f-031)).
14. **Don't rebuild OSV.** OSV-Scanner (Apache-2.0) already extracts full inventories from about 25 lockfile types, Maven included (`--format json --all-packages`, [F-032](#f-032)), and matches reviewed vulnerabilities. GhostCVE's unique value is the delta: on n8n, 24 ghost-affected packages are reported clean by OSV-Scanner ([F-033](#f-033)).
15. **No existing open tool does the full job, and GitHub won't close the gap soon.** Safeguard measured the same gap (30.7%) and ships a repo-list-only script with no inventory, mapping, version matching or workflow. Other trackers watch only the global DB ([F-034](#f-034)). GitHub cites throughput limits at more than 5,000 repo advisories a week and has no plan to alert before review ([F-035](#f-035)).

## Open questions

- ~~Q1. While a CVE is reserved but not yet published, does the repo advisory API already expose `cve_id`?~~ **Answered 2026-10-20: yes. Detectable via `cveawg /api/cve-id/{id}` ([F-029](#f-029)).**
- Q8. How do we reliably detect that a ghost candidate was reviewed under a different GHSA ID, and what's the true duplicate rate? ([F-028](#f-028))
- Q2. Was the 55-day median a backlog being cleared on Oct 15–16, or the normal state? Needs repeated sampling over weeks.
- Q3. What share of other-CNA CVEs affecting npm/PyPI/Go packages get package-level coverage in OSV through ecosystem DBs (Go vulndb, PyPA, RustSec)? Requires the CVE→package matching from Phase 2.
- Q4. How far behind GHSA are the scanner DBs (Trivy DB, Grype DB, OSV-Scanner)? GitLab Advisory DB lag can't be measured because its terms forbid querying it.
- Q5. Is "Not Scheduled" ever an NVD API `vulnStatus` value, or always `Deferred`? ([F-005](#f-005))
- Q6. Does ecosyste.ms's CC BY-SA 4.0 data license constrain GhostCVE? *Partly answered 2026-10-20: GhostCVE will be open source, so a commercial license isn't needed. Remaining constraint: share-alike applies to redistributed derived data. Plan §11: runtime use plus local cache only, with attribution, and never bundle derived datasets. Revisit before 1.0.* ([F-021](#f-021))
- Q7. How do we reliably detect packaging/recipe repos (conan-center-index, homebrew-core, distro packaging) so they aren't treated as upstream? ([F-021](#f-021))

## Log

### F-001
- **Date:** 2026-10-19 · **Status:** confirmed
- **Question:** Can `GET /repos/{owner}/{repo}/security-advisories` be used anonymously on public repos?
- **Method:** Docs plus a live GET on `expressjs/express`, no token.
- **Result:** 200, with an `ETag` header; anonymous limit 60/hr. Docs: "Anyone can access any published security advisory on a public repository." Fields include `vulnerabilities[].package{ecosystem,name}`, `vulnerable_version_range`, `patched_versions`, `cve_id` (nullable), `cvss_severities`, `state` (incl. `withdrawn`), `published_at`.
- **Implication:** Works without auth, but a few hundred repos need a token because of the rate limit.
- **Sources:** [GitHub REST: repository advisories](https://docs.github.com/en/rest/security-advisories/repository-advisories)

### F-002
- **Date:** 2026-10-19 · **Status:** confirmed
- **Question:** What does `GET /advisories` return by default?
- **Result:** "By default… will only return reviewed advisories that are not malware." `type=unreviewed` and `type=malware` must be requested explicitly. Pagination is cursor-based through the `Link` header, max 100 per page. The `after` cursor is already URL-encoded, so follow the `Link` URL as-is rather than re-encoding it.
- **Global advisory fields (observed):** `ghsa_id`, `cve_id`, `type`, `published_at`, `github_reviewed_at`, `nvd_published_at`, `repository_advisory_url`, `source_code_location`, `vulnerabilities`, `withdrawn_at`, `epss`, `identifiers`, `references`, and others.
- **Sources:** [GitHub REST: global advisories](https://docs.github.com/en/rest/security-advisories/global-advisories)

### F-003
- **Date:** 2026-10-19 · **Status:** confirmed (docs)
- **Result:** A 304 conditional response doesn't count against the primary rate limit **only if the request was authenticated**.
- **Implication:** The ETag cache saves quota only with a token.

### F-004
- **Date:** 2026-10-19 · **Status:** confirmed (docs)
- **Result:** OSV `POST /v1/querybatch` returns only `id` and `modified` per vuln. Pagination is per query (`next_page_token`) once a query exceeds about 1,000 results or a batch about 3,000. Full records come from `GET /v1/vulns/{id}`.
- **Sources:** [OSV querybatch](https://google.github.io/osv.dev/post-v1-querybatch/)

### F-005
- **Date:** 2026-10-19 · **Status:** tentative (secondary sources)
- **Result:** From 2026-04-15, NVD prioritizes enrichment for CISA KEV, federal-use software and EO 14028 critical software. Others are "Lowest Priority – not scheduled", and older unenriched CVEs (about 29k) were moved there. One blog maps "Not Scheduled" to API `vulnStatus = Deferred`; unconfirmed. A live record (CVE-2024-3094) had both `Primary` (NIST) and `Secondary` (CNA) CVSS metrics.
- **Implication:** Store `vulnStatus` raw. "Enriched" means NIST `Primary` metrics and/or `configurations` present; a CNA `Secondary` score doesn't count.
- **Sources:** [SecurityWeek](https://www.securityweek.com/nist-prioritizes-nvd-enrichment-for-cves-in-cisa-kev-critical-software/amp/), [CSA note](https://labs.cloudsecurityalliance.org/research/csa-research-note-nist-nvd-enrichment-changes-enterprise-vul/), [lilting.ch](https://lilting.ch/en/articles/nist-nvd-risk-based-cve-enrichment), [NVD status page](https://nvd.nist.gov/vuln/vulnerability-status)

### F-006
- **Date:** 2026-10-19 · **Status:** confirmed (observed; no official doc found)
- **Result:** `GET https://cveawg.mitre.org/api/cve/{id}` returns the CVE 5.x record without auth. `cveMetadata.assignerShortName` gives the CNA (e.g. `GitHub_M`).

### F-007
- **Date:** 2026-10-19 · **Status:** confirmed (observed)
- **Result:** `proxy.golang.org/{module}/@v/{version}.info` includes `Origin {VCS, URL, Hash, Ref}`. For `golang.org/x/net@v0.30.0`, `URL` = `https://go.googlesource.com/net`. The `?go-get=1` `go-import` meta tag gives the same repo root.
- **Implication:** Origin is the primary source for Go vanity-path mapping, with go-get as the fallback. Some upstreams aren't on GitHub, so no repo-advisory check is possible for them; record the reason.
- **Sources:** [Go test script mod_list_issue61423](https://go.dev/src/cmd/go/testdata/script/mod_list_issue61423.txt)

### F-008
- **Date:** 2026-10-19 · **Status:** confirmed (docs)
- **Result:** GitLab `artifacts:reports:sarif` ingestion requires Ultimate. It arrived in 18.11 behind flag `sarif_ingestion`, was on by default in 19.1, and went GA in 19.2. A finding is classified as dependency scanning only if an identifier is a CVE; otherwise it becomes secret detection (for secret CWEs) or SAST. Limits: SARIF 2.1.0 only, 10 MB artifact, 5,000 results per run.
- **Implication:** GHOST_ADVISORY and NO_CVE findings (no CVE by definition) would appear as SAST. Non-Ultimate users need other output paths (Code Quality report, issues).
- **Sources:** [GitLab SARIF reports](https://docs.gitlab.com/user/application_security/detect/sarif/)

### F-009
- **Date:** 2026-10-19 · **Status:** confirmed (observed)
- **Method:** `GET /advisories?type=reviewed&per_page=100&sort=published`, latest 100.
- **Result:** `published_at == github_reviewed_at` for 100 of 100. The global `published_at` is the review time, **not** the maintainer's publication time.
- **Implication:** To measure ghost windows, use the repo advisory's `published_at` (via `repository_advisory_url`).

### F-010
- **Date:** 2026-10-19 · **Status:** tentative (one batch; possible backlog bias, see Q2)
- **Method:** The 40 most recently reviewed advisories with `repository_advisory_url`. Compared the repo advisory's `published_at` with the global `github_reviewed_at`.
- **Result:** Repo publication to review: min 73 h, p25 24 days, **median 55 days**, p75 80 days, max 114 days. All 40 were over 72 h. All were reviewed between 2026-10-15 20:15 and 2026-10-16 21:15 UTC, though published between 2026-06-24 and 2026-10-13, which suggests batch review. Manual check: `GHSA-pw5q-rjx4-7f7p` (getarcaneapp/arcane) was published in the repo on 2026-07-29 and reviewed on 2026-10-16. Ecosystems: go 21, pip 8, npm 6, rust 2, maven, erlang, pub.
- **Implication:** Core product premise holds, with a much larger window than GitHub's documented 72 hours.

### F-011
- **Date:** 2026-10-19 · **Status:** tentative (n=38)
- **Method:** Same sample as F-010; CVE `datePublished` from cveawg.
- **Result:** The CVE was published **before** review in 38 of 38 cases (median 39 h earlier, up to about 100 days earlier). Repo publication to CVE publication: median about 47 days (min −153 h: one CVE was published *before* the repo advisory). CNAs: GitHub_M 36, JFROG 1, EEF 1.
- **Implication:** Window A (repo only, no public CVE) is usually the longest. Window B (CVE public, not reviewed) is shorter but can be long.

### F-012
- **Date:** 2026-10-19 · **Status:** confirmed (observed, n=30)
- **Method:** 30 random GitHub_M CVEs from the cvelistV5 delta log (Oct 14–19). For each GHSA: `GET /advisories/{ghsa}` (authenticated), the repo advisory, OSV `/v1/vulns/{GHSA}` and `/v1/vulns/{CVE}`.
- **Result:** Global DB: **404 for 23 of 30** (also no `unreviewed` or `malware` entry when queried by `cve_id`), 7 reviewed. OSV by GHSA: 404 for the same 23. OSV by CVE: 200 for 29 of 30, but those records have only `GIT` ranges, no `package`, with the GHSA as an alias.
- **Example:** `CVE-2026-102607` / `GHSA-7j62-cjxp-3cj5`: published in the repo 2026-07-22; CVE published 2026-10-16; NVD `Deferred` with CNA `Secondary` CVSS only and no configurations; absent from the global DB as of 2026-10-19 (≥89 days as a ghost).
- **Implication:** This resolves the plan's open premise. A pending advisory is invisible to GHSA- and OSV-package-based scanners. OSV `CVE-*` records don't help lockfile matching.

### F-013
- **Date:** 2026-10-19 · **Status:** confirmed (observed)
- **Method:** `https://raw.githubusercontent.com/CVEProject/cvelistV5/main/cves/deltaLog.json` (2,267 entries; latest 400 cover 2026-10-14 → 2026-10-19). Fetched the records of the "new" CVEs.
- **Result:** 2,534 new CVEs in 5 days; 254 assigned by `GitHub_M`, all of which reference the GHSA. `affected[].vendor`/`product` equals the repo `owner`/`repo` in 251 of 254. GitHub_M records never populate `packageName`, `collectionURL` or `repo`.
- **Implication:** A global, low-cost feed for window B (independent of inventory size and outside the GitHub API rate limit). Matching goes through our package→repo map.

### F-014
- **Date:** 2026-10-19 · **Status:** confirmed (single case)
- **Result:** `GHSA-7j62-cjxp-3cj5` lists package `pip/zoneminder`; `pypi.org/pypi/zoneminder/json` returns 404.
- **Implication:** Maintainer-entered package metadata is unreliable before review. Match on our package→repo mapping first; treat the advisory's package name as a weaker signal.

### F-015
- **Date:** 2026-10-19 · **Status:** tentative (n=23)
- **Result:** Of the 23 unreviewed advisories in F-012, 16 list ecosystem `''`, `other`, `c` or `c++/c`; also `riot`, composer 3, pip 1. GitHub docs say only ecosystems in the dependency graph go to the global DB.
- **Implication:** Many will likely never be reviewed. Report them as "likely permanent", not "pending".

### F-016
- **Date:** 2026-10-20 · **Status:** confirmed (observed)
- **Method:** 1,000 most recently reviewed advisories (reviewed 2026-09-18 → 2026-10-19), paginated via `gh api`.
- **Result:** 988 of 1,000 came from repo advisories. **117 (11.7%) have no CVE**, 109 of them from repo advisories.
- **Implication:** "Published, no CVE, reviewed" is common. These are visible to GHSA/OSV-based tools but invisible to CVE/NVD-keyed tools (NO_CVE).

### F-017
- **Date:** 2026-10-20 · **Status:** confirmed (observed); share of other-CNA package CVEs reviewed is unknown (Q3)
- **Method:** Same reviewed set as F-016, plus the 500 most recent unreviewed advisories (published 2026-10-19 → 2026-10-20). CNA lookup via cveawg.
- **Result:**
  - Reviewed but not from repo advisories: 12 of 1,000; only **4 carried another CNA's CVE** (all VulnCheck), 8 had no CVE. NVD publication to review for these: min 0.6, median 9.4, max 17.2 days (n=11).
  - Unreviewed: **0 of 500 carry package info**. CNAs (first 300): apple 133, VulnCheck 46, ibm 38, VulDB 22, CPANSec 15, mitre 9, WSO2 6, redhat 5.
- **Implication:** The user's observation holds with a nuance. Other-CNA advisories are *almost* always unreviewed, and their unreviewed records can't be matched to packages anyway. For GitHub-native tools these are near-permanent ghosts (ORPHAN_CVE). Ecosystem DBs feeding OSV (Go vulndb, PyPA, RustSec) may cover some; npm has no equivalent.

### F-018
- **Date:** 2026-10-19 · **Status:** confirmed (single case)
- **Result:** The brand-new `CVE-2026-102607` (published 2026-10-16) already had NVD `vulnStatus = Deferred`, with only a CNA `Secondary` CVSS and no `configurations`.
- **Implication:** NVD_UNENRICHED will be true for most new non-KEV CVEs, so treat it as informational by default.

### F-019
- **Date:** 2026-10-19 · **Status:** confirmed (docs)
- **Result:** GitHub docs: requesting a CVE "doesn't make your security advisory public"; GitHub "usually reviews the request within 72 hours" and publishes the CVE after the advisory is public. After publication, "GitHub will review each published security advisory, add it to the GitHub Advisory Database"; review "can take up to 72 hours". Only ecosystems in the dependency graph are added.
- **Implication:** Documented timelines don't match what we observed (F-010, F-011).
- **Sources:** [About repository security advisories](https://docs.github.com/en/code-security/security-advisories/working-with-repository-security-advisories/about-repository-security-advisories)

### F-020
- **Date:** 2026-10-20 · **Status:** confirmed (docs + observed)
- **Question:** Can deps.dev serve as a cross-ecosystem package→repo mapper?
- **Method:** `GET https://api.deps.dev/v3/systems/{system}/packages/{name}/versions/{version}` for 7 packages; docs at docs.deps.dev/api/v3.
- **Result:**
  - Systems: `GO`, `RUBYGEMS`, `NPM`, `CARGO`, `MAVEN`, `PYPI`, `NUGET` only (Composer returns 404).
  - `relatedProjects[]` has `relationType` (`SOURCE_REPO`, `ISSUE_TRACKER`) and `relationProvenance` (`SLSA_ATTESTATION`, `GO_ORIGIN`, `PYPI_PUBLISH_ATTESTATION`, `RUBYGEMS_PUBLISH_ATTESTATION`, `UNVERIFIED_METADATA`).
  - Projects are limited to github.com, gitlab.com and bitbucket.org.
  - Observed: express, serde, Newtonsoft.Json, rails, requests → SOURCE_REPO via `UNVERIFIED_METADATA`; npm `sigstore@3.0.0` also via `SLSA_ATTESTATION`; `golang.org/x/net` (googlesource) and Maven `commons-text` → none.
  - No batch endpoint. Use is under the Google API Terms of Service; "Clients are expressly permitted to cache data served by the API."
- **Implication:** A good second-tier mapper for 7 ecosystems, with provenance usable as a confidence signal. Not universal: it misses non-GitHub/GitLab/Bitbucket hosts and some Maven metadata.
- **Sources:** [deps.dev API v3](https://docs.deps.dev/api/v3/)

### F-021
- **Date:** 2026-10-20 · **Status:** confirmed (observed); licensing implications open (Q6)
- **Question:** Can ecosyste.ms cover registries that deps.dev doesn't?
- **Method:** `GET https://packages.ecosyste.ms/api/v1/registries` and `/registries/{registry}/packages/{name}`; site footer for license.
- **Result:**
  - 100 registries on the first page, including packagist, pub, hex, cpan, cran, hackage, conan, vcpkg, cocoapods, swiftpm, julia, opam and conda.
  - `repository_url` resolved for laravel/framework, dart `http`, phoenix, Moose, ggplot2 and aeson.
  - **conan `openssl` → `conan-io/conan-center-index`, the recipe repo, not OpenSSL's upstream.**
  - swiftpm lookup by URL-name returned 404 (name format unclear).
  - Anonymous rate limit 5,000/hr (`x-ratelimit-tier: anonymous`). Data license **CC BY-SA 4.0**, with commercial licenses offered.
- **Implication:** Widest mapping coverage, but lowest trust. Packaging/recipe repos must be detected and not treated as upstream. Share-alike terms may affect a commercial product that redistributes mapping data.
- **Sources:** [ecosyste.ms](https://ecosyste.ms/)

### F-022
- **Date:** 2026-10-20 · **Status:** confirmed (source code); behavior untested
- **Method:** `RANGE_CLASS_BY_SCHEMES` in `univers/src/univers/version_range.py` (main); PyPI latest version.
- **Result:** univers 32.0.1 has range classes for npm, pypi, maven, nuget, composer, gem, golang, hex, cargo, conan, github, deb, rpm, apk, alpm, ebuild, nginx, openssl, mozilla, apache, mattermost, generic, intdot, datetime, lexicographic. It also has `GitHubVersionRange` and `from_osv_v1()`. **No** scheme for pub, swift, hackage, cran or cpan. The README's ecosystem list is out of date compared with the code.
- **Implication:** Covers every GHSA ecosystem except pub and swift (both semver-like; small custom comparators needed). GitHub-range and OSV parsing exist but must be checked against real fixtures in Phase 3 before we rely on them.
- **Sources:** [univers](https://github.com/aboutcode-org/univers)

### F-023
- **Date:** 2026-10-20 · **Status:** confirmed (docs, from F-002 source)
- **Result:** GHSA ecosystem enum: `rubygems`, `npm`, `pip`, `maven`, `nuget`, `composer`, `go`, `rust`, `erlang`, `actions`, `pub`, `other`, `swift`.
- **Implication:** Anything else (C/C++, CPAN, CRAN, Hackage, vendored code, git submodules) falls into `other`/empty and is likely never reviewed (F-015). For those, matching by upstream repo is the only path, and GhostCVE may be the only tool that alerts at all.

### F-024
- **Date:** 2026-10-20 · **Status:** confirmed (observed)
- **Question:** Is GitHub's dependency-graph SBOM (`GET /repos/{o}/{r}/dependency-graph/sbom`) a usable inventory for research?
- **Result:** Mostly. Exact versions for about 99% of entries in gitea, kubernetes, open-webui and langchain; the rest are git SHAs or branch names. **n8n: 1,647 of 1,953 entries unresolved** (pnpm `catalog:` references and ranges), so GitHub's own dependency graph silently lacks versions there. n8n's `pnpm-lock.yaml` (lockfileVersion 9.0, pnpm 12) holds **two YAML documents**; the first lists only pnpm's own toolchain packages.
- **Implication:** Lockfile parsers must handle multi-document pnpm locks and pnpm catalogs. A dependency graph without resolved versions is exactly the silent-skip failure GhostCVE reports as UNRESOLVED.

### F-025
- **Date:** 2026-10-20 · **Status:** confirmed (observed, n=6,426)
- **Question:** How well does the mapper chain (Go module path / Actions path → deps.dev) cover real projects?
- **Method:** Unique package-versions from 5 projects (gitea, kubernetes, n8n, open-webui, langchain): npm, PyPI, Go, Cargo, Actions.
- **Result:**
  - **97.4% mapped to a GitHub repo.** By method: deps.dev `UNVERIFIED_METADATA` 4,176, `SLSA_ATTESTATION` 1,222, `PYPI_PUBLISH_ATTESTATION` 313, `GO_ORIGIN` 78; Go `github.com/` path 468; Actions path 1.
  - Unmapped: no repo 156, non-GitHub 8, deps.dev 404 4.
  - 3,271 unique upstream repos; 25 returned 404 when polled.
- **Implication:** deps.dev is strong enough to be the default second-tier mapper. About 24% of mappings carry attestation provenance.

### F-026
- **Date:** 2026-10-20 · **Status:** confirmed (observed)
- **Question:** How common are ghost advisories among the upstreams of real, popular projects?
- **Method:**
  - Polled `GET /repos/{r}/security-advisories?state=published` for the 3,246 reachable upstreams from F-025.
  - Checked every GHSA in OSV (`/v1/vulns/{ghsa}`).
  - Confirmed global status (`/advisories/{ghsa}`) for every OSV-missing advisory plus every advisory matching a dependency.
  - Checked CVE IDs with cveawg.
- **Result:**
  - 306 repos have ≥1 published advisory, **1,928 advisories in total**.
  - **350 (18.2%) are absent from the global DB** (all confirmed 404): 249 without a CVE, 29 with a *reserved* CVE ID (F-029), and 72 with a published CVE (GHOST_CVE).
  - Of the 1,578 reviewed advisories, 205 (13%) have no CVE.
  - **OSV-by-GHSA presence matched global review status in 939 of 939 directly confirmed cases.**
  - Pending ghosts by days since repo publication: median 9, p90 91, max 2,612. Buckets: <7 days 149, 7–30 days 120, 30–90 days 44, 90–365 days 29, >1 year 8.
  - Ghost ecosystems: npm 160, pip 152, go 26, rust 9.
- **Caveats:** This snapshot is censored: pending ages keep growing, so the median isn't comparable with F-010's completed-review lag. Some ghosts are duplicates of reviewed advisories under a different ID (F-028).
- **Implication:** OSV-by-GHSA is a free, quota-free first filter for "reviewed?"; only misses need confirming against GitHub's API. Ghosts aren't rare: about 1 in 5 upstream advisories.

### F-027
- **Date:** 2026-10-20 · **Status:** tentative (repo-advisory ranges, dedup heuristic, F-028/F-030)
- **Question:** Do popular projects actually ship ghost-affected versions?
- **Method:** Matched advisory package (ecosystem + normalized name) **and** advisory repo = mapped repo, then evaluated the repo advisory's `vulnerable_version_range` against the resolved version (univers comparators).
- **Result:** Version-affected ghost findings (advisory × package-version × project):

  | Project | Version-affected | Needs review (range unknown / repo-only) |
  |---|---|---|
  | go-gitea/gitea | 2 | 0 |
  | kubernetes/kubernetes | 3 | 0 |
  | langchain-ai/langchain | 122 | 42 |
  | n8n-io/n8n | 89 | 13 |
  | open-webui/open-webui | 95 | 23 |

  That's 167 unique ghost advisories affecting at least one used version. Examples:
  - gitea: `github.com/getkin/kin-openapi@v0.149.0`, GHSA-g3f9-hcw7-r9w2 (no CVE, 6 days, fix 0.150.0)
  - kubernetes: `github.com/go-jose/go-jose/v4@v4.1.5`, GHSA-mgcc-cww5-fp2q (high, no CVE, 5 days); `github.com/dlclark/regexp2/v2@v2.2.1`, GHSA-wq9v-j77v-qr26 (high, CVE reserved, 100 days)
  - n8n and open-webui: `markdown-it`, GHSA-r7fv-28h4-cvq7 (high, CVE-2026-111759 published, 37 days)
- **Implication:** Every sampled project had ghost-affected versions, including two lean Go projects. This supports the product premise on real inventories.

### F-028
- **Date:** 2026-10-20 · **Status:** tentative (heuristic)
- **Question:** Is every global 404 a true ghost?
- **Result:** No. GitHub sometimes publishes the reviewed record under a **different GHSA ID**. Examples:
  - dompurify GHSA-4w3q-35jp-p934 ("IN_PLACE… cross-window") ≈ reviewed GHSA-hpcv-96wg-7vj8 ("Cross-realm IN_PLACE…")
  - pyjwt GHSA-pxh4-856f-4h89 ≈ reviewed GHSA-9j54-fg26-wv3r

  Comparing summaries against reviewed advisories for the same package, across the 167 version-affected ghosts: likely duplicate (similarity ≥0.6) 23; possible (0.4–0.6) 50, though spot checks of that band showed mostly *different* issues; no match 94.
- **Implication:** Diff engine needs duplicate detection (same package, overlapping ranges, text similarity, shared CVE or references). Report suspected duplicates as "possibly covered by GHSA-…" instead of as a ghost. Rough estimate: about 14% of ghost candidates are duplicates.

### F-029
- **Date:** 2026-10-20 · **Status:** confirmed (observed). Answers Q1.
- **Result:** Repo advisories expose `cve_id` while the CVE is still **RESERVED**. `GET https://cveawg.mitre.org/api/cve/{id}` returns 404 `CVE_RECORD_DNE`, but `GET https://cveawg.mitre.org/api/cve-id/{id}` returns 200 without auth: `{"state":"RESERVED","owning_cna":"[REDACTED]"}`. 29 of the 350 ghosts are in this state, some for 100–111 days (e.g. CVE-2026-77299, CVE-2026-63402).
- **Implication:** Add a fact value `cve: reserved`. A ghost advisory with a reserved CVE is a distinct, detectable state, and CVE-keyed tools can't see it either.

### F-030
- **Date:** 2026-10-20 · **Status:** tentative
- **Question:** Can repo-advisory version ranges be evaluated directly?
- **Result:**
  - **372 of 1,353 advisory×dependency hits (27%) had ranges a strict GHSA grammar can't parse.** Maintainers enter npm-style space-separated ranges (`>=5.0.0-beta.0 <7.1.0`), hyphen ranges (`8.0.0-alpha.0 - 8.0.0-rc.5`), typos (`=>0.31.1`) and prose (`>=1.3.3 and <= 1.4.1`). Another 214 hits are repo-only (no package data).
  - Of 497 reviewed, version-affected hits (judged by repo ranges), **134 were not returned by OSV's package query** for that version. Examples have open-ended repo ranges such as aiohttp `>=3.10.6`. The repo advisory's range likely differs from the reviewed one.
- **Implication:**
  - The range parser must accept canonical GHSA syntax plus npm-semver and common sloppy forms; anything else becomes `UNRESOLVED(range_unparseable)`, never dropped.
  - Once an advisory is reviewed, prefer the reviewed/OSV range.
  - Disagreement between the repo range and the reviewed range is a frequent RANGE_DRIFT source and needs its own test cases.

### F-031
- **Date:** 2026-10-20 · **Status:** confirmed (observed, sampled)
- **Method:** NVD API 2.0 for all 80 CVEs on ghost hits and 60 randomly sampled CVEs on reviewed hits.
- **Result:**
  - **Ghost CVEs:** 24 absent from NVD, 31 `Received`, 13 `Awaiting Analysis`, 2 `Deferred`, 10 enriched.
  - **Reviewed CVEs:** 36 enriched (NIST CVSS or CPE); 24 not enriched (15 `Deferred`, 7 `Awaiting Analysis`, 1 `Undergoing Analysis`, 1 timeout).
- **Implication:** About 40% of reviewed CVEs on real dependencies are unenriched in NVD, so CPE-based tools miss them even after GitHub review. NVD calls need generous timeouts and a resumable checkpoint, because one read timeout killed a full run.

### F-032
- **Date:** 2026-10-20 · **Status:** confirmed (docs + observed)
- **Question:** Can OSV-Scanner / OSV-Scalibr serve as GhostCVE's inventory backend instead of our own parsers?
- **Method:** Docs (supported lockfiles, output formats). `go run github.com/google/osv-scanner/v2/cmd/osv-scanner@v2.7.0 scan source -L <lockfile>` on n8n `pnpm-lock.yaml` and gitea `go.mod`.
- **Result:**
  - OSV-Scanner v2.7.0 (2026-10-12) is **Apache-2.0**; extraction is implemented in the standalone **OSV-Scalibr** library.
  - Supported lockfiles include bun/npm/pnpm/yarn, Pipfile/poetry/requirements/pdm/pylock/uv, go.mod, Cargo.lock, composer.lock, Gemfile.lock, mix.lock, pubspec.lock, conan.lock, renv.lock, cabal/stack, NuGet `packages.lock.json`/`deps.json`, Gradle lockfiles, and **pom.xml with transitive resolution via deps.dev's resolver** (on by default, off with `--no-resolve` / offline). Also container images.
  - **n8n: 3,769 packages extracted in about 45 ms**, multi-document pnpm lock handled (F-024; GitHub's SBOM resolved only 306). gitea `go.mod`: 225.
  - `--format cyclonedx-1-5` / `spdx-2-3` list **only vulnerable packages** (46 for n8n). **`--format json --all-packages`** gives the full inventory with `name`, `version`, `ecosystem`, `purl`.
  - Exit code 1 when vulns are found; `--offline` and `--download-offline-databases` exist.
- **Implication:** Writing and maintaining lockfile parsers for every language duplicates OSV-Scalibr. Use OSV-Scanner's `--all-packages` JSON as an inventory backend. Keep native Python parsers only where we need data it doesn't expose (e.g. dev/direct flags, unresolved-range reporting); that needs checking.
- **Sources:** [OSV-Scanner output formats](https://google.github.io/osv-scanner/output/), [Supported languages and lockfiles](https://google.github.io/osv-scanner/supported-languages-and-lockfiles/)

### F-033
- **Date:** 2026-10-20 · **Status:** tentative (ranges from repo advisories, F-030)
- **Question:** Does GhostCVE add anything beyond OSV-Scanner on the same inventory?
- **Method:** Compared OSV-Scanner's vulnerable packages (F-032 run) with the ghost-affected packages from F-027.
- **Result:**
  - **n8n:** OSV-Scanner flags 46 vulnerable packages. 34 packages are affected by ghost advisories, and **24 of those are reported clean** by OSV-Scanner (e.g. `@bufbuild/protobuf@2.11.0`, `@modelcontextprotocol/sdk@1.31.0`).
  - **gitea:** OSV-Scanner flags 1. Both ghost-affected packages (`kin-openapi@0.149.0`, `go-chi/chi/v5@5.3.2`) are reported clean.
- **Implication:** GhostCVE's value is exactly the delta OSV can't contain yet (unreviewed repo advisories, F-012/F-026). Reviewed-vulnerability matching is OSV's job and should be consumed, not rebuilt.

### F-034
- **Date:** 2026-10-20 · **Status:** confirmed for what was checked; commercial DBs unverified
- **Question:** Does an existing tool already detect ghost advisories for a project's dependencies?
- **Result:**
  - **Safeguard** blog (2026-10-18), on 45 active Go/npm/PyPI projects:
    - 764 of 2,486 2026 repo advisories (30.7%) were not in the reviewed DB or OSV.
    - 77% of advisories without a CVE were missing, vs 11% with a CVE.
    - Arrivals had a median delay of 5.4 days, and about 1 in 6 took more than 30 days.
    - It ships a free stdlib script, `advisory_gap.py OWNER/REPO…`: one page of repo advisories, checked against OSV `/v1/vulns/{ghsa}`, exit 1 if any are missing. **No lockfile/SBOM input, no package→repo mapping, no version matching, no global-API check, no CI/issue integration, license not stated.** No Safeguard product is described as doing this.
  - **Apify scrapers and `timmKal01/github-security-advisory-tracker`** watch the *global* DB (reviewed/unreviewed), not repo advisories.
  - **ecosyste.ms advisories** mirrors the global DB (`source_kind: github`, UUID = GitHub node ID). It had none of 3 ghost GHSAs tested for kin-openapi, pyjwt and markdown-it.
  - **Academic work** (ACM paper on the GHSA review pipeline; Help Net Security 2026-02-16) is research, not tooling.
  - **Not verified:** commercial curated DBs (Snyk, Socket, Aikido Intel, Endor Labs, VulnCheck) may cover some ghosts through their own research. They need accounts, and their DBs can't be redistributed.
- **Implication:** The measurement itself has been done by others, and our data matches Safeguard's independently. **No open tool joins a real inventory to repo advisories with version matching, classification and GitLab workflow.** That join is GhostCVE's scope. Credit Safeguard's data in the README.
- **Sources:** [Safeguard blog](https://safeguard.sh/resources/blog/github-repository-advisories-missing-from-advisory-database-2026-data), [timmKal01 tracker](https://github.com/timmKal01/github-security-advisory-tracker), [Apify GHSA scraper](https://apify.com/parseforge/github-security-advisories-scraper), [ACM paper](https://dl.acm.org/doi/10.1145/3793302.3793360), [Help Net Security](https://www.helpnetsecurity.com/2026/02/16/github-security-advisorie-review-timelines-study/)

### F-035
- **Date:** 2026-10-20 · **Status:** confirmed (GitHub blog, 2026-06-29, updated 2026-07-01)
- **Question:** Is GitHub about to close the gap itself?
- **Result:**
  - GitHub: "since mid-April… we have not consistently met our internal goals for publication." Processing grew "to about a week, then to multiple weeks for a meaningful share." "The issue is throughput."
  - Repository advisories rose "to more than 5,000/week." Critical issues are prioritized; more risk signals are being explored.
  - Planned: "increased repository GitHub Security Advisory and Private Vulnerability Reporting data validation" at the source.
  - **No plan to alert from repo advisories before review.**
- **Implication:** The gap is structural (volume, about 5,000/week) and unlikely to close soon, which matches F-010 and F-026. Source-side validation may improve repo-advisory data quality over time (F-014, F-030), so re-measure periodically.
- **Sources:** [GitHub blog: Inside the Advisory Database](https://github.blog/security/supply-chain-security/inside-the-advisory-database-and-what-happens-when-vulnerability-volume-breaks-records/)

## Archive

(Superseded and refuted entries move here during cleanup.)
