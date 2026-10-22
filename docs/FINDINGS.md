# Limbowatch Findings Report

> Formerly *GhostCVE*; renamed 2026-10-21 (see [F-037](#f-037)). Log entries before that date use the old name and the term "ghost" for what is now called **limbo** (published, not yet reviewed). Their results are unchanged.

What we've verified or measured while building Limbowatch. Maintenance rules are in [CLAUDE.md](../CLAUDE.md#findings-report-docsfindingsmd).

Last summarized: 2026-10-22 (Phase 1, after the same-day re-measurement and off-GitHub scan)

## Summary

Current understanding (Phase 1, 2026-10-21), with entries linked:

1. **About 1 in 6 upstream advisories is in limbo.** Across the upstreams of 15 popular projects (5 on GitHub, 10 on GitLab/Codeberg/Tor/GNOME/Framagit/SourceHut), 415 of 2,517 unique published repo advisories (16.5%) are in neither GitHub's reviewed DB nor OSV: 14.3% for the GitHub-hosted set, 17.1% off-GitHub. All confirmed by the global API and verified automatically ([F-055](#f-055), [F-053](#f-053), [F-050](#f-050)).
2. **The median wait for GitHub review is about 3 weeks.** 23 days on 990 reviews (Sep 24 → Oct 22); 94% over the documented 72 hours, 44% over 30 days ([F-055](#f-055), [F-042](#f-042), [F-019](#f-019)). Review comes in bursts: 37 of one day's limbo set were reviewed within 30 hours ([F-050](#f-050)). GitHub attributes the delay to throughput, more than 5,000 repo advisories a week ([F-035](#f-035)).
3. **Real projects ship affected versions that scanners report clean.** 105 package-versions across 13 of 14 readable projects, including GitLab (14), Forgejo (7), Gitea (4) and Kubernetes (3), are affected by advisories in limbo that OSV-Scanner reports with no known vulnerability. Hosting off GitHub doesn't help ([F-055](#f-055), [F-053](#f-053)).
4. **Before review, an advisory is invisible everywhere scanners look.** It's not in the global DB, not even as `unreviewed`; at most OSV has a `CVE-*` record with GIT ranges and no package ([F-012](#f-012)). CVE records mostly appear about a day before review, 18 days after repo publication ([F-042](#f-042)).
5. **The lifecycle is not linear.** About 11% of reviewed advisories never get a CVE ([F-016](#f-016), [F-055](#f-055)). 27 CVE IDs stay *reserved but public* (up to 119 days, [F-029](#f-029)). 23 limbo advisories have a CVE assigned by VulnCheck/Tenable that they don't cite, so CVE-keyed tools see them first ([F-050](#f-050)). Other-CNA CVEs are almost never reviewed ([F-017](#f-017)). Model facts independently.
6. **Repo-advisory data is noisy.**
   - 16% of in-range matches contradict the advisory's own fixed version ([F-051](#f-051)).
   - Go advisories confuse `module` and `module/v2` ([F-052](#f-052)).
   - Duplicates are proven only by a shared CVE (5 + 13), with title overlap only a flag ([F-048](#f-048)).
   - Free-form ranges: about 4% unparseable after tolerant parsing ([F-044](#f-044)).
   - Wrong package names ([F-014](#f-014)); a CVE of another product cited ([F-050](#f-050)).
7. **NVD lags as well.** New non-priority CVEs are `Deferred` at once ([F-005](#f-005), [F-018](#f-018)). About 45% of reviewed CVEs on real dependencies are unenriched ([F-046](#f-046)).
8. **Global signals exist for part of the window.** The cvelistV5 delta log gives GitHub-CNA CVEs with GHSA links and owner/repo ([F-013](#f-013)). `cveawg /api/cve-id/` exposes RBP state ([F-029](#f-029)). OSV-by-GHSA is a free, validated proxy for "reviewed" ([F-041](#f-041)).
9. **Reuse, don't rebuild.** OSV-Scanner provides inventory for about 25 lockfile types ([F-032](#f-032)), but needs explicit lockfiles to avoid a silent empty scan ([F-040](#f-040)). deps.dev maps 96% of packages to repos ([F-020](#f-020), [F-041](#f-041)); univers compares versions ([F-022](#f-022)). OSV-Scanner can't load custom DBs ([F-039](#f-039)).
10. **The core scan already exists; the lifecycle layer doesn't.** blindspot does lockfile → repo advisories → OSV for npm/PyPI/Go ([F-036](#f-036)). Nobody runs a live tracker, an open limbo feed, GitLab/Gitea workflow or watch mode ([F-038](#f-038)). "Ghost CVE" already means reserved-but-public, hence the name Limbowatch ([F-037](#f-037)).
11. **Repo advisories contain personal data** (author, credits): never redistribute raw objects ([F-047](#f-047)).
12. **GitLab specifics:** SARIF ingestion is Ultimate-only (GA 19.2) and treats CVE-less findings as SAST ([F-008](#f-008)). GitLab's advisory DB can't be queried ([F-038](#f-038)).
13. **More languages are feasible in layers:** deps.dev (7 systems), then ecosyste.ms (~100 registries, CC BY-SA), then repo-only matching for languages GitHub doesn't review ([F-020](#f-020), [F-021](#f-021), [F-023](#f-023)).
14. **Verify automatically, from primary sources only.** Search results and AI summaries mis-pair advisory and CVE IDs. Stage 8 verifies every advisory in limbo (live re-check, cited-CVE consistency with live fetch, case-insensitive full CVE List reverse lookup, cross-ID review) and records the verdicts ([F-049](#f-049), [F-050](#f-050)). Time-varying data must be stored per snapshot ([F-054](#f-054)).

## Open questions

- ~~Q1. While a CVE is reserved but not yet published, does the repo advisory API already expose `cve_id`?~~ **Answered 2026-10-20: yes. Detectable via `cveawg /api/cve-id/{id}` ([F-029](#f-029)).**
- ~~Q2. Was the 55-day median a backlog being cleared on Oct 15–16, or the normal state?~~ **Answered 2026-10-21: a backlog batch. On 992 reviews the median is 26.6 days ([F-042](#f-042)). Keep re-measuring monthly (Phase 2 tracker).**
- Q3. What share of other-CNA CVEs affecting npm/PyPI/Go packages get package-level coverage in OSV through ecosystem DBs (Go vulndb, PyPA, RustSec)? Requires the CVE→package matching from Phase 2.
- Q4. How far behind GHSA are the scanner DBs (Trivy DB, Grype DB, OSV-Scanner)? GitLab Advisory DB lag can't be measured because its terms forbid querying it.
- Q5. Is "Not Scheduled" ever an NVD API `vulnStatus` value, or always `Deferred`? ([F-005](#f-005))
- Q6. Does ecosyste.ms's CC BY-SA 4.0 data license constrain Limbowatch? *Partly answered 2026-10-20: open source, so no commercial license is needed. Share-alike applies to redistributed derived data; use at runtime with a local cache only, with attribution. Revisit before 1.0.* ([F-021](#f-021))
- Q7. How do we reliably detect packaging/recipe repos (conan-center-index, homebrew-core, distro packaging) so they aren't treated as upstream? ([F-021](#f-021))
- Q8. How do we reliably detect that a limbo advisory was reviewed under a different GHSA ID when no CVE is shared? Shared CVEs prove 4; title overlap flags 4 more ([F-048](#f-048)). Advisories without a CVE remain undecidable by text alone.
- ~~Q9. Build separately, contribute upstream, or build only the layers blindspot lacks?~~ **Answered 2026-10-21: plan rev 5 approved. Report → tracker + limbo feed → upstream contributions → watcher. Renamed to Limbowatch ([F-036](#f-036), [F-037](#f-037)).**
- Q10. Under what terms may repository advisory content be redistributed? This decides whether the limbo feed can include summaries or descriptions, or only IDs and links ([F-047](#f-047)). Needed for Phase 2.

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

### F-036
- **Date:** 2026-10-21 · **Status:** confirmed (README + repo metadata; tool not executed). **Refines F-034:** an open tool for the core join *does* exist.
- **Question:** Is there an existing open-source tool that joins a dependency inventory to unreviewed repo advisories?
- **Result:** **Yes: `blindspot.py` in [munimtechnologies/advisory-import-census](https://github.com/munimtechnologies/advisory-import-census)** (Munim, Inc., "made with AI agents").
  - **Activity:** Apache-2.0. Created 2026-10-14, 87 commits, v0.9.24, last push 2026-10-20, 0 stars.
  - **Inputs:** PyPI (uv/poetry/pylock/Pipfile/requirements/pyproject), npm (package-lock v1–v3, yarn classic/Berry, pnpm v5/v6/v9), Go (go.mod/go.sum), and `--package` specs. Cargo and Composer lockfiles "are not read yet"; no SBOM input.
  - **Mapping:** registry metadata, a built-in map, `--map`, Go path; unmapped are listed. No confidence score; go.mod `replace` isn't followed.
  - **Check:** published repo advisories (one request per repo), version range covers your version ("range unclear" otherwise), then **OSV only** with the same package and version a scanner sends. No global-DB or NVD check.
  - **Output:** text, JSON, SARIF 2.1.0 (stable fingerprints, placed on the lockfile line), Markdown job summary, `--fail-on-blind`, `--ignore`. Composite **GitHub Action**.
  - **Not described:** GitLab, issues, watch/state/change detection, org-wide mode, caching/ETag, duplicate detection, reserved-CVE detection, CVE feed, classification beyond "blind spot".
  - The author: "As far as I can find, no existing scanner does this."
- **Implication:** GhostCVE's Phase 1–4 core (scan-time detection for npm/PyPI/Go, SARIF, CI gate) **substantially duplicates blindspot**. What remains unique to GhostCVE is listed in F-038.

### F-037
- **Date:** 2026-10-21 · **Status:** confirmed (READMEs, rbptracker.org)
- **Question:** Is "Ghost CVE" an existing term or project?
- **Result:** Yes, with a **different meaning**.
  - **RogoLabs (Jerry Gamblin) [`RogoLabs/GhostCVEs`](https://github.com/RogoLabs/GhostCVEs)** ("Ghost Hunter"), Apache-2.0 repo (README badge says MIT), 22 stars, created 2026-01-11, active. It defines a Ghost CVE as an identifier that "appears in the wild… but remains RESERVED or NOT_FOUND in official CVE registries". Ecosystem-wide, from 23 sources (RSS, GitHub Security Advisories, ExploitDB, CVE.org); not dependency-scoped.
  - **CIRCL Vulnerability-Lookup** uses the same definition.
  - **RogoLabs [`RBP`](https://github.com/RogoLabs/RBP) / [rbptracker.org](https://rbptracker.org):** "Reserved but Public" IDs, the CVE Program's own glossary term. 945 IDs in the last 90 days (of 1,846 total) as of 2026-10-21, from 19 feeds every 6 h, covering about 50.6% of CNAs.
  - **CVE Program RBP Policy v2.0.0** (CVE Board, 2026-08-13) "expects a record within 72 hours of disclosure".
  - RogoLabs also runs [`consensus-engine`](https://github.com/RogoLabs/consensus-engine) (NVD vs GitHub CVSS divergence) and built an hourly repo-advisory tracker for OpenClaw ([Socket blog, 2026-03-10](https://socket.dev/blog/openclaw-advisory-surge-highlights-gaps-between-ghsa-and-cve-tracking)).
- **Implication:**
  - **Name collision.** "GhostCVE" closely matches an existing, better-known Apache-2.0 project whose established meaning (reserved-but-public CVE) differs from ours (an unreviewed advisory affecting your dependency).
  - Our `cve: reserved` state (F-029) is the RBP concept. Reserved IDs held for 100+ days on repo advisories breach the 72-hour expectation. rbptracker.org is a possible cross-check, not something to rebuild.
  - Severity divergence is already tracked by consensus-engine.

### F-038
- **Date:** 2026-10-21 · **Status:** confirmed for what was checked; commercial DBs still unverified
- **Question:** What else exists, and what is still uncovered?
- **Result:**
  - **Aikido Intel:** open feed (AGPL, plus a commercial API) of malware and *undisclosed* vulns found by LLM analysis of changelogs; claims 67% "were never reported". A different signal (silent fixes) from ours (published but unreviewed advisories).
  - **Apify "Dependency Advisory Monitor":** package list → OSV + global GHSA; paid; no repo advisories.
  - **GitHub watch** only notifies on Dependabot alerts for repos you own; no documented feed of upstream repo advisories.
  - **GitLab Advisory DB:** sources page not reachable (404); its community mirror is described as "time-delayed". Not measurable under its terms.
  - Snyk, Socket, Endor Labs, Mend, JFrog, Sonatype: no public evidence either way about pre-review repo advisories.
  - **Still uncovered by any open tool found** (vs blindspot F-036, RogoLabs F-037):
    - GitLab/Gitea-native CI component and issues with lifecycle comments
    - watch mode with state and transition alerts; org-wide shared polling
    - global-DB check distinguishing "unreviewed" from "OSV lag"
    - duplicate-GHSA detection (F-028)
    - dependency-scoped reserved-CVE (RBP) state
    - cvelistV5 feed matching by repo
    - scanner-family visibility, ghost age, permanence
    - any-language inventory via OSV-Scanner
- **Sources:** [Aikido: external DBs](https://help.aikido.dev/code-scanning/scanning-practices/external-vulnerability-databases-used-in-our-sca-engine.md), [SC World: shadow patches](https://www.scworld.com/news/bsides-sf-using-ai-to-spot-shadow-patches-in-open-source-software), [Apify monitor](https://apify.com/nexgendata/dependency-advisory-monitor), [GitHub notifications docs](https://docs.github.com/en/subscriptions-and-notifications/how-tos/managing-security-notifications), [GitLab advisory DB README](https://gitlab.com/gitlab-org/security-products/gemnasium-db/-/blob/master/README.md), [dev.to: blindspot](https://dev.to/munimv2/the-critical-advisory-your-scanner-cant-see-find-it-in-one-ci-step-naa), [dev.to: AI-tools census](https://dev.to/munimv2/316-of-security-advisories-for-self-hosted-ai-tools-never-reach-the-database-your-scanner-reads-4cfh), [CIRCL Vulnerability-Lookup](https://vulnerability.circl.lu/)

### F-039
- **Date:** 2026-10-21 · **Status:** confirmed (docs)
- **Question:** Can OSV-Scanner consume a custom/additional advisory database (e.g. a Limbowatch "limbo feed")?
- **Result:** Not as a documented feature.
  - Offline mode reads `{OSV_SCANNER_LOCAL_DB_CACHE_DIRECTORY or os.UserCacheDir or os.TempDir}/osv-scanner/<ECOSYSTEM>/all.zip`, populated by `--download-offline-databases` from `https://osv-vulnerabilities.storage.googleapis.com/<ECOSYSTEM>/all.zip`.
  - No flag or documented path exists for adding custom records.
- **Implication:**
  - A limbo feed should be published as standard OSV-schema JSON, which is easy for any tool to consume.
  - Direct OSV-Scanner use needs an upstream feature request (custom local DB / extra source), not a hack into its cache.
- **Sources:** [OSV-Scanner offline mode](https://google.github.io/osv-scanner/usage/offline-mode/)

### F-040
- **Date:** 2026-10-21 · **Status:** confirmed (observed)
- **Question:** Does OSV-Scanner's recursive directory scan work as an inventory backend?
- **Result:**
  - `osv-scanner scan source --recursive DIR` **silently finds nothing** when `DIR` is under a hidden directory (here `.cache/`): it walks "1 dirs visited", says "No package sources found", and exits **128**.
  - The same files scanned with explicit `-L <lockfile>` (or from a non-hidden path) give the full inventory.
  - Non-standard requirements names need `-L requirements.txt:<path>`.
  - Against GitHub's dependency-graph SBOM, OSV-Scanner found **1,197 packages for gitea vs 256** (the SBOM had no npm entries; F-024).
  - In kubernetes, 161 of 2,042 `go.mod` entries have no version: local `replace` modules.
- **Implication:** The Phase 4 inventory adapter must pass explicit lockfiles (or check for exit 128 / zero sources) and report "no package sources" as `UNRESOLVED`, never as clean. That's the silent-skip failure the SPEC exists to prevent.

### F-042
- **Date:** 2026-10-21 · **Status:** confirmed (observed). **Supersedes F-010 and F-011.** Answers Q2.
- **Question:** How long does GitHub review take, on a large sample?
- **Method:** The 1,000 most recently reviewed advisories (reviewed 2026-09-22 → 2026-10-21); 992 originated as repo advisories. Repo advisory `published_at` vs global `github_reviewed_at`; CVE `datePublished` via CVE Services.
- **Result:**
  - Review lag: **median 26.6 days**, p25 13.3, p75 58.6, p90 90.7, max 2,272.7. **94.2% over 72 hours; 47.9% over 30 days.**
  - Of 866 with CVE dates, 780 (90%) had the CVE published before review, a median of 0.97 days earlier.
  - Repo publication to CVE publication: median 18.1 days.
  - 114 of 1,000 (11.4%) reviewed without a CVE.
- **Implication:** F-010's 55-day median (n=40) was one backlog batch (that was Q2's suspicion). The typical wait is about 4 weeks, still far above the documented 72 hours (F-019). CVE publication mostly happens just before review, so the repo advisory is the only early signal for most of the window.

### F-044
- **Date:** 2026-10-21 · **Status:** confirmed (observed). Refines F-030.
- **Question:** Which range forms do maintainers write, and how far can tolerant parsing go?
- **Result:**
  - Beyond F-030's forms, the data contains:
    - Unicode `≤`/`≥`;
    - `;` as OR (`< 6.24.0; 7.0.0 < 7.24.0`);
    - bare-lower-then-upper (`7.0.0 < 7.29.0` meaning `>= 7.0.0, < 7.29.0`);
    - `0.15.0 and earlier`;
    - commas used as OR (`<1.1.17, >= 2.0.0 < 2.1.3, 4.0.0 - 5.0.7`), detected because the AND reading is contradictory.
  - With these handled, unparseable ranges fell from 278 to **65 of 1,397 package matches (4.7%)**. The rest are prose (`all`, `All version prior and including to 8.0.0, 7.31.0, 5.10`), deliberately left `unknown`.
  - 116 advisory matches carry no package data at all (repo-only).
  - 10 advisories cite CVE IDs whose state is `REJECTED`.
- **Implication:** The Phase 2 evaluator should start from this parser (`research/.../scripts/common.py`, 20 self-check cases) and keep prose as `UNRESOLVED(range_unparseable)`.

### F-046
- **Date:** 2026-10-21 · **Status:** confirmed (observed, sampled). Refines F-031.
- **Result:**
  - **Published CVEs on advisories in limbo (n=65):** absent from NVD 10; not enriched 38 (Received 25, Awaiting Analysis 9, Undergoing 2, Deferred 2); enriched 17.
  - **Random sample on reviewed advisories (n=60):** enriched 32; not enriched 27 (Deferred 10, Awaiting 6, Undergoing 6, Received 2, Rejected 3); absent 1.
- **Implication:** About 45% of reviewed CVEs on real dependencies are unenriched in NVD, consistent with F-031.

### F-047
- **Date:** 2026-10-21 · **Status:** confirmed (observed)
- **Question:** What personal data do repository advisory API objects carry?
- **Result:** Each object includes `author` and `publisher` (when present), `credits`, `credits_detailed`, `collaborating_users` and `collaborating_teams` (GitHub accounts of real people), plus the full `description`.
- **Implication:**
  - Raw advisory objects must not be redistributed. The Phase 1 dataset keeps only IDs, states, dates, ranges and links; `.gitignore` excludes the intermediate JSON.
  - The Phase 2 limbo feed and site must apply the same rule.

### F-048
- **Date:** 2026-10-22 · **Status:** confirmed (observed). **Supersedes F-045.**
- **Question:** Is summary similarity a reliable duplicate signal?
- **Result:**
  - **No, not character-level similarity.** Same-repo titles share boilerplate (`undici vulnerable to Denial of Service via …`, `fast-uri vulnerable to … via …`, `pypdf: Possible long runtimes …`). `difflib` ratios of 0.6–0.8 linked one undici advisory to 12 unrelated CVEs.
  - **Strong evidence:** the advisory's own CVE is attached to a *different, reviewed* GHSA. This found **4 duplicates**: adm-zip GHSA-679w (CVE-2026-102282 → GHSA-j5f4), two prism advisories (CVE-2021-3801, CVE-2021-23341), MCP TS SDK GHSA-cqwc (CVE-2026-0621 → GHSA-8r9q).
  - **Word-set Jaccard ≥ 0.6/0.7** gives 4 possible duplicates.
  - F-045's 23 "likely duplicates" used the character ratio and overstated the correction. The limbo share is **14.7–15.1%**, not 13.9–15.1%.
- **Implication:** For dedup, use shared CVE IDs (and the CVE List reverse lookup, F-049) as proof and title overlap only as a flag. Never subtract text-only matches from headline counts.

### F-049
- **Date:** 2026-10-22 · **Status:** partly refuted by [F-050](#f-050) (GHSA case bug in the reverse lookup; the MSAL "conflict" was wrong)
- **Question:** Can every claim about an advisory in limbo be verified automatically, without manual checking?
- **Trigger:** The user searched a limbo advisory's title (GHSA-wq9v-j77v-qr26, regexp2) on Google and was shown **CVE-2026-102274**. That is PyJWT's CVE (GitHub CNA, linked to GHSA-w6j9-cwv2-h6wq). The advisory itself cites CVE-2026-77299, still `RESERVED`. An independent page (delphix/ollama PR #29) confirms CVE-2026-77299. Search results and AI summaries can mis-pair IDs.
- **Method:** Stage 8 (`s8_verify.py`) checks all 294 limbo advisories against primary sources only:
  1. Live re-check of the repo advisory, global DB and OSV.
  2. Cited-CVE consistency against the CVE List record.
  3. Reverse lookup across the full CVE List bulk export (`cve_2026-10-22_0800Z`, 412,863 records, of which 991 touch our repos or GHSAs).
  4. GitHub global DB by every linked CVE.
- **Result** (2026-10-22 08:54 UTC):
  - 286 verified in limbo; 4 duplicates (same CVE reviewed under another GHSA, F-048); 2 possible duplicates.
  - **2 cite a CVE belonging to another product.** cdxgen GHSA-j59w-7c4x-4xgw cites Node.js CVE-2025-27210 (HackerOne CNA). MSAL GHSA-xcx6-jx8p-x3h5 cites Microsoft's CVE-2026-109461, whose record doesn't reference it.
  - For the 199 without a CVE, no CVE List record references their GHSA ID.
  - All 10 report examples verified.
  - GitHub's single repo-advisory endpoint `GET /repos/{o}/{r}/security-advisories/{ghsa}` works authenticated and unauthenticated (an apparent 404 was a zsh word-splitting bug in our shell loop, not GitHub).
- **Implication:**
  - Verification is a pipeline stage, not a reader task.
  - The tracker (Phase 2) should run it on every refresh and publish verdicts with timestamps.
  - "Cited CVE belongs to another product" is a distinct, detectable data-quality state worth reporting to maintainers.
  - The CVE List reverse index is also the matching engine for the cvelistV5 feed (F-013).

### F-050
- **Date:** 2026-10-22 · **Status:** confirmed (observed). **Partly refutes F-049.**
- **Question:** Was the stage-8 verification of F-049 correct?
- **Result:** It had two bugs:
  - **GHSA IDs from the CVE List were upper-cased** before comparing with our mixed-case IDs, so the reverse lookup never matched. F-049's "no CVE List record references the 199 without a CVE" was untested. With the fix (re-verified 2026-10-22 17:25 UTC):
    - **22 limbo advisories have a published CVE the advisory doesn't cite**, all assigned by **VulnCheck** (plus one by Tenable). Example: CVE-2026-110858 for GitPython GHSA-f9j4-qggq-h239, published 2026-10-14.
    - For these, CVE-keyed tools can see the vulnerability while GHSA/OSV-based scanners can't, inverting the usual gap.
  - **"Cited CVE belongs to another product" was too strict.** Records newer than the bulk export, or from vendor CNAs, often don't link back.
    - Now a conflict only if the record references a *different* GitHub repo, or its affected product shares no name tokens with ours.
    - The **MSAL** case (Microsoft CNA, "Microsoft Identity Client for NodeJS") is **not** a conflict; F-049 was wrong.
    - **cdxgen citing Node.js CVE-2025-27210** remains one.
    - Body-parser/webpack-dev-server CVEs (OpenJS CNA) were newer than the export; they're now fetched live and link back correctly.
  - **37 of the 294 Oct-21 limbo advisories were reviewed within ~30 hours** (Pillow ×10, Electron ×6, pypdf, toml-node, …). Review comes in bursts.
- **Implication:** Reverse lookups must normalize IDs. Uncited CVEs from other CNAs (VulnCheck) are a distinct, reportable state. Verification verdicts are time-stamped, and examples must be in limbo at verification time.

### F-051
- **Date:** 2026-10-22 · **Status:** confirmed (observed)
- **Question:** Do maintainer-entered ranges agree with the advisory's own fixed version?
- **Result:**
  - **Often not.** In the Oct-21 matches, **222 of 1,397 (16%)** are "in range" yet at or after the advisory's fixed version for that release line. Off-GitHub snapshot: 132.
  - Examples:
    - quinn-proto GHSA-qfwj-vfxf-92j2: range `>= 0.11.15` (no upper bound), fixed `0.11.17`.
    - go-jose GHSA-6mp9-8xrw-74r4: range `< v4.1.5`, fixed `v4.1.4`.
    - icu_normalizer GHSA-3jjw-63vg-v3hh: range `>= 2.0.0`, fixed `<= 2.3.0`.
  - Per-branch fix lists (typebox: `0.24.52 … 0.27.12 … 0.34.52`) need the fix on the same major.minor line.
- **Implication:** Evaluate the range *and* cross-check the fixed version. A contradiction becomes `UNRESOLVED(range_contradicts_fixed_version)`, never "affected". Implemented as `common.already_fixed()` with self-check cases.

### F-052
- **Date:** 2026-10-22 · **Status:** confirmed (observed)
- **Question:** How should Go advisories match Go modules?
- **Result:**
  - Prefix matching was wrong. A `/vN` suffix is a different module under Go's major-version rule.
  - GHSA-frc4-6h9q-39fq lists only `github.com/pelletier/go-toml/v2`, yet it had matched Gitaly's `github.com/pelletier/go-toml@1.9.5` (v1).
  - Conversely, GHSA-wq9v-j77v-qr26 names the base module `github.com/dlclark/regexp2` with a range in v2 numbering (`< 2.3.0`). Forgejo's `regexp2@1.11.5` matches strictly. Kubernetes' `regexp2/v2@2.2.1` matches only if one assumes the module was mislabeled.
  - Strict matching moved 2 findings (Oct-21 set) and 27 (off-GitHub set) to unknown.
- **Implication:** For Go, match only equal paths or a package inside the module. Report `/vN` variants as `UNRESOLVED(go_major_version_module_mismatch)` (`common.go_relation()`).

### F-053
- **Date:** 2026-10-22 · **Status:** confirmed (observed)
- **Question:** Does the gap look different for popular projects hosted off GitHub?
- **Method:** Same pipeline (with F-050 to F-052 applied), snapshot `2026-10-22-offgithub`.
  - Projects: GitLab, GitLab Runner, Gitaly (gitlab.com); Forgejo, GoToSocial (codeberg.org); Arti (gitlab.torproject.org); Fractal (gitlab.gnome.org); F-Droid server (gitlab.com); Mobilizon (framagit.org); aerc (git.sr.ht).
  - Popularity: gitlab-org/gitlab 6,176 stars, Forgejo 5,695 (self-hosted instances undercount stars).
- **Result:**
  - Inventory: 16,051 entries (GitLab alone 7,932, incl. 3,441 RubyGems).
  - Mapping: 8,697 of 9,795 unique package-versions mapped to GitHub repos (88.8%; 1,099 unresolved, mostly RubyGems and Go).
  - Polling: 4,061 upstreams, 278 with advisories, **1,268 advisories, 217 (17.1%) in limbo**, 202–204 after duplicates (13 strong).
  - Limbo age: median 37 days, p90 107, 40 older than 3 months.
  - RBP: 16, all past 72 hours, median 83 days.
  - **8 of 9 readable projects ship affected versions**, 69 package-versions in total, **41 reported clean by OSV-Scanner**. GitLab: 32 affected (14 clean, 35 advisories, 16 high/critical); Forgejo 9/7; GoToSocial 8/5; Arti 7/2; Mobilizon 6/6; GitLab Runner 4/4; Gitaly 2/2; Fractal 1/1; aerc 0.
  - F-Droid server: no lockfile-based dependencies; recorded as an inventory gap.
  - Mobilizon's `mix.lock` (Elixir) is inventoried but unmappable (deps.dev has no Hex).
- **Implication:** The gap is the same or larger for the GitLab/Gitea ecosystem Limbowatch targets. Their dependencies' advisories live on GitHub regardless of where the project is hosted.

### F-054
- **Date:** 2026-10-22 · **Status:** confirmed (observed)
- **Question:** What broke when running the pipeline against other hosts and multiple snapshots?
- **Result:**
  1. **gitlab.com shed load** on our repeated blob-less clones and lazy blob fetches of gitlab-org/gitlab ("GitLab is currently unable to handle this request due to load"). Its raw endpoint `/-/raw/<sha>/<path>` kept working. Fallback: reuse the local tree, fetch only lockfiles over HTTPS at the recorded commit. Also seen: Forgejo `/raw/commit/<sha>/<path>`, SourceHut `/blob/<sha>/<path>`.
  2. **OSV-Scanner exits 128 "No package sources found"** when a repo's only lockfiles are test fixtures (F-Droid server). Recorded as an inventory gap, not clean (F-040).
  3. **The shared HTTP cache let a newer snapshot contaminate an older one.** Refreshing OSV/GitHub data for Oct 22 changed the Oct-21 limbo count from 294 to 288 on recompute. Fix: time-varying sources (GitHub, OSV, CVE Services, NVD) are cached per snapshot; deps.dev stays shared. The committed Oct-21 data files were restored from git.
- **Implication:** For the product:
  - The tracker needs per-snapshot storage of time-varying facts (the plan's `vuln_fact_snapshots`).
  - Host adapters need a raw-file fallback.
  - "No package sources" must surface as UNRESOLVED.

### F-055
- **Date:** 2026-10-22 · **Status:** confirmed (observed). **Supersedes F-041 and F-043** (pre-correction methods, Oct-21 commits); refines F-042 with a newer window.
- **Question:** With all corrections (F-050 to F-054), what does a same-day snapshot of both project sets show?
- **Method:** Pipeline rerun on 2026-10-22 for the five GitHub-hosted projects at new commits (gitea `facc0f2`, kubernetes `8f5bbad`, n8n `7d2e358`, open-webui `91ea4e3`, langchain `f4e6cde`), plus F-053's off-GitHub set. Per-snapshot cache.
- **Result:**
  - **GitHub-hosted set:**
    - 11,823 entries → 6,806 unique package-versions, 96.1% mapped → 3,293 upstreams (308 with advisories) → **1,876 advisories, 268 (14.3%) in limbo**; 260–263 after duplicates (5 strong, 3 possible).
    - Classes: 178 no CVE, 15 RBP, 75 CVE (22 of them uncited VulnCheck/Tenable CVEs found in the CVE List), 205 reviewed without CVE, 1,403 reviewed with CVE.
    - Verification (17:59 UTC): 238 verified, 22 CVE in CVE List, 5 duplicates, 2 possible, 1 conflict (cdxgen).
    - Limbo age: median 12.8 days, 35 older than 3 months.
    - Per project (affected / reported clean by OSV-Scanner): n8n 33/26, langchain 23/21, open-webui 18/10, gitea 6/4, kubernetes 3/3; **64 reported clean**.
  - **Review lag** (990 of 1,000 reviewed 2026-09-24 → 2026-10-22): median 23.0 days, p90 86.5; 94.1% over 72 h, 43.7% over 30 days. 92% of CVEs published before review (median 1 day earlier); repo → CVE median 17 days; 12% reviewed without a CVE.
  - **Both sets, de-duplicated:**
    - **2,517 unique advisories, 415 (16.5%) in limbo** (627 advisories appear in both sets).
    - 27 unique RBP (25 past 72 h, oldest 119 days).
    - 23 unique advisories with an uncited CVE (22 VulnCheck, 1 Tenable).
    - **105 package-versions reported clean by OSV-Scanner** across 13 of 14 readable projects.
- **Implication:** These are the numbers the State of the Gap report uses. Cross-set totals must be de-duplicated by GHSA ID, because the sets share upstreams.

## Archive

(Superseded and refuted entries move here during cleanup.)

### F-043
- **Date:** 2026-10-21 · **Status:** superseded by [F-055](#f-055) (pre-correction methods; Oct-21 commits)
- **Question:** Do popular projects ship versions affected by advisories in limbo that a scanner reports clean?
- **Result:**

  | Project | Affected package-versions | Reported clean by OSV-Scanner |
  |---|---|---|
  | gitea | 6 | 4 |
  | kubernetes | 3 | 3 |
  | langchain | 22 | 20 |
  | n8n | 29 | 23 |
  | open-webui | 18 | 9 |

  Likely duplicates are excluded; total reported clean: 59. "Reported clean" means OSV-Scanner reports no vulnerability at all for the package-version. Fifteen high/critical examples were re-checked on 2026-10-21: global 404, not reported by OSV-Scanner, not a likely duplicate. For example kubernetes `github.com/dlclark/regexp2/v2@2.2.1` (GHSA-wq9v-j77v-qr26, CVE reserved, 102 days) and langchain/open-webui `authlib@1.7.2` (GHSA-6v38-4h7w-rj9h, critical, CVE published).
- **Implication:** This is the report's core claim, measured on real lockfiles at pinned commits.

### F-041
- **Date:** 2026-10-21 · **Status:** superseded by [F-055](#f-055) (pre-correction methods; Oct-21 commits)
- **Question:** How many upstream advisories are in limbo, re-measured with OSV-Scanner inventory?
- **Method:** Phase 1 pipeline (research/2026-10-state-of-the-gap):
  - 5 projects; inventory from OSV-Scanner v2.7.0 across all lockfiles (11,959 entries);
  - deps.dev / Go-path mapping;
  - repo advisories polled for 3,357 upstreams;
  - OSV check for every GHSA, and GitHub global API for every OSV miss plus 200 random OSV hits.
- **Result:**
  - **294 of 1,949 advisories (15.1%) in limbo**: 199 without a CVE, 17 with a reserved CVE (RBP), 78 with a published CVE.
  - **All 294 confirmed 404** in the global DB; the OSV-present sample was reviewed in 200 of 200.
  - Reviewed: 1,455 with a CVE, 200 without (10.3%).
  - Limbo age: median 10.3 days, p90 97.5, 37 over 90 days, max 2,614.
  - Severity: critical 12, high 116, medium 134, low 32.
  - Mapping: 96.2% of 6,922 unique package-versions (attested provenance for 1,832).
- **Implication:** F-026's 18.2% came from a different inventory method and date. The current measure is 13.9–15.1% (F-045). OSV-by-GHSA presence is now validated on 494 directly confirmed cases.

### F-045
- **Date:** 2026-10-21 · **Status:** superseded by [F-048](#f-048) (character-level similarity over-matched; strong duplicates are 4, not 23)
- **Question:** With stronger signals, how many limbo advisories are duplicates of reviewed ones?
- **Method:** For each of 163 limbo advisories matching project dependencies, compared against reviewed advisories of the same package (`/advisories?type=reviewed&ecosystem=&affects=`): same CVE ID, shared fix commit or PR reference, summary similarity.
- **Result:**
  - **23 (14%) likely duplicates** (similarity ≥ 0.6); 115 below 0.6; 25 had no reviewed advisories to compare.
  - **No same-CVE or shared-fix-reference matches**: repo advisories have no `references` field, so only URLs in descriptions are usable.
  - The other 131 limbo advisories (not matching our dependencies) were not checked.
- **Implication:** Duplicate detection stays text-based for now. Q8 remains open. Report limbo as a range (13.9–15.1%).

### F-010
- **Date:** 2026-10-19 · **Status:** superseded by [F-042](#f-042) (n=40 single batch; backlog bias confirmed)
- **Method:** The 40 most recently reviewed advisories with `repository_advisory_url`. Compared the repo advisory's `published_at` with the global `github_reviewed_at`.
- **Result:** Repo publication to review: min 73 h, p25 24 days, **median 55 days**, p75 80 days, max 114 days. All 40 were over 72 h. All were reviewed between 2026-10-15 20:15 and 2026-10-16 21:15 UTC, though published between 2026-06-24 and 2026-10-13, which suggests batch review. Manual check: `GHSA-pw5q-rjx4-7f7p` (getarcaneapp/arcane) was published in the repo on 2026-07-29 and reviewed on 2026-10-16. Ecosystems: go 21, pip 8, npm 6, rust 2, maven, erlang, pub.
- **Implication:** Core product premise holds, with a much larger window than GitHub's documented 72 hours.

### F-011
- **Date:** 2026-10-19 · **Status:** superseded by [F-042](#f-042) (n=38). CVE-before-review held; repo→CVE is 18 days at scale, not 47
- **Method:** Same sample as F-010; CVE `datePublished` from cveawg.
- **Result:** The CVE was published **before** review in 38 of 38 cases (median 39 h earlier, up to about 100 days earlier). Repo publication to CVE publication: median about 47 days (min −153 h: one CVE was published *before* the repo advisory). CNAs: GitHub_M 36, JFROG 1, EEF 1.
- **Implication:** Window A (repo only, no public CVE) is usually the longest. Window B (CVE public, not reviewed) is shorter but can be long.

