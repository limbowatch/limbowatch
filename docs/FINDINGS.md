# Limbowatch Findings Report

> Formerly *GhostCVE*; renamed 2026-10-21 (see [F-037](#f-037)). Log entries before that date use the old name and the term "ghost" for what is now called **limbo** (published, not yet reviewed). Their results are unchanged.

What we've verified or measured while building Limbowatch. Maintenance rules are in [CLAUDE.md](../CLAUDE.md#findings-report-docsfindingsmd).

Last summarized: 2026-11-07 (end of Phase 4: the watcher, tested in real CI and released as 0.1.0a1; Phase 5 approved)

## Summary

Current understanding at the end of Phase 4 (2026-11-07), with entries linked. Points 1–14 come from the Phase 1 research (2026-10-21 to 10-25), 15–20 and 32 from the live tracker (Phase 2, measured again 2026-11-07), 21 from Phase 3, 22–31 from the watcher (Phase 4). Numbers are dated; review backlogs drift.

**Phase 1: the gap in a sample of real projects**

1. **About 1 in 6 upstream advisories is in limbo.** Across the upstreams of 15 popular projects (5 on GitHub, 10 on GitLab/Codeberg/Tor/GNOME/Framagit/SourceHut), 415 of 2,517 unique published repo advisories (16.5%) are in neither GitHub's reviewed DB nor OSV: 14.3% for the GitHub-hosted set, 17.1% off-GitHub (2026-10-22). All confirmed by the global API and verified automatically ([F-055](#f-055), [F-053](#f-053), [F-050](#f-050)).
2. **The median wait for GitHub review was about 3 weeks.** 23 days on 990 reviews (Sep 24 → Oct 22); 94% over the documented 72 hours, 44% over 30 days ([F-055](#f-055), [F-042](#f-042), [F-019](#f-019)). Review comes in batches ([F-050](#f-050), [F-056](#f-056)). GitHub attributes the delay to throughput, more than 5,000 repo advisories a week ([F-035](#f-035)).
3. **Real projects ship affected versions that scanners report clean.** 105 package-versions across 13 of 14 readable projects, including GitLab (14), Forgejo (7), Gitea (4) and Kubernetes (3), are affected by advisories in limbo that OSV-Scanner reports with no known vulnerability. Hosting off GitHub doesn't help ([F-055](#f-055), [F-053](#f-053)).
4. **Before review, an advisory is invisible everywhere scanners look.** It's not in the global DB, not even as `unreviewed`; at most OSV has a `CVE-*` record with GIT ranges and no package ([F-012](#f-012), [F-066](#f-066)).
5. **The lifecycle is not linear.** About 11% of reviewed advisories never get a CVE ([F-016](#f-016), [F-055](#f-055)). CVE IDs stay *reserved but public* for months ([F-029](#f-029), [F-056](#f-056)). Advisories often have a CVE from another CNA (mostly VulnCheck) that they don't cite, so CVE-keyed tools see them first ([F-050](#f-050), [F-067](#f-067)). Other-CNA CVEs are almost never reviewed ([F-017](#f-017)). Model facts independently.
6. **Repo-advisory data is noisy.**
   - 16% of in-range matches contradict the advisory's own fixed version ([F-051](#f-051)).
   - Go advisories confuse `module` and `module/v2` ([F-052](#f-052)).
   - Duplicates are proven only by a shared CVE, with title overlap only a flag ([F-048](#f-048)).
   - Package names are often unusable as entered ([F-014](#f-014), [F-069](#f-069)); a CVE of another product is sometimes cited ([F-050](#f-050)).
7. **NVD lags as well.** New non-priority CVEs are `Deferred` at once ([F-005](#f-005), [F-018](#f-018)). About 45% of reviewed CVEs on real dependencies are unenriched ([F-046](#f-046)).
8. **Global signals exist for part of the window.** The cvelistV5 delta log gives GitHub-CNA CVEs with GHSA links and owner/repo ([F-013](#f-013)). `cveawg /api/cve-id/` exposes RBP state ([F-029](#f-029)). OSV-by-GHSA plus the full reviewed list are a cheap test for "reviewed" ([F-055](#f-055), [F-057](#f-057)).
9. **Reuse, don't rebuild.** OSV-Scanner provides inventory for about 25 lockfile types ([F-032](#f-032)), but needs explicit lockfiles to avoid a silent empty scan ([F-040](#f-040), [F-054](#f-054)). deps.dev maps 94–96% of packages to repos ([F-020](#f-020), [F-055](#f-055), [F-063](#f-063)); univers compares versions ([F-022](#f-022)). OSV-Scanner can already scan against an extra database offline, and its matching library has a configurable download host ([F-073](#f-073), [F-074](#f-074)).
10. **The core scan already exists; the lifecycle layer doesn't.** blindspot does lockfile → repo advisories → OSV for npm/PyPI/Go ([F-036](#f-036)). Nobody else runs a live tracker, an open limbo feed, GitLab/Gitea workflow or watch mode ([F-038](#f-038)). "Ghost CVE" already means reserved-but-public, hence the name Limbowatch ([F-037](#f-037)).
11. **Repo advisories contain personal data** (author, credits): never redistribute raw objects. The feed carries factual metadata only, attributed to GitHub ([F-047](#f-047), [F-059](#f-059)).
12. **GitLab specifics:** SARIF ingestion is Ultimate-only (GA 19.2) and treats CVE-less findings as SAST ([F-008](#f-008)). GitLab's advisory DB can't be queried ([F-038](#f-038)).
13. **More languages are feasible in layers:** deps.dev (7 systems), then ecosyste.ms (~100 registries, CC BY-SA), then repo-only matching for languages GitHub doesn't review ([F-020](#f-020), [F-021](#f-021), [F-023](#f-023)).
14. **Verify automatically, from primary sources only.** Search results and AI summaries mis-pair advisory and CVE IDs. Verification is a pipeline stage with recorded verdicts ([F-049](#f-049), [F-050](#f-050)). Time-varying data must be stored per snapshot ([F-054](#f-054)).

**Phase 2: the live tracker**

15. **The gap at scale is far bigger than the sample.** On 2026-10-31, over a watchlist of 18,656 repos (every one polled at least once): **7,988 advisories pending review** in ecosystems GitHub reviews (861 critical, 3,191 high; median wait so far 57 days; 4,055 with no CVE anywhere), plus **13,852 likely permanent** in ecosystems GitHub doesn't review. Every number is a floor: only watched repos are seen ([F-064](#f-064), [F-070](#f-070)).
16. **Where the watchlist comes from matters.** Dependency upstreams of popular projects, origin repos of reviewed advisories, and every repo named by a GitHub-CNA CVE ([F-057](#f-057), [F-063](#f-063), [F-066](#f-066)). Adding the last source on 10-31 closed a 2,113-repo gap, mostly applications whose advisories are likely permanent ([F-068](#f-068), [F-070](#f-070)).
17. **The backlog is growing (tentative).** In the week to 2026-11-06, 744 advisories were published into limbo and 68 were reviewed out, about 11 in for each 1 out; over 14 days, 1,475 in and 172 out ([F-092](#f-092)). Earlier single days (10-29, 10-30) showed inflow of 93 and 71 against outflow of 88 and 20 ([F-067](#f-067), [F-070](#f-070)). Advisories that did get reviewed had waited a median 11 days. A rate, not yet a trend: the site shows the weekly numbers with their date.
18. **A published CVE doesn't mean scanners can see it.** One critical advisory's GitHub-CNA CVE took 85 days to publish; 134 days after publication (2026-10-28) the advisory was still in no package database, because it has no ecosystem ([F-066](#f-066)).
19. **Names, more than ranges, decide whether the feed matches.** OSV-Scanner's local matching compares names exactly. 359 names were unmatchable until cleaned; 406 are still malformed and flagged. 95.8% of ranges convert, and a range is left open only when the advisory says there's no fix. An entry with no usable range never matches, so it can miss but never false-alarm ([F-069](#f-069)).
20. **Running it cheaply.** A stable PAT plus conditional requests make an unchanged repo free to re-poll ([F-058](#f-058), [F-071](#f-071)). The scheduled run fires about 6 h 50 min late, consistently ([F-065](#f-065), [F-067](#f-067)). The tracker needs canonical repo identities and checkpoints ([F-060](#f-060)) and works on `GITHUB_TOKEN` alone, only slowly ([F-062](#f-062)).
21. **Phase 3 ended without outreach (2026-11-05).** The released OSV-Scanner can already scan against the feed ([F-074](#f-074)); letting it download the feed itself needs one configurable value that SCALIBR already has ([F-073](#f-073), [F-076](#f-076)). blindspot and RogoLabs both lack what we'd offer ([F-072](#f-072), [F-075](#f-075)). Nothing was posted: the feed, a data-quality page (1,294 advisories with a field scanners can't use) and a repo list are published for anyone who looks, and the drafts are in `docs/outreach/` ([F-077](#f-077)).

**Phase 4: the watcher**

22. **Real projects ship affected versions that scanners report clean, today.** On the October report's 15 projects (at their October commits, against the 2026-11-05 feed): **269 package-versions certainly affected** in 13 of 14 readable projects, GitLab 125. The watcher finds all 132 the research pipeline found that are still in limbo (recall 100%). Of 657 distinct findings checked live, 630 are in the advisory's current range, 12 possible and 0 contradicted ([F-085](#f-085), [F-082](#f-082)).
23. **OSV-Scanner works as an inventory, but it needs checking.** Without saying so, it reads `flask>=2` as version 2, drops git and path requirements, labels git crates as crates.io, skips npm entries with no `resolved`, and applies an enclosing repo's `.gitignore`. The watcher reports each such dependency as unchecked, with the reason ([F-078](#f-078), [F-081](#f-081), [F-085](#f-085)).
24. **Matching needs rules a scanner doesn't.**
    - Names are compared the way scanners compare them.
    - Repository matches only for unusable names; in a monorepo the name must mention the package.
    - Rust `A .. B` is certain when both readings agree.
    - An exact version beside a bound is an alternative.
    - Go `/vN` is a different module.
    - Ranges that can't be evaluated, or contradict their own fix, give *possible* findings, never passes ([F-082](#f-082), [F-085](#f-085)).
25. **Most dependencies need no GitHub calls.** The tracker already watches nearly every upstream: Gitea needed 0 polls, Open WebUI 9. GitLab's Ruby upstreams needed 356, which an unauthenticated CI job (60 an hour) can't do, so a read-only GitHub token matters ([F-082](#f-082), [F-085](#f-085)). deps.dev lacks source repos for most gems, so rubygems.org's metadata comes first ([F-085](#f-085)).
26. **CI and issues work end to end.**
    - The GitLab component and the Action fail, report and summarize correctly in a container ([F-084](#f-084)).
    - The issue lifecycle (open, idempotent, close on upgrade, reopen, refuse public repos) works against a real Gitea ([F-083](#f-083)).
    - GitLab issues are confidential; Gitea's can't be, so public repos get none by default ([F-079](#f-079), [F-080](#f-080)).
27. **It works in real CI, on real hosts (2026-11-06/07).**
    - GitLab, every tier: Code Quality shows findings on the lockfile line and "51 new findings" in a merge request; a JUnit test summary counts what fails the build; `expose_as` links the report folder; confidential issues work with any token sent as `Bearer` ([F-086](#f-086), [F-087](#f-087), [F-088](#f-088), [F-094](#f-094)).
    - GitHub: SARIF becomes code scanning alerts inline on the changed line (public repos, or with GitHub Code Security; needs `actions: read`) ([F-089](#f-089)).
    - Limits found only by running it: a component description over 256 characters breaks every including pipeline ([F-095](#f-095)); GitHub keeps 10 annotations per level per step and drops the rest silently, so annotations are one per package ([F-096](#f-096)); click strips colour off pipes ([F-097](#f-097)).
28. **Without Limbowatch, nothing reports these.** On the demo app, GitHub's Dependabot alerts and OSV-Scanner reported 0 of the 16 advisories Limbowatch found; all 16 were rechecked against primary sources and are real, fixed and unreviewed, 1.6 to 23.5 days in limbo ([F-090](#f-090), [F-091](#f-091)).
29. **The outputs are standard.** SARIF 2.1.0 and CycloneDX 1.6 validate against the official schemas ([F-093](#f-093)).
30. **Released as an alpha, 0.1.0a1 (2026-11-07).** PyPI with PEP 740 attestations; GitHub pre-release; the CI/CD Catalog accepts the pre-release `0.1.0-alpha.1` ([F-097](#f-097)).
31. **Both demos stay as live regression tests:** `limbowatch/demo-app` on GitHub (public, PR #1) and GitLab (private, MR !1) run the released action and component ([F-088](#f-088), [F-097](#f-097)).

**Coverage (measured 2026-11-07)**

32. **The tracker sees roughly 1 in 4 of all repository advisories.** About 1,100 to 1,250 newly published a week, in all ecosystems, against GitHub's "more than 5,000/week". 18,678 watched repos; most advisories come from repos found through earlier advisory activity (GitHub-assigned CVEs, reviewed-advisory origins), not from the dependency seeds. Coverage of what real projects depend on is much higher ([F-098](#f-098), [F-085](#f-085)). Raising it is Phase 5's first step.

## Open questions

Open:

- Q3. What share of other-CNA CVEs affecting npm/PyPI/Go packages get package-level coverage in OSV through ecosystem DBs (Go vulndb, PyPA, RustSec)? The tracker stores the CVEs ([F-067](#f-067)); the matching isn't built.
- Q4. How far behind GHSA are the scanner DBs (Trivy DB, Grype DB, OSV-Scanner)? GitLab Advisory DB lag can't be measured because its terms forbid querying it.
- Q5. Is "Not Scheduled" ever an NVD API `vulnStatus` value, or always `Deferred`? ([F-005](#f-005))
- Q6. Does ecosyste.ms's CC BY-SA 4.0 data license constrain Limbowatch? *Partly answered 2026-10-20: share-alike applies to redistributed derived data; use at runtime with a local cache only, with attribution. Revisit before 1.0* ([F-021](#f-021)). *Decided 2026-11-07: the watchlist built from its rankings is published CC BY-SA 4.0 with attribution; advisory data stays CC BY 4.0 (PHASE0_PLAN §13.12).*
- Q7. How do we reliably detect packaging/recipe repos (conan-center-index, homebrew-core, distro packaging) so they aren't treated as upstream? ([F-021](#f-021)) Not addressed in Phase 2: the tracker's seeds come from the research mapper, which has no such filter.
- Q8. How do we detect that a limbo advisory was reviewed under a different GHSA ID when no CVE is shared? The tracker proves duplicates by shared CVE only ([F-048](#f-048)).
- Q10. Under what terms may repository advisory content be redistributed? *Partly answered 2026-10-26: GitHub's terms are silent on repository advisories in limbo; the feed carries factual metadata only* ([F-059](#f-059)). Ask GitHub during outreach.
- Q12. Is review throughput keeping up with inflow? So far no: 744 in against 68 out in the week to 2026-11-06 ([F-092](#f-092)). Still open: whether that holds over a month, split by ecosystem and severity ([F-067](#f-067), [F-070](#f-070)).
- Q13. Do OSV-Scanner's other matching paths (the osv.dev API) normalize package names beyond PyPI? ([F-069](#f-069))
- Q14. Do the feed's well-formed names exist in their registries? A registry check would catch wrong-but-valid names ([F-069](#f-069)).
- Q15. Can per-branch ranges like `< 1.2.5, < 2.0.3` be converted without guessing where each branch starts, e.g. from the registry's version list? ([F-069](#f-069))
- Q16. Are pending advisories published before 2026 (258 on 2026-10-28) ever reviewed, or did GitHub never backfill them? ([F-064](#f-064))
- Q23. Do Packagist's newest-version source URLs ever point at a different repo than the installed version's? ([F-103](#f-103))
- Q17. How many Go modules on vanity paths (k8s.io, golang.org/x, go.opentelemetry.io) can be mapped to a GitHub repo without deps.dev? 320 Kubernetes dependencies stay checked by name only ([F-085](#f-085)). blindspot keeps a verified list (`docs/go-vanity-coverage.md`, [F-072](#f-072)).
- Q18. Should the tracker's seeds include the upstreams of popular GitLab-hosted projects' Ruby dependencies, so the watcher doesn't need to poll them? ([F-085](#f-085); Phase 5.)
- Q22. Does GitHub's "more than 5,000 repository advisories a week" count the same thing as the tracker (published, any ecosystem)? It sets the coverage estimate ([F-035](#f-035), [F-098](#f-098)).

Answered:

- ~~Q21. Are advisories published close to a release of their package?~~ **Yes: 71% within a day, 79% within 3 days; the fix release usually comes first ([F-100](#f-100)).**
- ~~Q20. How many source repos do the top packages of each ecosystem map to, and how many are already watched?~~ **About 45,000 unwatched repos in the top 10,000 of eight ecosystems; NuGet, Packagist, Maven and RubyGems are barely covered; a sample holds 30 advisories in limbo ([F-099](#f-099)).**
- ~~Q12 (partly). Is review throughput keeping up with inflow?~~ **Not in the weeks measured: 744 in against 68 out in the week to 2026-11-06 ([F-092](#f-092)).** Stays open above for the monthly, per-ecosystem view.
- ~~Q19. Do confidential issues and the Code Quality report behave on a real GitLab instance as the docs say?~~ **Yes, on gitlab.com 2026-11-06: Code Quality ([F-086](#f-086)), confidential issues ([F-087](#f-087)), the merge request widget ([F-088](#f-088)).**
- ~~Q1. While a CVE is reserved but not yet published, does the repo advisory API already expose `cve_id`?~~ **Yes. Detectable via `cveawg /api/cve-id/{id}` ([F-029](#f-029)).**
- ~~Q2. Was the 55-day median a backlog being cleared on Oct 15–16, or the normal state?~~ **A backlog batch; the median was 23–27 days ([F-042](#f-042), [F-055](#f-055)).** Kept under watch as Q12.
- ~~Q9. Build separately, contribute upstream, or build only the layers blindspot lacks?~~ **Plan rev 5: report → tracker + limbo feed → upstream contributions → watcher ([F-036](#f-036), [F-037](#f-037)).**
- ~~Q11. Do different `GITHUB_TOKEN`s share ETags for the same URL?~~ **Moot 2026-10-31: the daily job uses one stable PAT, and with it 1,330 of 1,410 next-day polls were free 304s ([F-071](#f-071)).**

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

### F-056
- **Date:** 2026-10-25 · **Status:** confirmed (observed)
- **Question:** Three days after the 2026-10-22 snapshots, what happened to the advisories in limbo, especially their CVEs?
- **Method:** `s9_followup.py`, live re-check (no cache) of all 415 unique advisories in limbo on 2026-10-22 (268 GitHub-hosted set, 217 off-GitHub set, 70 overlap) at 2026-10-25 09:45 UTC:
  - repo advisory (state, cited CVE), global DB, OSV;
  - CVE Services `cve` / `cve-id` for cited CVEs;
  - reverse lookup in CVE List release `cve_2026-10-25_0900Z` (413,919 records).
- **Result:**
  - **34 (8%) reviewed, all on 2026-10-23** (single batch). 381 still in limbo.
  - Of the 381:
    - 249 have no CVE anywhere (14 critical, 104 high);
    - 27 reserved (RBP);
    - 63 published and cited;
    - 42 published by another CNA but not cited.
  - Changes in 3 days:
    - 16 advisories now cite a CVE (GitHub CNA; 14 published, 2 reserved).
    - **24 gained an uncited CVE**: 26 CVEs, from VulnCheck 21, Red Hat 1, and **GitHub 4**. GitHub's CNA published a CVE referencing the advisory before the advisory page showed it.
    - **0 of 27 reserved CVEs were published.**
- **Implication:**
  - The "no CVE anywhere" state is common and sticky.
  - Review lands in batches.
  - The tracker must re-check daily and record transitions; a single snapshot understates churn.
  - Report readers need the CVE states explained in plain language. Added to the report as "What the CVE states mean".

### F-057
- **Date:** 2026-10-26 · **Status:** confirmed (observed)
- **Question:** How large is tracker watchlist source 1 (repos where reviewed advisories originated)?
- **Method:** Full pagination of `GET /advisories?type=reviewed&per_page=100&sort=published&direction=desc` (373 pages, about 6.5 minutes).
- **Result:**
  - 37,219 reviewed advisories; 16,873 (45%) have a `repository_advisory_url`; **3,587 distinct origin repos**; 685 repos have ≥ 5.
  - Combined with the ~6,000 dependency upstreams from the Phase 1 research, the watchlist is roughly 8–10k repos.
  - The full reviewed list is the cheapest way to know every reviewed GHSA (no per-advisory calls).
- **Implication:** A daily tracker is feasible. Bootstrap the reviewed set once from full pagination, then page incrementally by `published` (= review time, F-009).

### F-058
- **Date:** 2026-10-26 · **Status:** confirmed (docs + observed); per-run behaviour of `GITHUB_TOKEN` ETags untested
- **Question:** Can a daily GitHub Actions job poll ~9k repos within rate limits?
- **Result:**
  - Docs: `GITHUB_TOKEN` gets **1,000 requests/hour per repository**; user tokens (PATs) 5,000/hour.
  - Secondary limits: 100 concurrent requests, 900 points/minute (GET = 1 point).
  - A 304 from a conditional request "does not count against your primary rate limit" if the request was authorized. Observed: three 304s left `x-ratelimit-remaining` unchanged.
  - **ETags vary by token:** the repo-advisories response sends `Vary: Authorization`. The ETag differs between anonymous and authenticated requests, and an anonymous ETag sent with a token returned 200, not 304.
  - Untested: whether two different tokens of the same identity share ETags. Actions mints a new `GITHUB_TOKEN` every run, so per-run ETags may never match.
- **Implication:**
  - Don't rely on cheap daily polling of all repos with `GITHUB_TOKEN`. Poll in priority order within a request budget, resume across runs, and report coverage ("polled in the last 24 h").
  - Detect reviews from the global reviewed list and OSV, not repo polling.
  - Store ETags with a fingerprint of the token that obtained them, and ignore them for other tokens.
  - Recommend a stable fine-grained PAT secret (public read-only); `GITHUB_TOKEN` is the fallback.
- **Sources:** [Rate limits for the REST API](https://docs.github.com/en/rest/using-the-rest-api/rate-limits-for-the-rest-api), [Best practices for using the REST API](https://docs.github.com/en/rest/using-the-rest-api/best-practices-for-using-the-rest-api)

### F-059
- **Date:** 2026-10-26 · **Status:** tentative (docs silent on repository advisories). Partly answers Q10.
- **Question:** What may the limbo feed redistribute from repository advisories?
- **Result:**
  - GitHub's terms: the Advisory Database "is licensed under the Creative Commons Attribution 4.0 license". Contributions to it are released under CC0. Attribution "may be fulfilled by linking to the GitHub Advisory Database at https://github.com/advisories".
  - The terms don't distinguish reviewed, unreviewed or repository advisories. They don't say whether a repository advisory not yet in the database is covered.
  - Repository advisory objects also carry personal data (F-047).
- **Implication:**
  - The feed and site carry factual metadata only: IDs, repo, package, ecosystem, version range, fixed version, severity, CVSS vector, CWE IDs, dates and links. Titles, descriptions, author, publisher and credits are excluded.
  - Attribute with links to github.com/advisories and to each advisory.
  - Revisit if GitHub clarifies, or ask GitHub during outreach.
- **Sources:** [GitHub Terms for Additional Products and Features](https://docs.github.com/en/site-policy/github-terms/github-terms-for-additional-products-and-features), [github/advisory-database](https://github.com/github/advisory-database)

### F-060
- **Date:** 2026-10-26 · **Status:** confirmed (observed)
- **Question:** What broke when the tracker ran against the real watchlist?
- **Result:**
  - **Renamed / transferred repos.** `cryspen/libcrux` now redirects to `celabshq/libcrux`; both names were on the watchlist (seed + reviewed origin). The API follows the redirect, so the same advisory arrived twice and the run crashed on the duplicate key.
    - Fix: the canonical repo is taken from the advisory's `html_url`, and advisories are keyed by GHSA ID across repos.
  - **No state was saved from the first, interrupted run,** because state was only written at the end.
    - Fix: checkpoint after each step and every 500 polls, and always export on exit.
  - **The delta log alone misses older uncited CVEs.** After the first run, only 1 limbo advisory had a CVE from another CNA, vs 23 in the research snapshot (F-050).
    - Fix: one-time bootstrap from a bulk CVE List release (`--cve-list`); the daily delta log keeps it current. The delta log covers about 4 weeks (2,267 entries), so a longer outage needs another bootstrap.
- **Implication:** Watchlists built from several sources need canonical identities. Any long-running job must checkpoint.

### F-062
- **Date:** 2026-10-28 · **Status:** confirmed (observed)
- **Question:** Does the daily tracker work end to end in GitHub Actions on the private repo, with only `GITHUB_TOKEN`?
- **Method:** First dispatched run of `.github/workflows/tracker.yml` (run 40621299260), budget 900, no PAT, no NVD key.
- **Result:**
  - All steps succeeded in 6.5 minutes. The CVE List bootstrap imported 28,580 CVE records that reference a GHSA. The reviewed sync covered 37,320 advisories (320 new since F-057).
  - Polling: **533 of 8,850 watchlist repos** before the budget ran out (907 GitHub requests counted), 274 advisories found.
  - The report (25 in limbo, 2 newly published) was committed to `tracker-data` and posted to issue #1.
  - Pages deploy skipped (private repo).
- **Caveats:** With `GITHUB_TOKEN` alone, one full pass over the watchlist takes about 16 daily runs. Never-polled repos are taken in alphabetical order, so early reports skew toward repos starting with "a".
- **Implication:** Coverage, not correctness, is the constraint. A PAT (3,500 per run) gets a full pass in about 3 days, after which unchanged repos cost nothing if ETags carry over (Q11). The report states coverage, so partial numbers aren't read as totals.

### F-063
- **Date:** 2026-10-28 · **Status:** confirmed (observed)
- **Question:** How many upstream repos do the dependencies of the 100 most popular GitHub projects add to the tracker's watchlist?
- **Method:**
  - Selection (`tracker/seeds/make_seed.py select`): GitHub search `stars:>10000 archived:false fork:false`, sorted by stars. A repo qualifies if its recursive git tree has a supported lockfile outside test, fixture, vendor, example and docs directories. 171 repos were checked; 71 had no such lockfile.
  - Mapping: research pipeline s1 (OSV-Scanner v2.7.0 `--all-packages`) and s2 (deps.dev, Go module paths), snapshot `2026-10-28-top100`.
- **Result:**
  - All 100 projects were read. Two lockfiles failed to parse and were recorded as unreadable: `microsoft/Web-Dev-For-Beginners` (`7-bank-project/api/package-lock.json`) and `microsoft/ML-For-Beginners` (`package-lock.json`).
  - 51,374 unique package-versions: 48,301 mapped to a GitHub repo; 1,544 not found on deps.dev; 1,432 with no repo; 88 hosted off GitHub; 9 with no mapper.
  - **12,406 unique upstream repos**, of which 7,819 aren't in `popular-upstreams.txt`. The two seeds together hold 13,432 repos.
- **Caveats:**
  - A malformed lockfile used to abort the whole OSV-Scanner run (exit 127). s1 now drops it, records it and retries.
  - Selection by stars includes tutorial and list repos whose lockfiles only build their websites.
  - 34,985 of the mappings rest on unverified deps.dev metadata, not attestations.
- **Implication:** The watchlist grows to about 16,700 repos with the reviewed-origin repos. With `GITHUB_TOKEN` alone, a full pass takes about 18 daily runs, so a PAT, or a one-off local pass, is needed for full coverage.

### F-064
- **Date:** 2026-10-28 · **Status:** confirmed (observed)
- **Question:** How many published advisories are in limbo across the whole watchlist, and what does a full pass cost?
- **Method:**
  - `limbowatch track` run locally with the maintainer's `gh` token over the 16,431-repo watchlist: reviewed-origin repos, `popular-upstreams.txt` and `top100-upstreams.txt`.
  - Four runs, one per hourly rate-limit window, 07:18–09:50 UTC. State pushed to `tracker-data` (commit 0f77ae3). Metrics from `limbowatch.publish.metrics` on that state.
  - Spot check: 15 random feed records against `api.osv.dev/v1/vulns/{id}`.
- **Result:**
  - **Coverage:** all 16,431 repos polled with 0 failures. 3,796 have published advisories; 172 answered 404. About 16,000 counted GitHub requests in total; one 5,000/hour window covered about 4,600 polls.
  - **Advisories:** 9,738 not yet reviewed when first seen: 9,540 in limbo, 196 duplicates of a reviewed advisory, 2 reviewed since.
  - **Pending review (ecosystems GitHub reviews): 6,124.**
    - Severity: 533 critical, 2,477 high, 2,531 medium, 583 low.
    - CVE state: 3,355 with no CVE anywhere; 1,304 citing a published CVE; 982 with an uncited CVE from another CNA; 469 citing a reserved CVE (460 for more than 72 hours); 14 other.
    - Wait so far: median 47.4 days. 1,272 have waited more than 3 months.
    - By year published: 5,866 from 2026, and 258 from 2019–2025.
    - By ecosystem: Go 1,416, npm 1,345, PyPI 1,097, Packagist 955, Maven 589, crates.io 418, others 386.
  - **Likely permanent (ecosystems GitHub doesn't review): 3,416**, median age 167 days.
  - **Spot check:** 15 of 15 sampled records absent from OSV. The old ones (Envoy, Bottlerocket, 2020–2023) are in the likely-permanent bucket.
- **Caveats:**
  - Every number is a floor: only watchlisted repos are seen.
  - The 258 pending advisories from before 2026 look like advisories GitHub never backfilled, not slow reviews. The site keeps them out of the "longest waiting" list.
  - Today's 06:17 UTC scheduled tracker run hadn't fired at the time of writing; it fired late (see [F-065](#f-065)).
- **Implication:**
  - At steady state the adaptive schedule (`limbowatch/schedule.py`) works out to about 3,960 checks a day: 1,338 repos daily, 2,458 every 3 days, 12,635 weekly. That's slightly over the 3,500-request run budget, so tiers stretch a little until the ETags held by the PAT make unchanged repos free.
  - The pending count is about 15× the October report's 415, because the watchlist is about 3× larger and includes every reviewed-origin repo.

### F-065
- **Date:** 2026-10-28 · **Status:** confirmed (observed; one run)
- **Question:** Does the daily scheduled tracker run fire on time, and what does it cost right after a full pass?
- **Method:** `gh run list -R limbowatch/limbowatch` and the Track step's JSON summary of run 40693721039 (event `schedule`, cron `17 6 * * *`).
- **Result:**
  - The run was created at **13:08:23 UTC, 6 h 51 min after the 06:17 cron time**. It succeeded and triggered the site rebuild.
  - Track: 171 s; 90 reviewed advisories synced, 380 CVE records read, watchlist 16,433.
  - **2 repos polled, 3 counted GitHub requests**: every repo had been checked during the full pass 4–6 hours earlier, so nothing was due yet (F-064).
  - 9,742 OSV lookups (every advisory not yet reviewed is reassessed each run), 40 NVD lookups (the cap), 0 failures; 4 new advisories, 45 changed.
- **Caveats:** One observation. GitHub documents that scheduled workflows can be delayed during high load; how late they usually run here isn't known yet.
- **Implication:**
  - F-064's "never fired" was premature: the run fired, just late. A run later than 06:17 is still inside the schedule's 2-hour slack only if consecutive runs drift by a similar amount; a large swing (e.g. 13:08 one day, 06:20 the next) leaves daily-tier repos about 15 hours short of due, so they wait until the following run.
  - The first real day of scheduled checks under the PAT is the 2026-10-29 run.

### F-066
- **Date:** 2026-10-28 · **Status:** confirmed (observed; one case, plus a count over the tracker state)
- **Question:** How did one known stuck advisory, GHSA-hqfg-c8wf-w2g8 (CVE-2026-54694), move through each database, and does the tracker see it?
- **Method:**
  - `cveawg.mitre.org/api/cve/CVE-2026-54694`; `gh api /repos/NationalSecurityAgency/skills-service/security-advisories/GHSA-hqfg-c8wf-w2g8`; `gh api /advisories/<GHSA>` for all 5 of the repo's published advisories; `api.osv.dev/v1/vulns/` for the GHSA and the CVE; NVD `cves/2.0?cveId=`.
  - GitHub's replies to the reporter's three support follow-ups (2026-06-30, 08-11, 09-09), shared by the reporter.
  - Watchlist gap: `tracker-data` `state/cves.jsonl` vs `state/repos.jsonl` at commit of the 2026-10-28 13:11 UTC run.
- **Result:**
  - **Timeline:** CVE reserved 2026-06-15 by GitHub_M; repo advisory published 2026-06-16 (critical); CVE record published **2026-09-09, 85 days later**, after three follow-ups. GitHub's 06-30 reply cited an industry-wide surge in CVE requests, first-in-first-out processing and "approximately three weeks" turnaround, with no expediting. On 08-11 it was still publishing CVEs for May 2026 advisories.
  - **Today (134 days after publication):** the advisory is absent from the global Advisory Database (404) and from OSV by GHSA ID (404). OSV has `CVE-2026-54694` (aliasing the GHSA) with GIT ranges only and no package. NVD status: Deferred. All 5 of the repo's published advisories are 404 in the global database.
  - **Why it's never reviewed:** the advisory's packages have no ecosystem (a release `.jar` and a Docker Hub image), so it falls in the "likely permanent" bucket; Dependabot can't alert on it regardless of review.
  - **The tracker missed it:** `nationalsecurityagency/skills-service` isn't on the watchlist. The CVE List bootstrap (`tracker.import_cve_list`) stores CVEs but, unlike the CVE delta sync, doesn't add GitHub_M CVEs' repos to the watchlist. Of 21,735 stored GitHub_M CVEs naming 5,117 repos, **2,338 repos are missing from the 16,433-repo watchlist**.
- **Caveats:** One case for the timeline. The 2,338 repos are candidates; most of their advisories may be reviewed or out of scope.
- **Implication:**
  - Supports F-042/F-064: CVE publication by GitHub_M can lag the repo advisory by months, and a published CVE doesn't mean scanners can match it (no package in OSV's CVE record).
  - Fix: add GitHub_M CVEs' repos to the watchlist during the bulk import too (and once from the stored CVEs). At about 2,300 repos, mostly weekly tier, that's roughly 330 extra checks a day.

### F-067
- **Date:** 2026-10-30 · **Status:** tentative (three scheduled runs, two full days of review observations)
- **Question:** What do the first days of daily tracking show about growth, review throughput and the report's labels?
- **Method:** The daily reports `reports/2026-10-2{8,9}.md` and `2026-10-30.md` on `tracker-data`, plus the state at commit 699cf99 (2026-10-30 13:12 UTC) loaded with `limbowatch.publish.items`: "first seen" events split by advisory age (≤ 3 days after publication = fresh) and by whether the repo joined the watchlist that day; `-> reviewed` events; the CNA of each `new CVE from another CNA` event's CVE from `state/cves.jsonl`. `gh run list` for run times.
- **Result:**
  - **Pending limbo rose 6,128 → 6,272 → 6,655, mostly from watching more repos.** Of the +144 on 10-29, 140 were older advisories in repos that joined that day; of the +383 on 10-30, 328 were. Every one of those repos came from the CVE delta sync (`github-cna-cve`): a new GitHub_M CVE names the repo, and polling it turns up its whole backlog (labredescefetrj/wegia 212, e107inc/e107 190, cacti/cacti 67).
  - **Fresh inflow** (published ≤ 3 days before first seen, reviewable ecosystems): 93 on 10-29 and 71 on 10-30. **Outflow:** 88 reviewed on 10-29, 20 on 10-30, none withdrawn or found to duplicate.
  - **Observed review lag** (108 advisories seen in limbo, then reviewed): median 11.2 days, p25 8.6, p75 30.3, max 146; none under 2 days. Of the 1,102 tracked advisories published 10-20 to 10-29 in reviewable ecosystems, 32 were reviewed by 10-30. That ratio flatters the backlog's side: advisories already reviewed when first seen are never tracked, so fast reviews are missing from it.
  - **Age of pending limbo on 10-30:** 607 under 7 days, 1,700 at 7–30, 2,804 at 30–90, 1,153 at 90–365, 391 over a year; 6,249 of 6,655 were published in 2026. The median grew exactly a day per day (47.5 → 48.5 → 49.5).
  - **"Another CNA" mislabel:** of 77 `new CVE from another CNA` events, 56 were VulnCheck CVEs but **18 were GitHub_M's own** (e.g. labstack/echo's CVE-2026-1186xx); each of those advisories was reviewed the same day. None remain in the headline bucket: of the 1,003 pending advisories with an uncited CVE, 970 are VulnCheck, the rest small CNAs, none GitHub_M.
  - **Cron:** runs started 13:08, 13:14 and 13:06 UTC on the `17 6 * * *` schedule. The delay held steady at about 6 h 50 min, so the day-to-day swing F-065 warned about hasn't happened yet.
  - Every run finished under budget (1,394 and 1,410 repos polled; `stopped_early: null`).
- **Caveats:** Two days of review data, both weekdays; GitHub reviews in batches, so a daily figure means little on its own. "Fresh" uses first-seen time, so an advisory in a repo polled every 3 to 7 days can be counted as older.
- **Implication:**
  - The report's headline delta mixes watchlist growth with real change; it should split "newly published − left limbo" from "found in newly watched repos". Until the F-066 backfill runs, expect several hundred backlog finds a day.
  - At this sample, fresh inflow roughly matches review outflow on a good day and exceeds it on a slow one; the backlog isn't shrinking (the median climbs a day per day). It takes a few weeks of data to say more.
  - Label `new CVE from another CNA` only when the CVE's CNA isn't GitHub_M; otherwise say "CVE published by GitHub, not yet cited".
  - The report's "Longest waiting" table repeats the same 2019 advisories every day; it would say more limited to the last 90 days.

### F-068
- **Date:** 2026-10-31 · **Status:** confirmed (count over the tracker state)
- **Question:** How big is F-066's watchlist gap now that the CVE delta sync has been adding GitHub-CNA repos for two days?
- **Method:** `tracker-data` state at 699cf99 (2026-10-30 13:12 UTC): repos in `repo_refs` of every `state/cves.jsonl` record with `cna == "GitHub_M"`, excluding `advisories/…` (github.com/advisories links), minus `state/repos.jsonl`.
- **Result:** 21,893 GitHub_M CVEs name 4,958 repos; **2,113 aren't on the 16,499-repo watchlist** (F-066 counted 2,338 two days earlier, with a slightly different repo count). No `advisories/…` pseudo-repos were on the watchlist.
- **Caveats:** As F-066: candidates; many will have only reviewed advisories.
- **Implication:** The delta sync closes the gap only as repos get new CVEs, about 100 repos a day, and each brings its backlog into the daily "found for the first time" count. The tracker now adds them all on its next run (`Tracker.watch_cna_repos`). That first run polls about 2,100 new repos ahead of the regular ~1,400, close to the 3,500-request budget, so some daily-tier repos may wait one extra day.

### F-069
- **Date:** 2026-10-31 · **Status:** confirmed (OSV-SCALIBR source, Composer and OSV docs, count over the tracker state)
- **Question:** How clean are the package names and ranges the limbo feed publishes, and which defects stop scanners from matching?
- **Method:**
  - Matching rules: OSV-SCALIBR `enricher/vulnmatch/osvlocal/internal/vulns/vulnerability.go` (`IsAffected`), `osvlocal/zip.go` and `enricher/vulnmatch/osvutil/osvutil.go` (`name`), at commit b0c689b4e6 (2026-10-12), read with `gh api repos/google/osv-scalibr/contents/...`. Naming rules: the OSV schema's ecosystem table (`ossf/osv-schema` `docs/schema.md`, main) and Composer's `doc/04-schema.md` (`name`).
  - Data: every package of the 10,786 advisories in limbo (pending and likely permanent) in the state at 699cf99; the feed built from it by the code before and after the fix, compared entry by entry (9,508 entries in OSV ecosystems with a name).
- **Result:**
  - **Scanners match names exactly.** `IsAffected` requires `affected.package.name == name`; the loader doesn't normalize the record's side. The scanner's side is normalized for PyPI only (lowercase, runs of `-_.` to `-`, i.e. PEP 503, which the OSV schema also requires for PyPI). Composer requires lowercase names matching `^[a-z0-9]([_.-]?[a-z0-9]+)*/[a-z0-9](([_.]|-{1,2})?[a-z0-9]+)*$`.
  - So before the fix, these feed entries **could never match**:
    - 89 PyPI names not in PEP 503 form (e.g. `GitPython`);
    - 168 Packagist names with capitals or stray spaces (e.g. `givanz/Vvveb`, ` baserproject/basercms `);
    - 74 Go module paths wrapped in a URL, a markdown link or spaces (`https://github.com/siyuan-note/siyuan`, ` github.com/rancher/rancher`);
    - 28 others with stray spaces (Maven 17, crates.io 4, npm 4, NuGet, Actions, RubyGems 1 each).
    
    All 359 are now cleaned.
  - **406 names remain invalid** and are flagged (`name_valid: false`), not guessed: labels and file paths (`Hazelcast Management Center`, `application/modules/.../Invoices.php`), Maven group IDs with no artifact (`io.dataease`), Composer names with no vendor (`WeGIA`), Go repos with no host (`maximhq/bifrost`), Swift names that aren't URLs (`Sparkle`).
  - **An entry with no `ranges` and no `versions` is skipped** (`continue` in `IsAffected`), so an unconverted range causes misses, never false alarms.
  - **Open-ended ranges marked the fix as affected:** 103 entries had an `introduced` event and nothing else. In 45 of them the fixed field named a version that didn't close the range: a fix below the range's start, per-branch fixes that don't line up, or text like `< 0.2.2`. These are no longer converted, a reversal of the earlier rule that left such ranges open. The 58 open ranges left (90 over all ecosystems) all have a fixed field meaning no fix (`None`, `N/A`, `tbd`, `Will not fix`, empty).
  - **Newly converted, 55 entries:** `all`/`All`, `&` and `&&`, `A to B` and `A through B`, and plain version lists (`1.11.12, 1.11.14, …`, now OSV `versions`). Still left as text: Rust-style `A .. B` (44; `..` excludes its end in Rust, maintainers seem to mean it inclusively), per-branch upper bounds like `< 1.2.5, < 2.0.3` (about 80; the lower bound of each branch would be a guess), strict lower bounds `> X`, and words.
  - Range conversion overall: 9,111 of 9,508 entries (95.8%), 9,113 before.
  - **Fixed-version field shapes:** 7,684 one version, 866 `>= X`, 368 version lists, 471 empty, 60 words or hashes, 59 with other operators. Display and the site's upgrade advice now use the parsed versions (`>= 0.5.16, >= 0.6.3` shows as `0.5.16, 0.6.3`); unreadable text is shown as entered, not as "Upgrade to < 2.5.1 or later".
  - **Records by `quality`**, over the 6,583 with a named package in an OSV ecosystem: 5,690 with names ok and ranges converted, 164 with names cleaned and ranges converted; 398 with an invalid name; 344 with ranges left as text and 29 partly converted (these overlap).
- **Caveats:**
  - The name rules check form, not existence: a well-formed name can still be the wrong package. Checking names against each registry is a separate step.
  - npm, crates.io, NuGet, Maven and Go names keep their case; whether OSV-Scanner's other paths (e.g. the API) normalize more wasn't checked.
- **Implication:**
  - Name hygiene, not range parsing, was the feed's larger silent-miss problem.
  - The 406 invalid names and the ranges left as text are where a human (or the maintainer) is needed. They are candidates for a maintainer-facing "fix your advisory" note in the upstream phase.

### F-070
- **Date:** 2026-10-31 · **Status:** confirmed (count over the tracker state)
- **Question:** Did the first run with `Tracker.watch_cna_repos` close F-068's gap, and what did it bring in?
- **Method:** `tracker-data` state at 7fca6ac (run 10, 2026-10-31 12:44–12:52 UTC): `state/runs.jsonl`, `state/repos.jsonl` (`first_seen` on 2026-10-31), the F-068 count over `state/cves.jsonl`, and `reports/2026-10-31.md`.
- **Result:**
  - The watchlist went from 16,499 to 18,656 repos (2,157 added). **All 5,007 repos named by the 22,071 GitHub_M CVEs are now on it; 0 are missing.** Every repo on the watchlist has been polled at least once.
  - The run polled 3,484 repos and stopped at the budget (3,507 counted GitHub requests). No HTTP failures.
  - 1,675 of the 2,157 new repos have repository advisories, 13,307 in all.
  - Pending limbo rose from 6,655 to 7,988: 33 newly published, 1,355 older ones seen for the first time (1,294 in the new repos), 55 left limbo. Likely permanent rose from 4,131 to 13,852 (+9,721). Of the 11,195 unreviewed advisories first observed this run, 10,848 are in the new repos and 347 in repos already watched, so at least 9,374 of the +9,721 (96%) came from the new repos.
- **Caveats:** The report's likely-permanent delta has no breakdown, so the 96% is a lower bound from counts (latest facts per advisory in `state/facts.jsonl`), not a per-advisory classification. Because the run stopped at the budget, some daily-tier repos waited one extra day.
- **Implication:** The watchlist gap from bulk-imported GitHub_M CVEs (F-066, F-068) is closed. The delta sync keeps it closed. Most of what the new repos brought is likely permanent: these are mostly applications, not packages in ecosystems GitHub reviews. From the next run on, the daily delta should again reflect real inflow. Use 2026-11-01 onward, not 2026-10-31, as the baseline for throughput numbers.

### F-071
- **Date:** 2026-10-31 · **Status:** confirmed (count over the tracker state; four PAT runs)
- **Question:** Do conditional requests make repeat polls free under the tracker's PAT, and why did run 10 get no 304s?
- **Method:** `state/runs.jsonl` (runs 1–10) and `state/repos.jsonl` at 7fca6ac, compared with 699cf99: `etag_token` (token fingerprint), `etag`, `poll_status` and `advisory_count` of every repo polled on 2026-10-31.
- **Result:**
  - **Same token, next day: almost all free.** Run 9 (2026-10-30) polled 1,410 repos; 1,330 answered 304 and only 92 GitHub requests counted. Those repos had ETags from run 8 under the same PAT.
  - **Run 10 (2026-10-31): 0 of 3,484 answered 304, and that is expected.** 2,157 polls were new repos (F-070). The other 1,327 repos held ETags from other tokens: 1,296 from the maintainer's local token used for the 2026-10-28 full pass (F-064), 31 from run 1's `GITHUB_TOKEN`. The tracker doesn't send an ETag obtained by another token (F-058), so these were full requests. Their stored ETags all changed (now the PAT's); 22 of them had a different advisory count.
  - Run 8 (2026-10-29), the PAT's first scheduled run: 1 of 1,394 was 304, for the same reason.
- **Caveats:** Whether GitHub would honour an ETag across two tokens of the same user was never tested, because the tracker doesn't try. Four runs.
- **Implication:**
  - Q11 is moot: the daily job uses one stable PAT, and with it an unchanged repo costs nothing on its next poll.
  - Until every repo has been polled once under the PAT, polls are full price. 12,635 weekly-tier repos from the 2026-10-28 pass come due around 2026-11-04, on top of the 2,157 repos added on 10-31. At 3,500 requests a day that takes about four runs; daily-tier repos come first, and the weekly tier stretches by a few days. After that, the budget should cover the schedule with room to spare.
- **Sources:** [Best practices for using the REST API: conditional requests](https://docs.github.com/en/rest/using-the-rest-api/best-practices-for-using-the-rest-api)

### F-072
- **Date:** 2026-10-31 · **Status:** confirmed (repo contents and metadata; tool not executed). Refines [F-036](#f-036).
- **Question:** Phase 3 step 1: what does blindspot cover now, does it take outside contributions, and has anything new appeared since 2026-10-21?
- **Method:** `gh api repos/munimtechnologies/advisory-import-census` (metadata, releases, commits, the recursive tree at main, `README.md`, `blindspot.py`, all pulls and issues); `gh api search/repositories` for related terms, pushed or created after 2026-09-15 / 10-01.
- **Result:**
  - **blindspot:** v0.9.25 (2026-10-29, Marketplace metadata only; `blindspot.py` is still 0.9.24). About 105 commits, pushed today, 0 stars, 0 forks. Inputs, mapping, OSV-only check, SARIF and the Action are as in F-036; Cargo and Composer lockfiles are still not read.
  - `blindspot.py` has none of: reserved-CVE (RBP) state, duplicate-GHSA detection, a GitHub global-database check, GitLab output or CI, Code Quality output, a feed input.
  - **No outside contributions so far:** 0 pull requests and 0 issues ever, and no CONTRIBUTING file. Commits are by the owner's AI agents ("Made with AI agents working for MV2 of Munim, Inc.").
  - **Its focus has moved to research:** since 2026-10-30 it publishes pre-registered studies (S1–S5) on why advisories don't reach the database: CVE reuse, CVE lookups, late CVEs on package-less "twin" records, OSV alias bridging. It has filed issues on `github/advisory-database` (#10733, #10746).
  - **New since 2026-10-21:** `janghotan/depscope` (created 2026-10-26; npm/PyPI scanner over OSV that reports what it couldn't check; a possible feed consumer). `CyberNative-AI/apache-cve-ghsa-review-counts` (created 2026-10-31; one-off counts of ASF CVEs without a reviewed GHSA; the other-CNA gap of F-017). Neither runs a tracker or publishes a feed.
- **Caveats:** Read-only, from the repo; whether the owner wants outside PRs is unknown until asked. Search finds only what repo names and descriptions say.
- **Implication:** The planned blindspot contributions are all still missing there, but with no contribution history, open one issue asking which they'd want before writing any PR. Their studies overlap our findings (duplicates, late CVEs), so offering data may be as useful as code.

### F-073
- **Date:** 2026-10-31 · **Status:** confirmed (source and issue tracker). Refines [F-039](#f-039).
- **Question:** Can OSV-Scanner use an extra advisory source now, and would its maintainers consider it?
- **Method:** `gh api` reads of google/osv-scanner `cmd/osv-scanner/internal/helper/flags.go`, `pkg/osvscanner/scan.go`, `cmd/osv-scanner/fix/command.go` (main, latest release v2.7.0 of 2026-10-12) and google/osv-scalibr `enricher/vulnmatch/osvlocal/{osvlocal,matcher,zip}.go` at 9162ccacc0 (2026-10-30); commit history of `osvlocal.go`; issue search; issues #2198 and #3177 with comments; `curl -I` of `https://osv-vulnerabilities.storage.googleapis.com/PyPI/all.zip`.
- **Result:**
  - **SCALIBR's local matcher has a configurable download host** (`OSVLocalConfig.RemoteHost`, added 2026-02-03 in 5e3ca5326b, PR #1608 by ackama). It downloads `<host>/<Ecosystem>/all.zip` and stores it at `<local-db-path>/osv-scalibr/<Ecosystem>/all.zip` (F-039's `osv-scanner/` directory is now `osv-scalibr/`).
  - **OSV-Scanner hard-codes that host** to `https://osv-vulnerabilities.storage.googleapis.com` (`pkg/osvscanner/scan.go:84`, `fix/command.go:296`). No flag or environment variable sets it. `--local-db-path` only moves the cache.
  - The host is single-valued: pointing it elsewhere replaces OSV's data rather than adding to it.
  - When a cached zip exists, a refresh first sends `HEAD` and requires an `X-Goog-Hash: crc32c=<base64>` header; without it the load fails ("could not find crc32c= checksum"). GCS sends it (`x-goog-hash: crc32c=wKp+9g==` observed).
  - SCALIBR merges and de-duplicates findings that several matchers report for the same package (`dedupPackageVulns`).
  - **Issue #2198** ("Allow OSV-Scanner to use a custom database", 2025-08) was closed as not planned on 2025-10-22, because the requester wanted a MySQL backend. Collaborator another-rex had written "I am open to the idea of having osv-scanner using custom database", listed "download the .zip files from a custom url" as one option, and on 2025-11-12 called a configurable API host "pretty easily doable", asking for a new issue. None was filed (search by author and terms).
  - **Issue #3177** (open): since v2.7.0, npm lockfile entries without a `resolved` field are treated as local and not checked (PR #3104).
- **Implication:** The upstream ask is small and has a precedent: (1) expose the existing `RemoteHost` as a flag or environment variable, (2) better, accept additional zip hosts and merge their findings, which SCALIBR already de-duplicates. The feed should serve `<Ecosystem>/all.zip` with an `X-Goog-Hash` header so it works the day (1) ships.
- **Sources:** [osv-scanner#2198](https://github.com/google/osv-scanner/issues/2198), [osv-scanner#3177](https://github.com/google/osv-scanner/issues/3177), [osv-scalibr osvlocal](https://github.com/google/osv-scalibr/tree/main/enricher/vulnmatch/osvlocal)

### F-074
- **Date:** 2026-10-31 · **Status:** confirmed (observed; released binary, two packages)
- **Question:** Can the released OSV-Scanner scan against the limbo feed today, without code changes?
- **Method:** OSV-Scanner v2.7.0 built from source (`go install …@v2.7.0`, the research pipeline's binary). `https://limbo.watch/feed/all.zip` (21,840 records) split by `affected[].package.ecosystem` into `db/osv-scalibr/<Ecosystem>/all.zip`. Two test lockfiles: `requirements.txt` with `frappe==15.0.0`, and a `package-lock.json` v3 with `@vendure/core` 3.0.0. Both advisories checked first: `api.osv.dev/v1/vulns/GHSA-22v9-hw3x-x59w` and `GHSA-22x4-937q-5fr5` return 404. Run: `osv-scanner scan source --offline-vulnerabilities --local-db-path db -L …`.
- **Result:**
  - **Yes.** frappe 15.0.0: 58 limbo advisories reported. `@vendure/core` 3.0.0: 19, including GHSA-22x4-937q-5fr5 (CVSS 9.6, fixed 3.7.3). Exit code 1 (vulnerabilities found).
  - **A missing ecosystem zip fails the whole scan:** with the npm zip absent, the run exits 127 with "no offline version of the OSV database is available" and reports 0 findings, PyPI included. **An empty zip is accepted** ("Loaded npm local db").
  - An npm lock entry without `resolved` was skipped silently ("No issues found", exit 0), as #3177 describes; with `resolved` it matched.
  - OSV publishes 47 ecosystem names in `https://osv-vulnerabilities.storage.googleapis.com/ecosystems.txt` (2026-10-31).
- **Caveats:** Two packages. This mode scans against the limbo feed *instead of* OSV's data, so it complements a normal scan rather than replacing it. Range conversion caveats of F-069 apply.
- **Implication:** Publish one zip per ecosystem at `/osv/<Ecosystem>/all.zip`, an empty one for every OSV ecosystem the feed doesn't cover, so a second scan works today: download, then `--offline-vulnerabilities --local-db-path`. This is a working demo for the upstream request (F-073).

### F-075
- **Date:** 2026-10-31 · **Status:** confirmed (repo contents; count over the tracker state)
- **Question:** Does RogoLabs' rbptracker already read repository advisories, and what could our data add?
- **Method:** `gh api` reads of RogoLabs/RBP (`FEEDS.md`, `rbp/feeds.py`, `feedlab/ghsa-repos.json`, `rbp/feed_data/ghsa_repos.txt`, main, pushed 2026-10-31). Overlap with `tracker-data` state at 7fca6ac (`state/repos.jsonl`; latest facts per advisory in `state/facts.jsonl`).
- **Result:**
  - **It does, since 2026-08:** a `ghsa-repos` feed polls a committed list of 1,871 valid repos, conditionally (ETag), for published advisories that cite a CVE. On 2026-08-27 it was the sole source for 1,015 of 1,709 published rows (59% of their headline).
  - **The list is frozen** (curated 2026-08-26). Their code says: "NOT SELF-REFRESHING. Discovering a repository that publishes its FIRST advisory is a mining problem and it is not solved here."
  - **Overlap:** 1,848 of their 1,871 repos are on our 18,656-repo watchlist. **3,727 repos with published advisories on our watchlist aren't on their list.** Of the 1,303 unreviewed advisories in our state citing a CVE recorded as RESERVED (408 repos), **416 in 188 repos** are outside their list.
  - They publish counts, not CVE IDs from that cache, by design.
- **Caveats:** RESERVED is as of our last CVE check per advisory, not re-checked today. Their list may have been chosen deliberately (provenance rules in the file header).
- **Implication:** The useful offer is a daily, self-refreshing list of repos that publish advisories (repo names only, no CVE IDs), which is exactly their unsolved step. It's a contribution of data, not code.

### F-076
- **Date:** 2026-10-31 · **Status:** confirmed (observed; local build and local server)
- **Question:** If OSV-Scanner let users set the zip host (F-073), would the limbo feed's per-ecosystem layout work end to end, including cache reuse?
- **Method:**
  - `limbowatch publish` on the 7fca6ac state writes `osv/<Ecosystem>/all.zip` (46 names from F-074's list), `osv/crc32c.map` and `osv/limbo-db.zip`.
  - The site image (`deploy/site`, nginx 1.30.0-alpine) was built from that output and run locally; `curl -I` on `/osv/PyPI/all.zip`, `/osv/GitHub%20Actions/all.zip`, `/osv/Debian/all.zip`.
  - OSV-Scanner v2.7.0 source with one change: `RemoteHost` in `pkg/osvscanner/scan.go` read from `OSV_SCANNER_LOCAL_DB_REMOTE_HOST` (default unchanged). Run twice with `--offline-vulnerabilities --download-offline-databases --local-db-path <empty dir>` on F-074's two test lockfiles, host `http://127.0.0.1:18080/osv`.
  - CRC-32C check: our implementation on OSV's own `PyPI/all.zip` against its `x-goog-hash` header.
- **Result:**
  - Our CRC-32C gives `crc32c=wKp+9g==` for OSV's PyPI zip, the same as GCS's header. nginx sends `X-Goog-Hash` for every zip, including names with spaces.
  - **Run 1** downloaded `GET /osv/npm/all.zip` and `/osv/PyPI/all.zip` and reported 77 limbo advisories for the 2 packages. **Run 2** sent only `HEAD` for both, matched the checksums, reused the cache and reported the same 77.
  - The published bundle, unzipped and used with the released v2.7.0 (`--offline-vulnerabilities --local-db-path`), also reported 77.
  - Fixing the zip writer (entries now deflated; they had been stored uncompressed) shrank `feed/all.zip` from 34.9 MB to 18.4 MB. The scanner bundle is 7.5 MB; the per-ecosystem zips total 14 MB.
- **Caveats:** A local patch and a local server, not a released feature. With one host, the feed replaces OSV's data, so a real feature needs either a second host or merging (F-073).
- **Implication:** The upstream change can be one configurable value and works with the feed as published. The request can include this patch and the two-run log as a reproducible demo.

### F-077
- **Date:** 2026-11-05 · **Status:** confirmed (count over the tracker state)
- **Question:** How many advisories in limbo have a field scanners can't use, where are they, and what does a repo list for other trackers hold?
- **Method:** `limbowatch.publish.quality.problems` over the `tracker-data` state at fbcca97 (run of 2026-11-04): every package in an OSV ecosystem of every advisory in limbo. A name is a problem when `package_name` cleans it (exact fix) or finds it invalid; a range when `osv_ranges` returns None, classified by `range_problem`. `repos_with_advisories`: watched repos with `advisory_count > 0` and last poll 200 or 304.
- **Result:**
  - **1,467 problem fields in 1,294 advisories across 424 repos**, all pending review (none likely permanent).
  - Names: 924, of which 334 have an exact fix (case, spaces, a URL around the name) and 590 don't fit the ecosystem's rules (Maven 196, Packagist 177, Go 68, npm 50, SwiftURL 36, GitHub Actions 34, PyPI 19, others 10).
  - Ranges: 543. Not a range at all (`tbd`, `n/a`, prose, commit references) 246; several upper bounds in one range 100; exact versions mixed with bounds 45; `A .. B` 42; no upper bound with several fixed versions 39; `>` 35; no upper bound with a fix that doesn't close it 20; a fixed field that isn't a version 16.
  - **Concentrated:** labredescefetrj/wegia 114 advisories (113 name the package `WeGIA`, with no vendor), dataease/dataease 93, churchcrm/crm 53, siyuan-note/siyuan 37, hickory-dns/hickory-dns 30. One edit pattern per repo would fix most.
  - Grouped by repo and identical problem, the page has 754 rows.
  - **Repo list:** 5,541 of 18,661 watched repos have published advisories.
- **Caveats:** F-069 counted feed entries in the 2026-10-30 state (359 cleaned, 406 invalid); this counts problem fields in advisories in limbo four days later, so the numbers differ. Suggested fixes other than exact name fixes are advice, not certainties; per-release-line suggestions assume each line starts at `X.Y.0`.
- **Implication:** Published at limbo.watch/quality/ (linked from each affected advisory page and the feed page) and limbo.watch/feed/repos.txt, without contacting anyone (Phase 3 closed without outreach, docs/outreach/). A handful of repos account for a large share, so if outreach happens later, a few notes would cover hundreds of advisories.

### F-078
- **Date:** 2026-11-05 · **Status:** confirmed (observed; OSV-Scanner 2.7.0, OSV-SCALIBR 0.5.3, hand-made lockfiles)
- **Question:** What does OSV-Scanner's `--all-packages` JSON give the watcher as an inventory, and which dependencies does it drop or misreport without saying so?
- **Method:** A test tree with an npm `package-lock.json` v3 (a registry entry, an entry without `resolved`, a `link`/`file:` workspace package, a `git+ssh` dependency with a short hash), `requirements.txt` (`requests==2.31.0`, `flask>=2`, a `git+https` line, `-e ./localpkg`, bare `numpy`), `go.mod` with a `replace` to a local path, `Cargo.lock` (registry, local and git crates) and an unparseable `package-lock.json`. Runs of `osv-scanner scan source --all-packages --format json -r <tree>`: fully offline (`--offline --offline-vulnerabilities --local-db-path <dir of 46 empty zips>`), with and without `--no-call-analysis=all`, and once with online resolution (`--offline-vulnerabilities` only) for `requirements.txt`.
- **Result:**
  - **Output:** `results[].source.path` and `.type`, then `packages[].package` with `name`, `version`, `ecosystem`, `purl` (plus `commit` for GIT). No line numbers, no dependency groups, no field saying a package was skipped.
  - **Marked:** packages OSV-Scanner treats as local get `?source=LOCAL` in the purl: the npm entry without `resolved` (#3177) and the `link` workspace package. Its log says "Filtered 3 local/unscannable package/s from the scan" without naming them.
  - **Not marked:**
    - `flask>=2` is reported as version `2` offline (a range read as a version). With online resolution it becomes `3.1.3`, the latest, via deps.dev, and 12 transitive packages are added.
    - `numpy` with no version is reported with version `""`, online too.
    - The `git+https` and `-e ./localpkg` lines are left out entirely (5 lines in, 3 packages out).
    - The Go `replace` target is a package named `../local` with version `""`.
    - The Cargo git crate and the local crate are reported as `crates.io` packages with versions, so a crates.io advisory with the same name would match them.
    - The git npm dependency with a short hash is listed as `GIT` and skipped for matching ("short commit hash … cannot be queried").
  - **Exit codes:** 0 clean; **127** when any lockfile can't be read (the JSON still holds the other lockfiles; the file is named only on stderr: `Error during extraction: (extracting as javascript/packagelockjson) <path>: could not extract: …`), and also when Go call analysis fails without a Go toolchain (avoided with `--no-call-analysis=all`); **128** when no lockfile is found.
  - Offline with empty zips, the run sends nothing over the network and does no matching, so it works as a pure inventory step.
- **Caveats:** Hand-made files, one version. Other extractors (pnpm, yarn, poetry, uv, Gradle) not tried.
- **Implication:** OSV-Scanner is a usable inventory, but the watcher must add its own checks, each reported as `UNRESOLVED` with a reason, never dropped: empty versions; `?source=LOCAL`; requirements lines that aren't exact pins (re-read the file); lines that vanish (compare against the file); `GIT` entries; registry-looking packages from git or path sources where the lockfile says so (Cargo `source`); and unreadable lockfiles from stderr with exit 127. Code Quality needs a line per finding, so the watcher finds the package in the lockfile itself.

### F-079
- **Date:** 2026-11-05 · **Status:** confirmed (docs)
- **Question:** What do GitLab's issue, note and Code Quality interfaces and CI/CD components require of the watcher?
- **Method:** GitLab's own docs from its repository at master 0fe4f24f (2026-11-05): `doc/api/issues.md`, `doc/api/notes.md`, `doc/api/labels.md`, `doc/ci/testing/code_quality.md`, `doc/ci/components/_index.md`, fetched raw from gitlab.com.
- **Result:**
  - Issues: `POST /projects/:id/issues` (`title` required; `description` up to 1,048,576 characters; `labels` as comma-separated names, created if missing; **`confidential`**, default false). `PUT /projects/:id/issues/:issue_iid` edits, including `add_labels` and `state_event` to close or reopen. List filters include `labels` (all must match), `search` (title and description), `state`, `iids[]`. Creation can be rate limited per minute.
  - Notes: `POST /projects/:id/issues/:issue_iid/notes` with `body` (up to 1,000,000 characters) and `internal`.
  - **Code Quality:** a single JSON array, no byte order mark; each object needs `description`, `check_name`, `fingerprint`, `severity` (`info`, `minor`, `major`, `critical`, `blocker`), `location.path` (relative, no `./`) and `location.lines.begin`. Only those fields are processed.
  - **CI/CD components** live in a GitLab project with a top-level `templates/` directory (`<name>.yml` or `<name>/template.yml`) and a `README.md`, versioned together, up to 100 per project; publishing to the Catalog is a separate step. Components should take inputs rather than global keywords or hard-coded hosts.
- **Implication:** Issues default to confidential on GitLab (a public issue saying a project ships an affected version discloses something new). Deduplicate by a marker in the description plus the `limbowatch` label, not by title. The component needs its own GitLab project at release time; until then it lives in this repo and is tested with fixtures.

### F-080
- **Date:** 2026-11-05 · **Status:** confirmed (observed; local Gitea 28.3.0 in Docker)
- **Question:** How does Gitea's issue API behave for the watcher's lifecycle (create, label, find again, comment, close)?
- **Method:** `gitea/gitea:28.3.0` (released 2026-11-01) bound to 127.0.0.1, SQLite, a generated local admin and token. Endpoints read from its `/swagger.v1.json`. On a private test repo: create a label, an issue with that label and a hidden marker (`<!-- limbowatch:finding=… -->`) in the body, search, comment, close, list closed by label.
- **Result:**
  - Create issue: `POST /repos/{owner}/{repo}/issues` with `title`, `body`, `labels` as **label IDs** (int64). Adding labels later (`PUT/POST …/issues/{index}/labels`) accepts IDs or names. Edit and close: `PATCH …/issues/{index}` with `state`. Comment: `POST …/issues/{index}/comments` with `body`. List: `state`, `labels`, `q`, `type`, `since`, paging.
  - **No confidential issues** (no such field in `CreateIssueOption`).
  - **Search lags:** `q` found the new issue by title, label name or the body marker only seconds after creation (immediately after, it returned nothing). Listing by `labels=limbowatch` found it at once, open and closed.
  - Forgejo's latest release is v17.0.1 (2026-10-26, Codeberg API); not tested.
- **Caveats:** One version, one run. Forgejo is a Gitea fork but its API may have diverged.
- **Implication:** Resolve label names to IDs once per repo. Find existing issues by listing the `limbowatch` label and reading the marker, not by search. Because Gitea can't hide an issue, the watcher should warn before opening issues in a public Gitea/Forgejo repo and offer a setting to skip them there.

### F-081
- **Date:** 2026-11-05 · **Status:** confirmed (observed; two real projects)
- **Question:** Does the watcher's inventory (OSV-Scanner offline plus the F-078 checks) hold up on real projects?
- **Method:** `limbowatch inventory` (OSV-Scanner 2.7.0) on shallow clones of go-gitea/gitea at 3b9b8a8 and open-webui/open-webui at c38885a, 2026-11-05.
- **Result:**
  - Gitea: **1,193 dependencies** from `go.mod`, `pnpm-lock.yaml` and `uv.lock` (npm 957, Go 222, PyPI 14), none unchecked, every one located to a line.
  - Open WebUI: **1,992 dependencies** from `package-lock.json`, `uv.lock`, two `requirements*.txt` and a `Cargo.lock` (npm 1,266, PyPI 528, crates.io 198); 1 not located (line 1). Unchecked: the project's own package in `uv.lock` (`source = { editable = "." }`, reported by OSV-Scanner with an empty version) and a local crate. Both are now reported as local packages, after adding a `uv.lock` source check.
  - The unit tests found one more silent error, in the check itself: a hashed `pip-compile` requirement (`numpy==1.26.4 \` then `--hash=…`) read as a range, because the `--hash` option stayed in the specifier. Fixed.
- **Caveats:** Two projects, both well maintained and fully locked. Projects with loose `requirements.txt` files will show many range-only entries, by design.
- **Implication:** The inventory is ready for matching. On real lockfiles nearly every dependency is checkable; the unchecked list is short and specific.

### F-082
- **Date:** 2026-11-05 · **Status:** confirmed (observed; two projects, every finding verified live)
- **Question:** Does the watcher's matching find real advisories in limbo in real projects, and are they right?
- **Method:** `limbowatch.watch.scan` on the F-081 inventories of Gitea (3b9b8a8) and Open WebUI (c38885a), against the live feed (`limbo.watch/feed/all.zip`, 22,717 advisories) and watchlist (18,392 repos), 2026-11-05 ~22:10 UTC, with a GitHub token. Every distinct advisory found was then checked against primary sources: `api.osv.dev/v1/vulns/{id}`, `GET /advisories/{id}` (global database) and `GET /repos/{repo}/security-advisories/{id}` (state and current ranges).
- **Result:**
  - **Gitea:** 825 source repos mapped, all on the watchlist, so 0 polled; 1,008 deps.dev lookups, 9 s. **14 findings**, all certain, all from the feed, e.g. `github.com/andybalholm/brotli` 1.2.1 (`< 1.2.7`), `github.com/goccy/go-json` 0.10.6, `@sinclair/typebox` 0.27.10, `seroval` / `seroval-plugins` 1.5.4 (6), `solid-js` 1.9.13 (3).
  - **Open WebUI:** 1,165 source repos, 1,156 on the watchlist, 9 polled (9 GitHub requests); 1,806 deps.dev lookups, 9 s. **46 findings** (45 certain, 1 possible) for 32 advisories, e.g. `pydantic` 2.13.4 (3), `undici` 7.30.1 (6), `@sveltejs/kit` 2.70.3 (6), `authlib` 1.7.2, `qdrant-client` 1.18.0, `openmls` 0.9.1 (2). Most appear in two or three lockfiles.
  - **Verification: all 46 distinct advisories are published repository advisories, 404 in OSV and 404 in the global database.** For every certain finding the version is in the advisory's current range. The possible one is `prettier` 3.8.1 against `>=3.9.0, <=3.9.9; 3.9.9 tested`, unreadable because of the trailing words (the readable part excludes 3.8.1).
  - Four ranges in the feed differ from the advisory's current text (edited after the tracker's last poll, e.g. `@sveltejs/kit` `< 3.0.0` now `<= 2.70.3`); none changed the verdict.
  - Partly checked: 58 (Gitea) and 56 (Open WebUI) dependencies with no source repo from deps.dev, checked by name only.
  - **Bug found and fixed:** the first run gave Gitea 6 "repository" matches for `@napi-rs/wasm-runtime`: napi-rs advisories that name the crates.io crate `napi`. A repository match now requires that the advisory names no valid package in any ecosystem. A Go `/vN` mismatch (`regexp2/v2` 2.11.0 vs GHSA-wq9v's `< 2.3.0`) is now evaluated first and dropped when out of range.
- **Caveats:** Two projects. Feed ranges are as fresh as the tracker's last poll of the repo (up to about 10 days for quiet repos).
- **Implication:** Matching works on real projects with verified results, and it needs almost no GitHub requests because the tracker already covers nearly every upstream. Both projects ship versions affected by advisories that OSV-based scanners don't report.

### F-083
- **Date:** 2026-11-05 · **Status:** confirmed (observed; one end-to-end run)
- **Question:** Does the watcher's issue lifecycle work against a real tracker?
- **Method:** `scripts/e2e_gitea.py`: `gitea/gitea:28.3.0` in Docker on 127.0.0.1, a generated admin and token, one private and one public repo. A Go module pinned to `github.com/andybalholm/brotli` v1.2.1 (GHSA-c9gr-gmg4-2vqv, in limbo, F-082), scanned with `limbowatch scan --issues gitea --state …` against the live feed, five times: as is, unchanged, upgraded to v1.2.7, downgraded to v1.2.1, and against the public repo.
- **Result:** All five checks passed:
  1. One issue opened, `[limbo] GHSA-c9gr-gmg4-2vqv: go github.com/andybalholm/brotli 1.2.1 (low)`, labelled and carrying the finding marker.
  2. A second run changed nothing (no new issue, no comment).
  3. After the upgrade, the issue got one comment and was closed (the recorded range `< 1.2.7` excludes 1.2.7; the advisory isn't in OSV).
  4. After the downgrade, the same issue was reopened.
  5. The public repo got no issue, and the run said why.
- **Caveats:** Gitea only; GitLab is covered by recorded-response tests, not a live instance. The "now visible to scanners" path needs an advisory that reaches OSV during the test, so it is covered by unit tests only.
- **Implication:** The lifecycle the SPEC asks for works end to end on Gitea, idempotently, without a public post.

### F-084
- **Date:** 2026-11-05 · **Status:** confirmed (observed; one run per integration, in a container)
- **Question:** Do the GitLab CI/CD component's job and the Actions composite action work as written?
- **Method:** `scripts/check_integrations.py`: each job's shell taken from `integrations/gitlab/templates/limbowatch.yml` and `integrations/action/action.yml` with the inputs filled in as GitLab and Actions would, run in `python:3.12-slim` against a Go module pinned to `andybalholm/brotli` v1.2.1. Limbowatch installed from `git archive HEAD` (a local file standing in for GitHub's archive URL; the repo is private). OSV-Scanner 2.7.0 downloaded from Google's release and checked against `osv-scanner_SHA256SUMS`.
- **Result:**
  - GitLab job: exits 1 with `fail_on: low`, writes `gl-code-quality-report.json` (with GHSA-c9gr-gmg4-2vqv) and `limbowatch.md`; exits 0 with `fail_on: none`. No issues are attempted on a feature branch.
  - Action: exits 1, writes the SARIF file and appends the Markdown report to the job summary.
  - `python:3.12-slim` has no git, so `pip install git+…` would fail there; both install from the source archive URL instead. The PyPI name `limbowatch` is unregistered (404), so neither installs it by name.
- **Caveats:** The jobs ran in a plain container, not on GitLab or an Actions runner; runner-specific behaviour (the CI/CD Catalog, `$GITHUB_PATH` handling) is assumed from docs (F-079). Installing from the GitHub archive needs the repo to be public.
- **Implication:** Both integrations work end to end. Releasing them needs a public source (the repo or a release archive), a GitLab project for the component, and ideally the PyPI name reserved.

### F-085
- **Date:** 2026-11-05 · **Status:** confirmed (observed; 15 projects, recall and precision measured against primary sources)
- **Question:** On the 15 projects of the October report, does the watcher find what the research pipeline found, and are its extra findings right?
- **Method:** `limbowatch scan --scan-ignored --format json` on the research pipeline's lockfile-only clones at the commits of F-055/F-053 (2026-09-30 to 10-22), against the live feed of 2026-11-05 with a GitHub token. **Recall:** the research `findings.csv` rows (both 2026-10-22 snapshots) in a limbo class, `version_affected = yes`, not a likely duplicate, whose advisory is still in today's feed, de-duplicated to (advisory, ecosystem, package, version) per project. **Precision:** every distinct finding checked live: the repo advisory (`GET /repos/{repo}/security-advisories`), OSV by ID, and the installed version against the advisory's *current* range.
- **Result:**
  - **29,221 dependencies** across 15 projects; fdroidserver has no lockfile (as in F-053). **269 distinct package-versions certainly affected** (plus 19 possibly), in 13 of 14 readable projects: GitLab 125 (115 advisories), n8n 36, LangChain 30, Open WebUI 18, Forgejo 9, GoToSocial 9, Arti 9, Gitaly 8, GitLab Runner 8, Gitea 7, Mobilizon 5, Kubernetes 3, Fractal 2, aerc 0.
  - **Recall 100%:** 709 research rows; 330 have left limbo since; the remaining 132 distinct affected package-versions were all found.
  - **Precision:** of 657 distinct findings (275 advisories), **630 are in the advisory's current range**, 12 are "possible" with the live range still unreadable, 15 matched by Go package path or by repository (no same-name entry to compare), **0 contradicted**. 590 findings are new relative to the research set (advisories published since, or in repos the research didn't map).
  - **Bugs found and fixed while measuring:**
    1. OSV-Scanner applies an enclosing repo's `.gitignore`: the clones under the ignored `research/**/.cache/` read as empty ("No package sources found", exit 128, reported by the watcher as "no lockfiles", not as clean). Added `--scan-ignored` (`--no-ignore`) and a hint on that message.
    2. A repository match in a monorepo flagged every package: one opentelemetry-ruby-contrib advisory with a sentence as its package name matched 97 gems. When several of the project's packages map to the repo, the unusable name must now mention the package (97 → 4 for GitLab).
    3. Rust-style `A .. B` ranges (hickory-dns) were all "possible" (39 in Arti). Now evaluated under both readings; only a version equal to B stays possible.
    4. `<= 3.0.10, 4.0.0` was read as AND (never true), so `@sveltejs/adapter-static` 3.0.10 looked unaffected under the live range. An exact version beside a bound is now another alternative (`versions.alternatives`), which also lets the feed convert such ranges.
    5. Go versions went to deps.dev without their `v` (OSV-Scanner drops it), so every module off `github.com/` paths got a 404 (861 in Kubernetes).
    6. deps.dev has no source repo for most gems (1,084 in GitLab); rubygems.org's own `source_code_uri` / `homepage_uri` now comes first in the chain.
    
    With 5 and 6, dependencies checked by name only fell from 2,979 to 1,225 (GitLab 1,316 → 293, Kubernetes 861 → 320; most of the rest are hosted off GitHub or are vanity Go paths deps.dev can't map).
  - **Cost:** 532 GitHub requests in all (GitLab 356, because its Ruby upstreams aren't on the tracker's watchlist), 2–62 s per project.
- **Caveats:** One run; the feed is a day old at most. Precision checks the advisory's current range with Limbowatch's own evaluator, the same one that matched. Recall is against the research pipeline, which used the same matching rules.
- **Implication:** The watcher reproduces the October report's findings and finds about four times as many today, with no contradicted result. In GitLab CI without a GitHub token (60 requests an hour), a project like GitLab would leave most of those 356 repos unpolled and report them as checked by name only, so the docs should ask for a read-only GitHub token. Adding Ruby upstreams to the tracker's seeds (Phase 5) would cut that further.

### F-086
- **Date:** 2026-11-06 · **Status:** confirmed (observed; one pipeline on gitlab.com)
- **Question:** Does the component run on GitLab itself, and does GitLab accept its Code Quality report as written (Q19, first half)?
- **Method:** Created `gitlab.com/limbowatch/limbowatch-component` (public; project 88618678) and pushed `git subtree split -P integrations/gitlab` of f4424e1 as `main`. Its `.gitlab-ci.yml` includes the component from the same commit (`limbowatch@$CI_COMMIT_SHA`) with `path: tests/go-sample` (a `go.mod` pinning `andybalholm/brotli` v1.2.1) and `fail_on: none`; a `check-reports` job asserts on the artifacts. Then read GitLab's parsed report via GraphQL `project.pipeline(iid: "1") { codeQualityReportSummary codeQualityReports }`.
- **Result:**
  - Pipeline 3038736795 passed on gitlab.com shared runners with no extra account verification: `limbowatch` job 34 s (OSV-Scanner download with SHA-256 check, install from the GitHub source archive, scan), `check-reports` 22 s.
  - The job found GHSA-c9gr-gmg4-2vqv (low, no CVE, fixed in 1.2.7) against the live feed of 2026-11-06 22:36 UTC.
  - GitLab parsed the report: `count: 1`, severity `MINOR` (from `low`), `path: tests/go-sample/go.mod`, `line: 5`, description with the CC BY 4.0 attribution.
  - The REST path `pipelines/:id/codequality_reports` returns 404; GraphQL is the way to read parsed reports.
  - Before f4424e1, a scan of a subdirectory wrote paths relative to that directory (`go.mod`), which GitLab resolves from the repo root; caught while preparing this run and fixed for both Code Quality and SARIF.
  - CI/CD Catalog: `catalogResourcesCreate` succeeded and `isCatalogResource` is true. Nothing is listed until a semver tag is released.
- **Caveats:** One pipeline, on a branch, so the merge request widget and confidential issues weren't exercised. Code Quality in MRs compares against the target branch's report.
- **Implication:** The component works on gitlab.com as written and GitLab reads its report. Q19 stays open for confidential issues and the MR widget, which need a merge request and a project access token.

### F-087
- **Date:** 2026-11-06 · **Status:** confirmed (observed on gitlab.com; GitLab REST authentication docs)
- **Question:** Do the watcher's GitLab issues work on a real GitLab (Q19, second half), and which token header does GitLab accept?
- **Method:** `scripts/e2e_gitlab.py` against a private project `gitlab.com/limbowatch/limbowatch-e2e`, created by the script: a Go module pinned to `andybalholm/brotli` v1.2.1 (GHSA-c9gr-gmg4-2vqv), scanned with `--issues gitlab --state`, then upgraded to v1.2.7 and downgraded again. Token: glab's browser (OAuth) login, passed in `LIMBOWATCH_ISSUES_TOKEN`, never printed. Header check: `GET /api/v4/user` with the same token as `PRIVATE-TOKEN` and as `Authorization: Bearer`; [REST API authentication docs](https://docs.gitlab.com/api/rest/authentication/).
- **Result:**
  - `PRIVATE-TOKEN` with an OAuth token: **401**; `Authorization: Bearer`: 200. The docs say personal, project and group access tokens also work as `Bearer` ("OAuth-compliant headers"), while OAuth tokens must use it. The watcher sent `PRIVATE-TOKEN`, so glab or other OAuth tokens failed; it now sends `Bearer`.
  - 8 of 8 checks passed: the project is private; one issue opened, **confidential: true**, labels `limbowatch`, `security`, `severity:low`, body with the hidden marker, facts and links only (no advisory text) and the CC BY 4.0 attribution; a second run added nothing; upgrading past the fix closed it with a note; downgrading reopened the same issue (#1) with "Found again in go.mod:5".
- **Caveats:** One run, on gitlab.com (not self-managed), from a laptop rather than a CI job, with `--no-upstream`. The merge request Code Quality widget is still unexercised. The test project keeps the closed issue.
- **Implication:** GitLab issues behave as designed on real GitLab. With F-086, Q19 is answered except for the MR widget. Any GitLab token type works now, including a project access token in CI.

### F-088
- **Date:** 2026-11-06 · **Status:** confirmed (observed; one demo project per host, one run each)
- **Question:** Does the watcher work end to end for a realistic project in real CI: GitLab (component, Code Quality, merge request widget) and GitHub Actions (action, SARIF, job summary)?
- **Method:**
  - Demo app with real lockfiles generated by the tools themselves: `web/` npm (`npm install --package-lock-only`, 71 packages: express 5.1.0, lodash 4.18.1, undici 7.30.1), `api/` Go (`go mod tidy`: chi v5.4.0, pgx v5.11.0, uuid v1.6.0), `worker/requirements.txt` (dnspython==2.9.1, requests==2.34.2, `flask>=3.1`, a `git+https` install), `billing/Gemfile.lock` (`bundle lock` in `ruby:3.4-slim`: rack 2.2.24, nokogiri 1.19.4). Versions picked from the live feed of 2026-11-06 22:36 UTC.
  - GitLab: private `gitlab.com/limbowatch/demo-app` including the component at `limbowatch-component@cbf13db` with `fail_on: high` and `limbowatch_ref` = GitHub cd1849f; then MR !1 adding `scapy==2.7.0`. Read results from job logs, GraphQL `codeQualityReportSummary` / `codeQualityReports`, and the MR page in a browser.
  - GitHub: private `github.com/limbowatch/demo-app` running `limbowatch/limbowatch/integrations/action@cd1849f` with `fail-on: high` and `sarif:`, then `upload-artifact` and `codeql-action/upload-sarif`.
  - Checks: each finding's GHSA against `GET /advisories/{id}` (GitHub reviewed DB) and `GET api.osv.dev/v1/vulns/{id}`; plain OSV-Scanner 2.7.0 online (`scan source -r .`) on the same tree.
- **Result:**
  - Both CI runs and a local run agree: **80 dependencies, 16 advisories in limbo affecting 6 packages** in all four ecosystems (undici ×6, rack ×4, nokogiri ×3, pgx ×2, dnspython, chi), each at the right lockfile line; `flask>=3.1` (range only) and the git install reported as can't be checked; 1 checked by name only. All 16 return 404 from both GitHub's reviewed DB and OSV. Plain OSV-Scanner reports 6 reviewed vulnerabilities in transitive dependencies (golang.org/x/text, certifi, idna) and **none of the 16**.
  - GitLab main pipeline: job exits 1 (`fail_on: high`, 5 high findings) and still uploads `gl-code-quality-report.json`, `limbowatch.md`, `limbowatch.json`; GitLab parsed 16 Code Quality entries with repo-root paths (`web/package-lock.json:879`, `api/go.mod:8`, …) and severities high → CRITICAL, medium → MAJOR, low → MINOR. `--state` in the job cache reported "16 new". Upstream polling without a GitHub token was enough for this project.
  - MR !1: the widget shows **"Code Quality scans found 51 new findings"**: the branch report has 67, main 16, and the feed has 51 scapy advisories. The pipeline failing doesn't block merging unless the project requires passing pipelines.
  - GitHub Actions: action exits 1; SARIF with 16 results (levels error/warning/note by severity, repo-root URIs) and the Markdown report in the job summary. `upload-sarif` failed first with "Resource not accessible by integration" (needs `actions: read`), then with "Advanced Security must be enabled for this repository to use code scanning" (private repo in a free org).
  - Issues from CI on gitlab.com Free: `POST /projects/:id/access_tokens` returns 400 "User does not have permission to create project access token"; GitLab's docs: on GitLab.com project access tokens need Premium or Ultimate.
  - Fixed after this run: "1 were checked by name only" (now agrees in number); docs now give `actions: read`, the code-scanning requirement, the Free-tier token advice, and the offline inventory's Python limit.
- **Caveats:** One run per host, private projects only; code scanning alerts (needs a public repo or Code Security) and CI-opened issues (needs a token the user creates) weren't exercised in CI, though issues were from a laptop on gitlab.com (F-087). The offline inventory reads `requirements.txt` entries only, so certifi and idna, which OSV-Scanner resolves online, weren't checked.
- **Implication:** The watcher works for a realistic multi-ecosystem project in both GitLab CI and GitHub Actions, the merge request widget shows exactly the advisories a change adds, and none of these findings reach a scanner that reads OSV. Q19 is answered.

### F-089
- **Date:** 2026-11-06 · **Status:** confirmed (observed; one public repo, one PR)
- **Question:** Does the action's SARIF become GitHub code scanning alerts and pull request annotations (the part F-088 couldn't test on a private repo)?
- **Method:** Made `github.com/limbowatch/demo-app` (the F-088 demo, demo files only) public, reran the workflow on `main`, then opened PR #1 adding `scapy==2.7.0`. Read `GET /repos/limbowatch/demo-app/code-scanning/alerts?tool_name=limbowatch`, the PR's check runs, and the PR's files view in a browser.
- **Result:**
  - `upload-sarif@v4`: "Successfully uploaded results"; **16 alerts** on `main`, one per finding, at repo-root paths and lines (`web/package-lock.json:879`, `api/go.mod:8`, `worker/requirements.txt:2`, …), with `security_severity_level` high/medium/low taken from the SARIF `security-severity` scores.
  - PR #1: check run `limbowatch` (code scanning) failed with **"51 new alerts including 4 high severity security vulnerabilities"**, matching the 51 scapy advisories and GitLab's MR widget (F-088). Each alert is annotated on the added line `scapy==2.7.0` with the advisory ID, severity, fixed version and range.
  - The demo workflow runs twice per PR because it triggers on both `push` and `pull_request`; that's the workflow's choice, not the action's.
- **Caveats:** One repo; alerts close only when a later analysis no longer reports them, which wasn't exercised.
- **Implication:** On GitHub, the watcher's findings appear where reviewers look: as code scanning alerts and inline on the lockfile line a PR changes. Code scanning needs a public repo or GitHub Code Security.

### F-090
- **Date:** 2026-11-07 · **Status:** confirmed (observed; one public repo)
- **Question:** Without Limbowatch, would GitHub's own dependency alerts (Dependabot) have reported any of the demo's 16 findings (F-088)?
- **Method:** On the public `github.com/limbowatch/demo-app`, turned on Dependabot alerts (`PUT /repos/limbowatch/demo-app/vulnerability-alerts`). The dependency graph stayed empty ("No dependencies found") until a commit changed the manifests; then read `GET /repos/limbowatch/demo-app/dependency-graph/sbom` and `GET /repos/limbowatch/demo-app/dependabot/alerts`. Cross-checked each version with `GET /advisories?type=reviewed&ecosystem=…&affects=<pkg>@<version>`.
- **Result:**
  - Dependency graph: 16 entries, the direct dependencies from each manifest (npm express, lodash, undici; Go chi, pgx, uuid and three indirect modules; pip dnspython, requests, and flask and requests-oauthlib with no version; RubyGems nokogiri, rack). npm's 68 transitive packages from `package-lock.json` weren't listed.
  - **Dependabot alerts: 0.** Limbowatch, on the same tree: 16 advisories in limbo in six of those packages.
  - The reviewed database has no active advisory for any of the demo's versions, scapy 2.7.0 included. `affects=express@5.1.0` returns GHSA-pj86-cfqh-vqx6, but it was withdrawn on 2025-12-02, so no alert is correct.
  - A repo made public doesn't get a dependency graph until a push changes a manifest; an empty commit didn't trigger it.
- **Caveats:** One repo, Dependabot alerts only (not security updates). GitLab's own Dependency Scanning wasn't compared: it uses the GitLab Advisory Database, which Limbowatch must not query.
- **Implication:** For this project, GitHub's native alerts and OSV-Scanner both report nothing for the 16 advisories Limbowatch finds; the gap is exactly the review backlog. It closes as GitHub reviews them, which is what the watcher's "now visible to scanners" change reports.

### F-091
- **Date:** 2026-11-07 · **Status:** confirmed (primary sources; 16 findings)
- **Question:** Are the demo's 16 findings (F-088) real, and how long had they been in limbo?
- **Method:** `research/2026-11-demo-evidence/verify.py`: for each finding, `GET /repos/{repo}/security-advisories/{ghsa}`, `GET /advisories/{ghsa}`, `GET /advisories?type=reviewed&cve_id=…`, OSV `GET /v1/vulns/{ghsa}` and `POST /v1/query` by package and version. Version-in-range checked independently of Limbowatch with each ecosystem's own library (npm `semver`, `packaging.specifiers`, `Gem::Requirement` in `ruby:3.4-slim`, `golang.org/x/mod/semver`). Fixed versions looked up in each registry. chi's uncited CVE checked in CVE Services and OSV.
- **Result:**
  - 16 of 16: published, not withdrawn, in the upstream's own repository, naming the package; installed version in range and fixed version out of range by the ecosystem's rules; fixed version released; absent from GitHub's reviewed database (by ID and by cited CVE) and from OSV (by ID and by package and version).
  - CVEs: the six undici advisories cite published CVEs; chi has CVE-2026-118681 from VulnCheck (published 2026-10-28), which it doesn't cite and which OSV holds only as a GIT-range record with no package; the other nine have no CVE.
  - Days in limbo at 2026-11-07 01:33 UTC: 1.6 (undici ×6) to 23.5 (chi), median 4.9. Young because the demo's versions were picked from recent advisories.
  - Context from the live tracker the same morning: 8,803 in limbo, median wait so far 57 days, 2,844 over 3 months.
- **Caveats:** The demo's versions were chosen to be affected, so it shows the mechanism, not prevalence (F-085 is the prevalence evidence). Ranges are as entered by maintainers.
- **Implication:** Every finding Limbowatch reported on the demo is a real, fixed, unreviewed advisory that GitHub's alerts and OSV can't match yet. Evidence and reproduction: `research/2026-11-demo-evidence/`.

### F-092
- **Date:** 2026-11-07 · **Status:** tentative (two weeks of tracker data; a floor)
- **Question:** Is the limbo queue growing or draining: how many advisories enter it per week, and how many leave?
- **Method:** Tracker state at the 2026-11-06 14:35 UTC run (`tracker-data` branch). Inflow: advisories in ecosystems GitHub reviews whose maintainer `published_at` falls in the window, any status. Outflow: `in limbo -> …` events in the window for the same population. Windows of 7 and 14 days ending at the run. Now computed daily as `metrics.json` `flow_7d` and shown on limbo.watch.
- **Result:**
  - 7 days: **744 published** (743 still in limbo, 1 reviewed) against **68 reviewed** out of limbo. About 11 in for every 1 out.
  - 14 days: 1,475 published (1,428 still in limbo, 46 reviewed, 1 duplicate) against 172 reviewed.
  - Of the 744 published in the last week, 743 were still waiting at the end of it.
- **Caveats:** Only watched repos are seen (F-067); a repo polled every 3 to 7 days adds its new advisories late, so the latest days' inflow is undercounted. Outflow counts only advisories the tracker had seen in limbo; GitHub also reviews advisories from other sources. Two weeks is too short to call a trend; this is a rate, not a trajectory.
- **Implication:** At current rates the backlog grows by roughly 600 to 700 advisories a week in the watched repos alone. The site and press page state the weekly numbers with their date instead of a general claim.

### F-093
- **Date:** 2026-11-07 · **Status:** confirmed (validated against official schemas)
- **Question:** Do the watcher's SARIF and CycloneDX outputs pass their official schemas?
- **Method:** `limbowatch scan` on the demo app (16 findings, F-091) with `-o sarif=… -o cyclonedx=…`. CycloneDX: `cyclonedx-python-lib` 9.1.0 `JsonStrictValidator(SchemaVersion.V1_6)`, which bundles the official 1.6 schema. SARIF: `jsonschema` Draft 7 against `https://json.schemastore.org/sarif-2.1.0.json` (fetched 2026-11-07).
- **Result:** Both valid. CycloneDX: 6 components with package URLs and 16 vulnerabilities, each `affects` pointing at a component `bom-ref`; severities from the CycloneDX enum.
- **Caveats:** Valid against the schema is not the same as accepted by every consumer; Dependency-Track, for one, takes its own vulnerability data and uses imported vulnerabilities mainly for analysis states.
- **Implication:** SARIF and CycloneDX can be handed to strict tools. Re-run the check when either format changes.

### F-094
- **Date:** 2026-11-07 · **Status:** confirmed (GitLab docs)
- **Question:** How do `artifacts:expose_as` and JUnit reports behave in GitLab merge requests, and on which tier?
- **Method:** GitLab docs: CI/CD YAML reference (`artifacts:expose_as`), "Unit test reports", and "artifacts:reports:junit".
- **Result:**
  - `expose_as`: "If artifacts:paths only includes a single file, the link opens the file directly. In all other cases, the link opens the artifacts browser." Once per job, at most 10 jobs per merge request; no globs; a directory needs a trailing slash; paths with CI/CD variables aren't shown. Files download unless GitLab Pages is enabled, which lets some types preview in the browser.
  - JUnit: Free, Premium and Ultimate; shown in the merge request Test summary and the pipeline Tests tab. GitLab reads `testcase` `classname` (shown as the suite name), `name`, `file` and `time`, the content of `failure`, `error` and `skipped`, and `system-out` inside a test case. It doesn't read `testsuite` counts, `timestamp` or `line`. "If you have duplicate test names, only the first test is used." Files under 30 MB each, 100 MB per job. Reports don't change the job's status.
- **Caveats:** The docs don't say whether skipped tests are listed in the Test summary.
- **Implication:** The component writes every report into `limbowatch/` and links that folder; JUnit uses the lockfile path as `classname` and the advisory, severity, package and version as the name, so names don't collide across lockfiles; the job's exit code, not the JUnit file, fails the pipeline.
- **Sources:** [artifacts:expose_as](https://docs.gitlab.com/ci/yaml/#artifactsexpose_as), [Unit test reports](https://docs.gitlab.com/ci/testing/unit_test_reports/), [artifacts:reports:junit](https://docs.gitlab.com/ci/yaml/artifacts_reports/#artifactsreportsjunit)

### F-095
- **Date:** 2026-11-07 · **Status:** confirmed (observed; GitLab CI lint API)
- **Question:** Why did the demo's GitLab pipelines fail before any job ran?
- **Method:** Pipelines 3039387630 and 3039387670 on `limbowatch/demo-app` failed at creation. `POST /api/v4/projects/88619082/ci/lint` with the same `include: remote:` of the component template.
- **Result:** "header:spec config description is too long (maximum is 256 characters)". After shortening the description, the same lint returned `valid: true`.
- **Caveats:** GitLab's docs page for `spec:description` doesn't state the limit; it surfaced only on load.
- **Implication:** A too-long component description breaks every pipeline that includes it, before any job runs. `tests/test_integrations.py` now checks the limit, and that every declared input is used.

### F-096
- **Date:** 2026-11-07 · **Status:** confirmed (observed on a real pull request)
- **Question:** Does GitHub keep every workflow-command annotation a step prints?
- **Method:** `limbowatch/demo-app` pull request #1 (67 findings), action printing one annotation per finding. `GET /repos/limbowatch/demo-app/commits/{sha}/check-runs` and `GET /repos/limbowatch/demo-app/check-runs/{id}/annotations`.
- **Result:** The `scan` check run kept 32 annotations: 10 errors, 10 warnings, 10 notices, plus GitHub's own 2. The rest were dropped without notice, including the high-severity dnspython finding. The code scanning check run (SARIF) kept all 51 alerts for scapy.
- **Caveats:** GitHub documents a limit of 10 per level per step; the job total may also be capped.
- **Implication:** Annotations are now one per affected package (7 on the demo instead of 67), error if any of its findings fails the build. SARIF stays one result per finding.

### F-097
- **Date:** 2026-11-07 · **Status:** confirmed (observed)
- **Question:** What did the first release (0.1.0a1) and its demo screenshots turn up?
- **Method:** `limbowatch scan --color always` piped to a file; the release workflow on tag `v0.1.0a1`; PyPI JSON API and `GET https://pypi.org/integrity/limbowatch/0.1.0a1/limbowatch-0.1.0a1-py3-none-any.whl/provenance`; GitLab GraphQL `ciCatalogResource(fullPath: "limbowatch/limbowatch-component") { versions }` after pushing tag `0.1.0-alpha.1`.
- **Result:**
  - `click.echo` (under `typer.echo`) strips ANSI codes when stdout isn't a terminal, unless called with `color=True`. CI logs are pipes, so the table had no colour in GitHub Actions or GitLab CI despite `--color`. Fixed by passing the colour decision through.
  - PyPI serves both packages as 0.1.0a1 with "Development Status :: 3 - Alpha"; the provenance endpoint returns 200 (PEP 740 attestations from trusted publishing). The GitHub release is marked as a pre-release.
  - The CI/CD Catalog accepts a pre-release semantic version: `versions` lists `0.1.0-alpha.1`, and `@0.1.0-alpha.1` includes it.
- **Caveats:** Catalog search and `~latest` may prefer full releases; pin the alpha version explicitly.
- **Implication:** The alpha is installable as `pipx install limbowatch-cli==0.1.0a1`, `limbowatch/limbowatch/integrations/action@v0.1.0a1` and `limbowatch-component/limbowatch@0.1.0-alpha.1`; both demos now use these.

### F-098
- **Date:** 2026-11-07 · **Status:** tentative (one month of tracker data; GitHub's figure is from June 2026)
- **Question:** How much of GitHub's repository-advisory volume does the tracker see, and where does what it sees come from?
- **Method:** Tracker state at the 2026-11-06 14:35 UTC run (`tracker-data` branch): `repos.jsonl` (`sources` per repo, poll status, advisory count) and `advisories.jsonl` (`published_at`, all ecosystems). Weekly volume compared with GitHub's statement in F-035 ("more than 5,000/week").
- **Result:**
  - Watchlist 18,678 repos, all polled at least once (200: 13,430; 304: 4,968; 404: 280). By source (a repo can have several): dependencies of the 100 most-starred projects 12,406 (7,538 only from there); upstreams of the October report's projects 5,613 (965 only); named in a GitHub-assigned CVE 5,037 (2,242 only); origin of a reviewed advisory 3,617 (783 only).
  - 5,571 watched repos have at least one published advisory, 43,044 advisories in all. By the source of their repo: GitHub-assigned CVEs 36,276, reviewed-advisory origins 27,313, top-100 dependencies 4,251, October-report upstreams 2,704 (overlapping).
  - Newly published advisories seen, all ecosystems: 1,188 in the 7 days to 2026-11-06, 2,496 in 14 days, 4,507 in 28 days: about 1,100 to 1,250 a week. Against GitHub's "more than 5,000/week", that is roughly **1 in 4**.
- **Caveats:** GitHub's figure is from June 2026 and may count differently (for example, advisories later withdrawn). Repos checked every 3 to 7 days add new advisories late, so the latest week is undercounted. Coverage of what real projects depend on is much higher than 1 in 4: the October projects' upstreams were almost all watched (F-085).
- **Implication:** Most advisories are found through earlier advisory activity (CVEs GitHub assigned, reviewed advisories), not through the dependency seeds. The blind spot is a repo whose first advisory has no CVE and isn't reviewed yet. The site states the watchlist by source and this estimate, with its date.

### F-099
- **Date:** 2026-11-07 · **Status:** tentative (sample of about 1,000 repos; yields vary widely by repo)
- **Question:** How many source repos do the top packages of each ecosystem map to, how many are already watched, and what would the rest add (Q20)?
- **Method:** `research/2026-11-coverage/measure.py`. Top 50,000 packages per ecosystem from `GET https://packages.ecosyste.ms/api/v1/registries/{registry}/packages?sort=dependent_repos_count&order=desc&per_page=1000` (npm, PyPI, Go, Maven, crates.io, NuGet, RubyGems, Packagist; anonymous, 5,000/h); `repository_url` parsed for GitHub; compared with the tracker watchlist (tracker-data, 18,678 repos). A seeded random sample of 150 unwatched repos per ecosystem from the top 10,000, polled with `GET /repos/{repo}/security-advisories?state=published`; each advisory found checked with `GET /advisories/{ghsa}` and OSV `GET /v1/vulns/{ghsa}`.
- **Result:**
  - Already watched, top 1,000 / 10,000 / 50,000: npm 97/58/19%, crates.io 86/27/6%, PyPI 59/21/5%, Go 43/12/3%, RubyGems 26/5/1%, Maven 12/5/3%, Packagist 6/2/1%, NuGet 3/1/0%.
  - Not watched: about 3,300 repos in the top 1,000s, 45,000 in the top 10,000s, 250,000 in the top 50,000s (per ecosystem, before removing repos shared across ecosystems).
  - Usage falls fast: the 10,000th PyPI package has 61 dependent repos, the 50,000th has 3.
  - Sample (1,048 answered; 103 returned 301 because the repo moved, 41 returned 404): 8 repos with published advisories, **30 advisories, all 30 absent from both GitHub's reviewed database and OSV**; 23 in reviewable ecosystems, 7 with none. By ecosystem: Maven 21 (commonmark-java 8, zstd-jni 12, mxparser 1), PyPI 5 (svglib), Go 3 (go-slug, phonenumbers), RubyGems 1 (jekyll-feed); npm, crates.io, NuGet and Packagist 0.
  - Rough yield for the 45,000 unwatched top-10,000 repos, scaling each ecosystem's sample: on the order of 1,000 advisories in limbo, mostly Maven, PyPI and Go. The sample is small and a few repos hold most advisories, so this is an order of magnitude, not a count.
- **Caveats:** ecosyste.ms ranks by dependent repositories it has indexed; its `repository_url` comes from registry metadata, unverified. 301 responses (moved repos) weren't followed here, which undercounts slightly. Packages that share a monorepo count once.
- **Implication:** The seeds came from a few popular projects, so npm, crates.io and PyPI are well covered at the top and NuGet, Packagist, Maven and RubyGems barely at all. The unwatched repos hold real advisories in limbo in widely used packages. Watching the top 10,000 per ecosystem costs about 45,000 first polls (roughly two weeks at the tracker's current budget of 3,500 a run, or a few days with a larger one); re-checks are mostly free 304s (F-003). The top 50,000 is five times that for a long tail of packages with few users.

### F-100
- **Date:** 2026-11-07 · **Status:** confirmed for the observations; tentative for the cost model (instrumentation added the same day)
- **Question:** What did watching the top 1,000 packages per ecosystem add on its first run, how close to a release are advisories published (Q21), and why has the tracker hit its budget every run since 2026-11-04?
- **Method:**
  - Tracker run 42362625877 (manual, 2026-11-07 10:08 UTC, `--max-new 2500`, budget 3,500) on the new seed `tracker/seeds/top-packages.txt`; state read back from `tracker-data`. Six of the advisories found checked with `GET /advisories/{ghsa}` and OSV `GET /v1/vulns/{ghsa}`.
  - `research/2026-11-coverage/release_timing.py`: 300 advisories published in the 30 days to 2026-11-07 with one npm, PyPI, Go, Maven, crates.io or NuGet package; release times from deps.dev `GET /v3/systems/{system}/packages/{name}`.
  - ETags: 350 repos (150 daily tier, 100 three-day, 100 weekly) fetched twice 90 minutes apart, the second time with `If-None-Match`; 150 ETags 16 days old from the October research cache (same token) sent back to `/repos/{repo}/security-advisories?state=published&per_page=100`, comparing advisory IDs and `updated_at` when the answer was 200. The tracker's `poll_order()` run on the current state.
- **Result:**
  - **First stage:** 2,500 of the 3,342 new repos checked; 58 have published advisories, **109 advisories, all unreviewed and published in 2026, 108 of them since August** (RubyGems 35, Maven 23, NuGet 17, Packagist 10, PyPI 9, Go 9; e.g. a critical one in googleapis/google-api-java-client, mongodb drivers, dalli, net-ssh, padrino). Six checked: none is in GitHub's reviewed database or OSV.
  - **Release timing (Q21):** of 282 advisories with release data, **71% have a release of their package within a day, 79% within 3 days, 86% within 7 days**; in 82% the nearest release came first (the fix ships, then the advisory).
  - **ETags:** GitHub's ETags depend on the token (the same repo gives different ETags to different tokens) and a weak ETag (`W/"…"`, sent when the client accepts gzip) earns a 304 like a strong one. After 90 minutes all 150 daily-tier repos returned 304. After 16 days, all 50 repos without advisories returned 304; of 100 with advisories, 52 returned 304, 12 had changed advisories, and **36 returned 200 with the same advisory IDs and `updated_at`**: something else in the list changed.
  - **Budget:** since 2026-11-04 every run used its 3,500 counted requests, with 304 rates of 1–44% (95–98% before). 3,514 quiet seed repos were last checked on 2026-10-28 with an older token, so they have no usable ETag; they had waited 10 days for a weekly check. On the current state they come next in the order, after the 860 remaining new repos, so the next two runs refresh them.
- **Caveats:** Run reports kept only totals, so the 2026-11-04 to 11-06 spending can't be attributed per tier after the fact; from 2026-11-07 each run records polls per tier and outcome (`by_tier`, including polls sent without a usable ETag). The 16-day ETag sample is small.
- **Implication:** The expansion finds real advisories in limbo where coverage was weakest. Re-checks of repos with advisories aren't as free as assumed (about a third cost a full request after two weeks), and a token change makes every ETag useless until each repo is polled once. Before adding the top 10,000 (about 42,000 more repos), the per-tier numbers from the next runs set the budget and `--max-new`. Release-triggered checks would catch most new advisories within days of the fix release and cut blind re-polling; they are a candidate for the next part of Phase 5.

### F-101
- **Date:** 2026-11-07 · **Status:** confirmed (live probes, about 18:45 UTC)
- **Question:** Is there a source of "this package just released" for each ecosystem, so the tracker could check a repo after its package releases (Q21, F-100)?
- **Method:** `GET https://packages.ecosyste.ms/api/v1/registries/{registry}/packages?sort=latest_release_published_at&order=desc&per_page=1000` for the eight registries (span of the latest 1,000 packages); `GET https://index.golang.org/index?since={1h ago}&limit=2000`; `GET https://packagist.org/metadata/changes.json?since={1h ago, in 1/10,000 s}`. Also tried ecosyste.ms `/registries/pypi.org/versions` (500 after 30 s) and `/recent_versions` (404).
- **Result:**
  - ecosyste.ms's `latest_release_published_at` sort is current to within minutes for npm (the latest 1,000 packages span 1.1 h: about 22,000 releasing packages a day), PyPI (7,600/day), NuGet (5,000/day), crates.io (1,700/day), Maven (660/day) and RubyGems (400/day); 76–99% of those packages name a GitHub repo.
  - For Go and Packagist that sort is useless (the latest 1,000 span years). Their own feeds work: the Go module index returned 2,000 module versions for the last hour (including pseudo-versions such as `v0.0.0-20261107174219-…`, which aren't releases), and Packagist's change feed 375 `update`/`delete` actions (including `~dev` branches).
- **Caveats:** Volumes are from one hour or one page; they vary by weekday. ecosyste.ms is a third party (CC BY-SA data, anonymous limit 5,000/h) and its version-level endpoints failed here.
- **Implication:** A daily run can collect every release in all eight ecosystems with about 40 requests to ecosyste.ms plus paging the Go index and Packagist's feed. Release-triggered checks are feasible; the design is in `docs/RELEASE_CHECKS.md`.

### F-102
- **Date:** 2026-11-07 · **Status:** confirmed (one live collection; a single day)
- **Question:** What does release collection cost, and how many releases hit the watchlist each day?
- **Method:** `Tracker.collect_releases` on a copy of the tracker state (44,460 repos, tracker-data 2026-11-07 18:43), against the live feeds for the 24 hours to about 19:20 UTC, `release_min_dependents=100`; then `poll_order()` on the result.
- **Result:**
  - 55,661 releases in 304 seconds, every feed complete: npm 22,888, Go 19,020 (tagged versions), PyPI 5,381, NuGet 4,715, crates.io 1,553, Packagist 1,538, RubyGems 470, Maven 96.
  - **375 watched repos released** (npm 124, Go 79, PyPI 78, Packagist 51 by name, RubyGems 18, NuGet 13, crates.io 11, Maven 1); 73 of their checks were already due.
  - **76 unwatched repos** whose packages have at least 100 dependent repositories released (npm 58, PyPI 17, crates.io 1) and would join the watchlist.
- **Caveats:** One day. Maven's count is far below the 660 a day in F-101's page span, so it varies or ecosyste.ms lags for Maven. Go and Packagist give no dependent counts, so their unwatched repos aren't added.
- **Implication:** Release-triggered checks cost a few hundred GitHub requests a day and about 5 minutes of run time. Checking popular unwatched packages adds tens of repos a day, not thousands.

### F-103
- **Date:** 2026-11-07 · **Status:** confirmed (live lookups and one real project)
- **Question:** Can the watcher map Composer, Hex, Pub and Swift packages to their repos, and Maven packages deps.dev can't, and what does that change on a real project?
- **Method:** `GET https://repo.packagist.org/p2/{vendor}/{name}.json` (first version's `source.url`); `GET https://packages.ecosyste.ms/api/v1/registries/{hex.pm|pub.dev}/packages/{name}` (`repository_url`); Maven Central POMs `GET https://repo1.maven.org/maven2/{group}/{artifact}/{version}/{artifact}-{version}.pom` (`<scm>`, then `<parent>`); Swift names read as `github.com/owner/repo`. Then `limbowatch scan` on Mobilizon's `mix.lock` (framagit.org/framasoft/mobilizon, 169 lines, 162 Hex dependencies; redirects to framagit.org/kaihuri/mobilizon) before and after, `--fail-on none`; changed findings checked against the installed versions and with `GET /advisories/{ghsa}` and OSV.
- **Result:**
  - Mapped: laravel/framework, symfony/http-foundation, guzzlehttp/guzzle (→ guzzle/guzzle) via Packagist; phoenix, plug via ecosyste.ms (hex.pm); http, provider via pub.dev; swift-nio from its URL. Before, all four ecosystems returned "no mapper".
  - io.netty:netty-codec-http has no `<scm>` in its own POM; its parent netty-parent names github.com/netty/netty. org.apache.commons:commons-lang3's POM names gitbox.apache.org, reported as "not GitHub".
  - Mobilizon: dependencies checked by name only **162 → 7**; findings 43 → 37. **16 removed** were all "possibly affected" (no Hex comparator before); the installed versions are at or after the fix (mint 1.10.1, plug 1.20.3, bandit 1.12.5, postgrex 0.22.4, oidcc 3.9.0). **10 added** are certain, from repos the tracker doesn't watch, polled during the scan: jose 1.11.12 (8, potatosalad/erlang-jose), ssl_verify_fun 1.1.7, h2 0.12.3; the three checked are in neither GitHub's reviewed database nor OSV.
- **Caveats:** One project. Packagist's newest-version source URL may differ from older versions' repos; ecosyste.ms URLs are unverified registry metadata. POM properties in a parent version (`${revision}`) stop the parent walk rather than guess.
- **Implication:** Elixir, Dart, Swift and PHP projects now get the same upstream check as npm or PyPI ones. Hex ranges are evaluated instead of reported as possible, which removes false alarms. The README's ecosystem list and `--no-upstream` text needed no change; the guide lists the new sources.

### F-104
- **Date:** 2026-11-07 · **Status:** tentative (backtest on history; the routine delay is modeled, not observed)
- **Question:** Would release-triggered checks have found the last month's advisories sooner than the routine schedule, and what would moving quiet repos to a 30-day re-check cost (docs/RELEASE_CHECKS.md, steps 3 and 4)?
- **Method:** `research/2026-11-coverage/release_backtest.py`: advisories in the tracker state published 2026-10-08 to 2026-10-31 (each with 7 days to be found) with one package deps.dev knows (npm, PyPI, Go, Maven, crates.io, NuGet, RubyGems); release times from deps.dev; a release check at 20 hours and 3 days minus 2 hours after each release. The repo's tier at publication comes from its earlier advisories (daily if one was still unreviewed, every 3 days if it had others, weekly if none); routine delay is half the interval on average.
- **Result:**
  - 1,752 advisories, 1,672 with release data. Release checks would catch **85% (daily tier), 86% (3-day tier) and 88% (weekly tier)** within 7 days, at a median of 0.77–0.83 days after publication.
  - Daily tier (1,455 advisories, 87% of all): routine checks (0.5 days on average) are already quicker; release checks add nothing there, and that tier stays daily.
  - 3-day tier (151): 121 found sooner than the routine 1.5 days.
  - Weekly tier (66): 58 caught, 55 sooner than the routine 3.5 days. With quiet repos re-checked every 30 days plus release checks, the average delay goes from 3.5 to **2.6 days**; 55 found sooner, **11 later** (the 8 not caught by a release would wait about 15 days on average).
- **Caveats:** The routine delay assumes checks fall evenly in time and the budget never runs out (it did, 2026-11-04 to 11-06, F-100). The weekly-tier sample is small (66). Tiers are inferred from advisory history, not from the tracker's schedule at the time. Packagist isn't covered by deps.dev, so Composer advisories are left out.
- **Implication:** Most new advisories come from repos that already have advisories and are checked daily or every 3 days. For quiet repos, which are about three quarters of the watchlist, release checks find advisories sooner on average even with a 30-day routine check, and free most of the weekly re-check cost for the top-10,000 expansion. The price is 11 of 1,672 advisories (0.7%) found later.

## Archive

(Superseded and refuted entries move here during cleanup.)

### F-039
- **Date:** 2026-10-21 · **Status:** superseded by [F-073](#f-073) and [F-074](#f-074) (the cache directory is now `osv-scalibr/`; scanning against an extra database works offline today; the download host is configurable in SCALIBR)
- **Question:** Can OSV-Scanner consume a custom/additional advisory database (e.g. a Limbowatch "limbo feed")?
- **Result:** Not as a documented feature.
  - Offline mode reads `{OSV_SCANNER_LOCAL_DB_CACHE_DIRECTORY or os.UserCacheDir or os.TempDir}/osv-scanner/<ECOSYSTEM>/all.zip`, populated by `--download-offline-databases` from `https://osv-vulnerabilities.storage.googleapis.com/<ECOSYSTEM>/all.zip`.
  - No flag or documented path exists for adding custom records.
- **Implication:**
  - A limbo feed should be published as standard OSV-schema JSON, which is easy for any tool to consume.
  - Direct OSV-Scanner use needs an upstream feature request (custom local DB / extra source), not a hack into its cache.
- **Sources:** [OSV-Scanner offline mode](https://google.github.io/osv-scanner/usage/offline-mode/)

### F-061
- **Date:** 2026-10-26 · **Status:** superseded by [F-064](#f-064) (counts from a half-polled watchlist; F-064 is the first full pass. The implications stand and are implemented)
- **Question:** What does the tracker see on its first real runs?
- **Method:**
  - Watchlist: 8,827 repos = 5,613 seed (dependency upstreams of the 15 report projects) + 3,587 reviewed-origin repos (F-057), 373 in both.
  - Two runs, 2026-10-26 08:13–08:30 UTC. The reviewed list was synced in full (37,219). **4,388 repos polled** (budget-limited, 1,857 with advisories), 12,183 repo advisories.
- **Result:**
  - **2,966 in limbo in ecosystems GitHub reviews:**
    - median age 54 days; 1,018 ≤ 30 days, 712 > 90 days, 147 > 1 year;
    - CVE: 1,917 no CVE anywhere, 794 published & cited, 243 reserved (RBP);
    - ecosystems: Go 1,306, PyPI 767, npm 670, Maven 609, Packagist 549, NuGet 331, crates.io 220.
  - **1,947 more are likely permanent** (free-text or unreviewed ecosystems: `other` 973, bottlerocket 452, c/c++ 127, docker images, …): median age 257 days, 935 older than 1 year.
  - 133 duplicates (same CVE reviewed under another GHSA).
  - Live spot-check: 25 of 25 random limbo advisories (20 pending, 5 permanent) return 404 from the global API.
  - ETags: 0 of 3,889 polls returned 304 in the second run. Every repo it polled was new to the state, so this doesn't test Q11 yet.
- **Caveats:** About half the watchlist was unpolled at the time; numbers are a floor and will rise. The reviewed-origin repos skew toward repos that use advisories heavily (e.g. bottlerocket).
- **Implication:**
  - The headline must separate pending (reviewable) from likely-permanent limbo, or the long tail of never-reviewed ecosystems dominates.
  - Old pending advisories in reviewable ecosystems (147 > 1 year) suggest review may never come for some even there; track separately once lag data accumulates.

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

