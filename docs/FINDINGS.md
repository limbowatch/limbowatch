# Limbowatch Findings Report

> Formerly *GhostCVE*; renamed 2026-10-21 (see [F-037](#f-037)). Log entries before that date use the old name and the term "ghost" for what is now called **limbo** (published, not yet reviewed). Their results are unchanged.

What we've verified or measured while building Limbowatch. Maintenance rules are in [CLAUDE.md](../CLAUDE.md#findings-report-docsfindingsmd).

Last summarized: 2026-11-13 (end of Phase 8: the website redesign and the public proof, F-157 to F-168; reviewed and closed). Before that: 2026-11-12 (end of Phase 7: GitHub as a host, released as 0.1.0a10 to 0.1.0a12, F-145 to F-155), 2026-11-11 (end of Phase 6: C/C++ and other upstream sources, a feed that covers advisories without a package; released as 0.1.0a8, F-140 to F-142; a second review, tests and coverage in F-143, released as 0.1.0a9 in F-144), 2026-11-10 (end of Phase 5), 2026-11-07 (end of Phase 4).

## Summary

Current understanding at the end of Phase 8 (2026-11-13), with entries linked. Points 1–14 come from the Phase 1 research (2026-10-21 to 10-25), 15–20 and 32 from the live tracker (Phase 2, measured again 2026-11-07), 21 from Phase 3, 22–31 from the watcher (Phase 4), 33–46 from Phase 5, 47–51 from Phase 6, 52–56 from Phase 7, 57–65 from Phase 8. Numbers are dated; review backlogs drift.

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
17. **The backlog is growing (tentative).** In the week to 2026-11-06, 744 advisories were published into limbo and 68 were reviewed out, about 11 in for each 1 out; over 14 days, 1,475 in and 172 out ([F-092](#f-092)); in the 7 days to 2026-11-10, 805 in and 51 out, with 3,033 in limbo for more than three months ([F-120](#f-120)). Earlier single days (10-29, 10-30) showed inflow of 93 and 71 against outflow of 88 and 20 ([F-067](#f-067), [F-070](#f-070)). Advisories that did get reviewed had waited a median 11 days. A rate, not yet a trend: the site shows the weekly numbers with their date.
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
28. **Without Limbowatch, nothing reports these.** On the demo app, GitHub's Dependabot alerts and OSV-Scanner reported 0 of the 16 advisories Limbowatch found; all 16 were rechecked against primary sources and are real, fixed and unreviewed, 1.6 to 23.5 days in limbo ([F-090](#f-090), [F-091](#f-091)). On 13 real projects (2026-11-08), Dependabot raised 2,020 alerts and covered **0 of 1,080 confirmed findings** in limbo, every one in GitHub's own dependency graph ([F-112](#f-112)). The same check found 5 Limbowatch false positives, from Go modules nested under another module's path ([F-113](#f-113)); the tracker now resolves each Go path's module through the Go module proxy, which removes them ([F-114](#f-114), in production since 2026-11-09, [F-117](#f-117)). Three days on, the demo's advisories were still invisible to Dependabot ([F-111](#f-111), [F-119](#f-119)).
29. **The outputs are standard.** SARIF 2.1.0 and CycloneDX 1.6 validate against the official schemas ([F-093](#f-093)).
30. **Released as an alpha, 0.1.0a1 (2026-11-07) to 0.1.0a9 (2026-11-11); 0.1.0a7 and 0.1.0a8 are yanked.** PyPI with PEP 740 attestations; GitHub pre-release; the CI/CD Catalog accepts pre-releases like `0.1.0-alpha.1` ([F-097](#f-097)). 0.1.0a2 adds the image and the reworked component (point 39); 0.1.0a5 the range-parser fixes (point 41, [F-126](#f-126)); 0.1.0a6 org-wide mode and Maven resolution (points 45–46, [F-133](#f-133)); 0.1.0a7 upstream sources (points 47–51, [F-140](#f-140)), replaced by 0.1.0a8 and 0.1.0a9 after two independent reviews ([F-141](#f-141) to [F-144](#f-144)).
31. **Both demos stay as live regression tests:** `limbowatch/demo-app` on GitHub (public, PR #1) and GitLab (private, MR !1) run the released action and component ([F-088](#f-088), [F-097](#f-097)).

**Coverage (measured 2026-11-07)**

32. **The tracker sees roughly 1 in 4 of all repository advisories** (before Phase 5's expansion, point 33). About 1,100 to 1,250 newly published a week, in all ecosystems, against GitHub's "more than 5,000/week". 18,678 watched repos; most advisories come from repos found through earlier advisory activity (GitHub-assigned CVEs, reviewed-advisory origins), not from the dependency seeds. Coverage of what real projects depend on is much higher ([F-098](#f-098), [F-085](#f-085)). Raising it is Phase 5's first step.

**Phase 5: coverage, release checks, watcher completeness, org-wide mode (2026-11-07 to 11-10)**

33. **The watchlist missed most popular packages outside npm, crates.io and PyPI.** Of the top 1,000 packages per ecosystem, 3% (NuGet) to 97% (npm) were watched; for the top 10,000, 1% to 58%. About 45,000 unwatched repos sat in the top 10,000s, and a sample of them held 30 advisories in limbo, all in no database ([F-099](#f-099)). Adding the top 1,000 found 153 unreviewed advisories on the first pass ([F-100](#f-100)). Both waves of the top 10,000 are done: **64,021 watched repos on 2026-11-10, every one polled at least once.** The tail is thin (about 1% of the new repos have an advisory), but nearly all its advisories are in limbo; live totals 9,773 in limbo and 14,546 likely permanent ([F-121](#f-121)).
34. **Advisories follow releases.** 71% of advisories had a release of their package within a day and 79% within 3 days; in 82% the release came first, so the maintainer ships the fix, then publishes ([F-100](#f-100)). Every covered ecosystem has a release feed ([F-101](#f-101)). Collecting them costs about 40 requests a day plus a few hundred GitHub checks; popular unwatched packages add tens of repos a day ([F-102](#f-102)).
35. **Re-checks aren't free.** About a third of repos with advisories answer 200 after two weeks with no visible change, and a token change voids every ETag until each repo is polled once. In steady state a run spends about 1,600 counted requests on re-checks ([F-100](#f-100)).
36. **Release checks let quiet repos wait 30 days (tentative).** On the last month's advisories, release checks would catch 85–88% within 7 days, at a median of 0.8 days. Repos without advisories, re-checked every 30 days instead of weekly plus release checks, find new advisories sooner on average (3.5 → 2.6 days); 11 of 1,672 (0.7%) would be found later ([F-104](#f-104)). Adopted 2026-11-08.
37. **Release feeds lag, and some lag badly.** ecosyste.ms's Maven data is weeks behind per package, and no bulk Maven feed is current: Maven Central's index is rebuilt about every two weeks and search.maven.org stopped in June 2026. Each package's `maven-metadata.xml` is current and supports ETags, so the tracker polls the top 7,388 Maven packages there once a day; on its first live pass it found over twice as many releases in watched repos as ecosyste.ms ([F-105](#f-105), [F-108](#f-108), [F-110](#f-110)). A feed's cursor must follow the feed, never the clock ([F-105](#f-105)).
38. **The watcher maps more ecosystems.** Composer (Packagist), Hex and Pub (ecosyste.ms), Swift (the package URL) and Maven's `<scm>` fallback. On an Elixir project, name-only dependencies fell from 162 to 7, removing 16 false alarms and finding 10 real advisories ([F-103](#f-103)).
39. **The GitLab component runs a pinned, attested image.** Jobs take about 21 s instead of 34 s, on amd64 and arm64 ([F-107](#f-107)). GitLab Ultimate ingests SARIF only from a job that succeeds, so Ultimate mode passes the scan job and applies `fail_on` in a separate gate job. Job variables work in `rules:if`, and nested `rules` lists are flattened ([F-106](#f-106)). A new ghcr.io package starts private ([F-107](#f-107)).
40. **The exit code is a contract.** An uncaught Python exception exits 1, which CI reads as findings; the CLI now maps any crash to 2. Found while designing the component's `allow_failure`, which relies on 1 meaning findings (CHANGELOG 0.1.0a2).
41. **Independent recomputation finds what tests don't.** Rechecking the report and the tracker against primary sources found a range-parser error in about 1% of ranges (over- and under-matching) and a rule that linked CVEs to advisories their description merely mentions (1.6% of uncited links). Both are fixed, the October report is recomputed, and `scripts/audit.py` runs before every release ([F-120](#f-120), [F-123](#f-123), [F-124](#f-124), [F-126](#f-126)).
42. **A browser can run the check.** limbo.watch checks a package and its deps.dev dependency tree in the visitor's browser with the CLI's verdicts, and says so when it saw only the package ([F-118](#f-118)).
43. **Distribution.** The Action runs the image on Linux runners and falls back to pip elsewhere ([F-109](#f-109)); it's in GitHub Marketplace and the component in the GitLab CI/CD Catalog, and both give the CLI's results on the demo ([F-127](#f-127), [F-128](#f-128)). GitLab never shows GPG-signed tags as verified ([F-115](#f-115)).
44. **Running costs nothing while the repo is public.** The binding limits are the PAT's 5,000 requests an hour and run length ([F-116](#f-116)). The Actions cache had filled with image-build blobs and is now kept small ([F-122](#f-122)); site rollouts no longer drop requests ([F-125](#f-125)).
45. **Org-wide mode works on real groups.** `limbowatch watch` checks a GitLab group, a Gitea/Forgejo org or git URLs in one run: 50 projects of `gitlab-org/security-products/analyzers` in about 3 minutes, with 465 GitHub polls instead of 784 when each project is scanned alone ([F-130](#f-130)). GitLab lists projects shared into a group unless told not to, and Gitea answers a private org with an empty list, so an empty source is an error ([F-129](#f-129)). It also found an OSV-Scanner error format that made `scan` give up on any project with two unreadable lockfiles of one kind; fixed ([F-131](#f-131)).
46. **Maven needs resolving, Gradle a lockfile.** Run offline, OSV-Scanner checked 3 of the 171 dependencies Maven resolves for spring-petclinic and never said the rest were missing. Its resolver, which contacts only deps.dev and Maven Central, matched Maven exactly on two Spring Boot projects and found 37 advisories in limbo that the offline inventory missed; the inventory now resolves `pom.xml` by default, separately from every other file. It still misses profiles activated by JDK version, and modules that depend on unreleased siblings; those, and Gradle builds without a lockfile, are reported as unchecked. Gradle lockfiles are read completely ([F-132](#f-132)).

**Phase 6: upstream sources and advisories without a package (2026-11-10 to 11-11)**

47. **Most of the limbo feed named no package.** 14,785 of 24,561 records (60%) came from advisories whose ecosystem OSV doesn't have (`other`, `c`, `c/c++`, …), so the feed had left them without `affected` entries; 14,578 still gave versions. 1,472 of them come from 95 libraries that vcpkg, the Bazel Central Registry or ConanCenter build from (FreeRDP, ImageMagick, libheif, vim, OpenEXR), the rest mostly from applications ([F-135](#f-135), [F-136](#f-136)).
48. **Their fixes are tags.** 83% of the versions those advisories name are tags in the repo (exactly, `v`-prefixed, or by the numbers, as in `bacnet-stack-1.6.0`), so the feed gives 67% of such entries OSV GIT ranges, with the commits `git ls-remote` lists, at no API cost; ranges that list only exact versions are left as text ([F-136](#f-136), [F-138](#f-138), [F-141](#f-141)).
49. **C/C++ projects take code by git and archive, and offline OSV-Scanner reads none of it.** In 85 popular C/C++ projects: submodules (17 projects), CMake fetches (20; FetchContent 17), Bazel (5), vcpkg (5), vendored copies (22); 44 declare none of these (system libraries, or nothing). The watcher's detectors find 857 upstream sources in 33 of them, 89% with a repo and a tag or commit after registry lookups (BCR `source.json`, vcpkg baseline and portfile, the ConanCenter remote; conan-center-index on GitHub keeps only current versions) ([F-136](#f-136), [F-137](#f-137)).
50. **A commits-only clone answers "does this commit contain the fix?"** exactly, on any host, with no API quota (0.4–22 MB, under 3 s). A FreeRDP submodule at 3.10.0 is affected by 228 advisories in limbo, at 3.33.1 by none. Against OSV's own version ranges, 95% of verdicts agree and 1.6% disagree, each traced disagreement a conflict between the advisory and the CVE record; OSV's commit lookup lags its ranges, so it only ever raises a verdict ([F-136](#f-136), [F-138](#f-138), [F-139](#f-139)).
51. **Two silent failures found on the way:** a `conan.lock` failed the whole offline inventory since 0.1.0a1 (OSV-Scanner needs a ConanCenter database, which isn't in OSV's list), and package names in ecosystems Limbowatch doesn't know were all treated as valid, which hid package-less advisories from repository matching. Both fixed ([F-137](#f-137), [F-138](#f-138)). Releasing it, the feed briefly broke every older watcher: entries without a `package` made 0.1.0a1-0.1.0a6 fail for 53 minutes, until they got a `GIT` package; a test and the audit now guard it ([F-140](#f-140)). An independent review then found four silent passes in the verdicts (a fix of an older line clearing a newer one, misread tag versions, trailing letters read as pre-releases, mixed advisories skipped), a crash on malformed manifests and a git config command run; all fixed in 0.1.0a8 with the measurements unchanged ([F-141](#f-141)).

**Phase 7: GitHub as a host (2026-11-11 to 11-12)**

52. **GitHub issues work with the job's own token.** `GITHUB_TOKEN` with `issues: write` creates, labels, comments, closes and reopens; a missing label is created with the issue. The issue list lags a new issue by 3–7 seconds, so overlapping runs could duplicate one; the docs set a `concurrency` group ([F-145](#f-145), [F-147](#f-147)).
53. **GitHub lists only what a token can see, without saying so.** The job's `GITHUB_TOKEN` saw 5 of the org's 18 repos with no error. Org-wide mode notes every case it can tell (no token, no `repo` scope, a fine-grained token, an app token in Actions), and `size` can't tell an empty repo, so emptiness is found at clone time ([F-146](#f-146), [F-147](#f-147)).
54. **Live end to end on a private repo, from the CLI and from the action; an independent review found 12 real bugs before release**, among them empty repos passed as checked, reports lost when issues failed, and a retried POST that could open an issue twice ([F-148](#f-148)). Released as 0.1.0a10, 0.1.0a11 and 0.1.0a12, each with the published action run live ([F-149](#f-149), [F-152](#f-152), [F-154](#f-154)).
55. **A token whose user can't push to the repo opens no GitHub issues.** GitHub silently drops a new issue's labels then, and the repo's `permissions` show it up front for a user's token (`pull` without `push`); the job's `GITHUB_TOKEN` reads all false there but labels fine ([F-150](#f-150)). GitHub Marketplace picks the action's "latest" release by comparing tags as text, so only v0.1.0a10 to a12 are listed; text order breaks again at a20 and at 0.1.0 ([F-151](#f-151), [F-155](#f-155)).
56. **OSV-Scanner 2.7.1 reads the same dependencies as 2.7.0** on 111 projects (236,253 against 236,254), checking npm packages without `resolved` itself and dropping a false yarn `patch:` entry. The comparison found linked local npm packages checked as registry ones in both versions, now decided by the dependency's spec ([F-153](#f-153)).

**Phase 8: the website redesign and the public proof (2026-11-12 to 11-13)**

57. **Remediation clocks mostly start at detection, so limbo delays the deadline with the alert.** SOC 2 leaves the deadline to the company's policy, usually counted from the scanner's alert; CISA's BOD 26-04 counts from identification or a KEV listing; PCI DSS counts one month from the fix's release, so the review wait uses up the deadline itself ([F-156](#f-156), [F-134](#f-134)).
58. **Well-known packages sit in limbo for months with a fix released**, and no scanner database has them: on 2026-11-12, typebox, nats-server, go-openapi/spec, go-toml, mustache, rubyntlm and scapy, high or critical, fixed 41 to 212 days earlier. Some others in limbo (jackson-core, netty-handler, vm2, mistune) aren't silent in practice: a reviewed advisory on the same version already leads past the fix ([F-157](#f-157), [F-158](#f-158)). bundler-audit sees rubyntlm through ruby-advisory-db ([F-162](#f-162)).
59. **The public proof holds:** on the same files Limbowatch reports all 7, OSV-Scanner, `npm audit`, pip-audit and Dependabot none, while every tool reports the 5 old control packages (Dependabot: 95 alerts, all on controls). The job's `GITHUB_TOKEN` can't read Dependabot alerts (403), so the repository keeps a dated snapshot ([F-162](#f-162)). Ranges with one upper bound per release line had hidden affected versions (431 entries), fixed in 0.1.0a13 ([F-159](#f-159) to [F-161](#f-161)).
60. **The redesigned site meets WCAG AA contrast in both themes** after three colours were darkened, and has no horizontal scroll at 390 px. The demo moved from 67 to 63 advisories in limbo as rack's and nokogiri's were reviewed ([F-163](#f-163)).
61. **Maintainer-typed fields could inject Markdown into issues and reports.** 164 ranges in the tracker contain `||`, some contain backticks or link syntax; in a table a `|` cut `>=4.1.0, <=4.1.13 || >=5.0.0, <5.1.1` to its first half, and a backtick could render a link or an @mention in an issue the user's own bot opened. Only a code span stops a mention on GitHub; every such field is now one, checked in GitHub's and GitLab's own renderers ([F-164](#f-164)). The action's `install: python` now installs `uv.lock`'s exact versions with `--require-hashes`.
62. **Layout checks must compare an element with its container,** not only the page with the viewport: the home page's count ran 45–95 px past its column on desktop while the page had no horizontal scroll ([F-165](#f-165)).
63. **The scan sends package names and versions, never files or source code.** With `--no-upstream --no-resolve-maven` it contacts limbo.watch and nothing else, measured through a logging proxy; every host and the option that turns it off are documented and kept in step with the code by a test ([F-166](#f-166)).
64. **GitHub's review queue stalls for days:** no advisory at all was reviewed from 2026-11-07 13:24 to 11-09 16:52 UTC, nor from 11-11 00:47 to 11-12 23:30. The daily report's numbers were right; it now says how many GitHub reviewed overall and names moves between the two counts. The scheduled tracker run starts 6.5–10 hours after its 06:17 UTC slot ([F-167](#f-167)).
65. **Advisory pages are nearly all of the site** (25,730) and were titled with the GHSA ID alone; the sitemap dated every URL with the build day and would have passed 50,000 URLs in about 80 days. Titles now lead with the package, its ecosystem, severity and IDs; the sitemap is an index of dated files. `http://` and `www.` need Cloudflare settings ([F-168](#f-168)).

## Open questions

Open:

- Q3. What share of other-CNA CVEs affecting npm/PyPI/Go packages get package-level coverage in OSV through ecosystem DBs (Go vulndb, PyPA, RustSec)? The tracker stores the CVEs ([F-067](#f-067)); the matching isn't built.
- Q4. How far behind GHSA are the scanner DBs (Trivy DB, Grype DB, OSV-Scanner)? GitLab Advisory DB lag can't be measured because its terms forbid querying it.
- Q5. Is "Not Scheduled" ever an NVD API `vulnStatus` value, or always `Deferred`? ([F-005](#f-005))
- Q6. Does ecosyste.ms's CC BY-SA 4.0 data license constrain Limbowatch? *Partly answered 2026-10-20: share-alike applies to redistributed derived data; use at runtime with a local cache only, with attribution. Revisit before 1.0* ([F-021](#f-021)). *Decided 2026-11-07: the watchlist built from its rankings is published CC BY-SA 4.0 with attribution; advisory data stays CC BY 4.0 (PHASE0_PLAN §13.12).*
- Q7. How do we reliably detect packaging/recipe repos (conan-center-index, homebrew-core, distro packaging) so they aren't treated as upstream? ([F-021](#f-021)) Not addressed in Phase 2: the tracker's seeds come from the research mapper, which has no such filter.
- Q8. How do we detect that a limbo advisory was reviewed under a different GHSA ID when no CVE is shared? The tracker proves duplicates by shared CVE only ([F-048](#f-048)).
- Q10. Under what terms may repository advisory content be redistributed? *Partly answered 2026-10-26: GitHub's terms are silent on repository advisories in limbo; the feed carries factual metadata only* ([F-059](#f-059)). Ask GitHub during outreach.
- Q12. Is review throughput keeping up with inflow? So far no: 744 in against 68 out in the week to 2026-11-06 ([F-092](#f-092)), 805 against 51 in the week to 2026-11-10 ([F-120](#f-120)). Still open: whether that holds over a month, split by ecosystem and severity ([F-067](#f-067), [F-070](#f-070)).
- Q13. Do OSV-Scanner's other matching paths (the osv.dev API) normalize package names beyond PyPI? ([F-069](#f-069))
- Q14. Do the feed's well-formed names exist in their registries? A registry check would catch wrong-but-valid names ([F-069](#f-069)).
- Q15. Can per-branch ranges like `< 1.2.5, < 2.0.3` be converted without guessing where each branch starts, e.g. from the registry's version list? ([F-069](#f-069))
- Q16. Are pending advisories published before 2026 (258 on 2026-10-28) ever reviewed, or did GitHub never backfill them? ([F-064](#f-064))
- Q23. Do Packagist's newest-version source URLs ever point at a different repo than the installed version's? ([F-103](#f-103))
- Q17. How many Go modules on vanity paths (k8s.io, golang.org/x, go.opentelemetry.io) can be mapped to a GitHub repo without deps.dev? 320 Kubernetes dependencies stay checked by name only ([F-085](#f-085)). blindspot keeps a verified list (`docs/go-vanity-coverage.md`, [F-072](#f-072)).
- Q18. Should the tracker's seeds include the upstreams of popular GitLab-hosted projects' Ruby dependencies, so the watcher doesn't need to poll them? ([F-085](#f-085); Phase 5.) *Partly answered 2026-11-10: the repos of the top 10,000 gems are now watched ([F-121](#f-121)); how much of GitLab's 356 polls that removes wasn't measured.*
- Q25. Which Maven builds does the resolver get wrong beyond JDK-activated profiles and unreleased siblings: `<repositories>`, private registries, plugin-managed dependencies? Four projects were checked ([F-132](#f-132)).
- Q28. Is identifying vendored copies (OSV's `determineversion`, which sends file hashes) worth its egress, given that 22 of 85 C/C++ projects vendor code and nothing else says which version ([F-136](#f-136))?
- Q30. Does the GitHub integration work unchanged on GitHub Enterprise Server (API under `/api/v3`) and on GHE.com (data residency)? Neither is tested, and the maintainer has neither (2026-11-12): it waits for a user report. The GitHub docs read for [F-145](#f-145) and [F-148](#f-148) don't name GHE.com's API host; in Actions the job's `GITHUB_API_URL` is used, so both should work from their own Actions.
- Q31. Do labels set at issue creation stick with a fine-grained token or a GitHub App installation token, and what do those tokens' repo `permissions` show? Only a classic token and the job's `GITHUB_TOKEN` were probed; the check after creating still catches a dropped label ([F-150](#f-150)).
- Q22. Does GitHub's "more than 5,000 repository advisories a week" count the same thing as the tracker (published, any ecosystem)? It sets the coverage estimate ([F-035](#f-035), [F-098](#f-098)).

Answered:

- ~~Q29. On GitHub, does issue creation create a label that doesn't exist, and do labels set with `GITHUB_TOKEN` (`issues: write`) stick, or are they "silently dropped"? The watcher finds its issues by label ([F-145](#f-145)).~~ **Answered 2026-11-12: a missing label is created, and labels set with `GITHUB_TOKEN` stick ([F-147](#f-147)).**
- ~~Q27. How often is an upstream verdict wrong when read against the advisory itself?~~ **Answered 2026-11-11: 95% agree with OSV's version ranges, 3% possible, 1.6% disagree, each traced disagreement a conflict between the advisory and the CVE record ([F-139](#f-139)).**
- ~~Q26. For limbo advisories without a package, how often does the patched version map to a tag upstream, and how many of the 1,858 repos are libraries?~~ **Answered 2026-11-11: 95 repos (1,472 records) are libraries in vcpkg, BCR or conan-center; every patched version maps to a tag for 82% of their advisories ([F-136](#f-136)).**
- ~~Q24. Is ecosyste.ms's Maven lag temporary, and is there a primary-source feed of Maven Central releases?~~ **Not temporary: weeks behind per package. No current bulk feed exists; each package's `maven-metadata.xml` is current and supports ETags, and the tracker polls the watched ones daily ([F-108](#f-108)).**
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
- **Date:** 2026-10-22 · **Status:** confirmed (observed). **Partly refutes F-049.** The review-burst detail is corrected by [F-120](#f-120) (Pillow ×11, all on 2026-10-22 15:46–17:01 UTC).
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
- **Date:** 2026-10-22 · **Status:** confirmed (observed). **Supersedes F-041 and F-043** (pre-correction methods, Oct-21 commits); refines F-042 with a newer window. Per-project counts updated by [F-124](#f-124) (corrected range parser).
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
- **Date:** 2026-10-25 · **Status:** confirmed (observed). The "24 gained an uncited CVE" breakdown is corrected by [F-120](#f-120): 21 new, all VulnCheck; the other 3 weren't new links.
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

### F-105
- **Date:** 2026-11-08 · **Status:** confirmed (direct observation; whether the Maven lag is temporary is open, Q24)
- **Question:** Are the ecosyste.ms release feeds current enough for release-triggered checks, run after run?
- **Method:**
  - Tracker run reports of 2026-11-07 19:36 and 2026-11-08 03:43 UTC (`state/runs.jsonl`, `releases` per feed).
  - `GET packages.ecosyste.ms/api/v1/registries/repo1.maven.org/packages?sort=latest_release_published_at&order=desc&per_page=1000`, 2026-11-08 03:55 UTC, with the registry record (`/registries/repo1.maven.org`).
  - Page sizes, gzipped, per_page=100 (same date).
- **Result:**
  - Maven: the first run (24 hours back) saw 88 packages and the second (8 hours) saw 1. The latest 1,000 Maven packages span 2026-11-05 21:00 to 11-07 20:50: 812 dated Nov 6 and 25 dated Nov 7; 16% are `org.mvnpm` repackages of npm modules. The registry record was last updated 2026-11-06 05:03. In F-101 (2026-11-07) the same sort showed about 660 packages a day.
  - The other feeds were current: in 8 hours, npm 5,975, Go 5,071, NuGet 1,710, PyPI 1,639, Packagist 782, crates.io 477, RubyGems 75.
  - Gzipped page sizes: npm 528 KB, PyPI 458 KB and Maven 4.4 MB per 100 packages. Almost all of a Maven page (300 MB per 1,000, uncompressed) is `repo_metadata`.
  - The tracker set each ecosyste.ms cursor to the time of the run, so releases ecosyste.ms lists later with earlier dates were skipped for good.
- **Caveats:** One day of observation. There's no primary-source count of Maven Central releases to compare with: a `solrsearch` query for the last day on search.maven.org returned 0, which says more about the query than about Maven Central.
- **Implication:**
  - Fixed: an ecosyste.ms feed's cursor is now the newest release it returned, never earlier than the previous cursor. Each run re-reads 6 hours before it (`ECOSYSTEMS_OVERLAP`, about 6 extra npm pages). Each feed's `newest` release is in the run report, so a stall shows.
  - While Maven lags, quiet Maven repos are checked every 30 days, the routine fallback. Repos with advisories keep their daily or 3-day schedule. Releases ecosyste.ms lists more than 6 hours late are still missed.
  - Don't widen the overlap to days: Maven pages are large.
- **Sources:** [ecosyste.ms packages API](https://packages.ecosyste.ms/docs), tracker run reports on the `tracker-data` branch.

### F-106
- **Date:** 2026-11-08 · **Status:** confirmed (GitLab doc sources; two behaviors observed with GitLab's CI lint dry run on gitlab.com)
- **Question:** How can the GitLab component show findings in GitLab Ultimate's security features, and how can it add a job only when an input is set?
- **Method:**
  - GitLab doc sources from `gitlab-org/gitlab` master (`doc/ci/yaml/artifacts_reports.md`, `doc/user/application_security/detect/sarif.md`, `doc/ci/yaml/_index.md`, `doc/ci/inputs/_index.md`, `doc/ci/variables/where_variables_can_be_used.md`), read through the GitLab API on 2026-11-08.
  - `POST /projects/88618678/ci/lint` with `dry_run: true, include_jobs: true, ref: main`. Inline configs:
    - a job whose `rules:if` reads a variable set in the job's own `variables`, with the value `"true"` and then `"false"`;
    - a job whose `rules` holds a nested list, with a matching and then a non-matching condition.
- **Result:**
  - **SARIF:** `artifacts:reports:sarif` (Ultimate) puts third-party findings in the pipeline Security tab, the vulnerability report, the security dashboard, the merge request security widget and security policies. Introduced in 18.11; generally available in 19.2.
    - Findings are ingested only when the job succeeds. `allow_failure: true` or `allow_failure:exit_codes` doesn't help: the job still counts as failed. GitLab's advice is to exit 0 and fail elsewhere.
    - A finding is filed as dependency scanning when an identifier is a CVE: a `ruleId` like `CVE-…`, or a rule tag `cve-YYYY-N` or `cve:YYYY-N`. It's filed as secret detection for some CWEs, and as SAST otherwise.
    - Required: `ruleId` and `physicalLocation`. More than half the results unusable and nothing is ingested.
    - Identity is report type + `ruleId` + `file:startLine:endLine`; results without a `region` in the same file collapse into one.
    - Severity comes first from `result.rank`, then `security-severity`, then `level`.
    - Limits: 10 MB, 5,000 results per run, 10 tags per rule.
  - **`allow_failure:exit_codes`:** the job may fail only with the listed codes; any other code fails it as usual.
  - **Job variables in `rules:if`:** work. The job appeared with `"true"` and not with `"false"`. The docs list exceptions for `rules:if`, but job variables aren't among them.
  - **Nested lists in `rules`:** flattened and evaluated. The job appeared when the nested rule matched and not when it didn't.
  - **Inputs:** `spec:inputs:rules` (18.7) makes an input's options and default depend on other inputs. It doesn't add or remove jobs. An array input can be a whole `rules` or `needs` value.
- **Caveats:** The two lint behaviors were observed on gitlab.com only (GitLab 19.x); older self-managed instances weren't tested. SARIF ingestion wasn't observed: the component project has no Ultimate license.
- **Implication:**
  - The component's `security_report` input makes the scan job exit 0 on findings, so GitLab reads its SARIF. A `<job_name>-gate` job then applies `fail_on`.
  - The gate job's rules are `if: $LW_SECURITY_REPORT != "true"` → `never`, then the user's `rules` input as a nested list. So the gate job exists only in Ultimate mode, and only in pipelines where the scan job runs.
  - `allow_failure: true` in the component maps findings (exit 1) to exit 3, which is the only code the job may fail with. A scan that couldn't run (exit 2) still fails the pipeline.
  - SARIF rules carry `cve-YYYY-N` tags, so findings with a CVE are filed as dependency scanning. Most limbo advisories have none and are filed as SAST.
- **Sources:** [artifacts:reports:sarif](https://docs.gitlab.com/ci/yaml/artifacts_reports/#artifactsreportssarif), [SARIF reports](https://docs.gitlab.com/user/application_security/detect/sarif/), [allow_failure:exit_codes](https://docs.gitlab.com/ci/yaml/#allow_failureexit_codes), [spec:inputs:rules](https://docs.gitlab.com/ci/inputs/#define-conditional-input-options-with-specinputsrules), [where variables can be used](https://docs.gitlab.com/ci/variables/where_variables_can_be_used/).

### F-107
- **Date:** 2026-11-08 · **Status:** confirmed (one pipeline on gitlab.com)
- **Question:** Does the reworked component (image, gate job, exit-code-aware `allow_failure`) run on GitLab as designed?
- **Method:** Pushed the component subtree as branch `pro-component` of `gitlab.com/limbowatch/limbowatch-component`. Pipeline 3041549253: `mirror-image` copied `ghcr.io/limbowatch/limbowatch@sha256:1b86fff6…` (the `edge` build, attested by `image.yml`) to the project registry. The component then ran from that commit three ways against `tests/go-sample`: defaults with `fail_on: none`; `security_report: true` with `allow_failure: true`; and `fail_on: none` on a `saas-linux-small-arm64` runner. `check-reports` read the artifacts.
- **Result:**
  - Every job finished. Scan jobs took 21.5 s (amd64) and 29.0 s (arm64), against 34 s for the old install-at-run-time job (F-086). `mirror-image` took 18 s.
  - Ultimate mode: the scan job logged the finding and succeeded, so GitLab can read its SARIF. `limbowatch-ultimate-gate` exited 3 and showed as failed but allowed. The pipeline passed.
  - The setup section is folded (`section_start:…:limbowatch_setup[collapsed=true]`), headed by the Limbowatch and OSV-Scanner versions.
  - `gh attestation verify oci://ghcr.io/limbowatch/limbowatch:edge --owner limbowatch` verified SLSA provenance from `.github/workflows/image.yml@refs/heads/main`.
  - ghcr.io makes a new package private; anonymous pulls got 401 until it was made public in the package settings, which the REST API can't do.
- **Caveats:** No Ultimate license, so SARIF ingestion itself wasn't observed. The exit-2 path was tested in the image smoke test, not in this pipeline.
- **Implication:** The component is ready to release with the image pinned by digest. A new image package needs its visibility set by hand once.

### F-108
- **Date:** 2026-11-08 · **Status:** confirmed (official docs and direct observation)
- **Question:** Is there a current, primary source of Maven Central releases to use instead of ecosyste.ms (Q24)?
- **Method:** Read-only probes on 2026-11-08 around 09:45–10:05 UTC:
  - `repo.maven.apache.org/maven2/.index/nexus-maven-repository-index.properties`;
  - `search.maven.org/solrsearch/select?q=*:*&core=gav&sort=timestamp desc`;
  - Sonatype's docs (REST API guide, Central Search changelog, the 429 FAQs);
  - for 5 popular packages (AWS SDK BOM, jackson-databind, spring-boot, netty-codec-http, guava): `maven-metadata.xml` on repo1.maven.org, with `If-Modified-Since` and with `If-None-Match`; deps.dev `GET /v3/systems/maven/packages/{name}`; ecosyste.ms `/registries/repo1.maven.org/packages/{name}`;
  - then `releases.maven_central` on 300 random packages from the new `tracker/seeds/maven-packages.txt`, twice.
- **Result:**
  - **Maven Central's index:** last modified 2026-10-22. Sonatype: "The index is updated on a roughly two-week cycle".
  - **search.maven.org:** the newest artifact by timestamp is from 2026-06-10, five months stale. Sonatype documents no replacement.
  - **Sonatype's limits:** Maven Central is enforcing consumption limits on high-volume traffic. Tools are asked to cache, avoid repeated downloads, and keep Maven Central out of their runtime path.
  - **`maven-metadata.xml`:** current to the minute. jackson-databind 2.23.0 shows `lastUpdated` 2026-11-08 00:37:44. `If-Modified-Since` is ignored (200), but `If-None-Match` returns 304 with no body; guava's full file is 6,079 bytes.
  - **deps.dev:** current; it already listed jackson-databind 2.23.0, published 00:35:20 UTC. It sends no ETag, and a package is 30 KB.
  - **ecosyste.ms:** behind on all 5 except guava. It showed jackson-databind 2.22.4 (Oct 19) and the AWS SDK BOM 2.57.8 (Oct 30), when Central had 2.23.0 and 2.57.11.
  - **Live sample:** the top 10,000 Maven packages by dependents, keeping those that name a GitHub repo, are 7,388 packages in 2,914 repos. 300 of them took 5.3 s cold and 3.0 s with ETags, at 4 parallel requests, with no failures. 55 of the 300 (18%) were deployed in the last 7 days.
- **Caveats:** Five packages are a small sample of ecosyste.ms's lag. `lastUpdated` is when the metadata changed, normally at a deploy. A full pass of 7,388 is estimated from the sample, not measured.
- **Implication:**
  - Q24 answered: ecosyste.ms's Maven lag isn't a short outage but weeks behind per package, and no bulk Maven feed is current. The primary source is each package's `maven-metadata.xml`.
  - The tracker now polls the watched Maven packages there at most once every 20 hours, with stored ETags (`--maven-packages`, `package_meta` table). That's about 7,400 conditional requests a day, mostly 304s with no body, which stays inside Sonatype's guidance.
  - ecosyste.ms remains the Maven source only for discovering popular unwatched packages.
- **Sources:** [Maven Central index download limits](https://central.sonatype.org/faq/429-maven-index/), [429 and consumption limits](https://central.sonatype.org/faq/429-error/), [tooling providers](https://central.sonatype.org/faq/429-tooling-provider/), [Central Search REST API](https://central.sonatype.org/search/rest-api-guide/).

### F-109
- **Date:** 2026-11-08 · **Status:** confirmed (GitHub-hosted runners, one workflow, three runs)
- **Question:** Does the GitHub Action run the Limbowatch image on GitHub's runners, and does its pip fallback work where the image can't run?
- **Method:** Branch `action-image-test` of `limbowatch/demo-app` (the `add-scapy` dependencies) ran `limbowatch/limbowatch/integrations/action@main` four ways:
  - `ubuntu-latest` and `ubuntu-24.04-arm`, expecting the image;
  - `macos-latest` with Python 3.12, expecting pip;
  - a job in a `python:3.12-slim` container, expecting pip.
  The scan used `fail-on: high` and `allow-failure: true`. A follow-up step checked `LW_MODE`, the outputs, the SARIF file and the report.
- **Result:**
  - **Run 1:** both Linux jobs used the image and found 67 findings, 9 at or above high. The step passed with an `allow-failure` warning. The SARIF (110,857 bytes) was owned by the runner's user (uid 1001), not root.
  - **The container job failed:** `${{ github.action_path }}` expanded to `/home/runner/work/_actions/…`, which doesn't exist inside the job container (exit 127). `$GITHUB_ACTION_PATH` gives the container's path. Releases 0.1.0a1 and 0.1.0a2 have this bug.
  - **macOS failed:** the OSV-Scanner download got HTTP 504. From 10:10 to at least 10:18 UTC, github.com release downloads returned 504 for osv-scanner and uv assets. gh CLI's returned 200, and `api.github.com/repos/…/releases/assets/{id}` served the same files. githubstatus.com said "All Systems Operational".
  - **Run 3:** with the `$GITHUB_ACTION_PATH` fix and a fallback to the API after 3 retries, all four jobs passed with 67 findings each. Both pip jobs downloaded OSV-Scanner through the API, and its checksum was verified.
- **Caveats:** One day's outage; how often release downloads fail isn't measured. Windows wasn't tested.
- **Implication:**
  - The image path doesn't depend on GitHub's release downloads, so it's the default on Linux runners with Docker.
  - The pip path retries, then uses the API.
  - Container jobs, common on Gitea and Forgejo, work from the next release on.

### F-110
- **Date:** 2026-11-08 · **Status:** confirmed (one tracker run)
- **Question:** How does the Maven Central release feed (F-108) behave on its first live pass, compared with ecosyste.ms in the same run?
- **Method:** Tracker run of 2026-11-08 10:50 UTC (`state/runs.jsonl`, `releases`), the first with `--maven-packages tracker/seeds/maven-packages.txt`. It looked one day back, since there was no earlier cursor. An earlier dispatch at 10:30 never started tracking: `setup-uv` got HTTP 504 from GitHub's release downloads (F-109).
- **Result:**
  - Maven Central: 7,388 packages polled (7,388 requests to repo1.maven.org), 0 failed, 0 not found. 64 packages deployed in the past day, 30 of them in watched repos; the newest was 2026-11-08 06:03:37 UTC. 7,388 ETags were stored (`package_meta.jsonl`).
  - ecosyste.ms Maven in the same run: 25 releases, 7 in watched repos, newest still 2026-11-07 20:50:22 UTC.
  - The whole run took 533 s (wave one also polled 2,500 new repos).
- **Caveats:** One pass, and a cold one: every file was downloaded in full. The ETag passes come from the next daily run on.
- **Implication:** The Maven feed works at full size and finds over twice as many releases in watched repos as ecosyste.ms. Release-download outages on GitHub can stop a tracker run before it starts; the run fails visibly and the state is untouched.

### F-111
- **Date:** 2026-11-08 · **Status:** confirmed (observed; one public repo, second day)
- **Question:** One day after F-090, does Dependabot still report nothing on the demo app while Limbowatch reports the same advisories?
- **Method:** On `github.com/limbowatch/demo-app` (`main`, unchanged since F-090), 2026-11-08 ~18:00 UTC:
  - Dependabot alerts on: `GET /repos/limbowatch/demo-app/vulnerability-alerts` → 204.
  - Alerts: `GET /repos/limbowatch/demo-app/dependabot/alerts`.
  - Dependency graph: `GET /repos/limbowatch/demo-app/dependency-graph/sbom`.
  - Limbowatch: `limbowatch scan` 0.1.0a3 on a fresh clone, with the limbo feed of 2026-11-08 13:50 UTC.
  - Primary-source re-check: `research/2026-11-demo-evidence/verify.py`, as in F-091, run from a scratch copy so the committed `evidence.json` stays as of F-091.
- **Result:**
  - Dependabot: alerts on, **0 alerts**. The dependency graph lists 20 packages, including all 6 affected ones at the affected versions (undici 7.30.1, pgx v5.11.0, chi v5.4.0, rack 2.2.24, nokogiri 1.19.4, dnspython 2.9.1). GitHub sees the dependencies; it has no reviewed advisory to alert on.
  - Limbowatch: 80 dependencies scanned, **16 advisories in limbo in 6 packages**:
    - 5 high, 6 medium, 5 low;
    - packages undici, pgx, chi, rack, nokogiri and dnspython;
    - 7 of the 16 have a CVE.
    - It reported 2 dependencies it couldn't check (a version range, a Git URL) instead of dropping them.
  - Re-check: **16 of 16 still in limbo**. Each is published, not withdrawn, has the installed version in range, and is absent from GitHub's reviewed database (by ID and by CVE) and from OSV (by ID and by package and version). They have been public 3.3 to 25.2 days.
- **Caveats:** One repo, a demo with pinned versions, not a production project. Dependabot alerts only (not security updates). The dependency graph doesn't list npm's transitive packages, but none of the 16 findings is in one.
- **Implication:** F-090 holds a day later: for these 16 advisories, Dependabot's silence is the review backlog, not a coverage choice. When GitHub reviews one, Dependabot should start alerting and `limbowatch scan` reports it as "now visible to scanners"; re-running this check over the coming weeks shows when that happens.
- **Sources:** GitHub REST API (Dependabot alerts, dependency graph, repository and global security advisories); OSV API; `research/2026-11-demo-evidence/`.

### F-112
- **Date:** 2026-11-08 · **Status:** confirmed (observed; 13 real projects, one day)
- **Question:** On real projects, does Dependabot report the advisories in limbo that Limbowatch finds, and when it doesn't, is that because GitHub can't see the dependency?
- **Method:** `research/2026-11-dependabot-compare/` (`compare.py`, `ranges.py`). Projects: the October report's 15, at their HEAD of 2026-11-08.
  - **Files:** sparse, blob-less clones of only the dependency files (lockfiles plus manifests; test fixtures and vendored copies left out).
  - **Limbowatch:** `limbowatch scan` 0.1.0a3 `--scan-ignored` against the limbo feed of 2026-11-08 18:00 UTC.
  - **Dependabot:** for the 13 projects with findings, the same files in a private `limbowatch/dbcmp-<project>` repo, with Dependabot alerts turned on before the push. Read `GET /repos/{r}/dependabot/alerts` and `GET /repos/{r}/dependency-graph/sbom` after the alert counts had held across two polls 5 min apart (GitLab: 45 min after the push).
  - **Classification:** a finding is *alerted* if an alert has the same GHSA or CVE; otherwise *not alerted* (package and version in the graph) or *not in graph*.
  - **Live re-checks:**
    - upstream advisory still published, not withdrawn (`GET /repos/{repo}/security-advisories/{ghsa}`);
    - not reviewed (`GET /advisories/{ghsa}`);
    - not in OSV (`GET /v1/vulns/{ghsa}`).
  - **Versions:** each version is tested against the maintainer's range with the ecosystem's own library: npm and Rust `semver`, `packaging`, `Gem::Requirement`, `golang.org/x/mod/semver`. Go paths below the matched module are checked against `GET https://proxy.golang.org/<path>/@v/list`.
- **Result:**
  - **Limbowatch:** 1,140 findings (296 distinct advisories) in 13 of 15 projects. aerc had none; F-Droid server had no readable lockfile, reported as unchecked. Projects: GitLab 628, langchain 206, n8n 84, open-webui 83, Forgejo 24, GoToSocial 23, Gitea 22, Arti 22, Gitaly 16, Mobilizon 14, GitLab Runner 10, Kubernetes 4, Fractal 4.
  - **Dependabot:** 2,020 alerts on the 13 copies (GitLab 988, open-webui 271, Arti 169, n8n 148, langchain 115, GoToSocial 100, Gitaly 85, Forgejo 72, Gitea 35, Mobilizon 34, GitLab Runner 3, Kubernetes 0, Fractal 0).
  - **Alerts for Limbowatch findings: 0 of 1,140.** Every finding is *not alerted*: all 1,140 package versions are in GitHub's dependency graph.
  - **Re-checks:** all 1,140 still published upstream, 0 reviewed, 0 in OSV.
  - **Versions:**
    - **1,080 confirmed** in range by the ecosystem's own library: 277 advisories; 21 critical, 241 high, 618 medium, 200 low; 95 with a CVE; public 0.6 to 424 days, median 9.6.
    - 29 reported only as possible.
    - 26 depend on reading a malformed range: 5 advisories whose literal AND reading matches nothing (comma-as-OR, F-085).
    - **5 false positives** ([F-113](#f-113)).
  - **Timing:** the dependency graph was ready within minutes. Alerts appeared within ~10 min for 11 copies and after ~33 min for GitLab.
  - **Kubernetes:** its 0 alerts are correct. OSV `querybatch` on its 1,938 graph purls finds 3 Go vulndb entries, none with a GHSA alias.
- **Caveats:**
  - Copies of the dependency files, not the real repositories; Dependabot alerts only (not security updates).
  - Findings count per dependency file: an advisory in several lockfiles of a project counts once per file.
  - Malformed ranges are the maintainers' own and unreviewed.
  - It's a head start: as GitHub reviews these advisories, Dependabot will alert.
  - GitLab's Dependency Scanning wasn't compared (it reads the GitLab Advisory Database).
- **Implication:** F-090 holds on real projects at scale. On 13 popular projects, Dependabot sees every affected dependency and reports none of 1,080 confirmed advisories in limbo, while raising 2,020 alerts for reviewed advisories that Limbowatch, by design, doesn't repeat. The two are complementary: Limbowatch covers the time before review.
- **Sources:** GitHub REST API (Dependabot alerts, dependency graph, repository and global security advisories); OSV API; Go module proxy; `research/2026-11-dependabot-compare/data/2026-11-08/summary.json`.

### F-113
- **Date:** 2026-11-08 · **Status:** confirmed (Go module proxy; 5 findings in F-112)
- **Question:** Why do 5 of F-112's Go findings fail the independent version check?
- **Method:** For Go findings whose advisory names a path below the matched module, `GET https://proxy.golang.org/<path>/@v/list` for each named path (200 with versions = a module of its own; 404 = not a module). Read `go_relation()` in `packages/core/src/limbowatch/versions.py`.
- **Result:**
  - **Separate modules, wrongly matched to their parent:**
    - GHSA-q7gw-24fr-5p69 names `go.opentelemetry.io/otel/sdk`, `/sdk/log` and `/trace`, all modules (77, 25 and 70 versions). Limbowatch matched it to `go.opentelemetry.io/otel` (Gitaly 1.36.0, GitLab 1.46.0).
    - GHSA-3jcv-796g-cpjg names 406 `github.com/aws/aws-sdk-go-v2/service/*` modules (e.g. `service/iotwireless`, 230 versions, `< v1.53.10`). Limbowatch matched it to `github.com/aws/aws-sdk-go-v2` 1.47.x (Gitaly, GitLab, GitLab Runner) and compared the root's version with a service module's range.
  - **Correctly matched packages inside the module:** `go.opentelemetry.io/otel/baggage`, `go.mongodb.org/mongo-driver/v2/bson` and `/mongo` (all 404).
  - `go_relation()` returns `package_in_module` whenever the advisory path extends the module path (except `/vN`), without knowing whether the longer path is itself a module.
- **Caveats:** 5 of 1,140 findings in one comparison; how often this happens across the feed wasn't measured.
- **Implication:** A bug in the watcher's Go matching, in released 0.1.0a1 to 0.1.0a3. Telling a nested module from a package needs data the pure matcher doesn't have. The tracker could record, per Go advisory path, whether the module proxy lists it as a module, and the feed could carry that. Until then such findings should be reported as possible, not certain.
- **Sources:** Go module proxy; GitHub repository security advisories; `research/2026-11-dependabot-compare/`.

### F-114
- **Date:** 2026-11-08 · **Status:** confirmed (live proxy probe; tracker state of 2026-11-08 13:36 UTC)
- **Question:** How expensive is resolving every Go advisory path through the Go module proxy, how many paths are packages inside a shorter module or modules nested under another, and does it remove F-113's false positives?
- **Method:** The new tracker step `resolve_go_modules`, run locally against a copy of the tracker state:
  - **Lookup:** for each path, the longest prefix `GET https://proxy.golang.org/<prefix>/@v/list` serves with versions, falling back to `/@latest` when the list is empty. 404, 410 or 400 means the prefix isn't a module. Each prefix is asked once.
  - **Feed and re-scan:** built the feed from the result and re-scanned the Gitaly, GitLab and GitLab Runner trees from F-112 with it, without upstream polling.
- **Result:**
  - **Cost:** 1,272 valid Go paths (from 1,517 as entered) resolved in 52 s with 1,442 requests and 0 failures.
  - **Paths:**
    - 1,147 are modules themselves;
    - 97 are packages inside a shorter module (e.g. `go.opentelemetry.io/otel/baggage`);
    - 28 have no module on the proxy.
  - **Nested modules:** 34 paths, not counting `/vN` variants, are modules nested under another module that some advisory also names, e.g. `go.opentelemetry.io/otel/sdk` and `/trace`, OpenTelemetry exporters and contrib modules, and `…/backend` and `…/server` directories. This is a floor: `github.com/aws/aws-sdk-go-v2` isn't named by any advisory, so its 406 service modules aren't counted.
  - **Feed:** 2,265 Go package entries carry `go_module`.
  - **Re-scan:**
    - The 5 F-113 false positives are gone.
    - GHSA-3jcv-796g-cpjg matches nothing in these projects.
    - GHSA-q7gw-24fr-5p69 now matches the modules it names, `go.opentelemetry.io/otel/trace` (Gitaly, GitLab) and `/sdk` (GitLab), at v1.46.0, inside `>= 1.33.0`/`>= 1.35.0, < 1.47.0`: the same advisory, now on the right modules.
- **Caveats:**
  - Module boundaries can change between versions (a package split into its own module later), so a path is re-checked after 180 days.
  - Advisories the watcher polls itself, not from the feed, carry no module, so their sub-path matches stay possible.
- **Implication:**
  - **Fix:** F-113 is fixed for feed advisories, at the cost of about 1,400 proxy requests once and then a few per run.
  - **OSV form:** the feed's Go records now name their module the way OSV's Go records do (`package.name` = module, `ecosystem_specific.imports` = package). OSV-Scanner consumers of the feed also stop missing advisories that name a package inside a module.
- **Sources:** Go module proxy (`/@v/list`, `/@latest`); tracker state (tracker-data branch); `research/2026-11-dependabot-compare/.cache/repos/`.

### F-115
- **Date:** 2026-11-09 · **Status:** confirmed (official docs and live API)
- **Question:** Does GitLab show a GPG-signed tag as verified once the signing key is on the tagger's GitLab account?
- **Method:**
  - **Account:** added the release key (fingerprint `4F6C…F143D31D`, uid `blueandhack@gmail.com`) to the user's GitLab account (key 3260411). The key's email is a confirmed account email and the commit email.
  - **Tag:** checked the component tag `0.1.0-alpha.4` (tag object `1822b1f`, signed with `git tag -s`; `git tag -v` passes) before and after, with `GET projects/limbowatch%2Flimbowatch-component/repository/tags/0.1.0-alpha.4/signature`.
  - **Docs:** read GitLab's tags API docs (`doc/api/tags.md`) and its X.509 signing docs.
- **Result:**
  - **API:** before and after adding the key, the endpoint returns `signature_type: PGP`, `verification_status: null` and `gpg_key_primary_keyid: null`.
  - **Docs:** the API "returns X.509 signature information from signed tags", and the endpoint is titled "Retrieve X.509 signature of a tag". Only the X.509 page covers signing tags. GPG and SSH keys on GitLab verify commits only.
- **Caveats:** GitLab could add GPG tag verification later.
- **Implication:**
  - **No badge:** GitLab will not show the component's GPG-signed tags as verified. The signature is still in the tag, and `git tag -v` checks it against the public key, which GitHub also shows for this user.
  - **Release step:** keep signing component tags with GPG. Getting a GitLab badge would need an X.509 certificate, which isn't worth it.
- **Sources:** GitLab docs `doc/api/tags.md`, `doc/user/project/repository/signed_commits/x509.md` (master, 2026-11-09); GitLab API (tag signature, `user/gpg_keys`, `user/emails`).

### F-116
- **Date:** 2026-11-09 · **Status:** confirmed (official docs and the org's billing API)
- **Question:** Will the tracker and CI run out of GitHub Actions minutes or other free-tier limits as Phase 5 grows the watchlist?
- **Method:**
  - **Docs:** read GitHub's Actions billing docs (docs.github.com/en/billing/concepts/product-billing/github-actions).
  - **Usage:** `GET /organizations/limbowatch/settings/billing/usage?year=2026&month=11`, summed per repository and SKU.
  - **Runs:** durations of the last 12 tracker runs (`gh run list --workflow tracker.yml`).
  - **Cache:** `GET /repos/limbowatch/limbowatch/actions/cache/usage` and the cache list.
- **Result:**
  - **Minutes:** standard GitHub-hosted runners are free for public repositories, and Dependabot runs are free. The org is on GitHub Free, whose private-repo allowance is $12 a month of compute, not a minute count. November so far: `limbowatch` 706 Linux and 55 macOS minutes ($7.65 gross, $0 net); `demo-app` 35 minutes ($0); the 13 private `dbcmp-*` copies 1–3 Linux minutes each, from Dependabot ($0 net).
  - **Run length:** tracker runs take 7–19 min (18.5 min on 2026-11-09, with 5,906 repos polled and the first Go-module pass), against a 75-min job timeout and the tracker's own `--minutes 50` stop.
  - **Cache:** 9.95 GB of the 10 GB per-repo cache, in 257 entries. Almost all of it is the image build's BuildKit cache (`cache-to: type=gha,mode=max`): six 1.3 GB blobs, one per image build since 2026-11-08. The tracker keeps its state on the tracker-data branch and uses no Actions cache; only setup-uv's small caches are shared with it.
  - **Schedule:** the 06:17 UTC scheduled run started at 13:14 (2026-11-07), 13:36 (11-08) and 16:34 (11-09), 7–10 hours late.
- **Caveats:** one month's billing data, partly from before the repo went public on 2026-11-05.
- **Implication:**
  - **No cost:** Phase 5's growth costs nothing in minutes while the repo is public. The limits that bind are GitHub's API rate limit for the tracker's token (5,000 requests an hour), which `--budget` and `--max-new` already respect, and run length.
  - **Cache:** over 10 GB GitHub evicts the least recently used caches. That's harmless for the tracker, but it can evict setup-uv's caches and slow CI. Pruning old BuildKit blobs or switching to `mode=min` would fix it.
  - **Schedule:** a late scheduled run delays the daily report by hours. Manual runs fill the gap during Phase 5.
- **Sources:** GitHub docs (above); GitHub billing usage API; Actions runs and cache APIs.

### F-117
- **Date:** 2026-11-09 · **Status:** confirmed (tracker run of 2026-11-09 16:34 UTC)
- **Question:** Does the tracker's Go-module step (F-114) work in production?
- **Method:** the `go_modules` stats of the scheduled tracker run in `state/runs.jsonl` on the tracker-data branch.
- **Result:** 1,273 Go paths due and resolved, 92 inside a shorter module and 43 with no module on the proxy. It took 1,443 proxy requests with 0 failures. The run took 18.5 min in all. These match the local trial in F-114 (1,272 paths, 1,442 requests).
- **Caveats:** the next full pass is due in 180 days. Until then only new paths cost requests.
- **Implication:** feed records from this run carry `go_module`, so 0.1.0a4 watchers match Go advisories by module (F-113 fixed in production).
- **Sources:** `state/runs.jsonl` (tracker-data branch).

### F-118
- **Date:** 2026-11-09 · **Status:** confirmed (official docs, live probes, and a parity run on the tracker state of 2026-11-10 03:30 UTC)
- **Question:** Can limbo.watch check a package and its dependency tree in the visitor's browser, with the same verdicts as `limbowatch scan`?
- **Method:**
  - **deps.dev docs:** read docs.deps.dev/api/v3.
  - **deps.dev probes:** read-only requests to `GET https://api.deps.dev/v3/systems/{system}/packages/{name}` and `…/versions/{version}:dependencies` for react, next, django, tokio, spring-boot-starter-web and gin, with an `Origin: https://limbo.watch` header and an OPTIONS preflight.
  - **Parity:** the browser script (`publish/check.js`) run under Node against univers and `watch.match._version`:
    - every version bound and fixed version in the advisories in limbo for the four ecosystems, compared against 150 sampled bounds with all six operators;
    - the full verdict for every advisory entry at each of its own bounds, plus 0.0.1 and 999.0.
- **Result:**
  - **deps.dev:**
    - `GetDependencies` returns a resolved graph (nodes marked DIRECT or INDIRECT, edges, an `error` string) for npm, Cargo, Maven and PyPI only. Go isn't resolved; gin answered 404.
    - Responses carry `access-control-allow-origin: *` and `cache-control: public, max-age=3600`, and the docs permit caching. Use falls under the Google API Terms of Service.
    - A just-published version has no graph yet: next 16.4.6, published 2026-11-09 20:33 UTC, answered 404 "dependencies not found" while 16.4.5 resolved to 51 nodes.
    - Resolution can fail: tokio 1.54.1 returned 0 nodes with the error "bytes/^1.2.1: no candidates found".
    - The default version can be a pre-release: Maven's spring-boot-starter-web defaulted to 4.2.0-RC2.
    - react 19.3.1 has no dependencies; its graph is 1 node.
  - **Parity:** 3,589,200 comparisons had no difference from univers. They covered 1,658 npm, 1,140 PyPI, 446 crates.io and 744 Maven bounds. 24,909 verdicts had no difference from the watcher: 14,340 not affected, 9,635 affected and 934 possible.
  - **Index:** `check/index.json` holds 4,627 advisories in limbo (npm, PyPI, crates.io, Maven): 1.2 MB, 260 KB gzipped.
  - **Live examples:** gatsby 5.16.1 (1,383 packages) has an advisory in http2-wrapper 1.0.3, reached via got; trio-websocket 0.12.2 has one in its direct dependency trio 0.34.0.
- **Caveats:**
  - The tree is deps.dev's resolution of the package on its own, not a project's lockfile.
  - Matching is by package name only: advisories with unusable names (F-069), which the watcher matches by source repo, aren't checked.
  - The orderings are ports. A univers or packaging upgrade could change Python's behavior; tests/test_check.py would catch that.
- **Implication:**
  - **Same verdicts:** the browser checker gives the CLI's verdicts without a server and without limbo.watch seeing queries. The site's CSP must allow `connect-src https://api.deps.dev`.
  - **Honest output:** where deps.dev has no tree, the page says only the package itself was checked and offers the previous release's tree. It never reports a clean tree it didn't see.
- **Sources:** docs.deps.dev/api/v3; api.deps.dev (above); univers 30.x, packaging 26.3, semantic_version 2.10.0 source.

### F-119
- **Date:** 2026-11-10 · **Status:** confirmed (observed; one demo project)
- **Question:** After three days, are the demo app's advisories in limbo still invisible to scanners?
- **Method:** Reran the demo pull request (GitHub `limbowatch/demo-app` #1, run 42758588169) and merge request (GitLab !1, pipeline 3048115706) on 0.1.0a4 against the limbo feed of 2026-11-10 04:43 UTC, and compared `report.json` with the 2026-11-07 run (F-088, F-097).
- **Result:** Identical: 67 advisories in limbo in 7 packages (9 high, 25 medium, 33 low), 9 findings failing `--fail-on high`, Code Quality "51 new findings" and test summary "9 failed, 67 total tests". None of the 67 was reviewed or reached OSV in the 3 days.
- **Caveats:** One small project. scapy's 51 advisories dominate the count.
- **Implication:** The demo still shows the gap unchanged. The scan page's screenshots were refreshed from this run, in dark and light (docs/SCREENSHOTS.md), and their captions still hold.
- **Sources:** demo run artifacts (`limbowatch-report`); GitLab merge request !1.

### F-120
- **Date:** 2026-11-10 · **Status:** confirmed (recomputed from the committed data; GitHub API, CVE Services and the CVE List for the rest). **Corrects details of F-050, F-055, F-056.**
- **Question:** Does every number and claim in the State of the Gap report hold up against its data and its sources?
- **Method:**
  - Recomputed every number in the report from both folders' committed CSVs and `summary.json` (2026-10-22, 2026-10-22-offgithub, 2026-10-21), plus the chart labels.
  - CNAs of every uncited CVE from the two cached CVE List exports (`cve_2026-10-22_0800Z`, `cve_2026-10-25_0900Z`); `GET /api/cve-id/{id}` for the 2 reserved IDs.
  - `GET /advisories/{ghsa}` (`github_reviewed_at`) for all 294 advisories in limbo on 2026-10-21.
  - Checked the GitHub blog quote, the Safeguard and Munim figures and the prior-work links at their sources.
- **Result:** The headline numbers, every per-project row, the charts and the outside citations held. Errors found and fixed in the report:
  - **NVD paragraph.** The 10 "absent from NVD" CVEs are exactly the 10 *reserved* CVEs in the sample, not published ones. The sample also isn't "every published CVE in limbo": it's the 44 CVEs cited by advisories in limbo that affect a project's package (`s4_status.py`). Of the 34 published, 17 aren't enriched. The reviewed sample of 60 is 53 published (16 not enriched), 5 rejected and 2 reserved, not "21 of 60".
  - **Follow-up.** "24 gained a CVE from another CNA: 21 VulnCheck, 1 Red Hat, 4 GitHub" mixed advisories with CVEs (26 CVEs). Only 21 links were new (all VulnCheck, published 2026-10-22). The other 3:
    - gorilla/websocket and moby already had their older CVEs on 2026-10-22, as duplicates of reviewed advisories. `s9` compares against the cited CVE only.
    - lib0 GHSA-r5c8-rf4w-qrq8 is a false link. CVE-2026-102521's description calls it "similar to but different from" that advisory.
  - **Follow-up, reserved IDs.** The 2 newly cited reserved IDs (CVE-2026-115563, CVE-2026-115472) can't be attributed to GitHub: CVE Services redacts `owning_cna`. Both were still `RESERVED` on 2026-11-10.
  - **Review burst.** 37 of the 294 were reviewed between 2026-10-22 15:46 and 17:01 UTC, about 13 h after the first measurement. It was Pillow ×11, not ×10. 161 of the 294 were still not reviewed on 2026-11-10.
  - **105 package-versions** is a per-project count: 92 distinct package-versions.
  - **GitPython example.** OSV-Scanner does report *other* vulnerabilities for gitpython 3.1.50, so it isn't "reported as clean". It just doesn't report this advisory.
  - **Examples' "Used by".** Five rows named one project where several ship the version (typebox, pillow, jsonpointer, go-jose 4.1.4, qs).
  - **Smaller fixes:**
    - "Commits are recorded in `inventory.json`": that file isn't committed; they're in `summary.json`.
    - `summary.json` doesn't hold the cross-set totals.
    - Rust isn't off-GitHub-only (11 of 66 come from the GitHub-hosted set).
    - "The tracker is next" is out of date.
    - The data-quality examples come from the off-GitHub set.
- **Caveats:**
  - `github_reviewed_at` is read today and could reflect a later re-review. Its 37 matches F-050's count.
  - The false-link check covers the 79 reverse links in the report's data, and 1 was wrong. Across the 2026-10-25 CVE List, 150 of 28,278 records that name a GHSA name one only outside `references` and `source`. Some of those are legitimate.
- **Implication:**
  - The report's claims now match its data. Mechanical recomputation catches what reading doesn't, so rerun it before publication.
  - `normalize.cve_record` takes GHSA IDs from the whole CNA container, description included, so the live tracker can make the same false link. Taking them from `references` and `source` only would avoid it. That's a product change, still to do.
- **Update (2026-11-10, same day):**
  - **Fixed in the tracker.** `cve_record` now reads GHSA links from `references` (url, name) and `source` only, and records `link_rule`. `Tracker.assess` re-reads a stored record from an older rule when one of its links would count (an uncited CVE or a duplicate). A lookup that finds no record keeps the stored one.
  - **Live state (tracker-data, 2026-11-10):** 2,383 uncited links. 1,826 of their CVEs are in the 2026-10-25 CVE List, and 29 of those (1.6%) are false under the new rule. Every one is a description that names a *different* advisory ("distinct from", "after the fix for", "a different vulnerability from"). None was on an advisory marked as a duplicate. The other 557 are newer than that release and are re-read the same way.
  - **Report published** with the corrections. The review-wait text now cites GitHub's documented 72 hours and its own statement that it has missed its goals since mid-April. Live tracker counts for the 7 days to 2026-11-10: 805 new advisories in reviewable ecosystems, 51 reviewed; 3,033 in limbo for more than three months.
- **Sources:** `research/2026-10-state-of-the-gap/data/**`; cvelistV5 releases above; GitHub REST `/advisories`; CVE Services `cve-id`; [GitHub blog, 2026-06-29](https://github.blog/security/supply-chain-security/inside-the-advisory-database-and-what-happens-when-vulnerability-volume-breaks-records/); [Safeguard, 2026-10-18](https://safeguard.sh/resources/blog/github-repository-advisories-missing-from-advisory-database-2026-data); [munimtechnologies/advisory-import-census](https://github.com/munimtechnologies/advisory-import-census).

### F-121
- **Date:** 2026-11-10 · **Status:** confirmed (observed). Corrected the same day: the first version of this entry miscounted first checks and counted advisories from repos that were already watched.
- **Question:** What did coverage wave two (the top 10,000 packages per ecosystem, Phase 5 step 1) add?
- **Method:**
  - 11 tracker runs, 2026-11-09 16:34 → 2026-11-10 08:01 UTC, dispatched at least 80 minutes apart with `--max-new 2500`.
  - Counts from `tracker-data` (`state/runs.jsonl`; `state/repos.jsonl` for repos first seen on or after 2026-11-09; their advisories classified with `publish.items`).
  - Coverage from limbo.watch `metrics.json` (2026-11-10 08:06 UTC).
- **Result:**
  - **Every watched repo checked at least once:** 64,021 watched, 0 never polled. The 11 runs made 26,983 first checks: the 19,461 repos wave two added, plus 7,522 left from wave one. No run stopped early.
  - **First checks found 358 advisories.** The same runs found 221 more, newly published in repos already watched.
  - **The 19,461 wave-two repos:**
    - All polled; 377 not found; 184 with advisories.
    - 277 advisories: 275 in limbo, 2 duplicates.
    - Of the 275, 223 are in ecosystems GitHub reviews, in 105 repos: 13 critical, 96 high, 89 medium, 25 low. By ecosystem: Go 81, PyPI 78, npm 33, crates.io 29, Actions 11.
    - The other 52 are likely permanent.
    - Top repos: supertokens/supertokens-core 27, pdfcpu/pdfcpu 19, tmatens/compose-lint 12, share/sharedb 11, matthiasvalvekens/pyhanko 8.
  - **Top-10,000 coverage, repos with advisories:** Go 322, PyPI 368, npm 298, Packagist 235, Maven 187, crates.io 162, RubyGems 159, NuGet 54.
  - **Live totals:** 9,773 in limbo, 14,546 likely permanent.
- **Caveats:**
  - Repos map to packages through registry metadata, and a package with no repo isn't watched.
  - Advisories found on a first check can be old.
  - The last run used code from before the F-120 link fix.
- **Implication:**
  - The wide tail is thin: about 1% of the new repos have an advisory. But nearly all of their advisories are in limbo, and 109 of the 223 reviewable ones are high or critical.
  - Keep the tail: after the first pass it costs little, because repos without advisories are polled every 30 days.
  - The wave is done; the daily schedule takes over.
- **Sources:** `tracker-data` state at the 2026-11-10 08:01 run; https://limbo.watch/metrics.json.

### F-122
- **Date:** 2026-11-10 · **Status:** confirmed (observed)
- **Question:** Why was the Actions cache full (F-116: 9.95 of 10 GB), and what keeps it small?
- **Method:**
  - `gh cache list` (key, size, last access).
  - The image workflow's build log (run 42780040680).
  - `docker history` of local builds of the `osv` stage, before and after the change.
- **Result:**
  - **133 BuildKit entries, 9.46 GB, from `image.yml`'s `type=gha,mode=max` cache.**
    - Seven blobs were about 1.25 GB each.
    - Each is the `osv` stage's `go install` layer: OSV-Scanner's binary plus Go's whole module and build caches, one per architecture.
  - **What a build did with it:** an image build downloaded the 1.32 GB layer even when the stage was cached. When the layer was evicted and rebuilt, it came back under a new digest, so copies piled up until GitHub's LRU eviction.
  - **Fix:**
    - The `go install` runs with cache mounts for `/go/pkg/mod` and `/root/.cache/go-build`.
    - The binary is moved, not copied.
    - The layer is now 53.9 MB (108 MB with `cp`, 1.3 GB before).
    - The image's smoke test passes: `limbowatch 0.1.0a4`, OSV-Scanner 2.7.0.
  - **One-off cleanup:** deleted all 133 BuildKit entries. 3 caches (102 MB) were left. The next image build starts cold.
  - **Ongoing:** `.github/workflows/cache-cleanup.yml`.
    - When a pull request closes, it deletes that PR's caches.
    - Weekly, it deletes caches unread for 7 days, then the least recently read BuildKit entries down to 4 GB.
- **Caveats:** Cache-mount contents don't persist between CI runners, so a cold `osv` stage downloads its modules again (about a minute). A cached stage doesn't.
- **Implication:** The cache stays far from the 10 GB limit, and image builds stop moving 2.6 GB per run.
- **Sources:** `gh cache list`; image run 42780040680 log; local `docker buildx build --target osv`.

### F-123
- **Date:** 2026-11-10 · **Status:** confirmed (live checks and recomputation)
- **Question:** Are the tracker's verdicts, the site's numbers, the feed and the report right, checked independently against primary sources?
- **Method:** `tracker-data` at the 2026-11-10 08:01 run (commit 22d09c5), and the site and feed built from it (08:18:43 UTC).
  1. **Verdicts:** a seeded random sample, checked live (`gh api` repo advisory and `/advisories/{ghsa}`, OSV `/v1/vulns`, CVE Services). 300 in limbo, 100 likely permanent, 60 duplicates, 60 reviewed. For each: published state, cited CVE and its state, ecosystems, uncited CVEs (references or source must name the GHSA), and duplicates (reviewed with a shared CVE).
  2. **Reviewed-list completeness:** every reviewed advisory GitHub updated or published 2026-11-01..11 (`/advisories?type=reviewed`), against the tracker's list.
  3. **Site numbers:** `metrics.json` recomputed from the raw state files with code written for this check. Plus every number-bearing sentence on the eight pages.
  4. **Feed:** all 24,373 records validated against OSV's `validation/schema.json` (ossf/osv-schema), checked field by field against the state, and the index compared.
     - Ranges: a seeded sample of 3,000 converted ranges compared with univers on the maintainer's range, at the boundary versions. Every disagreement was read.
  5. **Checker index:** compared with the feed.
  6. **Report and comparisons:** every affected row of the October report, every finding of the Dependabot comparison (`ranges.json`) and the demo scan, re-evaluated with the corrected parser.
- **Result:**
  - **Verdicts: 0 of 520 sampled wrong.** All 300 in limbo and 100 likely permanent were published, absent from the global database and from OSV. All 60 reviewed were reviewed. All 60 duplicates were duplicates of reviewed advisories with a shared CVE. Every cited-CVE state and uncited link checked out.
  - **Reviewed list complete:** GitHub reviewed 121 advisories in the 7 days to 08:18 UTC, 78 of them repository advisories. All 78 are in the tracker's list and in watched repos.
    - 24 of the 78 were advisories the tracker labels likely permanent ("other", container images). GitHub's reviewers mapped them to Maven, Go, npm or PyPI (Keycloak, LXD, Kubeflow). In all, 33 of about 14,600 likely-permanent advisories have been reviewed: the label holds, at about 0.2%.
  - **Site numbers:** all `metrics.json` fields reproduce, and so do the page sentences checked (9,798 in limbo; 14,575 likely permanent; 4,772 critical or high; 3,038 over 3 months; 605 over a year; 64,021 on schedule; flow 800 / 51).
    - One wording fix: the feed page called its 24,373 records "every advisory in limbo" next to the home page's 9,798. It now gives both parts.
  - **Feed:** 0 records invalid against the OSV schema, 0 fields that disagree with the state, and the index matches the zip.
  - **Range parser bugs (`versions.alternatives`), in the tracker, feed, watcher and checker:**
    - **Commas re-read as OR left every bound alone.** `>= 2.2.0, < 2.2.10, >= 2.3.0, < 2.3.7` became four alternatives that together cover every version. 170 package ranges in 149 advisories, 47 of them in limbo.
    - **Equal inclusive bounds counted as a contradiction.** `>= 3.8.8, <= 3.8.8`, one version, became "everything".
    - **Wildcards matched nothing.** `2.16.*` parsed as `= 2.16.`. 119 ranges in 115 advisories, 15 in limbo.
    - **Spans without spaces matched nothing.** Packagist's `11.0.0-11.5.50` was read as one pre-release. 273 ranges in 255 advisories, 44 in limbo.
    - **Packagist ordering broken for four-part versions.** univers's `ComposerVersion` reads a fourth part as semver build metadata, so `6.7.13.0 < 6.7.13.1` and `6.7.13.0 == 6.7.13.1` were both False. 488 ranges in 322 advisories, 128 in limbo.
    - **Fixes:**
      - comma parts are read one by one, contradictory parts in order, lone bounds paired;
      - equal inclusive bounds are allowed;
      - wildcards and `a~b` / `a-b` spans are intervals;
      - Packagist uses a Composer-ordered class.
      - A re-read that still contradicts itself, or covers every version, can't be evaluated (`None`, so "possible"), instead of "none" or "all". 12 advisories, 4 in limbo (e.g. `>= 0.11.0, < 0.6.10`, `>= 9.0.0, < 9.0.0`).
    - The univers disagreements that remained were univers's own misreadings (no comma between bounds, "and", four-part Packagist versions) or open ranges the feed closes at the advisory's fix by design.
  - **Checker index:** the same 4,711 advisories as the feed.
  - **Impact:**
    - **October report:** 722 of 723 affected rows unchanged. Gitea's "advisories in limbo affecting it" is 15, not 16 (GHSA-9wx9-5pv9-3349, medium). The report is corrected with a note, and the research parser carries a comment.
    - **Dependabot comparison:** all 1,080 confirmed findings still affected, and the 26 interpretation-dependent ones unchanged. The comparison had already confirmed with each ecosystem's own library.
    - **Demo:** 67 findings before and after.
    - **Release feeds:** the 08:01 run's five empty feeds were an ecosyste.ms failure (6 failed requests). Partial feeds keep their cursor, so nothing is skipped.
- **Caveats:**
  - Sampling bounds the verdict error rate (0 of 300 in limbo: below about 1% at 95%); it doesn't prove zero.
  - Range checks cover boundary versions only.
  - F-085's 657 live re-checks used Limbowatch's own parser, so they don't independently cover the comma bug. F-112's 1,080 do.
- **Implication:**
  - The verdicts, the numbers and the feed's records are right. The range parser over-matched or under-matched about 1% of ranges, and the fix ships in the next release; 0.1.0a4 users keep the old reading until then.
  - Independent recomputation found what tests built on the same code didn't. Repeat it before each release.
- **Sources:** live GitHub, OSV and CVE Services responses (scratchpad); `tracker-data` 22d09c5; OSV schema from ossf/osv-schema `validation/schema.json`; research data folders.

### F-124
- **Date:** 2026-11-10 · **Status:** confirmed (rerun from the snapshots' caches). **Updates F-055's per-project counts.**
- **Question:** What does the October report say when its matching uses the corrected parser (F-123)?
- **Method:**
  - The research pipeline now evaluates ranges with `limbowatch.versions` (`affected`, `already_fixed`, `VERSION_CLASS`; the scripts depend on `packages/core`).
  - Stage 4 was rerun with `OFFLINE=1`, then stage 6. A response the snapshot never fetched is recorded as "not checked", never fetched today. The reviewed NVD sample is the one the snapshot drew.
  - `2026-10-22-offgithub` was read from the pre-namespace flat cache (`HTTP_CACHE_NS=flat`). It was last written on 2026-10-22, before that snapshot's summary.
  - Stage 8 (live verification) and stage 9 (follow-up) were not rerun. Their code now links CVEs through references or source only (F-120), and stage 9 counts only links added since the snapshot.
- **Result:**
  - **Unchanged:** the 268/217 advisories in limbo (415 unique), the classes, every package-version count (105 reported clean per project, 92 distinct; 13 of 14 projects), the verification verdicts and the charts.
  - **Advisories in limbo affecting a project:**
    - gitea 16 → 15 (GHSA-9wx9-5pv9-3349 no longer matches seroval 1.5.4).
    - open-webui 58 → 59 and GitLab 35 → 36, high/critical 18 → 19 and 16 → 17. lib0 0.2.117 is inside `0.2.1-0.2.117` (GHSA-r5c8-rf4w-qrq8, high, verified in limbo). It was already counted through GHSA-g75x-89c3-rvmr, so the package-version counts don't move.
  - **Matching, GitHub-hosted set:**
    - 1,532 → 1,507 matches. Of 1,391 with package data, ranges contradicting the fix 222 → 213 (15%) and unparseable 61 → 27 (1.9%).
    - langchain's mistune 3.3.3 against `>=3.0.0 & <=3.2.1` is now "not affected" instead of unknown.
  - **Matching, off GitHub:** 2,300 → 2,272; contradicting 132 → 123; unparseable 134 → 76.
  - **Offline gaps:** NVD for 1 new limbo CVE per set (CVE-2026-102360, lib0) and 2 CVE states of reviewed advisories off GitHub, recorded as not checked.
- **Caveats:**
  - The rerun reads the same cached responses as 2026-10-22. Only the parser differs.
  - "all" is now read as every version (the tracker's rule). The research parser used to leave it unknown; no advisory in limbo was affected by that.
- **Implication:** The report and the tracker now read every range the same way. The report's tables and data-quality figures are updated, and `summary.json` matches them again.
- **Sources:** `research/2026-10-state-of-the-gap/data/{2026-10-22,2026-10-22-offgithub}/` (regenerated); `.cache/http/` (not committed).

### F-125
- **Date:** 2026-11-10 · **Status:** confirmed (observed)
- **Question:** Does limbo.watch return errors while a new site image rolls out, and does the Deployment change fix it?
- **Method:**
  - Polled `/`, `/metrics.json` and `/feed/index.json` through Cloudflare about 3 times a second, with a 5 s timeout, during a deploy triggered by `gh workflow run site.yml`.
  - Read the Deployment and its events with `kubectl` on skylion.
  - Repeated the poll after the change, across two rollouts.
- **Result:**
  - **Before:** one replica, the default strategy (25%/25%), a readiness probe every 10 s, no preStop. The deploy returned 502 ("error code: 502") twice and one timeout, between 09:41:03 and 09:41:09 UTC. Kubernetes stopped the old pod about a second after the new one started, while Traefik still routed to it.
  - **Change** (`deploy/k8s/deployment.yaml`, server-side dry run first):
    - `maxSurge: 1`, `maxUnavailable: 0`, `minReadySeconds: 5`;
    - a readiness probe every 2 s;
    - a 10 s `preStop` sleep (Kubernetes' built-in sleep action; k3s v1.36.6) and `terminationGracePeriodSeconds: 30`.
  - **After:** the rollout that applied the change still had one 502, because the pod it replaced had no preStop yet. The next deploys went through 2,055 requests with 0 errors.
- **Caveats:** Polling at about 3 requests a second can miss a sub-second gap. Two clean rollouts aren't proof that every rollout is clean.
- **Implication:** Daily deploys are now invisible to visitors and to tools that fetch the feed.
- **Sources:** poll logs (scratchpad); `kubectl -n limbowatch get events`.

### F-126
- **Date:** 2026-11-10 · **Status:** confirmed (observed)
- **Question:** Release 0.1.0a5: did the pre-release audit pass, and did every artifact ship as tested?
- **Method:** `scripts/audit.py`, then the release order in the project's release checklist.
- **Result:**
  - **Audit:** passed on the 08:01 tracker run, as built into the site at 09:35 UTC:
    - 520 verdicts sampled live, 0 wrong;
    - reviewed sync complete (121 reviews in 7 days, 78 from repository advisories, 0 missing);
    - 19 metrics reproduced;
    - 24,373 feed records valid OSV and matching the state;
    - 12,099 converted ranges consistent with the parser;
    - checker index 4,711 = feed.
  - **Image:** `ghcr.io/limbowatch/limbowatch:0.1.0a5@sha256:785a5d3e…` (built from cbd78bb; reports `limbowatch 0.1.0a5` and OSV-Scanner 2.7.0; SLSA provenance verified), pinned in the action and the GitLab template (3988cfc).
  - **Tags:** `v0.1.0a5` is GPG-signed and verified. The release workflow published PyPI 0.1.0a5 and a GitHub pre-release, and the image workflow retagged the pinned digest.
  - **GitLab component:** split 26bb0d8 on gitlab.com `main` (pipeline 3048977643 passed); signed tag `0.1.0-alpha.5` (pipeline 3048996107 passed; CI/CD Catalog release 10:05 UTC).
  - **Org profile:** updated (bd38438).
  - **Smoke test:** `uvx --from limbowatch-cli==0.1.0a5` on the demo app found the same 67 advisories as 0.1.0a4. The screenshots still match, so they weren't refreshed.
- **Implication:** The range-parser fixes (F-123) reach watcher users. Run the audit before every release.
- **Sources:** GitHub Actions runs 42794370246, 42795617980, 42795618072; GitLab pipelines above; PyPI.

### F-127
- **Date:** 2026-11-10 · **Status:** confirmed (official docs; repo created and tested)
- **Question:** Can the Limbowatch action be listed in GitHub Marketplace, and what does that take?
- **Method:**
  - GitHub Docs, "Publishing actions in GitHub Marketplace".
  - Searched Marketplace for "limbowatch"; `/marketplace/actions/limbowatch` answers 404.
  - Created the repo, pushed the action, and ran its self-test.
- **Result:**
  - **Requirements:**
    - a public repository with a single `action.yml` at the root (metadata files in subfolders aren't listed);
    - a unique name: not an existing Marketplace action, not a user or org name unless that account publishes it, not a category;
    - the owner accepts the Marketplace Developer Agreement, and the publisher uses 2FA;
    - publishing is the "Publish this Action to the GitHub Marketplace" checkbox when drafting a release. The docs describe no API, and there's no review: it's listed at once.
  - **Name:** "Limbowatch" is free and matches the org, which may use it.
  - **Our action:** it lived in `integrations/action/` of the main repo, so it couldn't be listed from there. It's self-contained (scripts via `$GITHUB_ACTION_PATH`; pip installs from the main repo's release archive), so it moved unchanged.
  - **Done:**
    - `limbowatch/limbowatch-action` (public), with the subtree of `integrations/action/`: action.yml, scripts, README, LICENSE, self-test (split c44e6db).
    - Self-test run 42797393788 passed on ubuntu (image) and macOS (pip), with 51 findings for the scapy 2.7.0 fixture.
    - Signed tag `v0.1.0a5`, and a GitHub pre-release.
    - Docs and the scan page now show `uses: limbowatch/limbowatch-action@v0.1.0a5`; the old path keeps working.
- **Caveats:** Not listed yet: the agreement and the checkbox are the org owner's. The docs don't say whether Marketplace shows pre-releases.
- **Update (2026-11-10):** listed. The owner accepted the agreement and published the release. [github.com/marketplace/actions/limbowatch](https://github.com/marketplace/actions/limbowatch) answers 200 and shows v0.1.0a5 marked "Latest" and "Pre-release", by limbowatch, with the README as its page. So Marketplace does list a pre-release.
- **Implication:** Each release also pushes the action subtree and tags it (release checklist). The Marketplace listing follows once the owner ticks the box on a release.
- **Sources:** [GitHub Docs: Publishing actions in GitHub Marketplace](https://docs.github.com/en/actions/how-tos/create-and-publish-actions/publish-in-github-marketplace); limbowatch/limbowatch-action.

### F-128
- **Date:** 2026-11-10 · **Status:** confirmed (observed)
- **Question:** Do the published integrations work end to end on the demo app: the action from GitHub Marketplace and the component from the GitLab CI/CD Catalog?
- **Method:**
  - `limbowatch/demo-app` on GitHub now uses `limbowatch/limbowatch-action@v0.1.0a5`, and on GitLab component `0.1.0-alpha.5`.
  - Both on `main`, merged into `add-scapy`, which reran pull request #1 and merge request !1.
  - Read the runs' reports, GitLab's Code Quality summary (GraphQL) and test report.
  - Rechecked every advisory found against `GET /advisories/{ghsa}` and OSV.
- **Result:**
  - **GitHub (Marketplace action):**
    - Pull request run 42800465479, image mode: 67 findings, 67 advisories, 7 packages (9 high, 25 medium, 33 low). The job fails on the 9 high, as designed (`fail-on: high`).
    - Report artifact with all six reports; code scanning alert inline on the added `scapy==2.7.0` line.
    - The `main` run (42800452604): 16 findings in 6 packages (5 high), the "16 vs 0" demo.
  - **GitLab (Catalog component):** merge request pipeline 3049133249 ran `registry.gitlab.com/limbowatch/limbowatch-component:0.1.0a5@sha256:785a5d3e…`:
    - 81 dependencies, the same 9 high failing;
    - Code Quality 67 (9 critical, 25 major, 33 minor), and the merge request widget reports 51 new against `main`;
    - test summary 67 total, 9 failed.
  - **Still in limbo:** all 67 advisories answer 404 from GitHub's global database and from OSV (10:50 UTC).
  - **Screenshots:** all ten refreshed from these runs, in dark and light. The GitLab widget shot is now 1456×837 (was 822).
- **Caveats:** One demo project; scapy's 51 advisories dominate.
- **Implication:** The Marketplace action and the Catalog component give the same results as the CLI, and the scan page's captions hold on 0.1.0a5.
- **Sources:** demo-app runs and pipelines above; `limbowatch-report` artifacts.

### F-129
- **Date:** 2026-11-10 · **Status:** confirmed (official docs and direct observation)
- **Question:** How do GitLab and Gitea/Forgejo list a group's or org's projects for org-wide mode (Phase 5 step 3): defaults, pagination, and what a private group looks like without access?
- **Method:**
  - GitLab docs, "List projects" of a group (`GET /groups/:id/projects`).
  - Read-only requests to gitlab.com, no token: groups `limbowatch`, `gitlab-org/ci-cd`, `gitlab-org/cluster-integration`, `gitlab-org/security-products/analyzers`, with and without `archived`, `with_shared`, `simple`.
  - Codeberg (Forgejo 17.0.0, "gitea-1.22.0" compatible): `GET /api/v1/orgs/forgejo/repos`, `/api/v1/settings/api`.
  - Gitea 28.3.0 in Docker (`scripts/e2e_gitea.py`): a private org with private repos, listed with and without a token, as an org and as a user.
- **Result:**
  - **GitLab:**
    - `include_subgroups` defaults to false and `with_shared` (projects shared into the group from elsewhere) to true, so org-wide mode sets both explicitly.
    - `archived` has no default: archived projects are listed unless filtered. In `gitlab-org/ci-cd`, 41 of 234 are archived; in `cluster-integration`, 5 of 17.
    - Paging is by offset: `x-next-page`, `x-total`, and a `Link` header with `rel="next"` carrying every parameter. No offset limit is documented for this endpoint, and keyset paging isn't offered for it.
    - Fields used: `path_with_namespace`, `http_url_to_repo`, `web_url`, `visibility`, `archived`, `empty_repo`, `repository_access_level`, `marked_for_deletion_on`. Unauthenticated, the 500-requests-a-minute `throttle_unauthenticated_api` limit applies.
  - **Forgejo/Gitea:**
    - `max_response_items` is 50 on Codeberg; pages carry `Link: rel="next"` and `x-total-count`.
    - Fields used: `full_name`, `clone_url`, `html_url`, `private`, `internal`, `archived`, `empty`. In `forgejo`, 4 of 20 repos are archived and 3 empty.
    - An org that doesn't exist answers 404 on `/orgs/{name}/repos`; a user's repos are at `/users/{name}/repos`.
    - **A private org answers `200 []` to a request without access**, on both `/orgs/` and `/users/`, the same as an empty org.
  - **Git over HTTP with a token:** GitLab accepts Basic `oauth2:<token>` (checked with an OAuth token on the private `limbowatch/limbowatch-e2e`); a `Bearer` header is refused (git asks for a user name). Gitea accepts Basic with the token as password and any user name. Both work with the header passed as `http.<base>/.extraHeader` through `GIT_CONFIG_COUNT`.
- **Caveats:** GitLab behaviour was observed on gitlab.com only; self-managed versions before 18.8 lack the `active` filter, which isn't used.
- **Implication:** Org-wide mode sets `include_subgroups=true` and `with_shared=false`, filters archived, empty and deleted projects itself so each is reported, follows `rel="next"` only on the same host, and treats a source with no projects at all as an error that names the token, because Gitea hides a private org behind an empty list.
- **Sources:** [GitLab groups API](https://docs.gitlab.com/api/groups/); gitlab.com and codeberg.org responses; trimmed fixtures in `tests/fixtures/hosts/`; `scripts/e2e_gitea.py`.

### F-130
- **Date:** 2026-11-10 · **Status:** confirmed (observed); tentative for other groups (two groups, one machine)
- **Question:** What does org-wide mode (`limbowatch watch`) cost on real groups, and how much does polling each source repo once for all projects save?
- **Method:**
  - `limbowatch watch --gitlab-group …` on two public gitlab.com groups, no source token, with a GitHub token, OSV-Scanner 2.7.0, `--jobs 4`, on an Apple-silicon laptop, 2026-11-10.
  - `gitlab-org/cluster-integration` (17 projects) twice, with `--state`; `gitlab-org/security-products/analyzers` (98 projects) twice, before and after the F-131 fix.
  - Per-project polling cost read from each project's own `repos_polled` (what a separate `scan` of that project would have polled).
  - 12 of the 193 advisories found in `analyzers` sampled at random and checked against `GET /advisories/{ghsa}` and OSV.
- **Result:**
  - **cluster-integration:** 12 checked, 5 archived (listed as not checked). 1,270 dependencies, 528 source repos: 508 recently checked by the tracker, 20 polled. 42 findings in 6 projects. 14 s; the second run 12 s, with no changes reported.
  - **analyzers:** 98 listed, 50 checked; 46 archived and 2 empty listed as not checked.
    - 43,819 dependencies, 8,572 unique; 3,318 source repos, 2,853 recently checked by the tracker.
    - **465 repos polled for the whole group, against 784 if each project were scanned on its own** (7,867 repo look-ups summed over projects).
    - 907 findings, 193 advisories, in 31 projects (46 critical, 282 high).
    - About 3 minutes (179 s wall, 123 s CPU, mostly OSV-Scanner), 250 MB peak memory on the small group.
    - The first run left `analyzers/command` unchecked (F-131); after the fix all 50 were checked.
  - **Still in limbo:** all 12 sampled advisories answer 404 from GitHub's global database and from OSV (2026-11-10).
  - **Image:** git from Debian (2.47.3) adds a 102 MB layer to the image (359 MB in all, linux/arm64 local build); `watch` ran in it on cluster-integration with the same result.
- **Caveats:**
  - Public groups on gitlab.com; clone time grows with repo size, and these repos are small to medium.
  - The saving depends on how much the projects share; these analyzers share a lot (Go modules).
  - Without a GitHub token, 465 polls exceed the anonymous limit of 60 an hour; such repos are reported as checked by name only.
- **Implication:** One scheduled run covers a 50-project group in minutes, and shared polling cuts GitHub requests by about 40% there. A GitHub token is still needed for any real group.
- **Sources:** run JSON in the session scratchpad (not committed); gitlab.com group listings; GitHub and OSV lookups.

### F-131
- **Date:** 2026-11-10 · **Status:** confirmed (observed)
- **Question:** Why did `gitlab-org/security-products/analyzers/command` fail the inventory with "osv-scanner exited with 127"?
- **Method:** OSV-Scanner 2.7.0, offline as the watcher runs it, on a directory with one empty `pom.xml`, then on one with an empty `pom.xml` and two broken `package-lock.json`.
- **Result:**
  - One unreadable file of a kind: `Error during extraction: (extracting as java/pomxml) PATH: ERROR`, on one line (the format F-078 recorded).
  - Several of the same kind: the line ends after `(extracting as javascript/packagelockjson) `, and each file follows on its own tab-indented line, `\tPATH: ERROR`.
  - The parser read only the one-line form. With exit code 127 and no file it recognised, it treated the run as failed, so the whole project went unchecked. `analyzers/command` has two empty `pom.xml` test fixtures.
- **Caveats:** One OSV-Scanner version; the format comes from its error aggregation and may change.
- **Implication:** Fixed: both forms are read, and each file is reported as "lockfile couldn't be read". `limbowatch scan` had the same bug on any project with two unreadable lockfiles of one kind.
- **Sources:** recorded stderr in `tests/test_inventory.py`.

### F-132
- **Date:** 2026-11-10 · **Status:** confirmed (observed; 4 Maven and 3 Gradle projects, one day); tentative beyond them
- **Question:** Does the watcher's inventory of Maven and Gradle projects match what the build tool resolves (Phase 5, PHASE0_PLAN §9)? OSV-Scanner runs offline there, which turns off its `pom.xml` resolver (F-032).
- **Method:**
  - **Maven:** spring-projects/spring-petclinic `500158f`, jhipster/jhipster-sample-app `6b000b5`, apache/commons-text `ed3f23e` (single module) and apache/maven-resolver `77f371c` (32 `pom.xml`). Ground truth: `mvn -B dependency:list -Dsort=true` (Maven 3.9, `maven:3.9-eclipse-temurin-21` in Docker), every scope, compared by `group:artifact` and version.
  - **Compared:**
    - `limbowatch inventory` as released (OSV-Scanner 2.7.0 `--offline`);
    - OSV-Scanner online (`scan source --all-packages`);
    - a resolving run limited to `--x-no-default-plugins --x-plugins java/pomxml,transitivedependency/pomxml --offline-vulnerabilities` against empty databases.
  - **Hosts:** every run went through a local CONNECT proxy that logged each host and refused all but an allow-list.
  - **Gradle:** Netflix/maestro `4af9a65` (15 lockfiles), google/nomulus `0770838` (29), bitwarden/android `012c687` (3). Every `group:artifact:version` in their `*.lockfile`s compared with the inventory. Plus spring-petclinic's `build.gradle` alone (its `pom.xml` removed).
  - **Findings:** `limbowatch scan --fail-on none` on petclinic and JHipster with and without resolution; each advisory checked with `GET /advisories/{ghsa}` and OSV `GET /v1/vulns/{ghsa}`.
- **Result:**
  - **Offline, a `pom.xml` gives only its direct dependencies with a literal version.**

    | Project | Maven resolves | Checked offline | Reported as having no version | Not mentioned |
    |---|---|---|---|---|
    | spring-petclinic | 171 | 3 | 25 | 143 |
    | jhipster-sample-app | 282 | 6 | 42 | 234 |
    | commons-text | 33 | 9 | 2 | 22 (all test scope) |

    Nothing told the user the transitive dependencies were missing.
  - **OSV-Scanner's resolver matches Maven.** petclinic 171 of 171 and JHipster 282 of 282, with every version identical, BOMs, parents, properties and optional dependencies included. A hand-made fixture with an imported BOM also matches `mvn dependency:list` exactly, so the recorded test compares against Maven's own output.
  - **What it misses:**
    - commons-text: 24 of 33. The 9 missing are test dependencies in profiles activated by JDK version (`<jdk>[11,22)</jdk>`), which the resolver doesn't evaluate.
    - maven-resolver: 28 of the 30 Maven manifests it reads (`pom.xml` and two `*.pom` test files) fail with "failed resolution for PATH: … `2.0.26-SNAPSHOT`: not found", because each module depends on unreleased siblings from the same build. Maven itself stopped at the second module for the same reason without a full `install`, which wasn't run because it executes the project's build plugins.
  - **What it contacts.** The resolving run reached only `api.deps.dev` and `repo.maven.apache.org`. With only deps.dev allowed it fails: it fetches parent POMs from Maven Central.
  - **Without `--offline`, OSV-Scanner also resolves `requirements.txt` through deps.dev** (`transitivedependency/requirements`), which would pick versions for ranges like `flask>=2`. That's why the resolving run is limited to the pom.xml plugins and kept separate. On a mixed tree it changed only the `pom.xml` results (+168 packages); every other file's packages were identical.
  - **Output shape.** The resolving run lists each `pom.xml` twice: the direct dependencies (as offline, versionless ones included), then a group of `type: unknown` with the whole resolved tree. A `pom.xml` whose dependencies have none of their own (one `javax.inject:javax.inject:1`) gets no second group and no error. Failures are on stderr, one line per file, the first also after "Error during extraction: (extracting as transitivedependency/pomxml)". Exit code 127 when any file fails.
  - **Gradle lockfiles are read completely:** maestro 329 of 329 coordinates, nomulus 730 of 730, bitwarden 190 of 190. A Gradle build without a lockfile gives nothing: petclinic's `build.gradle` alone exits 128, and the inventory said only "no supported lockfile", with a `.gitignore` hint that didn't apply.
  - **It changes findings.** With resolution, petclinic goes from 0 findings to 19 and JHipster from 0 to 43 (`--fail-on none`), 37 distinct advisories in all: Netty, Thymeleaf, unbescape, PostgreSQL JDBC, Hibernate, Jackson 3, brotli4j. All 37 answer 404 from GitHub's reviewed database and from OSV. Run time: 3 s → 33 s (petclinic) and 2 s → 58 s (JHipster), mostly the extra repos polled on GitHub.
- **Caveats:**
  - Four Maven projects, three of them Spring; plugin-heavy builds, `<repositories>` and private registries weren't tried. None of these projects declares extra repositories, so whether the resolver would contact them is untested.
  - The docs say test dependencies aren't in the resolved graph; here they were, for every test dependency outside JDK-activated profiles.
  - Gradle builds without lockfiles weren't resolved, because that needs Gradle to run the project's build scripts.
  - deps.dev's view of Maven Central can lag a new release, so a just-published version may fail to resolve. A failure is reported, never silent.
- **Implication:**
  - **Resolve by default.** The inventory now resolves `pom.xml` in a second OSV-Scanner run limited to the pom.xml plugins, and merges the resolved tree. `--no-resolve-maven` (`scan`, `watch`, `inventory`) turns it off. The only new egress is a `pom.xml`'s dependencies to deps.dev and Maven Central, which already received package names for repo mapping.
  - **Never silent.** Every Maven manifest that isn't resolved (a failure, or the flag) is reported as "transitive dependencies not resolved", with the resolver's message. Every Gradle build file without a `gradle.lockfile` beside it (and no `gradle/verification-metadata.xml`) is reported as "Gradle build without a lockfile".
  - **For an exact Maven inventory,** use an SBOM from `cyclonedx-maven-plugin` (`--sbom`); docs/WATCHER.md lists the limits.
- **Sources:** OSV-Scanner v2.7.0 docs `docs/supported_languages_and_lockfiles.md` ("Transitive dependency scanning", "Data source") and `docs/offline-mode.md`; `osv-scanner scan source --help`; the runs above (raw output in the session scratchpad; fixture in `tests/fixtures/inventory/maven/`).

### F-133
- **Date:** 2026-11-10 · **Status:** confirmed (observed)
- **Question:** Release 0.1.0a6 (org-wide mode, Maven resolution): did the pre-release audit pass, and did every artifact ship as tested?
- **Method:** `scripts/audit.py`, then the release order in the project's release checklist.
- **Result:**
  - **Audit:** passed at 17:24 UTC on the site built at 15:19 UTC (tracker-data 9f42611):
    - 520 verdicts sampled live (300 limbo, 100 permanent, 60 duplicate, 60 reviewed), 0 wrong;
    - reviewed sync complete (121 reviews in 7 days, 78 from repository advisories, 0 missing);
    - 19 metrics reproduced;
    - 24,561 feed records valid OSV and matching the state;
    - 12,268 converted ranges consistent with the parser;
    - checker index 4,775 = feed.
  - **Image:** `ghcr.io/limbowatch/limbowatch:0.1.0a6@sha256:a10ccd3a…` (built from 8fcf60d; reports `limbowatch 0.1.0a6` and OSV-Scanner 2.7.0; SLSA provenance verified, signer `image.yml@refs/heads/main`), pinned in the action and the GitLab template (2e65507).
  - **Tags:** `v0.1.0a6` is GPG-signed and verified. The release workflow published PyPI 0.1.0a6 and a GitHub pre-release, and the image workflow retagged the pinned digest.
  - **GitLab component:** split 386d3f6 on gitlab.com `main` (pipeline 3051196247 passed; mirror digest equals the ghcr.io digest; `limbowatch-ultimate-gate` fails as designed and is allowed to, as in 0.1.0a5); signed tag `0.1.0-alpha.6` (pipeline 3051203974 passed; CI/CD Catalog release 18:55 UTC).
  - **Action repo:** split f7152f8 on `limbowatch/limbowatch-action` `main`; self-test passed on Linux (image) and macOS (pip), though the macOS runner was queued for 10 minutes; signed tag `v0.1.0a6` and a GitHub pre-release.
  - **Org profile:** updated (e900ebd).
  - **Smoke test:** `uvx --from limbowatch-cli==0.1.0a6` on the demo app (`add-scapy`) found the same 67 advisories as 0.1.0a5, with identical finding keys and the same 3 unresolved entries. The demo has no Maven or Gradle builds, so the screenshots still match and weren't refreshed.
- **Implication:** `watch` and Maven resolution ([F-132](#f-132)) reach users. Maven resolution is on by default (`--no-resolve-maven` opts out).
- **Sources:** GitHub Actions runs 42865043716 (image, 8fcf60d), 42879865561 (release), 42879865719 (image, tag), limbowatch-action 42881746321; GitLab pipelines above; PyPI.

### F-134
- **Date:** 2026-11-10 · **Status:** confirmed (official documents)
- **Question:** What do SOC 2 and PCI DSS say about finding and fixing newly published vulnerabilities, and when does the clock start? (For the home page's compliance section.)
- **Method:** Read the criteria text directly:
  - AICPA TSP Section 100, *2017 Trust Services Criteria* (with the March 2020 updates), CC7.1 and CC7.2, from the AICPA's PDF. The AICPA download page needs a free account, so the PDF was read from a copy of the same file;
  - PCI Security Standards Council FAQ 1597 (May 2025) on vulnerability risk rankings and Requirement 6.3.3.
- **Result:**
  - **SOC 2, CC7.1:** "the entity uses detection and monitoring procedures to identify (1) changes to configurations that result in the introduction of new vulnerabilities, and (2) susceptibilities to newly discovered vulnerabilities."
  - **SOC 2, CC7.1 point of focus "Conducts Vulnerability Scans":** scans run "on a periodic basis and after any significant change", and the entity "takes action to remediate identified deficiencies on a timely basis." CC7.2's points of focus include "use of intelligence sources to identify newly discovered threats and vulnerabilities".
  - **SOC 2 sets no deadline.** The entity's own policy does, and the auditor tests against it.
  - **PCI DSS, FAQ 1597:** Requirement 6.3.3 sets time frames for installing patches. Patches for critical vulnerabilities "must be resolved within one month of release"; for other vulnerabilities, the entity sets the time frames from its own risk rankings (6.3.1).
- **Caveats:**
  - Secondary sources disagree on whether v4.0 or v4.0.1 also put high-severity patches under the one-month rule, so the site cites only "critical", the FAQ's wording.
  - The AICPA published an exposure draft on 2026-10-27 that would restructure the common criteria (vulnerability monitoring would move to CC5.6). It isn't final, and the text above is the current criteria.
  - This is how the frameworks are worded, not audit advice.
- **Implication:**
  - Under a policy counted from the scanner's alert (common for SOC 2), time in limbo is added to the exposure without breaking the policy: at October's median review wait, a 30-day policy finishes on day 53 after publication ([F-055](#f-055)).
  - Under PCI DSS the one month runs from the fix's release. When the fix ships with the advisory, a scanner that waits for review speaks up on day 23 with 7 days left. 44% of October's reviews took longer than 30 days.
  - The home page says this, with sources, and adds that it isn't audit advice.
- **Sources:** [AICPA: 2017 Trust Services Criteria](https://www.aicpa-cima.com/resources/download/2017-trust-services-criteria-with-revised-points-of-focus-2022) (TSP 100, CC7.1, CC7.2); [PCI SSC FAQ 1597](https://www.pcisecuritystandards.org/faqs/1597/).

### F-135
- **Date:** 2026-11-10 · **Status:** confirmed (measured on the live feed and tracker state; docs and single probes for the rest)
- **Question:** Before planning Phase 6 (upstream-watch): how much of the limbo feed has no package a consumer can match, what does the watcher do with C/C++-style dependencies today, and what do existing tools and package indexes already give us?
- **Method:**
  - Feed: `limbo.watch/feed/all.zip` (24,561 records, modified 2026-11-10) joined to `state/advisories.jsonl` on the `tracker-data` branch (same day). A record "has no package" when `affected` is empty.
  - Watcher: `limbowatch inventory` (0.1.0a6) and OSV-Scanner 2.7.0, offline as the watcher runs it and online, on a test repo with a git submodule, a CMake `FetchContent_Declare(zlib GIT_REPOSITORY … GIT_TAG v1.3.1)` and a `vcpkg.json`.
  - Docs: OSV-Scanner v2.7.0 `docs/supported_languages_and_lockfiles.md` ("C/C++ scanning") and `docs/offline-mode.md`.
  - Package indexes: `microsoft/vcpkg` `ports/zlib/portfile.cmake` and `vcpkg.json`; `bazelbuild/bazel-central-registry` `modules/zlib/metadata.json`.
  - blindspot: the README of munimtechnologies/advisory-import-census (pushed 2026-11-11 00:58 UTC).
- **Result:**
  - **60% of the feed has no package.** 14,785 of 24,561 limbo records have an empty `affected`: their advisories name ecosystem `other` (11,426 packages), `bottlerocket`, `c`, `frappe`, `c/c++`, `php`, `docker`, … for which OSV has no ecosystem, so the feed leaves them out. They come from 1,858 repos (bottlerocket-os/bottlerocket 462, freerdp/freerdp 338, discourse/discourse 298, …, imagemagick/imagemagick 116, envoyproxy/envoy 108). 14,632 of them are likely permanent.
  - **Their versions are there.** 14,578 of the 14,785 carry a vulnerable range or patched version in the tracker state (207 don't). Formats vary: `<= 8.6.3`; `10.6.1-10.6.27, 10.11.1-10.11.18`; `2.1.15-2.1.38 (Earlier versions may be affected but were not tested)`.
  - **The watcher sees none of a C/C++ project's dependencies.** On the test repo, the inventory reports "0 dependencies from 0 files" and one "can't be checked" line whose hint (`.gitignore`) doesn't apply. Offline, OSV-Scanner makes 0 extract calls ("No package sources found"). Online it reads the submodule's `.git/modules/...` (0 packages for a local upstream with no tags or remote). CMake and vcpkg manifests aren't read in either mode.
  - **OSV-Scanner's C/C++ support is OSV's own commit ranges, online only.** It checks submodules (checked out, with history) and vendored copies (identified by hashing files through OSV's `determineversion` API) against OSV records with GIT ranges. Offline mode lists "commit level scanning is not supported".
  - **vcpkg and the Bazel Central Registry name the upstream.** The zlib port's `vcpkg_from_github(REPO madler/zlib REF v${VERSION})` gives the repo and the tag scheme, with version 1.3.2 in the port's `vcpkg.json`. BCR's `metadata.json` gives `repository: ["github:madler/zlib"]`, with versions like `1.3.2.bcr.3` (the BCR suffix must be stripped). Conan isn't in `limbowatch.ecosystems`; its recipes live in `conan-center-index`, a recipe repo (Q7).
  - **blindspot still reads npm, PyPI and Go lockfiles only.**
- **Caveats:**
  - "No package" also covers applications (Discourse, GLPI, OpenEMR) that are never a dependency; how much of the 14,785 is libraries consumed by other projects isn't measured.
  - One port and one module were read; coverage of `vcpkg_from_github` across ports, and of `repository` across BCR modules, isn't measured.
  - The online submodule probe used a local upstream, so it doesn't show what OSV-Scanner reports for a real one.
- **Implication:**
  - Phase 6's largest gap is in our own feed and watcher, not in other tools: OSV-Scanner covers OSV's reviewed commit ranges; nobody covers repository advisories for upstreams consumed by submodule, CMake, vcpkg, Bazel, Conan or copy.
  - Matching those needs the dependency's upstream repo plus a version or commit, and the advisory's versions mapped to the upstream's tags (Q26).
  - The inventory should stop calling a C/C++ project "no supported lockfile": it should say which dependency files it found and couldn't read.
- **Sources:** the probes above (raw output in the session scratchpad); OSV-Scanner v2.7.0 docs; GitHub API reads of the files named in Method.

### F-136
- **Date:** 2026-11-11 · **Status:** confirmed (measured; the project survey is a sample of 85)
- **Question:** Phase 6, step 0: which limbo advisories without a package are about libraries, do their patched versions exist as upstream tags (Q26), how do C/C++ projects take in dependencies, and how can a pinned commit be checked against a fix?
- **Method:** `research/2026-11-upstream-watch/` (README there):
  - `indexes.py`: upstream repo of every vcpkg port (`vcpkg_from_github`/`_gitlab`/`_git`, download URLs), Bazel Central Registry module (`metadata.json` `repository`, else `source.json` URL) and conan-center recipe (`conandata.yml` source URLs), from sparse shallow clones made 2026-11-10/11 (vcpkg e54ef0f, BCR 27778ec9, conan-center-index 355759d).
  - `libraries.py`: the feed of 2026-11-10 (24,561 records) and `state/advisories.jsonl` (tracker-data); tags of each library repo by `git ls-remote --tags`; each patched version looked up as `X`/`vX`, then by the numbers in the tag.
  - `survey.py`: 85 projects (25 most-starred C++ and 25 most-starred C repos on GitHub search, 35 drawn with seed 20261110 from repos with 200-2,000 stars pushed in 2026), cloned shallow and blob-less with a sparse checkout of dependency files only.
  - Probes: `git clone --bare --filter=tree:0` of 7 upstreams; `git merge-base --is-ancestor`; `GET /repos/madler/zlib/compare/{base}...{head}`; OSV `POST /v1/query` and `/v1/querybatch` with `{"commit": …}`.
- **Result:**
  - **Indexes:** 2,437 of 2,917 vcpkg ports, 1,284 of 1,400 BCR modules and 1,641 of 1,977 conan-center recipes name an upstream forge repo; 3,661 repos in all, 3,620 on GitHub. The rest are vcpkg helper and meta-ports, other hosts, or recipes downloading from project sites.
  - **Libraries among the package-less records:** 1,472 of 14,785 (10%), from 95 repos (vcpkg 78, conan 58, BCR 40): FreeRDP 338, ImageMagick 116, libheif 90, vim 82, OpenEXR 73, bacnet-stack 60, Fast DDS 36, git 32, Exiv2 32, libyang 31. Another 89 limbo records with a package come from 19 index repos.
  - **Fixes as tags (Q26):** every patched version found for 1,207 of the 1,472 advisories (82%), some for 102, none for 83; 68 give no patched version and 12 are in repos without tags. Per patched version: 1,663 exact, 281 by numbers (`bacnet-stack-1.6.0`, `release-22.1.8`, `v26.03`; checked by hand on a sample of 14), 3 ambiguous, 187 missing. Misses seen: ImageMagick 6 versions (released from ImageMagick/ImageMagick6), `0.27.5 RC1` vs tag `v0.27.5-RC1`, commit hashes given as the patched version.
  - **Projects (85):** 41 declare dependencies in a form the survey reads, 1,201 dependencies in all:
    - git submodules: 17 projects, 300 dependencies, 296 with repo and commit (from the tree; the submodules weren't fetched);
    - Bazel: `MODULE.bazel` 5 projects, 163 (158 resolved through BCR to repo and version); `http_archive` and wrappers such as `tf_http_archive` 4 projects, 325 (182 with repo and tag or commit);
    - CMake: FetchContent 17 projects, 75 (35 with repo and ref); ExternalProject 13 projects, 58 (5; URLs are mostly variables);
    - `vcpkg.json`: 5 projects, 114 (41 through a registry port; the rest are helper ports or the project's own overlay ports); the version needs the builtin baseline;
    - vendored copies (a license file under `third_party/`, `3rdparty/`, `vendor/`, …): 22 projects, 153, version unknown;
    - CPM and meson wraps: 3 projects, 13.
    - Upstream and version or commit known: 718 of 1,201 (60%).
    - 14 of the 85 projects (16%) depend on an upstream with records in the limbo feed (protobuf, fmt, gRPC, c-ares, xz, libpng, harfbuzz, nghttp2, PCRE2, cpp-httplib, capstone, …).
  - **Commit vs fix:** commits-only bare clones took 0.6-2.6 s and 0.4 MB (zlib, 1,212 commits) to 22 MB (gRPC, 66,927 commits); `merge-base --is-ancestor` gives v1.2.11 ⊂ v1.3.1 and not the reverse. The compare API agrees (`v1.3.1...v1.2.11` behind 216; reversed ahead 216; same tag identical) at one request per pair. Tags must be peeled (`refs/tags/X^{}`): zlib's are annotated, and the tag object's SHA gives 404 from the compare API and nothing from OSV.
  - **OSV by commit:** zlib v1.2.11 → 6 CVEs (CVE-2018-25032, CVE-2022-37434, CVE-2023-45853, three of 2026), v1.3.1 → 4; c-ares v1.19.0 → 6. `querybatch` returns the same IDs.
- **Caveats:**
  - Index membership is a lower bound for "library": a repo consumed only by submodule or copy isn't counted.
  - "Depends on an upstream with limbo records" doesn't mean the pinned version is affected; it includes projects pinning themselves (protobuf, gRPC).
  - The survey's parsers are regex-based; ExternalProject URLs built from variables, project-local vcpkg overlays and vendored code without a license file in the expected place are missed or unmapped.
  - Popularity-sampled projects; enterprise C/C++ (Conan-heavy, private registries) is under-represented: no project in the sample uses Conan.
- **Implication:**
  - Step 1 detectors, by yield: submodules (exact repo and commit), Bazel (`MODULE.bazel` through BCR, and `http_archive` URLs including wrappers), CMake FetchContent, then vcpkg (needs the baseline), Conan (absent from the sample; keep last), vendored (report only).
  - Step 2: check commits with a commits-only clone of the upstream and `merge-base --is-ancestor`, not the compare API: no quota, any git host, exact. Patched versions that are commit hashes are used directly. Peel tags.
  - Step 3: one OSV `querybatch` per project covers its commits.
  - Step 4: 82% of the library advisories can get OSV `GIT` ranges from `ls-remote` alone; the rest keep their versions as entered.
- **Sources:** the scripts and `libraries.json`, `survey.json` in `research/2026-11-upstream-watch/`; OSV API; GitHub REST API docs ("Compare two commits").

### F-137
- **Date:** 2026-11-11 · **Status:** confirmed (measured on 85 projects; registry APIs probed live)
- **Question:** Phase 6, step 1: on real projects, how many upstream sources do the watcher's detectors find, and how many end with a repo and a tag or commit once registry names are looked up? What do the registries need?
- **Method:**
  - `research/2026-11-upstream-watch/detectors.py`: `limbowatch.inventory.upstream.detect` on the 85 clones of F-136, then `limbowatch.watch.registries.Registries.resolve` (live, 2026-11-11); upstreams counted once per project.
  - Probes: `https://bcr.bazel.build/modules/zlib/metadata.json` and `.../1.3.1.bcr.3/source.json`; `https://raw.githubusercontent.com/microsoft/vcpkg/e54ef0f…/versions/baseline.json` and `ports/*/portfile.cmake`; `https://raw.githubusercontent.com/conan-io/conan-center-index/master/recipes/zlib/{config.yml,all/conandata.yml}`; `https://center2.conan.io/v2/conans/zlib/1.3.1/_/_/latest` and `.../revisions/{rev}/files[/conan_export.tgz]`; OSV-Scanner 2.7.0 offline on a directory holding only a `conan.lock`.
- **Result:**
  - **Upstream sources:** 857 in 33 of the 85 projects; **763 (89%) end with a repo and a tag or commit** (411 commits, 352 tags), 7 with a repo and a version only, 14 with a repo only, 73 with no repo. 164 vendored copies are reported.
    - git submodules 300 of 303 (commits from the index; the clones' submodules weren't fetched);
    - Bazel modules 132 of 135 (through BCR's `source.json`), `http_archive` and wrappers 213 of 247;
    - CMake FetchContent 45 of 54, ExternalProject 8 of 30 (19 are archives inside the tree), CPM 2 of 7;
    - vcpkg ports 60 of 76, after reading the project's own (overlay) ports from their portfiles: without that, 35 of 76, because an overlay port's `vcpkg.json` (sirius-db: 11 of them) has no baseline of its own;
    - meson wraps 3 of 5.
  - **No repo:** downloads from project sites (curl.se, zlib.net, sqlite.org, ftp.gnu.org through a TensorFlow mirror, sourceforge), archives inside the tree, and URLs built from variables the project doesn't set.
  - **Registry cost:** 119 requests to bcr.bazel.build and 108 to raw.githubusercontent.com for all 85 projects; nothing to GitHub's API.
  - **BCR:** a module version's `source.json` names its archive, e.g. zlib 1.3.1.bcr.3 → `github.com/madler/zlib/releases/download/v1.3.1/zlib-1.3.1.tar.gz` (tag v1.3.1); `metadata.json` lists `repository: ["github:madler/zlib"]`.
  - **vcpkg:** the baseline file (229 KB) gives each port's version; a portfile's `vcpkg_from_github(REPO … REF …)` gives the repo and tag template (`v${VERSION}`, `"${VERSION}"`). curl's REF is computed (`string(REPLACE "." "_" curl_version "curl-${VERSION}")`), so only its version is known.
  - **Conan:** conan-center-index on GitHub keeps only current versions (zlib: only 1.4 on 2026-11-11, so 1.3.1 isn't there). The ConanCenter remote serves every version: `…/latest` gives the recipe revision, and `…/revisions/{rev}/files/conan_export.tgz` (447 bytes for zlib 1.3.1) holds `conandata.yml` with the source URLs (zlib 1.3.1 → madler/zlib v1.3.1; openssl 3.2.1 → openssl/openssl `openssl-3.2.1`). `conandata.yml` isn't served on its own (404).
  - **OSV-Scanner offline fails on any `conan.lock`:** "unable to fetch OSV database: no offline version of the OSV database is available", and the whole inventory is lost. Its packages are ecosystem `ConanCenter`, which isn't in OSV's ecosystem list, so our empty databases had no zip for it. With an empty `ConanCenter/all.zip` the lock is read (2 packages). This affected every release since 0.1.0a1, and OSV-Scanner users of the feed's zips.
- **Caveats:**
  - Survey projects only; vcpkg and Conan are thin in the sample (3 vcpkg projects, 0 Conan); the Conan path was checked on a test lock.
  - A vcpkg override or `version>=` above the baseline uses the baseline's portfile with the new version substituted; when the REF isn't a `${VERSION}` template, the tag is left unknown.
  - ConanCenter's latest recipe revision is read, not the one in the lock; source URLs rarely change between revisions.
- **Implication:**
  - Step 2 can compare 89% of upstream sources directly; for "repo and version" (curl's computed tag, 7 here) it needs the tag looked up by version, as in F-136.
  - Fixed in the watcher's empty databases and the feed: `OFFLINE_ECOSYSTEMS` = OSV's list plus ConanCenter.
- **Sources:** `research/2026-11-upstream-watch/detectors.py` and `detectors.json`; the URLs above; recorded fixtures in `tests/fixtures/upstream/`.

### F-138
- **Date:** 2026-11-11 · **Status:** confirmed (measured on the tracker's state and a local rebuild of the feed; two end-to-end cases). The FreeRDP counts are updated by [F-139](#f-139) after three verdict fixes.
- **Question:** Phase 6, steps 2-5: can advisories without a package be given OSV GIT ranges, does the watcher decide correctly whether a pinned upstream source is affected, and how many C/C++ upstreams would the tracker add?
- **Method:**
  - The `tracker-data` state of 2026-11-11 with the new tracker step `resolve_git_tags` (`git ls-remote --tags` per repo, `versions.tag_for`), then `limbowatch publish` locally; every record validated against the OSV schema (`tests/fixtures/osv_schema.json`).
  - The watcher (`watch.upstream_check`) on a test project: a git submodule of FreeRDP and a CMake `FetchContent` of ImageMagick, at old and at current releases, against that local feed, with commits-only clones and OSV `querybatch` by commit.
  - `tracker/seeds/make_cpp_upstreams.py` on vcpkg 2ec0f17, BCR 27778ec9 and conan-center-index 152616e, compared with the watchlist.
- **Result:**
  - **Tags:** 1,888 repos have advisories in limbo that name no package OSV knows; 1,692 name versions to look up, 8,539 versions in all, of which **7,065 (83%) are tags** (exactly, `v`-prefixed or by the numbers in the tag). 0 repos failed to list; 47 s for all of them.
  - **Feed:** 24,561 records, 0 invalid. 14,961 records have entries without a package (18,687 entries); **13,690 (73%) carry GIT ranges**, e.g. FreeRDP `>= 3.11.0, <= 3.30.0` → `introduced` 4312666c…, `last_affected` 6b107f0a…. No record has an empty `affected` any more (14,785 had, F-135).
  - **Watcher, FreeRDP submodule at 3.10.0** (6e662fd): 234 of FreeRDP's 338 advisories in limbo match, 231 certainly ("older than 3.29.0, the fix release, and doesn't contain it") and 3 possibly (ranges "N/A", "3.27.1 and HEAD", and one in prose); the rest are fixed before 3.10.0 or start after it. **At 3.33.1, the newest release: 0 certain, the same 3 possible.**
  - **ImageMagick `FetchContent` at 7.1.1-30:** 114 affected; one of them because OSV lists the commit under CVE-2026-109276, which the advisory cites. At 7.1.2-35: none.
  - Runs took 7-25 s, mostly the two clones (cached on the second run).
  - **A bug found on the way:** `package_name` calls any name valid in an ecosystem it doesn't know (`other`, `c`), so the first run treated FreeRDP's advisories as naming a package and matched only 2 of them. Upstream matching now counts a package only in an ecosystem OSV knows.
  - **Seeds:** 3,603 GitHub repos (vcpkg 2,312, BCR 1,209, ConanCenter 1,585, overlapping); 245 are already watched, 3,358 are new.
- **Caveats:**
  - Two upstreams were checked end to end; the verdicts follow from the tags and the advisories' own ranges, not from a reading of each advisory.
  - Advisories give versions, not fix commits: a commit between the fix commit and the fix release counts as affected, and GIT ranges built from `<= X` end at X's tag (`last_affected`), so unreleased commits after it count as unaffected.
  - Tags can move; the audit rebuilds a sample of the GIT ranges from the tags as they are now.
- **Implication:** advisories without a package, 60% of the feed, now reach C/C++ users through the watcher and OSV tools through GIT ranges. The tracker's seed list adds the C/C++ upstreams most projects build from.
- **Sources:** `packages/core/src/limbowatch/watch/upstream_check.py`, `publish/feed.py`, `tracker.py` (`resolve_git_tags`); `tracker/seeds/cpp-upstreams.txt`; tests in `tests/test_upstream_check.py`.

### F-139
- **Date:** 2026-11-11 · **Status:** confirmed (1,082 comparisons in 7 libraries; disagreements traced by hand: 3 of 17)
- **Question:** (Q27) Do the watcher's upstream verdicts agree with an independent judge?
- **Method:** `research/2026-11-upstream-watch/agreement.py`: FreeRDP (3.10.0, 3.20.0), ImageMagick (7.1.1-30, 7.1.2-0), vim (v9.1.0000, v9.1.1000), Exiv2 v0.28.0, libheif v1.17.0, OpenEXR v3.2.0, c-ares 1.19.0 (`cares-1_19_0`) and zlib v1.2.11, pinned by tag (zlib gave no comparison: it has no advisory in limbo). For each of their limbo advisories that cite a CVE OSV holds with GIT ranges on the same repo, the watcher's verdict (OSV's commit lookup off) is compared with OSV's version ranges for that CVE (`extracted_events` from the CVE record's affected field and NVD's CPE ranges) at the pin's release. OSV's commit lookup (`querybatch`) is recorded alongside. Feed: the local rebuild of F-138.
- **Result:**
  - **1,029 of 1,082 agree (95%)**, 35 are *possible* for us (3%), 17 disagree (1.6%): 12 we call affected and OSV doesn't, 5 the reverse; 1 has no usable OSV range. Each of the 3 disagreements traced is the advisory's own range differing from the CVE record or NVD: FreeRDP CVE-2026-111380 `<= 3.31.0` vs OSV from 3.29.0; libheif CVE-2026-62377 `>=1.20.0, <= 1.23.0` vs OSV from 0; vim CVE-2026-34714 `> v9.1.1390` vs OSV's affected field from 0.
  - **Three watcher bugs found and fixed on the way:**
    - a range's upper bounds were taken as fix releases even when the advisory names its fixes: OpenEXR's `2.*, 3.0.*, 3.1.*, 3.2.0-3.2.9, …` reads `3.1.*` as `< 3.2.0`, so v3.2.0 counted as "containing a fix" (13 disagreements at v3.2.0, none after the fix);
    - a range of exact versions was read as only those: FreeRDP's `3.26.0` (fixed in 3.27.0) meant "up to 3.26.0"; an older pin is now *possible*, never cleared;
    - a pin older than the fix release, with a range that can't be read, was called affected: vim's `Version > v9.1.0425 and Version < v9.1.0689` at v9.1.0000. Such a pin is now *possible*, and the parser reads a "Version" label (2 of the tracker's 58,246 ranges become readable; no reading changes).
  - **OSV's commit lookup can't be the judge:** it differs from OSV's own ranges in 465 of the 1,082. For FreeRDP it lists no CVE at all for 3.10.0's commit (223 for 3.5.0's), and its affected versions stop at 3.5.1, though 3.10.0 is in the history of the fix commits. OSV's GIT ranges can't be read literally either: fixes made only on release branches (FreeRDP's `stable-2.0`) leave every later `master` commit "affected" under a plain reading; OSV resolves those with its own branch and cherry-pick analysis.
  - **After the fixes,** the FreeRDP submodule at 3.10.0 of F-138 gives 228 certain and 12 possible findings (was 231 and 3); ImageMagick at 7.1.1-30 still 114.
- **Caveats:** only advisories citing a CVE that OSV holds with ranges on the same repo could be judged (1,082 comparisons, 7 libraries, mostly FreeRDP: 650); OSV's version ranges are themselves maintainer or NVD data.
- **Implication:** the verdicts are as good as the advisories' own ranges; where those can't be read, findings are *possible*. OSV's commit lookup is used only to raise a verdict to affected, never to clear one.
- **Sources:** `research/2026-11-upstream-watch/agreement.py`, `agreement.json`; OSV API.

### F-140
- **Date:** 2026-11-11 · **Status:** confirmed (observed)
- **Question:** Release 0.1.0a7 (Phase 6): did the pre-release audit pass, did every artifact ship as tested, and what went wrong?
- **Method:** `scripts/audit.py`, then the release order in the project's release checklist; `scripts/check_integrations.py` (repaired, below); published releases run against the live and a locally rebuilt feed.
- **Result:**
  - **Audit:** passed at 09:49 UTC on the site built at 09:39 UTC (tracker-data e42dc11): 520 verdicts sampled live, 0 wrong; reviewed sync complete (193 reviews in 7 days, 154 from repository advisories, 0 missing); 19 metrics reproduced; 24,639 feed records valid OSV and matching the state; 12,215 converted ranges consistent with the parser; checker index 4,753 = feed; **new: 925 GIT-range entries in 150 repos rebuilt from live tags, 0 differ** (1,489 repos have GIT ranges).
  - **Image:** `ghcr.io/limbowatch/limbowatch:0.1.0a7@sha256:4e3f9a6b…` (built from 6f138ce; reports `limbowatch 0.1.0a7`, OSV-Scanner 2.7.0 and git 2.47.3; SLSA provenance verified), pinned in the action and the GitLab template (495cfec). In the image, the FreeRDP/ImageMagick test project of F-138 gives the same 354 findings as the CLI.
  - **Tags:** `v0.1.0a7` GPG-signed and verified; the release workflow published PyPI 0.1.0a7 and a GitHub pre-release, and the image workflow retagged the pinned digest.
  - **GitLab component:** split f7bd4a9 on gitlab.com `main` (pipeline 3053714371 passed; the mirror's digest equals ghcr.io's; `limbowatch-ultimate-gate` fails by design, allowed); signed tag `0.1.0-alpha.7` (pipeline 3053725626 passed; CI/CD Catalog release 10:05 UTC).
  - **Action repo:** split 7f90272; self-test passed on Linux (image) and macOS (pip); signed tag `v0.1.0a7` and a GitHub pre-release.
  - **Org profile:** updated (d853298).
  - **Integrations harness:** `scripts/check_integrations.py` had been broken since the component moved to the image (0.1.0a2): it looked for a job named `limbowatch`, and nothing installed Limbowatch for the job script. It now runs the job script after the Action's own installer, and applies `GITHUB_PATH`/`GITHUB_ENV` between Action steps as the runner does: 13 checks passed on 6f138ce's tree.
  - **Incident: older watchers failed on the feed from 09:21 to 10:14 UTC.** The feed's new entries for advisories without a package (F-138) had no `package`; every release before 0.1.0a7 reads `affected[].package` of every entry, so `scan` and `watch` failed with `KeyError: 'package'` (exit 2) for anyone on 0.1.0a1-0.1.0a6, including pinned Actions and components. Found by the post-release smoke test of 0.1.0a6. Fixed by giving those entries a `GIT` package named by the repo URL (5c2e271, deployed 10:14 UTC): 0.1.0a1, 0.1.0a5, 0.1.0a6 and 0.1.0a7 all read the rebuilt feed, 0.1.0a7's results on the test project are unchanged, and 0.1.0a6 scans the demo app again: 61 findings and 3 unchecked, the same finding keys as 0.1.0a7's. A test and an audit check now require a `package` on every entry.
  - **A behaviour change that comes with the feed:** 153 records have entries in a registry ecosystem with no package name (Composer 37, Go 27, GitHub Actions 23, Maven 20, Rust 19, RubyGems 16, PyPI 8, npm 7, Swift 3). The feed used to drop them; a dependency from the same repo now matches them by repository as *possible*, which repos polled directly already did.
- **Implication:** a feed format change is a change to every released watcher; rebuild the feed locally and read it with the oldest and newest releases before deploying.
- **Sources:** GitHub Actions runs 42998750693 (image, 6f138ce), 43000387793 (release), 43000387800 (image, tag), limbowatch-action 43000427461; GitLab pipelines above; PyPI; the audit report (session scratchpad).

### F-141
- **Date:** 2026-11-11 · **Status:** confirmed (each finding reproduced, then covered by a test)
- **Question:** Does an independent review of the Phase 6 code find wrong verdicts, dropped dependencies, crashes or security problems that the tests and the agreement study (F-139) missed?
- **Method:** a fresh reviewer read `git diff 8fcf60d..HEAD -- packages scripts/audit.py` with the hard rules and reproduced what it reported; each finding was reproduced again here, fixed, and given a regression test (`tests/test_upstream.py`, `tests/test_upstream_check.py`). Then the agreement study (F-139), the end-to-end case (F-138) and the detector measurement (F-137) were re-run on the fixed code.
- **Result:** eight findings and seven smaller ones, all reproduced; all fixed in 0.1.0a8 but one cosmetic (a vcpkg dependency's line can point at an earlier mention of the same port name):
  - **Silent passes (four):**
    - a fix release of an older line in a pin's history cleared a newer, still affected line: `< 1.2.5 || >= 2.0.0, < 2.0.3` at 2.0.1 (it contains 1.2.5) was "not affected". Now only the fixes of the pin's own line, or all the advisory names, clear it, and never past an open range (`< 1.2.5 || >= 2.0.0` stays *possible*);
    - tag versions came from the last digit run: `v1.2.3-r2` → 2, `v2.5.0-win64` → 64, `pcre2-10.44` → `2-10.44`, `v1.2.3+20240101` → 20240101. Now the first dotted version, with a trailing letter, pre-release or revision, and a tag's version must lead back to the same commit before it stands for a release;
    - a trailing letter was a pre-release: `1.1.1a` sorted before `1.1.1`, so `< 1.0.2b` cleared 1.0.2. A single letter is a pre-release only with a number after it (`1.0b1`);
    - an advisory naming a registry package and the C code (`pip:protobuf` and `other:protobuf C++`) was skipped for upstream sources altogether. Its unpackaged entries are now evaluated.
  - **A false certainty:** a commit after the last affected release but before the fix release was "certainly affected", though the fix commit may be in it (common for submodules on a branch head). It's certain now only when a release in the affected range contains the commit (`git tag --contains`), else *possible*.
  - **Dropped:** two unresolved upstream sources with the same name in different files (`ExternalProject_Add(zlib …)` in `a/` and `b/`) were reported once. Deduplication now keys on the whole declaration.
  - **Crashes:** a `vcpkg.json` or `conan.lock` that's valid JSON of the wrong shape (`[]`, `{"dependencies": [1]}`) raised and ended the scan (exit 2; in org mode the project's whole inventory). Each file is now read under its own guard and reported as unreadable; `{"dependencies": "zlib"}` no longer lists ports `z`, `l`, `i`, `b`.
  - **Security:** git ran with `-c safe.directory=*` (needed for checkouts owned by another user, as in CI containers), so a scanned tree's `core.fsmonitor` command ran (shown with `touch`). Every git call on a scanned tree now passes `-c core.fsmonitor=false`; the test fails without it.
  - **Feed:** an exact-only range (`3.26.0`, fixed in 3.26.1) became a single-commit GIT range, understating what maintainers mostly mean; such ranges are now left as text.
  - **Smaller:** `*.MODULE.bazel` files that MODULE.bazel includes (Bazel 7.2+) were not read; a relative submodule URL under an scp-style remote (`git@github.com:o/super.git`) resolved to the wrong repo; `www.github.com` counted as off GitHub; a renamed repo's old name found no advisories (polling now records GitHub's redirect as an alias); a vcpkg graph cut at 500 ports didn't say so, and vcpkg's `version>=` compared versions by their digits; exact-version checks compared version strings, not versions. (The false certainty above was the seventh.)
  - **The feed after the exact-only change:** 12,577 of 18,687 entries without a package carry GIT ranges (67%, was 13,690, 73%, in F-138), rebuilt from the same state; 0 invalid, every entry with a `package`; 0.1.0a1, 0.1.0a6 and 0.1.0a7 read it.
  - **Re-measured after the fixes:** the agreement study is unchanged (1,029 of 1,082 agree, 35 possible, 17 disagree, the same comparisons as F-139); the FreeRDP/ImageMagick case is unchanged (228 + 114 certain, 12 possible at the old pins; 3 possible at the newest); the detectors find the same 857 upstream sources (F-137).
- **Caveats:** the review covered the Phase 6 diff, not the earlier watcher; the fsmonitor exposure applies to scans of trees another user controls (org-wide mode clones fresh, so it wasn't exposed).
- **Implication:** 0.1.0a7 could pass pins it shouldn't (the four silent passes above); 0.1.0a8 replaces it. Ask for an independent review of verdict code before a release, not only tests written by the same hand.
- **Sources:** the tests named above; `research/2026-11-upstream-watch/agreement.json`, `detectors.json`.

### F-142
- **Date:** 2026-11-11 · **Status:** confirmed (observed)
- **Question:** Release 0.1.0a8 (the review's fixes, F-141): did the audit pass, and what did it catch?
- **Method:** `scripts/audit.py` before the release, then the release checklist; `scripts/check_integrations.py` on 9caf3cf's tree.
- **Result:**
  - **The audit caught two things before release:**
    - its first run compared a CDN-cached `all.zip` from the build before with the new code (81 "differing" GIT ranges, all exact-only ranges the new code leaves as text); the site's own feed was right. The audit now fetches every limbo.watch file past the cache;
    - its second run found 4 GIT ranges the fixed tag reader no longer reproduced: it missed `aide.0.13.release` (a version right after a dot) and mailcow's `2024-04` (year-month tags), and read libspdm's `3.0.0-rc` as 3.0.0, so 3.0 had two tags; Netflix dispatch's `v20230817c` is now, rightly, not 20230817. All three fixed. The tracker had kept tags it resolved once, so a better reading never replaced an old one: it now lists every repo's tags each run (1,752 repos, 0 failures; 7,271 of 8,729 versions tagged).
  - **Audit, third run:** passed at 12:07 UTC on the site built at 12:05 UTC (tracker-data d5553ed): 520 verdicts sampled live, 0 wrong; reviewed sync complete (193 reviews in 7 days, 154 from repository advisories, 0 missing); 19 metrics reproduced; 24,816 feed records valid OSV and matching the state; 12,246 converted ranges consistent with the parser; checker index 4,762 = feed; 1,275 GIT-range entries in 150 repos rebuilt from live tags, 0 differ.
  - **Integrations:** 13 checks passed (GitLab job script and Action, installed from the tree).
  - **Image:** `ghcr.io/limbowatch/limbowatch:0.1.0a8@sha256:b90a82d9…` (built from 60a6c0c; reports `limbowatch 0.1.0a8`, OSV-Scanner 2.7.0 and git 2.47.3; SLSA provenance verified), pinned in the action and the GitLab template (3619b15). In the image, the test project at FreeRDP 3.33.1 and ImageMagick 7.1.2-35 gives the 3 *possible* findings of F-138, and a `vcpkg.json` of `[]` is reported as unreadable, with the scan completing.
  - **Tags:** `v0.1.0a8` and the component's `0.1.0-alpha.8` GPG-signed and verified.
  - **GitLab component:** split c95d6c2 on gitlab.com `main` (pipeline 3054214721 passed; mirror digest equals ghcr.io's; the gate job fails by design, allowed).
  - **Release:** the release workflow published PyPI 0.1.0a8 and a GitHub pre-release, and the image workflow retagged the pinned digest; component tag pipeline 3054221547 passed, CI/CD Catalog release 12:20 UTC.
  - **Action repo:** split f6907ae; self-test passed on Linux (image) and macOS (pip); signed tag `v0.1.0a8` and a GitHub pre-release. Org profile updated (06a6635).
  - **0.1.0a7 marked superseded:** its GitHub pre-releases (main repo and action) now open with a note to upgrade, naming the four silent passes.
  - **Smoke test (PyPI 0.1.0a8):** the demo app gives 61 findings and 3 unchecked, the same keys as 0.1.0a6; the FreeRDP/ImageMagick test project at the old pins 228 + 114 certain and 12 possible, as F-141 measured.
- **Implication:** the audit's GIT-range check earns its place: it caught a tag-reading regression the unit tests didn't. A check against a live site must read past its CDN.
- **Sources:** the audit reports (session scratchpad); GitHub Actions and GitLab runs above.

### F-143
- **Date:** 2026-11-11 · **Status:** confirmed (each finding reproduced, then covered by a test)
- **Question:** A second independent review, of how upstream sources plug into scan, org-wide mode, outputs, issues, the tracker and the audit; and how far do the tests reach?
- **Method:** a fresh reviewer read those paths and reproduced what it reported; each finding was reproduced again here and fixed with a regression test. Coverage measured with pytest-cov (`uv run pytest --cov`). New end-to-end tests (`tests/test_e2e_upstream.py`, offline: the real CLI on local git repos and a recorded feed) and a live script (`scripts/e2e_upstream.py`: FreeRDP, ImageMagick and a vcpkg port, at old and current releases). The audit was rerun with three new checks.
- **Result:**
  - **Findings, all fixed in 0.1.0a9:**
    - **a silent pass:** an upstream repo that polling skipped (GitHub rate limit) wasn't matched against the feed either, and the table counted it as "checked by name only"; the scan passed. It's now matched against the feed and reported as partly checked;
    - **a crash on any project:** a path in the git index that isn't UTF-8 (`caf\xe9.txt`) made every scan exit 2, C/C++ or not. git output is decoded with `surrogateescape`, upstream detection can't end a scan (`detect_safely`), and the commit graph's git calls can't raise on a timeout;
    - **issues closed wrongly:** an upstream finding's issue was closed as "no longer affected" whenever the finding was missing, including when the source wasn't checked (`--no-upstream`, rate limit, a failed clone). It's closed only when the source was checked in full or removed from the project, and labelled "visible" when the advisory reached OSV;
    - **duplicates:** a vcpkg port pulled in by two direct ports was listed, and its findings counted, twice; and a manifest's `overrides` weren't applied to ports pulled in. Both fixed;
    - **the tracker's tag step lost everything at the deadline:** a worker raised mid-gather, so nothing listed was stored; it now stops, stores what it listed, and the run goes on next time;
    - **smaller:** `.venv`, `site-packages` and other caches were walked (a pip package's `.cmake` file became an upstream); line numbers cost quadratic time (a 2 MB `.cmake` file with 70,000 `set()` calls took 19 s, now well under 5 s in the test); the commit graph asked `git tag --contains` once per advisory, now once per commit; the flag was misnamed in a message (`--no-upstream-check` for `--no-upstream`), and with `--no-upstream` registry sources were "repository unknown"; a "graph cut at 500 ports" note appeared when nothing was cut; vcpkg compared a version override with the baseline's as strings;
    - **found by the new tests:** with an untagged fix on one line, "every fix is in its history" counted only the tagged fixes, so `< 1.2.5 || >= 2.0.0, < 2.0.4` (2.0.4 untagged) at 2.0.3 was cleared. It counts every fix named now.
  - **Measurements unchanged after the fixes:** the agreement study (F-139: 1,029 of 1,082 agree, 35 possible, 17 disagree), the detector counts (F-137) and the FreeRDP/ImageMagick case (228 + 114 certain, 12 possible at the old pins). The live script finds 239 certain for FreeRDP (228 from the submodule at 3.10.0, 11 from the vcpkg port at 3.32.2), 114 for ImageMagick, and none for certain at the current releases.
  - **Coverage:** 87% before, 92.4% after (93% with OSV-Scanner installed); CI now fails below 90%. The CLI went from 30% to 79%, `upstream_check` from 83% to 99%, the HTTP client from 78% to 96%, the registries from 84% to 96%.
  - **Audit, three new checks** (all passed at 19:35 UTC on the site built at 14:52 UTC): GIT entries without a range whose versions are all tagged now (at most 2% allowed, for tags made since the last run): 0 of 1,726; every entry has a package, and GIT ones name their record's repo and keep the versions as entered: 19,268, 0 don't; the oldest release (0.1.0a1) and the newest on PyPI read the live feed: both read 25,104 of 25,104 records. The audit's own `git ls-remote` can't abort it on a timeout.
  - **0.1.0a7 yanked on PyPI** (`limbowatch` and `limbowatch-cli`), with the reason pip shows: it "can report affected C/C++ upstream sources as not affected; use 0.1.0a8 or later".
- **Caveats:** the reviewer covered the Phase 6 integration paths; the older watcher code (Phase 4-5) was reviewed only where it touches upstream sources.
- **Implication:** two independent reviews found eight ways to pass an affected dependency between them, after the tests and the agreement study had passed; reviews and the e2e script stay part of releasing verdict code.
- **Sources:** `tests/test_e2e_upstream.py`, `tests/test_sources_http.py`, `tests/test_upstream*.py`; `scripts/e2e_upstream.py`; `scripts/audit.py`; PyPI's JSON API (`yanked: true`).

### F-144
- **Date:** 2026-11-11 · **Status:** confirmed (observed)
- **Question:** Release 0.1.0a9 (the second review's fixes, F-143): did every artifact ship as tested?
- **Method:** the release checklist; the audit of F-143 (19:35 UTC) covers the same feed code; CI on 7e82f91 with the new coverage gate on Python 3.12-3.14 and macOS.
- **Result:**
  - **CI:** every job passed, coverage 92.4% against the 90% gate.
  - **Image:** `ghcr.io/limbowatch/limbowatch:0.1.0a9@sha256:5ffea84f…` (built from de52ebe; reports `limbowatch 0.1.0a9`, OSV-Scanner 2.7.0, git 2.47.3; SLSA provenance verified), pinned in the action and the GitLab template (4cf7a17). In the image: the FreeRDP/ImageMagick test project at the old pins gives 228 + 114 certain and 12 possible; a repo with a non-UTF-8 file name in its index (which ended 0.1.0a8's scan) scans and passes.
  - **Tags:** `v0.1.0a9`, `0.1.0-alpha.9` and the action's `v0.1.0a9` GPG-signed and verified; release workflow 43101634080 (PyPI, GitHub pre-release), image retag 43101634087.
  - **GitLab component:** split 436abb8, pipelines passed (tag pipeline 3056447322), CI/CD Catalog release 21:18 UTC; mirror digest equals ghcr.io's.
  - **Action repo:** split 6318042, self-test 43101644252 passed on Linux and macOS, pre-release published. Org profile updated (d8adff8).
  - **Smoke test (PyPI 0.1.0a9):** demo app 61 findings, 3 unchecked; the test project 228 + 114 certain, 12 possible.
  - **Superseded releases:** 0.1.0a7 and 0.1.0a8 yanked on PyPI (`limbowatch` and `limbowatch-cli`), each with the reason pip shows; their GitHub pre-releases open with an upgrade note.
- **Sources:** the runs above; PyPI's JSON API (`yanked`).

### F-145
- **Date:** 2026-11-11 · **Status:** confirmed (official docs), with gaps listed below for Phase 7 step 0
- **Question:** What does GitHub's REST API offer for the watcher's issue lifecycle (find again, open, comment, label, close, reopen), and what permissions does it take?
- **Method:** GitHub REST docs: Issues, Labels, "Permissions required for fine-grained personal access tokens", the `GITHUB_TOKEN` and workflow-syntax pages, the Actions variables reference.
- **Result:**
  - **Listing:** `GET /repos/{owner}/{repo}/issues` takes `labels`, `state=all` and `per_page` up to 100. It returns pull requests too ("every pull request an issue"); they carry a `pull_request` key.
  - **Creating:** `POST /repos/{owner}/{repo}/issues`. Labels are set only for users with push access and are "silently dropped otherwise". Issues disabled in the repo give 410 Gone. There are no confidential issues.
  - **Updating:** `PATCH .../issues/{n}` with `state` open/closed and `state_reason` (completed, not_planned, duplicate, reopened).
  - **Fine-grained token permissions:** listing issues needs Issues read; create, update, comment, add labels and create labels need Issues write; reading a repo needs Metadata read.
  - **In Actions:** `permissions: issues: write` lets `GITHUB_TOKEN` write issues. The token is "limited to the repository that contains your workflow", expires with the job, and events it triggers don't start new workflow runs. `GITHUB_API_URL` and `GITHUB_SERVER_URL` give the API and server URLs.
- **Caveats:** the docs don't say whether a label that doesn't exist is created on issue creation, or whether `GITHUB_TOKEN` with `issues: write` counts as "push access" for labels. The watcher finds issues again by label, so a dropped label would mean a duplicate issue every run. GitHub Enterprise Server's API path isn't on these pages.
- **Implication:** the GitHub tracker creates its labels explicitly (as the Gitea one does), checks that a new issue carries the `limbowatch` label and stops if it doesn't, skips pull requests when listing, and reports a 410 as "issues are disabled". With no confidential issues, GitHub follows the Gitea rule: no new issues in a public repo without `--issues-public`. In Actions, the job's own `GITHUB_TOKEN` is enough for issues in its repo; org-wide mode needs a PAT or an app token.
- **Sources:** [Issues](https://docs.github.com/en/rest/issues/issues), [fine-grained token permissions](https://docs.github.com/en/rest/authentication/permissions-required-for-fine-grained-personal-access-tokens), [GITHUB_TOKEN](https://docs.github.com/en/actions/concepts/security/github_token), [workflow syntax: permissions](https://docs.github.com/en/actions/reference/workflows-and-actions/workflow-syntax), [variables](https://docs.github.com/en/actions/reference/workflows-and-actions/variables)

### F-146
- **Date:** 2026-11-11 · **Status:** confirmed (official docs)
- **Question:** Which GitHub limits apply to writing issues and to listing an org's repos?
- **Method:** GitHub REST docs: "Rate limits for the REST API", Repositories (list org, user and authenticated-user repos).
- **Result:**
  - **Primary limits:** `GITHUB_TOKEN` gets 1,000 requests an hour per repository (15,000 on Enterprise Cloud); a PAT gets 5,000 an hour.
  - **Secondary limits:** at most 100 concurrent requests and 900 points a minute (GET 1 point, most writes 5). Content-creating requests are limited to about 80 a minute and 500 an hour. A 403 or 429 with a secondary-limit message signals one. Clients honour `retry-after`, or `x-ratelimit-reset` when the remaining count is 0, or else wait at least a minute and back off. Ignoring this "may result in the banning of your integration".
  - **Listing repos:** `GET /orgs/{org}/repos` (`type=all`) and `GET /user/repos` (`affiliation=owner`) include private repos the token can read. `GET /users/{name}/repos` lists only public ones. `per_page` goes up to 100. Each repo carries `full_name`, `private`, `visibility`, `archived`, `disabled`, `fork`, `size`, `has_issues`, `clone_url` and `html_url`. All three endpoints need Metadata read.
- **Caveats:** `visibility` has no documented enum on these pages (Enterprise has `internal`).
- **Implication:**
  - A first run on a project with many findings can exceed 80 new issues a minute or 500 an hour, so GitHub writes are spaced out and a secondary limit stops the run's writes with the rest reported, never dropped.
  - `HttpClient.request` (the code-host path) retries 429 and 5xx but not GitHub's 403 secondary limit; it needs the same handling as the advisory path.
  - Only `visibility == "public"` counts as public: internal repos are treated like private ones, as on Gitea.
- **Sources:** [rate limits](https://docs.github.com/en/rest/using-the-rest-api/rate-limits-for-the-rest-api), [repositories](https://docs.github.com/en/rest/repos/repos)

### F-147
- **Date:** 2026-11-12 · **Status:** confirmed (observed; small sample, one private repo)
- **Question:** Phase 7 step 0 (Q29): how do GitHub issues, labels, listing and cloning behave in practice, with a PAT and with `GITHUB_TOKEN`?
- **Method:** a new private repo `limbowatch/limbowatch-e2e` (a `go.mod` fixture). PAT probes through `gh api` (the maintainer's login, `repo` scope). A `workflow_dispatch` probe with `permissions: issues: write, contents: read`, run 43135780310. Clones with the token in an `http.<base>/.extraHeader` Basic header, `GIT_CONFIG_NOSYSTEM=1` and `GIT_CONFIG_GLOBAL=/dev/null`. 10 probe issues and 1 PR, all closed afterwards, probe labels and branch deleted, probe workflow removed.
- **Result:**
  - **Labels (Q29):**
    - A label that doesn't exist is created by issue creation, both with the PAT and with `GITHUB_TOKEN` (grey `ededed`).
    - Labels set with `GITHUB_TOKEN` stick: the issue came back with both labels, by `github-actions[bot]`.
    - `POST /labels` with `GITHUB_TOKEN` gives 201.
    - Comment, close with `state_reason: completed`, and reopen with `reopened` all work with `GITHUB_TOKEN`.
  - **Listing lags:**
    - A new issue appears in `GET /issues` 3.3 to 6.5 seconds after creation (5 issues), filtered by label or not.
    - A label added to a PR showed up in the label filter after a few seconds.
    - `GET /issues/{n}` returns a new issue at once.
    - Pull requests are in the label-filtered list (`pull_request` key).
  - **Issues disabled:** creating gives 410 "Issues has been disabled in this repository", but listing gives 200. The repo's `has_issues` says it up front.
  - **`GITHUB_TOKEN` scope:**
    - Reading another private repo of the same org gives 404.
    - `GET /orgs/limbowatch/repos?type=all` gives 5 repos, against 18 with the PAT. That is the public ones plus the workflow's own, with no error.
    - The repo's `permissions` object reads all false for this token, so it can't tell write access.
    - `x-ratelimit-limit` was 5000, not the documented 1,000 (F-146).
  - **Clone:** a PAT or `GITHUB_TOKEN` as the Basic password works with any user name (`limbowatch` and `x-access-token` both). Without a token, a private repo fails ("could not read Username"), but only with the system git config off: on the maintainer's Mac the system credential helper answered instead.
  - **Empty repo:**
    - A shallow clone of an empty repo exits 0 ("You appear to have cloned an empty repository"), and `rev-parse HEAD` fails.
    - `size` was 0 while empty, and still 0 minutes after two small commits, so `size` can't tell an empty repo.
- **Caveats:** one repo and one org; the lag is a handful of samples. Secondary limits weren't probed (that would risk the account; F-146 has the docs). Enterprise Server stays untested (Q30).
- **Implication:**
  - **Tracker:**
    - The GitHub tracker can rely on its labels, but still checks the `limbowatch` label on each new issue.
    - It reads `has_issues` in `prepare()`, and uses neither `permissions` nor `size`.
  - **Listing lag:** two runs seconds apart could open the same issue twice. The integrations' docs set a `concurrency` group, and the e2e waits between runs.
  - **Org mode with `GITHUB_TOKEN`:** a partial listing comes back without an error, so `watch --github-org` says when it runs with the job's `GITHUB_TOKEN`: it sees only public repos and its own repo, and private ones need `LIMBOWATCH_SOURCE_TOKEN`.
  - **Empty repos:** an empty clone (no HEAD) is reported as an empty repository, not as checked. This holds for every host, because GitHub has no reliable empty flag.
  - **Clone auth:** `hosts.git` can use any user name for GitHub. Its clone environment doesn't turn off the system git config, so a credential helper on the machine can still answer. That is harmless (the user's own credentials), but tests set `GIT_CONFIG_NOSYSTEM`.
- **Sources:** run 43135780310 (limbowatch/limbowatch-e2e, private); probe output in the session scratchpad.

### F-148
- **Date:** 2026-11-12 · **Status:** confirmed (observed)
- **Question:** Phase 7: does the watcher work on GitHub end to end (issues from the CLI and from the action with the job's token, org-wide mode), and what did an independent review of the change find?
- **Method:**
  - `scripts/e2e_github.py` against the private `limbowatch/limbowatch-e2e`, run 3 times: open or reopen, a second run, upgrade, downgrade; then `watch --github-org limbowatch` with every repo but the test repo excluded.
  - The action from a commit, in a `workflow_dispatch` workflow in that repo with `permissions: issues: write` and no secret: runs 43139440923 (4a994a6) and 43141533855 (b668644).
  - `scripts/e2e_gitlab.py`, `scripts/e2e_gitea.py` and `scripts/check_integrations.py` again, because the issue planner and the HTTP client changed for every tracker.
  - An independent review: a fresh agent given the diff and F-145 to F-147, not my conclusions.
- **Result:**
  - **CLI e2e:** every step passed on each run. Issue #12 opened with the `limbowatch`, `security` and `severity:low` labels; a second run changed nothing; upgrading closed it as `completed`; downgrading reopened the same issue.
  - **Org-wide mode:** the PAT listed all 18 org repos, 14 of them private, with no partial-listing note, and checked the test repo's own `go.mod` (GHSA-c9gr-gmg4-2vqv). The dry run planned nothing new, because the issue was open.
  - **The action:** with the job's `GITHUB_TOKEN` it reopened #12 as `github-actions[bot]` ("Found again in go.mod:5") and passed with 1 finding.
  - **GitLab and Gitea:** the e2e scripts pass after one fix to the scripts themselves. They expected a new issue on every run, while a later run correctly reopens the finding's earlier issue (the key is stable), so they had failed on any second run since F-087.
  - **The review** reported 13 findings. One was wrong: the Gitea tracker treats internal repos as private, not public. The other 12 were fixed with tests, the most serious first:
    1. org-wide mode took an empty repo for a checked one, because `git rev-parse HEAD` prints `HEAD` (exit 128) in an empty repo (the earlier test faked the clone);
    2. one-time "changed" comments were dropped without a word when issue writes were skipped (a rate limit in `prepare`, an earlier project's limit in `watch`, a tracker error);
    3. a secondary limit that never lifts ended in a 403 error instead of the clean stop;
    4. a tracker error in `scan` (such as a read-only `GITHUB_TOKEN`) ended the run before any report was written;
    5. a dropped label left an issue open that later runs couldn't find;
    6. a POST was retried after a timeout or 5xx, so an issue could be opened twice;
    7. the action wrote issues on `pull_request_target`, `issue_comment` and `workflow_run`, which run on the default branch but may scan a fork's files;
    8. a dry run without a token sent an empty `Bearer` header and failed;
    9. a repo answer without visibility fields counted as private;
    10. partial listings went unnoted for classic tokens without `repo` scope and for fine-grained tokens;
    11. GHE.com's API host was guessed wrong;
    12. a reopen's comment could be lost.
  - **Checks:** CI and coverage 93.4% (353 tests); the audit of 2026-11-12 02:12 UTC passed all 9 checks.
- **Caveats:**
  - One private repo and one org.
  - Enterprise Server and GHE.com are untested (Q30): GitHub's docs read don't name GHE.com's API host, so in Actions the job's `GITHUB_API_URL` is used, and nothing is guessed.
  - Secondary limits were exercised only with recorded responses.
- **Implication:** GitHub is a full host for the watcher. The reviewer found real bugs a passing test suite hid (a faked clone), so tests now run real git for empty repos. A new tracker or host gets a live e2e and an independent review before release.
- **Sources:** the runs above; `scripts/e2e_github.py`; `tests/test_github.py`.

### F-149
- **Date:** 2026-11-12 · **Status:** confirmed (observed)
- **Question:** Release 0.1.0a10 (Phase 7, GitHub as a host): did every artifact ship as tested?
- **Method:** the release checklist. Audit of 2026-11-12 02:12 UTC (all 9 checks passed, [F-148](#f-148)); before tagging, the GitHub, GitLab and Gitea e2e, the container check and the action from a commit, all on b668644 (the code released).
- **Result:**
  - **Image:** `ghcr.io/limbowatch/limbowatch:0.1.0a10@sha256:2ec8dea9…`, built from 4bcebc8. It reports `limbowatch 0.1.0a10` and OSV-Scanner 2.7.0, and its attestation verifies. It's pinned in the action and the GitLab template (0747c51), and CI passed on both commits.
  - **Tags:** `v0.1.0a10`, `0.1.0-alpha.10` and the action's `v0.1.0a10`, GPG-signed and verified.
  - **Release workflow:** PyPI `limbowatch` and `limbowatch-cli` 0.1.0a10 and the GitHub pre-release; the image retag gives the pinned digest.
  - **GitLab component:** split 36d746f, pipeline 3057341070 and tag pipeline 3057345404 passed; CI/CD Catalog release at 02:40 UTC; the mirror's digest equals ghcr.io's.
  - **Action repo:** split acc8bf3; self-test 43142874460 passed on Linux (image) and macOS (pip). In its new dry-run step, both runners read this public repo's tracker and opened nothing ("GitHub issues in limbowatch/limbowatch-action are public"). Pre-release published; org profile updated.
  - **Smoke test (PyPI 0.1.0a10):** a `go.mod` pinned to brotli v1.2.1 gives GHSA-c9gr-gmg4-2vqv.
  - **Marketplace:** the listing's releases are v0.1.0a9 and v0.1.0a5, the ones published through the release form's Marketplace checkbox. v0.1.0a10 appears there once the maintainer ticks it; there's no API for this.
- **Sources:** the runs above; PyPI's JSON API; the Marketplace page's release data.

### F-150
- **Date:** 2026-11-12 · **Status:** confirmed (docs and direct observation)
- **Question:** Can the watcher tell, before opening a GitHub issue, that GitHub will drop its labels (the case F-148 handles only after the fact, by closing the stray issue)?
- **Method:** the "Create an issue" REST docs; `GET /repos/{owner}/{repo}` with the maintainer's classic token (`repo` scope) on a public repo it doesn't belong to (google/brotli, torvalds/linux) and on two org repos it administers; a live `scan --issues github --issues-dry-run` against google/brotli (read-only: the repo and its `limbowatch`-labelled issues); `scripts/e2e_github.py`, which now repeats that dry run.
- **Result:**
  - The docs: "Only users with push access can set labels for new issues. Labels are silently dropped otherwise." The same holds for assignees and milestones.
  - **The repo's `permissions` object gives the token user's role:** `pull: true, push: false` on google/brotli and torvalds/linux, all true on the org's repos. The job's `GITHUB_TOKEN` reads all false, yet its labels stick ([F-147](#f-147)), so only `pull` without `push` is taken as "labels would be dropped".
  - Built on that: such a repo gets no new issues. A dry run prints a warning and "wouldn't create" lines; a real run makes its comments and closes, then exits 2 naming the token to use. In `watch`, other repos of the org still get theirs (roles differ per repo). Live against google/brotli, the warning showed and nothing was created.
- **Caveats:** classic token only. A fine-grained token or a GitHub App token wasn't probed: if its `permissions` show the user's role but the token lacks a permission, the check after creating (F-148) still catches a dropped label. A triage-only user is refused too: the docs require push to label at creation.
- **Implication:** the case F-148 left ("each run opens one issue, closes it and fails") now opens nothing for user tokens. It remains only for tokens whose `permissions` can't tell.
- **Sources:** [Create an issue](https://docs.github.com/en/rest/issues/issues?apiVersion=2022-11-28#create-an-issue); the probes above.

### F-151
- **Date:** 2026-11-12 · **Status:** confirmed by [F-155](#f-155) (first inferred from one listing)
- **Question:** The maintainer published the action's v0.1.0a10 to GitHub Marketplace. Why does the listing still show v0.1.0a9 as latest?
- **Method:** fetched `github.com/marketplace/actions/limbowatch` without a cache and read the page's embedded release data; compared it with `GET /repos/limbowatch/limbowatch-action/releases`.
- **Result:**
  - The listing holds v0.1.0a9, v0.1.0a5 and v0.1.0a10, **in that order**, with `latestRelease` v0.1.0a9. v0.1.0a10 was published last (02:40 UTC, edited 03:06), so the order isn't by date.
  - **The order is what comparing the tags as text gives** ("v0.1.0a9" > "v0.1.0a5" > "v0.1.0a10"). Semver's rule for pre-release identifiers gives the same, but these tags aren't valid semver anyway. GitHub's own "latest release" API returns 404, because every release is a pre-release.
  - The Marketplace page shows the default branch's README, so its usage examples already say `@v0.1.0a10`.
- **Caveats:** inferred from one ordering; GitHub doesn't document how Marketplace picks its latest release.
- **Implication:** while v0.1.0a9 is listed, Marketplace will call it latest over a10 to a19. Unpublishing v0.1.0a9 and v0.1.0a5 from Marketplace (the release form's checkbox) makes v0.1.0a10 latest, and a11 to a19 then sort above it. Under text order, v0.1.0b1 and v0.1.1 would sort above everything listed, but v0.1.0 would not ("v0.1.0" < "v0.1.0a9").
- **Sources:** the listing's embedded `releaseData`; the releases API.

### F-152
- **Date:** 2026-11-12 · **Status:** confirmed (observed)
- **Question:** Release 0.1.0a11 (the push-access fix, [F-150](#f-150)): did every artifact ship as tested?
- **Method:** the release checklist. Before tagging, on b97bf4b (the code released): the GitHub (14 checks), GitLab and Gitea e2e, the container check, the upstream e2e, and the action from that commit with the job's token. Audits at 04:09 and 04:22 UTC: all 9 checks passed both times, including 0.1.0a1 and 0.1.0a10 reading the live feed.
- **Result:**
  - **Image:** `ghcr.io/limbowatch/limbowatch:0.1.0a11@sha256:4337484a…`, built from 9b61436. It reports `limbowatch 0.1.0a11`, and its attestation verifies. It's pinned in the action and the GitLab template (07df5e4); CI passed.
  - **Tags:** `v0.1.0a11`, `0.1.0-alpha.11` and the action's `v0.1.0a11`, GPG-signed and verified.
  - **Release workflow:** PyPI `limbowatch` and `limbowatch-cli` 0.1.0a11 and the GitHub pre-release; the image tag gives the pinned digest, and so does the GitLab mirror.
  - **GitLab component:** split 904976f; pipeline 3057607349 and the tag pipeline passed; CI/CD Catalog release at 04:33 UTC.
  - **Action repo:** split 1dbfd31; self-test passed; pre-release published; org profile updated.
  - **The published action, live:** `limbowatch/limbowatch-action@v0.1.0a11` in the private e2e repo pulled the pinned image and, with the job's token, reopened the test issue as `github-actions[bot]` (run 43155763903).
  - **Smoke test (PyPI 0.1.0a11):** a `go.mod` pinned to brotli v1.2.1 gives GHSA-c9gr-gmg4-2vqv.
- **Sources:** the runs above; PyPI's JSON API.

### F-153
- **Date:** 2026-11-12 · **Status:** confirmed (direct observation)
- **Question:** Does OSV-Scanner 2.7.1 change what the watcher's inventory reads, compared with 2.7.0 ([F-074](#f-074), [F-078](#f-078))?
- **Method:** built both from source (`go install …@v2.7.0`, `@v2.7.1`); ran Limbowatch's own inventory (`osv_scanner.run`, offline, no Maven resolution, ignored files included) with each binary on the 111 projects cloned for the Phase 1 report (lockfiles only, 266 npm lockfiles among them) and on the test fixtures; compared every dependency (name, version, source, line, purl, note) and every unresolved entry. Release notes: osv-scanner v2.7.1.
- **Result:**
  - **2.7.1 checks npm packages that have no `resolved`** (osv-scanner#3216, the fix for #3177): 3,246 entries in 12 projects come back as registry packages instead of local ones. Limbowatch already checked them, through its own workaround; name, version, file and line are unchanged.
  - **yarn `patch:` entries are no longer listed twice** (osv-scalibr#2498): one entry fewer in storybook. 2.7.0 listed `react-element-to-jsx-string@15.0.1`, the upstream package, which isn't installed; the project installs the fork `@7rulnik/react-element-to-jsx-string`, and both versions list that.
  - **10 unresolved entries change reason, none disappear:** npm entries without a version (optional platform builds that weren't installed, fixtures) go from "local package" to "no resolved version".
  - **A bug, found by the comparison:** a `file:` dependency whose target sits under another directory's `node_modules` (bun's npm-arborist fixture `external-link--root`: `node_modules/o` linked to `../m/node_modules/n/o`) was checked as the npm package of that name. 2.7.1 does this for `o` and `o2`; with 2.7.0, Limbowatch's own `resolved` workaround did it for `b`. Now the parent's spec decides: a link declared `file:`, `link:`, `workspace:` or as a bare path is local, whatever OSV-Scanner says.
  - **My first fix was wrong, and the comparison caught it:** treating every link target as local made caveman's pnpm-installed `@types/node` and `typescript` (links into pnpm's store, `../../node_modules/.pnpm/…`) "local package", unchecked. A link with a version spec, or into a `node_modules` without one, is a registry package.
  - **Totals:** 0.1.0a11's code with 2.7.0 reads 236,255 dependencies and 3,193 unresolved; the new code 236,254 and 3,194 with 2.7.0 (bun's `b` now local), 236,253 and 3,194 with 2.7.1 (the storybook entry). Of the 266 npm lockfiles, 4 link targets are local and under a `node_modules`, all in bun's test fixtures.
- **Caveats:** lockfiles from the default branches cloned in October; Maven resolution (deps.dev) was off in both runs. The fixtures recorded from 2.7.0 stay, so the tests keep covering older binaries.
- **Implication:** the watcher moves to 2.7.1 (`TESTED_VERSION`, the image, the action's `install: python`, the research pipeline). The `resolved` workaround stays for 2.7.0 users.
- **Sources:** [osv-scanner v2.7.1 release notes](https://github.com/google/osv-scanner/releases/tag/v2.7.1); the comparison above (raw output in the session scratchpad).

### F-154
- **Date:** 2026-11-12 · **Status:** confirmed (observed)
- **Question:** Release 0.1.0a12 (OSV-Scanner 2.7.1, the Python 3.14 image, dependency updates, the npm link fix of [F-153](#f-153)): did every artifact ship as tested?
- **Method:** the release checklist. Before tagging: the 111-project comparison ([F-153](#f-153)); the GitHub, GitLab and Gitea e2e, the container check and the upstream e2e with OSV-Scanner 2.7.1 (on 835eb28; c542a74 then changed only the npm link rule, covered by tests and the comparison); CI on Python 3.12 to 3.14 and macOS; audit 2026-11-12 07:31 UTC, all 9 checks passed (0.1.0a1 and 0.1.0a11 read the live feed).
- **Result:**
  - **Image:** `ghcr.io/limbowatch/limbowatch:0.1.0a12@sha256:c89c62a4…`, built from 71f144d. It reports `limbowatch 0.1.0a12`, OSV-Scanner 2.7.1 and Python 3.14.10, and its attestation verifies. It's pinned in the action and the GitLab template (887d8ca); CI passed.
  - **Tags:** `v0.1.0a12`, `0.1.0-alpha.12` and the action's `v0.1.0a12`, GPG-signed and verified.
  - **Release workflow:** PyPI `limbowatch` and `limbowatch-cli` 0.1.0a12 and the GitHub pre-release; the image tag and the GitLab mirror give the pinned digest.
  - **GitLab component:** split d8d0f5e; pipeline 3058138321 and the tag pipeline passed (the Ultimate gate warns, as designed, on the sample's finding in limbo); CI/CD Catalog release at 07:45 UTC.
  - **Action repo:** split 2c0269f; self-test passed; pre-release published; org profile updated.
  - **The published action, live:** `limbowatch/limbowatch-action@v0.1.0a12` in the private e2e repo pulled the pinned image and reopened the test issue as `github-actions[bot]` (run 43177708982).
  - **Smoke test (PyPI 0.1.0a12, OSV-Scanner 2.7.1):** a `go.mod` pinned to brotli v1.2.1 gives GHSA-c9gr-gmg4-2vqv, with no version warning.
- **Sources:** the runs above; PyPI's JSON API.

### F-155
- **Date:** 2026-11-12 · **Status:** confirmed (observed)
- **Question:** Does Marketplace call the highest tag "latest" once only v0.1.0a10 to a12 are listed ([F-151](#f-151))?
- **Method:** the maintainer unticked "Publish this Action to the GitHub Marketplace" on v0.1.0a5 to a9 and ticked it on a10 to a12; the listing's embedded `releaseData` was read before and after, next to `GET /repos/limbowatch/limbowatch-action/releases`.
- **Result:**
  - In between, with a5 to a12 listed, the order was a9, a8, a7, a6, a5, a12, a11, a10, latest a9: text order again.
  - After: a12, a11, a10, latest **v0.1.0a12**. The yanked a7 and a8 are no longer offered.
  - Ticking or unticking the box doesn't change a release's `updated_at` in the API (a5 and a9 kept theirs from 2026-11-10 and 11-11), so the API can't tell which releases are listed; only the listing page can.
- **Caveats:** the sort rule is still undocumented; with a10 to a19 text order and version order agree, so the next proof point is a tag past a19 or 0.1.0 (under text order, "v0.1.0" sorts below "v0.1.0a10").
- **Implication:** [F-151](#f-151) is confirmed. Before 0.1.0a20 or 0.1.0, check the listing after release; unlist older releases if the new one doesn't come out latest.
- **Sources:** the listing's `releaseData`; the releases API.

### F-156
- **Date:** 2026-11-12 · **Status:** confirmed for BOD 26-04 (CISA); SOC 2 and PCI DSS were already confirmed in [F-134](#f-134) (see the correction below); FedRAMP not read
- **Question:** Do compliance regimes set deadlines for fixing high and critical vulnerabilities, and when does the clock start? (For the website's framing: an advisory in limbo delays the alert, so it delays the fix.)
- **Method:** read the CISA directive pages (cisa.gov/directives; BOD 19-02, 22-01, 26-04) and BOD 26-04's Table 1 (an image, read directly). Tried the AICPA Trust Services Criteria PDF, PCI DSS v4.0.1 and FedRAMP's continuous-monitoring guides: each download returned an HTML page (sign-in, license acceptance or a moved document), so none was read.
- **Result:**
  - **BOD 26-04, "Prioritizing Security Updates Based on Risk" (issued 2026-06-10)** revokes and supersedes BOD 19-02 and BOD 22-01. It applies to federal civilian executive branch agencies (contractors only when a contract says so).
  - **Its clock starts at detection:** "whichever comes first" of CISA adding the CVE to the KEV catalog, or the agency identifying the vulnerability on an asset. Publication and a vendor's fix release are not triggers. BOD 19-02 said the same: "from the time of initial detection, not the time when notification is made."
  - **Table 1 deadlines** (calendar days), by exposure, KEV status, automatability and technical impact: 3 days (with forensic triage for total control) for publicly exposed and KEV-listed or automatable; 14 days for most other exposed or KEV cases; 60 days for exposed, not KEV, not automatable, partial control, and for unexposed automatable; "fix on system upgrade" for unexposed, not KEV, not automatable.
  - **The directive tracks vulnerabilities by CVE.** It says nothing about open source dependencies.
  - **Not verified:** that SOC 2's criteria (CC7.1) require detecting and monitoring vulnerabilities without setting a number of days (the deadline comes from each company's own policy, which the auditor tests); that PCI DSS v4 requirement 6.3.3 asks for critical and high patches within one month of release; FedRAMP's 30/90/180-day timeframes. These are common understanding, not read here.
- **Caveats:** BOD 26-04 binds federal agencies only; companies copy such tables into their own policies, but that wasn't measured. That teams upgrade dependencies mainly when an alert forces them is plausible (Phase 1 found affected versions shipped in 13 of 14 projects, [F-055](#f-055)), not measured.
- **Implication:** where the clock starts at detection, an advisory in limbo for weeks ([F-055](#f-055): median 23 days to review; [F-064](#f-064): 7,988 pending on 2026-10-31, median wait so far 57 days) doesn't count against the deadline: a team can meet every deadline and still run a publicly known vulnerability for weeks. That's the website's point, stated from this entry. Before quoting SOC 2, PCI DSS or FedRAMP on the site, read their texts.
- **Correction (same day):** the "Not verified" item above overlooked [F-134](#f-134) (2026-11-10), which read SOC 2's CC7.1 and CC7.2 and PCI SSC FAQ 1597: SOC 2 sets no deadline (the entity's policy does), and PCI DSS 6.3.3 wants critical patches "resolved within one month of release", counted from the **fix's release**, not from detection. Under PCI DSS, limbo eats into the deadline itself: at October's median review wait the scanner speaks up on day 23 with 7 days left. FedRAMP's timeframes remain unread.
- **Sources:** [BOD 26-04](https://www.cisa.gov/news-events/directives/bod-26-04-prioritizing-security-updates-based-risk) and its Table 1 image; [BOD 19-02](https://www.cisa.gov/news-events/directives/bod-19-02-vulnerability-remediation-requirements-internet-accessible-systems); [BOD 22-01](https://www.cisa.gov/news-events/directives/bod-22-01-reducing-significant-risk-known-exploited-vulnerabilities).

### F-157
- **Date:** 2026-11-12 · **Status:** confirmed (live checks; Dependabot tested in [F-158](#f-158))
- **Question:** For the website: which well-known packages have a high or critical advisory, published by their own maintainers and fixed, that scanners still don't report?
- **Method:**
  - **Candidates:** the live `press/limbo.csv` of 2026-11-12 07:32 UTC: pending review (not likely permanent), high or critical, a fixed version entered, an ecosystem GitHub reviews, waiting at least 60 days. 2,195 advisories, 921 packages.
  - **Ranking:** dependent repositories and downloads from ecosyste.ms (a secondary source, used only to rank). Dropped advisories filed by another project (phpunit's came from prestashopcorp/ps_checkout, golang.org/x/crypto's from dragonfly) and one that affects only pre-releases (smallvec 2.0 alphas).
  - **Live checks for each example:** `GET /repos/{repo}/security-advisories/{ghsa}` (published, its ranges and fixes), `GET /advisories/{ghsa}` (404 means not in GitHub's reviewed database), `GET api.osv.dev/v1/vulns/{ghsa}` (and the CVE where one exists); release dates from deps.dev and the RubyGems API.
  - **Limbowatch 0.1.0a12** (OSV-Scanner 2.7.1) on a directory pinning the last affected version of each (`pom.xml`, `package-lock.json`, `requirements.txt`, `go.mod`, `Gemfile.lock`).
- **Result** (days counted to 2026-11-12; "dependent repos" from ecosyste.ms):

  | Package | Ecosystem | Severity | Advisory published (in limbo) | Fix released | Dependent repos |
  |---|---|---|---|---|---|
  | jackson-core | Maven | high | 2026-09-12 (61 days) | 2.18.10, 2026-08-16 (88 days) | 116,784 |
  | netty-handler | Maven | high | 2026-08-07 (97 days) | 4.1.137.Final, 2026-08-06 (98 days) | 7,905 |
  | @sinclair/typebox | npm | high | 2026-08-21 (83 days) | 0.34.52, 2026-07-11 (124 days) | 707,802 |
  | mistune | PyPI | high | 2026-06-21 (144 days) | 3.3.0, 2026-06-21 (144 days) | 64,256 |
  | vm2 | npm | critical | 2026-09-03 (70 days) | 3.12.1, 2026-09-03 (70 days) | 52,172 |
  | nats-server/v2 | Go | high | 2026-06-29 (136 days) | v2.12.7, 2026-04-14 (212 days) | 24,884 |
  | go-openapi/spec | Go | critical | 2026-07-21 (114 days) | v0.22.9, 2026-07-20 (115 days) | 43,720 |
  | go-toml/v2 | Go | high | 2026-07-07 (128 days) | v2.4.3, 2026-07-05 (130 days) | 28,005 |
  | mustache | RubyGems | critical | 2026-08-20 (84 days) | 1.1.3, 2026-08-20 (84 days) | 9,411 |
  | rubyntlm | RubyGems | critical | 2026-09-09 (64 days) | 0.6.6, 2026-09-09 (64 days) | 8,404 |
  | scapy | PyPI | high | 2026-09-08 (65 days) | 2.8.0, 2026-10-02 (41 days) | n/a |

  - Every advisory is published in the maintainers' own repository, absent from GitHub's reviewed database (404) and absent from OSV (404). Advisories: GHSA-649p-m576-vr99, GHSA-p85m-gvr3-788c, GHSA-976x-prgx-qv35, GHSA-jxhr-4j38-fpxg, GHSA-j89j-5m6r-cr2q, GHSA-38x3-76xf-cq45, GHSA-gqhc-vf4h-h7hg, GHSA-frc4-6h9q-39fq, GHSA-5hrj-7fc3-cmx9, GHSA-cx24-f932-rr55, GHSA-c547-xwrv-q9jm.
  - **jackson-core's CVE (CVE-2026-68498) is published and in OSV, with no package:** OSV's record has only GIT ranges, so package-based scanners can't match it, while the same record links fixes already shipped by SUSE and AlmaLinux. nats-server's CVE is published too; typebox's is still reserved.
  - **Limbowatch 0.1.0a12 flags all 11 packages** (85 advisories in limbo, with the upgrade that clears each).
  - **A Limbowatch bug:** the two `pom.xml` findings point at line 1 instead of the dependency's line, so a code-scanning annotation would land on the wrong line.
- **Caveats:** dependent-repo counts are ecosyste.ms's and include indirect use; they rank, they don't prove exposure. The ranges are as the maintainers entered them, unreviewed. Not yet shown on these packages: that Dependabot stays silent. GitHub's documentation says Dependabot alerts come from reviewed advisories, all 11 are absent from the reviewed database, and [F-112](#f-112) found 0 alerts for 1,080 confirmed findings in limbo; a private repository pinning these versions, with a control package per ecosystem, would show it directly (waiting for the maintainer's go-ahead).
- **Implication:** the website can name real, popular packages with high or critical advisories, fixed upstream for weeks to months, that scanners still call clean. Re-check before publishing: these leave limbo when GitHub reviews them.
- **Sources:** the API responses above (GitHub, OSV, deps.dev, RubyGems, ecosyste.ms); raw output in the session scratchpad.

### F-158
- **Date:** 2026-11-12 · **Status:** confirmed (direct observation); netty-handler corrected in [F-159](#f-159)
- **Question:** Does Dependabot alert on the F-157 examples, and does it lead to their fix some other way?
- **Method:** a new private repository, `limbowatch/limbo-examples`, with Dependabot alerts turned on (`PUT /repos/{r}/vulnerability-alerts`) before the first push. It holds only dependency files pinning the last affected version of each F-157 example (`pom.xml`, `package-lock.json`, `requirements.txt`, `go.mod`, `Gemfile.lock`), plus one control per ecosystem with reviewed advisories at that version (jackson-databind 2.9.10, lodash 4.17.20, requests 2.31.0, golang.org/x/net v0.17.0, rack 2.2.0; 97 reviewed advisories between them by `GET /advisories?type=reviewed&affects=`). Read `GET /repos/{r}/dependency-graph/sbom` and all of `GET /repos/{r}/dependabot/alerts`.
- **Result:**
  - **The dependency graph** listed all 16 packages at the pinned versions within a minute of the push (netty-handler as `4.1.136`, without `.Final`).
  - **No alerts for 23 minutes after the first push, controls included.** A second push that changed a manifest (one comment line) produced alerts 2.5 minutes later. The first push alone didn't start Dependabot's scan, although alerts were on before it.
  - **111 alerts in all:** 95 on the controls (jackson-databind 50, rack 34, lodash 4, golang.org/x/net 4, requests 3), so Dependabot was working.
  - **None for any of the 11 advisories in limbo.**
  - **For 3 examples, Dependabot alerts on other, reviewed advisories whose fix is as new or newer:** jackson-core 2.18.9 (2 high, fixed in 2.18.11; the limbo fix is 2.18.10), vm2 3.12.0 (4, fixed in 3.12.1 and 3.12.2; the limbo fix is 3.12.1), mistune 3.2.1 (10, fixed in 3.3.0; the limbo fix GHSA-jxhr-4j38-fpxg is 3.3.0, though other limbo advisories need 3.3.4). A Dependabot user upgrading as told would get those limbo fixes by coincidence.
  - **For the other 8, Dependabot raised nothing:** @sinclair/typebox 0.34.51, netty-handler 4.1.136.Final, nats-server v2.12.6, go-openapi/spec v0.22.4, go-toml/v2 v2.4.2, mustache 1.1.2, rubyntlm 0.6.5, scapy 2.7.0.
- **Caveats:** one repository, alerts only (not security updates); the delayed start may be a one-off, but [F-090](#f-090) saw a similar need for a manifest-changing commit.
- **Implication:** the site's examples must be versions Dependabot says nothing about. The generated examples will skip a version when a reviewed advisory already asks for an upgrade to the limbo fix or past it (`GET /advisories?type=reviewed&affects=<package>@<version>`, compare patched versions with the ecosystem's rules). For F-157's list that keeps typebox, netty-handler, nats-server, go-openapi/spec, go-toml, mustache, rubyntlm and scapy. For scripts that create a test repository: push a manifest change after the first push, and wait for the control alerts before reading the rest.
- **Sources:** the API responses above; raw output in the session scratchpad.

### F-159
- **Date:** 2026-11-12 · **Status:** confirmed (the range miss and the netty records); tentative (Dependabot's `.Final` miss: one observation)
- **Question:** Building a public proof from the F-157/F-158 examples: does each tool behave as the examples claim?
- **Method:** Limbowatch 0.1.0a12, OSV-Scanner 2.7.1, `npm audit`, pip-audit 2.10.1 and bundler-audit 0.9.3 on the example files plus controls; `POST api.osv.dev/v1/query` for each package and version; `GET /advisories?type=reviewed&affects=<pkg>@<version>`; the feed of 2026-11-12 07:32 UTC (`feed/all.zip`) for range shapes; `limbowatch.versions.affected` called directly.
- **Result:**
  - **A Limbowatch miss: ranges with several upper bounds.** nats-server's GHSA-38x3-76xf-cq45 gives `<= 2.12.6, <= 2.11.15`, fixed in 2.14.0, 2.12.7 and 2.11.16. GitHub's syntax reads a comma as AND, so the range means `<= 2.11.15`, and `affected("go", "2.12.6", ...)` is False: the watcher says nothing about 2.12.6, though the maintainers' fix list shows it's affected. The maintainers meant one bound per release line. Read as AND, such a range only works for versions on the lowest line listed (nats' `<= 2.14.2, <= 2.12.11` does flag 2.12.6).
  - **In the feed, 506 package entries have only upper bounds, two or more, comma-separated** (36 critical, 178 high), e.g. FreeRDP `<= 3.4.0, <= 2.11.5`, Umbraco `<=17.7.1, <=18.2.1`, Nix with five. All 506 are published with no usable range (`range_converted: false`), so a scanner reading the feed can't match them, and the watcher reads them as AND.
  - **netty-handler isn't a clean example.** At 4.1.136.Final, GitHub's reviewed database and OSV hold GHSA-c4c3-7fpv-j4q5 (critical) and GHSA-fccg-mwvh-qqg4, both fixed in 4.1.137.Final, the limbo fix's version: a scanner user would upgrade past it anyway. [F-158](#f-158)'s "Dependabot raised nothing" for netty-handler is therefore not evidence about limbo: Dependabot didn't alert on those reviewed advisories either, and its dependency graph recorded the version as `4.1.136`, without `.Final`, which looks like why (one observation).
  - **The 7 clean examples:** @sinclair/typebox 0.34.51, nats-server v2.12.6 (GHSA-qrcv-3558-gj4f, high, fix v2.12.9 released 2026-05-20, used instead of GHSA-38x3 until the miss above is fixed), go-openapi/spec v0.22.4, go-toml/v2 v2.4.2, mustache 1.1.2, rubyntlm 0.6.5, scapy 2.7.0. For each, the reviewed database and OSV's package query return nothing at that version, and Limbowatch reports the advisory.
  - **OSV holds related records that don't name the package:** CVE-2026-58213 (nats) has no affected package and BIT-nats-2026-58213 is Bitnami's container; OSV's package query for the Go module returns nothing.
  - **The tools on the controls:** OSV-Scanner reports lodash 4.17.20 (8 IDs), x/net v0.17.0 (56), jackson-databind 2.9.10 (101), rack 2.2.0 (72), requests 2.31.0 (9); `npm audit` lodash (4); pip-audit requests (9).
- **Caveats:** bundler-audit ran locally only under Ruby 2.6, which failed; CI will run it. The `.Final` reading of Dependabot's miss is an inference from the graph.
- **Implication:**
  - **Fix the watcher:** when a range is two or more upper bounds only, read it as one bound per release line, using the fixed versions to place each line; report a version as affected when it's below the fix for its own line, and "possibly affected" when its line isn't listed. Convert such ranges in the feed per line where every bound has a fix on the same line. A release follows.
  - The examples drop netty-handler. The examples rule (plan §13.21) checks both GitHub's reviewed database and OSV's package query at the version.
- **Sources:** the API responses above; raw output in the session scratchpad.

### F-160
- **Date:** 2026-11-12 · **Status:** confirmed (direct observation)
- **Question:** With ranges of several upper bounds read one per release line ([F-159](#f-159)), what changes in the watcher and the feed, and does anything else move?
- **Method:** `limbowatch.versions` before (HEAD) and after, side by side over every package entry in the feed of 2026-11-12 07:32 UTC: `alternatives()` and `osv_ranges()` for 13,672 entries with a package and 19,268 package-less (upstream) entries; the range parser self-check (`research/.../common.py`); `limbowatch scan` on the F-157 example files.
- **Result:**
  - **The reading:** the lowest bound covers every older version; each higher bound starts at x.y.0 (same major as the bound below) or x.0.0 (new major). `<= 2.12.6, <= 2.11.15` becomes `<= 2.11.15` or `>= 2.12.0, <= 2.12.6`. Bounds on one line, or not plain numbers, keep the AND reading. A bound that holds no release as a line of its own (iTop's `< 3.2.0` after `< 3.1.1`) adds nothing. A version between the listed lines, on a line none of them names (nats 2.13.x), is "possibly affected", not "not affected".
  - **Only that shape moved:** 90 package entries and 341 package-less ones read differently (3 of them the same shape written with "≤", "and below" or "and"); no other reading changed, and no conversion was lost or altered.
  - **The feed converts it only when the fixed versions confirm a fix per line:** 90 more package entries (13,154 → 13,244) and 323 more package-less ones (16,680 → 17,003) get OSV ranges. The rest stay as text and on the data-quality page, with the per-line suggestion.
  - **The watcher on the example files:** nats-server 2.12.6 now gets 11 advisories in limbo, not 9: GHSA-38x3-76xf-cq45 and GHSA-3g5q-cfh2-cq67 were silent passes. The AND reading also missed whole lines above the lowest bound, e.g. nats 2.14.0–2.14.2 for `<= 2.14.2, <= 2.12.11`.
  - **The `pom.xml` line (F-157):** a Maven dependency is now located on its `<artifactId>` line inside the `<dependency>` whose `<groupId>` matches (lines 8 and 9 in the example, not 1).
  - **An independent review** (a fresh agent given the diff, which ran code to confirm each point) found 7 issues, all fixed with tests: the browser checker on limbo.watch/check didn't apply the "possibly affected" rule; a `< x.y.0` bound counted as naming its own line, and a pre-release below a line's start (2.12.0rc1, 4.2.0.CR1, 7.0.0.rc1) came back "not affected", both now "possibly affected"; the feed accepted a fix lying inside a published interval (`<= 2.11.5, <= 3.4.0` fixed in 3.2.0) and detected `<=` by searching the text (missing `=<`), both now rejected from the parsed bounds; the data-quality advice turned `<=` into `<` and could suggest empty intervals, now built from the per-line reading; and the `pom.xml` lookup could land on an `<exclusion>` or another group's artifact. The totals above are unchanged after the fixes; the old and newest releases read a feed rebuilt with the final code (25,104 records each).
- **Caveats:** the start of each higher line is a reading, not something the maintainer wrote. It's narrower than the maintainer's own bound read alone, so it can miss versions in a gap but can't flag anything the bound itself excludes. The 2026-11-12 feed is one snapshot.
- **Implication:** released as 0.1.0a13. The feed change only adds ranges to records that had none, which every released watcher already parses (checked with the oldest and newest releases before deploying, as for every feed change).
- **Sources:** the comparison above; raw output in the session scratchpad.

### F-161
- **Date:** 2026-11-12 · **Status:** confirmed (observed)
- **Question:** Release 0.1.0a13 (the range fix of [F-160](#f-160)): did every artifact ship as tested?
- **Method:** the release checklist. Before tagging: tests and CI on 7a3b573 (the code released) and the version commits; the independent review and its fixes ([F-160](#f-160)); the feed rebuilt with the final code and read by 0.1.0a1 and 0.1.0a12; after the site deployed it, the audit of 2026-11-12 10:54 UTC (all 9 checks; 12,511 converted ranges checked at their boundary versions, 90 more than the day before, 0 disagree); the upstream e2e.
- **Result:**
  - **Image:** `ghcr.io/limbowatch/limbowatch:0.1.0a13@sha256:68739b75…`, built from 7782ecc; `limbowatch 0.1.0a13`, OSV-Scanner 2.7.1; attestation verifies; pinned in the action and the GitLab template (ca704c6).
  - **Tags:** `v0.1.0a13`, `0.1.0-alpha.13` and the action's `v0.1.0a13`, GPG-signed and verified.
  - **PyPI** `limbowatch` and `limbowatch-cli` 0.1.0a13 and the GitHub pre-release; the image tag and the GitLab mirror give the pinned digest.
  - **GitLab component:** split 0ea317c; pipeline 3059010886 passed. The tag pipeline 3059020768 first failed on GitLab's arm64 runner (`runner_system_failure`, an infrastructure fault); the job passed on retry and the CI/CD Catalog release ran at 11:07 UTC.
  - **Action repo:** split 6c4eac7; self-test passed; pre-release published; org profile updated.
  - **Smoke test (PyPI 0.1.0a13, OSV-Scanner 2.7.1):** on the proof repository's files, all 7 advisories are reported, nats-server's GHSA-38x3-76xf-cq45 among them, which 0.1.0a12 missed.
- **Sources:** the runs above; PyPI's JSON API.

### F-162
- **Date:** 2026-11-12 · **Status:** confirmed (direct observation)
- **Question:** Does a public proof repository show the gap in a way anyone can check?
- **Method:** public repository `limbowatch/limbo-poc`: dependency files pinning the 7 clean examples ([F-159](#f-159), with nats-server's GHSA-38x3-76xf-cq45 now that 0.1.0a13 reports it) and 5 controls with reviewed advisories; a workflow (`proof.yml`, on push and daily) running the published action v0.1.0a13, OSV-Scanner 2.7.1, `npm audit`, pip-audit 2.10.1 and bundler-audit 0.9.3, then asking GitHub about each advisory; Dependabot alerts on before the first push, read with a maintainer token. First complete run: 43207387208.
- **Result:**
  - **Limbowatch reports all 7; OSV-Scanner none of them;** `npm audit` and pip-audit say nothing for typebox and scapy; GitHub's reviewed database has none of the 7 (each `github.com/advisories/<GHSA>` page is a 404); each maintainer advisory is published.
  - **Every scanner reports the controls:** OSV-Scanner lodash 8, x/net 56, jackson-databind 101, rack 72, requests 9; `npm audit` lodash 4; pip-audit requests 9; bundler-audit rack 69.
  - **bundler-audit reports rubyntlm 0.6.5** (GHSA-cx24-f932-rr55): the community ruby-advisory-db has it, though GitHub's database and OSV don't. So rubyntlm isn't silent for every Ruby user; the website's examples leave it out.
  - **Dependabot: 95 alerts, all on the controls** (jackson-databind 50, rack 34, lodash 4, x/net 4, requests 3), none for the 7. The workflow's `GITHUB_TOKEN` can't read Dependabot alerts (HTTP 403, with `security-events: read`), so the repository keeps a dated snapshot. The `git push` output itself reported "95 vulnerabilities" on the default branch.
  - A workflow-level `env` can't use `${{ runner.temp }}`: the first run failed with no jobs; the value is set in a step.
- **Caveats:** a snapshot of one day; as GitHub reviews these advisories, the daily run shows them leaving limbo.
- **Implication:** the website links to the repository and its latest run as public proof. The examples rule also checks ruby-advisory-db for RubyGems (or leaves Ruby examples out).
- **Sources:** https://github.com/limbowatch/limbo-poc and its workflow runs.

### F-163
- **Date:** 2026-11-12 · **Status:** confirmed (direct observation and computation)
- **Question:** What does the demo show on 0.1.0a13, and do the site's colours meet WCAG AA?
- **Method:**
  - Demo: `limbowatch/demo-app` bumped to the action v0.1.0a13 (GitHub) and component 0.1.0-alpha.13 (GitLab), `main` merged into `add-scapy`; pull request run 43258602783 (`report.json` from its artifact), GitLab merge request pipeline 3060569992 (the merge request page). Terminal output from `uvx --from limbowatch-cli==0.1.0a13` with OSV-Scanner 2.7.1 on the `add-scapy` checkout.
  - Contrast: WCAG 2.x relative luminance for every text token against `bg`, `surface` and `sunk`, in both themes (`tests/test_site.py`).
  - Layout: Chrome device emulation at 390 and 1440 CSS px, light and dark, on home, tracker, scan, compliance, an advisory page and methodology; `document.documentElement.scrollWidth` against the viewport.
- **Result:**
  - **Demo: 63 advisories in limbo in 5 packages, 8 at or above high** (was 67 in 7 packages, 9 at or above high, on 2026-11-10, [F-128](#f-128)). The advisories for rack 2.2.24 and nokogiri 1.19.4 left limbo in between: OSV's package query returns all six (GHSA-5v64-555j-wjxm, GHSA-p8x9-v4hv-2w4g, GHSA-wvg4-6p58-3gh3; GHSA-3w22-6jfg-527w, GHSA-4p39-36wj-23h4, GHSA-v995-44v6-5fqm), each published there 2026-11-10, and the `git push` reported "6 vulnerabilities" from Dependabot on the default branch. scapy 2.7.0 has 52 (was 51). GitLab: "Code Quality scans found 52 new findings", "Test summary: 8 failed, 63 total tests". The pull request diff now also shows the `github`-format annotation on the dnspython line.
  - **Contrast: three text colours were below 4.5:1:** light `muted` and `faint` #6B6F78 on `sunk` 4.30; dark `faint` #7C818C on `surface` 4.46 and on `sunk` 4.18; light `mark` #B87400 as the brand name's text 3.51. Changed to #646871 (4.77 on `sunk`), #848994 (4.66 on `sunk`), and `amber-text` for the brand (5.35).
  - **No horizontal scroll** on any of the six pages at 390 px; the only clipped element was the PCI clock's "7 left" label on phones, now "7".
- **Caveats:** the demo's numbers move as GitHub reviews its advisories; the screenshots are a dated snapshot (docs/SCREENSHOTS.md).
- **Implication:** the scan page's screenshots, alt text and captions use these numbers; the design tokens are tested so contrast can't regress.
- **Sources:** https://github.com/limbowatch/demo-app/actions/runs/43258602783, https://gitlab.com/limbowatch/demo-app/-/merge_requests/1 (private), docs/redesign/DESIGN.md.

### F-164
- **Date:** 2026-11-12 · **Status:** confirmed (direct observation)
- **Question:** How free-form are the maintainer-entered advisory fields Limbowatch puts into issues, reports and the site, and does each output survive them?
- **Method:**
  - Every package entry of the tracker state's `advisories.jsonl` on 2026-11-12: 42,955 repository advisories, 234,455 string fields (`vulnerable_version_range`, `patched_versions`, `name`, `ecosystem`), searched for backticks, line breaks, control and ANSI escape characters, `<` followed by a letter, `[`, `|`, `@` before a word, `::`, URLs and length.
  - The issue body (`limbowatch.watch.issues.body`) for two ranges, rendered by GitHub's Markdown API (`POST /markdown`, `mode: gfm`): a real shape, `>=4.1.0, <=4.1.13 || >=5.0.0, <5.1.1`, and a hostile one with a backtick, a link and an `@` mention.
  - The built site (25,740 HTML pages) searched for an unescaped `<` before a digit, `v` or `=`.
- **Result:**
  - **Free text is common:** 164 ranges contain `|` (`||`), 35 contain backticks (e.g. `` `<= 6.8.4 ``), 41 use `[`, 341 start like a tag (`<v0.18.6`), 16 are URLs, 2 contain `@`, 2 contain `::`; 70 fixed-version fields contain `|`, 35 are URLs; 12 package names contain backticks and 178 are URLs. **None** contains a line break, a control character or an ANSI escape.
  - **Issue bodies break on them.** GitHub splits a table cell at `|` even inside a code span, so the first range's "Affected versions" cell shows only `>=4.1.0, <=4.1.13`: the issue states a narrower range than the advisory. A backtick ends the code span, so the hostile range renders a working link and an `@octocat` mention. A `-->` in a field ends the hidden marker early; later runs still read it, but the rest shows as text.
  - **The site escapes all of them:** no unescaped `<` before a digit, `v` or `=` in 25,740 pages (the one hit is the site's own script). The scan's HTML, JUnit, CSV and workflow-annotation outputs escape them too (`watch/output.py`); SARIF and JSON carry them as JSON strings. The Markdown report (job summary, merge request) escapes `|` and HTML but not backticks or `[text](url)`, so a fixed-version field written as a link renders as one.
- **Caveats:** "none contains a line break" is what this state shows, not a GitHub guarantee.
- **Implication:** issue bodies and the Markdown report must escape `|`, backticks, `[`/`]` and `<`/`>` in advisory fields, and the marker JSON must not contain `-->`.
- **Fix (unreleased, 2026-11-12):** every advisory or lockfile field is a code span (`limbowatch.mdsafe`) in issues, comments, the Markdown report and the daily report; rendered by GitHub's and GitLab's Markdown APIs, both ranges show in full and the hostile one adds no link, mention or image. The marker JSON-escapes `<`, `>`, `&`; the Gitea e2e reads it back.
- **Sources:** tracker-data `state/advisories.jsonl` (2026-11-12), https://docs.github.com/rest/markdown/markdown, https://github.github.com/gfm/#tables-extension-

### F-165
- **Date:** 2026-11-12 · **Status:** confirmed (direct observation)
- **Question:** Does the home page's advisory count fit its column now that it has five digits?
- **Method:** Chrome device emulation at 320, 360, 375, 390, 414, 700, 901, 1000, 1200, 1440 and 1920 CSS px on https://limbo.watch/; the `.huge` text's right edge (a Range over its contents) against its column `.now-n`.
- **Result:** "10,239" at `clamp(88px,15vw,196px)` fitted phones with 12 px to spare at 320 px, but **ran past its column at every width from 901 px**, by 45 to 95 px; at 1440 px it reached x=757 while the text column beside it starts at 726. After the fix (`min(196px, 24cqi)` of a size container) it fits at every width, and so does "100,000" in the site font and in Arial.
- **Caveats:** [F-163](#f-163)'s layout check compared `scrollWidth` with the viewport, which can't see one element overlapping another inside the page; it stands for what it measured.
- **Implication:** layout checks should compare elements with their containers, not only the page with the viewport.
- **Sources:** commit 1d6ae00, docs/redesign/DESIGN.md.

### F-166
- **Date:** 2026-11-13 · **Status:** confirmed (direct observation; small sample, one project)
- **Question:** Which hosts does `limbowatch scan` contact, and does `--no-upstream --no-resolve-maven` contact only limbo.watch?
- **Method:** A logging HTTP CONNECT proxy (`HTTPS_PROXY`/`HTTP_PROXY`, honoured by httpx, OSV-Scanner and git), no GitHub token, an empty cache per run. Project: the test fixtures for npm, Go, Cargo, Python (`requirements.txt`), Maven (3 `pom.xml`), Gradle, plus a `CMakeLists.txt` that fetches madler/zlib v1.3.1. Three runs: default, `--no-upstream`, `--no-upstream --no-resolve-maven`. Then a code read of every URL constant reachable from `scan` (`watch.scan`, `watch.mapping`, `watch.registries`, `watch.upstream`, `watch.upstream_check`, `sources.github`, `sources.cve`, `sources.osv`).
- **Result:**
  - Default: api.deps.dev (14 tunnels), repo1.maven.org (4), repo.maven.apache.org (1, from OSV-Scanner's Maven resolver), limbo.watch (1). 22 findings. No GitHub, CVE or OSV calls in this run: every source repo was on the tracker's watchlist and fresh, and zlib has no advisory in limbo.
  - `--no-upstream`: api.deps.dev (1, Maven resolution), repo.maven.apache.org (1), limbo.watch (1). 22 findings.
  - `--no-upstream --no-resolve-maven`: **limbo.watch only.** 20 findings: the 2 lost come from Maven transitive dependencies, now reported as not fully resolved.
  - Code read: beyond the hosts above, the scan can contact rubygems.org, repo.packagist.org, packages.ecosyste.ms, bcr.bazel.build, raw.githubusercontent.com, center2.conan.io, api.github.com, github.com (history-only clones), **cveawg.mitre.org** (CVE IDs cited by polled advisories; missing from WATCHER.md's "What leaves the machine" until now) and api.osv.dev; all but limbo.watch sit behind `--no-upstream`, except OSV calls for findings that went away (`--state`) and Maven resolution (`--no-resolve-maven`). A GitHub token goes only to api.github.com (`http.py`).
- **Caveats:** a proxy sees only clients that honour proxy settings; the code read covers the rest (Limbowatch's own requests all go through `limbowatch.http`; OSV-Scanner runs with `--offline` apart from the Maven resolver run). One project, one day; upstream polling and clones weren't exercised live here.
- **Implication:** the claim "your code never leaves; feed-only mode contacts only limbo.watch" holds and is now documented (WATCHER.md "Security and data", READMEs, limbo.watch/scan). `test_security_and_data_names_every_host_and_option` keeps the documented hosts and options in step with the code.
- **Sources:** proxy logs in the session scratchpad; packages/core/src/limbowatch/watch/*.py, sources/*.py, http.py.

### F-167
- **Date:** 2026-11-13 · **Status:** confirmed (direct observation)
- **Question:** Are the daily report's numbers right, and does it reach subscribers when it should?
- **Method:** The reports of 2026-11-06 to 11-12 on `tracker-data` (`reports/*.md`) and the comments on issue #1; `state/events.jsonl` and `state/cursors.jsonl` from `tracker-data`; GitHub's reviewed list for each report window (`GET /advisories?type=reviewed&published=<from>..<to>`, paginated); `gh run list --workflow tracker.yml --event schedule` for 2026-10-28 to 11-12; a read of `publish/report.py` and `tracker.py`.
- **Result:**
  - **"0 reviewed by GitHub" is right.** GitHub reviewed no advisory at all, of any kind, between 2026-11-07 13:24 and 11-09 16:52 UTC, nor between 11-11 00:47 and 11-12 23:30 UTC (the tracker's `reviewed_at` cursor stopped at 11-11 00:47 for the same reason). Other windows: 16 (11-06/07), 45 (11-09/10), 100+ (11-10/11). The report doesn't say that GitHub reviewed nothing at all, so "0 left limbo" reads like a tracker fault.
  - **The 180 CVE changes on 11-08 are real:** 176 of the "new CVE from another CNA" events are for CVEs published that day.
  - **The scheduled run fires 6.5 to 10 hours late**, every day: cron `17 6 * * *` (06:17 UTC), created between 12:43 and 16:34 UTC across 16 days. Reports carry the run's date, so the gap doesn't lose data; subscribers just get them in the afternoon (UTC).
  - **Three reports on 11-07** went to subscribers, from two manual runs and the scheduled one; the guard that only scheduled runs report (added that day) has kept it to one a day since.
  - **"+32 other changes" (11-08)** has no matching event: advisories that move into the in-limbo count other than by being first seen (from likely permanent, or back from another state) aren't recorded as events, so the report can't name them.
  - **Code:** the CVE changes table still writes `[GHSA](html_url)` and the event text raw, not through `mdsafe` like the other tables ([F-164](#f-164)); the values are the tracker's own (CVE IDs), so nothing is exploitable today, but it's inconsistent. `sync_reviewed` adds only the last partial batch to `reviewed_synced` (a run-log undercount, not a report number). The workflow truncates the comment at 65,000 bytes without a note (reports are 9 to 12 KB).
- **Caveats:** one week of reports.
- **Implication:** the numbers are right; the report should say how many advisories GitHub reviewed overall, name the "other changes", and link "…and N more" to the tracker. The schedule delay is GitHub's.
- **Fixed (2026-11-13):** the report counts GitHub's reviews in the period (by review date, plus any seen leaving limbo by review, so the two lines agree when GitHub lists a review late), keeps the IDs it counted so the next report names moves between the two counts (the cursor grows from 1.4 KB to about 0.6 MB, about 2 KB a day once packed), links the rest of the newly published table to the tracker, orders and escapes the CVE changes, cuts a too-long comment at a line with a link, and `reviewed_synced` counts every entry. The schedule is unchanged.
- **Sources:** issue #1 comments; tracker-data `reports/`, `state/`; GitHub REST API; workflow run list.

### F-168
- **Date:** 2026-11-13 · **Status:** confirmed (direct observation)
- **Question:** What keeps limbo.watch from being found in search, and what can the site itself fix?
- **Method:** `curl` of https://limbo.watch/sitemap.xml, `robots.txt`, a missing page, `http://limbo.watch/` and `https://www.limbo.watch/`; title, description, `h1` and JSON-LD of the ten main pages and a sample of advisory pages; then a full local build from the 2026-11-12 tracker state (25,730 advisory pages) after the changes.
- **Result:**
  - **Sitemap:** one file of 25,740 URLs (2.6 MB), every `lastmod` the build day (2026-11-13), so it said nothing about what changed. At about 300 new advisories a day it would pass the 50,000-URL limit per sitemap in about 80 days.
  - **Advisory pages** (25,730, nearly all the site's pages): titles were `GHSA-… (name) · limbo.watch` (no package ecosystem, severity or CVE, though people search for those), no structured data, and links to them only from the sitemap, the home page's examples and the script-rendered tracker.
  - **The ecosystem field is free text for "other"**: 13,795 package entries say `other`, and many more name an ecosystem GitHub doesn't know (`bottlerocket`, `c/c++`, `frappe`, a sentence); only an ecosystem OSV knows reads well in a title.
  - **Hosts:** `http://limbo.watch/` answers 200 (Cloudflare, no redirect to https), so every page exists twice; the canonical tags point at https, which limits the damage. `https://www.limbo.watch/` answers **526** (Cloudflare can't validate the origin's certificate, which covers only limbo.watch).
  - Fine already: canonical URLs, Open Graph and Twitter tags, `robots.txt` with the sitemap, a real 404, one `h1` per page, alt text, HSTS, gzip.
  - After the changes: an index plus `sitemap-pages.xml` and three files of at most 10,000 advisories, each advisory dated by its last fact change (10,927 on 2026-10-31, 8,913 on 2026-10-28, …); advisory titles median 81 characters, unique; descriptions median 168.
- **Caveats:** no Search Console data (the user's account); what search engines make of it shows over weeks.
- **Implication:** fixed in the site generator: sitemap index with real dates; advisory titles and descriptions from facts (package, known ecosystem, severity, CVE, GHSA, fix), BreadcrumbList JSON-LD, and links to up to 8 other advisories in limbo from the same repository; WebSite JSON-LD on the home page; clearer titles for the tracker, feed, check and scan pages. Left to the user, in Cloudflare: "Always Use HTTPS", and a redirect (or certificate) for www.
- **Sources:** live responses on 2026-11-13; packages/core/src/limbowatch/publish/site.py.

### F-169
- **Date:** 2026-11-13 · **Status:** confirmed (direct observation)
- **Question:** Release 0.1.0a14 (F-164's escaping, the hash-pinned `install: python`, F-166's docs): do the pre-release checks pass?
- **Method:** the release checklist on e88e232: `scripts/e2e_github.py` (CLI issues and org-wide mode on the private limbowatch/limbowatch-e2e), the action from that commit with `install: python` and `limbowatch-ref` set to it (limbowatch-e2e run 43416252646), `scripts/check_integrations.py`, and `scripts/audit.py` (sample seed 20261113, 520 verdicts) against the site built from `tracker-data` ee0f280 (run 2026-11-12 15:24 UTC).
- **Result:**
  - GitHub e2e passed (open, label, second run unchanged, close on upgrade, reopen; org listing; a token without push access opens nothing). The action reopened #12 with the ranges as code spans, and pip's hash-checked install reported "No broken requirements found". Integrations passed.
  - The audit first **failed verdicts**: 4 "wrong" of 520. All 4 changed after the run: three reviewed by GitHub between 2026-11-12 21:54 and 11-13 00:45 UTC, one newly citing a CVE, and one CVE published (counted as changed). The audit treated any review, OSV record or withdrawal as a change since the run, whatever its date, but a new citation or a CVE state change always as an error. It now asks each source for its date (review time, OSV `published`, the repository advisory's `updated_at` or `withdrawn_at`, the CVE record's `datePublished`/`dateUpdated`) and counts a difference as a change since the run only when dated after the run started; anything dated before is an error. Rerun: **all 10 checks pass**, 0 wrong, 5 changed since the run.
  - `scripts/e2e_gitlab.py` passed (private project, confidential issue, marker, label, second run unchanged, close on upgrade, reopen) with a one-day `api` token the maintainer created and kept in 1Password, passed to the test with `op run` so it never appeared in the session. The token in glab's config file is stale (401).
- **Caveats:** the tracker's state was 20 hours old (today's scheduled run hadn't started, F-167); the stricter date rule hasn't yet met a review listed late by GitHub's API.
- **Implication:** the audit is now stricter about misses and fairer about staleness.
- **Sources:** scratchpad `audit.md`, `audit2.md`; scripts/audit.py.

### F-170
- **Date:** 2026-11-13 · **Status:** confirmed (direct observation)
- **Question:** Release 0.1.0a14: did every artifact ship as tested?
- **Method:** the release checklist after the checks of [F-169](#f-169): version commit 35cb7eb, image built on main (`sha-35cb7eb`), pin commit 2495cbc, signed tag `v0.1.0a14`; the component split aaeea2b pushed to gitlab.com with its signed tag `0.1.0-alpha.14`; the action split 710abec pushed to limbowatch/limbowatch-action, its self-test, its signed tag and pre-release; the org profile; the proof repository's run on the published action (limbowatch/limbo-poc run 43420230782).
- **Result:**
  - PyPI serves 0.1.0a14 for both packages; the GitHub pre-release exists; `ghcr.io/limbowatch/limbowatch:0.1.0a14` resolves to `sha256:b578721a…`, the digest pinned in `action.yml` and the GitLab template.
  - The component's pipelines passed on `main` and on the tag; 0.1.0-alpha.14 is in the GitLab CI/CD Catalog.
  - The action's self-test passed on Linux (image) and macOS (`install: python`, hash-checked); release v0.1.0a14 created. Marketplace still listed a11–a13 before the maintainer ticks a14; its page already showed the new README.
  - The proof run on the published action: Limbowatch reports all 7 examples (typebox, nats-server, go-openapi/spec, go-toml, mustache, rubyntlm, scapy); OSV-Scanner none; bundler-audit sees rubyntlm, as in [F-162](#f-162).
  - The action tag in the separate clone wouldn't sign with `-u 4F6CE172` (a short ID gpg didn't resolve to the signing key); without `-u` it signed with the configured key `…F143D31D`.
- **Caveats:** the screenshots on the scan page weren't refreshed: they need the signed-in browser, which wasn't connected. Only the job summary's table changes (values as code).
- **Implication:** 0.1.0a14 shipped as tested.
- **Sources:** PyPI JSON API; `docker buildx imagetools inspect`; GitLab and GitHub run lists; the runs named above.

### F-171
- **Date:** 2026-11-13 · **Status:** confirmed (direct measurement; official docs); the size measure and the 8-month estimate are superseded by [F-172](#f-172)
- **Question:** Would the public site fit on GitHub Pages behind Cloudflare, and what would that cost?
- **Method:** built the site from the `tracker-data` branch with `limbowatch publish` (as `site.yml` does) and measured it with `du` and `find`; read the GitHub Pages limits and the Cloudflare Workers pricing and limits, Snippets, Transform Rules and plan pages.
- **Result:**
  - The site is **508 MB in 51,813 files**: `advisory/` 311 MB (26,030 pages, about 12 KB each), `feed/` 130 MB, `osv/` 48 MB (50 ecosystems), everything else under 16 MB.
  - Each watcher scan downloads `feed/all.zip` (25.0 MB) and `feed/watchlist.json` (3.1 MB), and reuses its cached copy when the ETag matches (`watch/scan.py`). The home page is 12 KB gzipped plus its CSS (12 KB) and one of two screenshots (198 KB).
  - The tracker holds 43,255 advisories; 5,039 were published in 2026-10, up from 2,083 in 2026-04.
  - GitHub Pages: the published site may be no larger than **1 GB**; soft limits of **100 GB bandwidth a month** and 10 builds an hour (the build limit doesn't apply to custom Actions workflows); deployments time out after 10 minutes. No custom response headers. The docs name no paid tier that raises these limits.
  - Cloudflare Free: $0, CDN included with no stated bandwidth limit; 10 Transform Rules in total, each setting a fixed header value. Snippets are Pro and up only (Pro costs $20/month billed annually or $25 monthly). Workers Free allows 100,000 requests a day (fail-open or fail-closed with error 1027 beyond that); Workers Paid costs at least $5/month with 10 million requests included, then $0.30 per million. Static assets served by Workers are free and unlimited, but capped at 20,000 files per version on Free and 100,000 on Paid, 25 MiB per file.
- **Caveats:** one build on one day. Growth depends on how many repos the tracker adds, not only on new advisories. No traffic numbers were measured, because the Cloudflare analytics weren't accessible from here.
- **Implication:** Pages holds the site today with about 490 MB to spare. At about 19 KB per advisory, the site would pass 1 GB in roughly 8 months at the October rate, sooner if the watchlist grows. The fixed security headers fit in free Transform Rules. The per-file `X-Goog-Hash` ([F-073](#f-073)) needs a Worker on `/osv/*` (free under 100,000 requests a day) or a Pro plan for Snippets. Workers static assets would need Paid ($5/month), because the site has more than 20,000 files.
- **Sources:** [GitHub Pages limits](https://docs.github.com/en/pages/getting-started-with-github-pages/github-pages-limits); [Workers pricing](https://developers.cloudflare.com/workers/platform/pricing/); [Workers limits](https://developers.cloudflare.com/workers/platform/limits/); [Snippets](https://developers.cloudflare.com/rules/snippets/); [Transform Rules](https://developers.cloudflare.com/rules/transform/); [Cloudflare plans](https://www.cloudflare.com/plans/network-cdn/).

### F-172
- **Date:** 2026-11-13 · **Status:** confirmed (direct measurement; official docs), except where the 1 GB limit is measured (unknown)
- **Question:** Would compressing the site help it fit GitHub Pages?
- **Method:** the build from [F-171](#f-171): summed file bytes, `tar -cf - . | wc -c`, `tar | gzip -6 | wc -c`; compared two advisory pages and measured their `<header>`, `<footer>`, `<nav>`, `<svg>` and `<script>` blocks; `curl -D -` with `Accept-Encoding: gzip, br` on https://pages.github.com/; read the actions/upload-pages-artifact README.
- **Result:**
  - The site has 445 MB of file bytes (F-171's 508 MB was `du` disk blocks). As a tar it is **662 MB**, because tar adds a 512-byte header to each of the 51,813 files and 26,030 advisory directories and pads every file to 512 bytes. Gzipped, the tar is 98 MB.
  - By part (file bytes, then gzipped tar): `advisory/` 300 MB, 16.6 MB (18 times smaller); `feed/` 79 MB, 30 MB; `osv/` 51 MB, 46 MB (already zips). The per-advisory `feed/GHSA-*.json` files total 50 MB.
  - An advisory page is about 10.8 KB. Header 2,253 B, footer 2,364 B, script 1,374 B, SVG 1,262 B and nav 1,159 B, most of it the same on every page. Two pages share about 10 KB as character runs.
  - Pages already sends gzip in transit (`content-encoding: gzip` observed).
  - upload-pages-artifact: the artifact is a gzip of a single tar; "the tar file must be under 10GB", "(we recommend under 1 GB!)".
- **Caveats:** the docs don't say whether the 1 GB limit counts the tar or the unpacked files, so the tar (662 MB) is the safe reading. The character-run match overstates shared content. The gzip ratio is the better sign of how much is repeated.
- **Implication:** compressing the files doesn't help. Pages counts the files you deploy, can't serve pre-compressed files, and already compresses in transit. What helps is less boilerplate per advisory page: at about 3 KB a page, `advisory/` would drop from about 320 MB to about 107 MB in tar terms. The per-advisory feed JSON and the advisory URLs are public (sitemaps, checker links, old watchers), so they stay. At the October rate (about 3,000 new pages a month, about 25 KB each in tar terms), the site reaches 1 GB in about 4.5 months as it is.
- **Sources:** [upload-pages-artifact](https://github.com/actions/upload-pages-artifact); [GitHub Pages limits](https://docs.github.com/en/pages/getting-started-with-github-pages/github-pages-limits); the measurements above.

### F-173
- **Date:** 2026-11-13 · **Status:** confirmed (official docs; file counts from the build in [F-171](#f-171))
- **Question:** Could the whole site move to Cloudflare (Workers static assets, or R2), and what are the limits?
- **Method:** read the Workers static assets `_headers` docs and the R2 pricing page; counted the site's OSV zips.
- **Result:**
  - Workers static assets take a `_headers` file: per-path rules with splats; at most **100 rules**, 2,000 characters a line; `Access-Control-Allow-Origin` takes only `*`, `null` or one exact origin. `_headers` doesn't apply to responses a Worker script generates.
  - The nginx headers would need about 52 rules: one for the security headers on `/*`, about 3 for CORS (`/feed/*`, `/osv/*`, `/metrics.json`), one for `press/limbo.csv`, and one `X-Goog-Hash` rule per zip (47 ecosystem zips plus `limbo-db.zip`).
  - Static assets limits (F-171): 20,000 files on Free and 100,000 on Paid ($5/month); 25 MiB per file. The site has 51,813 files; its largest are `osv/limbo-db.zip` at 24.2 MiB and `feed/all.zip` at 23.9 MiB.
  - R2: 10 GB-month of storage, 1 million Class A and 10 million Class B operations a month free; then $0.015 per GB-month, $4.50 per million Class A and $0.36 per million Class B; no egress fees.
- **Caveats:** the docs don't say whether requests answered with `_headers` rules count as Worker invocations. No file-count growth measured over time: each advisory adds a page and a feed JSON, and pages stay after an advisory leaves limbo.
- **Implication:** Workers static assets fit today on Paid, with every header in `_headers`. They hit two hard limits within months: the 25 MiB file size (the two big zips) and the 100,000 files (about 3,000 new advisories a month, two files each, so roughly 8 months). R2 behind a Worker has neither limit and costs about $0 to $5 a month, but every request runs the Worker (100,000 a day free).
- **Sources:** [Static assets headers](https://developers.cloudflare.com/workers/static-assets/headers/); [R2 pricing](https://developers.cloudflare.com/r2/pricing/); [Workers limits](https://developers.cloudflare.com/workers/platform/limits/).

### F-174
- **Date:** 2026-11-13 · **Status:** confirmed (direct measurement; official docs); the daily change is one day's sample, so tentative as a rate
- **Question:** How much of the site changes each day, and what do moving between Cloudflare accounts and scoping its tokens involve?
- **Method:** built the site with the same code from `tracker-data` at 76530a5 (2026-11-12) and 48cbde8 (2026-11-13) and compared MD5s file by file; read the Cloudflare docs on account-owned tokens, R2 API tokens and moving a domain between accounts; looked up limbo.watch in RDAP.
- **Result:**
  - Between the two builds: 51,263 → 51,813 files; 600 new, 50 gone (feed JSON of advisories that left the feed), 27,015 changed. That's 168.7 MB to upload. The changed files: 25,692 in `feed/`, 1,891 in `advisory/`, 15 in `osv/`.
  - **Every per-advisory feed JSON changes on every build**: its `modified` field is the build time (e.g. `2026-11-14T06:31:49Z` and then `2026-11-14T05:53:17Z`; the two builds were run minutes apart, so the difference is only the clock).
  - Account-owned API tokens (`cfat_` prefix, detectable by scanners) belong to the account, not a person, and keep working after the creator leaves. Workers and R2 support them; Registrar and Page Rules don't.
  - R2 API tokens: Admin Read & Write, Admin Read only, Object Read & Write, Object Read only. Object tokens can be scoped to chosen buckets and can be account-owned. The S3 key ID is the token ID, and the secret is the SHA-256 of the token value.
  - Moving a zone to another account: add it there and change the nameservers at the registrar. Certificates don't carry over. Remove DNSSEC and zone holds first. Domains registered with Cloudflare Registrar need a manual transfer request.
  - limbo.watch: registrar Spaceship, Inc.; nameservers chad and dina.ns.cloudflare.com; DNSSEC not signed.
- **Caveats:** one pair of builds. The second build's `modified` reflects when it was run here, not the CI run. The 600 new files in one day may include a watchlist expansion.
- **Implication:** with `modified` as the build time, R2 sync would write about 27,600 objects a day (about 830,000 a month, near the 1 million free). Feed mirrors also can't use ETags. Setting `modified` to when a record's content last changed brings the writes to about 2,500 a day. Moving accounts needs only a nameserver change at Spaceship. Tokens can be limited to one bucket and owned by the account. See [docs/HOSTING_PLAN.md](HOSTING_PLAN.md).
- **Sources:** [Account API tokens](https://developers.cloudflare.com/fundamentals/api/get-started/account-owned-tokens/); [R2 API tokens](https://developers.cloudflare.com/r2/api/tokens/); [Move a domain between accounts](https://developers.cloudflare.com/fundamentals/manage-domains/move-domain/); RDAP for limbo.watch.

### F-175
- **Date:** 2026-11-13 · **Status:** confirmed (direct observation)
- **Question:** How much traffic does limbo.watch get, and what is it?
- **Method:** Cloudflare dashboard, zone limbo.watch (Free plan), Analytics → Requests, last 30 days and last 24 hours, read on 2026-11-13. Cloudflare's own numbers, not counted from logs.
- **Result:**
  - Last 30 days: **175,880 requests, 14.58 GB transferred, 71,530 visits**. Cache hit rate 2.26%: 168,640 requests were "dynamic", so nearly everything went to the origin. Status codes: 2xx 166,040; 3xx 7,930; 4xx 1,590; 5xx 320 (526 origin SSL error 250, 521 origin down 70).
  - Last 24 hours: 63,000 requests, 1.68 GB, 4,640 visits, a burst from crawlers. The 30-day average is about 5,900 a day.
  - By user agent, last 30 days: ClaudeBot 52,690; GPTBot 49,290; AhrefsBot 26,370; Googlebot 9,760; ShapBot 6,220; curl 5,910. That's about 80% crawlers, 58% AI crawlers.
  - Top paths: `/` 3,200; `/favicon.svg` 2,900; `/metrics.json` 1,900; `/feed/index.json` 1,830; **`/feed/all.zip` 960**; `/tracker/` 870.
  - Countries: United States 137,470, Canada 16,500, then Germany, the United Kingdom and France.
- **Caveats:** Free plan analytics may be sampled. The `/feed/all.zip` count includes 304s and `HEAD`, so it isn't a count of full downloads. Client IPs were seen but not recorded.
- **Implication:** all of it fits every option in [F-171](#f-171) and [F-173](#f-173): 14.58 GB a month is far under GitHub Pages' 100 GB, and Workers Paid's 10 million requests a month is 57 times the current traffic. But the busiest recent day (63,000) is close to the 100,000-a-day limit of Workers Free. Above that the Worker returns error 1027 until midnight UTC, and with R2 behind it there's no origin to fail open to. So the plan budgets Workers Paid ($5/month). About 32 feed fetches a day come from watchers and curl.
- **Sources:** Cloudflare dashboard analytics for the zone (not public).

### F-176
- **Date:** 2026-11-13 · **Status:** confirmed (official docs)
- **Question:** What does Workers Paid include beyond requests, and what else is free for a public repo?
- **Method:** read the Workers pricing page and GitHub's docs on secret scanning, push protection and Advanced Security.
- **Result:**
  - Workers Paid: 10 million requests a month and **30 million CPU milliseconds**; then $0.30 per million requests and $0.02 per million CPU milliseconds. No charge for egress or bandwidth. Requests answered from the Worker's cache are billed per request like any other (CPU time only on a miss).
  - A Workers **spending limit** blocks new invocations of every Worker on the account once usage charges pass a threshold (the subscription isn't counted). Email alerts can be set instead, without blocking.
  - GitHub: secret scanning and push protection are free for public repositories. Private repositories need GitHub Secret Protection (Team or Enterprise).
- **Implication:** the site's capacity on Workers Paid depends on requests, not bandwidth: 10 million is about 57 times the traffic in [F-175](#f-175). A spending limit would take the site down when it trips, so it has to sit well above expected use, with an email alert below it.
- **Sources:** [Workers pricing](https://developers.cloudflare.com/workers/platform/pricing/); [About secret scanning](https://docs.github.com/en/code-security/secret-scanning/introduction/about-secret-scanning); [About GitHub Advanced Security](https://docs.github.com/en/get-started/learning-about-github/about-github-advanced-security).

### F-177
- **Date:** 2026-11-13 · **Status:** confirmed (official docs)
- **Question:** Which AI crawlers are for training and which for search or user requests, and do they honour robots.txt?
- **Method:** read OpenAI's bots page and Anthropic's crawler help article.
- **Result:**
  - OpenAI: **GPTBot** crawls for training and honours robots.txt. **OAI-SearchBot** crawls for ChatGPT search and honours robots.txt; opted-out sites don't appear in search answers. **ChatGPT-User** fetches when a user asks; "robots.txt rules may not apply". OpenAI may share one crawl between GPTBot and OAI-SearchBot when both are allowed. Changes take about 24 hours to show in search.
  - Anthropic: **ClaudeBot** crawls for training, honours robots.txt and `Crawl-delay`. **Claude-SearchBot** crawls for search. **Claude-User** fetches when a user asks. Anthropic says its bots honour robots.txt and advises against blocking by IP, which hides robots.txt from them.
- **Implication:** the training crawlers (GPTBot, ClaudeBot) made 102,000 of the 175,880 requests in [F-175](#f-175). They can be kept off chosen paths with robots.txt, without affecting search crawlers or answers to users' questions, which read the live page. An advisory page's status changes as advisories are reviewed, so a training snapshot of it goes out of date; live fetches don't.
- **Sources:** [OpenAI crawlers](https://developers.openai.com/api/docs/bots); [Anthropic crawlers](https://support.claude.com/en/articles/8896518-does-anthropic-crawl-data-from-the-web-and-how-can-site-owners-block-the-crawler).

### F-178
- **Date:** 2026-11-14 · **Status:** confirmed (direct measurement)
- **Question:** With `modified` kept for unchanged records, how much of the site changes a day, and do old watchers still read the feed?
- **Method:** `limbowatch publish --previous-feed` (new): a record whose content, without `modified`, is the same as in the previous `all.zip` keeps that feed's `modified`. Built from `tracker-data` 48cbde8 with the 76530a5 build (F-174) as the previous feed; compared MD5s file by file with that build. Read the new `all.zip` with `from_feed_zip` from limbowatch-cli 0.1.0a1, 0.1.0a6 and 0.1.0a14 (`uvx`). 0.1.0a7 and 0.1.0a8 aren't installable from PyPI.
- **Result:**
  - 25,063 of 25,685 records were unchanged and kept their `modified`.
  - Files changed or new compared with the previous build: **3,112, down from 27,615**: `advisory/` 2,154, `feed/` 329, `osv/` 12, others 17 changed; 600 new.
  - All three releases read 25,685 records. No release reads `modified`: no `watch/` code from v0.1.0a1 to v0.1.0a14 contains it.
- **Caveats:** one pair of days. The 2,154 changed advisory pages now make up most of the daily change; why they change wasn't examined. The previous feed is fetched from limbo.watch in `site.yml`; if that fails, every record's `modified` is the build time for that day, as before.
- **Implication:** R2 sync writes about 3,100 objects a day (about 93,000 a month, well inside 1 million free). Feed mirrors and incremental OSV consumers see only records that changed. Supersedes the estimate of about 2,500 a day in [F-174](#f-174).
- **Sources:** the builds and commands above.

### F-179
- **Date:** 2026-11-14 · **Status:** confirmed (direct observation; local runtime, not yet Cloudflare's network)
- **Question:** Does the Worker in `deploy/worker/` serve the site as nginx does, and how does the Workers runtime behave locally?
- **Method:** 19 tests in workerd with an in-memory R2 bucket (`@cloudflare/vitest-plugin` 1.4.11, vitest 4.1.12, wrangler 4.156.0). `wrangler deploy --dry-run`. `wrangler dev --local` with 15 files from today's build put into a local R2, and `curl -sI` on 18 paths of it and of https://limbo.watch, comparing status and headers. The 25 MB `feed/all.zip` fetched from the Worker: MD5, `If-None-Match`, `Range: bytes=0-99`; read with `from_feed_zip` from limbowatch-cli 0.1.0a14.
- **Result:**
  - Same as nginx on all 18 paths: status, `Content-Type` (including `text/csv; charset=utf-8` and `application/atom+xml`), CORS only on `/feed/`, `/osv/` and `/metrics.json`, the five security headers (also on 404s and redirects), `X-Goog-Hash` only on `/osv/<Ecosystem>/all.zip`. The exceptions are below.
  - Differences, all expected: redirects go to a relative `/tracker/` where nginx sends `http://limbo.watch/tracker/`. The live site's `cache-control: max-age=14400` and `age` on zip, CSV, CSS, SVG and robots.txt, and its missing `accept-ranges` on compressed text, come from Cloudflare's edge (browser cache setting, edge cache, compression), which `wrangler dev` doesn't have. nginx itself sends `max-age=300`.
  - The zip came back byte for byte (MD5 `49be1d43…`), the ETag is the R2 MD5 (`"49be1d43…"`, where nginx's was `"<mtime>-<size>"`), `If-None-Match` gave 304, the range 206 with 100 bytes, and `X-Goog-Hash` matched `osv/crc32c.map`. 0.1.0a14 read 25,685 records.
  - **The runtime treats every named export of the main module as an entry point.** `export const UNSATISFIABLE = "…"` in `src/index.js` made `wrangler dev` fail: "Incorrect type for map entry 'UNSATISFIABLE': the provided value is not of type 'function or ExportedHandler'". The vitest tests didn't catch it, because they import the module directly. The helpers now live in `src/serve.js`, and a test checks that `src/index.js` exports only `default`.
  - Local R2 ignores a range it can't satisfy (`bytes=5000-6000` on 1,000 bytes returned all 1,000 bytes as `{offset: 0, length: 1000}`), and also a malformed one (`bytes=abc`). So the Worker parses `Range` itself: past the end gives 416, malformed is ignored, as nginx does.
- **Caveats:** local runtime only. Compression, edge headers, latency and CPU time on Cloudflare's network are measured in step 4 against a `workers.dev` deployment. Old ETags won't match the new ones, so each watcher with a cached feed downloads it once after the switch.
- **Implication:** the Worker is ready to deploy for the parity check. After the switch, browsers revalidate zips and CSS after 5 minutes instead of 4 hours, unless the zone's browser cache setting applies to Worker responses, which step 4 will show.
- **Sources:** `deploy/worker/`; the runs above.

### F-180
- **Date:** 2026-11-14 · **Status:** confirmed (official docs; GitHub billing API); dynamic rewrites and redirects on the Free plan are tentative (not stated in the docs)
- **Question:** Can limbo.watch be served from R2 at no monthly cost, without a Worker on every request? What does the project cost on GitHub today?
- **Method:** read Cloudflare's docs on R2 public buckets, URL rewrites, Single Redirects, Rules language functions and Worker routes. `gh api orgs/limbowatch/settings/billing/usage`.
- **Result:**
  - An R2 bucket can be public on a **custom domain** of a zone in the same account, with Cloudflare's cache, WAF and rules in front. Only some file types are cached unless a cache-everything rule is set. `r2.dev` is rate-limited and meant for development. The docs don't mention index documents (`index.html` for `/`).
  - Single Redirects: 10 rules on Free (25 Pro, 50 Business), wildcards on every plan, regex only on Business and up. Transform Rules: 10 on Free in total (F-173). `concat`, `ends_with`, `starts_with`, `regex_replace` and `wildcard_replace` have no plan restriction in the Rules language reference. The rewrite and redirect pages don't say whether dynamic expressions work on Free.
  - A Worker route can cover a subpath only (`example.com/images/*`); other paths go to the origin. On Workers Free with fail open, requests over the daily limit skip the Worker ([F-173](#f-173)).
  - GitHub, organization limbowatch (Free plan): **$0 net**. November gross so far: Actions Linux 2,135 minutes ($12.81), macOS 204 minutes ($12.65), all discounted to $0 for a public repository. Storage is negligible, with no Packages line. The site image has been built 126 times since 2026-10-28.
- **Caveats:** free-plan support for dynamic rewrites and redirects has to be confirmed by creating the rules. The package list needs `read:packages`, which the token here lacks.
- **Implication:** the site can run at $0 a month as R2 on a custom domain:
  - one URL rewrite (`/…/` → `/…/index.html`);
  - two header rules (the security headers; CORS on the feed, OSV files and metrics);
  - two redirects (slash, www);
  - a cache rule;
  - the Worker only on `/osv/*` for `X-Goog-Hash`, failing open.
  Requests not on `/osv/*` never run a Worker, so the 100,000-a-day limit can't take the site down, and Workers Paid isn't needed.
- **Sources:** [R2 public buckets](https://developers.cloudflare.com/r2/buckets/public-buckets/); [URL rewrites](https://developers.cloudflare.com/rules/transform/url-rewrite/); [URL forwarding availability](https://developers.cloudflare.com/rules/url-forwarding/); [Rules language functions](https://developers.cloudflare.com/ruleset-engine/rules-language/functions/); [Worker routes](https://developers.cloudflare.com/workers/configuration/routing/routes/); GitHub billing usage API.

### F-181
- **Date:** 2026-11-14 · **Status:** confirmed (official docs)
- **Question:** Could D1 (Cloudflare's SQLite) serve the tracker search or the package checker, and at what cost?
- **Method:** read the D1 pricing and limits pages.
- **Result:**
  - Free (Workers Free): **5 million rows read and 100,000 rows written a day**, 5 GB in total, 10 databases of up to 500 MB each, 50 queries per Worker invocation. Past a daily limit, "you will not be able to run queries against D1" until 00:00 UTC.
  - Paid (Workers Paid, $5/month): 25 billion rows read and 50 million written a month included; databases up to 10 GB.
  - **Rows read counts rows scanned, not returned.** A filter on an unindexed column, or a full-text match over every row, reads the whole table. Indexes cut rows read and cost one extra row written per indexed write.
  - Each database runs one query at a time; at 1 ms a query that's at most 1,000 a second. Results are capped at 50 MB.
  - D1 is queried from Workers, so every query also counts against the Workers request limit (100,000 a day on Free, [F-173](#f-173)).
- **Implication:** an indexed lookup ("is npm `x` 1.2.3 in limbo?") would fit the free tier easily. A substring search over the tracker's 43,255 advisories (its state on 2026-11-13) scans them all, which allows only about 115 searches a day on Free. Any D1 endpoint runs a Worker on every request, bringing back the daily cap that the $0 setup avoids ([F-180](#f-180)). The static files already used by the search and the checker have neither limit.
- **Sources:** [D1 pricing](https://developers.cloudflare.com/d1/platform/pricing/); [D1 limits](https://developers.cloudflare.com/d1/platform/limits/).

### F-182
- **Date:** 2026-11-14 · **Status:** confirmed (direct observation; official docs)
- **Question:** Step 3: does `uv` check the hashes in a requirements file, and can a Worker route's fail-open be set from config?
- **Method:** `uv pip compile --generate-hashes --exclude-newer 2026-10-31` for `boto3==1.43.123` (deploy/cloudflare/requirements.txt). Replaced both of boto3's hashes with zeros in a copy, cleared boto3 from uv's cache, and installed the copy two ways. Read the Workers limits page on fail-open.
- **Result:**
  - `uv run --no-project --with-requirements <copy> python -c "import boto3"` **installed boto3 and exited 0**: the wrong hashes weren't checked.
  - `uv pip install --require-hashes -r <copy>` into a new venv failed: "Hash mismatch for `boto3==1.43.123`", computed `sha256:d18d66e1…`. With the real file it installed boto3 1.43.123.
  - Workers limits: "You can configure the fail mode by toggling the corresponding route." The docs name no wrangler or API field for it, nor a default.
- **Caveats:** one uv version (the one installed here). The fail-open default wasn't observed.
- **Implication:** `site.yml` installs the upload script's dependencies with `uv pip install --require-hashes` into a separate venv, not `uv run --with-requirements`. The `/osv/*` route's fail-open is switched on in the dashboard after the first deploy, and checked in step 4.
- **Sources:** the commands above; [Workers limits](https://developers.cloudflare.com/workers/platform/limits/).

### F-183
- **Date:** 2026-11-14 · **Status:** confirmed (direct observation)
- **Question:** Steps 3 and 4: does the $0 setup work on Cloudflare, and does `next.limbo.watch` serve what `limbo.watch` (nginx) serves?
- **Method:**
  - `site.yml` run 43578856207 uploaded the build to the new bucket `limbowatch-site`; `next.limbo.watch` was connected as its custom domain with minimum TLS 1.2.
  - `scripts/cf_rules.py --host next.limbo.watch` applied the six rules, then ran a second time. `wrangler deploy` (4.156.0) deployed the Worker on `next.limbo.watch/osv/*`, run twice.
  - The route's failure mode was set in the dashboard and read back through `GET /zones/{id}/workers/routes`.
  - `scripts/check_hosting.py` (new) compared 165 paths: the site's pages, every OSV zip, and 40 advisory pages and 40 feed records sampled with seed 0. The tracker search ("typebox") and the checker (`@jest/schemas` 29.6.3, npm) were tried in Chrome on next.limbo.watch.
- **Result:**
  - **First upload: 51,814 files in 12 min 12 s** (09:06:52 to 09:19:04 UTC), 0 deleted. boto3's default pool of 10 connections limited the script's 32 threads; it now has 32.
  - **The Free plan accepted the dynamic rewrite and redirect** (`concat`, `ends_with`, `contains`). A second run reported every phase up to date. The www rule, which uses `substring`, isn't applied yet.
  - The custom domain went from "Initializing" to "Active" within about 15 minutes.
  - **A new route fails closed by default** (dashboard: "Fail closed (block)"). The API has a field for it, `request_limit_fail_open`. **`wrangler deploy` reset it to `false`**: a read right after the redeploy still showed `true`, and a read a few minutes later showed `false`. `cf_rules.py` now sets it through the API (`PUT /zones/{id}/workers/routes/{id}`), and two reads showed `true`.
  - `HEAD` requests report `cf-cache-status: DYNAMIC`. `GET` requests give `MISS`, then `HIT` with a growing `age`, for HTML, CSS, CSV and JSON. HTML responses have no `ETag` on either host.
  - **Parity: 165 paths, 0 differ.** Status, body SHA-256, `Content-Type`, CORS, the five security headers, and redirects compared by path all match. Redirects now go to `https://`; nginx's went to `http://`. On next.limbo.watch, `If-None-Match` gave 304 and `Range: bytes=0-99` gave 206 for every zip. `HEAD /osv/<Ecosystem>/all.zip` sent an `X-Goog-Hash` equal to the body's CRC-32C for all 47 ecosystem zips.
  - The tracker search found `@sinclair/typebox` (1 of 10,410). The checker resolved `@jest/schemas` 29.6.3 through deps.dev and reported `@sinclair/typebox` 0.27.12 as possibly affected. No console errors on either page.
- **Caveats:** one day, one sample. The www redirect and the `limbo.watch/osv/*` route are untested until step 5. Old watchers weren't run against next.limbo.watch, because their feed URL is fixed to limbo.watch; the bytes they'd get are identical.
- **Implication:** steps 3 and 4 pass. Run `cf_rules.py` after every `wrangler deploy` (deploy/README.md), or the route goes back to failing closed. Step 5 can switch `limbo.watch` once you approve.
- **Sources:** the runs and commands above.

### F-184
- **Date:** 2026-11-14 · **Status:** confirmed (direct observation)
- **Question:** Step 5: does limbo.watch serve the same site from R2 after the switch, and what happened during it?
- **Method:**
  - `cf_rules.py --host limbo.watch --host next.limbo.watch --www www.limbo.watch` applied the rules, with a dry run first. The Worker was redeployed with the route `limbo.watch/osv/*`, then `cf_rules.py` set fail-open. Both were done while nginx still served limbo.watch, and `check_hosting.py` was run between steps.
  - limbo.watch was then connected to the bucket as a custom domain (minimum TLS 1.2), at about 09:37 UTC. The DNS records before the switch were kept outside the repo for rollback.
  - After the switch:
    - `check_hosting.py --old https://next.limbo.watch --new https://limbo.watch` (165 paths);
    - SHA-256 of five files from the cluster directly (`curl --resolve`) and from limbo.watch;
    - the watcher's own `watch.scan.fetch`, run twice with one cache directory;
    - requests with five user agents;
    - the zone's sampled security events.
- **Result:**
  - Before the switch the rules changed nothing visible: 125 paths, 0 differ. Redirects and caching moved to Cloudflare's edge (`MISS`/`REVALIDATED` where it had been `DYNAMIC`). The www rule (`substring`) was accepted and sends `https://www.limbo.watch/tracker/?x=1` to `https://limbo.watch/tracker/?x=1`.
  - **Connecting the custom domain replaced the zone's two proxied A records with the R2 record** automatically. The domain showed "Initializing".
  - **For a short time right after the switch, three requests got 403.** Within a minute or two every request got 200 (6 rounds of 4 URLs, with and without query strings).
  - **After the switch: 165 paths, 0 differ** from next.limbo.watch. On limbo.watch, 304s, ranges and `X-Goog-Hash` (all 47 ecosystem zips) passed, and `feed/all.zip` has an R2 ETag (`"03b9dd36…"`).
  - `feed/all.zip`, `feed/watchlist.json`, `tracker/data.json` and `osv/limbo-db.zip` are byte-identical to the cluster's. The home page differs only by two `<!--email_off-->` markers: the build emits them (`site.py`) and Cloudflare strips them on the way out, as it did with nginx.
  - The watcher's fetch got the feed (24,996,510 bytes, 0.6 s), reused it by ETag the second time, and read 25,685 records. Both routes fail open; all four rule phases are up to date.
  - **Python's `urllib` user agent gets 403 on both hosts**; curl, httpx, an empty user agent and `limbowatch/…` get 200. The zone's Browser Integrity Check blocked a request on 2026-11-13 11:47 PST, before the switch, so this setting predates the move.
- **Caveats:** the 403 window wasn't measured precisely. Cloudflare analytics may show how many visitors hit it.
- **Implication:** limbo.watch is served from R2 at $0 a month. The cluster keeps running, still deployed daily by `site.yml`, until step 6 (after 2026-11-21). Rolling back means disconnecting the custom domain and restoring the two A records. Browser Integrity Check blocks `urllib` scripts from fetching the feed; turning it off for `/feed/` and `/osv/` is a separate decision.
- **Sources:** the runs and commands above; Cloudflare dashboard (DNS, R2, security events).

### F-185
- **Date:** 2026-11-14 · **Status:** confirmed (direct observation)
- **Question:** Do real watcher scans work against limbo.watch on R2, and how long does a daily deploy take now?
- **Method:** cloned limbowatch/limbo-poc (the proof repository, F-170) and ran `limbowatch scan` on it with a fresh cache and OSV-Scanner 2.7.1: the current code (`uv run`), and limbowatch-cli 0.1.0a1 and 0.1.0a14 (`uvx`). Checked the 7 examples from F-170 among the findings. Ran `site.yml` by hand (run 43582872578, same tracker data as the run before) and read the step times and the upload script's summary.
- **Result:**
  - Current code: 103 findings in 3.7 s, all 7 examples (typebox, nats-server, go-openapi/spec, go-toml, mustache, rubyntlm, scapy). 0.1.0a14: 103 findings in 3 s, 7 of 7. **0.1.0a1: 101 findings in 4 s, 7 of 7.** It warns that it was tested with OSV-Scanner 2.7.0. Its two fewer findings are the ranges fixed in 0.1.0a13 (F-159, F-160).
  - `site.yml`: **2 min 26 s in total**. Publish 50 s, image build and push 40 s, **Upload to R2 35 s**, which includes making the venv, listing 51,814 objects and comparing MD5s: "r2: 402 uploaded, 0 deleted, 51412 unchanged". With the pool of 32, uploading is no longer the slow part. The first upload with a pool of 10 took 12 min (F-183).
- **Caveats:** one run with few changes. A day with the usual ~3,100 changed files ([F-178](#f-178)) adds about 3,100 uploads; at the speed observed that's well under a minute more. Not yet measured on such a day.
- **Implication:** old and new watchers work on the R2 setup. A daily deploy takes about 2 to 3 minutes; step 6 removes the image build (40 s).
- **Sources:** the runs above.

### F-186
- **Date:** 2026-11-14 · **Status:** confirmed (direct observation)
- **Question:** Step 6: was the cluster setup retired cleanly, and does limbo.watch still serve correctly from R2 alone?
- **Method:**
  - On the cluster (`ssh root@skylion kubectl`): listed the Argo CD applications and their repositories, deleted the application `limbowatch-site` (no finalizers), the namespace `limbowatch`, and the repository secret `argocd/repo-limbowatch-ssh`.
  - On GitHub: deleted the deploy key `argocd-skylion` (`gh api -X DELETE repos/…/keys/…`).
  - In the repository: removed `deploy/site`, `deploy/k8s`, `deploy/argocd-app.yaml` and `deploy/node`; `site.yml` builds and uploads to R2 only.
  - Removed `next.limbo.watch` from `wrangler.jsonc` and redeployed, read the zone's routes, and ran `cf_rules.py --host limbo.watch --www www.limbo.watch` twice. Checked six URLs on limbo.watch.
- **Result:**
  - Argo CD now lists only the cluster's other four applications, which use other repositories. The namespace `limbowatch` is gone. The repository has no deploy keys left. limbo.watch kept answering 200. A direct request to a cluster address no longer gets a TLS answer.
  - **The redeploy removed the `next.limbo.watch/osv/*` route** and reset `limbo.watch/osv/*` to fail closed (as in F-183). `cf_rules.py` set fail-open again, and its second run had nothing to change.
  - limbo.watch serves redirects (`/tracker` → `https://limbo.watch/tracker/`; www → apex, keeping the query), `X-Goog-Hash` on `/osv/PyPI/all.zip`, CORS on the feed, `text/csv; charset=utf-8`, and the CSP on pages and files. The www redirect carries no security headers: the security rule covers only the served hosts.
- **Caveats:** the kubelet image GC config (`20-image-gc.conf`) stays installed on both nodes. It's general and harmless; its source file left the repo. The private package `ghcr.io/limbowatch/limbowatch-site` (126 versions) wasn't deleted: that needs the `delete:packages` scope. `next.limbo.watch` is still connected to the bucket until it's disconnected in the dashboard.
- **Implication:** the cluster serves nothing for limbo.watch any more. Going back now means rebuilding the nginx setup from git history (before this commit), not only restoring DNS.
- **Sources:** the commands above.

### F-187
- **Date:** 2026-11-14 · **Status:** confirmed (direct observation)
- **Question:** Are the last pieces of the cluster setup gone (follow-up to [F-186](#f-186))?
- **Method:** `gh api orgs/limbowatch/packages/container/limbowatch-site` (with `read:packages`, `delete:packages` added by the maintainer), then `DELETE` on it, then the package list. `dig` and `curl` for next.limbo.watch after it was removed from the bucket in the dashboard.
- **Result:**
  - The private package `limbowatch-site` (created 2026-10-28, last pushed 2026-11-14 09:58 UTC) had **387 versions**, not 126. Each of the 126 pushes also stored untagged versions. It's deleted. The only container package left is the public `limbowatch` watcher image.
  - `next.limbo.watch` has no DNS record and doesn't connect.
- **Implication:** nothing of the cluster setup remains outside git history and the kubelet GC config on the two nodes. F-186's caveats about the package and next.limbo.watch are resolved.
- **Sources:** the commands above.

### F-188
- **Date:** 2026-11-14 · **Status:** confirmed for the samples (direct observation); the total isn't broken down
- **Question:** Who sends requests with Python's `urllib` user agent, which Browser Integrity Check blocks ([F-184](#f-184))?
- **Method:** Cloudflare dashboard, zone limbo.watch: Security → Analytics, last 30 days (totals by security service), and Events filtered to Service = Browser integrity check, last 72 hours and last 30 days (sampled logs, each opened for user agent, host and path). Searched the repository for `urllib.request`/`urlopen`. Visitors' IP addresses were read but aren't recorded here.
- **Result:**
  - Last 30 days: 186,750 requests; **90 mitigated, 30 of them by Browser Integrity Check** and 60 by managed rules.
  - The sampled Browser Integrity Check blocks (8 shown):
    - 2026-11-14 09:41 UTC: 4 requests from `Python-urllib/3.12` and `/3.15` to `/feed/index.json` and `/feed/all.zip` on limbo.watch and next.limbo.watch. These were this session's own tests (F-184).
    - 2026-11-13 19:47 UTC: **one request from `Python-urllib/3.12`, through Cloudflare's own network (AS13335), for `/feed/GHSA-5hrj-7fc3-cmx9.json`**, one of the home page's examples ([F-157](#f-157)). Origin unknown. The repository's scripts that use `urllib` call only api.osv.dev (`research/2026-11-demo-evidence/verify.py`) or the GitHub, GitLab and Gitea test servers.
    - 2026-11-06 20:11–20:13 UTC: 3 requests for `www.limbo.watch/` with a malformed, truncated user agent (`"Mozilla/5.0 (iPhone; CPU iPhone OS 17_2 like Mac OS X)`, beginning with a quote) from three residential networks. That looks like a scanner, not a visitor.
  - The traffic samples also showed `next.limbo.watch/tracker/` still being requested at 10:55–11:04 UTC, after the test hostname was removed: crawlers had found it within hours.
- **Caveats:** sampled logs. 22 of the 30 blocks weren't shown, so their user agents are unknown.
- **Implication:** almost nobody fetches the site with `urllib`: one unidentified request in 30 days, besides this session's tests. Browser Integrity Check costs nothing and blocks junk such as the malformed scanner, so there's no reason to turn it off for the feed. A test hostname is found by crawlers quickly, so a future one should send `noindex` or sit behind Access.
- **Sources:** Cloudflare dashboard (zone security analytics and events).

### F-189
- **Date:** 2026-11-14 · **Status:** confirmed (direct observation)
- **Question:** Do the published GitHub Action and GitLab component work against limbo.watch on R2 from hosted CI runners, or does Cloudflare block them?
- **Method:**
  - Ran limbowatch/limbo-poc's `proof` workflow by hand (run 43588916833, GitHub-hosted `ubuntu-latest`, `limbowatch/limbowatch-action@v0.1.0a14` with its pinned image).
  - Ran a pipeline of the GitLab demo project limbowatch/demo-app (pipeline 3068138374, GitLab.com shared runner on Google Cloud, component `limbowatch@0.1.0-alpha.14`, `fail_on: high`, runner cache from before the switch).
  - Grouped the zone's 25 sampled security events of the last 72 hours by service, network, user agent, method and path.
- **Result:**
  - Action: success. The scan read the "limbo feed of 2026-11-14 10:13 UTC" (the first R2-only build, F-186) and reported **103 advisories in limbo in 7 packages**, as on 2026-11-13.
  - GitLab component: the scan read the same 10:13 feed after restoring its cache, which held the feed with nginx's ETag. It reported **11 advisories in 4 packages, 4 high**, the same as before the switch. The job fails, as the demo intends with `fail_on: high`.
  - Security events: 16 `wp-config.php` probes (TLM-Audit-Scanner), 3 `POST /` from Google Cloud with a Windows browser user agent, 2 exploit probes from a Go client, and 4 `urllib` requests (this session's tests). None was a feed or OSV download by a watcher.
- **Caveats:** one run on each platform. Self-hosted runners and Gitea/Forgejo weren't tried; they use the same client and user agent.
- **Implication:** customers using the Action, the component or the CLI aren't affected by Browser Integrity Check or managed rules. Limbowatch sends its own user agent (`limbowatch/<version> (+https://limbo.watch)`) from every release, and its requests are plain `GET`s of the feed. Only hand-written scripts using Python's default `urllib` user agent are blocked; the feed's documentation should say to send a user agent.
- **Sources:** the runs above; Cloudflare dashboard (zone security events).

### F-190
- **Date:** 2026-11-14 · **Status:** confirmed (direct observation and GitLab source); why GitLab counts 0 is unknown
- **Question:** Can we tell how many projects use the GitHub Action and the GitLab CI/CD Catalog component, and can a README badge show it?
- **Method:**
  - GitHub: `github.com/limbowatch/limbowatch-action/network/dependents` (the dependency graph, logged out); `gh api search/code` for `"limbowatch/limbowatch-action" path:.github/workflows`; `gh api repos/limbowatch/limbowatch-action/traffic/{clones,views}`; the ghcr package page's "Total downloads".
  - GitLab: GraphQL `ciCatalogResource(fullPath: "limbowatch/limbowatch-component") { last30DayUsageCount }`, by POST and by GET, logged out and with `glab api graphql`, and per component version. Compared with `components/sast` and `components/secret-detection`. Read GitLab's docs (`doc/ci/components/_index.md`) and source (`Chain::ComponentUsage`, `TrackComponentUsageWorker`, `AggregateLast30DayUsageService`) on master. Listed the private GitLab demo-app's pipelines and its `include:`.
  - PyPI: `pypistats.org/api/packages/{limbowatch-cli,limbowatch}/recent`.
  - Badges: shields.io dynamic JSON badge on the GitLab GraphQL GET URL, and `img.shields.io/pypi/dm/limbowatch-cli`.
- **Result:**
  - **GitHub Action: 3 dependent repositories, all ours** (limbowatch/demo-app, limbowatch/limbo-poc and the maintainer's personal site). GitHub has no API or shields.io badge for an Action's dependents; the page is HTML and says its counts are approximate. Code search found only 1 of the 3 (the index lags). Marketplace shows no usage count. Repo traffic, last 14 days: 170 clones (55 unique), 7 views; clones include our own CI.
  - **ghcr image: 455 total downloads** since it was published. That includes our own CI, e2e and release checks. The Packages API doesn't return download counts; only the HTML page does.
  - **GitLab component: `last30DayUsageCount` = 0**, for the resource and for each version, logged out or in. SAST shows 8,419 and Secret Detection 9,934, so the counter works on GitLab.com. The field is public and GraphQL accepts GET, so shields.io can render it directly (it shows "0").
    - Docs: the count is unique projects that used any component of the resource in a pipeline in the last 30 days. The Analytics tab (Free, 18.9) shows the same number to maintainers; the per-project Usage tab is Premium (19.0).
    - Source: a pipeline enqueues `TrackComponentUsageWorker` with the included components. It records a usage only if the project is a catalog resource and the included SHA is a released version, and only when the pipeline has a user. A daily cron job counts distinct projects per resource over 30 days.
    - The private demo-app has included released versions (`@0.1.0-alpha.5` to `@0.1.0-alpha.14`) on every push since at least 2026-11-07 (15 pipelines, the latest on 2026-11-14 by API), so it should count as 1. It doesn't, and the cause isn't visible from outside.
  - PyPI: limbowatch-cli 1,417 downloads in the last month, limbowatch 1,606 (pypistats, excluding nothing). These include mirrors, bots, and our own `install: python` CI runs.
- **Caveats:** one day's look. The GitHub dependents page sees only public repos with the dependency graph enabled; private users are invisible. Download counts are not users. Limbo.watch's Cloudflare analytics by user agent (`limbowatch/<version>`, F-189) would count feed fetches from every host, but weren't read here (no API token in this session).
- **Implication:** today there are no outside users we can see on either platform; every visible user is ours. A usage badge would show 3 (GitHub, all ours) and 0 (GitLab), which is misleading or unhelpful. Only GitLab's count can be badged without our own infrastructure. Combining both would need a scheduled job that reads the dependents page (minus the limbowatch org) and the GraphQL field and publishes a shields.io endpoint JSON on limbo.watch.
- **Sources:** GitHub dependency graph page and REST API; ghcr package page; GitLab GraphQL API; [GitLab CI/CD components docs](https://docs.gitlab.com/ci/components/); GitLab source (`lib/gitlab/ci/pipeline/chain/component_usage.rb`, `app/workers/ci/catalog/resources/track_component_usage_worker.rb`, `app/services/ci/catalog/resources/aggregate_last30_day_usage_service.rb`); pypistats.org API; shields.io.

### F-191
- **Date:** 2026-11-15 · **Status:** confirmed (direct observation; code read)
- **Question:** Can users, and the Action in their CI, trust what they download from limbo.watch?
- **Method:**
  - Live checks with curl and openssl: plain HTTP, TLS 1.0, 1.1 and 1.2, bucket listing (`?list-type=2`), `..` paths, the headers on each file type, and the certificate.
  - Read the Action's `install.sh` and the watcher's HTTP client, feed reader (`from_feed_zip`) and annotation output. Listed every `${…}` in `check.js` not wrapped in `esc()`, and followed each value that comes from the URL or deps.dev.
  - Added `actions/attest` v4.2.2 to `site.yml` (run 43684806854). Downloaded six files from limbo.watch and ran `gh attestation verify` with `--signer-workflow …/site.yml --source-ref refs/heads/main --deny-self-hosted-runners`, then the same on a copy with one byte added.
  - Read the GitHub org's 2FA settings (API) and the Cloudflare login's (dashboard).
- **Result:**
  - **`http://limbo.watch/feed/all.zip` returned 200**, served unencrypted. A new zone rule, `limbowatch-https`, now answers 301 to `https://` for every path, keeping the query. TLS 1.0 and 1.1 are refused; the certificate (Google Trust Services, valid to 2027-02-12) is fine. The bucket can't be listed, and `..` paths get 400.
  - Every file type carries its `Content-Type`, `nosniff`, HSTS and the CSP; CORS is on feed and OSV files only.
  - The Action pulls its image by digest (attested), or in Python mode checks OSV-Scanner's SHA-256 and installs with `--require-hashes`. The watcher keeps httpx's TLS verification. Annotations escape `%`, CR and LF, and Markdown output is escaped (F-164).
  - `check.js` and the tracker escape every value from the URL, deps.dev or the feed before writing HTML: no cross-site scripting found.
  - **`from_feed_zip` has no size limits.** A tampered feed couldn't run code, but a zip bomb could exhaust a runner's memory.
  - Attestation: "Attestation created for 18 subjects": the 51 files have 18 distinct digests, since many empty ecosystem zips are identical. All six live downloads VERIFIED; the altered copy was rejected (no attestation for its digest, HTTP 404).
  - That run uploaded 6,567 changed files (45,475 unchanged), more than the 3,100 estimated in F-178 but far inside R2's free writes.
  - Cloudflare login: TOTP 2FA on. GitHub: the org's only member has 2FA, but the org doesn't require it.
- **Caveats:** the watcher doesn't verify the attestation itself yet; users and mirrors can, with `gh`. Attestations exist only for builds from this run on.
- **Implication:** downloads are HTTPS-only, and any copy can be checked against a signature that doesn't depend on the website, R2 or Cloudflare. Still to do: the watcher should verify the feed's attestation before using it, and cap what it reads from the zip (next release). The org should require 2FA.
- **Sources:** the commands and runs above; `integrations/action/install.sh`, `limbowatch/http.py`, `watch/candidates.py`, `watch/output.py`, `publish/check.js`.

### F-192
- **Date:** 2026-11-15 · **Status:** confirmed (direct observation; tests on recorded fixtures)
- **Question:** Can the watcher itself refuse a feed that isn't ours, and stay within a real feed's size, before customers rely on it?
- **Method:**
  - `GET https://api.github.com/repos/limbowatch/limbowatch/attestations/sha256:<digest>` for the live `feed/all.zip`, without a token; the answer is recorded as `tests/fixtures/attestations/feed_all_zip.json`.
  - Measured the live zip: size, records, largest record.
  - Built `watch/feedtrust.py`, the download cap in `limbowatch.http` and the zip limits in `watch/candidates.py`, plus 8 tests (`tests/test_feedtrust.py`).
  - Ran the new watcher on limbowatch/limbo-poc against limbo.watch, then dropped one advisory (GHSA-gqhc-vf4h-h7hg, critical) from its cached `all.zip` and ran it again. The server answers 304, so the altered cache is reused.
- **Result:**
  - The attestation API answers without a token (`x-ratelimit-limit: 60` an hour), with the Sigstore bundle. Its in-toto statement lists the 18 subjects by SHA-256, `predicateType` `https://slsa.dev/provenance/v1`, `externalParameters.workflow` = `{repository: https://github.com/limbowatch/limbowatch, path: .github/workflows/site.yml, ref: refs/heads/main}`, and builder `…/site.yml@refs/heads/main`.
  - Live feed: 25.1 MB, 25,782 records, 50.1 MB unpacked, largest record 210.4 KB. The limits: downloads 500 MB (watchlist 100 MB), counted after decompression; 500,000 records, 5 MB each, 1 GB unpacked, checked from the zip's listing before unpacking.
  - **Normal scan:** both files verified (2 digests cached), 103 findings, the same as before. **Tampered cache:** "the limbo feed's feed/all.zip failed verification (GitHub has no attestation for it), so it wasn't used", exit 2.
  - Tests: a statement for another file, workflow, ref, fork or predicate type is refused. 404 is refused; 5xx, 403 or 429 rate limits are "unknown", answered without waiting. `auto` warns and goes on when GitHub can't be reached; `require` refuses; `off` asks nothing. A verified digest isn't asked again. A gzip response that unpacks past the cap is stopped, as are zips over each limit.
- **Caveats:**
  - The watcher trusts GitHub's API, over TLS, for the signature: it checks the statement GitHub stored, not the Sigstore certificate chain, which `gh attestation verify` does.
  - The unauthenticated limit is 60 lookups an hour per address. A scan asks only for a feed it hasn't verified before (about once a day per cache), and uses `GITHUB_TOKEN` when set.
  - Pinned old releases don't verify; customers get this from the next release.
- **Implication:** a feed swapped anywhere between our build and the customer's runner (R2, Cloudflare, the network, or the runner's cache) is refused rather than used to under-report. The WATCHER.md hosts table now lists api.github.com for verification (`--verify-feed off` removes it), so "feed only" means limbo.watch and api.github.com unless verification is off.
- **Sources:** the API answer and runs above; `tests/test_feedtrust.py`.

### F-193
- **Date:** 2026-11-15 · **Status:** confirmed (independent review, reproduced; fixed and tested)
- **Question:** Before 0.1.0a15: does an independent review of the changes since 0.1.0a14 find bugs or crashes in the feed verification and size limits ([F-192](#f-192))?
- **Method:**
  - A fresh reviewer agent got only `git diff v0.1.0a14..HEAD -- packages integrations`, not my conclusions. It traced cases with mock transports.
  - I probed `GET /repos/limbowatch/limbowatch/attestations/sha256:…` anonymously, with a classic token, and with an invalid token.
  - After the fixes, live runs on limbowatch/limbo-poc: a normal scan, a cache with one advisory removed, the next run, and a run with an expired `LIMBOWATCH_GITHUB_TOKEN`.
- **Result:**
  - No crash in normal use. Problems found, all fixed:
    1. Any 200 answer that wasn't the expected JSON (a proxy's HTML page, entries with only `bundle_url`) refused a genuine feed. Now only a 404, an empty list, or attestations that were read and don't match are a rejection; anything unreadable is "unknown".
    2. `patient=False` still retried with sleeps: about 63 s unreachable and 122 s on 5xx per file, up to about 7 min with a firewall dropping packets, twice. Now it's one attempt with a 10 s timeout, and after one "unknown" the second file isn't asked.
    3. A read-only cache, or a `feed-verified.txt` that isn't UTF-8, turned a successful check into exit 2. Now the cache is read and written on a best-effort basis.
    4. `publish --previous-feed` crashed on `2026-13-45T10:00:00Z`, `…T24:00:00Z` or Unicode digits, which matched the regex; and a tampered previous feed could lend earlier dates. Now timestamps must parse (`re.ASCII`), and `site.yml` uses the previous feed only if `gh attestation verify` vouches for it.
    5. A damaged record (bad JSON, unsupported compression) ended in a traceback. Now it's a clean error naming the record (exit 2).
  - Suspicions:
    - Token: anonymous 200, classic token 200, **invalid token 401**. A 401, 403 or 404 with a token is now retried without it.
    - A refused copy stayed cached and failed every run until the ETag changed. It's now deleted, and the next run recovered by itself.
    - F-192's "in the runner's cache" holds for the cached feed, but not against someone who can also write `feed-verified.txt`. Anyone who can write the runner's files could change the watcher too.
  - Live after the fixes: normal scan exit 1 with 103 findings and no warning; tampered cache exit 2 with the copy removed; the next run exit 1, verified; expired token exit 1, verified anonymously.
  - Also: in Docker mode the action now passes `LIMBOWATCH_VERIFY_FEED` into the container.
- **Caveats:** the tests use recorded and mocked answers. The live runs were on one network.
- **Implication:** the feed check can no longer refuse a genuine feed for an answer it can't read, slow a scan by minutes, or fail on a cache problem. 405 tests pass.
- **Sources:** the review and runs above; `tests/test_feedtrust.py`.

### F-194
- **Date:** 2026-11-15 · **Status:** confirmed (independent re-review; fixed and tested on Python 3.12, 3.13, 3.14)
- **Question:** Do the fixes in [F-193](#f-193) hold, and is anything left before 0.1.0a15?
- **Method:**
  - The same reviewer re-read commit a2b4bee.
  - CI (`ci.yml`) on a2b4bee: Python 3.12, 3.13, 3.14 on Ubuntu and 3.12 on macOS.
  - Full test suite locally on Python 3.12, 3.13 and 3.14, in separate environments.
  - The `site` run on a2b4bee: its new `gh attestation verify` of the previous feed.
- **Result:**
  - The six fixes hold; no crash or stall found. **Still open: rollback.** Every build's attestation stays valid, so whoever controls limbo.watch could serve an older genuine `all.zip` next to today's watchlist. Both verified on their own, and newer advisories disappeared.
    - **Fixed:** one lookup of `all.zip` must return a statement from the site workflow on `main` that also lists the downloaded `watchlist.json`'s digest. The two must come from the same build, as one statement lists all 18 files (F-191).
    - A mix this run caused itself (a download failed and an older cached copy stood in) is a warning in `auto` and refused in `require`.
    - A pair from one old build still verifies, so a feed whose `generated_at` is over 3 days old is a warning.
  - Also from the re-review:
    - A retry without the token now happens only on 401 or 403. A 404 with a working token is GitHub's final "none", and a rate-limited retry mustn't soften it.
    - `per_page=100`, since a byte-identical `all.zip` can be attested daily.
    - Malformed statements (`predicate: 3`, `subject: 7`) no longer raise.
  - **CI failed on Python 3.14 only:** `datetime.fromisoformat("2026-11-14T24:00:00Z")` is accepted there (the next midnight) and refused on 3.12 and 3.13. Now a previous-feed timestamp counts only if it reads back exactly as written. The full suite (408 tests) passes on 3.12, 3.13 and 3.14.
  - `site` run on a2b4bee: the previous feed verified, "feed: 25782 of 25782 records unchanged", "Attestation created for 18 subjects", "r2: 162 uploaded".
- **Caveats:** a rollback to a pair from a single old build can only be warned about, not refused. Nothing ties a build to today except its date.
- **Implication:** the checks are ready for 0.1.0a15.
- **Sources:** the review, runs and tests above.

### F-195
- **Date:** 2026-11-15 · **Status:** confirmed (independent re-review; fixed and tested on Python 3.12, 3.13, 3.14; live runs)
- **Question:** Does the same-build check in [F-194](#f-194) hold against someone who controls limbo.watch?
- **Method:**
  - The same reviewer re-read commit bc66c02.
  - After the fix: the full test suite on Python 3.12, 3.13 and 3.14.
  - Live scans of limbowatch/limbo-poc: a fresh cache, the cached pair under `require`, a cached `all.zip` with one advisory removed, the next run, and `off`.
- **Result:**
  - **Hole:** F-194's exception (a mixed pair is only a warning when this run fell back to a cached copy) could be triggered at will. limbo.watch answers 503 for one file and serves a forged or old other file, and the mix got in with a warning. A forged watchlist could also mark every repo as freshly checked, which skips the watcher's own checks, and hide the age warning.
  - **Fixed:** the two files are one pair.
    - Downloads stay in memory and go to the cache only after the pair verifies.
    - If either download fails, the cached pair stands in, both files: the last pair that went together. One new file is never used next to an old one.
    - Every mixed pair is refused, in `auto` too.
  - **Lookup by the watchlist's digest, not all.zip's.** With stable `modified` dates, `all.zip` can be byte-identical across builds, each attesting it with a different watchlist; past 100 builds the right statement might not be on the first page. The watchlist carries its build time, so its answer is that one build's statement, which must also list the `all.zip`.
  - The watchlist is parsed after verification. A broken one is removed from the cache, and deeply nested JSON (RecursionError) is a clean error.
  - Tests: 410 pass on 3.12, 3.13 and 3.14. New cases: a forged watchlist after a failed zip download, and a forged zip after a failed watchlist download, both answered from the cached pair; no cached pair means a clean error; the cache is untouched by a refused pair.
  - Live: fresh cache exit 1, 103 findings, no warning. Cached pair under `require` exit 1. Altered cached zip exit 2: "its all.zip and watchlist.json come from different builds". The next run exit 1. `off` exit 1.
- **Caveats:** a pair from one old build verifies; it's only warned about after 3 days (F-194).
- **Implication:** someone who controls limbo.watch can make scans fail (exit 2) or, by serving one old build, warn after 3 days. They can't make a scan quietly use a feed the build didn't make.
- **Sources:** the review, tests and runs above.

### F-196
- **Date:** 2026-11-15 · **Status:** confirmed (independent review; fixed, tested on Python 3.12, 3.13, 3.14; integrations in a container)
- **Question:** Does the pair check of [F-195](#f-195) hold up in normal operation, not only under attack?
- **Method:**
  - The same reviewer's final pass on commit 9bdfee3.
  - The full suite on three Pythons, and `scripts/check_integrations.py` (the GitLab component and Action in a clean container, against the live feed).
- **Result:**
  - Against an attacker controlling limbo.watch, every combination of 200, 304, 5xx and oversize per file was closed.
  - **Genuine feeds were refused around each deploy.** `sync_r2.py` uploaded `watchlist.json` (rank 0) a minute or so before the zips (rank 1), among about 3,100 files, and Cloudflare cached each file on its own for `max-age=300`. For the upload time plus up to about 5 minutes per edge, a scan could get a new watchlist with an old `all.zip` and refuse the pair as "mixed" (exit 2, "may have been tampered with"), every day. Fixed on both sides:
    - **Site:** the pair is uploaded last, `all.zip` then `watchlist.json`, back to back. Both carry `Cache-Control: no-cache`, so the edge checks R2 on each request instead of keeping a copy for minutes. Both are uploaded on every sync, so they always carry it.
    - **Watcher:** a mixed pair is downloaded again, fresh, after 5 s. If it's still mixed, a cached pair verified before is used, with a warning. Otherwise it's refused with "It may be updating: try again in a few minutes", and the cache is kept.
  - A damaged `.etag` file crashed the scan in two ways: a UnicodeDecodeError, and, once that was decoded with replacement, httpx's UnicodeEncodeError on a non-ASCII header. Now an ETag that isn't printable ASCII is ignored, and the file is downloaded again.
  - `--verify-feed require` now also refuses a feed more than 3 days old.
  - 415 tests pass on 3.12, 3.13 and 3.14; integrations passed.
- **Caveats:** two GETs can still straddle the moment between the two uploads; the retry after 5 s covers that.
- **Implication:** a deploy no longer fails scans. A scan uses only a pair from one build, verified, or its own cached pair verified before.
- **Sources:** the review, tests and runs above.

### F-197
- **Date:** 2026-11-15 · **Status:** confirmed (direct observation)
- **Question:** After [F-196](#f-196), what cache headers do clients actually get for the feed pair?
- **Method:** `curl -D -` on `feed/all.zip`, `feed/watchlist.json`, `osv/PyPI/all.zip` and `assets/site.css` after the `site` run on cc72cb1, which uploaded the pair last with `Cache-Control: no-cache` ("r2: 94 uploaded"). Then added `browser_ttl: respect_origin` to the zone's cache rule (`cf_rules.py`) and checked again.
- **Result:**
  - Before the rule change, the edge revalidated the pair (`cf-cache-status: REVALIDATED`, `EXPIRED`), but clients got `cache-control: max-age=14400`: the zone's "Browser Cache TTL: 4 hours" replaced the files' own headers. The site had sent that with nginx too.
  - After it (within about a minute): the pair `cache-control: no-cache`, `assets/site.css` `max-age=300`; `osv/PyPI/all.zip` `max-age=300`, from the Worker. Both pair files `last-modified: 07:33:40 GMT`, the same second.
- **Caveats:** a client or proxy that ignores `no-cache` is out of our hands; the watcher's retry and verified-pair fallback cover it.
- **Implication:** a caching proxy at a customer site can't keep an old `all.zip` for 4 hours next to a new watchlist. The cache rule in the repo now carries this setting.
- **Sources:** the requests above; `deploy/cloudflare/rules.json`.

### F-198
- **Date:** 2026-11-15 · **Status:** confirmed (direct observation)
- **Question:** Release 0.1.0a15: did every artifact ship as tested?
- **Method:** the release checklist after the checks of [F-193](#f-193) to [F-197](#f-197).
  - Commits: version commit 20aec98, image built on main (`sha-20aec98`), pin commit 9f1b969.
  - Before tagging:
    - the audit, twice (all 10 checks passed);
    - the integration check in a container;
    - the upstream end-to-end test;
    - 415 tests on Python 3.12, 3.13 and 3.14, and CI on Ubuntu and macOS;
    - the image's attestation, version and a scan inside it;
    - the component pipeline on its split 9b70950;
    - the action from the pin commit in the private e2e repository (run 43691513484, issues on).
  - Then the signed tag `v0.1.0a15`; the component's signed tag `0.1.0-alpha.15` on gitlab.com; the action split 0cb59c8 with its self-test, signed tag and pre-release; the org profile; the proof repository's run on the published action (limbowatch/limbo-poc run 43692013227).
- **Result:**
  - PyPI serves 0.1.0a15 for both packages, and a fresh install reports `limbowatch 0.1.0a15`. The GitHub pre-release has its 4 files. `ghcr.io/limbowatch/limbowatch:0.1.0a15` resolves to `sha256:637702af…`, the digest pinned in `action.yml` and the GitLab template.
  - The component's pipelines passed on `main` and on the tag (the `limbowatch-ultimate-gate` job fails by design and may fail, as for 0.1.0a14), and its release `0.1.0-alpha.15` exists in the CI/CD Catalog.
  - The action's self-test passed on Linux (image) and macOS (`install: python`).
  - Inside the image, the private e2e run and the proof run, the scan read the live feed (built 07:41 UTC) and verified it without a warning.
  - Proof run: 103 advisories in limbo in all 7 example packages; the other scanners report only the controls.
  - Marketplace still lists v0.1.0a14 as latest until the maintainer ticks v0.1.0a15.
- **Caveats:** the screenshots on the scan page are of 0.1.0a14. The output they show didn't change, apart from the new warnings, which a normal run doesn't print.
- **Implication:** 0.1.0a15 shipped as tested.
- **Sources:** PyPI JSON API; `docker buildx imagetools inspect`; GitLab and GitHub run lists; the runs named above.

### F-199
- **Date:** 2026-11-15 · **Status:** confirmed (direct observation)
- **Question:** Do the demo runs on 0.1.0a15 match the scan page's screenshots and captions?
- **Method:** the demo pull request and merge request after bumping both demos to 0.1.0a15 (GitHub run 43693090565, GitLab pipeline 3070036485, 08:08 UTC, live feed built 07:41 UTC); the run's `report.json`; `gh api /advisories/GHSA-vvf4-9x63-8xvv` and OSV's `/v1/vulns/GHSA-vvf4-9x63-8xvv`.
- **Result:**
  - Both runs: 81 dependencies, 64 advisories in limbo in 4 packages (scapy 54, undici 6, pgx 3, chi 1), 7 high failing the build, exit 1. The feed verified without a warning on both hosts.
  - On 0.1.0a14 (2026-11-13) it was 63 in 5 packages, 8 failing. dnspython's one advisory, GHSA-vvf4-9x63-8xvv (high), left limbo: GitHub reviewed it at 2026-11-13 20:19 UTC and OSV has it since 20:30 UTC. scapy gained 2 low or medium advisories (52 to 54).
  - GitLab shows "Code Quality scans found 54 new findings" and "Test summary: 7 failed, 64 total tests".
- **Caveats:** the demo's numbers move as advisories are reviewed or published; the captions are dated by this entry.
- **Implication:** all ten screenshots and their captions were refreshed (docs/SCREENSHOTS.md). The [F-198](#f-198) caveat about 0.1.0a14 screenshots no longer holds.
- **Sources:** the runs above; GitHub Advisory Database API; OSV API.

### F-200
- **Date:** 2026-11-15 · **Status:** confirmed (direct observation; GitHub's monthly totals count reviews by publish date)
- **Question:** Is GitHub catching up on the review backlog (Q12)? Has its review throughput risen since the June blog post ([F-035](#f-035))?
- **Method:**
  - GitHub's throughput: `gh api --paginate "/advisories?type=reviewed&published=2026-MM-01..2026-MM-DD"` for each month of 2026 (12,553 reviewed advisories, 2026-01-01 to 2026-11-15 08:30 UTC), counted by week and month, split by `repository_advisory_url` (reviewed from a repository advisory). For 10,442 of them, `published_at` and `github_reviewed_at` fall on the same day.
  - Inflow against outflow in the watched repos: the tracker's daily reports on `tracker-data` (2026-11-01 to 11-14), "newly published" against "reviewed by GitHub".
  - GitHub's statements: github/advisory-database#10425 (2026-10-19) and community discussion #189802 (last GitHub post 2026-10-02).
- **Result:**
  - Reviews from repository advisories per month: Jan 362, Feb 595, Mar 1,377, Apr 1,190, May 1,260, Jun 1,152, Jul 1,211, **Aug 660, Sep 873, Oct 1,182**, Nov 1–15 251. Throughput peaked March to July and hasn't risen since; weeks swing between 35 and 433 (batches, as in [F-050](#f-050)).
  - In the watched repos, 2026-11-01 to 11-14: **1,757 advisories newly published into limbo, 203 reviewed out**, about 9 in for each 1 out (F-092 and F-120 found 11 to 1 and 16 to 1). The in-limbo count rose 8,167 → 10,463, part of it from newly watched repos.
  - GitHub (2026-10-19): review times "are currently longer than our documentation states"; the 72-hour estimate is being removed; no replacement estimate. Its October updates are about intake: structured report forms, daily rate limits on private vulnerability reports, and planned AI-assisted triage for maintainers. None says review capacity has grown.
- **Caveats:** the monthly totals include reviews of advisories that didn't come from watched repos; a review whose global `published_at` predates 2026 is not counted. Throughput is weekly batches, so single weeks mislead.
- **Implication:** No sign that GitHub is closing the gap: outflow is about 250 to 300 a week against about 900 a week of new advisories in reviewable ecosystems in the watched repos alone. Q12 stays open for the per-ecosystem view; the answer to "is it shrinking" is no as of this date.
- **Sources:** GitHub Advisory Database REST API; `tracker-data` reports 2026-11-01 to 11-14; https://github.com/github/advisory-database/issues/10425; https://github.com/orgs/community/discussions/189802.

### F-201
- **Date:** 2026-11-15 · **Status:** confirmed (direct observation)
- **Question:** The home page compared "0" scanner findings against "7" for the proof repository, typed in by hand. What does `limbowatch scan` report there today, and can the site compute it daily?
- **Method:**
  - The proof repository's run 43692013227 (2026-11-15 07:54 UTC, action v0.1.0a15): its `evidence` artifact (`limbowatch.json`, `osv-scanner.json`, `npm-audit.json`, `pip-audit.json`, `bundler-audit.json`).
  - `limbowatch.publish.proof.counts`: the live `feed/all.zip` through the watcher's own matching (`watch.match`) for the 7 pins in limbo-poc's `proof/packages.json`, counting certain findings with a fixed version.
- **Result:**
  - The run: 103 findings in 7 packages (critical 6, high 32, medium 36, low 29). One is only "possibly affected": GHSA-724w-jvcm-4c58 names `github.com/nats-io/nats-server` without `/v2`. Certain: **102, of them 37 critical or high** (nats-server 40, scapy 54, go-openapi/spec 4, one each for typebox, go-toml, mustache, rubyntlm).
  - `counts` on the live feed gives the same 102 IDs, 0 different.
  - OSV-Scanner, npm audit and pip-audit report none of the 103. bundler-audit reports one, rubyntlm's GHSA-cx24-f932-rr55, from ruby-advisory-db (the README already says so); the home page doesn't name bundler-audit.
  - The hand-typed 7 counted one advisory per package; it could have gone stale without notice if GitHub reviewed one.
- **Caveats:** the proof repository runs at 06:17 UTC on the previous build's feed; the site is rebuilt after the tracker, so the two can differ by the day's changes. The audit accepts a difference only for advisories that left limbo or changed since.
- **Implication:** the home page now shows the critical and high count from each build's feed (37 today), with the total (102) beside it, and drops the comparison if none is left. `scripts/audit.py` check 11 compares it with the live feed and the proof repository's latest run.
- **Sources:** limbowatch/limbo-poc run 43692013227 and `proof/packages.json`; https://limbo.watch/feed/all.zip.

### F-202
- **Date:** 2026-11-15 · **Status:** confirmed (direct observation)
- **Question:** Can the Worker deploy from GitHub with a token that can't touch anything else?
- **Method:** creating the account token in the Cloudflare dashboard (Account API tokens → Create → Start from scratch); `.github/workflows/worker.yml` runs 43699386428 and 43700413002; `curl -I` on `/osv/SHA256SUMS.txt` and `/osv/PyPI/all.zip`.
- **Result:**
  - A policy's scope can be **Specified Workers**: the token `limbowatch-worker-deploy` has Individual Workers Editor on `limbowatch-site` only (the account's other Workers are out of reach), plus Workers Routes Write and Zone Read on limbo.watch. That was enough for `wrangler deploy` (with an R2 binding) and for setting the route to fail open; no R2 permission was needed.
  - The first run deployed but failed to set the route to fail open: `uv run` at the workspace root installs only the root project, which has no httpx. With `--package limbowatch` the second run set `limbo.watch/osv/*` to fail open and the live check passed.
  - Live after the deploy: `osv/SHA256SUMS.txt` sends `no-cache`; the zips keep `max-age=300` and `X-Goog-Hash`.
- **Caveats:** between the two runs (about 5 minutes) the route failed closed; traffic was far below the daily limit.
- **Implication:** Worker changes deploy from `main` after a maintainer approves the `worker` environment; Cache-Control comes from the object the site sync stores, so cache changes need no Worker deploy.
- **Sources:** the runs above; Cloudflare dashboard token review page.

### F-203
- **Date:** 2026-11-15 · **Status:** confirmed (direct observation; one day, 55 projects)
- **Question:** For the home page: in the dependency files of popular open-source projects, how many advisories in limbo are there today, and can the site count them daily?
- **Method:**
  - 55 popular projects on GitHub, listed in `tracker/showcase/projects.txt` before scanning (5 were also in [F-112](#f-112)).
  - `scripts/showcase.py`: a shallow, blob-less clone of each default branch's lockfiles and manifests (test fixtures, `vendor`, `node_modules` left out), OSV-Scanner 2.7.1's inventory (`limbowatch.inventory.osv_scanner.run`, no Maven resolution).
  - `limbowatch.publish.showcase.counts`: every dependency through `watch.match` against the live feed of 2026-11-15 07:41 UTC; certain findings with a fixed version only; by package name (no source-repo matching).
  - Live re-checks of the three most widely pinned packages' advisories: `GET /repos/{repo}/security-advisories/{ghsa}`, `GET /advisories/{ghsa}`, OSV `GET /v1/vulns/{ghsa}`.
- **Result:**
  - All 55 read: 127,535 distinct dependencies (package and version per project), in 19.6 min on a laptop (CPU-bound parsing; 6 processes).
  - **627 advisories in limbo, 261 critical or high, in 54 of the 55 projects.** Most: PostHog 192, AutoGPT 115, llama_index 100, Grafana 86, Payload 84, cal.com 83, n8n 82. Fewest: Kubernetes 1, browser-use 1, Caddy 4; huggingface/transformers 0.
  - Most widely pinned with a critical or high advisory: brace-expansion (43 of 55 projects; GHSA-6jwq-xf8q-xcwh, high, published 2026-11-11), ws (42; GHSA-37g9-w4hg-h9qr, high, 2026-11-12), vite (38; GHSA-p4f5-76q4-ffq7, critical, 2026-11-10). All three are published by their maintainers, not reviewed, not in OSV.
  - An earlier pass the same day with `limbowatch scan --no-upstream` per project gave the same numbers for Gitea (30), Caddy (4) and open-webui (61), and more for some others (PostHog 204, Kubernetes 3): `scan` also counts possible matches' advisories and reads each lockfile on its own.
- **Caveats:**
  - A pinned version isn't necessarily exploitable; dev, test, docs and example lockfiles count.
  - Name matching only: `limbowatch scan` also matches through source repositories and can find more.
  - The most widely pinned advisories are days old and may be reviewed soon; the counts are a daily snapshot.
- **Implication:** the home page now shows this count (critical and high, with the total), the most widely pinned packages as cards, and `/popular/` with every project, its commit and its advisory IDs. The `showcase` workflow refreshes the inventory daily; the site build recounts it against each feed; audit check 12 verifies it.
- **Sources:** GitHub (clones, REST API); OSV API; https://limbo.watch/feed/all.zip.

### F-204
- **Date:** 2026-11-15 · **Status:** confirmed (measured)
- **Question:** Why did the showcase inventory take 20 minutes locally and over 45 in CI, when OSV-Scanner itself is fast?
- **Method:** `cProfile` of `limbowatch.inventory.osv_scanner.run` on cal.com's dependency files (3,901 dependencies); then the old and new `checks.locate` on every package OSV-Scanner reports for cal.com, Grafana and Gitea (12,646 calls), comparing results and time; `tests/test_locate.py` compares them on every name in the test lockfiles.
- **Result:**
  - cal.com: 57.5 s in all, 0.2 s of it OSV-Scanner. 56.6 s in `checks.locate`, which split the lockfile and ran a regular expression on every line once per dependency: 164 million regex searches.
  - Indexed once per lockfile, with each pattern tried only on lines holding a literal it can't match without: **0 of 12,646 lines differ**; cal.com 44.4 s → 1.6 s, Grafana 23.9 s → 1.0 s, Gitea 2.0 s → 0.1 s.
- **Caveats:** case-insensitive patterns (requirements files) still check every line, and any non-ASCII line, so `re.I`'s Unicode folding can't be skipped.
- **Implication:** `limbowatch scan` on large monorepos, in users' CI too, no longer spends minutes locating lines; the showcase inventory fits easily in its daily run.
- **Sources:** the profile and timings above; `tests/test_locate.py`, `tests/locate_reference.py`.

### F-205
- **Date:** 2026-11-15 · **Status:** confirmed (measured; Cloudflare's pricing page)
- **Question:** On Cloudflare's free tier, what do the site deploys cost in R2 operations, and what drives the count?
- **Method:** the `r2: N uploaded, N deleted, N unchanged` line of every successful `site.yml` run since the move to R2 (2026-11-14 and 15, 15 runs); https://developers.cloudflare.com/r2/pricing/; the size of a local build.
- **Result:**
  - Free each month: 10 GB-month storage, 1 million Class A (PutObject, ListObjects…), 10 million Class B (GetObject, HeadObject); egress and DeleteObject free. Beyond: $4.50 per million Class A, $0.36 per million Class B, $0.015 per GB-month.
  - The site: 52,045 files, about 0.5 GB.
  - Uploads in those 15 runs: about 91,000 Class A, plus about 52 list calls a run. Of them, 51,814 were the first upload; one run uploaded 26,185 (2774cac, a stylesheet change: every page links `site.css?v=<hash>`, so all advisory pages changed); the others 84 to 6,567 (a normal deploy 84 to 1,030).
- **Caveats:** two days; the tracker's daily deploy uploads about 3,100 files (F-178).
- **Implication:** a normal month is about 15% of the free Class A allowance. The risk was stylesheet changes, at 26,000 to 52,000 uploads each; `site.css` and `analytics.js` are now linked without a version, so a stylesheet change uploads one file. Browsers may pair a new page with the old stylesheet for at most the 5-minute cache. The deploy that drops the version uploads every page once more.
- **Sources:** the site.yml run logs; Cloudflare R2 pricing page.

### F-206
- **Date:** 2026-11-15 · **Status:** confirmed (direct observation)
- **Question:** One day after the switch to R2 ([F-184](#f-184)), how close is limbo.watch to any Cloudflare free-tier limit?
- **Method:** Cloudflare dashboard, read 2026-11-15 about 13:00 PST: R2 overview (billing period usage) and bucket `limbowatch-site` metrics, Worker `limbowatch-site` metrics, Workers & Pages usage, zone limbo.watch Analytics → Requests. All "last 24 hours" unless noted.
- **Result:**
  - **R2, billing period 2026-11-14 to 12-14 so far (account-wide):** Class A 120,710 of 1 million (12%), Class B 34,630 of 10 million, storage 611 MB of 10 GB; billable usage **$0.00**. The account holds two other buckets (about 153 MB), so not all of it is this site.
  - **R2, bucket, last 24 hours:** 457.7 MB, 52,260 objects; Class A 64,670 (two deploy spikes of about 27,000 and 21,000, the uploads of every page in [F-205](#f-205)); Class B 19,660; errors 1,370 (404 1,370, 503 1).
  - **Worker** (`/osv/*`): 91 invocations, 0 errors, median CPU 1.29 ms. **Account Workers usage today: 105 of 100,000** requests (three Workers on the account).
  - **Zone:** 32,880 requests (down 47.7% on the day before), 2.9 GB, 5,070 visits, 5xx 0%. Status: 2xx 17,690, **3xx 13,790**, 4xx 1,400. Cache: none 13,640, miss 13,120, expired 3,010, revalidated 2,760, hit 327 (hit rate 9.4%). Top paths: `/tracker/` 263, `/` 242, `/feed/all.zip` 165, `/feed/watchlist.json` 114, `/feed/critical.atom` 97. Countries: US 29,470, Singapore 1,720.
- **Caveats:** one day, and a deploy day with two full uploads. Free-plan analytics may be sampled. Where the 3xx come from (slash, www or HTTP→HTTPS redirects) wasn't examined.
- **Implication:** nothing is near a limit. At about 20,000 Class B a day, a month is about 600,000 (6% of free); cache misses are the long tail of 52,000 pages crawled under a 5-minute cache, which costs reads, not money. The only allowance that can run out is Class A, and only through repeated full uploads (about 52,000 each; about 17 a month on top of the daily 3,100 would pass 1 million). Past a free allowance R2 bills ($4.50 per million Class A) rather than blocking, so the site wouldn't go down; a budget alert on the account would show it. The Worker uses 0.1% of its daily limit and fails open.
- **Sources:** Cloudflare dashboard for the account and zone (not public).

### F-207
- **Date:** 2026-11-15 · **Status:** confirmed (direct observation)
- **Question:** An outside security review said (1) a `../` in a build file's registry name, version or vcpkg baseline could redirect the watcher's registry lookups; (2) a tar header with a false size could make `_conandata` read without bound; (3) org-wide mode sends `LIMBOWATCH_SOURCE_TOKEN` over plain `http://`. Which are true?
- **Method:** httpx 0.28.1: `httpx.URL()` on registry URLs built with `../` segments. Python's `tarfile`: a gzip tar whose `conandata.yml` header says 5 bytes, followed by 2 MB of data; `extractfile(m).read()`. Code reading of `limbowatch.hosts.git_project`, `split_url` and `hosts.git.environment`.
- **Result:**
  - (1) True. httpx removes dot segments before sending: `https://raw.githubusercontent.com/microsoft/vcpkg/../../a/b/main/x` is requested as `https://raw.githubusercontent.com/a/b/main/x`, and `center2.conan.io/v2/conans/z/1.0/../../../q/...` as `center2.conan.io/v2/q/...`. The host never changes, and only api.github.com gets a token. Percent-encoded `%2e%2e` is left as is.
  - (2) False. `extractfile` reads at most the header's size (5 of 2,000,000 bytes). The download itself, though, had no cap.
  - (3) True. `git_project` and `split_url` accepted `http://`, and the clone's `extraHeader` and the API calls carried the token to any such URL.
- **Caveats:** for (1) the scanned project can only misreport its own dependencies; it could already name any repository directly (`git_override`, `FetchContent`).
- **Implication:** registry names, versions and Maven coordinates must be single plain path segments, and the vcpkg baseline a full commit hash; registry downloads stop at 5 MB. Tokens go over `http://` only to loopback addresses or with `--allow-insecure-http`. A host API's clone URL is used only on the listed host and scheme.
- **Sources:** the probes above; `tests/test_upstream.py::test_registry_edges`, `tests/test_org.py`, `tests/test_cli.py::test_tokens_are_refused_over_plain_http`.

### F-208
- **Date:** 2026-11-16 · **Status:** confirmed (direct observation)
- **Question:** Why did the release audit's `popular` check fail right after a push, when the site and showcase runs had both succeeded?
- **Method:** `scripts/audit.py` at 2026-11-16 06:26 UTC; the `site` run log for 62c4027 (`showcase: run …`); `gh run download` of showcase runs 43709071028 and 43814254356, diffed per project; `scanned_at` in the live `/popular/data.json`.
- **Result:** a push starts `site` and `showcase` together. `site` took the newest showcase run finished at 06:04:17, 43709071028 (`scanned_at` 2026-11-15T11:28:29Z, as the live data.json says); the push's own run, 43814254356, finished later. The audit recounted from the newest successful run, so it compared the site with an artifact it was never built from: 665 advisories shown, 659 recounted. The two artifacts differ in 9 projects, each with a new commit, and every project read the same number of files in both.
- **Caveats:** none; the difference was upstream projects changing their dependencies overnight.
- **Implication:** the audit now picks the showcase run whose `scanned_at` equals the live data.json's (of the last 10 successful runs) and notes newer runs the site hasn't shown yet. With it, all 12 checks passed at 06:40 UTC.
- **Sources:** the runs above; `scripts/audit.py` check 12.

### F-209
- **Date:** 2026-11-16 · **Status:** confirmed (direct observation)
- **Question:** Do the CVE List's deltaLog `githubLink` URLs always point into CVEProject/cvelistV5, so the tracker can refuse any other link?
- **Method:** `GET https://raw.githubusercontent.com/CVEProject/cvelistV5/main/cves/deltaLog.json` at 2026-11-16 07:40 UTC; every `new` and `updated` item's `githubLink`.
- **Result:** 3,149 entries (fetch times 2026-10-17T06:30Z to 2026-11-16T06:11Z), 101,021 links; **all** start with `https://raw.githubusercontent.com/CVEProject/cvelistV5/`, as `…/main/cves/<year>/<n>xxx/<CVE-ID>.json`.
- **Caveats:** one month of the log; CVEProject could change the form.
- **Implication:** `sources.cve.record` fetches only links under that prefix and treats any other as unreadable (logged), like a failed download. If CVEProject changes the form, CVE updates stop being read and the log says why, rather than the tracker fetching from wherever the log points.
- **Sources:** the deltaLog above.

### F-210
- **Date:** 2026-11-16 · **Status:** confirmed (direct observation)
- **Question:** Before fcf9f9b, a repository listing whose later page failed was stored as complete: advisories past page 1 got `gone_since` and page 1's ETag was kept (so they'd stay marked). Did that ever happen in the live tracker?
- **Method:** `git archive origin/tracker-data state` (commit 15eda5a, the run of 2026-11-15T14:03Z); `repos.jsonl` and `advisories.jsonl`, read locally.
- **Result:** 67,591 repos, 43,494 advisories. 45 repos list 100 or more advisories (more than one page; bottlerocket-os/bottlerocket 517, discourse/discourse 340, freerdp/freerdp 338, …); **none has an advisory with `gone_since`**. Only 1 advisory in the whole state has `gone_since`, in graphql-hive/gateway, a one-page repo. Poll statuses: 200 57,152, 304 8,757, 404 1,681, 451 1.
- **Caveats:** a cut-off listing repaired by a later full read (page 1 changed) leaves no trace; this shows the state is clean now, not that it never happened.
- **Implication:** nothing in the live state needs repairing. From fcf9f9b on, a partly read listing leaves the repo as it was (and the scan reports it as not read).
- **Sources:** the tracker-data state above.

### F-211
- **Date:** 2026-11-16 · **Status:** confirmed (direct observation)
- **Question:** Which known vulnerabilities do Limbowatch's own dependencies and its published image have, and can they be upgraded away?
- **Method:** OSV-Scanner 2.7.1 `scan source --lockfile` on uv.lock, deploy/worker/package-lock.json, integrations/action/requirements.txt and deploy/cloudflare/requirements.txt; `limbowatch scan` (ec718b5) on the same files; `osv-scanner scan image ghcr.io/limbowatch/limbowatch:0.1.0a15`; `apt-cache policy zlib1g` in the pinned python:3.14-slim; OSV-Scanner's go.mod at v2.7.1 and on main. Dependabot alerts are disabled for the repository (API 403), so they were not a source.
- **Result:**
  - **OSV-Scanner on the lockfiles:** no issues in any of the four (48, 165, 30 and 7 packages).
  - **Limbowatch on the same files:** 7 advisories in limbo, all in the Worker's test tooling (`@cloudflare/vitest-plugin` → miniflare 5.20261113.0-beta, which pins them exactly, in its newest release too): undici 7.30.1 (6, one high, fixed in 7.30.2) and ws 8.21.0 (GHSA-37g9-w4hg-h9qr, high, no CVE, fixed in 8.23.0). Not in the deployed Worker (no runtime dependencies). Fixed with npm `overrides`; the Worker's 22 tests pass.
  - **The 0.1.0a15 image:** 194 advisory–package pairs. With a fix available: Debian zlib 1:1.3.dfsg+really1.3.1-1+b1 (3 CVEs, up to 8.3; `+deb13u1` is in trixie-security, not yet in the newest python:3.14-slim, whose digest the Dockerfile already pins), and in the OSV-Scanner binary go.opentelemetry.io/otel/trace 1.45.0 (GHSA-q7gw-24fr-5p69, 5.3) and golang.org/x/crypto 0.58.0 (GO-2026-5932), both indirect, both already bumped on OSV-Scanner's main (1.47.0, 0.59.0). The rest are Debian packages with no fix.
  - **Rebuilt with `apt-get upgrade`:** 191 pairs; the 3 zlib ones gone, none new.
  - **Python:** nothing vulnerable; 5 newer versions (semver 3.1.2 at runtime; coverage, grimp, pytest-asyncio, ruff for development).
- **Caveats:** reachability of the two Go advisories in OSV-Scanner wasn't checked (govulncheck wasn't run). Image results are for linux/arm64 locally and the published multi-arch image as pulled on an arm64 host.
- **Implication:** the image installs Debian's security updates at build time; the Worker's test tooling is pinned past the advisories; the Go ones leave with OSV-Scanner's next release (bump the pinned 2.7.1 then). Limbowatch found the undici and ws advisories that OSV-Scanner, run on the same lockfile, didn't.
- **Sources:** the scans and registry metadata above.

### F-212
- **Date:** 2026-11-16 · **Status:** confirmed (direct observation)
- **Question:** Release 0.1.0a16: did every artifact ship as tested?
- **Method:** the release checklist after the checks and reviews of [F-207](#f-207) to [F-211](#f-211).
  - Commits: version commit fa7cf60, image built on main (`sha-fa7cf60`), pin commit 49d5f6a.
  - Before tagging:
    - the audit, at 08:43 UTC (all 12 checks passed), and earlier the same day on each fix;
    - the integration check in a container; the Gitea, GitLab, GitHub and upstream end-to-end tests;
    - 451 tests on Python 3.12, 3.13 and 3.14, and CI;
    - a tracker run on a copy of the live state (306 repos polled, 26,116 OSV, 90 CVE and 3 NVD requests);
    - the image's attestation (SLSA provenance from image.yml on main), version and zlib;
    - the component pipeline on its split 4a7516d;
    - the action from the pin commit in the private e2e repository (run 43835024059, issues on).
  - Then the signed tag `v0.1.0a16`; the component's signed tag `0.1.0-alpha.16` on gitlab.com; the action split fd1a8e3 with its self-test, signed tag and pre-release; the org profile; the proof repository's run on the published action (limbowatch/limbo-poc run 43836234449); the e2e repository on the published action (run 43836259175).
- **Result:**
  - PyPI serves 0.1.0a16 for both packages, and a fresh install reports `limbowatch 0.1.0a16`. The GitHub pre-release has its 4 files. `ghcr.io/limbowatch/limbowatch:0.1.0a16` resolves to `sha256:034d8c3f…`, the digest pinned in `action.yml` and the GitLab template; inside it zlib is `1:1.3.dfsg+really1.3.1-1+deb13u1`.
  - The component's pipelines passed on `main` and on the tag (`limbowatch-ultimate-gate` fails by design and may fail, as before), and its release `0.1.0-alpha.16` exists. Its description said "(verify with )": the pipeline's description goes through a shell, which ran the backticked `gh attestation verify …` (with `<digest>` as a redirection) and substituted nothing; 0.1.0-alpha.15 has the same. Fixed by hand for alpha.16 through the API, and in `.gitlab-ci.yml` for the next release.
  - The action's self-test passed on Linux (image) and macOS (`install: python`). The Marketplace listed v0.1.0a11 to v0.1.0a15 (latest a15) before the release; a16 sorts after a15 as text, so ticking it makes it latest with nothing to untick.
  - The e2e and proof runs on the published action read the live feed without a warning. Proof run: 103 findings in all 7 example packages; the other scanners report only the controls (bundler-audit reports rubyntlm from the Ruby advisory database, as the day before; it is in neither GitHub's reviewed database nor OSV).
- **Caveats:** the Marketplace tick is the owner's; `LIMBOWATCH_ALLOW_INSECURE_HTTP` passing into the action's container was not exercised by a run (the same `-e` pass-through as `LIMBOWATCH_VERIFY_FEED`, tested in 0.1.0a15).
- **Implication:** 0.1.0a16 shipped as tested.
- **Sources:** the runs above; PyPI; ghcr.io; gitlab.com/limbowatch/limbowatch-component.

### F-213
- **Date:** 2026-11-16 · **Status:** confirmed (live checks)
- **Question:** Eight days after [F-112](#f-112), and four after [F-157](#f-157)/[F-162](#f-162), are those advisories still in limbo? (Re-check before naming them in a public post.)
- **Method:**
  - **F-112's set:** the 277 distinct advisories behind its 1,080 confirmed findings (`research/2026-11-dependabot-compare/data/2026-11-08/ranges.json`, verdict `confirmed`). For each: `GET /advisories/{ghsa}` (404 means not in GitHub's reviewed database), `GET api.osv.dev/v1/vulns/{ghsa}`; for those still absent from both, `GET /repos/{repo}/security-advisories/{ghsa}` (state, `withdrawn_at`).
  - **The proof repository's examples:** the same three checks for typebox GHSA-976x-prgx-qv35, nats-server GHSA-38x3-76xf-cq45 and GHSA-qrcv-3558-gj4f, go-openapi/spec GHSA-gqhc-vf4h-h7hg, go-toml GHSA-frc4-6h9q-39fq, mustache GHSA-5hrj-7fc3-cmx9, rubyntlm GHSA-cx24-f932-rr55, scapy GHSA-c547-xwrv-q9jm.
- **Result:**
  - **F-112's 277:** 78 reviewed since (200 from GitHub and OSV, both); 199 absent from both. Of those, 198 still published upstream with no `withdrawn_at`; graphql-hive/gateway's GHSA-xrjv-fc7j-8f77 now returns 404 from its repository, so it's left out. **198 still in limbo**: 10 critical, 71 high, 90 medium, 27 low (severity as of 2026-11-08); npm 86, PyPI 41, RubyGems 34, Go 33, crates.io 4.
  - By project, advisories confirmed on 2026-11-08 → still in limbo: GitLab 110 → 55, n8n 58 → 49, Open WebUI 53 → 49, LangChain 48 → 33, Forgejo 23 → 23, Gitea 22 → 22, GoToSocial 22 → 22, Arti 18 → 9, Gitaly 11 → 9, GitLab Runner 9 → 9, Mobilizon 9 → 9, Kubernetes 3 → 3, Fractal 1 → 1. These are the projects' 2026-11-08 dependency files; they may have upgraded since.
  - **The 8 example advisories:** all still published, 404 in GitHub's reviewed database, 404 in OSV. Days in limbo on 2026-11-16: nats-server 140, go-toml 132, go-openapi/spec 118, mustache 88, typebox 87, scapy 69, rubyntlm 68.
  - **The proof repository** (`limbowatch/limbo-poc`): run 43836234449 (2026-11-16 09:02 UTC, action v0.1.0a16) shows the same day counts; Limbowatch reports all 7, OSV-Scanner none, `npm audit`/pip-audit none, bundler-audit only rubyntlm. Its Dependabot alerts read with a maintainer token today (`GET /repos/limbowatch/limbo-poc/dependabot/alerts?state=open`): still 95, all on the controls (jackson-databind 50, rack 34, lodash 4, golang.org/x/net 4, requests 3), 0 for the 7, unchanged from the README's 2026-11-12 snapshot. A signed-out visitor can open the run page; logs need sign-in.
- **Caveats:** one day's check; the projects' current HEADs weren't rescanned. Severity is the maintainer's.
- **Implication:** about 70% of the advisories F-112 found on popular projects are still unreviewed 8 days later; the public examples still hold. Used for the second LinkedIn post (dated 2026-11-16).
- **Sources:** GitHub REST API (global and repository security advisories); OSV API; raw output in the session scratchpad.

### F-214
- **Date:** 2026-11-16 · **Status:** confirmed (live runs, 4 projects)
- **Question:** Without the limbo feed (`limbowatch scan --feed none`: every dependency's source repo read on GitHub during the scan), what does a scan find, miss and cost, compared with the feed? (A company can't fetch limbo.watch, by network or policy.)
- **Method:** shallow clones of `limbowatch/limbo-poc` (8f1ed9f), `open-webui/open-webui` (b0e6098), `go-gitea/gitea` (8b48b45) and `mastodon/mastodon` (43126b2). Each scanned twice back to back, `--feed limbo.watch` then `--feed none`, each mode with its own empty cache, a GitHub token, OSV-Scanner 2.7.1, `--fail-on none -o json`. Requests counted per host by wrapping `httpx.AsyncClient.send` in-process. Findings compared on (package, version, advisory, certain/possible), then field by field per finding key.
- **Result:**

  | Project | Deps | Repos | Feed: s / GitHub req | No feed: s / GitHub / OSV / CVE Services req | Findings feed / no feed |
  |---|---:|---:|---|---|---|
  | limbo-poc | 14 | 13 | 4.9 / 1 | 20.8 / 13 / 203 / 20 | 103 / 103 |
  | Open WebUI | 1,993 | 1,165 | 28.9 / 600 | 50.6 / 1,165 / 1,048 / 22 | 70 / 70 |
  | Gitea | 1,152 | 801 | 22.3 / 494 | 34.3 / 801 / 392 / 13 | 21 / 21 |
  | Mastodon | 1,731 | 1,025 | 25.6 / 482 | 46.2 / 1,026 / 658 / 13 | 16 / 17 |

  - **No finding was lost.** Every finding with the feed was found without it, with the same severity, range, fixed version and verdict.
  - **One extra, possible finding without the feed:** nokogiri 1.19.7, GHSA-qwq9-89rg-ww72 (high, "JRuby only"). Its CVE-2022-34169 is reviewed under GHSA-9339-86wc-4qgf (Xalan-J), so the tracker counts it as a duplicate and the feed leaves it out (live: `GET /advisories?cve_id=CVE-2022-34169`); the scan's own poll can't see duplicates.
  - **CVE labels:** 3 of the shared findings (2 in limbo-poc, 1 in Open WebUI) lose "CVE published by another CNA, not cited" (CVE-2026-128237, -128238, -114062) and read "no CVE anywhere": uncited CVEs come from the CVE List, which only the tracker reads.
  - **Unchecked dependencies:** the same ones (1, 56, 44 and 14 with no known source repo; 2 local packages); without the feed their reason is "not checked" instead of "checked by name only".
  - **Cost:** 1.4 to 4 times as long (12 to 22 s more on the large projects); GitHub requests rise from 482–600 to 801–1,165, one per source repo; plus one OSV lookup per published advisory of those repos (392–1,048), to tell reviewed from not. With the feed, about half the repos were polled anyway (not on the watchlist, or checked more than 10 days ago).
  - limbo.watch got 2 requests per feed run and 0 without; with the feed, api.github.com got one attestation lookup on the first run.
- **Caveats:** one run per mode, back to back on 2026-11-16, so the tracker's state and GitHub's could differ by minutes. One transient HTTP error (Mastodon, no feed) was retried; no repo went unread. GitHub's 5,000 requests an hour per token bound a no-feed org-wide run to a few thousand repos per hour (each repo is polled once for all projects, F-130).
- **Status of the feature:** `--feed none` / `LIMBOWATCH_FEED=none` (Unreleased).
- **Implication:** without the feed, a scan finds the same advisories in limbo at roughly twice the time and one GitHub request per source repo. It loses CVE List facts (uncited CVEs, duplicates) and name-only checks of dependencies whose repo isn't known, and reports those as not checked. Good enough for teams that can't use limbo.watch; a self-built feed (next) gives them everything back.
- **Sources:** GitHub REST API (repository advisories, global advisories by CVE); OSV API; CVE Services; raw output in the session scratchpad.

### F-215
- **Date:** 2026-11-17 · **Status:** confirmed (local runs of the pipelines' scripts in the image; live GitHub)
- **Question:** Can a team build the limbo feed itself (`limbowatch track` + `publish --feed-only`, the `deploy/own-feed/` pipelines) and scan against it (`--feed <URL or directory>`) without losing findings? What does a first run cost?
- **Method:**
  - **Fresh tracker, minimal:** `limbowatch track` on an empty state with 100 repos from `popular-upstreams.txt`, `--budget 1500 --no-releases --no-nvd`, no CVE List; then `publish --feed-only`; requests counted per host (as F-214).
  - **Scans:** limbo-poc, Mastodon and Gitea (F-214's clones) with `--feed <that feed's directory>`, each compared with F-214's limbo-feed run by (package, version, advisory, verdict). The first try ran with an exhausted GitHub token and was redone after the reset.
  - **Pipelines:** each one's shell extracted from its YAML and run in an image built from the working tree (`docker build`; 0.1.0a16 has no `--feed-only`):
    - **GitLab:** the `pages` script, `BUDGET` 600, `MAX_NEW` 50, its artifacts API answered by a local server: a 404, then the first run's `public/` and `state/` as a zip;
    - **GitHub:** the "Track and publish" step, with the October CVE List copy (`cve_2026-10-25`) standing in for the download.
  - Finally a scan of limbo-poc against the feed the GitLab script built.
- **Result:**
  - **Fresh tracker, minimal:** 6.5 min; 562 GitHub requests (37,881 reviewed advisories synced, about 380 of them), 2,172 to raw.githubusercontent.com (two days of the CVE delta log), 328 OSV, 91 CVE Services. Watchlist 3,773 (100 seeds plus the reviewed advisories' origin repos), 183 polled before the budget, 681 advisories stored, 326 in the feed.
  - **Scans against it:** nothing the limbo feed found was missed (limbo-poc 103 = 103, Gitea 21 = 21, Mastodon 16 of 16). Mastodon had 3 more:
    - nokogiri GHSA-qwq9-89rg-ww72, the duplicate of F-214; this tracker had no CVE List, so it can't tell either;
    - puma 8.0.3, GHSA-4v6q-hvv7-49h9 and GHSA-rhww-p99c-hgj9 (medium; fixed in 8.0.4). Published 2026-11-17 00:38 UTC, after F-214's runs: real advisories in limbo, found by the scan's own poll of puma/puma (404 in GitHub's reviewed database and OSV, not on limbo.watch yet).
    - The feed watched few of the projects' repos (14 and 15 of 1,025 and 801), so the scans polled the rest: 13, 1,011 and 786 GitHub requests; 17, 46 and 36 s.
  - **With the token exhausted** (first try): 1,091 of Gitea's dependencies were reported as "source repository not checked (GitHub rate limit)" and the scan passed with 0 findings. The gate doesn't count unchecked dependencies, as before.
  - **GitLab script, first run:** found no earlier state (404) and started a new one. It took the CVE List bulk export (`2026-11-17_all_CVEs_at_midnight`, 663 MB), imported 30,685 CVE records that name an advisory, synced 37,881 reviewed advisories, watched 67,350 repos and polled 50, then published 35 advisories with `feed/` (all.zip, watchlist.json, index.json, SHA256SUMS.txt, repos.txt) and `osv/`. Tracking took 17.5 min, mostly the release checks: 7,387 requests to repo1.maven.org, 429 to api.github.com.
  - **GitLab script, second run:** restored the first run's 12 state files from the artifacts and skipped the CVE List. 40 s: 41 newly reviewed advisories, 50 more repos polled, 57 advisories published.
  - **GitHub step:** imported 28,248 CVE records, watched 67,256 repos, polled 50 and published 38 advisories; the state files belong to the runner's user, not root.
  - **The scan against the GitLab-built feed:** limbo-poc 103 findings, as with the limbo feed; the report names that feed.
  - **cvelistV5's `releases/latest` was an end-of-day release with only a delta file** (`cve_2026-11-16_at_end_of_day`, published 2026-11-17 00:39 UTC), so the first version of both pipelines found no bulk export. They now take the newest of the last 10 releases that has `*_all_CVEs_at_midnight.zip.zip`. This repository's tracker.yml takes it from the latest release too, but only on its first run, long past.
- **Caveats:** the real Pages deployments, GitHub's attestation step, the state branch push and GitLab's job token weren't exercised (local runs). Small budgets: a full watchlist takes about 27 daily runs at `MAX_NEW` 2,500.
- **Implication:** a self-built feed works with the same code and the same sources. Scans stay complete while its watchlist is young, because they poll what it doesn't cover, at the cost of GitHub requests, which fall as it grows. Shipped as `publish --feed-only`, `--feed <URL or directory>`, `deploy/own-feed/` and docs/OWN_FEED.md (Unreleased).
- **Sources:** GitHub REST API (repository and global advisories, releases); OSV API; CVE Services; CVE List (cvelistV5 releases); raw output in the session scratchpad.

### F-216
- **Date:** 2026-11-17 · **Status:** confirmed (live runs, 3 projects; the pipelines' scripts locally in the image)
- **Question:** A feed focused on one's own dependencies (`limbowatch repos` → `track --only-seeds`): does it lose findings against the limbo feed, and what does it save per scan?
- **Method:**
  - **Seeds:** `limbowatch repos` on F-214's clones of limbo-poc, Mastodon and Gitea.
  - **Feed:** `limbowatch track --only-seeds` on an empty state with those seeds, `--budget 3000 --max-new 2000`, the CVE List bulk export of 2026-10-25 (`--cve-list`, a local copy), `--maven-packages tracker/seeds/maven-packages.txt`; then `publish --feed-only`. Requests counted per host (as F-214).
  - **Scans:** the three projects with `--feed <that feed's directory>`, compared with F-214's limbo-feed runs by (package, version, advisory, verdict), then field by field.
  - **Pipeline:** the GitHub pipeline's focused steps, extracted from its YAML, run in an image built from the working tree with the limbowatch org as the "company" (`ORGS=limbowatch`); the branch step pushed to a local bare repository instead of github.com.
- **Result:**
  - **`limbowatch repos`:** 1,511 GitHub repositories from 2,538 package versions in 13.5 s, no GitHub request; 58 package versions have none (listed in the file).
  - **Focused tracker, first run:** all 1,511 polled; 20.5 min; 1,890 GitHub requests (37,881 reviewed advisories synced), 2,220 to raw.githubusercontent.com, 214 OSV, 24 CVE Services. It stored 1,026 advisories and published 211 in limbo. 7,387 of the 20.5 minutes' requests went to Maven Central for the releases of all 7,387 listed Maven packages; only 16 of them are watched repos' packages. Fixed: with `--only-seeds`, only the watched repos' Maven packages are polled (`Tracker.maven_watched`).
  - **Scans against it:**

    | Project | Findings limbo feed / focused | GitHub requests limbo feed / focused | Seconds limbo feed / focused |
    |---|---|---|---|
    | limbo-poc | 103 / 103 | 1 / 0 | 4.9 / 1.6 |
    | Mastodon | 16 / 18 | 482 / 4 | 25.6 / 7.5 |
    | Gitea | 21 / 21 | 494 / 0 | 22.3 / 5.3 |

    - Nothing the limbo feed found was missed. Mastodon's 2 more are puma's GHSA-4v6q-hvv7-49h9 and GHSA-rhww-p99c-hgj9, published after F-214's runs (F-215).
    - nokogiri's GHSA-qwq9-89rg-ww72, F-214's and F-215's extra, isn't reported: this tracker imported the CVE List, so it knows the duplicate.
    - Mastodon's 4 polls: jaredwray/file-entry-cache, jaredwray/flat-cache, moove-it/sidekiq-scheduler and substack/node-concat-map, where deps.dev or rubygems.org point; all four answer 404 on GitHub (`GET /repos/{repo}`: gone, or moved without a redirect). The feed's watchlist leaves 404 repos out, so each scan polls them again.
  - **CVE labels:** 2 limbo-poc findings read "no CVE anywhere" instead of "CVE published by another CNA, not cited" (CVE-2026-128237 and -128238, VulnCheck, published 2026-11-13). The bulk export was from 2026-10-25, and a new tracker reads only 2 days of the CVE delta log, so CVEs from the 19 days between were missed. The pipelines download the newest bulk export, so they have no such gap. `track --cve-list` now warns when the export is older than that window.
  - **The GitHub pipeline, focused** (limbowatch org as the company, the 2026-10-25 CVE List copy):
    - the focused step listed the org's 5 projects and wrote 210 repositories in 7 s;
    - the track step watched and polled exactly those 210 and published 163 advisories, in 11 min (mostly the CVE List import and 2,220 CVE delta requests). GitHub took 589 requests. Maven Central was polled for the 9 watched packages, not 7,387;
    - the branch step, run twice, left `limbo-feed` with one commit holding `feed/all.zip`, `watchlist.json`, `index.json` and `SHA256SUMS.txt`; `shasum -a 256 -c` passed on a clone;
    - a scan of limbo-poc against that clone: 103 findings, as with the limbo feed; 0 GitHub requests, 1.7 s.
- **Caveats:** one run per feed; three projects of one person's choosing; the focused feed was built minutes before the scans, so every repo was fresh (a day later, some due repos would be polled).
- **Implication:** for a team's own scans, a focused feed loses nothing against the limbo feed. It cuts GitHub requests per scan from hundreds to almost none and scan time by 3 to 4 times, and it builds in one run instead of weeks. Shipped as `limbowatch repos`, `track --only-seeds` and the pipelines' `focused` option (Unreleased).
- **Sources:** GitHub REST API; OSV API; CVE Services; CVE List (cvelistV5); deps.dev, rubygems.org; raw output in the session scratchpad.

### F-217
- **Date:** 2026-11-17 · **Status:** confirmed (direct observation)
- **Question:** Release 0.1.0a17 (`--feed none`, your own feed, focused feeds: [F-214](#f-214) to [F-216](#f-216)): did the checks find anything, and did every artifact ship as tested?
- **Method:** the release checklist.
  - Before the version commit:
    - the audit at 05:11 UTC, then again at 05:14 after a fix to the audit itself (below): all 13 checks passed, 520 verdicts sampled live, 0 wrong, 5 changed after the run;
    - the Gitea, GitHub and GitLab issue end-to-end tests, the upstream end-to-end test and the integration check in a container;
    - an independent review (a fresh agent given the diff since v0.1.0a16, read-only), in three rounds, each on the newest commit, until a round found nothing;
    - 470 tests on Python 3.12, 3.13 and 3.14, and CI.
  - Commits: version commit 6fec7a1, image built on main (`sha-6fec7a1`), pin commit 16f7bec. Before tagging: the component pipeline on its split 278cb38, and the action from the pin commit in the private e2e repository (run 44025700558, issues on).
  - Then the signed tag `v0.1.0a17`; the component's signed tag `0.1.0-alpha.17`; the action split 78890b1 with its self-test, signed tag and pre-release; the org profile; the proof repository on the published action (run 44026480410); the e2e repository on the published action (run 44026510615).
- **Result:**
  - **The audit's popular check failed on a false alarm:** 3 of the home page's 278 high or critical advisories were reviewed at 18:45 and 22:11 UTC, after the 16:00 tracker run the site was built from. The verdict check already sets such changes aside ([F-169](#f-169)); the popular check now does too (fcef5d9).
  - **Round 1 of the review found four problems in the unreleased code, all fixed before the release (3698fe6):**
    - with `--feed none`, state kept a finding unless its repo was polled that run, so a removed dependency's finding, or one from a repo GitHub had renamed, was never reported as no longer affected;
    - issues opened from your own feed credited the limbo feed;
    - the "checked by name only" reasons named the limbo feed whatever the feed;
    - the docs called a focused feed complete, although it can hardly ever match a dependency with no GitHub repository by name. A minor point was fixed too: `limbowatch repos` didn't list the projects it skipped.
  - **Round 2** found that the new state rule compared package names as written, not normalized as finding keys are (`PyYAML` vs `pyyaml`); fixed in f021a82. **Round 3** found nothing.
  - **Release:**
    - PyPI serves 0.1.0a17, and a fresh install reports `limbowatch 0.1.0a17`. The GitHub pre-release has its 4 files.
    - `ghcr.io/limbowatch/limbowatch:0.1.0a17` resolves to `sha256:1c99aecc…`, the digest pinned in `action.yml`, the GitLab template and both own-feed pipelines.
    - The component's pipelines passed on `main` and on the tag. Its release description now shows the verify command (the d5b6c9f fix).
    - The action's self-test passed.
  - **Runs on the published action:**
    - The e2e run used the pinned image and reopened, then left, its issue.
    - The proof run found 103 findings in all 7 example packages, with no feed warning; the other scanners report only the controls (bundler-audit reports rubyntlm, as before).
  - **Marketplace:** before the release it listed v0.1.0a11 to v0.1.0a16 (latest a16). a17 sorts after a16 as text.
- **Caveats:** the own-feed pipelines haven't run in real CI yet (Pages, attestation, the job tokens); their steps were run locally in the image ([F-215](#f-215), [F-216](#f-216)). The Marketplace tick is the owner's.
- **Implication:** 0.1.0a17 shipped as tested. An independent review loop caught real defects again: three rounds, five fixes.
- **Sources:** the runs above; PyPI; ghcr.io; gitlab.com/limbowatch/limbowatch-component.

### F-218
- **Date:** 2026-11-17 · **Status:** confirmed (direct observation)
- **Question:** Do the own-feed GitHub pipeline (0.1.0a17, [F-215](#f-215), [F-216](#f-216)) and the documented scan snippet work in real GitHub Actions, in a public and a private repository?
- **Method:** two scratch repositories in the limbowatch organization (Free plan), each with `deploy/own-feed/github/limbo-feed.yml` as released, `LIMBO_FEED_WATCH=focused` (the organization's public repositories; job token only, no secrets):
  - `limbowatch/own-feed-test`, public, `pages` (Pages source: GitHub Actions). Runs 44032637746 (first) and 44035152170 (second).
  - `limbowatch/own-feed-test-private`, private, `branch`. Runs 44032642520 (first) and 44035146760 (second, with the fix below). A `scan` workflow there checks out `limbo-feed` and runs `limbowatch/limbowatch-action@v0.1.0a17` with `LIMBOWATCH_FEED: limbo-feed/feed` on limbo-poc's `go/go.mod` (run 44035378424), as docs/OWN_FEED.md shows.
  - Locally: the Pages feed downloaded, `shasum -c`, `gh attestation verify all.zip --repo limbowatch/own-feed-test`, and scans of limbo-poc against the Pages URL and against limbo.watch.
- **Result:**
  - **Public, Pages:** the first run took 18.5 minutes: the CVE List bulk export (2026-11-17), `repos` over the organization, track and publish, state saved, attestation, Pages deploy. The feed had 163 advisories in limbo and a 210-repository watchlist. The second run took about 1 minute: state restored, 0 repositories polled (all fresh), the same 163.
    - All 3 checksums match. The attestation verifies: one, by `.github/workflows/limbo-feed.yml` on `refs/heads/main`.
    - limbo-poc against the Pages URL found 103 findings, the same 103 as against limbo.watch, with 0 repositories polled in either.
  - **Private, branch: the first run failed at the attest step.** "Failed to persist attestation: Feature not available for the limbowatch organization. To enable this feature, please upgrade the billing plan, or make this repository public." The state had already been saved, but the feed was never published.
    - GitHub's attestation docs name no plan. They say private repositories use GitHub's own Sigstore instance.
    - Fix: the attest step is `continue-on-error` in private repositories only.
    - The second run then logged the same error, carried on, and published the branch: one commit holding `feed/all.zip` (154 KB), `watchlist.json`, `index.json` and `SHA256SUMS.txt`, still one commit after two runs.
  - **Scan from the checked-out branch:** 46 findings, 0 repositories polled, 163 feed advisories. The report credits "a feed built with Limbowatch (…/limbo-feed/feed)". A local scan of the same `go.mod` against limbo.watch also gives 46.
- **Caveats:**
  - Only the Free plan was observed; whether Team includes private-repository attestations wasn't checked.
  - Private repositories' Pages weren't tried, since that depends on the plan.
  - The GitLab pipeline wasn't run in GitLab CI: it needs a GitHub token as a CI/CD variable.
- **Implication:** the GitHub pipeline works as documented in public repositories. As released in 0.1.0a17, it failed in private repositories on plans without attestations, and that is fixed on main. The branch option and the scan snippet work as documented.
- **Sources:** the runs above; GitHub REST API; docs.github.com/en/actions/concepts/security/artifact-attestations.

### F-219
- **Date:** 2026-11-17 · **Status:** confirmed (direct observation)
- **Question:** Release 0.1.0a18 (the own-feed pipeline fix of [F-218](#f-218)): did it ship as tested, and does the released pipeline publish from a private repository?
- **Method:** the release checklist.
  - Before tagging:
    - the audit at 07:13 UTC: all 13 checks passed;
    - 470 tests on Python 3.12, 3.13 and 3.14, and CI.
    - No scanner code changed since 0.1.0a17, so there was no review loop and no issue end-to-end tests.
  - Commits: version commit 7f20a31, image `sha-7f20a31`, pin commit 190ed45.
  - The component pipeline on its split 36555a2, and the action from the pin commit in the private e2e repository (run 44038538487).
  - Then the signed tags `v0.1.0a18` and `0.1.0-alpha.18`; the action split 9ebdf40 with its self-test, signed tag and pre-release; the org profile; the proof run (44039094410); the e2e run on the published action (44039124414).
  - The released `limbo-feed.yml` in both scratch repositories of F-218: runs 44039105209 (public, Pages) and 44039115739 (private, branch). Their daily schedules were turned off again afterwards.
- **Result:**
  - PyPI serves 0.1.0a18, and the GitHub pre-release has its 4 files. `ghcr.io/limbowatch/limbowatch:0.1.0a18` resolves to `sha256:036a7dc5…`, the pinned digest. The component release `0.1.0-alpha.18` exists, and the action's self-test passed.
  - The e2e run used the pinned image and reopened its issue (closed afterwards). The proof run found 103 findings.
  - The public scratch repository built and deployed. The private one logged the same attestation refusal, carried on, and replaced the `limbo-feed` branch with one commit ("limbo feed 2026-11-17T07:30:37Z", 163 advisories). With `continue-on-error`, the step shows as succeeded, and the error stays in the log as an annotation.
  - Marketplace: latest was v0.1.0a17 before the owner's tick for a18.
- **Caveats:** the Marketplace tick is the owner's.
- **Implication:** 0.1.0a18 shipped as tested, and its GitHub pipeline publishes from a private repository on the Free plan.
- **Sources:** the runs above; PyPI; ghcr.io; gitlab.com/limbowatch/limbowatch-component.

### F-220
- **Date:** 2026-11-17 · **Status:** confirmed (direct observation)
- **Question:** Does the own-feed GitLab pipeline (0.1.0a18) work in real GitLab CI, keep its state between runs, and serve a feed scans can use?
- **Method:** a public scratch project `gitlab.com/limbowatch/own-feed-test` (group `limbowatch`, GitLab Free).
  - Set-up: the released `.gitlab-ci.yml`, `WATCH=focused` (the group's projects), and a masked, protected `LIMBOWATCH_GITHUB_TOKEN` (fine-grained, public repositories read-only, entered by the owner). A scan job uses component `0.1.0-alpha.18` with `LIMBOWATCH_FEED: public/feed`.
  - Runs started from the UI ("web"): pipelines 3077738100 and 3077812642 (as released), then 3077874490, 3077915353 and 3077924031 (with the fix below).
  - Probes in API-started pipelines, from inside a job, printing only status codes:
    - `GET /projects/:id/jobs/artifacts/main/download?job=pages` with the job token as header and as parameter, and with none;
    - generic package upload, download, list and delete with the job token.
  - The CVE List's `deltaLog.json`, read once (3,230 entries).
- **Result:**
  - **State was never restored.** The second released run logged "no earlier state: starting a new one", downloaded the CVE List again, and took 9.3 min.
    - The probe got 404 with the job token (header and parameter) and 200 (2.4 MB) with no token, only because the project is public. A private project would get 404 every run.
    - GitLab's docs mark the endpoint's `job_token` parameter "Premium and Ultimate only", while listing job artifacts downloads as allowed for job tokens.
    - The endpoint also picks the newest successful pipeline by creation time. Once a probe pipeline without a `pages` job had succeeded, even an owner's token got 404.
  - **The package registry works with the job token on Free:** upload 201 (twice), download 200 returning the newest upload, list 200, delete 204. The pipeline now keeps its state there (`limbo-feed-state/1/state.tar.gz`, about 2.1 MB for this focused feed).
    - The first fixed run started new and saved its state. The second restored 12 files, skipped the CVE List, and took 76 s instead of 594 s. The third left exactly two copies.
  - **Pages:** the project got a unique domain, `https://own-feed-test-538628.gitlab.io`. The `https://limbowatch.gitlab.io/own-feed-test/` the docs gave, and the unique domain itself, both redirected to sign-in, because the group's projects have Pages visibility `private`. After setting it to "everyone", the feed downloaded, checksums matched (49 advisories), and a local scan of the sample against the URL gave 46 findings with 0 repositories polled.
  - **The scan job** read `public/feed` from the `pages` job and found 46 findings, 0 polled, crediting "a feed built with Limbowatch".
  - **First-run time:** 17 of the first run's 18 min went to 2,265 single CVE record downloads from raw.githubusercontent.com: the last two days of the delta, although the bulk export was from that midnight. The delta log spans 2026-10-18 to 2026-11-17 (about 30 days). Changes since the export's midnight less an hour came to 164 records.
  - **Run report:** with `--only-seeds`, `releases.*.added` showed 216 (npm) and others, while the watchlist stayed at 4. It counted repositories before `add_repos` skipped them.
- **Caveats:**
  - The fixed pipeline ran with the 0.1.0a18 image; the faster first run needs the next release's image to be seen in CI.
  - Only GitLab Free (gitlab.com) was observed.
  - The registry fix was tested in a public project. The job token's registry access doesn't depend on visibility, but a private project wasn't run.
- **Implication:**
  - As released up to 0.1.0a18, the GitLab pipeline rebuilt from nothing every run. In a private project a popular feed would never fill. Fixed on main (Unreleased).
  - A new tracker reads CVE changes from the bulk export's date.
  - The own-feed docs now name the Pages URL and visibility.
- **Sources:** the pipelines and probes above; docs.gitlab.com/api/job_artifacts/ and /ci/jobs/ci_job_token/; CVEProject/cvelistV5 `cves/deltaLog.json`.

### F-221
- **Date:** 2026-11-17 · **Status:** confirmed (direct observation)
- **Question:** Release 0.1.0a19: what did its review find, did it ship as tested, and do the released own-feed pipelines keep their state and start faster ([F-220](#f-220))?
- **Method:**
  - **Before tagging:** the audit at about 08:55 UTC (all checks passed); 472 tests on Python 3.12, 3.13 and 3.14; an independent review of `v0.1.0a18..HEAD` in two rounds; the scratch GitLab project on the fixed pipeline file (pipeline 3077983584).
  - **Release:** commits 4bf954f (version) and f05de47 (pin, image `sha256:d94e96ab…`). The pre-tag e2e run 44054054610 and the component pipeline on split 7ec8c3e, then the signed tags, the action split 2528908 with its self-test, and the pre-release.
  - **After tagging:** the proof run 44054712032, the e2e run 44054750737, the GitHub scratch repositories (runs 44054724892 and 44054739717), and two first runs from nothing with the released image: GitLab pipeline 3078064076 (released file), then 3078138589 (file fixed below), and GitHub `own-feed-test` run 44057603734, after deleting its `limbo-feed-state` branch.
- **Result:**
  - **Review round 1 found a stall.** Reading the CVE delta from a bulk export days old can take longer than a run, and `sync_cve_delta` moved its cursor only at the end. A run that hit its deadline kept nothing and skipped polling; the next run stopped at the same place (reproduced with a scripted deadline). Fixed in f9421bc: the delta is read in batches of whole deltaLog entries (200 CVEs), with the cursor saved after each.
  - **Also fixed in f9421bc:** urllib forwards custom headers on redirects, so the GitLab restore could have sent the job token to object storage. A redirect to another host now drops it, checked for 301, 302, 303, 307 and 308. Round 2 found nothing.
  - **Release:**
    - PyPI serves 0.1.0a19 (its JSON API showed 0.1.0a18 for a few minutes after the release). The GitHub pre-release has 4 files, and `ghcr.io/limbowatch/limbowatch:0.1.0a19` resolves to the pinned digest.
    - The component release `0.1.0-alpha.19` exists. Marketplace's latest is v0.1.0a19 after the owner's tick.
    - The proof run found 103 findings; the e2e run passed.
  - **First runs from nothing:**
    - GitHub (`focused`, 210 repositories): 183 CVE records read instead of 2,220 ([F-218](#f-218)); 11.0 min instead of 18.5.
    - GitLab with the released file: 2,284 records, 17 min. It saved the export as `/tmp/cvelist.zip.zip`, and the tracker reads the export's date from the file name, so it fell back to two days.
    - GitLab with the export's own name: 183 records, 8.7 min, state saved. The fix (Unreleased) keeps the asset name, checked against `[\w.-]+_all_CVEs_at_midnight\.zip\.zip`.
  - **State between GitLab runs** (scratch pipeline 3077983584, before the release): restored from the package registry, 2 copies kept.
- **Caveats:** one first run per pipeline. The remaining first-run time wasn't broken down.
- **Implication:**
  - 0.1.0a19 shipped as tested, and its GitHub pipeline gets the shorter first run.
  - Its GitLab pipeline keeps its state between runs but still has the long first run until the file is copied from main (Unreleased).
- **Sources:** the runs above; PyPI; ghcr.io; gitlab.com/limbowatch/limbowatch-component and limbowatch/own-feed-test.

### F-222
- **Date:** 2026-11-17 · **Status:** confirmed (direct observation)
- **Question:** Release 0.1.0a20 (the GitLab first-run fix of [F-221](#f-221)): did it ship as tested?
- **Method:**
  - **Before tagging:** the audit (all checks passed) and 472 tests on Python 3.12, 3.13 and 3.14. Only the GitLab pipeline file, a test and docs had changed since 0.1.0a19, so no review loop ran.
  - **Release:** commits f1f8a2e (version) and 3be61bc (pin, image `sha256:705d1567…`). The pre-tag e2e run 44062587407 and the component pipeline on split 7f6aa18, then the signed tags, the action split f941c24 with its self-test, and the pre-release.
  - **After tagging:** the proof run 44063272790, the e2e run 44063309668, both GitHub scratch repositories (44063285431, 44063298875), and GitLab scratch pipeline 3078305060, all on the released files.
- **Result:**
  - The GitHub pre-release has 4 files; the image and the component release `0.1.0-alpha.20` exist.
  - The proof run found 103 findings. The e2e run and all scratch runs passed, and the GitLab one restored its saved state (12 files).
- **Caveats:** the Marketplace tick for v0.1.0a20 is the owner's.
- **Implication:** 0.1.0a20 shipped as tested.
- **Sources:** the runs above; ghcr.io; gitlab.com/limbowatch/limbowatch-component.

### F-223
- **Date:** 2026-11-17 · **Status:** confirmed (direct observation)
- **Question:** Do the CLI-only own-feed pipelines (no Limbowatch image) work in real CI, from nothing and from saved state?
- **Method:** the files as committed in 73fd8a9, with Limbowatch 0.1.0a20 from PyPI and OSV-Scanner 2.7.1.
  - **GitHub:** `deploy/own-feed/github/limbo-feed-cli.yml`, in the private scratch repository `limbowatch/own-feed-test-private` (job token only, `LIMBO_FEED_ORGS` unset, so the `limbowatch` organization), after deleting its `limbo-feed-state` branch. Runs 44068646298 (from nothing) and 44071123384.
  - **GitLab:** `deploy/own-feed/gitlab/.gitlab-ci.cli.yml` plus the scratch scan job, in `limbowatch/own-feed-test`, after deleting its saved state. Pipelines 3078455459 (from nothing) and 3078526109.
- **Result:**
  - **Install:** both checked OSV-Scanner against its release's sums (`osv-scanner_linux_amd64: OK`) and reported `limbowatch 0.1.0a20`. GitHub used the runner's `pipx`, `git`, `gh`, `curl` and `jq`, with no actions; GitLab used `python:3.12`.
  - **GitHub first run (15.7 min):** `repos` listed 210 repositories from 6 projects (9 dependencies or upstream sources with no GitHub repository, 18 not readable, all listed). It imported 30,685 CVE records from the dated bulk export, read 194 changed records, polled 210 repositories, and published 163 advisories to a one-commit `limbo-feed` branch.
  - **GitHub second run (53 s):** the state restored from `limbo-feed-state`; 1 CVE record, 0 repositories due, the same 163 advisories, and the branch still one commit.
  - **GitLab first run (13.9 min):** no saved state; 4 repositories from 2 projects; 194 CVE records; 49 advisories; state saved. The scan job read `public/feed`.
  - **GitLab second run (102 s):** the state restored with curl, 1 CVE record, 0 repositories due, 49 advisories, 2 copies kept.
  - The CLI-only first runs took longer than the image ones (GitLab 13.9 against 8.7 min, F-221). The time wasn't broken down; installing and downloading the CVE List outside the image are the likely difference.
- **Caveats:**
  - One run of each. The GitLab state download returned 200 directly, so the redirect path (followed without the token) wasn't exercised.
  - The CLI's dependencies come from pip's resolution at install time, not pinned by hash.
- **Implication:** both CLI-only pipelines work as documented in docs/OWN_FEED.md#cli-only.
- **Sources:** the runs above.

### F-224
- **Date:** 2026-11-17 · **Status:** confirmed (direct observation)
- **Question:** Release 0.1.0a21 (the CLI-only own-feed pipelines, [F-223](#f-223), and the reorganised website): did it ship as tested?
- **Method:**
  - **Before tagging:** the audit (all checks passed) and 474 tests on Python 3.12, 3.13 and 3.14. No scanner or tracker code had changed since 0.1.0a20, so no review loop ran.
  - **Release:** commits 9ecf68f (version) and c19588c (pin, image `sha256:375e87f1…`). The pre-tag e2e run 44126920172 and the component pipeline on split 69e6e91, then the signed tags, the action split 26695bc with its self-test, and the pre-release.
  - **After tagging:** the proof run 44127850294, the e2e run 44127903801, the public scratch repository's image pipeline (44127869745), the private one's CLI-only pipeline (44127889954), and the GitLab scratch project's CLI-only pipeline (3080041816), all on the released files.
- **Result:**
  - PyPI serves 0.1.0a21. The GitHub pre-release has 4 files; the image and the component release `0.1.0-alpha.21` exist.
  - The proof run found 103 findings, and the e2e run passed.
  - The CLI-only pipelines installed `limbowatch 0.1.0a21` from PyPI and restored their state. GitHub read 553 CVE records changed since its last run 5.5 hours earlier, polled 0 repositories, and published 163 advisories; GitLab published 49, and its scan job passed.
  - The scratch schedules were turned off again afterwards.
- **Caveats:** the Marketplace tick for v0.1.0a21 is the owner's.
- **Implication:** 0.1.0a21 shipped as tested.
- **Sources:** the runs above; PyPI; ghcr.io; gitlab.com/limbowatch/limbowatch-component.

### F-225
- **Date:** 2026-11-18 · **Status:** confirmed (direct observation; one project, as [F-166](#f-166))
- **Question:** Does `--audit-log` record every host a scan contacts, so a company can see every URL called without a logging proxy? And what does the record show that the host table didn't?
- **Method:**
  - **Code read:** the run's ways to the network. HTTP goes through `limbowatch.http` only. git's network calls are `clone`/`fetch` in `watch.gitgraph`, `clone` in `hosts.git` and `ls-remote` in `sources.gitrefs`; the others (`ls-files`, `rev-parse`, `merge-base`, …) are local. The only OSV-Scanner run that goes online is the `pom.xml` resolution.
  - **Hooks, not a transport:** httpx 0.28.1's `AsyncClient.__init__` sets `allow_env_proxies = trust_env and transport is None`, so a wrapping transport would have dropped `HTTPS_PROXY`; event hooks don't.
  - **Live run:** the logging CONNECT proxy method of F-166, an empty cache, OSV-Scanner 2.7.1, `limbowatch scan --format json --audit-log …` from the working tree. Project: the npm, Go, Cargo and Python fixtures, the Maven/Gradle fixture tree (3 `pom.xml`), and a `CMakeLists.txt` fetching madler/zlib v1.3.1. Two runs: default, and `--no-upstream --no-resolve-maven`.
- **Result:**
  - **Default run:** 25 HTTP requests recorded: api.deps.dev 13, repo1.maven.org 6, api.github.com 4, limbo.watch 2. Also one OSV-Scanner resolution run (exit 127, fixture pom.xml with an unresolvable sibling), recorded with its three hosts.
  - **What the proxy saw:** tunnels to api.deps.dev (14), repo1.maven.org (4), api.github.com (3), limbo.watch (1) and repo.maven.apache.org (1). Every one is in the record: repo.maven.apache.org and the 14th deps.dev tunnel through the OSV-Scanner entry, the rest by URL. There are fewer tunnels than requests because connections are reused.
  - **Feed only:** 3 requests (limbo.watch 2: the feed and the watchlist; api.github.com 1: the attestation). The proxy saw exactly those two hosts, as in F-166.
  - **The record showed what a proxy can't:** full URLs, and which requests carried a credential. `authorization` went to api.github.com only: the CLI falls back to `gh auth token`, which on macOS answers from the keychain even with an empty `GH_CONFIG_DIR`, so this "no token" run had one. `cookie` went to repo1.maven.org on 2 of 6 requests. Maven Central's Cloudflare sets `__cf_bm` (Domain=maven.org, 30 minutes), and httpx's client-wide cookie jar sends it back for the rest of the run. Nothing is written to disk.
  - **Failures are recorded too.** With the proxy down, each of the 6 attempts to fetch the feed was recorded as a `ConnectError`.
- **Caveats:** one project and one run each. OSV-Scanner's own URLs aren't visible to Limbowatch: the record names only the hosts its resolver can contact. Timings are from the probe machine.
- **Implication:** `--audit-log` and `--show-network` (all network-using commands; `LIMBOWATCH_AUDIT_LOG`, `LIMBOWATCH_SHOW_NETWORK`) give a per-run record a company can keep, and the host table in WATCHER.md "Security and data" holds. Open: the client keeps cookies a server sets. That's harmless for a public registry, but a scanner doesn't need it, and turning it off would make "what it sends" exactly the URL.
- **Sources:** httpx 0.28.1 `_client.py`; probe output in the session scratchpad (`probe/audit-*.jsonl`, `probe/proxy-*.log`); `curl -sI https://repo1.maven.org/maven2/javax/inject/javax.inject/1/javax.inject-1.pom` (the `set-cookie` header).

### F-226
- **Date:** 2026-11-18 · **Status:** confirmed (git's source, and direct observation)
- **Question:** Can the scan be made to send anything over plain http, or follow a URL somewhere unexpected? Can https-only be enforced, git included? What happens to the open cookie point of [F-225](#f-225)?
- **Method:**
  - **Code read:** every URL constant (all `https://`), and every URL that comes from a response or a build file:
    - pagination: `hosts.next_link` and `sources.github._on_api`;
    - API clone URLs: `hosts.clone_url`;
    - CVE record links: `sources.cve.record`;
    - registry repository URLs: `watch.mapping`;
    - upstream clones: `watch.upstream_check`, `CLONE_URL.format(repo=…)`.
  - **git's redirect handling:** read in git's `http.c` at e1ec09b (`gh api repos/git/git/contents/http.c`).
  - **Live checks with the new settings:**
    - git 2.54.0: `ls-remote`, clone and fetch of github.com/madler/zlib, and `ls-remote` of a renamed repository's old URL (github.com/blueandhack/Limbowatch, which redirects).
    - The F-225 scan again, behind the logging proxy, with an empty cache.
- **Result:**
  - **URLs were already checked** before use: same host and scheme for next-page and clone URLs, the CVE List repository for record links, and only owner/name from a registry's repository URL. Build files only supply names. A URL in a `CMakeLists.txt` or `.gitmodules` is never fetched, and upstreams not on GitHub are reported as unchecked.
  - **Gaps before this entry:**
    - httpx followed redirects to any scheme.
    - git followed redirects under its defaults.
    - Plain http to a source the user named was allowed without a token, so its answers could be changed on the way.
  - **git:** `get_curl_allowed_protocols()` builds both `CURLOPT_PROTOCOLS(_STR)` and `CURLOPT_REDIR_PROTOCOLS(_STR)` from `protocol.allow` / `protocol.<name>.allow`. So `-c protocol.allow=never -c protocol.https.allow=always` also limits redirects to https.
    - Locally, with those options, `ls-remote` refused `file://`, `ext::`, `git://` and `ssh://` ("transport … not allowed"), and the `ext::` command didn't run.
    - Against GitHub: `ls-remote` gave zlib's 79 tags, clone (1.9 s) and fetch (0.3 s) worked, and the renamed repository's redirect was followed (https to https).
  - **The scan:** 25 requests, all https. `authorization` went to api.github.com only, and no request carried a `cookie` (2 of 6 to repo1.maven.org did in F-225). The proxy saw the same tunnels as in F-225, and the scan reported the same 22 findings.
- **Caveats:** the https-to-http redirect refusal was tested against mocked responses (respx) for HTTP; for git it rests on git's source, since a local https server wasn't set up. The check is on the scheme. An https redirect to another host is still followed: httpx then drops the `Authorization` header, and the record shows each hop.
- **Implication:**
  - **https only, enforced where requests are made.** HTTP: an event hook raises `InsecureRequest` before sending, which isn't retried. git: the transports above, in `ls-remote`, the upstream clone and fetch, and project clones. The only exceptions are localhost, and the hosts the user names with `http://` and `--allow-insecure-http`. That flag is now needed even without a token: a breaking change for `http://` sources.
  - **No cookies.** The HTTP client's cookie jar refuses every cookie, which closes F-225's open point.
  - **Request bodies are in `--audit-log`**, so the record shows everything a request sends besides standard headers.
  - **Doc gap fixed:** `--issues` sends OSV the package name and installed versions, when deciding whether to close an issue whose advisory reached OSV. That row was missing from WATCHER.md's host table.
- **Sources:** git `http.c` (e1ec09b); `tests/test_audit.py`, `tests/test_sources_http.py`; probe output in the session scratchpad (`probe/audit-v2.jsonl`, `probe/proxy-v2.log`).

### F-227
- **Date:** 2026-11-19 · **Status:** confirmed (direct observation)
- **Question:** Release 0.1.0a22 (https only, the network record, the action's image isolated, the sealed scan): did it ship as tested?
- **Method:**
  - **Before tagging:**
    - The audit passed all 13 checks: 520 verdicts sampled live, 0 wrong; 0.1.0a1 and 0.1.0a21 both read all 26,769 feed records.
    - 488 tests passed on Python 3.12, 3.13 and 3.14.
    - The upstream e2e (FreeRDP, ImageMagick, vcpkg), the issue e2e on GitHub, GitLab and Gitea, and `check_integrations.py` all passed.
    - The action ran from main in limbowatch-e2e (run 44498706837).
  - **Independent review:** four rounds by a reviewer given only the diff, until a round found nothing.
    - Round 1 found two holes in the action's isolation. With `reports: .`, every file the image left was copied back, so it could replace `.git/config` or a tracked `package.json`. And the outputs run's `::stop-commands::` line went to /dev/null, leaving workflow commands live while it ran.
    - Rounds 2 and 3 found the first fixes incomplete. `git ls-files` exiting 128 counted as "not tracked"; `reports: tests` could add `conftest.py`; a symlinked reports directory was followed; and a nobody-owned subdirectory in the sealed `out/` defeated `find -delete`. Fixed in 73f707f, dbdf041 and 0e9944a.
    - Round 4 found nothing to fix.
    - Deferred: in a `tree:0` partial clone, git may fetch a missing object on its own, outside `--audit-log`. Unverified.
  - **Release:** 7a2078f (version), 1e36bde (pin). The image is sha-7a2078f (`sha256:593a8b2a…`); the later fix commits changed no image input, so image.yml built none. The action ran at the pin commit (run 44501596148). The component split is 32cedb6 and its pipeline 3088417203. Signed tags `v0.1.0a22` and `0.1.0-alpha.22`; the action split is 0dd8110, its self-test 44502067052.
  - **After tagging:**
    - The published action in limbowatch-e2e (run 44502416213) and the proof run (44502340227).
    - In the scratch repositories: the released own-feed pipeline (public 44502679523, private 44502685462), the CLI-only pipeline (44507005609), and the sealed scan (44502691305).
    - On GitLab: the CLI-only pipeline 3088458164, started from the web UI.
- **Result:**
  - PyPI serves 0.1.0a22. The GitHub pre-release has 4 files. `ghcr.io/limbowatch/limbowatch:0.1.0a22` and the component's mirror both have the pinned digest.
  - The proof run found 103 findings, the same as with 0.1.0a21.
  - Own-feed pipelines published 162 advisories on GitHub, both kinds, and 49 on GitLab. GitLab's scan of the feed found 46 findings and passed.
  - The released sealed scan read 1,822 dependencies and found 52 findings at high or above, ending at the gate as expected.
  - The private repository's attestation step failed as expected (F-218). The scratch schedules were turned off again.
- **Caveats:**
  - The Marketplace tick for v0.1.0a22 is the owner's.
  - GitLab's CLI-only run took about 25 minutes, against 8.7 in F-221. It caught up a day of CVE changes; the run log doesn't break the time down.
- **Implication:** 0.1.0a22 shipped as tested. An independent review of security changes needs more than one round: each fix opened a narrower hole.
- **Sources:** the runs above; PyPI; ghcr.io; gitlab.com/limbowatch/limbowatch-component.

### F-228
- **Date:** 2026-11-20 · **Status:** confirmed (official docs and direct observation)
- **Question:** Can limbo.watch serve its own 404 page in the $0 setup (Free plan, R2 custom domain, Worker only on `/osv/*`)?
- **Method:**
  - Live: `curl -i https://limbo.watch/nope.html`, `/nope`, `/nope/`, `/osv/nope.zip`.
  - Cloudflare docs, read 2026-11-20: Custom Errors overview (modified 2026-11-03), create-rules, edit-error-pages, and the parameters reference.
- **Result:**
  - Today a missing file returns 404 with R2's generic Cloudflare "Not Found" page (Cloudflare favicon, no site styling), and the zone's security headers. `/nope` returns a 301 to `/nope/`, which returns 404. A missing file under `/osv/` gets the Worker's plain nginx-style 404.
  - **R2 public buckets have no error-document setting.** A rewrite rule can't help, because it can't know whether an object exists.
  - **Custom Errors are paid-only.** The availability table gives Free 0 rules and 0 assets, with no Error Pages. Pro gets 25 rules and 25 assets. The docs say "Custom Errors are available to all paid plans." They apply to 400+ responses from the origin and from Workers. The status is kept unless overridden, and Response Header Transform Rules still apply. Assets are fetched from a URL, inlined, and limited to 1.5 MB. The phase is `http_custom_errors` and the action is `serve_error`.
  - On Free, the only way is the Worker: run it on page paths, and when the bucket answers 404, return the site's own `404.html` with status 404. Workers Free allows 100,000 requests a day. The busiest recent day was 63,000 requests, all paths, mostly crawlers ([F-175](#f-175)). The routes fail open ([F-183](#f-183)), so past the limit visitors get R2's page again, and nothing breaks.
- **Caveats:** The docs don't mention R2. Whether Custom Error Rules catch an R2 custom domain's 404 is inferred, not tested; no paid zone was tried.
- **Implication:** A custom 404 costs either the Pro plan ($20/month billed annually, [F-171](#f-171)) or more Worker traffic within the free tier. Leaving `/feed/*` off the Worker keeps watchers' traffic off the Worker and the feed path unchanged.
- **Sources:** https://developers.cloudflare.com/rules/custom-errors/ ; …/custom-errors/create-rules/ ; …/custom-errors/edit-error-pages/ ; …/custom-errors/reference/parameters/ ; live responses from limbo.watch.

### F-229
- **Date:** 2026-11-24 · **Status:** confirmed (direct observation)
- **Question:** Before quoting them in public posts: are the proof's seven advisories, and the skills-service advisory from "Why this exists", still in limbo? What are the live counts?
- **Method:**
  - For each of the 7 GHSA IDs in limbowatch/limbo-poc and GHSA-hqfg-c8wf-w2g8: `gh api advisories/{ghsa}` and `GET https://api.osv.dev/v1/vulns/{ghsa}`; for reviewed ones, `github_reviewed_at` and the repository advisory's `published_at`.
  - `https://limbo.watch/metrics.json` (`flow_7d`, generated 2026-11-23 18:49 UTC) and the home page text.
- **Result:**
  - **mustache's GHSA-5hrj-7fc3-cmx9 (critical) left limbo:** reviewed 2026-11-18 16:28 UTC (CVE-2026-130001), 90 days after the maintainers published it (2026-08-20); OSV has it from 16:45 UTC the same day. The other 6 still return 404 from both.
  - **GHSA-hqfg-c8wf-w2g8** (skills-service, critical, CVE-2026-54694, published 2026-06-16): 404 in GitHub's reviewed database and in OSV, 161 days after publication.
  - Live, 2026-11-23: 11,860 advisories in limbo, 93% naming a fixed version; 310 critical or high in limbo in the 55 popular projects' dependency files. In the 7 days to 2026-11-23 18:49 UTC, 1,092 advisories were published in watched repos in ecosystems GitHub reviews and 146 were reviewed (147 left limbo): about 7 in for each 1 out.
- **Caveats:**
  - One day's check. The flow counts are floors (watched repos only, F-098).
  - GHSA-hqfg-c8wf-w2g8 isn't *in limbo* by the site's definition: it covers a release .jar and a Docker image, not a package in an ecosystem GitHub reviews, so it's likely permanent, not waiting for review ([F-066](#f-066), limbo.watch/why/). Public posts must not call it "waiting for review"; its CVE stayed reserved for 85 days.
- **Implication:** "7 vs 0" in README.md and the limbo-poc README (table "checked 2026-11-12") is now stale: today it's 6 still in limbo, and mustache shows the end of the lifecycle (reported by every tool once reviewed). Public posts should say 6 of 7, or use the 90-day review as the example. Re-check every number on the day it's posted.
- **Sources:** GitHub REST API (global and repository advisories); OSV API; https://limbo.watch/metrics.json.

### F-230
- **Date:** 2026-11-24 · **Status:** confirmed (official docs) for points 1–3; tentative for point 4 (docs silent, not yet observed)
- **Question:** Can a workflow fix a Dependabot uv.lock bump (regenerate integrations/action/requirements.txt), push it to the Dependabot branch, and get CI to test the new head commit?
- **Method:** Read GitHub's docs on GITHUB_TOKEN-triggered events and on Dependabot-triggered workflows. Checked the repo's settings: `gh api repos/limbowatch/limbowatch/rulesets/27254827` and `.../actions/permissions/workflow`. Context: PR #5 (python group bump) failed `test_action_python_install_is_pinned_with_uv_lock_hashes` because Dependabot updates uv.lock but not the action's hashed requirements.txt.
- **Result:**
  1. Events caused by GITHUB_TOKEN create no new workflow runs, except `workflow_dispatch` and `repository_dispatch` ("always create workflow runs"), and pull_request `opened`/`synchronize`/`reopened`, which create runs in an approval-required state. A push to the PR branch with GITHUB_TOKEN therefore doesn't run `ci` without a click; dispatching `ci` does.
  2. Workflows triggered by Dependabot get a read-only GITHUB_TOKEN and are treated like fork PRs; the `permissions` key can raise it. Only Dependabot secrets are available, not Actions secrets.
  3. This repo: the `protect main` ruleset has only `non_fast_forward` and `deletion` rules (no required status checks); default workflow token permission is `read`.
  4. The docs don't say whether a `workflow_dispatch` run's check runs show on the PR for that branch's head commit.
- **Caveats:** Point 4 is unobserved until the first Dependabot uv bump after .github/workflows/dependabot-action-requirements.yml lands. hatchling's build dependencies aren't in uv.lock, so each regeneration also takes their newest versions from PyPI (tomlkit 0.15.2 → 0.15.3 on 2026-11-24).
- **Implication:** .github/workflows/dependabot-action-requirements.yml regenerates the file on Dependabot PRs that touch uv.lock, pushes with GITHUB_TOKEN (contents: write), then `gh workflow run ci.yml --ref <branch>` (actions: write); ci.yml gained `workflow_dispatch`. The job is gated on the PR author being `dependabot[bot]` and the head repo being this one (zizmor `bot-conditions`: `github.actor` is spoofable). If point 4 turns out false, switch the push to a GitHub App token stored as a Dependabot secret.
- **Sources:** https://docs.github.com/en/actions/how-tos/write-workflows/choose-when-workflows-run/trigger-a-workflow ; https://docs.github.com/en/actions/concepts/security/github_token ; https://docs.github.com/en/code-security/dependabot/troubleshooting-dependabot/troubleshooting-dependabot-on-github-actions ; https://docs.github.com/en/code-security/dependabot/working-with-dependabot/automating-dependabot-with-github-actions

### F-231
- **Date:** 2026-11-24 · **Status:** confirmed (direct observation) for the OSV listing; tentative for the time split (estimated, not measured per step)
- **Question:** The daily `tracker` run takes 19–28 minutes, and its Track step takes almost all of that. Where does the time go, and what can be cut without lowering coverage?
- **Method:**
  - `gh run view --log` for tracker run 45238040225 (2026-11-23) and site runs 45364740750 and 45242560706; per-step times from `gh run view --json jobs`.
  - `state/runs.jsonl` on `tracker-data` (52 runs): seconds against requests per host, by least squares (42 complete runs, R² 0.84).
  - Latency from a laptop, 6–10 requests each: `GET api.osv.dev/v1/vulns/<missing GHSA>`, conditional `GET repo1.maven.org/.../maven-metadata.xml`, conditional `GET api.github.com/repos/expressjs/express/security-advisories`.
  - `Store.export_jsonl` (the checkpoint) timed on the 2026-11-23 state.
  - `https://osv-vulnerabilities.storage.googleapis.com/modified_id.csv` (`curl -I`, full download). Its GHSA IDs compared with the latest `in_osv` fact of every tracked advisory, then with `GET api.osv.dev/v1/vulns/{id}` for 408 IDs: the 6 disagreements, the 2 recorded present, 300 random absent and 100 random listed ones (seed 20261124).
- **Result:**
  - **Run 2026-11-23:** Track 1,490 s of the job's 1,535 s. Requests: api.osv.dev 28,465, repo1.maven.org 7,387, api.github.com 5,677 (5,298 of them 304), cveawg.mitre.org 2,174, raw.githubusercontent.com 1,312; 2,013 repos listed by `git ls-remote`.
  - **Latency:** OSV 404 0.26–0.28 s; Maven 304 0.09–0.12 s; GitHub 304 0.49–0.73 s. At the client's per-host limits (OSV 16, Maven 4, GitHub 8 polls), that puts OSV presence at about 8 min (28,465 × 0.27 s / 16), GitHub polling about 6.5 min and Maven about 3 min. Eight GitHub workers at about 0.55 s each make about 870 requests a minute, just under GitHub's secondary limit of 900 points a minute, so more polling workers would likely be throttled.
  - **Checkpoint:** a full export takes 2.5 s on a laptop. It runs about 16 times a run (every 500 polls and after each step) and blocks the event loop each time.
  - **OSV listing:** 166,290,443 bytes, 2,913,572 lines `<modified>,<Ecosystem>/<ID>`, `Cache-Control: public, max-age=3600`. Last-Modified 10:03:56 UTC with its newest line at 10:01:48: refreshed within minutes. **38,049 distinct GHSA IDs** (npm 8,185, Maven 7,266, PyPI 6,949, Packagist 6,633, Go 5,149, …). Download 2.8–3.3 s; parsing the IDs 0.04 s; peak memory 388 MB through `HttpClient`.
  - **Agreement:** of 28,465 tracked facts, 28,457 matched the listing. All 6 that differed were recorded absent weeks ago (2026-10-28 to 11-04) and the API now returns 200 for them: the stored facts are stale, not the listing. **All 408 sampled IDs: the listing and the API agree.**
  - **Site:** `Upload to R2` took 730 s for 28,825 files after a site-code push (every page changed) and 95–320 s on daily runs (5,000–13,000 files), about 40–80 files a second plus about 30 s fixed. F-183's first upload ran at 71 files a second with 10 connections, so the 32 connections since then haven't raised throughput.
- **Caveats:** the regression is collinear (Maven, CVE lookups and git tags began together), so the time split comes from per-request latency, not from per-step measurement. The latency was measured from a laptop, not a runner. Through its edge cache, the listing can be up to an hour behind the API, so an advisory imported into OSV in the hour before a run is recorded on the next run.
- **Implication:**
  - The tracker reads OSV presence from the listing when 2,000 or more advisories are open (`OSV_LISTING_MIN`). That replaces about 28,000 requests and about 8 minutes with one download of a few seconds. Below that (e.g. a focused tracker), or when the listing fails, is too large, or has fewer than 20,000 GHSA IDs, it asks per ID as before, so a broken listing can't put advisories that are in OSV into limbo.
  - `RunReport.phases` records each step's seconds in `runs.jsonl`, so the next runs measure the split this entry estimates.
  - Not changed yet: Maven concurrency (4), checkpoint frequency, and the R2 upload, whose limit isn't connections (boto3's per-request CPU under the GIL is a candidate).
- **Sources:** GitHub Actions run logs; `tracker-data` state; OSV API; OSV's GCS bucket; https://docs.github.com/en/rest/using-the-rest-api/rate-limits-for-the-rest-api

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

