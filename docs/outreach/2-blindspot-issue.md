> **Draft, not sent.** Phase 3 closed on 2026-11-05 without outreach, at the maintainer's choice. Numbers are as of 2026-10-31; refresh them before using this.

Repo: munimtechnologies/advisory-import-census
Title: Contributions you'd want? Reserved CVEs, duplicates, GitLab output, a daily limbo feed

Hi, I run [limbo.watch](https://limbo.watch), a daily tracker of published repository advisories that aren't in GitHub's reviewed database or OSV yet. It covers the same gap blindspot checks at scan time. I'd rather contribute to blindspot than build a second scanner, so I'm asking first which of these, if any, you'd take as PRs:

1. **Reserved-but-public CVE flag.** The advisory cites a CVE that is still `RESERVED` (`GET https://cveawg.mitre.org/api/cve-id/{id}`). We see about 560 of these among pending advisories today.
2. **Duplicate detection.** The advisory's CVE is already on a *different*, reviewed GHSA, so the scanner probably does warn, just under another ID. This is the CVE-reuse case your S1 and S2 studies look at.
3. **GitLab output.** A Code Quality report and a CI template, for projects hosted on GitLab.
4. **An optional feed input.** Instead of one request per repo, read `https://limbo.watch/feed/index.json` and the per-advisory records, which are OSV-schema JSON, rebuilt daily and CC BY 4.0. That helps big lockfiles that hit the 60 or 1,000 requests-per-hour limits.

Each would be a separate PR, standard library only, with offline tests in your style. If none of these fit your plans, that's fine too.

Separately, the tracker's data overlaps your studies: about 18,600 watched repos, daily fact snapshots, CVE state transitions and observed review lag. If any of it would help your studies, I'm happy to share it.
