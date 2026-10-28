# Limbo Tracker

A daily job that counts published GitHub security advisories still **in limbo**: not yet in GitHub's reviewed Advisory Database or in OSV, so most scanners can't see them. It publishes a static site and an open feed for limbo.watch.

## What one run does

1. **Reviewed list.** Syncs GitHub's reviewed advisories since the last run. The first run walks the whole list (about 370 requests). Every repo where a reviewed advisory originated joins the watchlist.
2. **CVE delta log.** Reads new and updated CVE records from cvelistV5. CVEs that reference a GHSA are kept, and repos named by GitHub-assigned CVEs join the watchlist.
3. **Polling.** Polls repos for published advisories, within a request budget:
   - never-polled repos first, then repos with advisories in limbo, then the oldest-polled;
   - conditional requests: an unchanged repo returns 304, which is free.
4. **Assessment.** For each advisory not yet reviewed:
   - checks OSV and the cited CVE's state (re-checks reserved CVEs about daily);
   - looks for CVEs from other CNAs that reference it, and for duplicates (the same CVE already reviewed under another GHSA);
   - looks up NVD status (capped per run).

   It stores a fact snapshot only when something changed, plus a readable event ("in limbo -> reviewed", "CVE-X RESERVED -> PUBLISHED").
5. **Publish.** `limbowatch publish` writes:
   - `index.html`;
   - `metrics.json`;
   - `feed/all.zip`: OSV schema, one `<GHSA>.json` per advisory in limbo, same layout as OSV's bulk exports;
   - `feed/index.json`.

## Seeds

- `seeds/popular-upstreams.txt`: upstream repos of the 15 projects in the October report.
- `seeds/top100-upstreams.txt`: upstream repos of the dependencies of `seeds/top100-projects.txt`, the 100 most-starred GitHub repos with a readable lockfile (FINDINGS F-063). To regenerate:

```sh
uv run tracker/seeds/make_seed.py select
cd research/2026-10-state-of-the-gap/scripts
SNAPSHOT_DATE=$(date +%F)-top100 PROJECT_SET=top100 uv run s1_inventory.py && SNAPSHOT_DATE=$(date +%F)-top100 uv run s2_map.py
cd - && uv run tracker/seeds/make_seed.py upstreams $(date +%F)-top100
```

## Running it

```sh
uv run limbowatch track --state tracker/state --seed tracker/seeds/popular-upstreams.txt \
  --seed tracker/seeds/top100-upstreams.txt --budget 4000 --minutes 50
uv run limbowatch publish --state tracker/state --out tracker/site
```

- **Token:** `LIMBOWATCH_GITHUB_TOKEN` or `GITHUB_TOKEN`; locally, `gh auth token` is used.
- **NVD:** `NVD_API_KEY` is optional; it speeds up lookups from 6.5 s to 0.7 s each.
- **Interrupted runs:** state is checkpointed after each step and every 500 polls, so a cut-off run keeps its progress.

## Daily report

`limbowatch report` writes `reports/YYYY-MM-DD.md` (and `latest.md`). It covers:
- **the current numbers**, with the change since the previous report;
- **newly published advisories** that entered limbo, sorted by severity;
- **what left limbo:** reviewed, duplicate, or withdrawn;
- **CVE changes:** reserved CVEs that got published, and new CVEs from other CNAs;
- **the longest-waiting advisories**, and coverage.

The previous report's position is stored in the state, so a skipped day is covered by the next report.

In CI the report is:
- shown in the run summary;
- committed to the `tracker-data` branch under `reports/`;
- posted as a comment on the **"Limbo Tracker daily report"** issue. Subscribe to that issue to get it by email.

## In CI

`.github/workflows/tracker.yml`:
- runs `track` and `publish`;
- commits the JSONL state to the `tracker-data` branch;
- deploys the site to GitHub Pages.

It runs daily at 06:17 UTC (and on manual dispatch). The first run also downloads the latest CVE List release once, to bootstrap CVEs that other CNAs assigned earlier. The website deploy is skipped while the repo is private, because Pages on a private repo needs a paid plan; the report and the feed are still produced every day.

**Token choice:**
- **`GITHUB_TOKEN`** allows 1,000 requests/hour, and its ETags probably don't carry over between runs (FINDINGS F-058, Q11). So most repos cost a full request every day.
- **A fine-grained PAT** stored as the `LIMBOWATCH_GITHUB_TOKEN` secret (public repositories, read-only, no extra permissions) allows 5,000/hour, and its ETags stay valid, so unchanged repos are free. Recommended.

## What it doesn't see

- **Repos outside the watchlist.** GitHub has no global list of repository advisories, so the tracker sees only repos on its watchlist: where reviewed advisories originated, the seed lists, and repos named in new GitHub-assigned CVEs. **Every number is a floor.**
- **First advisories in unknown repos.** A repo's first advisory with no CVE, in a repo that isn't a popular upstream, appears only once something else reveals it.

## What it publishes

Factual metadata only:
- IDs, repository, package, ecosystem, version range, fixed version, severity, CVSS vector, CWE IDs, dates, links and lifecycle facts.
- No advisory titles, descriptions, authors or credits (FINDINGS F-047, F-059).

Data is CC BY 4.0, with attribution to the GitHub Advisory Database.
