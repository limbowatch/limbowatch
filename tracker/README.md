# Limbo Tracker

A daily job that counts published GitHub security advisories still **in limbo**: not yet in GitHub's reviewed Advisory Database or in OSV, so most scanners can't see them. It publishes a static site and an open feed for limbo.watch.

## What one run does

1. **Reviewed list.** Syncs GitHub's reviewed advisories since the last run. The first run walks the whole list (about 370 requests). Every repo where a reviewed advisory originated joins the watchlist.
2. **CVE delta log.** Reads new and updated CVE records from cvelistV5. CVEs that reference a GHSA are kept, and repos named by GitHub-assigned CVEs join the watchlist. Each run also adds repos named by GitHub-assigned CVEs already in the state, including those from the CVE List bootstrap (F-066).
3. **Polling.** Polls the repos that are due for published advisories, within a request budget (`limbowatch/schedule.py`):
   - each repo has a target interval: daily if it has an advisory in limbo, every 3 days if it has other advisories, every 30 days if it has none yet, weekly if it answered 404;
   - after a release of a repo's package, it's also checked about a day and about three days later, ahead of routine checks (docs/RELEASE_CHECKS.md, F-104). Releases come from ecosyste.ms (npm, PyPI, NuGet, crates.io, RubyGems), the Go module index, Packagist's change feed and, for the top 10,000 Maven packages (`seeds/maven-packages.txt`), Maven Central itself once a day (F-108);
   - each run polls only repos that are due, most overdue first (time since the last check ÷ the interval). If the budget can't cover everything due, every tier slows down by the same factor. Never-polled repos rank above repos that are merely due;
   - conditional requests: an unchanged repo returns 304, which is free;
   - coverage is reported as "up to date on schedule" (site, daily report, `metrics.json` `coverage.on_schedule`).
4. **Releases** (docs/RELEASE_CHECKS.md). Collects every release since the last run from ecosyste.ms (npm, PyPI, NuGet, crates.io, Maven, RubyGems), the Go module index and Packagist's change feed. A watched repo whose package released is checked about a day and about three days later, ahead of routine checks; an unwatched repo whose package has at least 100 dependent repositories joins the watchlist. `--no-releases` turns it off.
5. **Assessment.** For each advisory not yet reviewed:
   - checks OSV and the cited CVE's state (re-checks reserved CVEs about daily);
   - looks for CVEs from other CNAs that reference it, and for duplicates (the same CVE already reviewed under another GHSA);
   - looks up NVD status (capped per run).

   It stores a fact snapshot only when something changed, plus a readable event ("in limbo -> reviewed", "CVE-X RESERVED -> PUBLISHED").
6. **Go modules** (F-113). For each Go package path an advisory names, asks the Go module proxy which module contains it: the longest prefix that `proxy.golang.org/<prefix>/@v/list` serves. New paths are looked up on their first run and every path again after 180 days, stored in `go_modules.jsonl`. The first pass took 1,442 requests for 1,272 paths.
7. **Publish.** `limbowatch publish` writes:
   - `index.html`;
   - `metrics.json`, including `flow_7d`: advisories published in the last 7 days against those that left limbo (F-092);
   - `feed/all.zip`: OSV schema, one `<GHSA>.json` per advisory in limbo, same layout as OSV's bulk exports;
     - package names are cleaned only where the result is certain (stray spaces, URL wrappers, PyPI's PEP 503 form, lowercase Packagist names); the original is kept in `name_as_entered`, and names that still don't fit the ecosystem's rules get `name_valid: false`;
     - a range that can't be converted exactly is left as text (`range_converted: false`), never published open-ended when a fix is listed;
     - Go packages name their module, as OSV's Go records do: when the advisory's path is a package inside a module, `package.name` is the module and the path is in `ecosystem_specific.imports`; `database_specific.go_module` marks a resolved module (F-113);
     - `database_specific.limbowatch.quality` sums up both, per record (F-069);
   - `feed/index.json`;
   - `osv/<Ecosystem>/all.zip`: the same records split by ecosystem, the way OSV serves its own downloads, with an empty zip for every OSV ecosystem the feed doesn't cover (OSV-Scanner's offline mode fails the whole scan when one is missing, F-074). nginx sends each zip's CRC-32C as `X-Goog-Hash` from `osv/crc32c.map` (F-073);
   - `feed/watchlist.json`: every watched repo with when the tracker last checked it, so the watcher polls only the rest (PHASE0_PLAN §13.9);
   - `feed/repos.txt`: every watched repo with at least one published advisory, one `owner/repo` per line, names only, for trackers that poll repos (F-075, F-077);
   - `check/`: the package checker. The browser resolves a package's dependency tree on deps.dev (npm, PyPI, crates.io, Maven) and matches every package against `check/index.json`, the advisories in limbo with their ranges already parsed by the watcher's parser; `assets/check.js` ports the version orderings and is tested against the Python code (`tests/test_check.py`, F-118);
   - `quality/`: advisories in limbo whose package name or range scanners can't use, grouped by repo, with the fix for each (F-077);
   - `feed/limbo.atom` and `feed/critical.atom`: the newest 100 advisories in limbo (all, or critical and high), for feed readers;
   - `press/`: citable numbers and a contact for reporters, the queue chart as `queue.svg`, and every advisory in limbo as `limbo.csv` (one row per advisory with ranges and fixed versions as entered; UTF-8 with a BOM for Excel; a cell that could run as a spreadsheet formula gets a leading `'`), and the contact email as an image;
   - `methodology/`, `sitemap.xml` and `robots.txt`; every page carries Open Graph tags, and the home and press pages a schema.org `Dataset`;
   - `osv/limbo-db.zip`: those zips laid out as OSV-Scanner's cache, so `osv-scanner scan source --offline-vulnerabilities --local-db-path <unzipped dir> -r .` scans against the feed (F-076).

## Seeds

- `seeds/popular-upstreams.txt`: upstream repos of the 15 projects in the October report.
- `seeds/top-packages.txt`: source repos of the most-used packages per ecosystem (npm, PyPI, Go, Maven, crates.io, NuGet, RubyGems, Packagist), ranked by dependent repositories on ecosyste.ms (F-099). Regenerate with `uv run tracker/seeds/make_top_packages.py --top 1000 --deeper nuget.org=10000 …` (per-registry depth with `--deeper`). The ranking is CC BY-SA 4.0, so this file and the published watchlist files are too. A run polls at most `--max-new` never-checked repos (2,500 in CI), so a large list can't starve the daily re-checks.
- `seeds/cpp-upstreams.txt`: C/C++ upstreams, the GitHub repos that vcpkg ports, Bazel Central Registry modules and ConanCenter recipes build from (3,603 on 2026-11-11; F-138). Their advisories mostly name no package, so the watcher matches them to submodules, CMake fetches, Bazel, vcpkg and Conan dependencies by repository. Regenerate with `uv run python tracker/seeds/make_cpp_upstreams.py`.
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
- **the current numbers**, pending and likely permanent, each with the change since the previous report split into newly published advisories, older ones found for the first time (mostly in newly watched repos) and ones that left limbo. Older finds are coverage growth, not new limbo (F-067);
- **newly published advisories** that entered limbo, sorted by severity;
- **what left limbo:** reviewed, duplicate, or withdrawn;
- **CVE changes:** reserved CVEs that got published, new CVEs from other CNAs, and GitHub-assigned CVEs the advisory doesn't cite yet;
- **the longest-waiting advisories published in the last 90 days** (older ones would top it every day), the count waiting more than a year, and coverage.

The previous report's position is stored in the state, so a skipped day is covered by the next report.

In CI the report is:
- shown in the run summary;
- committed to the `tracker-data` branch under `reports/`;
- posted as a comment on the **"Limbo Tracker daily report"** issue. Subscribe to that issue to get it by email. Only the scheduled run reports; a manual run tracks and saves state, and the next daily report covers its changes.

## In CI

`.github/workflows/tracker.yml`:
- runs `track` and `publish`;
- commits the JSONL state to the `tracker-data` branch;
- deploys the site to GitHub Pages.

It runs daily at 06:17 UTC (and on manual dispatch). The first run also downloads the latest CVE List release once, to bootstrap CVEs that other CNAs assigned earlier. When it succeeds, the `site` workflow publishes and deploys limbo.watch ([deploy/README.md](../deploy/README.md)).

**Token choice:**
- **`GITHUB_TOKEN`** allows 1,000 requests/hour, and its ETags probably don't carry over between runs (FINDINGS F-058, Q11). So most repos cost a full request every day.
- **A fine-grained PAT** stored as the `LIMBOWATCH_GITHUB_TOKEN` secret (public repositories, read-only, no extra permissions) allows 5,000/hour, and its ETags stay valid, so unchanged repos are free. Recommended.

## What it doesn't see

- **Repos outside the watchlist.** GitHub has no global list of repository advisories, so the tracker sees only repos on its watchlist: where reviewed advisories originated, the seed lists, and repos named in GitHub-assigned CVEs. **Every number is a floor.**
- **First advisories in unknown repos.** A repo's first advisory with no CVE, in a repo that isn't a popular upstream, appears only once something else reveals it.

## What it publishes

Factual metadata only:
- IDs, repository, package, ecosystem, version range, fixed version, severity, CVSS vector, CWE IDs, dates, links and lifecycle facts.
- No advisory titles, descriptions, authors or credits (FINDINGS F-047, F-059).

Data is CC BY 4.0, with attribution to the GitHub Advisory Database.
