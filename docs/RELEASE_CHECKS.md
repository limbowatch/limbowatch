# Design: check a repository when its package releases

Status (2026-11-07): **built: steps 1, 2 and 4.** Releases of unwatched packages with at least 100 dependent repositories are included. Step 3's week of measurement was replaced by a backtest on the last month's advisories (FINDINGS F-104); per-tier counts in each run report keep measuring it live. First live collection: F-102.

## Why

The tracker re-polls every watched repository on a fixed schedule (daily, every 3 days, weekly), whether or not anything happened there. That's how it finds new advisories, and it's what limits how many repositories it can watch: the 3,500 counted requests a run go first to re-checks (about 1,600 in steady state, F-100) and only the rest to new repositories.

Advisories follow releases. Of 282 recent advisories with release data, **71% had a release of their package within a day and 79% within 3 days**; in 82% the release came first: the maintainer ships the fix, then publishes the advisory (F-100). So "this package just released" is a strong signal that its repository is about to publish an advisory, and every ecosystem we cover has a feed of releases (F-101).

## What changes

1. **Collect releases each run.** Since the previous run:
   - npm, PyPI, NuGet, crates.io, Maven, RubyGems: ecosyste.ms packages sorted by `latest_release_published_at`, paged until older than the last run (about 40 requests a day at 1,000 a page);
   - Go: `index.golang.org/index?since=…`, ignoring pseudo-versions;
   - Packagist: `packagist.org/metadata/changes.json?since=…`, `update` actions, ignoring `~dev` branches.
2. **Map each release to a repository**, using the registry's repository URL (as the seed already does), and keep only releases of packages we care about: every watched repository, plus, optionally, any package above a usage threshold (see the decisions below).
3. **Schedule checks after a release:** one about a day after the release and one about three days after. These rank with the daily tier, ahead of routine weekly checks.
4. **Relax the routine schedule.** Repositories without advisories that didn't release go from weekly to every 30 days, which saves most of today's weekly cost. Repositories with an advisory in limbo stay daily, because that's where review status changes.

## What it buys

- **New advisories found within about a day of the fix release**, instead of up to a week later for quiet repositories.
- **Room to watch far more repositories:** a repository costs nothing until its package releases. On a typical day only a few percent of watched packages release, so the top 10,000 (and later the top 50,000) per ecosystem become affordable.
- **A path towards "all packages":** with a usage threshold, any package that releases can be checked once, even if it was never on the watchlist.

## Risks and limits

- **Advisories without a release:** about 14% have none within a week. The 30-day routine check still catches them, just later. Repositories with known advisory activity keep their shorter schedule.
- **Feed outages:** ecosyste.ms is a third party; its version-level endpoints failed in testing, and its Maven feed fell behind on 2026-11-07 (F-105). If a feed fails, the run falls back to the routine schedule and says so in the run report; each feed's newest release is reported too, so a lagging feed shows.
- **Wrong repository URLs** in registry metadata only waste a poll; they can't create a false finding.
- **Licence:** the ecosyste.ms data is CC BY-SA 4.0. It's used at run time for scheduling and not republished, apart from the watchlist (already CC BY-SA, PHASE0_PLAN §13.12).

## How we'd check it works

Before relaxing any schedule: run release collection alongside the current schedule for a week. Record, for every new advisory the tracker finds, whether a release-triggered check would have found it, and how much sooner or later. Relax the weekly tier only if release checks catch at least as much, sooner.

## Decisions (2026-11-07)

1. Build it in that order: collect, trigger checks, measure for a week, then relax the schedule. **Approved.**
2. Also check releases of unwatched packages with at least 100 dependent repositories (`--release-min-dependents`). **Approved.** Measured on the first collection: 76 such repos in a day, not the 1,000–2,000 guessed, because most popular packages are already watched (F-102).

3. Measure on history instead of waiting a week (F-104): release checks catch 85–88% of advisories within 7 days, at a median of 0.8 days. **Approved.**
4. Relax the routine schedule: repositories without advisories are re-checked every 30 days instead of weekly. **Approved**, on F-104: for those repositories the average delay goes from 3.5 to 2.6 days, and 11 of 1,672 advisories (0.7%) would have been found later. Repositories with advisories, and repositories answering 404, keep their schedule.

## Built

- `limbowatch.sources.releases`: the three feeds; each reports whether it reached the previous run, and a partial feed keeps its cursor.
- Maven Central (F-108): ecosyste.ms's Maven data lags by weeks, Maven Central's index is rebuilt about every two weeks, and search.maven.org stopped updating in June 2026. So the tracker polls each watched Maven package's `maven-metadata.xml` once a day with its ETag (`--maven-packages tracker/seeds/maven-packages.txt`, the top 10,000 Maven packages). An unchanged file is a 304 with no body.
- `Tracker.collect_releases`: marks `Repo.released_at`, adds popular unwatched repos (source `release:<registry>`), records per feed in the run report (`releases`).
- `schedule.release_due`: checks at about 20 hours and about 3 days after a release, ahead of routine checks; a repo added because it just released goes before a seed list's backlog.
- Per-tier counts in each run report include a `release` tier and the new advisories each tier finds, which keeps measuring step 3 live.
- `schedule.INTERVAL`: repositories without advisories every 30 days (step 4). Never-checked repositories still gain one point of priority per week waiting (`NEW_GROWTH`).
