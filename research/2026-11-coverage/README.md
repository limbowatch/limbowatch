# Coverage: what would watching the most-used packages add? (November 2026)

Phase 5, step 1 (FINDINGS [F-099](../../docs/FINDINGS.md#f-099), questions Q20 and Q21). `measure.py` takes the top 50,000 packages of eight ecosystems from [ecosyste.ms](https://packages.ecosyste.ms) (ranked by dependent repositories), maps them to GitHub repos, compares them with the tracker's watchlist, and polls a random sample of the repos it doesn't watch. `summary.json` holds the aggregate counts; raw responses stay in `.cache/` (not committed).

## Share of the top packages' repos already watched (2026-11-07)

| Ecosystem | Top 1,000 | Top 10,000 | Top 50,000 |
|---|---:|---:|---:|
| npm | 97% | 58% | 19% |
| PyPI | 59% | 21% | 5% |
| Go | 43% | 12% | 3% |
| crates.io | 86% | 27% | 6% |
| RubyGems | 26% | 5% | 1% |
| Maven | 12% | 5% | 3% |
| Packagist | 6% | 2% | 1% |
| NuGet | 3% | 1% | 0% |

Not yet watched: about 3,300 repos in the top 1,000s, 45,000 in the top 10,000s, 250,000 in the top 50,000s (before removing repos shared across ecosystems).

## What the unwatched repos hold

A random sample of 150 unwatched repos per ecosystem from the top 10,000 (1,048 answered; 10% had moved and returned 301): 8 repos had published advisories, 30 advisories in all, and **all 30 are in neither GitHub's reviewed database nor OSV** (checked by ID, 2026-11-07). 23 name a reviewable ecosystem; 7 name none. They include commonmark-java (8, published 2026-10-22), zstd-jni (12), svglib (4), hashicorp/go-slug, jekyll-feed and phonenumbers.

Data: package rankings from ecosyste.ms (CC BY-SA 4.0), used here only for measurement; advisory facts from GitHub (CC BY 4.0).
