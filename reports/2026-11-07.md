# Limbo Tracker daily report — 2026-11-07

Generated 2026-11-07 12:06:24 UTC; changes since 2026-11-07 10:14:39 UTC.

## Now

- **8,999 advisories in limbo** (+91 since the last report: 13 newly published, 78 older ones found for the first time, 0 left limbo): published by maintainers on GitHub, in ecosystems GitHub reviews, but not yet in GitHub's reviewed database or OSV.
  - 4,789 with no CVE anywhere · 583 citing a CVE that's still only reserved · 1,082 with a CVE from another CNA they don't cite
  - severity: 893 critical, 3,534 high, 3,747 medium, 825 low · median wait so far 57.4 days
- **14,370 more are likely permanent** (+48 since the last report: 2 newly published, 46 older ones found for the first time, 0 left limbo): in ecosystems GitHub doesn't review, so GitHub-based scanners will probably never see them.

## Since the last report

- **13 newly published** advisories entered limbo.
- 78 older advisories were found for the first time (0 in newly watched repos).
- **Left limbo** (likely permanent included): 0 reviewed by GitHub, 0 found to duplicate a reviewed advisory, 0 withdrawn or unpublished.
- **CVE changes:** 0.

## Newly published, in limbo

| Advisory | Package | Severity | CVE | Days | Fixed in |
|---|---|---|---|---:|---|
| [GHSA-mjwg-5fm3-fx2p](https://github.com/ruvnet/metaharness/security/advisories/GHSA-mjwg-5fm3-fx2p) | `npm:@metaharness/darwin, npm:metaharness` | high | no CVE anywhere | 1 | 0.13.0, 0.4.20 |
| [GHSA-h928-qgv7-pq8g](https://github.com/ruvnet/RuVector/security/advisories/GHSA-h928-qgv7-pq8g) | `npm:@ruvector/graph-node` | high | no CVE anywhere | 1 | 2.1.2 |
| [GHSA-p62c-q7fc-qmg9](https://github.com/ruvnet/RuVector/security/advisories/GHSA-p62c-q7fc-qmg9) | `npm:@ruvector/attention` | high | no CVE anywhere | 1 | 2.2.3 |
| [GHSA-c27m-v4wg-f9qj](https://github.com/ruvnet/RuVector/security/advisories/GHSA-c27m-v4wg-f9qj) | `npm:@ruvector/sona` | high | no CVE anywhere | 1 | 0.1.9 |
| [GHSA-mc5p-3gj7-h877](https://github.com/toss/es-toolkit/security/advisories/GHSA-mc5p-3gj7-h877) | `npm:es-toolkit` | high | no CVE anywhere | 1 | 1.53.1 |
| [GHSA-8f9m-54jh-jwxr](https://github.com/toss/es-toolkit/security/advisories/GHSA-8f9m-54jh-jwxr) | `npm:es-toolkit` | high | no CVE anywhere | 1 | 1.39.4 |
| [GHSA-9qjg-mfqr-5gqq](https://github.com/toss/es-toolkit/security/advisories/GHSA-9qjg-mfqr-5gqq) | `npm:es-toolkit` | high | no CVE anywhere | 1 | 1.51.0 |
| [GHSA-cjcq-mj39-74pj](https://github.com/toss/es-toolkit/security/advisories/GHSA-cjcq-mj39-74pj) | `npm:es-toolkit` | high | no CVE anywhere | 1 | 1.39.4 |
| [GHSA-68ch-232w-w277](https://github.com/rusqlite/rusqlite/security/advisories/GHSA-68ch-232w-w277) | `rust:rusqlite` | high | no CVE anywhere | 0 | – |
| [GHSA-hmqc-2jxx-4392](https://github.com/toss/es-toolkit/security/advisories/GHSA-hmqc-2jxx-4392) | `npm:es-toolkit` | medium | no CVE anywhere | 1 | 1.53.1 |
| [GHSA-2h47-xrv3-xpjm](https://github.com/toss/es-toolkit/security/advisories/GHSA-2h47-xrv3-xpjm) | `npm:es-toolkit` | medium | no CVE anywhere | 1 | 1.53.1 |
| [GHSA-9mff-c522-6jhr](https://github.com/ruvnet/RuVector/security/advisories/GHSA-9mff-c522-6jhr) | `rust:rvf-crypto` | medium | no CVE anywhere | 0 | 0.3.1 |
| [GHSA-jjh7-c792-c9qw](https://github.com/rusqlite/rusqlite/security/advisories/GHSA-jjh7-c792-c9qw) | `rust:rusqlite` | medium | no CVE anywhere | 0 | – |

## Longest waiting, published in the last 90 days

| Advisory | Package | Severity | CVE | Days | Fixed in |
|---|---|---|---|---:|---|
| [GHSA-j548-9grx-fh4f](https://github.com/rustfs/rustfs/security/advisories/GHSA-j548-9grx-fh4f) | `rust:rustfs` | high | CVE published, cited (CVE-2026-73288) | 89 | 1.0.0-rc.1 |
| [GHSA-x298-9x87-fvjq](https://github.com/rustfs/rustfs/security/advisories/GHSA-x298-9x87-fvjq) | `rust:rustfs` | medium | CVE published, cited (CVE-2026-73290) | 89 | 1.0.0-beta.12 |
| [GHSA-6r96-hmgc-726c](https://github.com/rustfs/rustfs/security/advisories/GHSA-6r96-hmgc-726c) | `rust:rustfs` | high | CVE published, cited (CVE-2026-73286) | 89 | 1.0.0-beta.12 |
| [GHSA-v9cp-qfw9-9pfp](https://github.com/rustfs/rustfs/security/advisories/GHSA-v9cp-qfw9-9pfp) | `rust:rustfs` | high | CVE published, cited (CVE-2026-73289) | 89 | 1.0.0-beta.12 |
| [GHSA-2w7f-x78f-89q2](https://github.com/kimai/kimai/security/advisories/GHSA-2w7f-x78f-89q2) | `composer:kimai/kimai2` | medium | CVE published by another CNA, not cited (CVE-2026-80193) | 89 | 2.62.0 |

591 advisories in limbo have waited more than a year.

## Coverage

Watchlist 22,038 repositories; 19,146 up to date on their schedule (daily for repos with an advisory in limbo, every 3 to 7 days for the rest); 13,282 checked in the last 24 hours; the last run stopped early (budget); 37,542 reviewed advisories known. Every number is a floor: the tracker only sees repositories on its watchlist. Version ranges are as entered by maintainers and unreviewed.

_Advisory metadata from published GitHub repository security advisories and the GitHub Advisory Database (https://github.com/advisories, CC BY 4.0); CVE state from CVE Services; OSV.dev; NVD API (this product uses the NVD API but is not endorsed or certified by the NVD). Compiled by Limbowatch (https://limbo.watch), CC BY 4.0._
