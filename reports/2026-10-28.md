# Limbo Tracker daily report — 2026-10-28

Generated 2026-10-28 13:11:43 UTC; changes since 2026-10-28 09:53:48 UTC.

## Now

- **6,128 advisories in limbo** (+4 since the last report): published by maintainers on GitHub, in ecosystems GitHub reviews, but not yet in GitHub's reviewed database or OSV.
  - 3,355 with no CVE anywhere · 471 citing a CVE that's still only reserved · 982 with a CVE from another CNA they don't cite
  - severity: 535 critical, 2,478 high, 2,532 medium, 583 low · median wait so far 47.5 days
- **3,416 more are likely permanent** (+0 since the last report): in ecosystems GitHub doesn't review, so GitHub-based scanners will probably never see them.

## Since the last report

- **1 newly published** advisories entered limbo.
- 3 older advisories were found for the first time (newly watched repos).
- **Left limbo:** 0 reviewed by GitHub, 0 found to duplicate a reviewed advisory, 0 withdrawn or unpublished.
- **CVE changes:** 0.

## Newly published, in limbo

| Advisory | Package | Severity | CVE | Days | Fixed in |
|---|---|---|---|---:|---|
| [GHSA-vrrv-3f46-c3x7](https://github.com/topluyo/App/security/advisories/GHSA-vrrv-3f46-c3x7) | `npm:topluyo-desktop` | critical | CVE published, cited (CVE-2026-115904) | 0 | 2026.9.2410 |

## Longest waiting

| Advisory | Package | Severity | CVE | Days | Fixed in |
|---|---|---|---|---:|---|
| [GHSA-6pc9-r5gr-m9c9](https://github.com/rschultheis/many_versioned_gem/security/advisories/GHSA-6pc9-r5gr-m9c9) | `rubygems:many_versioned_gem` | medium | no CVE anywhere | 2813 | 0.1.1 |
| [GHSA-3wjh-93gr-chh6](https://github.com/flarum/framework/security/advisories/GHSA-3wjh-93gr-chh6) | `composer:flarum/core` | high | CVE published, cited (CVE-2019-13183) | 2672 | 0.1.0-beta.9 |
| [GHSA-jchv-x857-q8fq](https://github.com/apple/swift-nio-http2/security/advisories/GHSA-jchv-x857-q8fq) | `swift:swift-nio-http2` | high | no CVE anywhere | 2632 | 1.5.0 |
| [GHSA-hv27-vjg3-m59x](https://github.com/apple/swift-nio-http2/security/advisories/GHSA-hv27-vjg3-m59x) | `swift:swift-nio-http2` | high | CVE published, cited (CVE-2019-9515) | 2632 | 1.5.0 |
| [GHSA-9cqv-v2w2-7j52](https://github.com/apple/swift-nio-http2/security/advisories/GHSA-9cqv-v2w2-7j52) | `swift:swift-nio-http2` | high | CVE published, cited (CVE-2019-9516) | 2632 | 1.5.0 |

## Coverage

Watchlist 16,433 repositories; 16,433 up to date on their schedule (daily for repos with an advisory in limbo, every 3 to 7 days for the rest); 16,433 checked in the last 24 hours; 37,320 reviewed advisories known. Every number is a floor: the tracker only sees repositories on its watchlist. Version ranges are as entered by maintainers and unreviewed.

_Advisory metadata from published GitHub repository security advisories and the GitHub Advisory Database (https://github.com/advisories, CC BY 4.0); CVE state from CVE Services; OSV.dev; NVD API (this product uses the NVD API but is not endorsed or certified by the NVD). Compiled by Limbowatch (https://limbo.watch), CC BY 4.0._
