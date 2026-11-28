# Limbo Tracker daily report — 2026-11-28

Generated 2026-11-28 15:53:10 UTC; changes since 2026-11-27 17:08:26 UTC.

## Now

- **12,762 advisories in limbo** (+115 since the last report: 110 newly published, 5 older ones found for the first time, 0 left limbo): published by maintainers on GitHub, in ecosystems GitHub reviews, but not yet in GitHub's reviewed database or OSV.
  - 7,584 with no CVE anywhere · 557 citing a CVE that's still only reserved · 1,656 with a CVE from another CNA they don't cite
  - severity: 1,124 critical, 4,955 high, 5,407 medium, 1,276 low · median wait so far 52.9 days
- **16,862 more are likely permanent** (+112 since the last report: 107 newly published, 5 older ones found for the first time, 0 left limbo): in ecosystems GitHub doesn't review, so GitHub-based scanners will probably never see them.

## Since the last report

- **110 newly published** advisories entered limbo.
- 5 older advisories were found for the first time (0 in newly watched repos).
- **Left limbo** (likely permanent included): 0 reviewed by GitHub, 0 found to duplicate a reviewed advisory, 0 withdrawn or unpublished. **GitHub reviewed no advisories at all in this period.**
- **CVE changes:** 10 (0 reserved CVEs published, 9 new CVEs from other CNAs).

## Newly published, in limbo

| Advisory | Package | Severity | CVE | Days | Fixed in |
|---|---|---|---|---:|---|
| [GHSA-299f-9wgh-7jhv](https://github.com/opsmill/infrahub/security/advisories/GHSA-299f-9wgh-7jhv) | `pip:infrahub-server` | critical | no CVE anywhere | 0 | `1.10.12, 1.11.14, 1.12.4` |
| [GHSA-7m49-74q2-hxc9](https://github.com/christianhelle/refitter/security/advisories/GHSA-7m49-74q2-hxc9) | `nuget:Refitter.Core` | critical | no CVE anywhere | 0 | `2.4.4` |
| [GHSA-4j78-2jpc-xg6w](https://github.com/christianhelle/refitter/security/advisories/GHSA-4j78-2jpc-xg6w) | `nuget:Refitter` | critical | no CVE anywhere | 0 | `2.4.4` |
| [GHSA-fc6g-2vwf-pcv6](https://github.com/ronf/asyncssh/security/advisories/GHSA-fc6g-2vwf-pcv6) | `pip:asyncssh` | critical | no CVE anywhere | 0 | `2.24.2` |
| [GHSA-hq3m-m74p-49w7](https://github.com/fent/node-m3u8stream/security/advisories/GHSA-hq3m-m74p-49w7) | `npm:m3u8stream` | high | no CVE anywhere | 1 | `0.10.1` |
| [GHSA-3wgp-hmvf-xj8h](https://github.com/canonical/pylxd/security/advisories/GHSA-3wgp-hmvf-xj8h) | `pip:pylxd` | high | CVE published, cited (`CVE-2026-127163`) | 1 | `2.4.3` |
| [GHSA-cx95-gjrm-h7hh](https://github.com/tefra/xsdata/security/advisories/GHSA-cx95-gjrm-h7hh) | `pip:xsdata` | high | no CVE anywhere | 1 | `26.11.1` |
| [GHSA-95mj-7gh2-2h2m](https://github.com/WaterFutures/EPyT-Flow/security/advisories/GHSA-95mj-7gh2-2h2m) | `pip:epyt-flow` | high | no CVE anywhere | 1 | `0.17.4` |
| [GHSA-fpj9-cx6c-h4wv](https://github.com/coreshop/CoreShop/security/advisories/GHSA-fpj9-cx6c-h4wv) | `composer:coreshop/core-shop` | high | no CVE anywhere | 1 | `2026.3.0, 4.1.14, 5.0.4, 5.1.4` |
| [GHSA-9x6f-pr27-q95g](https://github.com/codenotary/immudb/security/advisories/GHSA-9x6f-pr27-q95g) | `go:github.com/codenotary/immudb` | high | no CVE anywhere | 1 | `1.12.0` |
| [GHSA-f7pp-fgh4-77mq](https://github.com/codenotary/immudb/security/advisories/GHSA-f7pp-fgh4-77mq) | `go:github.com/codenotary/immudb` | high | no CVE anywhere | 1 | `1.12.0` |
| [GHSA-6q62-8vx6-gwwj](https://github.com/codenotary/immudb/security/advisories/GHSA-6q62-8vx6-gwwj) | `go:github.com/codenotary/immudb` | high | no CVE anywhere | 1 | `1.12.0` |
| [GHSA-984f-678g-77x2](https://github.com/codenotary/immudb/security/advisories/GHSA-984f-678g-77x2) | `go:github.com/codenotary/immudb` | high | no CVE anywhere | 1 | `1.12.0` |
| [GHSA-cq58-3pgm-wgv6](https://github.com/codenotary/immudb/security/advisories/GHSA-cq58-3pgm-wgv6) | `go:github.com/codenotary/immudb` | high | no CVE anywhere | 1 | `1.12.0` |
| [GHSA-27mw-m39x-fm32](https://github.com/lxml/lxml/security/advisories/GHSA-27mw-m39x-fm32) | `pip:lxml` | high | no CVE anywhere | 1 | `6.2.0` |
| [GHSA-4w9h-57gf-h3px](https://github.com/smalot/pdfparser/security/advisories/GHSA-4w9h-57gf-h3px) | `composer:smalot/pdfparser` | high | CVE published, cited (`CVE-2026-134129`) | 0 | `2.14.0` |
| [GHSA-3qjc-mqvq-rch9](https://github.com/mikro-orm/mikro-orm/security/advisories/GHSA-3qjc-mqvq-rch9) | `npm:@mikro-orm/knex, npm:@mikro-orm/sql` | high | no CVE anywhere | 0 | `7.2.13, 6.6.20` |
| [GHSA-m8gq-fmc8-f582](https://github.com/mikro-orm/mikro-orm/security/advisories/GHSA-m8gq-fmc8-f582) | `npm:@mikro-orm/mongodb` | high | no CVE anywhere | 0 | `7.2.13, 6.6.20` |
| [GHSA-j4pj-2xg4-35f6](https://github.com/mikro-orm/mikro-orm/security/advisories/GHSA-j4pj-2xg4-35f6) | `npm:@mikro-orm/mariadb, npm:@mikro-orm/mysql, npm:@mikro-…` | high | no CVE anywhere | 0 | `7.2.13, 6.6.20` |
| [GHSA-xx29-jph9-vq39](https://github.com/ronf/asyncssh/security/advisories/GHSA-xx29-jph9-vq39) | `pip:asyncssh` | high | no CVE anywhere | 0 | `2.24.1` |
| [GHSA-xw5f-qvpr-c3v6](https://github.com/ronf/asyncssh/security/advisories/GHSA-xw5f-qvpr-c3v6) | `pip:asyncssh` | high | no CVE anywhere | 0 | `2.24.1` |
| [GHSA-jr2x-9894-h63r](https://github.com/ronf/asyncssh/security/advisories/GHSA-jr2x-9894-h63r) | `pip:asyncssh` | high | no CVE anywhere | 0 | `2.24.1` |
| [GHSA-qh52-pm2g-92v4](https://github.com/ronf/asyncssh/security/advisories/GHSA-qh52-pm2g-92v4) | `pip:asyncssh` | high | no CVE anywhere | 0 | `2.24.1` |
| [GHSA-gv85-2g9p-9j8x](https://github.com/ronf/asyncssh/security/advisories/GHSA-gv85-2g9p-9j8x) | `pip:asyncssh` | high | no CVE anywhere | 0 | `2.24.1` |
| [GHSA-7p24-mqc7-93r2](https://github.com/ronf/asyncssh/security/advisories/GHSA-7p24-mqc7-93r2) | `pip:asyncssh` | high | no CVE anywhere | 0 | `2.24.1` |

…and 85 more: [the tracker](https://limbo.watch/tracker/) lists them all, newest first.

## CVE changes

| Advisory | Change |
|---|---|
| [GHSA-2wmw-5fmc-m25v](https://github.com/thymeleaf/thymeleaf/security/advisories/GHSA-2wmw-5fmc-m25v) | cites CVE-2026-136410 (was none) |
| [GHSA-4f44-frcc-8824](https://github.com/gphoto/libgphoto2/security/advisories/GHSA-4f44-frcc-8824) | new CVE from another CNA: CVE-2026-138158 |
| [GHSA-94pv-f379-3gp3](https://github.com/kestra-io/kestra/security/advisories/GHSA-94pv-f379-3gp3) | new CVE from another CNA: CVE-2026-138121 |
| [GHSA-j26h-55cv-c7pm](https://github.com/kestra-io/kestra/security/advisories/GHSA-j26h-55cv-c7pm) | new CVE from another CNA: CVE-2026-138119 |
| [GHSA-38rc-2jxj-2h75](https://github.com/kestra-io/kestra/security/advisories/GHSA-38rc-2jxj-2h75) | new CVE from another CNA: CVE-2026-138120 |
| [GHSA-5r2f-7788-qp8v](https://github.com/SylphxAI/anymd/security/advisories/GHSA-5r2f-7788-qp8v) | new CVE from another CNA: CVE-2026-138030 |
| [GHSA-6mr5-wx6p-65fg](https://github.com/clidey/whodb/security/advisories/GHSA-6mr5-wx6p-65fg) | new CVE from another CNA: CVE-2026-138032 |
| [GHSA-pvf2-6h4x-r24j](https://github.com/clidey/whodb/security/advisories/GHSA-pvf2-6h4x-r24j) | new CVE from another CNA: CVE-2026-138032 |
| [GHSA-rgg9-pwc3-jg39](https://github.com/SylphxAI/anymd/security/advisories/GHSA-rgg9-pwc3-jg39) | new CVE from another CNA: CVE-2026-138030 |
| [GHSA-w4h3-92qg-f374](https://github.com/baptisteArno/typebot.io/security/advisories/GHSA-w4h3-92qg-f374) | new CVE from another CNA: CVE-2026-138031 |

## Longest waiting, published in the last 90 days

| Advisory | Package | Severity | CVE | Days | Fixed in |
|---|---|---|---|---:|---|
| [GHSA-j4m5-rrc4-5qv6](https://github.com/laradashboard/laradashboard/security/advisories/GHSA-j4m5-rrc4-5qv6) | `composer:laradashboard/laradashboard` | high | CVE published by another CNA, not cited (`CVE-2026-90933`) | 89 | `–` |
| [GHSA-g5xh-m3w7-jmcq](https://github.com/chamilo/chamilo-lms/security/advisories/GHSA-g5xh-m3w7-jmcq) | `composer:chamilo/chamilo-lms` | high | CVE reserved (RBP) (`CVE-2026-70647`) | 89 | `1.11.40, 2.0.3` |
| [GHSA-x63q-6gqg-qr8p](https://github.com/chamilo/chamilo-lms/security/advisories/GHSA-x63q-6gqg-qr8p) | `composer:chamilo/chamilo-lms` | high | CVE reserved (RBP) (`CVE-2026-70648`) | 89 | `1.11.40` |
| [GHSA-wcj2-r6vg-rm97](https://github.com/rhukster/dom-sanitizer/security/advisories/GHSA-wcj2-r6vg-rm97) | `composer:rhukster/dom-sanitizer` | medium | CVE published, cited (`CVE-2026-100370`) | 89 | `1.0.15` |
| [GHSA-jvrf-c7q2-qghg](https://github.com/chamilo/chamilo-lms/security/advisories/GHSA-jvrf-c7q2-qghg) | `composer:chamilo/chamilo-lms` | critical | CVE reserved (RBP) (`CVE-2026-70649`) | 89 | `2.0.3` |

625 advisories in limbo have waited more than a year.

## Coverage

Watchlist 68,219 repositories; 68,219 up to date on their schedule (daily for repos with an advisory in limbo, every 3 days for other repos with advisories, every 30 days and after each release for the rest); 7,348 checked in the last 24 hours; 38,014 reviewed advisories known. Every number is a floor: the tracker only sees repositories on its watchlist. Version ranges are as entered by maintainers and unreviewed.

_Advisory metadata from published GitHub repository security advisories and the GitHub Advisory Database (https://github.com/advisories, CC BY 4.0); CVE state from CVE Services; OSV.dev; NVD API (this product uses the NVD API but is not endorsed or certified by the NVD). Compiled by Limbowatch (https://limbo.watch), CC BY 4.0._
