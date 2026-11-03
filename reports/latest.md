# Limbo Tracker daily report — 2026-11-03

Generated 2026-11-03 14:36:08 UTC; changes since 2026-11-02 16:20:56 UTC.

## Now

- **8,354 advisories in limbo** (+122 since the last report: 114 newly published, 10 older ones found for the first time, 2 left limbo): published by maintainers on GitHub, in ecosystems GitHub reviews, but not yet in GitHub's reviewed database or OSV.
  - 4,360 with no CVE anywhere · 583 citing a CVE that's still only reserved · 1,034 with a CVE from another CNA they don't cite
  - severity: 873 critical, 3,313 high, 3,435 medium, 733 low · median wait so far 56.0 days
- **14,041 more are likely permanent** (+52 since the last report: 49 newly published, 3 older ones found for the first time, 0 left limbo): in ecosystems GitHub doesn't review, so GitHub-based scanners will probably never see them.

## Since the last report

- **114 newly published** advisories entered limbo.
- 10 older advisories were found for the first time (0 in newly watched repos).
- **Left limbo** (likely permanent included): 2 reviewed by GitHub, 0 found to duplicate a reviewed advisory, 0 withdrawn or unpublished.
- **CVE changes:** 8 (2 reserved CVEs published, 0 new CVEs from other CNAs).

## Newly published, in limbo

| Advisory | Package | Severity | CVE | Days | Fixed in |
|---|---|---|---|---:|---|
| [GHSA-5q7h-w9jf-cx97](https://github.com/chainguard-forks/kaniko/security/advisories/GHSA-5q7h-w9jf-cx97) | `go:github.com/chainguard-dev/kaniko` | critical | CVE published, cited (CVE-2026-105769) | 0 | 1.25.20 |
| [GHSA-pcrw-h46h-c93h](https://github.com/Automattic/mongoose/security/advisories/GHSA-pcrw-h46h-c93h) | `npm:mongoose` | critical | no CVE anywhere | 0 | ^6.13.11 || ^7.8.12 || ^8.24.3 || ^9.9.2 |
| [GHSA-j448-mmvh-r877](https://github.com/chamilo/chamilo-lms/security/advisories/GHSA-j448-mmvh-r877) | `composer:chamilo/chamilo-lms` | critical | CVE reserved (RBP) (CVE-2026-54749) | 0 | 3.0.0 |
| [GHSA-h3rw-gm3p-6757](https://github.com/amphp/http-server/security/advisories/GHSA-h3rw-gm3p-6757) | `composer:amphp/http-server` | high | CVE reserved (RBP) (CVE-2026-103037) | 1 | 3.4.8, 2.1.12 |
| [GHSA-3r5h-5jcg-gmgg](https://github.com/andialbrecht/sqlparse/security/advisories/GHSA-3r5h-5jcg-gmgg) | `pip:sqlparse` | high | no CVE anywhere | 1 | 0.6.1 |
| [GHSA-h96x-rm9v-xh6x](https://github.com/graph-gophers/graphql-go/security/advisories/GHSA-h96x-rm9v-xh6x) | `go:github.com/graph-gophers/graphql-go` | high | no CVE anywhere | 1 | 1.11.0 |
| [GHSA-7p5p-67m9-5c8j](https://github.com/graphql-hive/gateway/security/advisories/GHSA-7p5p-67m9-5c8j) | `npm:@graphql-tools/executor-http` | high | no CVE anywhere | 0 | >3.5.0 |
| [GHSA-xrjv-fc7j-8f77](https://github.com/graphql-hive/gateway/security/advisories/GHSA-xrjv-fc7j-8f77) | `npm:@graphql-tools/batch-execute` | high | no CVE anywhere | 0 | >10.3.0 |
| [GHSA-wm4f-qpxp-rch4](https://github.com/cosmos/evm/security/advisories/GHSA-wm4f-qpxp-rch4) | `go:github.com/cosmos/evm` | high | no CVE anywhere | 0 | 0.6.4, 0.7.4 |
| [GHSA-2m6r-q6x4-4w5g](https://github.com/cosmos/evm/security/advisories/GHSA-2m6r-q6x4-4w5g) | `go:github.com/cosmos/evm` | high | no CVE anywhere | 0 | 0.7.4 |
| [GHSA-c6xv-pppp-rjw6](https://github.com/cosmos/evm/security/advisories/GHSA-c6xv-pppp-rjw6) | `go:github.com/cosmos/evm` | high | no CVE anywhere | 0 | 0.6.4, 0.7.4 |
| [GHSA-p8x8-4gg6-prcc](https://github.com/cosmos/evm/security/advisories/GHSA-p8x8-4gg6-prcc) | `go:github.com/cosmos/evm` | high | no CVE anywhere | 0 | 0.7.4, 0.6.4 |
| [GHSA-hq78-cm2m-h24h](https://github.com/craftcms/cms/security/advisories/GHSA-hq78-cm2m-h24h) | `composer:craftcms/cms` | high | no CVE anywhere | 0 | 5.11.4 |
| [GHSA-cphx-cx67-jcqj](https://github.com/craftcms/cms/security/advisories/GHSA-cphx-cx67-jcqj) | `composer:craftcms/cms` | high | no CVE anywhere | 0 | 5.11.5 |
| [GHSA-gg4r-jv3p-qx3c](https://github.com/Automattic/mongoose/security/advisories/GHSA-gg4r-jv3p-qx3c) | `npm:mongoose` | high | no CVE anywhere | 0 | ^6.13.12 || ^7.8.13 || ^8.24.7 || ^9.11. |
| [GHSA-8332-j7wj-wjw4](https://github.com/Automattic/mongoose/security/advisories/GHSA-8332-j7wj-wjw4) | `npm:mongoose` | high | no CVE anywhere | 0 | ^6.13.12 || ^7.8.13 || ^8.24.7 || ^9.11. |
| [GHSA-5r3c-5x4v-8gjh](https://github.com/vllm-project/vllm/security/advisories/GHSA-5r3c-5x4v-8gjh) | `pip:vllm` | high | no CVE anywhere | 0 | 0.33.0 |
| [GHSA-q9v9-qpjp-fc24](https://github.com/vllm-project/vllm/security/advisories/GHSA-q9v9-qpjp-fc24) | `pip:vllm` | high | no CVE anywhere | 0 | 0.33.0 |
| [GHSA-jc7w-vxj4-8phv](https://github.com/rubygems/rubygems.org/security/advisories/GHSA-jc7w-vxj4-8phv) | `rubygems:Registry` | high | no CVE anywhere | 0 | 162b883 |
| [GHSA-jpm2-x6wf-fxjc](https://github.com/nektos/act/security/advisories/GHSA-jpm2-x6wf-fxjc) | `go:github.com/nektos/act` | high | no CVE anywhere | 0 | 0.2.95 |
| [GHSA-828q-59cf-rgp5](https://github.com/tox-dev/python-discovery/security/advisories/GHSA-828q-59cf-rgp5) | `pip:python-discovery` | high | no CVE anywhere | 0 | 1.9.2 |
| [GHSA-gp2m-377p-m4j3](https://github.com/authlib/authlib/security/advisories/GHSA-gp2m-377p-m4j3) | `pip:authlib` | high | no CVE anywhere | 0 | 1.9.3 |
| [GHSA-xh2g-9hw9-mvp3](https://github.com/vert-x3/vertx-web/security/advisories/GHSA-xh2g-9hw9-mvp3) | `maven:io.vertx:vertx-web-client` | high | no CVE anywhere | 0 | 4.5.36, 5.2.3 |
| [GHSA-hwgg-pgp5-r4ch](https://github.com/authlib/joserfc/security/advisories/GHSA-hwgg-pgp5-r4ch) | `pip:joserfc` | high | no CVE anywhere | 0 | 1.7.6 |
| [GHSA-vvgp-wfq3-pjxj](https://github.com/authlib/joserfc/security/advisories/GHSA-vvgp-wfq3-pjxj) | `pip:joserfc` | high | no CVE anywhere | 0 | 1.7.7 |

…and 89 more (see the feed).

## CVE changes

| Advisory | Change |
|---|---|
| [GHSA-493h-fvcx-6q62](https://github.com/FOSSBilling/FOSSBilling/security/advisories/GHSA-493h-fvcx-6q62) | CVE-2026-111048 RESERVED -> PUBLISHED |
| [GHSA-8v98-cfpm-9p67](https://github.com/frappe/frappe/security/advisories/GHSA-8v98-cfpm-9p67) | cites CVE-2026-109601 (was none) |
| [GHSA-c88w-7h6p-27xr](https://github.com/element-hq/element-web/security/advisories/GHSA-c88w-7h6p-27xr) | cites CVE-2026-119407 (was none) |
| [GHSA-h5p6-j8m9-xx4p](https://github.com/octo-sts/app/security/advisories/GHSA-h5p6-j8m9-xx4p) | cites CVE-2026-105770 (was none) |
| [GHSA-rx38-p542-v527](https://github.com/altcha-org/altcha-lib/security/advisories/GHSA-rx38-p542-v527) | cites CVE-2026-119795 (was none) |
| [GHSA-wg9q-3w29-xv5q](https://github.com/error311/FileRise/security/advisories/GHSA-wg9q-3w29-xv5q) | cites CVE-2026-119796 (was none) |
| [GHSA-x2vm-cf3p-m2w8](https://github.com/libp2p/js-libp2p/security/advisories/GHSA-x2vm-cf3p-m2w8) | cites CVE-2026-119793 (was none) |
| [GHSA-x82x-2qj6-5rm2](https://github.com/rancher/rancher/security/advisories/GHSA-x82x-2qj6-5rm2) | CVE-2026-88811 RESERVED -> PUBLISHED |

## Longest waiting, published in the last 90 days

| Advisory | Package | Severity | CVE | Days | Fixed in |
|---|---|---|---|---:|---|
| [GHSA-g293-vf99-xv36](https://github.com/directus/directus/security/advisories/GHSA-g293-vf99-xv36) | `npm:directus` | high | no CVE anywhere | 89 | 12.1.0 |
| [GHSA-6rxf-4hh9-pp46](https://github.com/kimai/kimai/security/advisories/GHSA-6rxf-4hh9-pp46) | `composer:kimai/kimai` | low | CVE published by another CNA, not cited (CVE-2026-80195) | 89 | 2.63.0 |
| [GHSA-chfm-g7r3-vv42](https://github.com/directus/directus/security/advisories/GHSA-chfm-g7r3-vv42) | `npm:directus` | high | CVE published, cited (CVE-2026-10716) | 89 | 12.1.0 |
| [GHSA-wx94-r5p4-hx2f](https://github.com/mattiasw/ExifReader/security/advisories/GHSA-wx94-r5p4-hx2f) | `npm:exifreader` | high | no CVE anywhere | 89 | 4.42.0 |
| [GHSA-ff8w-8crv-9rcf](https://github.com/directus/directus/security/advisories/GHSA-ff8w-8crv-9rcf) | `npm:directus` | medium | no CVE anywhere | 89 | 12.1.0 |

591 advisories in limbo have waited more than a year.

## Coverage

Watchlist 18,656 repositories; 18,655 up to date on their schedule (daily for repos with an advisory in limbo, every 3 to 7 days for the rest); 4,435 checked in the last 24 hours; 37,509 reviewed advisories known. Every number is a floor: the tracker only sees repositories on its watchlist. Version ranges are as entered by maintainers and unreviewed.

_Advisory metadata from published GitHub repository security advisories and the GitHub Advisory Database (https://github.com/advisories, CC BY 4.0); CVE state from CVE Services; OSV.dev; NVD API (this product uses the NVD API but is not endorsed or certified by the NVD). Compiled by Limbowatch (https://limbo.watch), CC BY 4.0._
