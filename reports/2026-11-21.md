# Limbo Tracker daily report — 2026-11-21

Generated 2026-11-21 15:08:57 UTC; changes since 2026-11-20 16:02:58 UTC.

## Now

- **11,515 advisories in limbo** (+107 since the last report: 86 newly published, 35 older ones found for the first time, 14 left limbo): published by maintainers on GitHub, in ecosystems GitHub reviews, but not yet in GitHub's reviewed database or OSV.
  - 6,726 with no CVE anywhere · 539 citing a CVE that's still only reserved · 1,429 with a CVE from another CNA they don't cite
  - severity: 1,051 critical, 4,509 high, 4,859 medium, 1,096 low · median wait so far 53.7 days
- **16,173 more are likely permanent** (+94 since the last report: 83 newly published, 11 older ones found for the first time, 0 left limbo): in ecosystems GitHub doesn't review, so GitHub-based scanners will probably never see them.

## Since the last report

- **86 newly published** advisories entered limbo.
- 35 older advisories were found for the first time (33 in newly watched repos).
- **Left limbo** (likely permanent included): 14 reviewed by GitHub, 0 found to duplicate a reviewed advisory, 0 withdrawn or unpublished. GitHub reviewed 20 advisories in all in this period, from any repository.
- **CVE changes:** 85 (57 reserved CVEs published, 9 new CVEs from other CNAs).

## Newly published, in limbo

| Advisory | Package | Severity | CVE | Days | Fixed in |
|---|---|---|---|---:|---|
| [GHSA-frgf-vm55-4hj8](https://github.com/jmaupetit/md2pdf/security/advisories/GHSA-frgf-vm55-4hj8) | `pip:md2pdf` | critical | no CVE anywhere | 1 | `5.0.0` |
| [GHSA-jg5c-8mvg-5wph](https://github.com/pnpm/pnpm/security/advisories/GHSA-jg5c-8mvg-5wph) | `npm:pnpm` | critical | no CVE anywhere | 0 | `12.10.0` |
| [GHSA-84w6-xrf3-f8q8](https://github.com/fastify/fastify-express/security/advisories/GHSA-84w6-xrf3-f8q8) | `npm:@fastify/express` | critical | CVE reserved (RBP) (`CVE-2026-133867`) | 0 | `4.0.10` |
| [GHSA-662w-h4p6-jq4p](https://github.com/fastify/fastify-express/security/advisories/GHSA-662w-h4p6-jq4p) | `npm:@fastify/express` | critical | CVE reserved (RBP) (`CVE-2026-124626`) | 0 | `4.0.10` |
| [GHSA-f44m-4qwg-5587](https://github.com/fastify/fastify-express/security/advisories/GHSA-f44m-4qwg-5587) | `npm:@fastify/express` | critical | CVE reserved (RBP) (`CVE-2026-129504`) | 0 | `4.0.10` |
| [GHSA-w877-hjcp-88rc](https://github.com/fastify/fastify-express/security/advisories/GHSA-w877-hjcp-88rc) | `npm:@fastify/express` | critical | CVE reserved (RBP) (`CVE-2026-133120`) | 0 | `4.0.10` |
| [GHSA-gcf6-j9m3-p97x](https://github.com/fastify/middie/security/advisories/GHSA-gcf6-j9m3-p97x) | `npm:@fastify/middie` | critical | CVE reserved (RBP) (`CVE-2026-133250`) | 0 | `9.3.8` |
| [GHSA-3x2m-c67v-vw77](https://github.com/neuvector/neuvector/security/advisories/GHSA-3x2m-c67v-vw77) | `go:github.com/neuvector/neuvector` | critical | CVE reserved (RBP) (`CVE-2026-127182`) | 0 | `5.7.0, 5.6.5, 5.5.6` |
| [GHSA-v7m5-cp6v-m46h](https://github.com/neuvector/neuvector/security/advisories/GHSA-v7m5-cp6v-m46h) | `go:github.com/neuvector/neuvector` | critical | CVE reserved (RBP) (`CVE-2026-127183`) | 0 | `5.7.0, 5.6.5, 5.5.6` |
| [GHSA-wxw8-4jgj-q85j](https://github.com/squidfunk/mkdocs-material/security/advisories/GHSA-wxw8-4jgj-q85j) | `pip:mkdocs-material` | high | no CVE anywhere | 1 | `9.8.2` |
| [GHSA-xg58-2j88-q7f7](https://github.com/ionic-team/ionicons/security/advisories/GHSA-xg58-2j88-q7f7) | `npm:ionicons` | high | no CVE anywhere | 1 | `8.1.1` |
| [GHSA-jpcj-2prg-452w](https://github.com/zaggino/z-schema/security/advisories/GHSA-jpcj-2prg-452w) | `npm:z-schema` | high | no CVE anywhere | 1 | `12.6.1` |
| [GHSA-fg36-9vq2-6v57](https://github.com/dagster-io/dagster/security/advisories/GHSA-fg36-9vq2-6v57) | `pip:dagster, pip:dagster-gcp, pip:dagster-snowflake, pip:…` | high | no CVE anywhere | 1 | `1.13.31, 0.29.31` |
| [GHSA-mcqj-j2jp-6gph](https://github.com/zaggino/z-schema/security/advisories/GHSA-mcqj-j2jp-6gph) | `npm:z-schema` | high | no CVE anywhere | 1 | `12.7.0` |
| [GHSA-65jr-3rqp-fpf9](https://github.com/zaggino/z-schema/security/advisories/GHSA-65jr-3rqp-fpf9) | `npm:z-schema` | high | no CVE anywhere | 1 | `12.7.0` |
| [GHSA-5vmc-qgf8-rw36](https://github.com/phoenixframework/phoenix/security/advisories/GHSA-5vmc-qgf8-rw36) | `erlang:phoenix` | high | CVE published, cited (`CVE-2026-129344`) | 0 | `1.5.16, 1.6.18, 1.7.25, 1.8.17` |
| [GHSA-pvfx-rx4x-phrr](https://github.com/phoenixframework/phoenix/security/advisories/GHSA-pvfx-rx4x-phrr) | `erlang:phoenix` | high | CVE published, cited (`CVE-2026-128361`) | 0 | `1.5.16, 1.6.18, 1.7.25, 1.8.17` |
| [GHSA-3php-fr37-9h54](https://github.com/storyblok/monoblok/security/advisories/GHSA-3php-fr37-9h54) | `npm:@storyblok/react` | high | no CVE anywhere | 0 | `4.7.1, 5.4.23, 6.1.12, 7.5.2` |
| [GHSA-987m-fcvp-pfxm](https://github.com/Project-MONAI/MONAI/security/advisories/GHSA-987m-fcvp-pfxm) | `pip:monai` | high | no CVE anywhere | 0 | `1.6.2` |
| [GHSA-95v4-gm26-h6xf](https://github.com/Project-MONAI/MONAI/security/advisories/GHSA-95v4-gm26-h6xf) | `pip:monai` | high | no CVE anywhere | 0 | `1.6.2` |
| [GHSA-8wp8-g6wq-2m6r](https://github.com/Project-MONAI/MONAI/security/advisories/GHSA-8wp8-g6wq-2m6r) | `pip:monai` | high | no CVE anywhere | 0 | `1.6.2` |
| [GHSA-4724-w94g-2rfp](https://github.com/Project-MONAI/MONAI/security/advisories/GHSA-4724-w94g-2rfp) | `pip:monai` | high | no CVE anywhere | 0 | `1.6.2` |
| [GHSA-vq3w-pqfr-2w2r](https://github.com/Project-MONAI/MONAI/security/advisories/GHSA-vq3w-pqfr-2w2r) | `pip:monai` | high | no CVE anywhere | 0 | `1.6.2` |
| [GHSA-ccjq-25j8-m4ph](https://github.com/zzet/gortex/security/advisories/GHSA-ccjq-25j8-m4ph) | `go:github.com/zzet/gortex` | high | no CVE anywhere | 0 | `–` |
| [GHSA-6rmc-f24g-hmp6](https://github.com/fastify/fastify-express/security/advisories/GHSA-6rmc-f24g-hmp6) | `npm:@fastify/express` | high | CVE reserved (RBP) (`CVE-2026-129850`) | 0 | `4.0.10` |

…and 61 more: [the tracker](https://limbo.watch/tracker/) lists them all, newest first.

## CVE changes

| Advisory | Change |
|---|---|
| [GHSA-662q-v5rm-78gm](https://github.com/nukeviet/nukeviet/security/advisories/GHSA-662q-v5rm-78gm) | CVE-2026-94565 RESERVED -> PUBLISHED |
| [GHSA-cp55-wmv6-wxpp](https://github.com/nukeviet/nukeviet/security/advisories/GHSA-cp55-wmv6-wxpp) | CVE-2026-94567 RESERVED -> PUBLISHED |
| [GHSA-mx78-9mrq-rfm5](https://github.com/fastify/fastify-reply-from/security/advisories/GHSA-mx78-9mrq-rfm5) | CVE-2026-133212 RESERVED -> PUBLISHED |
| [GHSA-25qc-m4pw-2w8r](https://github.com/Budibase/budibase/security/advisories/GHSA-25qc-m4pw-2w8r) | CVE-2026-122247 RESERVED -> PUBLISHED |
| [GHSA-2cvj-x8hg-6wcq](https://github.com/nukeviet/nukeviet/security/advisories/GHSA-2cvj-x8hg-6wcq) | CVE-2026-94597 RESERVED -> PUBLISHED |
| [GHSA-32jr-2xqg-gv48](https://github.com/Netatalk/netatalk/security/advisories/GHSA-32jr-2xqg-gv48) | CVE-2026-49387 RESERVED -> PUBLISHED |
| [GHSA-35qh-49hm-5rcx](https://github.com/MapServer/MapServer/security/advisories/GHSA-35qh-49hm-5rcx) | CVE-2026-77324 RESERVED -> PUBLISHED |
| [GHSA-42mm-6m68-h9g2](https://github.com/Netatalk/netatalk/security/advisories/GHSA-42mm-6m68-h9g2) | CVE-2026-62321 RESERVED -> PUBLISHED |
| [GHSA-4mwc-qc95-5959](https://github.com/MapServer/MapServer/security/advisories/GHSA-4mwc-qc95-5959) | CVE-2026-77326 RESERVED -> PUBLISHED |
| [GHSA-5fvw-g64v-r556](https://github.com/Netatalk/netatalk/security/advisories/GHSA-5fvw-g64v-r556) | CVE-2026-49388 RESERVED -> PUBLISHED |
| [GHSA-5wp7-47vr-j2mh](https://github.com/Netatalk/netatalk/security/advisories/GHSA-5wp7-47vr-j2mh) | CVE-2026-62318 RESERVED -> PUBLISHED |
| [GHSA-6fxm-h49m-4fg3](https://github.com/isomorphic-git/isomorphic-git/security/advisories/GHSA-6fxm-h49m-4fg3) | CVE-2026-77355 RESERVED -> PUBLISHED |
| [GHSA-7pv3-g7fw-7xhq](https://github.com/nukeviet/nukeviet/security/advisories/GHSA-7pv3-g7fw-7xhq) | CVE-2026-94564 RESERVED -> PUBLISHED |
| [GHSA-8xch-674f-grqr](https://github.com/nukeviet/nukeviet/security/advisories/GHSA-8xch-674f-grqr) | CVE-2026-94561 RESERVED -> PUBLISHED |
| [GHSA-9963-q595-wm2x](https://github.com/Netatalk/netatalk/security/advisories/GHSA-9963-q595-wm2x) | CVE-2026-45356 RESERVED -> PUBLISHED |
| [GHSA-9xfw-vx6g-wpmm](https://github.com/nukeviet/nukeviet/security/advisories/GHSA-9xfw-vx6g-wpmm) | CVE-2026-61832 RESERVED -> PUBLISHED |
| [GHSA-c4xr-7rr6-43mr](https://github.com/1Panel-dev/MaxKB/security/advisories/GHSA-c4xr-7rr6-43mr) | CVE-2026-129998 RESERVED -> PUBLISHED |
| [GHSA-gc94-xqg8-v8r7](https://github.com/logto-io/logto/security/advisories/GHSA-gc94-xqg8-v8r7) | CVE-2026-55216 RESERVED -> PUBLISHED |
| [GHSA-hjxg-4v29-j33c](https://github.com/nukeviet/nukeviet/security/advisories/GHSA-hjxg-4v29-j33c) | CVE-2026-94562 RESERVED -> PUBLISHED |
| [GHSA-p25r-m7hm-2rh2](https://github.com/Kovah/LinkAce/security/advisories/GHSA-p25r-m7hm-2rh2) | CVE-2026-104184 RESERVED -> PUBLISHED |
| [GHSA-p7cw-whjw-crcm](https://github.com/nukeviet/nukeviet/security/advisories/GHSA-p7cw-whjw-crcm) | CVE-2026-94598 RESERVED -> PUBLISHED |
| [GHSA-pvh8-4vwp-j58p](https://github.com/isomorphic-git/isomorphic-git/security/advisories/GHSA-pvh8-4vwp-j58p) | CVE-2026-86017 RESERVED -> PUBLISHED |
| [GHSA-qh43-24gm-5j57](https://github.com/LibreChat-AI/LibreChat/security/advisories/GHSA-qh43-24gm-5j57) | CVE-2026-54044 RESERVED -> PUBLISHED |
| [GHSA-qj62-fcj5-w24x](https://github.com/Netatalk/netatalk/security/advisories/GHSA-qj62-fcj5-w24x) | CVE-2026-103933 RESERVED -> PUBLISHED |
| [GHSA-r2q3-7m4h-63qg](https://github.com/Budibase/budibase/security/advisories/GHSA-r2q3-7m4h-63qg) | CVE-2026-122244 RESERVED -> PUBLISHED |

…and 60 more.

## Longest waiting, published in the last 90 days

| Advisory | Package | Severity | CVE | Days | Fixed in |
|---|---|---|---|---:|---|
| [GHSA-3hvv-wxpw-cx83](https://github.com/librenms/librenms/security/advisories/GHSA-3hvv-wxpw-cx83) | `librenms/librenms` | low | CVE published by another CNA, not cited (`CVE-2026-86427`) | 89 | `26.8.0` |
| [GHSA-275v-rxgc-4rcj](https://github.com/goshs-labs/goshs/security/advisories/GHSA-275v-rxgc-4rcj) | `go:goshs.de/goshs/v2` | high | no CVE anywhere | 89 | `v2.1.6` |
| [GHSA-ppmc-5w4w-2669](https://github.com/goshs-labs/goshs/security/advisories/GHSA-ppmc-5w4w-2669) | `go:goshs.de/goshs/v2` | high | no CVE anywhere | 89 | `v2.1.6` |
| [GHSA-2q29-798w-6qcp](https://github.com/goshs-labs/goshs/security/advisories/GHSA-2q29-798w-6qcp) | `go:goshs.de/goshs/v2` | high | no CVE anywhere | 89 | `v2.1.6` |
| [GHSA-whqg-vqcj-px54](https://github.com/goshs-labs/goshs/security/advisories/GHSA-whqg-vqcj-px54) | `go:goshs.de/goshs/v2` | medium | no CVE anywhere | 89 | `v2.1.6` |

613 advisories in limbo have waited more than a year.

## Coverage

Watchlist 67,965 repositories; 67,965 up to date on their schedule (daily for repos with an advisory in limbo, every 3 days for other repos with advisories, every 30 days and after each release for the rest); 7,056 checked in the last 24 hours; 37,989 reviewed advisories known. Every number is a floor: the tracker only sees repositories on its watchlist. Version ranges are as entered by maintainers and unreviewed.

_Advisory metadata from published GitHub repository security advisories and the GitHub Advisory Database (https://github.com/advisories, CC BY 4.0); CVE state from CVE Services; OSV.dev; NVD API (this product uses the NVD API but is not endorsed or certified by the NVD). Compiled by Limbowatch (https://limbo.watch), CC BY 4.0._
