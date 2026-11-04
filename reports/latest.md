# Limbo Tracker daily report — 2026-11-04

Generated 2026-11-04 14:51:55 UTC; changes since 2026-11-03 14:36:08 UTC.

## Now

- **8,518 advisories in limbo** (+164 since the last report: 163 newly published, 7 older ones found for the first time, 6 left limbo): published by maintainers on GitHub, in ecosystems GitHub reviews, but not yet in GitHub's reviewed database or OSV.
  - 4,464 with no CVE anywhere · 583 citing a CVE that's still only reserved · 1,065 with a CVE from another CNA they don't cite
  - severity: 881 critical, 3,358 high, 3,517 medium, 762 low · median wait so far 56.4 days
- **14,096 more are likely permanent** (+55 since the last report: 45 newly published, 11 older ones found for the first time, 1 left limbo): in ecosystems GitHub doesn't review, so GitHub-based scanners will probably never see them.

## Since the last report

- **163 newly published** advisories entered limbo.
- 7 older advisories were found for the first time (7 in newly watched repos).
- **Left limbo** (likely permanent included): 7 reviewed by GitHub, 0 found to duplicate a reviewed advisory, 0 withdrawn or unpublished.
- **CVE changes:** 100 (28 reserved CVEs published, 65 new CVEs from other CNAs).

## Newly published, in limbo

| Advisory | Package | Severity | CVE | Days | Fixed in |
|---|---|---|---|---:|---|
| [GHSA-p6c9-h3f7-xq9f](https://github.com/goshs-labs/goshs/security/advisories/GHSA-p6c9-h3f7-xq9f) | `go:goshs.de/goshs/v2` | critical | no CVE anywhere | 0 | v2.1.8 |
| [GHSA-8mf3-p375-389g](https://github.com/gina-io/swig/security/advisories/GHSA-8mf3-p375-389g) | `npm:@rhinostone/swig, npm:@rhinostone/swig-core, npm:@rhi…` | critical | no CVE anywhere | 0 | 2.12.1 |
| [GHSA-4wq4-2ppv-q3hg](https://github.com/better-auth/better-auth/security/advisories/GHSA-4wq4-2ppv-q3hg) | `npm:@better-auth/expo, npm:better-auth` | critical | CVE published by another CNA, not cited (CVE-2026-121802) | 0 | 1.7.16, 1.8.0-beta.5 |
| [GHSA-7jp3-2229-xgqj](https://github.com/openremote/core/security/advisories/GHSA-7jp3-2229-xgqj) | `maven:io.openremote:openremote-manager` | critical | no CVE anywhere | 0 | 1.34.0 |
| [GHSA-m7pm-7jm9-cfp4](https://github.com/node-opcua/node-opcua/security/advisories/GHSA-m7pm-7jm9-cfp4) | `npm:node-opcua-pki` | critical | no CVE anywhere | 0 | 6.22.1, 7.0.0 |
| [GHSA-gx67-694c-655c](https://github.com/team-alembic/ash_authentication/security/advisories/GHSA-gx67-694c-655c) | `erlang:ash_authentication` | high | CVE published, cited (CVE-2026-119215) | 0 | 5.0.0-rc.16 |
| [GHSA-7r2m-g5wf-pj9j](https://github.com/surrealdb/surrealdb/security/advisories/GHSA-7r2m-g5wf-pj9j) | `rust:surrealdb` | high | no CVE anywhere | 0 | 4.0.0 |
| [GHSA-fq69-wr4w-v3gm](https://github.com/surrealdb/surrealdb/security/advisories/GHSA-fq69-wr4w-v3gm) | `rust:surrealdb` | high | no CVE anywhere | 0 | 4.0.0 |
| [GHSA-5w6j-qm42-4rc2](https://github.com/surrealdb/surrealdb/security/advisories/GHSA-5w6j-qm42-4rc2) | `rust:surrealdb` | high | no CVE anywhere | 0 | 4.0.0 |
| [GHSA-cr79-9p8r-p5wx](https://github.com/surrealdb/surrealdb/security/advisories/GHSA-cr79-9p8r-p5wx) | `rust:surrealdb` | high | no CVE anywhere | 0 | 4.0.0 |
| [GHSA-p3c2-wh5f-jwqm](https://github.com/surrealdb/surrealdb/security/advisories/GHSA-p3c2-wh5f-jwqm) | `rust:surrealdb` | high | no CVE anywhere | 0 | 4.0.0 |
| [GHSA-fh2q-8f75-m4h6](https://github.com/surrealdb/surrealdb/security/advisories/GHSA-fh2q-8f75-m4h6) | `rust:surrealdb` | high | no CVE anywhere | 0 | 4.0.0 |
| [GHSA-7pqw-x84x-frxc](https://github.com/surrealdb/surrealdb/security/advisories/GHSA-7pqw-x84x-frxc) | `rust:surrealdb` | high | no CVE anywhere | 0 | 4.0.0 |
| [GHSA-6c37-x4jm-529x](https://github.com/surrealdb/surrealdb/security/advisories/GHSA-6c37-x4jm-529x) | `rust:surrealdb` | high | no CVE anywhere | 0 | 4.0.0 |
| [GHSA-cph5-pm57-9w9c](https://github.com/surrealdb/surrealdb/security/advisories/GHSA-cph5-pm57-9w9c) | `rust:surrealdb` | high | no CVE anywhere | 0 | 4.0.0 |
| [GHSA-5xcv-fm6g-4hf3](https://github.com/surrealdb/surrealdb/security/advisories/GHSA-5xcv-fm6g-4hf3) | `rust:surrealdb` | high | no CVE anywhere | 0 | 4.0.0 |
| [GHSA-q83r-f38r-rwvj](https://github.com/surrealdb/surrealdb/security/advisories/GHSA-q83r-f38r-rwvj) | `rust:surrealdb-core` | high | no CVE anywhere | 0 | 4.0.0 |
| [GHSA-m9qr-4rcq-3jhc](https://github.com/surrealdb/surrealdb/security/advisories/GHSA-m9qr-4rcq-3jhc) | `rust:surrealdb-core` | high | no CVE anywhere | 0 | 4.0.0 |
| [GHSA-9fm9-c4h4-8g93](https://github.com/surrealdb/surrealdb/security/advisories/GHSA-9fm9-c4h4-8g93) | `rust:surrealkv` | high | no CVE anywhere | 0 | 1.2.0 |
| [GHSA-9j7q-g3ch-2283](https://github.com/nektos/act/security/advisories/GHSA-9j7q-g3ch-2283) | `go:github.com/nektos/act` | high | no CVE anywhere | 0 | 0.2.96 |
| [GHSA-vqhw-xhff-464q](https://github.com/langroid/langroid/security/advisories/GHSA-vqhw-xhff-464q) | `pip:langroid` | high | no CVE anywhere | 0 | 0.69.19 |
| [GHSA-jm8m-792v-c66w](https://github.com/madeofpendletonwool/PinePods/security/advisories/GHSA-jm8m-792v-c66w) | `rust:pinepods` | high | CVE reserved (RBP) (CVE-2026-68504) | 0 | 0.9.1 |
| [GHSA-3rqp-8h7g-xxv8](https://github.com/getgrav/grav/security/advisories/GHSA-3rqp-8h7g-xxv8) | `composer:getgrav/grav-plugin-api` | high | no CVE anywhere | 0 | 1.1.4 |
| [GHSA-g5h5-fp5g-fmx4](https://github.com/cc-tweaked/CC-Tweaked/security/advisories/GHSA-g5h5-fp5g-fmx4) | `maven:cc.tweaked:cc-tweaked-1.20.1-core, maven:cc.tweaked…` | high | no CVE anywhere | 0 | 1.121.0 |
| [GHSA-q747-mqgr-4gh7](https://github.com/better-auth/better-auth/security/advisories/GHSA-q747-mqgr-4gh7) | `npm:better-auth` | high | no CVE anywhere | 0 | 1.7.16, 1.8.0-beta.5 |

…and 138 more (see the feed).

## CVE changes

| Advisory | Change |
|---|---|
| [GHSA-23wx-88m8-pfm2](https://github.com/AzuraCast/AzuraCast/security/advisories/GHSA-23wx-88m8-pfm2) | new CVE from another CNA: CVE-2026-121428 |
| [GHSA-2c9x-4gr7-hrwx](https://github.com/FreeRDP/FreeRDP/security/advisories/GHSA-2c9x-4gr7-hrwx) | new CVE from another CNA: CVE-2026-121406 |
| [GHSA-2j2x-c587-q33g](https://github.com/parse-community/parse-server/security/advisories/GHSA-2j2x-c587-q33g) | new CVE from another CNA: CVE-2026-121413 |
| [GHSA-2wcv-vv3g-g86q](https://github.com/AzuraCast/AzuraCast/security/advisories/GHSA-2wcv-vv3g-g86q) | new CVE from another CNA: CVE-2026-121427 |
| [GHSA-34r4-95hx-gxqr](https://github.com/yeti-platform/yeti/security/advisories/GHSA-34r4-95hx-gxqr) | CVE-2026-63482 RESERVED -> PUBLISHED |
| [GHSA-3hf9-w6hr-hf9j](https://github.com/FreeRDP/FreeRDP/security/advisories/GHSA-3hf9-w6hr-hf9j) | new CVE from another CNA: CVE-2026-121409 |
| [GHSA-3vh3-jf65-656w](https://github.com/darylldoyle/svg-sanitizer/security/advisories/GHSA-3vh3-jf65-656w) | new CVE from another CNA: CVE-2026-121446 |
| [GHSA-47p6-w2rc-5qf7](https://github.com/lepture/mistune/security/advisories/GHSA-47p6-w2rc-5qf7) | new CVE from another CNA: CVE-2026-121438 |
| [GHSA-4p2j-qj3c-6x84](https://github.com/anthropics/claude-code/security/advisories/GHSA-4p2j-qj3c-6x84) | CVE-2026-88066 RESERVED -> PUBLISHED |
| [GHSA-4p53-46xw-7mx2](https://github.com/stape-io/gtm-server-side-wordpress-plugin/security/advisories/GHSA-4p53-46xw-7mx2) | CVE-2026-118422 RESERVED -> PUBLISHED |
| [GHSA-4q3w-w2g5-8wqq](https://github.com/yeti-platform/yeti/security/advisories/GHSA-4q3w-w2g5-8wqq) | CVE-2026-63502 RESERVED -> PUBLISHED |
| [GHSA-4vh4-3pc3-32p7](https://github.com/FreeRDP/FreeRDP/security/advisories/GHSA-4vh4-3pc3-32p7) | new CVE from another CNA: CVE-2026-121399 |
| [GHSA-532v-ccph-m3xg](https://github.com/nocodb/nocodb/security/advisories/GHSA-532v-ccph-m3xg) | new CVE from another CNA: CVE-2026-121736 |
| [GHSA-5fm2-8wxf-xc5v](https://github.com/froxlor/froxlor/security/advisories/GHSA-5fm2-8wxf-xc5v) | new CVE from another CNA: CVE-2026-121436 |
| [GHSA-5j39-x36c-x9pm](https://github.com/FreeRDP/FreeRDP/security/advisories/GHSA-5j39-x36c-x9pm) | new CVE from another CNA: CVE-2026-121394 |
| [GHSA-5qqp-5ffm-m3p9](https://github.com/FreeRDP/FreeRDP/security/advisories/GHSA-5qqp-5ffm-m3p9) | new CVE from another CNA: CVE-2026-121403 |
| [GHSA-5x35-83gj-w8gw](https://github.com/AzuraCast/AzuraCast/security/advisories/GHSA-5x35-83gj-w8gw) | new CVE from another CNA: CVE-2026-121433 |
| [GHSA-5xjx-9qx6-jcrv](https://github.com/anthropics/claude-code/security/advisories/GHSA-5xjx-9qx6-jcrv) | CVE-2026-88968 RESERVED -> PUBLISHED |
| [GHSA-6437-7wc6-gmx5](https://github.com/HumanSignal/label-studio/security/advisories/GHSA-6437-7wc6-gmx5) | new CVE from another CNA: CVE-2026-121561 |
| [GHSA-655c-2xf3-77x9](https://github.com/parse-community/parse-server/security/advisories/GHSA-655c-2xf3-77x9) | new CVE from another CNA: CVE-2026-121415 |
| [GHSA-66mr-7wc7-23vc](https://github.com/FreeRDP/FreeRDP/security/advisories/GHSA-66mr-7wc7-23vc) | new CVE from another CNA: CVE-2026-121389 |
| [GHSA-6p3w-fv52-cf24](https://github.com/FreeRDP/FreeRDP/security/advisories/GHSA-6p3w-fv52-cf24) | new CVE from another CNA: CVE-2026-121396 |
| [GHSA-6vjr-55fw-r5x2](https://github.com/froxlor/froxlor/security/advisories/GHSA-6vjr-55fw-r5x2) | new CVE from another CNA: CVE-2026-121435 |
| [GHSA-6w3r-6hpr-hp6p](https://github.com/Agamnentzar/ag-psd/security/advisories/GHSA-6w3r-6hpr-hp6p) | CVE-2026-63501 RESERVED -> PUBLISHED |
| [GHSA-6xf2-8436-rgvf](https://github.com/yeti-platform/yeti/security/advisories/GHSA-6xf2-8436-rgvf) | CVE-2026-63500 RESERVED -> PUBLISHED |

…and 75 more.

## Longest waiting, published in the last 90 days

| Advisory | Package | Severity | CVE | Days | Fixed in |
|---|---|---|---|---:|---|
| [GHSA-5f8w-f448-47cj](https://github.com/spring-ai-community/mcp-security/security/advisories/GHSA-5f8w-f448-47cj) | `maven:org.springaicommunity:mcp-client-security` | medium | no CVE anywhere | 89 | 0.1.14 |
| [GHSA-fp4j-ff6j-9793](https://github.com/vendurehq/vendure/security/advisories/GHSA-fp4j-ff6j-9793) | `npm:@vendure/core` | medium | no CVE anywhere | 89 | 3.7.2 |
| [GHSA-rgjm-ff27-p2hf](https://github.com/vendurehq/vendure/security/advisories/GHSA-rgjm-ff27-p2hf) | `npm:@vendure/core` | medium | no CVE anywhere | 89 | 3.7.2 |
| [GHSA-w3hf-fcg5-p4cc](https://github.com/simonw/datasette/security/advisories/GHSA-w3hf-fcg5-p4cc) | `pip:datasette` | high | no CVE anywhere | 89 | 0.65.3, 1.0a38 |
| [GHSA-5784-6qcr-48fq](https://github.com/authzed/spicedb/security/advisories/GHSA-5784-6qcr-48fq) | `docker:authzed/spicedb, go:github.com/authzed/spicedb` | low | no CVE anywhere | 89 | v1.56.0 |

591 advisories in limbo have waited more than a year.

## Coverage

Watchlist 18,661 repositories; 6,616 up to date on their schedule (daily for repos with an advisory in limbo, every 3 to 7 days for the rest); 4,574 checked in the last 24 hours; the last run stopped early (budget); 37,519 reviewed advisories known. Every number is a floor: the tracker only sees repositories on its watchlist. Version ranges are as entered by maintainers and unreviewed.

_Advisory metadata from published GitHub repository security advisories and the GitHub Advisory Database (https://github.com/advisories, CC BY 4.0); CVE state from CVE Services; OSV.dev; NVD API (this product uses the NVD API but is not endorsed or certified by the NVD). Compiled by Limbowatch (https://limbo.watch), CC BY 4.0._
