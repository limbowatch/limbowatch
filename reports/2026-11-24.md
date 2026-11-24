# Limbo Tracker daily report — 2026-11-24

Generated 2026-11-24 18:21:52 UTC; changes since 2026-11-23 18:49:38 UTC.

## Now

- **12,048 advisories in limbo** (+188 since the last report: 182 newly published, 12 older ones found for the first time, 7 left limbo, 1 moved in from likely permanent): published by maintainers on GitHub, in ecosystems GitHub reviews, but not yet in GitHub's reviewed database or OSV.
  - 7,061 with no CVE anywhere · 552 citing a CVE that's still only reserved · 1,554 with a CVE from another CNA they don't cite
  - severity: 1,079 critical, 4,678 high, 5,084 medium, 1,207 low · median wait so far 53.3 days
- **16,456 more are likely permanent** (+79 since the last report: 64 newly published, 16 older ones found for the first time, 0 left limbo, 1 moved to the in-limbo count): in ecosystems GitHub doesn't review, so GitHub-based scanners will probably never see them.

## Since the last report

- **182 newly published** advisories entered limbo.
- 12 older advisories were found for the first time (11 in newly watched repos).
- **Left limbo** (likely permanent included): 7 reviewed by GitHub, 0 found to duplicate a reviewed advisory, 0 withdrawn or unpublished. GitHub reviewed 7 advisories in all in this period, from any repository.
- **CVE changes:** 46 (21 reserved CVEs published, 11 new CVEs from other CNAs).

## Newly published, in limbo

| Advisory | Package | Severity | CVE | Days | Fixed in |
|---|---|---|---|---:|---|
| [GHSA-hhqh-8jpj-27rf](https://github.com/LMCache/LMCache/security/advisories/GHSA-hhqh-8jpj-27rf) | `pip:lmcache` | critical | no CVE anywhere | 0 | `0.5.8` |
| [GHSA-mrhx-8xm7-chrq](https://github.com/wekan/wekan/security/advisories/GHSA-mrhx-8xm7-chrq) | `actions:wekan/wekan` | critical | no CVE anywhere | 0 | `9.96` |
| [GHSA-hgm3-wq4h-8vvq](https://github.com/geoserver/geoserver/security/advisories/GHSA-hgm3-wq4h-8vvq) | `maven:org.geoserver:gs-main` | critical | CVE reserved (RBP) (`CVE-2026-129245`) | 0 | `3.0.2, 2.28.6, 2.27.7` |
| [GHSA-7fw9-8x6m-w2wr](https://github.com/DIRACGrid/DIRAC/security/advisories/GHSA-7fw9-8x6m-w2wr) | `pip:dirac` | critical | no CVE anywhere | 0 | `v8.0.87, v9.0.30, v9.1.24` |
| [GHSA-jccq-v27v-rhjv](https://github.com/langroid/langroid/security/advisories/GHSA-jccq-v27v-rhjv) | `pip:langroid` | critical | no CVE anywhere | 0 | `0.70.4` |
| [GHSA-v48h-wg8v-4qxq](https://github.com/milvus-io/milvus/security/advisories/GHSA-v48h-wg8v-4qxq) | `go:github.com/milvus-io/milvus` | critical | no CVE anywhere | 0 | `2.6.25, 3.0.3` |
| [GHSA-952m-m7x7-mg46](https://github.com/elysiajs/elysia/security/advisories/GHSA-952m-m7x7-mg46) | `npm:elysia` | critical | no CVE anywhere | 0 | `1.4.31` |
| [GHSA-7f78-4837-6rc4](https://github.com/elysiajs/elysia/security/advisories/GHSA-7f78-4837-6rc4) | `npm:elysia` | critical | no CVE anywhere | 0 | `1.4.31` |
| [GHSA-g7gw-g6xr-hc3w](https://github.com/elysiajs/elysia/security/advisories/GHSA-g7gw-g6xr-hc3w) | `npm:elysia` | critical | no CVE anywhere | 0 | `1.4.31` |
| [GHSA-7jpf-w5v7-43vw](https://github.com/elysiajs/elysia/security/advisories/GHSA-7jpf-w5v7-43vw) | `npm:elysia` | critical | no CVE anywhere | 0 | `1.4.31` |
| [GHSA-8m2q-mx4w-gx5x](https://github.com/elysiajs/elysia/security/advisories/GHSA-8m2q-mx4w-gx5x) | `npm:elysia` | critical | no CVE anywhere | 0 | `1.4.31` |
| [GHSA-mmpg-3m88-65rj](https://github.com/elysiajs/elysia/security/advisories/GHSA-mmpg-3m88-65rj) | `npm:elysia` | critical | no CVE anywhere | 0 | `1.4.31` |
| [GHSA-g6c9-j4vm-mwq4](https://github.com/Graphify-Labs/graphify/security/advisories/GHSA-g6c9-j4vm-mwq4) | `pip:graphifyy` | high | no CVE anywhere | 1 | `0.9.115` |
| [GHSA-mwxj-5v28-gh2q](https://github.com/telegraphic/hickle/security/advisories/GHSA-mwxj-5v28-gh2q) | `pip:hickle` | high | CVE reserved (RBP) (`CVE-2026-103926`) | 1 | `5.0.4` |
| [GHSA-834p-3m5w-q478](https://github.com/AlaSQL/alasql/security/advisories/GHSA-834p-3m5w-q478) | `npm:alasql` | high | no CVE anywhere | 1 | `0.5.12, 0.6.9, 0.7.3, 1.7.7, 2.0.9, 2.1.` |
| [GHSA-h3g2-2pf7-h77p](https://github.com/gopcua/opcua/security/advisories/GHSA-h3g2-2pf7-h77p) | `go:github.com/gopcua/opcua` | high | no CVE anywhere | 1 | `0.9.2` |
| [GHSA-798p-q82c-7h3m](https://github.com/gopcua/opcua/security/advisories/GHSA-798p-q82c-7h3m) | `go:github.com/gopcua/opcua` | high | no CVE anywhere | 1 | `0.9.2` |
| [GHSA-rfmw-8v99-55q7](https://github.com/AlaSQL/alasql/security/advisories/GHSA-rfmw-8v99-55q7) | `npm:alasql` | high | no CVE anywhere | 1 | `4.21.1, 4.20.2, 4.19.2, 4.18.1, 4.17.4,` |
| [GHSA-5f96-p49v-qh87](https://github.com/savonrb/httpi/security/advisories/GHSA-5f96-p49v-qh87) | `rubygems:httpi` | high | no CVE anywhere | 1 | `4.1.0` |
| [GHSA-h3wp-2gww-26c4](https://github.com/google/conscrypt/security/advisories/GHSA-h3wp-2gww-26c4) | `maven:org.conscrypt:conscrypt-android, maven:org.conscryp…` | high | CVE reserved (RBP) (`CVE-2026-132784`) | 1 | `2.10.0` |
| [GHSA-3mxc-hm56-xrc9](https://github.com/FHIR/Ucum-java/security/advisories/GHSA-3mxc-hm56-xrc9) | `maven:org.fhir:ucum` | high | no CVE anywhere | 1 | `1.0.11` |
| [GHSA-xgf2-wxx4-3r42](https://github.com/tus/tusd/security/advisories/GHSA-xgf2-wxx4-3r42) | `go:github.com/tus/tusd/v2` | high | no CVE anywhere | 1 | `2.10.3` |
| [GHSA-xfcm-rmv3-crmq](https://github.com/Automattic/mongoose/security/advisories/GHSA-xfcm-rmv3-crmq) | `npm:mongoose` | high | no CVE anywhere | 0 | `^8.24.10 \|\| ^9.12.2` |
| [GHSA-wf3p-5g39-c599](https://github.com/ruvnet/RuVector/security/advisories/GHSA-wf3p-5g39-c599) | `npm:ruvector` | high | no CVE anywhere | 0 | `0.2.36` |
| [GHSA-26jc-7f59-gg92](https://github.com/ruvnet/RuVector/security/advisories/GHSA-26jc-7f59-gg92) | `npm:@ruvector/burst-scaling` | high | no CVE anywhere | 0 | `1.0.3` |

…and 157 more: [the tracker](https://limbo.watch/tracker/) lists them all, newest first.

## CVE changes

| Advisory | Change |
|---|---|
| [GHSA-24q6-6h89-f9p7](https://github.com/Significant-Gravitas/AutoGPT/security/advisories/GHSA-24q6-6h89-f9p7) | CVE-2026-130169 RESERVED -> PUBLISHED |
| [GHSA-3x2m-c67v-vw77](https://github.com/neuvector/neuvector/security/advisories/GHSA-3x2m-c67v-vw77) | CVE-2026-127182 RESERVED -> PUBLISHED |
| [GHSA-v7m5-cp6v-m46h](https://github.com/neuvector/neuvector/security/advisories/GHSA-v7m5-cp6v-m46h) | CVE-2026-127183 RESERVED -> PUBLISHED |
| [GHSA-3885-pq5f-788j](https://github.com/valkey-io/valkey/security/advisories/GHSA-3885-pq5f-788j) | CVE-2026-130822 RESERVED -> PUBLISHED |
| [GHSA-3c7g-v5hv-wwv4](https://github.com/Significant-Gravitas/AutoGPT/security/advisories/GHSA-3c7g-v5hv-wwv4) | CVE-2026-130178 RESERVED -> PUBLISHED |
| [GHSA-57mf-wqwq-6g6x](https://github.com/Significant-Gravitas/AutoGPT/security/advisories/GHSA-57mf-wqwq-6g6x) | CVE-2026-132257 RESERVED -> PUBLISHED |
| [GHSA-5pc2-f2v7-5w5p](https://github.com/rsyslog/rsyslog/security/advisories/GHSA-5pc2-f2v7-5w5p) | CVE-2026-129837 RESERVED -> PUBLISHED |
| [GHSA-6459-9m4c-jxhc](https://github.com/frappe/lms/security/advisories/GHSA-6459-9m4c-jxhc) | CVE-2026-75582 RESERVED -> PUBLISHED |
| [GHSA-f9hg-rj32-693x](https://github.com/rsyslog/rsyslog/security/advisories/GHSA-f9hg-rj32-693x) | CVE-2026-129833 RESERVED -> PUBLISHED |
| [GHSA-h3gv-c5rc-p453](https://github.com/react/react/security/advisories/GHSA-h3gv-c5rc-p453) | CVE-2026-130165 RESERVED -> PUBLISHED |
| [GHSA-hf7q-6hwp-f6v2](https://github.com/Significant-Gravitas/AutoGPT/security/advisories/GHSA-hf7q-6hwp-f6v2) | CVE-2026-133448 RESERVED -> PUBLISHED |
| [GHSA-m7qq-gm3x-v79g](https://github.com/n8n-io/n8n/security/advisories/GHSA-m7qq-gm3x-v79g) | CVE-2026-130166 RESERVED -> PUBLISHED |
| [GHSA-q8rc-7m84-mfvj](https://github.com/n8n-io/n8n/security/advisories/GHSA-q8rc-7m84-mfvj) | CVE-2026-130167 RESERVED -> PUBLISHED |
| [GHSA-x447-gqmh-6mcx](https://github.com/neuvector/neuvector/security/advisories/GHSA-x447-gqmh-6mcx) | CVE-2026-127181 RESERVED -> PUBLISHED |
| [GHSA-5cw8-qxqw-9j5w](https://github.com/neuvector/neuvector/security/advisories/GHSA-5cw8-qxqw-9j5w) | CVE-2026-127180 RESERVED -> PUBLISHED |
| [GHSA-6f2g-95mv-mgwv](https://github.com/Significant-Gravitas/AutoGPT/security/advisories/GHSA-6f2g-95mv-mgwv) | CVE-2026-129984 RESERVED -> PUBLISHED |
| [GHSA-7wwh-vfq4-v488](https://github.com/netbirdio/netbird/security/advisories/GHSA-7wwh-vfq4-v488) | CVE-2026-105428 RESERVED -> PUBLISHED |
| [GHSA-f3mw-f2qc-wh9m](https://github.com/Significant-Gravitas/AutoGPT/security/advisories/GHSA-f3mw-f2qc-wh9m) | CVE-2026-132270 RESERVED -> PUBLISHED |
| [GHSA-p835-fqv4-4x3m](https://github.com/Significant-Gravitas/AutoGPT/security/advisories/GHSA-p835-fqv4-4x3m) | CVE-2026-133455 RESERVED -> PUBLISHED |
| [GHSA-v5w2-pqxj-6r94](https://github.com/netbirdio/netbird/security/advisories/GHSA-v5w2-pqxj-6r94) | CVE-2026-105430 RESERVED -> PUBLISHED |
| [GHSA-48m5-pfp4-gcm9](https://github.com/netbirdio/netbird/security/advisories/GHSA-48m5-pfp4-gcm9) | CVE-2026-105431 RESERVED -> PUBLISHED |
| [GHSA-3r7g-mq96-7hhc](https://github.com/PyTables/PyTables/security/advisories/GHSA-3r7g-mq96-7hhc) | cites CVE-2026-134019 (was none) |
| [GHSA-7c2r-jhm9-43vf](https://github.com/pion/dtls/security/advisories/GHSA-7c2r-jhm9-43vf) | cites CVE-2026-135388 (was none) |
| [GHSA-hhpj-h56m-9f2p](https://github.com/pion/dtls/security/advisories/GHSA-hhpj-h56m-9f2p) | cites CVE-2026-135389 (was none) |
| [GHSA-6prc-h956-hxjq](https://github.com/symfony/symfony/security/advisories/GHSA-6prc-h956-hxjq) | cites CVE-2026-135803 (was none) |

…and 21 more.

## Longest waiting, published in the last 90 days

| Advisory | Package | Severity | CVE | Days | Fixed in |
|---|---|---|---|---:|---|
| [GHSA-9394-85jj-2mhj](https://github.com/davidjurgens/potato/security/advisories/GHSA-9394-85jj-2mhj) | `pip:potato-annotation` | high | no CVE anywhere | 89 | `2.8.2` |
| [GHSA-cm4p-5rfv-x252](https://github.com/davidjurgens/potato/security/advisories/GHSA-cm4p-5rfv-x252) | `pip:potato-annotation` | critical | no CVE anywhere | 89 | `2.8.1` |
| [GHSA-r4ww-vc5h-35qf](https://github.com/davidjurgens/potato/security/advisories/GHSA-r4ww-vc5h-35qf) | `pip:potato-annotation` | low | no CVE anywhere | 89 | `2.8.2` |
| [GHSA-634g-4wr8-xwxv](https://github.com/Guard-Core/guard-core/security/advisories/GHSA-634g-4wr8-xwxv) | `pip:guard-core` | high | no CVE anywhere | 89 | `3.14.0` |
| [GHSA-8xvm-856x-7hwp](https://github.com/Guard-Core/guard-core/security/advisories/GHSA-8xvm-856x-7hwp) | `pip:guard-core` | high | no CVE anywhere | 89 | `3.14.0` |

624 advisories in limbo have waited more than a year.

## Coverage

Watchlist 68,086 repositories; 68,086 up to date on their schedule (daily for repos with an advisory in limbo, every 3 days for other repos with advisories, every 30 days and after each release for the rest); 7,108 checked in the last 24 hours; 37,999 reviewed advisories known. Every number is a floor: the tracker only sees repositories on its watchlist. Version ranges are as entered by maintainers and unreviewed.

_Advisory metadata from published GitHub repository security advisories and the GitHub Advisory Database (https://github.com/advisories, CC BY 4.0); CVE state from CVE Services; OSV.dev; NVD API (this product uses the NVD API but is not endorsed or certified by the NVD). Compiled by Limbowatch (https://limbo.watch), CC BY 4.0._
