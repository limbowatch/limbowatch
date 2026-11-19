# Limbo Tracker daily report — 2026-11-19

Generated 2026-11-19 16:12:10 UTC; changes since 2026-11-18 16:13:13 UTC.

## Now

- **11,253 advisories in limbo** (+236 since the last report: 189 newly published, 57 older ones found for the first time, 10 left limbo): published by maintainers on GitHub, in ecosystems GitHub reviews, but not yet in GitHub's reviewed database or OSV.
  - 6,434 with no CVE anywhere · 598 citing a CVE that's still only reserved · 1,416 with a CVE from another CNA they don't cite
  - severity: 1,028 critical, 4,418 high, 4,745 medium, 1,062 low · median wait so far 52.9 days
- **15,942 more are likely permanent** (+190 since the last report: 102 newly published, 91 older ones found for the first time, 3 left limbo): in ecosystems GitHub doesn't review, so GitHub-based scanners will probably never see them.

## Since the last report

- **189 newly published** advisories entered limbo.
- 57 older advisories were found for the first time (42 in newly watched repos).
- **Left limbo** (likely permanent included): 12 reviewed by GitHub, 1 found to duplicate a reviewed advisory, 0 withdrawn or unpublished. GitHub reviewed 19 advisories in all in this period, from any repository.
- **CVE changes:** 96 (46 reserved CVEs published, 42 new CVEs from other CNAs).

## Newly published, in limbo

| Advisory | Package | Severity | CVE | Days | Fixed in |
|---|---|---|---|---:|---|
| [GHSA-v36f-rjg3-3v46](https://github.com/faye/websocket-driver-node/security/advisories/GHSA-v36f-rjg3-3v46) | `npm:websocket-driver` | critical | no CVE anywhere | 1 | `0.8.0` |
| [GHSA-pg9p-672x-44jc](https://github.com/markabrahams/node-net-snmp/security/advisories/GHSA-pg9p-672x-44jc) | `npm:net-snmp` | critical | no CVE anywhere | 1 | `3.29.3` |
| [GHSA-7q35-5h53-wm34](https://github.com/julianhille/MuhammaraJS/security/advisories/GHSA-7q35-5h53-wm34) | `npm:@muhammara/native, npm:@muhammara/native-with-source,…` | critical | no CVE anywhere | 0 | `7.2.4, 1.2.4` |
| [GHSA-wqwr-83qv-cqpp](https://github.com/shopperlabs/shopper/security/advisories/GHSA-wqwr-83qv-cqpp) | `composer:shopper/framework` | critical | no CVE anywhere | 0 | `2.11.2, 3.0.0-beta.6` |
| [GHSA-vx6h-9344-wxcg](https://github.com/shopperlabs/shopper/security/advisories/GHSA-vx6h-9344-wxcg) | `composer:shopper/framework` | critical | no CVE anywhere | 0 | `2.11.2, 3.0.0-beta.6` |
| [GHSA-qr43-hv93-6x7p](https://github.com/LMCache/LMCache/security/advisories/GHSA-qr43-hv93-6x7p) | `pip:lmcache` | critical | no CVE anywhere | 0 | `0.5.7` |
| [GHSA-fqv4-9pm4-v2q2](https://github.com/getgrav/grav/security/advisories/GHSA-fqv4-9pm4-v2q2) | `composer:getgrav/grav-plugin-api` | critical | no CVE anywhere | 0 | `1.1.21` |
| [GHSA-pqgf-g7m7-vh98](https://github.com/OpenMage/magento-lts/security/advisories/GHSA-pqgf-g7m7-vh98) | `composer:openmage/magento-lts` | critical | no CVE anywhere | 0 | `20.18.3, 20.19.1, 21.0.0-beta4` |
| [GHSA-2223-v44q-q2hc](https://github.com/FabianRolfMatthiasNoll/MyMangaDB/security/advisories/GHSA-2223-v44q-q2hc) | `pip:fabianrolfmatthiasnoll/mymangadb` | critical | no CVE anywhere | 0 | `2.8.5` |
| [GHSA-rch3-xxjq-365j](https://github.com/apple/swift-crypto/security/advisories/GHSA-rch3-xxjq-365j) | `swift:swift-crypto` | critical | no CVE anywhere | 0 | `5.1.2` |
| [GHSA-p26w-9mq2-6cf7](https://github.com/WWBN/AVideo/security/advisories/GHSA-p26w-9mq2-6cf7) | `composer:wwbn/avideo` | critical | no CVE anywhere | 0 | `–` |
| [GHSA-9g4r-f5gq-qjrr](https://github.com/faye/websocket-driver-node/security/advisories/GHSA-9g4r-f5gq-qjrr) | `npm:websocket-driver` | high | no CVE anywhere | 1 | `0.8.0` |
| [GHSA-c4gv-fww2-jp3r](https://github.com/faye/websocket-driver-node/security/advisories/GHSA-c4gv-fww2-jp3r) | `npm:websocket-driver` | high | no CVE anywhere | 1 | `0.8.0` |
| [GHSA-2wfx-5gcf-mprw](https://github.com/open-feature/flagd/security/advisories/GHSA-2wfx-5gcf-mprw) | `go:github.com/open-feature/flagd/core, go:github.com/open…` | high | no CVE anywhere | 1 | `0.15.8, 0.19.0, 0.15.9, 0.19.3, 0.8.1` |
| [GHSA-9qwq-36xr-2436](https://github.com/aws/efs-utils/security/advisories/GHSA-9qwq-36xr-2436) | `rust:Amazon efs-utils` | high | CVE published, cited (`CVE-2026-130621`) | 1 | `v3.3.5` |
| [GHSA-769w-vfpw-g8c8](https://github.com/kelvinmo/simplejwt/security/advisories/GHSA-769w-vfpw-g8c8) | `composer:kelvinmo/simplejwt` | high | no CVE anywhere | 1 | `1.1.3` |
| [GHSA-f56c-v883-vx8r](https://github.com/fastapi/fastapi/security/advisories/GHSA-f56c-v883-vx8r) | `pip:fastapi` | high | no CVE anywhere | 1 | `0.163.2` |
| [GHSA-v472-jp5g-c53f](https://github.com/ddnexus/pagy/security/advisories/GHSA-v472-jp5g-c53f) | `rubygems:pagy` | high | no CVE anywhere | 1 | `43.8.3` |
| [GHSA-5vm7-vc2x-p3w2](https://github.com/jaydenseric/graphql-upload/security/advisories/GHSA-5vm7-vc2x-p3w2) | `npm:graphql-upload` | high | no CVE anywhere | 1 | `–` |
| [GHSA-jjpx-x4gm-m546](https://github.com/markabrahams/node-net-snmp/security/advisories/GHSA-jjpx-x4gm-m546) | `npm:net-snmp` | high | no CVE anywhere | 1 | `3.29.3` |
| [GHSA-f9vc-qvc8-p7cf](https://github.com/gogs/gogs/security/advisories/GHSA-f9vc-qvc8-p7cf) | `go:gogs.io/gogs` | high | no CVE anywhere | 0 | `0.15.0+dev` |
| [GHSA-j9x8-49mc-xpgh](https://github.com/mercurius-js/mercurius/security/advisories/GHSA-j9x8-49mc-xpgh) | `npm:mercurius` | high | no CVE anywhere | 0 | `16.12.2` |
| [GHSA-fwgf-gjvf-62q6](https://github.com/endatix/endatix/security/advisories/GHSA-fwgf-gjvf-62q6) | `nuget:Endatix.Infrastructure, other:endatix-api docker image` | high | no CVE anywhere | 0 | `0.9.2` |
| [GHSA-2prw-vqf5-g6cv](https://github.com/endatix/endatix/security/advisories/GHSA-2prw-vqf5-g6cv) | `nuget:Endatix.Api, nuget:Endatix.Infrastructure` | high | no CVE anywhere | 0 | `0.9.2` |
| [GHSA-6972-pq3q-8w9r](https://github.com/gogs/gogs/security/advisories/GHSA-6972-pq3q-8w9r) | `go:gogs.io/gogs` | high | no CVE anywhere | 0 | `0.15.0+dev` |

…and 164 more: [the tracker](https://limbo.watch/tracker/) lists them all, newest first.

## CVE changes

| Advisory | Change |
|---|---|
| [GHSA-2gq3-9q77-8hgv](https://github.com/Dokploy/dokploy/security/advisories/GHSA-2gq3-9q77-8hgv) | CVE-2026-129991 RESERVED -> PUBLISHED |
| [GHSA-8m32-h7qx-8r79](https://github.com/Dokploy/dokploy/security/advisories/GHSA-8m32-h7qx-8r79) | CVE-2026-129985 RESERVED -> PUBLISHED |
| [GHSA-945r-hp2m-928m](https://github.com/Dokploy/dokploy/security/advisories/GHSA-945r-hp2m-928m) | CVE-2026-129986 RESERVED -> PUBLISHED |
| [GHSA-97gp-5f3j-vwqr](https://github.com/chamilo/chamilo-lms/security/advisories/GHSA-97gp-5f3j-vwqr) | CVE-2026-61532 RESERVED -> PUBLISHED |
| [GHSA-98j8-6vjr-c3xw](https://github.com/Dokploy/dokploy/security/advisories/GHSA-98j8-6vjr-c3xw) | CVE-2026-129989 RESERVED -> PUBLISHED |
| [GHSA-9932-qg8x-pr32](https://github.com/Dokploy/dokploy/security/advisories/GHSA-9932-qg8x-pr32) | CVE-2026-129987 RESERVED -> PUBLISHED |
| [GHSA-gxjg-q5fc-94q3](https://github.com/wavelog/wavelog/security/advisories/GHSA-gxjg-q5fc-94q3) | CVE-2026-55506 RESERVED -> PUBLISHED |
| [GHSA-pwg8-2x8c-wc2m](https://github.com/Dokploy/dokploy/security/advisories/GHSA-pwg8-2x8c-wc2m) | CVE-2026-129316 RESERVED -> PUBLISHED |
| [GHSA-rrrq-ch2q-pqmp](https://github.com/wavelog/wavelog/security/advisories/GHSA-rrrq-ch2q-pqmp) | CVE-2026-55508 RESERVED -> PUBLISHED |
| [GHSA-28r7-prwc-hf5c](https://github.com/samtools/htslib/security/advisories/GHSA-28r7-prwc-hf5c) | CVE-2026-62255 RESERVED -> PUBLISHED |
| [GHSA-2jx2-wm7f-rv9m](https://github.com/samtools/htslib/security/advisories/GHSA-2jx2-wm7f-rv9m) | CVE-2026-62258 RESERVED -> PUBLISHED |
| [GHSA-2wm6-8hgm-7g92](https://github.com/samtools/htslib/security/advisories/GHSA-2wm6-8hgm-7g92) | CVE-2026-63390 RESERVED -> PUBLISHED |
| [GHSA-39qq-f7xc-9w6q](https://github.com/chamilo/chamilo-lms/security/advisories/GHSA-39qq-f7xc-9w6q) | CVE-2026-61578 RESERVED -> PUBLISHED |
| [GHSA-3wm4-r2jj-43pp](https://github.com/OSC/ondemand/security/advisories/GHSA-3wm4-r2jj-43pp) | CVE-2026-55171 RESERVED -> PUBLISHED |
| [GHSA-4hjq-r829-8c8v](https://github.com/samtools/htslib/security/advisories/GHSA-4hjq-r829-8c8v) | CVE-2026-62256 RESERVED -> PUBLISHED |
| [GHSA-6q7c-m967-9v37](https://github.com/samtools/htslib/security/advisories/GHSA-6q7c-m967-9v37) | CVE-2026-62257 RESERVED -> PUBLISHED |
| [GHSA-6qwh-9m43-gx3q](https://github.com/chamilo/chamilo-lms/security/advisories/GHSA-6qwh-9m43-gx3q) | CVE-2026-61584 RESERVED -> PUBLISHED |
| [GHSA-7fhg-337c-qvf7](https://github.com/chamilo/chamilo-lms/security/advisories/GHSA-7fhg-337c-qvf7) | CVE-2026-61528 RESERVED -> PUBLISHED |
| [GHSA-82w8-65qw-gch6](https://github.com/altcha-org/altcha-lib-php/security/advisories/GHSA-82w8-65qw-gch6) | CVE-2026-71481 RESERVED -> PUBLISHED |
| [GHSA-853c-q5q4-jm2c](https://github.com/chamilo/chamilo-lms/security/advisories/GHSA-853c-q5q4-jm2c) | CVE-2026-61583 RESERVED -> PUBLISHED |
| [GHSA-88q3-gch3-5396](https://github.com/uhop/install-artifact-from-github/security/advisories/GHSA-88q3-gch3-5396) | CVE-2026-73864 RESERVED -> PUBLISHED |
| [GHSA-cjp7-8r57-vc8f](https://github.com/music-assistant/server/security/advisories/GHSA-cjp7-8r57-vc8f) | CVE-2026-73971 RESERVED -> PUBLISHED |
| [GHSA-h8qx-4jh5-pf43](https://github.com/DataDog/datadog-agent/security/advisories/GHSA-h8qx-4jh5-pf43) | CVE-2026-61581 RESERVED -> PUBLISHED |
| [GHSA-j282-pjg5-j643](https://github.com/pavlo-v-chernykh/keystore-go/security/advisories/GHSA-j282-pjg5-j643) | CVE-2026-76101 RESERVED -> PUBLISHED |
| [GHSA-jv7g-9ff9-6cc5](https://github.com/chamilo/chamilo-lms/security/advisories/GHSA-jv7g-9ff9-6cc5) | CVE-2026-54747 RESERVED -> PUBLISHED |

…and 71 more.

## Longest waiting, published in the last 90 days

| Advisory | Package | Severity | CVE | Days | Fixed in |
|---|---|---|---|---:|---|
| [GHSA-j87f-x5h5-gr75](https://github.com/langchain-ai/langgraphjs/security/advisories/GHSA-j87f-x5h5-gr75) | `npm:@langchain/langgraph, npm:@langchain/langgraph-checkp…` | high | no CVE anywhere | 89 | `0.4.10, 0.1.3, 1.4.12, 1.1.4` |
| [GHSA-h7xh-9h2x-2m37](https://github.com/cakephp/authentication/security/advisories/GHSA-h7xh-9h2x-2m37) | `composer:cakephp/authentication` | critical | CVE published, cited (`CVE-2026-77337`) | 89 | `2.11.2, 3.3.7, 4.2.1` |
| [GHSA-8c32-52rh-j928](https://github.com/textile/php-textile/security/advisories/GHSA-8c32-52rh-j928) | `composer:netcarver/textile` | high | no CVE anywhere | 89 | `4.1.5` |
| [GHSA-p4cq-83j9-7g73](https://github.com/wekan/wekan/security/advisories/GHSA-p4cq-83j9-7g73) | `actions:wekan/wekan` | medium | no CVE anywhere | 89 | `11.07` |
| [GHSA-fpm6-r5fg-2mrg](https://github.com/wekan/wekan/security/advisories/GHSA-fpm6-r5fg-2mrg) | `actions:wekan/wekan` | medium | no CVE anywhere | 89 | `11.07` |

609 advisories in limbo have waited more than a year.

## Coverage

Watchlist 67,882 repositories; 67,882 up to date on their schedule (daily for repos with an advisory in limbo, every 3 days for other repos with advisories, every 30 days and after each release for the rest); 6,124 checked in the last 24 hours; 37,853 reviewed advisories known. Every number is a floor: the tracker only sees repositories on its watchlist. Version ranges are as entered by maintainers and unreviewed.

_Advisory metadata from published GitHub repository security advisories and the GitHub Advisory Database (https://github.com/advisories, CC BY 4.0); CVE state from CVE Services; OSV.dev; NVD API (this product uses the NVD API but is not endorsed or certified by the NVD). Compiled by Limbowatch (https://limbo.watch), CC BY 4.0._
