# Limbo Tracker daily report — 2026-11-20

Generated 2026-11-20 16:02:58 UTC; changes since 2026-11-19 16:12:10 UTC.

## Now

- **11,408 advisories in limbo** (+155 since the last report: 186 newly published, 64 older ones found for the first time, 98 left limbo, 3 moved in from likely permanent): published by maintainers on GitHub, in ecosystems GitHub reviews, but not yet in GitHub's reviewed database or OSV.
  - 6,640 with no CVE anywhere · 551 citing a CVE that's still only reserved · 1,422 with a CVE from another CNA they don't cite
  - severity: 1,038 critical, 4,461 high, 4,821 medium, 1,088 low · median wait so far 53.0 days
- **16,079 more are likely permanent** (+137 since the last report: 117 newly published, 30 older ones found for the first time, 7 left limbo, 3 moved to the in-limbo count): in ecosystems GitHub doesn't review, so GitHub-based scanners will probably never see them.

## Since the last report

- **186 newly published** advisories entered limbo.
- 64 older advisories were found for the first time (55 in newly watched repos).
- **Left limbo** (likely permanent included): 105 reviewed by GitHub, 0 found to duplicate a reviewed advisory, 0 withdrawn or unpublished. GitHub reviewed 115 advisories in all in this period, from any repository.
- **CVE changes:** 95 (58 reserved CVEs published, 11 new CVEs from other CNAs).

## Newly published, in limbo

| Advisory | Package | Severity | CVE | Days | Fixed in |
|---|---|---|---|---:|---|
| [GHSA-27cp-f4p8-8qwv](https://github.com/rubygems/gemstash/security/advisories/GHSA-27cp-f4p8-8qwv) | `rubygems:gemstash` | critical | no CVE anywhere | 1 | `2.9.0` |
| [GHSA-c35f-chp7-9chr](https://github.com/open-telemetry/opentelemetry-collector-contrib/security/advisories/GHSA-c35f-chp7-9chr) | `go:github.com/open-telemetry/opentelemetry-collector-cont…` | critical | no CVE anywhere | 0 | `0.165.0` |
| [GHSA-9426-q567-pc36](https://github.com/MervinPraison/PraisonAI/security/advisories/GHSA-9426-q567-pc36) | `npm:praisonai, pip:praisonai, pip:praisonai-bot, pip:prai…` | critical | no CVE anywhere | 0 | `1.8.0, 4.8.0, 0.2.0` |
| [GHSA-2wq4-4wj9-7pq3](https://github.com/mongodb/mongo-java-driver/security/advisories/GHSA-2wq4-4wj9-7pq3) | `maven:org.mongodb:mongodb-driver-reactivestreams, maven:o…` | critical | CVE published, cited (`CVE-2026-129932`) | 0 | `5.15.0` |
| [GHSA-hg3m-q4fj-ggmq](https://github.com/wallabag/wallabag/security/advisories/GHSA-hg3m-q4fj-ggmq) | `composer:wallabag/wallabag` | critical | no CVE anywhere | 0 | `–` |
| [GHSA-qhvm-xwjm-g4f8](https://github.com/roomi-fields/gemini-notebook-mcp/security/advisories/GHSA-qhvm-xwjm-g4f8) | `npm:@roomi-fields/notebooklm-mcp` | critical | no CVE anywhere | 0 | `4.11.2` |
| [GHSA-gpcm-8jw9-8fg8](https://github.com/EGroupware/egroupware/security/advisories/GHSA-gpcm-8jw9-8fg8) | `composer:egroupware/egroupware` | critical | no CVE anywhere | 0 | `26.9.2020928, 23.1.20261021` |
| [GHSA-f73m-7563-jjf9](https://github.com/EGroupware/egroupware/security/advisories/GHSA-f73m-7563-jjf9) | `composer:egroupware/egroupware` | critical | no CVE anywhere | 0 | `26.8.20260825, 23.1.20261021` |
| [GHSA-xv2j-8j5x-m228](https://github.com/doobidoo/mcp-memory-service/security/advisories/GHSA-xv2j-8j5x-m228) | `pip:mcp-memory-service` | critical | no CVE anywhere | 0 | `13.0.0` |
| [GHSA-vjjc-h367-2gx3](https://github.com/jupyter-server/enterprise_gateway/security/advisories/GHSA-vjjc-h367-2gx3) | `pip:jupyter-enterprise-gateway` | critical | no CVE anywhere | 0 | `3.5.0` |
| [GHSA-m434-r2pf-qr3g](https://github.com/jupyter-server/enterprise_gateway/security/advisories/GHSA-m434-r2pf-qr3g) | `pip:jupyter-enterprise-gateway` | critical | no CVE anywhere | 0 | `3.5.0` |
| [GHSA-6944-p22h-3qpx](https://github.com/wekan/wekan/security/advisories/GHSA-6944-p22h-3qpx) | `actions:wekan/wekan` | critical | no CVE anywhere | 0 | `9.96` |
| [GHSA-cp2w-pc8v-r54p](https://github.com/obot-platform/obot/security/advisories/GHSA-cp2w-pc8v-r54p) | `go:github.com/obot-platform/obot` | critical | no CVE anywhere | 0 | `0.28.2` |
| [GHSA-mx78-9mrq-rfm5](https://github.com/fastify/fastify-reply-from/security/advisories/GHSA-mx78-9mrq-rfm5) | `npm:@fastify/reply-from` | critical | CVE reserved (RBP) (`CVE-2026-133212`) | 0 | `12.9.1` |
| [GHSA-xfw4-3v4j-82mr](https://github.com/rubygems/gemstash/security/advisories/GHSA-xfw4-3v4j-82mr) | `rubygems:gemstash` | high | no CVE anywhere | 1 | `2.9.0` |
| [GHSA-c927-fwqw-cm2g](https://github.com/rubygems/gemstash/security/advisories/GHSA-c927-fwqw-cm2g) | `rubygems:gemstash` | high | no CVE anywhere | 1 | `2.9.0` |
| [GHSA-8mrq-q9c6-h23v](https://github.com/mas-bandwidth/netcode/security/advisories/GHSA-8mrq-q9c6-h23v) | `go:github.com/mas-bandwidth/netcode.go, other:netcode, ot…` | high | no CVE anywhere | 0 | `1.5.0, 1.16.0, 1.2.0` |
| [GHSA-6fhg-8r33-fcww](https://github.com/fastify/fastify-http-proxy/security/advisories/GHSA-6fhg-8r33-fcww) | `npm:@fastify/http-proxy` | high | CVE published, cited (`CVE-2026-130647`) | 0 | `11.6.10` |
| [GHSA-29w6-p7r8-xmf9](https://github.com/fastify/fastify-http-proxy/security/advisories/GHSA-29w6-p7r8-xmf9) | `npm:@fastify/http-proxy` | high | CVE published, cited (`CVE-2026-129502`) | 0 | `11.6.10` |
| [GHSA-q659-79j2-32h5](https://github.com/fastify/fastify-http-proxy/security/advisories/GHSA-q659-79j2-32h5) | `npm:@fastify/http-proxy` | high | CVE published, cited (`CVE-2026-129500`) | 0 | `11.6.10` |
| [GHSA-xc6w-588x-m445](https://github.com/cycle/database/security/advisories/GHSA-xc6w-588x-m445) | `composer:cycle/database` | high | no CVE anywhere | 0 | `2.23.5` |
| [GHSA-3h66-wm86-pcq8](https://github.com/Automattic/juice/security/advisories/GHSA-3h66-wm86-pcq8) | `npm:juice` | high | no CVE anywhere | 0 | `12.2.5` |
| [GHSA-2cfc-5mg3-74jc](https://github.com/wallabag/wallabag/security/advisories/GHSA-2cfc-5mg3-74jc) | `composer:wallabag/wallabag` | high | no CVE anywhere | 0 | `2.6.18` |
| [GHSA-52xm-74j7-7j7f](https://github.com/wallabag/wallabag/security/advisories/GHSA-52xm-74j7-7j7f) | `composer:wallabag/wallabag` | high | no CVE anywhere | 0 | `2.6.18` |
| [GHSA-rvg4-ph3q-9x5g](https://github.com/wallabag/wallabag/security/advisories/GHSA-rvg4-ph3q-9x5g) | `composer:wallabag/wallabag` | high | no CVE anywhere | 0 | `2.6.18` |

…and 161 more: [the tracker](https://limbo.watch/tracker/) lists them all, newest first.

## CVE changes

| Advisory | Change |
|---|---|
| [GHSA-4hrh-34w3-5ww8](https://github.com/fabiolb/fabio/security/advisories/GHSA-4hrh-34w3-5ww8) | CVE-2026-104099 RESERVED -> PUBLISHED |
| [GHSA-hq2p-f2vj-v3cm](https://github.com/daptin/daptin/security/advisories/GHSA-hq2p-f2vj-v3cm) | CVE-2026-77367 RESERVED -> PUBLISHED |
| [GHSA-mc8w-wjhw-45x5](https://github.com/ether/etherpad/security/advisories/GHSA-mc8w-wjhw-45x5) | CVE-2026-114516 RESERVED -> PUBLISHED |
| [GHSA-p34x-fmph-9fjx](https://github.com/flytohub/flyto-core/security/advisories/GHSA-p34x-fmph-9fjx) | CVE-2026-77312 RESERVED -> PUBLISHED |
| [GHSA-wj7x-58c2-5793](https://github.com/daptin/daptin/security/advisories/GHSA-wj7x-58c2-5793) | CVE-2026-77369 RESERVED -> PUBLISHED |
| [GHSA-x8q7-6c7m-52gw](https://github.com/nltk/nltk/security/advisories/GHSA-x8q7-6c7m-52gw) | CVE-2026-128138 RESERVED -> PUBLISHED |
| [GHSA-2ccw-8rvh-6cmg](https://github.com/fastify/fastify-reply-from/security/advisories/GHSA-2ccw-8rvh-6cmg) | CVE-2026-130886 RESERVED -> PUBLISHED |
| [GHSA-2mr3-rxrq-238c](https://github.com/flytohub/flyto-core/security/advisories/GHSA-2mr3-rxrq-238c) | CVE-2026-77315 RESERVED -> PUBLISHED |
| [GHSA-2pj4-v76f-wjvx](https://github.com/baserproject/basercms/security/advisories/GHSA-2pj4-v76f-wjvx) | CVE-2026-62955 RESERVED -> PUBLISHED |
| [GHSA-32p6-cwhc-8r78](https://github.com/nltk/nltk/security/advisories/GHSA-32p6-cwhc-8r78) | CVE-2026-129229 RESERVED -> PUBLISHED |
| [GHSA-6mph-mjg3-f943](https://github.com/fastify/fastify-reply-from/security/advisories/GHSA-6mph-mjg3-f943) | CVE-2026-127064 RESERVED -> PUBLISHED |
| [GHSA-8846-p9w9-5frf](https://github.com/nltk/nltk/security/advisories/GHSA-8846-p9w9-5frf) | CVE-2026-129223 RESERVED -> PUBLISHED |
| [GHSA-9657-8vc2-7g2p](https://github.com/poweradmin/poweradmin/security/advisories/GHSA-9657-8vc2-7g2p) | CVE-2026-115463 RESERVED -> PUBLISHED |
| [GHSA-cc5r-64rf-75hg](https://github.com/nltk/nltk/security/advisories/GHSA-cc5r-64rf-75hg) | CVE-2026-129234 RESERVED -> PUBLISHED |
| [GHSA-hghq-53p7-c582](https://github.com/phires/go-guerrilla/security/advisories/GHSA-hghq-53p7-c582) | CVE-2026-115578 RESERVED -> PUBLISHED |
| [GHSA-j8g8-j4j7-8j54](https://github.com/nltk/nltk/security/advisories/GHSA-j8g8-j4j7-8j54) | CVE-2026-128139 RESERVED -> PUBLISHED |
| [GHSA-pfg2-w999-497v](https://github.com/flytohub/flyto-core/security/advisories/GHSA-pfg2-w999-497v) | CVE-2026-77313 RESERVED -> PUBLISHED |
| [GHSA-prhx-9q2h-ph2x](https://github.com/Paymenter/Paymenter/security/advisories/GHSA-prhx-9q2h-ph2x) | CVE-2026-103026 RESERVED -> PUBLISHED |
| [GHSA-rh8m-wqhc-qmrf](https://github.com/nltk/nltk/security/advisories/GHSA-rh8m-wqhc-qmrf) | CVE-2026-129222 RESERVED -> PUBLISHED |
| [GHSA-v9v2-98xq-627c](https://github.com/prest/prest/security/advisories/GHSA-v9v2-98xq-627c) | CVE-2026-104129 RESERVED -> PUBLISHED |
| [GHSA-w3f2-pr6x-wwjc](https://github.com/git-lfs/git-lfs/security/advisories/GHSA-w3f2-pr6x-wwjc) | CVE-2026-69260 RESERVED -> PUBLISHED |
| [GHSA-wr3g-j6qj-xpgh](https://github.com/nltk/nltk/security/advisories/GHSA-wr3g-j6qj-xpgh) | CVE-2026-128135 RESERVED -> PUBLISHED |
| [GHSA-x72p-hmqp-46hw](https://github.com/git-lfs/git-lfs/security/advisories/GHSA-x72p-hmqp-46hw) | CVE-2026-105803 RESERVED -> PUBLISHED |
| [GHSA-x7xj-4j4f-88xr](https://github.com/git-lfs/git-lfs/security/advisories/GHSA-x7xj-4j4f-88xr) | CVE-2026-69261 RESERVED -> PUBLISHED |
| [GHSA-xrgv-7vx6-5vx6](https://github.com/git-lfs/git-lfs/security/advisories/GHSA-xrgv-7vx6-5vx6) | CVE-2026-105802 RESERVED -> PUBLISHED |

…and 70 more.

## Longest waiting, published in the last 90 days

| Advisory | Package | Severity | CVE | Days | Fixed in |
|---|---|---|---|---:|---|
| [GHSA-f9xh-7rcj-jc8j](https://github.com/NeoRazorX/facturascripts/security/advisories/GHSA-f9xh-7rcj-jc8j) | `composer:facturascripts/facturascripts` | medium | CVE reserved (RBP) (`CVE-2026-77530`) | 89 | `2026.5` |
| [GHSA-r4f8-3xc4-c8vw](https://github.com/drivendataorg/cloudpathlib/security/advisories/GHSA-r4f8-3xc4-c8vw) | `pip:cloudpathlib` | medium | no CVE anywhere | 89 | `0.25.0` |
| [GHSA-ggq4-hxgw-346r](https://github.com/AsfhtgkDavid/theshit/security/advisories/GHSA-ggq4-hxgw-346r) | `rust:theshit` | high | no CVE anywhere | 89 | `0.2.2` |
| [GHSA-g7ph-gmq8-5qgg](https://github.com/inducer/relate/security/advisories/GHSA-g7ph-gmq8-5qgg) | `pip:relate` | medium | no CVE anywhere | 89 | `–` |
| [GHSA-mc3w-gp54-vv77](https://github.com/jon4hz/jellysweep/security/advisories/GHSA-mc3w-gp54-vv77) | `go:github.com/jon4hz/jellysweep` | medium | no CVE anywhere | 89 | `0.16.0` |

613 advisories in limbo have waited more than a year.

## Coverage

Watchlist 67,932 repositories; 67,932 up to date on their schedule (daily for repos with an advisory in limbo, every 3 days for other repos with advisories, every 30 days and after each release for the rest); 7,126 checked in the last 24 hours; 37,969 reviewed advisories known. Every number is a floor: the tracker only sees repositories on its watchlist. Version ranges are as entered by maintainers and unreviewed.

_Advisory metadata from published GitHub repository security advisories and the GitHub Advisory Database (https://github.com/advisories, CC BY 4.0); CVE state from CVE Services; OSV.dev; NVD API (this product uses the NVD API but is not endorsed or certified by the NVD). Compiled by Limbowatch (https://limbo.watch), CC BY 4.0._
