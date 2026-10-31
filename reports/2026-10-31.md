# Limbo Tracker daily report — 2026-10-31

Generated 2026-10-31 12:52:32 UTC; changes since 2026-10-30 13:12:50 UTC.

## Now

- **7,988 advisories in limbo** (+1,333 since the last report: 33 newly published, 1,355 older ones found for the first time, 55 left limbo): published by maintainers on GitHub, in ecosystems GitHub reviews, but not yet in GitHub's reviewed database or OSV.
  - 4,055 with no CVE anywhere · 563 citing a CVE that's still only reserved · 1,027 with a CVE from another CNA they don't cite
  - severity: 861 critical, 3,191 high, 3,245 medium, 691 low · median wait so far 57.3 days
- **13,852 more are likely permanent** (+9,721 since the last report): in ecosystems GitHub doesn't review, so GitHub-based scanners will probably never see them.

## Since the last report

- **33 newly published** advisories entered limbo.
- 1,355 older advisories were found for the first time (1,294 in newly watched repos).
- **Left limbo** (likely permanent included): 60 reviewed by GitHub, 0 found to duplicate a reviewed advisory, 0 withdrawn or unpublished.
- **CVE changes:** 63 (31 reserved CVEs published, 15 new CVEs from other CNAs).

## Newly published, in limbo

| Advisory | Package | Severity | CVE | Days | Fixed in |
|---|---|---|---|---:|---|
| [GHSA-hh7c-hrv9-6qw9](https://github.com/openedx/openedx-platform/security/advisories/GHSA-hh7c-hrv9-6qw9) | `pip:openedx-platform` | critical | no CVE anywhere | 1 | >= ulmo |
| [GHSA-2vm4-4f35-jgpv](https://github.com/openedx/openedx-platform/security/advisories/GHSA-2vm4-4f35-jgpv) | `pip:openedx-platform` | critical | no CVE anywhere | 1 | >= ulmo |
| [GHSA-744p-w4gc-m3gh](https://github.com/trilogy-libraries/trilogy/security/advisories/GHSA-744p-w4gc-m3gh) | `rubygems:trilogy` | critical | no CVE anywhere | 1 | 2.13.2 |
| [GHSA-7p86-8g3v-vgv9](https://github.com/LMCache/LMCache/security/advisories/GHSA-7p86-8g3v-vgv9) | `pip:lmcache` | critical | CVE published, cited (CVE-2026-107204) | 1 | 0.5.6 |
| [GHSA-48p7-6mjr-3jjj](https://github.com/rubygems/rubygems.org/security/advisories/GHSA-48p7-6mjr-3jjj) | `rubygems:Registry` | high | no CVE anywhere | 1 | cf71ca2 |
| [GHSA-x7w9-v9f4-288p](https://github.com/convex/convex-backend/security/advisories/GHSA-x7w9-v9f4-288p) | `npm:convex` | high | no CVE anywhere | 0 | 1.41.0 |
| [GHSA-p8mc-r577-q897](https://github.com/convex/convex-backend/security/advisories/GHSA-p8mc-r577-q897) | `npm:convex` | high | no CVE anywhere | 0 | 1.41.0 |
| [GHSA-qw8j-4xj7-6f28](https://github.com/convex/convex-backend/security/advisories/GHSA-qw8j-4xj7-6f28) | `npm:convex` | high | no CVE anywhere | 0 | 1.48.0 |
| [GHSA-j38q-h3ph-jjpq](https://github.com/jackc/pgx/security/advisories/GHSA-j38q-h3ph-jjpq) | `go:github.com/jackc/pgx/v4, go:github.com/jackc/pgx/v5` | high | no CVE anywhere | 0 | – |
| [GHSA-95fj-3fxw-g62g](https://github.com/jackc/pgx/security/advisories/GHSA-95fj-3fxw-g62g) | `go:github.com/jackc/pgx/v5` | high | no CVE anywhere | 0 | – |
| [GHSA-hmhp-3vmh-wr85](https://github.com/freescout-help-desk/freescout/security/advisories/GHSA-hmhp-3vmh-wr85) | `composer:freescout-help-desk/freescout` | high | no CVE anywhere | 0 | 1.8.249 |
| [GHSA-r79h-87qg-7gr3](https://github.com/freescout-help-desk/freescout/security/advisories/GHSA-r79h-87qg-7gr3) | `composer:freescout-help-desk/freescout` | high | no CVE anywhere | 0 | 1.8.249 |
| [GHSA-fpx7-53j2-fc79](https://github.com/openedx/openedx-platform/security/advisories/GHSA-fpx7-53j2-fc79) | `pip:openedx-platform` | medium | no CVE anywhere | 1 | >= ulmo |
| [GHSA-3gx3-8wpj-4qc2](https://github.com/openedx/openedx-platform/security/advisories/GHSA-3gx3-8wpj-4qc2) | `pip:openedx-platform` | medium | no CVE anywhere | 1 | >= ulmo |
| [GHSA-863f-jpf7-cqhq](https://github.com/openedx/openedx-platform/security/advisories/GHSA-863f-jpf7-cqhq) | `pip:openedx-platform` | medium | no CVE anywhere | 1 | >= ulmo |
| [GHSA-8vc9-m4jp-4mm9](https://github.com/grpc/grpc-rust/security/advisories/GHSA-8vc9-m4jp-4mm9) | `rust:tonic` | medium | no CVE anywhere | 1 | 0.14.9 |
| [GHSA-h7w4-52vv-9xpx](https://github.com/excon/excon/security/advisories/GHSA-h7w4-52vv-9xpx) | `rubygems:excon` | medium | no CVE anywhere | 1 | 1.10.0 |
| [GHSA-9mw5-7p28-rvv4](https://github.com/convex/convex-backend/security/advisories/GHSA-9mw5-7p28-rvv4) | `npm:convex` | medium | no CVE anywhere | 1 | 1.48.0 |
| [GHSA-pm7j-752h-qfvj](https://github.com/wekan/wekan/security/advisories/GHSA-pm7j-752h-qfvj) | `actions:wekan/wekan` | medium | no CVE anywhere | 1 | 12.69 |
| [GHSA-h8jh-mv4w-3gm5](https://github.com/komari-monitor/komari/security/advisories/GHSA-h8jh-mv4w-3gm5) | `go:github.com/komari-monitor/komari` | medium | no CVE anywhere | 1 | 1.6.0 |
| [GHSA-v97q-3xf5-rj74](https://github.com/labstack/echo/security/advisories/GHSA-v97q-3xf5-rj74) | `go:github.com/labstack/echo/v5` | medium | no CVE anywhere | 1 | 5.4.3 |
| [GHSA-gg5j-6742-v827](https://github.com/grpc/grpc-node/security/advisories/GHSA-gg5j-6742-v827) | `npm:@grpc/grpc-js-xds` | medium | no CVE anywhere | 0 | 1.14.2 |
| [GHSA-8fc3-xmhg-c8h5](https://github.com/hasenbanck/sevenz-rust2/security/advisories/GHSA-8fc3-xmhg-c8h5) | `rust:sevenz-rust2` | medium | no CVE anywhere | 0 | 0.24.2 |
| [GHSA-r7hq-q2xm-6c5m](https://github.com/grpc/grpc-node/security/advisories/GHSA-r7hq-q2xm-6c5m) | `npm:@grpc/grpc-js-xds` | medium | no CVE anywhere | 0 | 1.14.2, 1.13.2 |
| [GHSA-mm6p-53cp-mcx7](https://github.com/freescout-help-desk/freescout/security/advisories/GHSA-mm6p-53cp-mcx7) | `composer:freescout-help-desk/freescout` | medium | no CVE anywhere | 0 | 1.8.249 |

…and 8 more (see the feed).

## CVE changes

| Advisory | Change |
|---|---|
| [GHSA-23wf-92cp-8pcj](https://github.com/labstack/echo/security/advisories/GHSA-23wf-92cp-8pcj) | cites CVE-2026-118658 (was none) |
| [GHSA-246p-cpwv-v3jq](https://github.com/labstack/echo/security/advisories/GHSA-246p-cpwv-v3jq) | cites CVE-2026-118653 (was none) |
| [GHSA-28hp-c82p-8vqj](https://github.com/traefik/traefik/security/advisories/GHSA-28hp-c82p-8vqj) | new CVE from another CNA: CVE-2026-119573 |
| [GHSA-2ffq-g2xg-c22p](https://github.com/labstack/echo/security/advisories/GHSA-2ffq-g2xg-c22p) | cites CVE-2026-118657 (was none) |
| [GHSA-2wx3-8x3w-r8qv](https://github.com/Project-MONAI/MONAI/security/advisories/GHSA-2wx3-8x3w-r8qv) | new CVE from another CNA: CVE-2026-119578 |
| [GHSA-358w-w75h-x6rx](https://github.com/gopacket/gopacket/security/advisories/GHSA-358w-w75h-x6rx) | new CVE from GitHub's CNA, not cited: CVE-2026-119299 |
| [GHSA-375p-5qhx-8wq4](https://github.com/labstack/echo/security/advisories/GHSA-375p-5qhx-8wq4) | cites CVE-2026-118650 (was none) |
| [GHSA-396x-v8w4-9x82](https://github.com/openvm-org/openvm/security/advisories/GHSA-396x-v8w4-9x82) | CVE-2026-62333 RESERVED -> PUBLISHED |
| [GHSA-3cmx-xjww-583x](https://github.com/i18next/i18next-http-backend/security/advisories/GHSA-3cmx-xjww-583x) | cites CVE-2026-118258 (was none) |
| [GHSA-3fx2-cqw9-xr3c](https://github.com/langchain-ai/langgraph/security/advisories/GHSA-3fx2-cqw9-xr3c) | cites CVE-2026-118667 (was none) |
| [GHSA-3pmx-cf9f-34xr](https://github.com/labstack/echo/security/advisories/GHSA-3pmx-cf9f-34xr) | cites CVE-2026-118654 (was none) |
| [GHSA-3rj6-rvwh-j2xg](https://github.com/nocodb/nocodb/security/advisories/GHSA-3rj6-rvwh-j2xg) | new CVE from another CNA: CVE-2026-119715 |
| [GHSA-434m-5hcj-pxf3](https://github.com/ardatan/graphql-tools/security/advisories/GHSA-434m-5hcj-pxf3) | cites CVE-2026-118665 (was none) |
| [GHSA-4hm6-w6qq-w73v](https://github.com/langchain-ai/langgraph/security/advisories/GHSA-4hm6-w6qq-w73v) | cites CVE-2026-118668 (was none) |
| [GHSA-4vgv-vvxr-9fh9](https://github.com/wp-graphql/wp-graphql/security/advisories/GHSA-4vgv-vvxr-9fh9) | new CVE from another CNA: CVE-2026-119702 |
| [GHSA-5p5r-f66g-r4vp](https://github.com/wp-graphql/wp-graphql/security/advisories/GHSA-5p5r-f66g-r4vp) | new CVE from another CNA: CVE-2026-119699 |
| [GHSA-6j26-wcv6-gp3f](https://github.com/socfortress/CoPilot/security/advisories/GHSA-6j26-wcv6-gp3f) | CVE-2026-61708 RESERVED -> PUBLISHED |
| [GHSA-6jcc-5g8w-32mx](https://github.com/i18next/i18next/security/advisories/GHSA-6jcc-5g8w-32mx) | CVE-2026-63402 RESERVED -> PUBLISHED |
| [GHSA-6jxj-px6v-747w](https://github.com/rgrove/crass/security/advisories/GHSA-6jxj-px6v-747w) | CVE-2026-61846 RESERVED -> PUBLISHED |
| [GHSA-6mfr-rv66-x7m3](https://github.com/parse-community/parse-server/security/advisories/GHSA-6mfr-rv66-x7m3) | new CVE from another CNA: CVE-2026-119570 |
| [GHSA-773f-9j7c-cr54](https://github.com/ArcadeData/arcadedb/security/advisories/GHSA-773f-9j7c-cr54) | new CVE from another CNA: CVE-2026-119576 |
| [GHSA-8hqj-cqcc-5f6w](https://github.com/socfortress/CoPilot/security/advisories/GHSA-8hqj-cqcc-5f6w) | CVE-2026-61728 RESERVED -> PUBLISHED |
| [GHSA-8j8q-73xx-w3m4](https://github.com/parse-community/parse-server/security/advisories/GHSA-8j8q-73xx-w3m4) | new CVE from another CNA: CVE-2026-119571 |
| [GHSA-8rj2-88v5-mx6w](https://github.com/chamilo/chamilo-lms/security/advisories/GHSA-8rj2-88v5-mx6w) | CVE-2026-44344 RESERVED -> PUBLISHED |
| [GHSA-8vfg-2r28-hvhj](https://github.com/rgrove/crass/security/advisories/GHSA-8vfg-2r28-hvhj) | CVE-2026-61848 RESERVED -> PUBLISHED |

…and 38 more.

## Longest waiting, published in the last 90 days

| Advisory | Package | Severity | CVE | Days | Fixed in |
|---|---|---|---|---:|---|
| [GHSA-gmj2-gq3j-vqmj](https://github.com/sparkle-project/Sparkle/security/advisories/GHSA-gmj2-gq3j-vqmj) | `swift:sparkle-project/Sparkle` | medium | CVE reserved (RBP) (CVE-2026-115568) | 89 | 2.9.5 |
| [GHSA-34vq-766q-gc73](https://github.com/libp2p/py-libp2p/security/advisories/GHSA-34vq-766q-gc73) | `pip:libp2p` | high | no CVE anywhere | 89 | – |
| [GHSA-h8xc-824q-pwfh](https://github.com/flytohub/flyto-core/security/advisories/GHSA-h8xc-824q-pwfh) | `pip:flyto-core` | medium | no CVE anywhere | 89 | 2.26.11 |
| [GHSA-wc94-386q-5478](https://github.com/flytohub/flyto-core/security/advisories/GHSA-wc94-386q-5478) | `pip:flyto-core` | high | no CVE anywhere | 89 | 2.26.11 |
| [GHSA-xchh-cp84-9838](https://github.com/flytohub/flyto-core/security/advisories/GHSA-xchh-cp84-9838) | `pip:flyto-core` | critical | no CVE anywhere | 89 | 2.26.11 |

586 advisories in limbo have waited more than a year.

## Coverage

Watchlist 18,656 repositories; 16,168 up to date on their schedule (daily for repos with an advisory in limbo, every 3 to 7 days for the rest); 4,894 checked in the last 24 hours; the last run stopped early (budget); 37,507 reviewed advisories known. Every number is a floor: the tracker only sees repositories on its watchlist. Version ranges are as entered by maintainers and unreviewed.

_Advisory metadata from published GitHub repository security advisories and the GitHub Advisory Database (https://github.com/advisories, CC BY 4.0); CVE state from CVE Services; OSV.dev; NVD API (this product uses the NVD API but is not endorsed or certified by the NVD). Compiled by Limbowatch (https://limbo.watch), CC BY 4.0._
