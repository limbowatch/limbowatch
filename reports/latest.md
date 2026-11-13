# Limbo Tracker daily report — 2026-11-13

Generated 2026-11-13 15:19:39 UTC; changes since 2026-11-12 15:51:59 UTC.

## Now

- **10,410 advisories in limbo** (+171 since the last report: 218 newly published, 3 older ones found for the first time, 50 left limbo): published by maintainers on GitHub, in ecosystems GitHub reviews, but not yet in GitHub's reviewed database or OSV.
  - 5,813 with no CVE anywhere · 609 citing a CVE that's still only reserved · 1,324 with a CVE from another CNA they don't cite
  - severity: 978 critical, 4,091 high, 4,361 medium, 980 low · median wait so far 52.1 days
- **15,275 more are likely permanent** (+79 since the last report: 79 newly published, 0 older ones found for the first time, 0 left limbo): in ecosystems GitHub doesn't review, so GitHub-based scanners will probably never see them.

## Since the last report

- **218 newly published** advisories entered limbo.
- 3 older advisories were found for the first time (0 in newly watched repos).
- **Left limbo** (likely permanent included): 50 reviewed by GitHub, 0 found to duplicate a reviewed advisory, 0 withdrawn or unpublished. GitHub reviewed 51 advisories in all in this period, from any repository.
- **CVE changes:** 307 (13 reserved CVEs published, 231 new CVEs from other CNAs).

## Newly published, in limbo

| Advisory | Package | Severity | CVE | Days | Fixed in |
|---|---|---|---|---:|---|
| [GHSA-cfgx-mprf-xh64](https://github.com/goreleaser/nfpm/security/advisories/GHSA-cfgx-mprf-xh64) | `go:github.com/goreleaser/nfpm/v2` | critical | no CVE anywhere | 1 | `2.49.0` |
| [GHSA-8xmc-886f-g496](https://github.com/nats-io/nats-server/security/advisories/GHSA-8xmc-886f-g496) | `go:github.com/nats-io/nats-server/v2` | critical | no CVE anywhere | 0 | `2.14.9, 2.15.2` |
| [GHSA-g9p6-654w-mr9v](https://github.com/nats-io/nats-server/security/advisories/GHSA-g9p6-654w-mr9v) | `go:github.com/nats-io/nats-server/v2` | critical | no CVE anywhere | 0 | `2.12.14, 2.14.4, 2.15.0` |
| [GHSA-q57r-qh7g-9wgm](https://github.com/nats-io/nats-server/security/advisories/GHSA-q57r-qh7g-9wgm) | `go:github.com/nats-io/nats-server/v2` | critical | no CVE anywhere | 0 | `2.12.14, 2.14.4, 2.15.0` |
| [GHSA-qmhq-mh7j-xr7c](https://github.com/mongodb/node-mongodb-native/security/advisories/GHSA-qmhq-mh7j-xr7c) | `npm:mongodb` | critical | CVE published, cited (`CVE-2026-126837`) | 0 | `7.8.0` |
| [GHSA-p8wx-9px6-7rmp](https://github.com/cdxgen/cdxgen/security/advisories/GHSA-p8wx-9px6-7rmp) | `npm:@cdxgen/cdxgen` | critical | no CVE anywhere | 0 | `13.8.0` |
| [GHSA-72jc-54pr-qq5w](https://github.com/cdxgen/cdxgen/security/advisories/GHSA-72jc-54pr-qq5w) | `npm:@cdxgen/cdxgen, npm:@cyclonedx/cdxgen` | critical | no CVE anywhere | 0 | `13.8.0, 12.9.2` |
| [GHSA-h3h3-4g48-gxq9](https://github.com/agenticmail/agenticmail/security/advisories/GHSA-h3h3-4g48-gxq9) | `npm:@agenticmail/cli` | critical | no CVE anywhere | 0 | `0.9.110` |
| [GHSA-4x3j-9wxx-863h](https://github.com/agenticmail/agenticmail/security/advisories/GHSA-4x3j-9wxx-863h) | `npm:@agenticmail/api, npm:@agenticmail/claudecode` | critical | no CVE anywhere | 0 | `0.9.65, 0.2.40` |
| [GHSA-vm2m-87j8-8w9m](https://github.com/agenticmail/agenticmail/security/advisories/GHSA-vm2m-87j8-8w9m) | `npm:@agenticmail/api, npm:@agenticmail/claudecode` | critical | no CVE anywhere | 0 | `0.2.40, 0.9.65` |
| [GHSA-vj36-c6cj-8qmh](https://github.com/agenticmail/agenticmail/security/advisories/GHSA-vj36-c6cj-8qmh) | `npm:@agenticmail/api` | critical | no CVE anywhere | 0 | `0.9.65` |
| [GHSA-cg7r-g8r9-c93w](https://github.com/PuruVJ/neotraverse/security/advisories/GHSA-cg7r-g8r9-c93w) | `npm:neotraverse` | high | no CVE anywhere | 1 | `1.0.2` |
| [GHSA-349g-v965-9v9w](https://github.com/opsmill/infrahub/security/advisories/GHSA-349g-v965-9v9w) | `pip:infrahub-server` | high | no CVE anywhere | 1 | `1.11.11, 1.12.0` |
| [GHSA-839m-5qhj-w4rm](https://github.com/goreleaser/nfpm/security/advisories/GHSA-839m-5qhj-w4rm) | `go:github.com/goreleaser/nfpm/v2` | high | no CVE anywhere | 1 | `2.49.0` |
| [GHSA-g2c3-j8g3-7gpw](https://github.com/opencontainers/runc/security/advisories/GHSA-g2c3-j8g3-7gpw) | `go:github.com/opencontainers/runc` | high | CVE reserved (RBP) (`CVE-2026-119101`) | 1 | `1.3.7, 1.4.4, 1.5.3, 1.6.0-rc.2` |
| [GHSA-8hp3-xxrg-v9c8](https://github.com/codewhale-hq/Codewhale/security/advisories/GHSA-8hp3-xxrg-v9c8) | `npm:codewhale, rust:codewhale-tui` | high | CVE reserved (RBP) (`CVE-2026-83817`) | 1 | `0.9.0` |
| [GHSA-3mgh-93r5-r7jf](https://github.com/codewhale-hq/Codewhale/security/advisories/GHSA-3mgh-93r5-r7jf) | `npm:codewhale, rust:codewhale-tui` | high | CVE reserved (RBP) (`CVE-2026-83816`) | 1 | `0.9.0` |
| [GHSA-mmhh-p37m-v88f](https://github.com/python-social-auth/social-app-django/security/advisories/GHSA-mmhh-p37m-v88f) | `pip:social-auth-app-django` | high | no CVE anywhere | 1 | `–` |
| [GHSA-492h-rq3v-xf2h](https://github.com/django-tenants/django-tenants/security/advisories/GHSA-492h-rq3v-xf2h) | `pip:django-tenants` | high | no CVE anywhere | 0 | `4.0.4` |
| [GHSA-9qc3-h48f-7h96](https://github.com/intlify/vue-i18n/security/advisories/GHSA-9qc3-h48f-7h96) | `npm:@intlify/core, npm:@intlify/core-base, npm:@intlify/s…` | high | no CVE anywhere | 0 | `11.4.19, 12.0.0-alpha.10` |
| [GHSA-7356-3q55-jvxm](https://github.com/intlify/vue-i18n/security/advisories/GHSA-7356-3q55-jvxm) | `npm:@intlify/core, npm:@intlify/core-base, npm:@intlify/s…` | high | no CVE anywhere | 0 | `11.4.19, 12.0.0-alpha.10` |
| [GHSA-j8cw-grjg-f39x](https://github.com/sebhildebrandt/systeminformation/security/advisories/GHSA-j8cw-grjg-f39x) | `npm:systeminformation` | high | no CVE anywhere | 0 | `5.33.19` |
| [GHSA-xm4v-pwj4-92qv](https://github.com/mariadb-corporation/mariadb-connector-nodejs/security/advisories/GHSA-xm4v-pwj4-92qv) | `npm:mariadb` | high | no CVE anywhere | 0 | `3.2.6, 3.3.5, 3.4.8, 3.5.5` |
| [GHSA-fvvw-v6c3-hhqm](https://github.com/graphql-hive/graphql-yoga/security/advisories/GHSA-fvvw-v6c3-hhqm) | `npm:@graphql-yoga/plugin-graphql-sse` | high | no CVE anywhere | 0 | `4.1.0` |
| [GHSA-2wxw-wgx7-4ffx](https://github.com/nats-io/nats-server/security/advisories/GHSA-2wxw-wgx7-4ffx) | `go:github.com/nats-io/nats-server/v2` | high | no CVE anywhere | 0 | `2.14.8, 2.15.1` |

…and 193 more: [the tracker](https://limbo.watch/tracker/) lists them all, newest first.

## CVE changes

| Advisory | Change |
|---|---|
| [GHSA-vm84-8c4p-64hx](https://github.com/xyproto/algernon/security/advisories/GHSA-vm84-8c4p-64hx) | CVE-2026-68548 RESERVED -> PUBLISHED |
| [GHSA-2xm5-gjpc-9m6q](https://github.com/bacnet-stack/bacnet-stack/security/advisories/GHSA-2xm5-gjpc-9m6q) | CVE-2026-47710 RESERVED -> PUBLISHED |
| [GHSA-8384-pwhh-cxjh](https://github.com/bacnet-stack/bacnet-stack/security/advisories/GHSA-8384-pwhh-cxjh) | CVE-2026-46674 RESERVED -> PUBLISHED |
| [GHSA-9w9m-w7w5-rrv3](https://github.com/bacnet-stack/bacnet-stack/security/advisories/GHSA-9w9m-w7w5-rrv3) | CVE-2026-47259 RESERVED -> PUBLISHED |
| [GHSA-c4q6-7827-mfg6](https://github.com/bacnet-stack/bacnet-stack/security/advisories/GHSA-c4q6-7827-mfg6) | CVE-2026-52786 RESERVED -> PUBLISHED |
| [GHSA-fv2r-c2m2-7qhh](https://github.com/bacnet-stack/bacnet-stack/security/advisories/GHSA-fv2r-c2m2-7qhh) | CVE-2026-45341 RESERVED -> PUBLISHED |
| [GHSA-rjmv-3mcm-r83j](https://github.com/bacnet-stack/bacnet-stack/security/advisories/GHSA-rjmv-3mcm-r83j) | CVE-2026-47258 RESERVED -> PUBLISHED |
| [GHSA-v3gx-mwrp-xvh5](https://github.com/bacnet-stack/bacnet-stack/security/advisories/GHSA-v3gx-mwrp-xvh5) | CVE-2026-45265 RESERVED -> PUBLISHED |
| [GHSA-vrpm-9gm2-x552](https://github.com/bacnet-stack/bacnet-stack/security/advisories/GHSA-vrpm-9gm2-x552) | CVE-2026-47711 RESERVED -> PUBLISHED |
| [GHSA-wjw5-q9g6-2764](https://github.com/bacnet-stack/bacnet-stack/security/advisories/GHSA-wjw5-q9g6-2764) | CVE-2026-47217 RESERVED -> PUBLISHED |
| [GHSA-x6pp-3pf3-f87r](https://github.com/bacnet-stack/bacnet-stack/security/advisories/GHSA-x6pp-3pf3-f87r) | CVE-2026-47257 RESERVED -> PUBLISHED |
| [GHSA-2fwp-32cj-g3x4](https://github.com/bacnet-stack/bacnet-stack/security/advisories/GHSA-2fwp-32cj-g3x4) | CVE-2026-46676 RESERVED -> PUBLISHED |
| [GHSA-rv5h-cxwq-q3mh](https://github.com/bacnet-stack/bacnet-stack/security/advisories/GHSA-rv5h-cxwq-q3mh) | CVE-2026-46677 RESERVED -> PUBLISHED |
| [GHSA-4hmw-qw74-vrhm](https://github.com/renovatebot/renovate/security/advisories/GHSA-4hmw-qw74-vrhm) | cites CVE-2026-88883 (was none) |
| [GHSA-6655-6qjp-jx7x](https://github.com/facelessuser/soupsieve/security/advisories/GHSA-6655-6qjp-jx7x) | cites CVE-2026-126191 (was none) |
| [GHSA-6j6f-fh7w-vvjr](https://github.com/renovatebot/renovate/security/advisories/GHSA-6j6f-fh7w-vvjr) | cites CVE-2026-110865 (was none) |
| [GHSA-7chm-46wx-888m](https://github.com/renovatebot/renovate/security/advisories/GHSA-7chm-46wx-888m) | cites CVE-2026-88886 (was none) |
| [GHSA-8rqp-w6vc-pf27](https://github.com/renovatebot/renovate/security/advisories/GHSA-8rqp-w6vc-pf27) | cites CVE-2026-110868 (was none) |
| [GHSA-9hmg-9h89-jhmx](https://github.com/renovatebot/renovate/security/advisories/GHSA-9hmg-9h89-jhmx) | cites CVE-2026-88880 (was none) |
| [GHSA-f2v7-35mm-3hx7](https://github.com/renovatebot/renovate/security/advisories/GHSA-f2v7-35mm-3hx7) | cites CVE-2026-88889 (was none) |
| [GHSA-j7mp-839j-jrm7](https://github.com/pgEdge/pgedge-postgres-mcp/security/advisories/GHSA-j7mp-839j-jrm7) | cites CVE-2026-126196 (was none) |
| [GHSA-mmhr-3c5m-f64f](https://github.com/facelessuser/soupsieve/security/advisories/GHSA-mmhr-3c5m-f64f) | cites CVE-2026-126190 (was none) |
| [GHSA-mpf8-qxrw-gq3w](https://github.com/renovatebot/renovate/security/advisories/GHSA-mpf8-qxrw-gq3w) | cites CVE-2026-88885 (was none) |
| [GHSA-r5pp-jx86-r6r9](https://github.com/pgEdge/pgedge-postgres-mcp/security/advisories/GHSA-r5pp-jx86-r6r9) | cites CVE-2026-126197 (was none) |
| [GHSA-rh7w-ccch-gh49](https://github.com/renovatebot/renovate/security/advisories/GHSA-rh7w-ccch-gh49) | cites CVE-2026-88882 (was none) |

…and 282 more.

## Longest waiting, published in the last 90 days

| Advisory | Package | Severity | CVE | Days | Fixed in |
|---|---|---|---|---:|---|
| [GHSA-f66g-8pcg-jm8r](https://github.com/WeblateOrg/weblate/security/advisories/GHSA-f66g-8pcg-jm8r) | `pip:weblate` | medium | CVE reserved (RBP) (`CVE-2026-86042`) | 89 | `2026.8` |
| [GHSA-327h-qqgm-qv55](https://github.com/WeblateOrg/weblate/security/advisories/GHSA-327h-qqgm-qv55) | `pip:weblate` | high | CVE published, cited (`CVE-2026-86035`) | 89 | `2026.8` |
| [GHSA-45m9-pf98-8jmq](https://github.com/WeblateOrg/weblate/security/advisories/GHSA-45m9-pf98-8jmq) | `pip:weblate` | low | CVE published, cited (`CVE-2026-77573`) | 89 | `2026.8` |
| [GHSA-x84p-6892-473c](https://github.com/WeblateOrg/weblate/security/advisories/GHSA-x84p-6892-473c) | `pip:weblate` | medium | CVE published, cited (`CVE-2026-77508`) | 89 | `2026.8` |
| [GHSA-vvc6-wvqm-w5gc](https://github.com/WeblateOrg/weblate/security/advisories/GHSA-vvc6-wvqm-w5gc) | `pip:weblate` | medium | CVE published, cited (`CVE-2026-77507`) | 89 | `2026.8` |

607 advisories in limbo have waited more than a year.

## Coverage

Watchlist 67,485 repositories; 67,485 up to date on their schedule (daily for repos with an advisory in limbo, every 3 days for other repos with advisories, every 30 days and after each release for the rest); 6,585 checked in the last 24 hours; 37,737 reviewed advisories known. Every number is a floor: the tracker only sees repositories on its watchlist. Version ranges are as entered by maintainers and unreviewed.

_Advisory metadata from published GitHub repository security advisories and the GitHub Advisory Database (https://github.com/advisories, CC BY 4.0); CVE state from CVE Services; OSV.dev; NVD API (this product uses the NVD API but is not endorsed or certified by the NVD). Compiled by Limbowatch (https://limbo.watch), CC BY 4.0._
