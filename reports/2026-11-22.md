# Limbo Tracker daily report — 2026-11-22

Generated 2026-11-22 15:07:14 UTC; changes since 2026-11-21 15:08:57 UTC.

## Now

- **11,696 advisories in limbo** (+181 since the last report: 173 newly published, 8 older ones found for the first time, 0 left limbo): published by maintainers on GitHub, in ecosystems GitHub reviews, but not yet in GitHub's reviewed database or OSV.
  - 6,804 with no CVE anywhere · 531 citing a CVE that's still only reserved · 1,532 with a CVE from another CNA they don't cite
  - severity: 1,059 critical, 4,558 high, 4,929 medium, 1,150 low · median wait so far 53.6 days
- **16,210 more are likely permanent** (+37 since the last report: 36 newly published, 1 older ones found for the first time, 0 left limbo): in ecosystems GitHub doesn't review, so GitHub-based scanners will probably never see them.

## Since the last report

- **173 newly published** advisories entered limbo.
- 8 older advisories were found for the first time (2 in newly watched repos).
- **Left limbo** (likely permanent included): 0 reviewed by GitHub, 0 found to duplicate a reviewed advisory, 0 withdrawn or unpublished. **GitHub reviewed no advisories at all in this period.**
- **CVE changes:** 185 (9 reserved CVEs published, 176 new CVEs from other CNAs).

## Newly published, in limbo

| Advisory | Package | Severity | CVE | Days | Fixed in |
|---|---|---|---|---:|---|
| [GHSA-g9m6-r3rx-75h3](https://github.com/janephp/janephp/security/advisories/GHSA-g9m6-r3rx-75h3) | `composer:jane-php/json-schema` | critical | no CVE anywhere | 1 | `8.1.3` |
| [GHSA-3f6m-8554-vq58](https://github.com/CoreWCF/CoreWCF/security/advisories/GHSA-3f6m-8554-vq58) | `nuget:CoreWCF.Primitives` | critical | no CVE anywhere | 1 | `1.9.2` |
| [GHSA-2p8r-7mx6-gh86](https://github.com/christianhelle/refitter/security/advisories/GHSA-2p8r-7mx6-gh86) | `nuget:Refitter, nuget:Refitter.Core, nuget:Refitter.MSBui…` | critical | no CVE anywhere | 0 | `2.4.1` |
| [GHSA-v99p-m5vm-fqqc](https://github.com/janko/image_processing/security/advisories/GHSA-v99p-m5vm-fqqc) | `rubygems:image_processing` | critical | no CVE anywhere | 0 | `2.0.1` |
| [GHSA-jm85-wxjw-3vv5](https://github.com/janko/image_processing/security/advisories/GHSA-jm85-wxjw-3vv5) | `rubygems:image_processing` | critical | no CVE anywhere | 0 | `2.0.3` |
| [GHSA-3c52-7fc8-c39j](https://github.com/kerberos-io/agent/security/advisories/GHSA-3c52-7fc8-c39j) | `go:github.com/kerberos-io/agent/machinery` | critical | no CVE anywhere | 0 | `3.14.4` |
| [GHSA-rv4m-8r4r-q43c](https://github.com/kerberos-io/agent/security/advisories/GHSA-rv4m-8r4r-q43c) | `go:github.com/kerberos-io/agent/machinery` | critical | no CVE anywhere | 0 | `3.6.14` |
| [GHSA-pxjw-337g-c9ww](https://github.com/cuga-project/cuga-agent/security/advisories/GHSA-pxjw-337g-c9ww) | `pip:cuga` | critical | no CVE anywhere | 0 | `0.4.6` |
| [GHSA-v937-cj22-v527](https://github.com/janephp/janephp/security/advisories/GHSA-v937-cj22-v527) | `composer:jane-php/json-schema-runtime` | high | no CVE anywhere | 1 | `8.1.3` |
| [GHSA-wffx-g49c-3x8r](https://github.com/janephp/janephp/security/advisories/GHSA-wffx-g49c-3x8r) | `composer:jane-php/json-schema-runtime, composer:jane-php/…` | high | no CVE anywhere | 1 | `8.1.3` |
| [GHSA-58mf-c3jj-277p](https://github.com/rack/rack/security/advisories/GHSA-58mf-c3jj-277p) | `rubygems:rack` | high | no CVE anywhere | 1 | `3.1.24, 3.2.9` |
| [GHSA-36cw-mv2m-c7m8](https://github.com/CoreWCF/CoreWCF/security/advisories/GHSA-36cw-mv2m-c7m8) | `nuget:CoreWCF.NetFramingBase` | high | no CVE anywhere | 1 | `1.9.2` |
| [GHSA-5rwx-f2cj-3q7r](https://github.com/CoreWCF/CoreWCF/security/advisories/GHSA-5rwx-f2cj-3q7r) | `nuget:CoreWCF.Primitives` | high | no CVE anywhere | 1 | `1.9.2` |
| [GHSA-q25m-3c62-qch4](https://github.com/CoreWCF/CoreWCF/security/advisories/GHSA-q25m-3c62-qch4) | `nuget:CoreWCF.Primitives` | high | no CVE anywhere | 1 | `1.9.2` |
| [GHSA-xvhx-496r-7682](https://github.com/python-poetry/poetry/security/advisories/GHSA-xvhx-496r-7682) | `pip:poetry` | high | no CVE anywhere | 1 | `2.4.2` |
| [GHSA-h9cp-hwxx-jphf](https://github.com/janko/image_processing/security/advisories/GHSA-h9cp-hwxx-jphf) | `rubygems:image_processing` | high | no CVE anywhere | 1 | `–` |
| [GHSA-9gvv-6cg2-w8vv](https://github.com/zip-rs/zip2/security/advisories/GHSA-9gvv-6cg2-w8vv) | `rust:zip` | high | no CVE anywhere | 0 | `9.4.2` |
| [GHSA-rjqv-f2vc-frxh](https://github.com/zip-rs/zip2/security/advisories/GHSA-rjqv-f2vc-frxh) | `rust:zip` | high | no CVE anywhere | 0 | `9.4.2` |
| [GHSA-5x9w-w2q9-62rg](https://github.com/forgekeep/nebula-mesh/security/advisories/GHSA-5x9w-w2q9-62rg) | `go:github.com/forgekeep/nebula-mesh` | high | no CVE anywhere | 0 | `0.22.1` |
| [GHSA-xp38-wccv-8v49](https://github.com/nilsteampassnet/TeamPass/security/advisories/GHSA-xp38-wccv-8v49) | `composer:nilsteampassnet/teampass` | high | no CVE anywhere | 0 | `3.2.4.5` |
| [GHSA-484j-g4pq-cjpr](https://github.com/daptin/daptin/security/advisories/GHSA-484j-g4pq-cjpr) | `go:github.com/daptin/daptin` | high | no CVE anywhere | 0 | `0.13.58` |
| [GHSA-58rp-r3fg-rh7r](https://github.com/oxyno-zeta/s3-proxy/security/advisories/GHSA-58rp-r3fg-rh7r) | `go:github.com/oxyno-zeta/s3-proxy` | high | no CVE anywhere | 0 | `5.3.0` |
| [GHSA-9pr8-85xc-qhv7](https://github.com/pion/webrtc/security/advisories/GHSA-9pr8-85xc-qhv7) | `go:github.com/pion/webrtc/v4` | high | no CVE anywhere | 0 | `4.2.28` |
| [GHSA-mgqj-ph59-3r6r](https://github.com/christianhelle/refitter/security/advisories/GHSA-mgqj-ph59-3r6r) | `nuget:Refitter, nuget:Refitter.Core, nuget:Refitter.MSBui…` | high | no CVE anywhere | 0 | `2.4.1` |
| [GHSA-7hgj-q592-v892](https://github.com/christianhelle/refitter/security/advisories/GHSA-7hgj-q592-v892) | `nuget:Refitter, nuget:Refitter.Core, nuget:Refitter.MSBui…` | high | no CVE anywhere | 0 | `2.4.1` |

…and 148 more: [the tracker](https://limbo.watch/tracker/) lists them all, newest first.

## CVE changes

| Advisory | Change |
|---|---|
| [GHSA-662w-h4p6-jq4p](https://github.com/fastify/fastify-express/security/advisories/GHSA-662w-h4p6-jq4p) | CVE-2026-124626 RESERVED -> PUBLISHED |
| [GHSA-7g3h-59cw-27vf](https://github.com/google/security-research/security/advisories/GHSA-7g3h-59cw-27vf) | CVE-2026-74127 RESERVED -> PUBLISHED |
| [GHSA-84w6-xrf3-f8q8](https://github.com/fastify/fastify-express/security/advisories/GHSA-84w6-xrf3-f8q8) | CVE-2026-133867 RESERVED -> PUBLISHED |
| [GHSA-f44m-4qwg-5587](https://github.com/fastify/fastify-express/security/advisories/GHSA-f44m-4qwg-5587) | CVE-2026-129504 RESERVED -> PUBLISHED |
| [GHSA-gcf6-j9m3-p97x](https://github.com/fastify/middie/security/advisories/GHSA-gcf6-j9m3-p97x) | CVE-2026-133250 RESERVED -> PUBLISHED |
| [GHSA-w877-hjcp-88rc](https://github.com/fastify/fastify-express/security/advisories/GHSA-w877-hjcp-88rc) | CVE-2026-133120 RESERVED -> PUBLISHED |
| [GHSA-6rmc-f24g-hmp6](https://github.com/fastify/fastify-express/security/advisories/GHSA-6rmc-f24g-hmp6) | CVE-2026-129850 RESERVED -> PUBLISHED |
| [GHSA-24mh-2vvh-5r45](https://github.com/fastify/fastify-rate-limit/security/advisories/GHSA-24mh-2vvh-5r45) | CVE-2026-133312 RESERVED -> PUBLISHED |
| [GHSA-j7qm-jhpc-mj26](https://github.com/fastify/fastify-swagger-ui/security/advisories/GHSA-j7qm-jhpc-mj26) | CVE-2026-133273 RESERVED -> PUBLISHED |
| [GHSA-7jp3-2229-xgqj](https://github.com/openremote/core/security/advisories/GHSA-7jp3-2229-xgqj) | new CVE from another CNA: CVE-2026-134287 |
| [GHSA-26pv-59j4-p5m7](https://github.com/frappe/erpnext/security/advisories/GHSA-26pv-59j4-p5m7) | new CVE from another CNA: CVE-2026-134411 |
| [GHSA-29xj-69vf-fmmh](https://github.com/frappe/erpnext/security/advisories/GHSA-29xj-69vf-fmmh) | new CVE from another CNA: CVE-2026-134404 |
| [GHSA-2rxj-6v32-2v6j](https://github.com/parse-community/parse-server/security/advisories/GHSA-2rxj-6v32-2v6j) | new CVE from another CNA: CVE-2026-134242 |
| [GHSA-2vpw-p335-mmmp](https://github.com/getgrav/grav/security/advisories/GHSA-2vpw-p335-mmmp) | new CVE from another CNA: CVE-2026-134250 |
| [GHSA-3598-wrmp-2pp2](https://github.com/go-vikunja/vikunja/security/advisories/GHSA-3598-wrmp-2pp2) | new CVE from another CNA: CVE-2026-134265 |
| [GHSA-3rqp-8h7g-xxv8](https://github.com/getgrav/grav/security/advisories/GHSA-3rqp-8h7g-xxv8) | new CVE from another CNA: CVE-2026-134253 |
| [GHSA-4fqv-v627-2ggm](https://github.com/Admidio/admidio/security/advisories/GHSA-4fqv-v627-2ggm) | new CVE from another CNA: CVE-2026-134254 |
| [GHSA-5pj7-wx9m-cjh6](https://github.com/web-token/jwt-framework/security/advisories/GHSA-5pj7-wx9m-cjh6) | new CVE from another CNA: CVE-2026-134458 |
| [GHSA-5q53-5vm3-cjq8](https://github.com/frappe/erpnext/security/advisories/GHSA-5q53-5vm3-cjq8) | new CVE from another CNA: CVE-2026-134429 |
| [GHSA-5w6j-qm42-4rc2](https://github.com/surrealdb/surrealdb/security/advisories/GHSA-5w6j-qm42-4rc2) | new CVE from another CNA: CVE-2026-134292 |
| [GHSA-64h3-xccr-q5jr](https://github.com/frappe/erpnext/security/advisories/GHSA-64h3-xccr-q5jr) | new CVE from another CNA: CVE-2026-134389 |
| [GHSA-66qv-66mg-9h74](https://github.com/rclone/rclone/security/advisories/GHSA-66qv-66mg-9h74) | new CVE from another CNA: CVE-2026-134352 |
| [GHSA-6c37-x4jm-529x](https://github.com/surrealdb/surrealdb/security/advisories/GHSA-6c37-x4jm-529x) | new CVE from another CNA: CVE-2026-134294 |
| [GHSA-6pgq-xpqq-rmjx](https://github.com/ArcadeData/arcadedb/security/advisories/GHSA-6pgq-xpqq-rmjx) | new CVE from another CNA: CVE-2026-134338 |
| [GHSA-77q9-p3mx-p357](https://github.com/frappe/erpnext/security/advisories/GHSA-77q9-p3mx-p357) | new CVE from another CNA: CVE-2026-134393 |

…and 160 more.

## Longest waiting, published in the last 90 days

| Advisory | Package | Severity | CVE | Days | Fixed in |
|---|---|---|---|---:|---|
| [GHSA-x39c-q2jx-f325](https://github.com/IBM/mcp-context-forge/security/advisories/GHSA-x39c-q2jx-f325) | `pip:mcp-contextforge-gateway` | medium | CVE reserved (RBP) (`CVE-2026-104877`) | 89 | `v1.0.7` |
| [GHSA-8m2q-wq3r-6hq8](https://github.com/tsutsu3/linkify-it-py/security/advisories/GHSA-8m2q-wq3r-6hq8) | `pip:linkify-it-py` | high | no CVE anywhere | 89 | `2.1.1` |
| [GHSA-8fg2-3gpc-x8m7](https://github.com/nilsteampassnet/TeamPass/security/advisories/GHSA-8fg2-3gpc-x8m7) | `composer:nilsteampassnet/teampass` | critical | no CVE anywhere | 89 | `3.2.0.3` |
| [GHSA-xrjw-r5hx-29rj](https://github.com/nilsteampassnet/TeamPass/security/advisories/GHSA-xrjw-r5hx-29rj) | `composer:nilsteampassnet/teampass` | medium | no CVE anywhere | 89 | `3.2.1.5` |
| [GHSA-g797-4rh6-m2xp](https://github.com/nilsteampassnet/TeamPass/security/advisories/GHSA-g797-4rh6-m2xp) | `composer:nilsteampassnet/teampass` | medium | no CVE anywhere | 89 | `3.2.1.5` |

613 advisories in limbo have waited more than a year.

## Coverage

Watchlist 68,002 repositories; 68,002 up to date on their schedule (daily for repos with an advisory in limbo, every 3 days for other repos with advisories, every 30 days and after each release for the rest); 6,576 checked in the last 24 hours; 37,989 reviewed advisories known. Every number is a floor: the tracker only sees repositories on its watchlist. Version ranges are as entered by maintainers and unreviewed.

_Advisory metadata from published GitHub repository security advisories and the GitHub Advisory Database (https://github.com/advisories, CC BY 4.0); CVE state from CVE Services; OSV.dev; NVD API (this product uses the NVD API but is not endorsed or certified by the NVD). Compiled by Limbowatch (https://limbo.watch), CC BY 4.0._
