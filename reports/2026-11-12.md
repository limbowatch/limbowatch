# Limbo Tracker daily report — 2026-11-12

Generated 2026-11-12 15:51:59 UTC; changes since 2026-11-11 14:51:29 UTC.

## Now

- **10,239 advisories in limbo** (+180 since the last report: 153 newly published, 27 older ones found for the first time, 0 left limbo): published by maintainers on GitHub, in ecosystems GitHub reviews, but not yet in GitHub's reviewed database or OSV.
  - 5,751 with no CVE anywhere · 601 citing a CVE that's still only reserved · 1,241 with a CVE from another CNA they don't cite
  - severity: 969 critical, 4,006 high, 4,306 medium, 958 low · median wait so far 52.7 days
- **15,196 more are likely permanent** (+151 since the last report: 133 newly published, 18 older ones found for the first time, 0 left limbo): in ecosystems GitHub doesn't review, so GitHub-based scanners will probably never see them.

## Since the last report

- **153 newly published** advisories entered limbo.
- 27 older advisories were found for the first time (27 in newly watched repos).
- **Left limbo** (likely permanent included): 0 reviewed by GitHub, 0 found to duplicate a reviewed advisory, 0 withdrawn or unpublished.
- **CVE changes:** 31 (23 reserved CVEs published, 5 new CVEs from other CNAs).

## Newly published, in limbo

| Advisory | Package | Severity | CVE | Days | Fixed in |
|---|---|---|---|---:|---|
| [GHSA-4g86-54fm-h9h8](https://github.com/microsoft/aspire/security/advisories/GHSA-4g86-54fm-h9h8) | `nuget:Aspire.Dashboard.Sdk.linux-arm64, nuget:Aspire.Dash…` | critical | CVE published, cited (CVE-2026-118740) | 1 | 13.6.5 |
| [GHSA-33f6-vcmh-2xfm](https://github.com/gpustack/gpustack/security/advisories/GHSA-33f6-vcmh-2xfm) | `pip:gpustack` | critical | no CVE anywhere | 0 | 2.3.1 |
| [GHSA-gjf9-3p3r-9h9c](https://github.com/gpustack/gpustack/security/advisories/GHSA-gjf9-3p3r-9h9c) | `pip:gpustack` | critical | no CVE anywhere | 0 | 2.3.1 |
| [GHSA-jj89-69wm-jj39](https://github.com/apostrophecms/apostrophe/security/advisories/GHSA-jj89-69wm-jj39) | `npm:apostrophe` | critical | no CVE anywhere | 0 | 4.34.1 |
| [GHSA-pwg8-2x8c-wc2m](https://github.com/Dokploy/dokploy/security/advisories/GHSA-pwg8-2x8c-wc2m) | `npm:dokploy` | critical | no CVE anywhere | 0 | – |
| [GHSA-mv55-58pg-4xgf](https://github.com/gpustack/gpustack/security/advisories/GHSA-mv55-58pg-4xgf) | `pip:gpustack` | high | no CVE anywhere | 0 | 2.3.1 |
| [GHSA-7345-vjfr-2hcx](https://github.com/gpustack/gpustack/security/advisories/GHSA-7345-vjfr-2hcx) | `pip:gpustack` | high | no CVE anywhere | 0 | 2.3.1 |
| [GHSA-9jmg-hx5p-h592](https://github.com/gpustack/gpustack/security/advisories/GHSA-9jmg-hx5p-h592) | `pip:gpustack` | high | no CVE anywhere | 0 | 2.3.0 |
| [GHSA-9vwx-hfm8-g59g](https://github.com/gpustack/gpustack/security/advisories/GHSA-9vwx-hfm8-g59g) | `pip:gpustack` | high | no CVE anywhere | 0 | 2.3.1 |
| [GHSA-hgj7-52cp-647p](https://github.com/micronaut-projects/micronaut-core/security/advisories/GHSA-hgj7-52cp-647p) | `maven:io.micronaut:micronaut-http-server-netty` | high | no CVE anywhere | 0 | 3.10.19, 4.10.37, 5.2.23 |
| [GHSA-4j6j-v86m-5xv7](https://github.com/micronaut-projects/micronaut-core/security/advisories/GHSA-4j6j-v86m-5xv7) | `maven:io.micronaut:micronaut-http-netty, maven:io.microna…` | high | no CVE anywhere | 0 | 4.10.30, 5.2.2, 3.10.13 |
| [GHSA-88m6-wjjg-mc7g](https://github.com/micronaut-projects/micronaut-core/security/advisories/GHSA-88m6-wjjg-mc7g) | `maven:io.micronaut:micronaut-http-server, maven:io.micron…` | high | no CVE anywhere | 0 | 5.2.23 |
| [GHSA-v7wh-x8v3-vgrv](https://github.com/rpgp/rpgp/security/advisories/GHSA-v7wh-x8v3-vgrv) | `rust:pgp` | high | no CVE anywhere | 0 | 0.21.1 |
| [GHSA-9wx5-rxfg-8rpw](https://github.com/apostrophecms/apostrophe/security/advisories/GHSA-9wx5-rxfg-8rpw) | `npm:apostrophe` | high | no CVE anywhere | 0 | 4.34.1 |
| [GHSA-xpxg-j6jm-rp27](https://github.com/django-tenants/django-tenants/security/advisories/GHSA-xpxg-j6jm-rp27) | `pip:django-tenants` | high | no CVE anywhere | 0 | 4.0.2 |
| [GHSA-696p-p8vv-3jjf](https://github.com/qax-os/excelize/security/advisories/GHSA-696p-p8vv-3jjf) | `go:github.com/xuri/excelize/v2` | high | no CVE anywhere | 0 | – |
| [GHSA-3j3m-rp8w-pxpv](https://github.com/flytohub/flyto-core/security/advisories/GHSA-3j3m-rp8w-pxpv) | `pip:flyto-core` | high | no CVE anywhere | 0 | 2.41.0 |
| [GHSA-24v5-vjqf-qhv9](https://github.com/siyuan-note/siyuan/security/advisories/GHSA-24v5-vjqf-qhv9) | `go:github.com/siyuan-note/dejavu` | high | no CVE anywhere | 0 | v3.8.11 |
| [GHSA-h3mh-9vmc-cpfg](https://github.com/frappe/frappe/security/advisories/GHSA-h3mh-9vmc-cpfg) | `pip:frappe` | high | no CVE anywhere | 0 | 16.35.0, 15.121.1 |
| [GHSA-qrxv-3vjh-gpx7](https://github.com/frappe/frappe/security/advisories/GHSA-qrxv-3vjh-gpx7) | `pip:frappe` | high | no CVE anywhere | 0 | 16.36.0, 15.121.2 |
| [GHSA-vp4r-5v6w-r962](https://github.com/frappe/frappe/security/advisories/GHSA-vp4r-5v6w-r962) | `pip:frappe` | high | no CVE anywhere | 0 | 16.33.0, 15.120.0 |
| [GHSA-582m-wh92-4vhr](https://github.com/zereight/gitlab-mcp/security/advisories/GHSA-582m-wh92-4vhr) | `npm:@zereight/mcp-gitlab` | high | no CVE anywhere | 0 | 2.3.26 |
| [GHSA-qrx6-xqcq-pwhh](https://github.com/ChilliCream/graphql-platform/security/advisories/GHSA-qrx6-xqcq-pwhh) | `nuget:HotChocolate.AspNetCore, nuget:HotChocolate.CostAna…` | high | no CVE anywhere | 0 | 16.7.4, 15.1.21, 14.3.5, 13.9.20 |
| [GHSA-qfcm-85pq-g95p](https://github.com/ChilliCream/graphql-platform/security/advisories/GHSA-qfcm-85pq-g95p) | `nuget:HotChocolate.ApolloFederation, nuget:HotChocolate.A…` | high | no CVE anywhere | 0 | 16.7.4 |
| [GHSA-x5xr-hpjp-f34h](https://github.com/ChilliCream/graphql-platform/security/advisories/GHSA-x5xr-hpjp-f34h) | `nuget:HotChocolate.AspNetCore, nuget:HotChocolate.Fusion.…` | high | no CVE anywhere | 0 | 16.7.4 |

…and 128 more (see the feed).

## CVE changes

| Advisory | Change |
|---|---|
| [GHSA-22xj-f767-ppw6](https://github.com/getprobo/probo/security/advisories/GHSA-22xj-f767-ppw6) | CVE-2026-76078 RESERVED -> PUBLISHED |
| [GHSA-2x86-cf3f-86gw](https://github.com/ForbesLindesay/sync-rpc/security/advisories/GHSA-2x86-cf3f-86gw) | CVE-2026-65843 RESERVED -> PUBLISHED |
| [GHSA-378x-q589-34mv](https://github.com/heymrun/heym/security/advisories/GHSA-378x-q589-34mv) | CVE-2026-67546 RESERVED -> PUBLISHED |
| [GHSA-395p-pj7r-jm42](https://github.com/fulgur-rs/fulgur/security/advisories/GHSA-395p-pj7r-jm42) | CVE-2026-68538 RESERVED -> PUBLISHED |
| [GHSA-3v8c-738m-4gcj](https://github.com/opencloud-eu/reva/security/advisories/GHSA-3v8c-738m-4gcj) | CVE-2026-57500 RESERVED -> PUBLISHED |
| [GHSA-4pv2-52v7-vrfx](https://github.com/python-social-auth/social-core/security/advisories/GHSA-4pv2-52v7-vrfx) | new CVE from another CNA: CVE-2026-126775 |
| [GHSA-5748-x76g-v68m](https://github.com/heymrun/heym/security/advisories/GHSA-5748-x76g-v68m) | CVE-2026-67540 RESERVED -> PUBLISHED |
| [GHSA-5wqw-q7gh-j65v](https://github.com/meeting-room-booking-system/mrbs-code/security/advisories/GHSA-5wqw-q7gh-j65v) | cites CVE-2026-124474 (was none) |
| [GHSA-6jp8-c2w2-x7wr](https://github.com/coreruleset/coreruleset/security/advisories/GHSA-6jp8-c2w2-x7wr) | CVE-2026-62971 RESERVED -> PUBLISHED |
| [GHSA-6vw5-w22x-ghxv](https://github.com/tinacms/tinacms/security/advisories/GHSA-6vw5-w22x-ghxv) | new CVE from another CNA: CVE-2026-126774 |
| [GHSA-75qh-632x-j5pr](https://github.com/maplibre/geojson-vt/security/advisories/GHSA-75qh-632x-j5pr) | CVE-2026-58505 RESERVED -> PUBLISHED |
| [GHSA-773r-585g-6vc3](https://github.com/blueprintue/blueprintue-self-hosted-edition/security/advisories/GHSA-773r-585g-6vc3) | cites CVE-2026-122138 (was none) |
| [GHSA-7fgc-3h6c-698r](https://github.com/Power-Components/livewire-powergrid/security/advisories/GHSA-7fgc-3h6c-698r) | CVE-2026-65971 RESERVED -> PUBLISHED |
| [GHSA-8wj7-v2w6-wfcx](https://github.com/heymrun/heym/security/advisories/GHSA-8wj7-v2w6-wfcx) | CVE-2026-67545 RESERVED -> PUBLISHED |
| [GHSA-c74x-79w6-63jh](https://github.com/getprobo/probo/security/advisories/GHSA-c74x-79w6-63jh) | CVE-2026-63505 RESERVED -> PUBLISHED |
| [GHSA-cppp-g98f-gfpp](https://github.com/getprobo/probo/security/advisories/GHSA-cppp-g98f-gfpp) | CVE-2026-76079 RESERVED -> PUBLISHED |
| [GHSA-f5qm-3h4p-8qhg](https://github.com/coreruleset/coreruleset/security/advisories/GHSA-f5qm-3h4p-8qhg) | CVE-2026-61619 RESERVED -> PUBLISHED |
| [GHSA-fqg9-x2xw-5crx](https://github.com/gotenberg/gotenberg/security/advisories/GHSA-fqg9-x2xw-5crx) | new CVE from another CNA: CVE-2026-126799 |
| [GHSA-fwgq-c3c6-p67j](https://github.com/blueprintue/blueprintue-self-hosted-edition/security/advisories/GHSA-fwgq-c3c6-p67j) | cites CVE-2026-122139 (was none) |
| [GHSA-gf4p-7p27-26w7](https://github.com/opencloud-eu/opencloud/security/advisories/GHSA-gf4p-7p27-26w7) | CVE-2026-57500 RESERVED -> PUBLISHED |
| [GHSA-hcv7-mg77-pg73](https://github.com/heymrun/heym/security/advisories/GHSA-hcv7-mg77-pg73) | CVE-2026-67543 RESERVED -> PUBLISHED |
| [GHSA-hq2c-hh95-vrr6](https://github.com/siyuan-note/siyuan/security/advisories/GHSA-hq2c-hh95-vrr6) | new CVE from another CNA: CVE-2026-126776 |
| [GHSA-jjvx-3wfc-p8hq](https://github.com/heymrun/heym/security/advisories/GHSA-jjvx-3wfc-p8hq) | CVE-2026-67542 RESERVED -> PUBLISHED |
| [GHSA-mp23-7m6r-jfw4](https://github.com/heymrun/heym/security/advisories/GHSA-mp23-7m6r-jfw4) | CVE-2026-67544 RESERVED -> PUBLISHED |
| [GHSA-prh2-g8pv-m7p9](https://github.com/getprobo/probo/security/advisories/GHSA-prh2-g8pv-m7p9) | CVE-2026-64861 RESERVED -> PUBLISHED |

…and 6 more.

## Longest waiting, published in the last 90 days

| Advisory | Package | Severity | CVE | Days | Fixed in |
|---|---|---|---|---:|---|
| [GHSA-q55v-4cmj-xh65](https://github.com/go-gitea/gitea/security/advisories/GHSA-q55v-4cmj-xh65) | `go:gitea.dev` | high | CVE published, cited (CVE-2026-73804) | 89 | 1.27.2 |
| [GHSA-8xjr-x7rg-hp5h](https://github.com/go-gitea/gitea/security/advisories/GHSA-8xjr-x7rg-hp5h) | `go:gitea.dev` | high | CVE published, cited (CVE-2026-73535) | 89 | 1.27.2 |
| [GHSA-92j2-6qcg-c28c](https://github.com/go-gitea/gitea/security/advisories/GHSA-92j2-6qcg-c28c) | `go:gitea.dev` | high | CVE published, cited (CVE-2026-73278) | 89 | 1.27.2 |
| [GHSA-7452-653r-6gp8](https://github.com/go-gitea/gitea/security/advisories/GHSA-7452-653r-6gp8) | `go:gitea.dev` | medium | CVE published, cited (CVE-2026-60008) | 89 | 1.27.2 |
| [GHSA-8qcx-gvfr-p397](https://github.com/datamodel-code-generator/datamodel-code-generator/security/advisories/GHSA-8qcx-gvfr-p397) | `pip:datamodel-code-generator` | high | no CVE anywhere | 89 | 0.70.0 |

606 advisories in limbo have waited more than a year.

## Coverage

Watchlist 67,483 repositories; 67,483 up to date on their schedule (daily for repos with an advisory in limbo, every 3 days for other repos with advisories, every 30 days and after each release for the rest); 4,126 checked in the last 24 hours; 37,686 reviewed advisories known. Every number is a floor: the tracker only sees repositories on its watchlist. Version ranges are as entered by maintainers and unreviewed.

_Advisory metadata from published GitHub repository security advisories and the GitHub Advisory Database (https://github.com/advisories, CC BY 4.0); CVE state from CVE Services; OSV.dev; NVD API (this product uses the NVD API but is not endorsed or certified by the NVD). Compiled by Limbowatch (https://limbo.watch), CC BY 4.0._
