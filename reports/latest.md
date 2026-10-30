# Limbo Tracker daily report — 2026-10-30

Generated 2026-10-30 13:12:50 UTC; changes since 2026-10-29 13:19:53 UTC.

## Now

- **6,655 advisories in limbo** (+383 since the last report): published by maintainers on GitHub, in ecosystems GitHub reviews, but not yet in GitHub's reviewed database or OSV.
  - 3,608 with no CVE anywhere · 489 citing a CVE that's still only reserved · 1,003 with a CVE from another CNA they don't cite
  - severity: 654 critical, 2,617 high, 2,773 medium, 611 low · median wait so far 49.5 days
- **4,131 more are likely permanent** (+385 since the last report): in ecosystems GitHub doesn't review, so GitHub-based scanners will probably never see them.

## Since the last report

- **71 newly published** advisories entered limbo.
- 328 older advisories were found for the first time (newly watched repos).
- **Left limbo:** 20 reviewed by GitHub, 0 found to duplicate a reviewed advisory, 0 withdrawn or unpublished.
- **CVE changes:** 85 (3 reserved CVEs published, 33 new CVEs from other CNAs).

## Newly published, in limbo

| Advisory | Package | Severity | CVE | Days | Fixed in |
|---|---|---|---|---:|---|
| [GHSA-qfmw-gw96-ffcr](https://github.com/rancher/fleet/security/advisories/GHSA-qfmw-gw96-ffcr) | `go: github.com/rancher/fleet` | critical | CVE reserved (RBP) (CVE-2026-94290) | 0 | 0.13.17; 0.14.12; 0.15.8; 0.16.3 |
| [GHSA-5pgx-q9xx-j3qv](https://github.com/lxc/incus/security/advisories/GHSA-5pgx-q9xx-j3qv) | `go:github.com/lxc/incus/v7/cmd/incusd` | critical | no CVE anywhere | 0 | >= v7.6.0 |
| [GHSA-jcw9-v2ff-8m79](https://github.com/lxc/incus/security/advisories/GHSA-jcw9-v2ff-8m79) | `go:github.com/lxc/incus/v7/cmd/incusd` | critical | no CVE anywhere | 0 | >= v7.6.0 |
| [GHSA-xg75-xf37-cph9](https://github.com/lxc/incus/security/advisories/GHSA-xg75-xf37-cph9) | `go:github.com/lxc/incus/v7/cmd/incusd` | critical | no CVE anywhere | 0 | >= v7.6.0 |
| [GHSA-p45f-gqqj-6qq3](https://github.com/lxc/incus/security/advisories/GHSA-p45f-gqqj-6qq3) | `go:github.com/lxc/incus/v7/cmd/incusd` | critical | no CVE anywhere | 0 | >= v7.6.0 |
| [GHSA-q9fc-p923-6vp7](https://github.com/lxc/incus/security/advisories/GHSA-q9fc-p923-6vp7) | `go:github.com/lxc/incus/v7/cmd/incusd` | critical | no CVE anywhere | 0 | >= v7.6.0 |
| [GHSA-cwg9-8mc4-hf7j](https://github.com/lxc/incus/security/advisories/GHSA-cwg9-8mc4-hf7j) | `go:github.com/lxc/incus/v7/cmd/incusd` | critical | no CVE anywhere | 0 | >= v7.6.0 |
| [GHSA-5c64-j5m6-8433](https://github.com/lxc/incus/security/advisories/GHSA-5c64-j5m6-8433) | `go:github.com/lxc/incus/v7/cmd/incusd` | critical | no CVE anywhere | 0 | >= v7.6.0 |
| [GHSA-3wxw-5gh2-j2x2](https://github.com/lxc/incus/security/advisories/GHSA-3wxw-5gh2-j2x2) | `go:github.com/lxc/incus/v7/cmd/incusd` | critical | no CVE anywhere | 0 | >= v7.6.0 |
| [GHSA-8r7w-f22p-qfhh](https://github.com/ChilliCream/graphql-platform/security/advisories/GHSA-8r7w-f22p-qfhh) | `nuget:HotChocolate.AspNetCore, nuget:HotChocolate.Fusion.…` | critical | no CVE anywhere | 0 | 16.7.3 |
| [GHSA-g485-r83w-3cxj](https://github.com/ChilliCream/graphql-platform/security/advisories/GHSA-g485-r83w-3cxj) | `nuget:HotChocolate.AspNetCore, nuget:HotChocolate.Validation` | critical | no CVE anywhere | 0 | 16.7.3 |
| [GHSA-22xh-p7rr-c3vp](https://github.com/ChilliCream/graphql-platform/security/advisories/GHSA-22xh-p7rr-c3vp) | `nuget:HotChocolate.AspNetCore, nuget:HotChocolate.Fusion.…` | critical | no CVE anywhere | 0 | 16.7.3 |
| [GHSA-j5vg-mqw8-p958](https://github.com/ChilliCream/graphql-platform/security/advisories/GHSA-j5vg-mqw8-p958) | `nuget:HotChocolate.AspNetCore, nuget:HotChocolate.Fusion,…` | critical | no CVE anywhere | 0 | 13.9.19; 14.3.4; 15.1.20; 16.7.3 |
| [GHSA-pxqr-744h-rvvx](https://github.com/ChilliCream/graphql-platform/security/advisories/GHSA-pxqr-744h-rvvx) | `nuget:HotChocolate.AspNetCore, nuget:HotChocolate.Fusion.…` | critical | no CVE anywhere | 0 | 16.7.3 |
| [GHSA-6rwj-6h6r-xmch](https://github.com/lxsmnsyc/seroval/security/advisories/GHSA-6rwj-6h6r-xmch) | `npm:seroval-plugins` | high | no CVE anywhere | 0 | 1.7.4 |
| [GHSA-4rw8-495r-pf6j](https://github.com/rmosolgo/graphql-ruby/security/advisories/GHSA-4rw8-495r-pf6j) | `rubygems:graphql` | high | no CVE anywhere | 0 | 2.6.14 |
| [GHSA-fc89-m4rj-8472](https://github.com/lxsmnsyc/seroval/security/advisories/GHSA-fc89-m4rj-8472) | `npm:seroval-plugins` | high | no CVE anywhere | 0 | 1.7.5 |
| [GHSA-x8v2-vj73-gfwm](https://github.com/lancedb/lancedb/security/advisories/GHSA-x8v2-vj73-gfwm) | `pip:lancedb` | high | no CVE anywhere | 0 | >=0.41.0 |
| [GHSA-p39g-3xw6-83jx](https://github.com/nolabs-ai/nono/security/advisories/GHSA-p39g-3xw6-83jx) | `rust:nono` | high | no CVE anywhere | 0 | <0.81.0 |
| [GHSA-gx8v-2929-9q95](https://github.com/rancher/fleet/security/advisories/GHSA-gx8v-2929-9q95) | `go: github.com/rancher/fleet` | high | CVE reserved (RBP) (CVE-2026-104615) | 0 | 0.13.17; 0.14.12; 0.15.17; 0.16.3 |
| [GHSA-f9gf-wh3x-jx3v](https://github.com/rancher/rancher/security/advisories/GHSA-f9gf-wh3x-jx3v) | `go:github.com/rancher/rancher` | high | CVE reserved (RBP) (CVE-2026-88809) | 0 | 2.11.19; 2.12.15; 2.13.11; 2.14.7; 2.15. |
| [GHSA-x82x-2qj6-5rm2](https://github.com/rancher/rancher/security/advisories/GHSA-x82x-2qj6-5rm2) | `go:github.com/rancher/rancher` | high | CVE reserved (RBP) (CVE-2026-88811) | 0 | 2.11.19; 2.12.15; 2.13.11; 2.14.7; 2.15. |
| [GHSA-x3j2-rfj9-cc32](https://github.com/appsmithorg/appsmith/security/advisories/GHSA-x3j2-rfj9-cc32) | `maven:com.appsmith:server` | high | no CVE anywhere | 0 | 2.4 |
| [GHSA-342c-q2qr-jxrj](https://github.com/appsmithorg/appsmith/security/advisories/GHSA-342c-q2qr-jxrj) | `maven:com.appsmith:server` | high | no CVE anywhere | 0 | 2.4 |
| [GHSA-3rgf-297m-775x](https://github.com/lxc/incus/security/advisories/GHSA-3rgf-297m-775x) | `go:github.com/lxc/incus/v7/cmd/incusd` | high | no CVE anywhere | 0 | >= v7.6.0 |

…and 46 more (see the feed).

## CVE changes

| Advisory | Change |
|---|---|
| [GHSA-2qm8-x737-gmw5](https://github.com/pyasn1/pyasn1/security/advisories/GHSA-2qm8-x737-gmw5) | cites CVE-2026-119196 (was none) |
| [GHSA-2vgq-wchc-25w7](https://github.com/digitalbazaar/forge/security/advisories/GHSA-2vgq-wchc-25w7) | cites CVE-2026-118776 (was none) |
| [GHSA-3594-hhm2-76fj](https://github.com/lightdash/lightdash/security/advisories/GHSA-3594-hhm2-76fj) | CVE-2026-61576 RESERVED -> PUBLISHED |
| [GHSA-3g3m-2fjr-6pw4](https://github.com/isaacs/node-glob/security/advisories/GHSA-3g3m-2fjr-6pw4) | cites CVE-2026-118773 (was none) |
| [GHSA-3r89-v5mq-j5xf](https://github.com/bytecodealliance/wasmtime/security/advisories/GHSA-3r89-v5mq-j5xf) | new CVE from another CNA: CVE-2026-119142 |
| [GHSA-3xf4-9g3c-4h4w](https://github.com/nuxt/nuxt/security/advisories/GHSA-3xf4-9g3c-4h4w) | cites CVE-2026-119201 (was none) |
| [GHSA-42gh-23hr-vphw](https://github.com/py-pdf/pypdf/security/advisories/GHSA-42gh-23hr-vphw) | cites CVE-2026-119206 (was none) |
| [GHSA-4487-j8r4-4g2f](https://github.com/digitalbazaar/forge/security/advisories/GHSA-4487-j8r4-4g2f) | cites CVE-2026-118780 (was none) |
| [GHSA-4642-5mcj-2rqw](https://github.com/digitalbazaar/forge/security/advisories/GHSA-4642-5mcj-2rqw) | cites CVE-2026-118775 (was none) |
| [GHSA-4jq2-8v3c-97w8](https://github.com/mariadb-corporation/mariadb-connector-j/security/advisories/GHSA-4jq2-8v3c-97w8) | cites CVE-2026-119280 (was none) |
| [GHSA-4vqv-7265-gm2w](https://github.com/py-pdf/pypdf/security/advisories/GHSA-4vqv-7265-gm2w) | cites CVE-2026-119207 (was none) |
| [GHSA-525v-9gp9-w22h](https://github.com/digitalbazaar/forge/security/advisories/GHSA-525v-9gp9-w22h) | cites CVE-2026-118778 (was none) |
| [GHSA-54p9-vhhq-8f7q](https://github.com/bytecodealliance/wasmtime/security/advisories/GHSA-54p9-vhhq-8f7q) | new CVE from another CNA: CVE-2026-119132 |
| [GHSA-556j-q8c8-qqg3](https://github.com/siyuan-note/siyuan/security/advisories/GHSA-556j-q8c8-qqg3) | cites CVE-2026-100645 (was none) |
| [GHSA-5849-834g-hvw5](https://github.com/py-pdf/pypdf/security/advisories/GHSA-5849-834g-hvw5) | cites CVE-2026-119203 (was none) |
| [GHSA-5cwg-6vw7-rj6p](https://github.com/digitalbazaar/forge/security/advisories/GHSA-5cwg-6vw7-rj6p) | cites CVE-2026-119186 (was none) |
| [GHSA-5hhx-4wrr-3j9g](https://github.com/bytecodealliance/wasmtime/security/advisories/GHSA-5hhx-4wrr-3j9g) | new CVE from another CNA: CVE-2026-119140 |
| [GHSA-5qpp-g3j2-8frx](https://github.com/bytecodealliance/wasmtime/security/advisories/GHSA-5qpp-g3j2-8frx) | new CVE from another CNA: CVE-2026-119130 |
| [GHSA-5x38-2vff-x55p](https://github.com/digitalbazaar/forge/security/advisories/GHSA-5x38-2vff-x55p) | cites CVE-2026-119190 (was none) |
| [GHSA-62m5-6wh8-28x7](https://github.com/py-pdf/pypdf/security/advisories/GHSA-62m5-6wh8-28x7) | cites CVE-2026-119208 (was none) |
| [GHSA-63h4-6cx9-pjfj](https://github.com/bytecodealliance/wasmtime/security/advisories/GHSA-63h4-6cx9-pjfj) | new CVE from another CNA: CVE-2026-119135 |
| [GHSA-648h-gw55-m2g7](https://github.com/nuxt/nuxt/security/advisories/GHSA-648h-gw55-m2g7) | cites CVE-2026-119199 (was none) |
| [GHSA-6pmg-vc6m-6wrr](https://github.com/frappe/frappe/security/advisories/GHSA-6pmg-vc6m-6wrr) | new CVE from another CNA: CVE-2026-119144 |
| [GHSA-6qrw-m8cv-hcxf](https://github.com/digitalbazaar/forge/security/advisories/GHSA-6qrw-m8cv-hcxf) | cites CVE-2026-119192 (was none) |
| [GHSA-6wvx-3r32-xmcg](https://github.com/digitalbazaar/forge/security/advisories/GHSA-6wvx-3r32-xmcg) | cites CVE-2026-118777 (was none) |

…and 60 more.

## Longest waiting

| Advisory | Package | Severity | CVE | Days | Fixed in |
|---|---|---|---|---:|---|
| [GHSA-6pc9-r5gr-m9c9](https://github.com/rschultheis/many_versioned_gem/security/advisories/GHSA-6pc9-r5gr-m9c9) | `rubygems:many_versioned_gem` | medium | no CVE anywhere | 2815 | 0.1.1 |
| [GHSA-3wjh-93gr-chh6](https://github.com/flarum/framework/security/advisories/GHSA-3wjh-93gr-chh6) | `composer:flarum/core` | high | CVE published, cited (CVE-2019-13183) | 2674 | 0.1.0-beta.9 |
| [GHSA-jchv-x857-q8fq](https://github.com/apple/swift-nio-http2/security/advisories/GHSA-jchv-x857-q8fq) | `swift:swift-nio-http2` | high | no CVE anywhere | 2634 | 1.5.0 |
| [GHSA-hv27-vjg3-m59x](https://github.com/apple/swift-nio-http2/security/advisories/GHSA-hv27-vjg3-m59x) | `swift:swift-nio-http2` | high | CVE published, cited (CVE-2019-9515) | 2634 | 1.5.0 |
| [GHSA-9cqv-v2w2-7j52](https://github.com/apple/swift-nio-http2/security/advisories/GHSA-9cqv-v2w2-7j52) | `swift:swift-nio-http2` | high | CVE published, cited (CVE-2019-9516) | 2634 | 1.5.0 |

## Coverage

Watchlist 16,499 repositories; 16,499 up to date on their schedule (daily for repos with an advisory in limbo, every 3 to 7 days for the rest); 1,419 checked in the last 24 hours; 37,437 reviewed advisories known. Every number is a floor: the tracker only sees repositories on its watchlist. Version ranges are as entered by maintainers and unreviewed.

_Advisory metadata from published GitHub repository security advisories and the GitHub Advisory Database (https://github.com/advisories, CC BY 4.0); CVE state from CVE Services; OSV.dev; NVD API (this product uses the NVD API but is not endorsed or certified by the NVD). Compiled by Limbowatch (https://limbo.watch), CC BY 4.0._
