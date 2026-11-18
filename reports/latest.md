# Limbo Tracker daily report — 2026-11-18

Generated 2026-11-18 16:13:13 UTC; changes since 2026-11-17 16:42:45 UTC.

## Now

- **11,017 advisories in limbo** (+174 since the last report: 159 newly published, 21 older ones found for the first time, 6 left limbo): published by maintainers on GitHub, in ecosystems GitHub reviews, but not yet in GitHub's reviewed database or OSV.
  - 6,268 with no CVE anywhere · 606 citing a CVE that's still only reserved · 1,377 with a CVE from another CNA they don't cite
  - severity: 1,012 critical, 4,322 high, 4,644 medium, 1,039 low · median wait so far 53.9 days
- **15,752 more are likely permanent** (+160 since the last report: 108 newly published, 55 older ones found for the first time, 3 left limbo): in ecosystems GitHub doesn't review, so GitHub-based scanners will probably never see them.

## Since the last report

- **159 newly published** advisories entered limbo.
- 21 older advisories were found for the first time (20 in newly watched repos).
- **Left limbo** (likely permanent included): 8 reviewed by GitHub, 0 found to duplicate a reviewed advisory, 1 withdrawn or unpublished. GitHub reviewed 10 advisories in all in this period, from any repository.
- **CVE changes:** 160 (46 reserved CVEs published, 103 new CVEs from other CNAs).

## Newly published, in limbo

| Advisory | Package | Severity | CVE | Days | Fixed in |
|---|---|---|---|---:|---|
| [GHSA-95rw-c7w3-xh7f](https://github.com/langflow-ai/langflow/security/advisories/GHSA-95rw-c7w3-xh7f) | `pip:langflow, pip:langflow-base` | critical | CVE published, cited (`CVE-2026-7646`) | 0 | `1.9.1, 0.9.1` |
| [GHSA-h924-jfhp-9vjr](https://github.com/christianhelle/refitter/security/advisories/GHSA-h924-jfhp-9vjr) | `nuget:Refitter` | critical | no CVE anywhere | 0 | `–` |
| [GHSA-pf93-24xc-xgxc](https://github.com/faye/websocket-driver-ruby/security/advisories/GHSA-pf93-24xc-xgxc) | `rubygems:websocket-driver` | critical | no CVE anywhere | 0 | `0.9.0` |
| [GHSA-4frp-8844-m589](https://github.com/shopware/shopware/security/advisories/GHSA-4frp-8844-m589) | `composer:shopware/core, composer:shopware/platform` | critical | no CVE anywhere | 0 | `6.7.16.1, 6.6.10.32` |
| [GHSA-28fx-g7qc-7c24](https://github.com/shopware/shopware/security/advisories/GHSA-28fx-g7qc-7c24) | `composer:shopware/administration, composer:shopware/platform` | critical | no CVE anywhere | 0 | `6.6.10.32, 6.7.16.1` |
| [GHSA-fmvh-847r-3hmq](https://github.com/shopware/shopware/security/advisories/GHSA-fmvh-847r-3hmq) | `composer:shopware/core, composer:shopware/platform` | critical | no CVE anywhere | 0 | `6.6.10.32, 6.7.16.1` |
| [GHSA-cw69-92rj-fp3r](https://github.com/umbraco/Umbraco.Commerce.Issues/security/advisories/GHSA-cw69-92rj-fp3r) | `nuget:Umbraco.Commerce` | high | no CVE anywhere | 1 | `13.3.4, 17.2.13, 18.1.13, 19.0.0-rc.2` |
| [GHSA-6pff-wf7m-6f5h](https://github.com/k1LoW/mo/security/advisories/GHSA-6pff-wf7m-6f5h) | `go:github.com/k1LoW/mo` | high | no CVE anywhere | 1 | `1.8.1` |
| [GHSA-f646-3mjc-3w77](https://github.com/k1LoW/mo/security/advisories/GHSA-f646-3mjc-3w77) | `go:github.com/k1LoW/mo` | high | no CVE anywhere | 1 | `1.8.2` |
| [GHSA-pfg6-ffjv-jhmp](https://github.com/orneryd/NornicDB/security/advisories/GHSA-pfg6-ffjv-jhmp) | `go:github.com/orneryd/nornicdb` | high | no CVE anywhere | 0 | `1.5.0` |
| [GHSA-484r-38cf-9m96](https://github.com/microsoft/OpenAPI.NET/security/advisories/GHSA-484r-38cf-9m96) | `nuget:Microsoft.OpenApi` | high | no CVE anywhere | 0 | `3.11.0, 2.13.0` |
| [GHSA-67p7-xj24-jfm9](https://github.com/faye/permessage-deflate-node/security/advisories/GHSA-67p7-xj24-jfm9) | `npm:permessage-deflate, npm:websocket-driver, npm:websock…` | high | no CVE anywhere | 0 | `0.2.0, 0.8.0` |
| [GHSA-q35r-h2pj-j86x](https://github.com/faye/faye/security/advisories/GHSA-q35r-h2pj-j86x) | `npm:faye` | high | no CVE anywhere | 0 | `1.5.0` |
| [GHSA-qffv-7c9f-grmr](https://github.com/faye/faye/security/advisories/GHSA-qffv-7c9f-grmr) | `npm:faye` | high | no CVE anywhere | 0 | `1.5.0` |
| [GHSA-m4cr-m4qc-9hh3](https://github.com/pydantic/pydantic-ai/security/advisories/GHSA-m4cr-m4qc-9hh3) | `pip:pydantic-ai-harness` | high | no CVE anywhere | 0 | `0.70.0` |
| [GHSA-5m5q-5qj4-gx9h](https://github.com/pydantic/pydantic-ai/security/advisories/GHSA-5m5q-5qj4-gx9h) | `pip:pydantic-ai-harness` | high | no CVE anywhere | 0 | `0.70.0` |
| [GHSA-4rq7-f537-x35q](https://github.com/sebhildebrandt/systeminformation/security/advisories/GHSA-4rq7-f537-x35q) | `npm:systeminformation` | high | no CVE anywhere | 0 | `5.33.23` |
| [GHSA-p4q5-rhgr-hg46](https://github.com/middleapi/orpc/security/advisories/GHSA-p4q5-rhgr-hg46) | `npm:@orpc/server` | high | no CVE anywhere | 0 | `1.16.3` |
| [GHSA-mvm8-x28h-fw3q](https://github.com/QwikDev/qwik/security/advisories/GHSA-mvm8-x28h-fw3q) | `npm:@builder.io/qwik` | high | no CVE anywhere | 0 | `1.20.4` |
| [GHSA-4g84-qfwg-r9wx](https://github.com/QwikDev/qwik/security/advisories/GHSA-4g84-qfwg-r9wx) | `npm:@qwik.dev/core` | high | no CVE anywhere | 0 | `1.20.4, 2.0.0-rc.5` |
| [GHSA-7fcf-wrcg-gcgf](https://github.com/shopware/shopware/security/advisories/GHSA-7fcf-wrcg-gcgf) | `composer:shopware/core, composer:shopware/platform` | high | no CVE anywhere | 0 | `6.6.10.32, 6.7.16.1` |
| [GHSA-g8r6-cxw8-f75w](https://github.com/shopware/shopware/security/advisories/GHSA-g8r6-cxw8-f75w) | `composer:shopware/core, composer:shopware/platform` | high | no CVE anywhere | 0 | `6.7.16.1` |
| [GHSA-4v6j-jh9j-pmch](https://github.com/shopware/shopware/security/advisories/GHSA-4v6j-jh9j-pmch) | `composer:shopware/core, composer:shopware/platform` | high | no CVE anywhere | 0 | `6.6.10.32, 6.7.16.1` |
| [GHSA-4v2w-jpmg-wp82](https://github.com/shopware/shopware/security/advisories/GHSA-4v2w-jpmg-wp82) | `composer:shopware/core, composer:shopware/platform` | high | no CVE anywhere | 0 | `6.7.16.1, 6.6.10.32` |
| [GHSA-59j5-8mv2-2fc5](https://github.com/shopware/shopware/security/advisories/GHSA-59j5-8mv2-2fc5) | `composer:shopware/core, composer:shopware/platform` | high | no CVE anywhere | 0 | `6.6.10.32, 6.7.16.1` |

…and 134 more: [the tracker](https://limbo.watch/tracker/) lists them all, newest first.

## CVE changes

| Advisory | Change |
|---|---|
| [GHSA-c6vj-372g-m3cw](https://github.com/LabRedesCefetRJ/WeGIA/security/advisories/GHSA-c6vj-372g-m3cw) | CVE-2026-61675 RESERVED -> PUBLISHED |
| [GHSA-cw2f-3w8g-4x9q](https://github.com/signalwire/freeswitch/security/advisories/GHSA-cw2f-3w8g-4x9q) | CVE-2026-119293 RESERVED -> PUBLISHED |
| [GHSA-f732-866c-g3hc](https://github.com/LabRedesCefetRJ/WeGIA/security/advisories/GHSA-f732-866c-g3hc) | CVE-2026-61676 RESERVED -> PUBLISHED |
| [GHSA-fjwm-mmjp-c6vm](https://github.com/LabRedesCefetRJ/WeGIA/security/advisories/GHSA-fjwm-mmjp-c6vm) | CVE-2026-61680 RESERVED -> PUBLISHED |
| [GHSA-mvj8-mqqq-2w5f](https://github.com/ZoneMinder/zoneminder/security/advisories/GHSA-mvj8-mqqq-2w5f) | CVE-2026-28273 RESERVED -> PUBLISHED |
| [GHSA-pfwx-xjp4-qxcj](https://github.com/ontola/atomic-server/security/advisories/GHSA-pfwx-xjp4-qxcj) | CVE-2026-69157 RESERVED -> PUBLISHED |
| [GHSA-pvhq-2cf3-xmch](https://github.com/LabRedesCefetRJ/WeGIA/security/advisories/GHSA-pvhq-2cf3-xmch) | CVE-2026-61677 RESERVED -> PUBLISHED |
| [GHSA-x585-4vv8-2mh2](https://github.com/rucio/rucio/security/advisories/GHSA-x585-4vv8-2mh2) | CVE-2026-100397 RESERVED -> PUBLISHED |
| [GHSA-27h8-4v64-8v85](https://github.com/LabRedesCefetRJ/WeGIA/security/advisories/GHSA-27h8-4v64-8v85) | CVE-2026-69187 RESERVED -> PUBLISHED |
| [GHSA-464h-4j8h-q5mf](https://github.com/mganss/HtmlSanitizer/security/advisories/GHSA-464h-4j8h-q5mf) | CVE-2026-102529 RESERVED -> PUBLISHED |
| [GHSA-5hj8-q7fv-qrj6](https://github.com/russellhaering/gosaml2/security/advisories/GHSA-5hj8-q7fv-qrj6) | CVE-2026-128073 RESERVED -> PUBLISHED |
| [GHSA-6qrw-m8cv-hcxf](https://github.com/digitalbazaar/forge/security/advisories/GHSA-6qrw-m8cv-hcxf) | CVE-2026-119192 RESERVED -> PUBLISHED |
| [GHSA-8j7w-m3cr-6q6x](https://github.com/pi-hole/FTL/security/advisories/GHSA-8j7w-m3cr-6q6x) | CVE-2026-65963 RESERVED -> PUBLISHED |
| [GHSA-8vc4-8hjq-988p](https://github.com/ontola/atomic-server/security/advisories/GHSA-8vc4-8hjq-988p) | CVE-2026-69156 RESERVED -> PUBLISHED |
| [GHSA-ff87-73jp-f3v4](https://github.com/ontola/atomic-server/security/advisories/GHSA-ff87-73jp-f3v4) | CVE-2026-69158 RESERVED -> PUBLISHED |
| [GHSA-g6f8-c3x9-jv7f](https://github.com/code16/sharp/security/advisories/GHSA-g6f8-c3x9-jv7f) | CVE-2026-84987 RESERVED -> PUBLISHED |
| [GHSA-ggg2-79hg-mwrp](https://github.com/chevereto/chevereto/security/advisories/GHSA-ggg2-79hg-mwrp) | CVE-2026-104796 RESERVED -> PUBLISHED |
| [GHSA-jmmc-wjpc-pg34](https://github.com/xwiki/xwiki-platform/security/advisories/GHSA-jmmc-wjpc-pg34) | CVE-2026-61689 RESERVED -> PUBLISHED |
| [GHSA-phmp-hrw4-r36r](https://github.com/lepture/mistune/security/advisories/GHSA-phmp-hrw4-r36r) | CVE-2026-97698 RESERVED -> PUBLISHED |
| [GHSA-pw8r-75cr-c993](https://github.com/cri-o/cri-o/security/advisories/GHSA-pw8r-75cr-c993) | CVE-2026-106096 RESERVED -> PUBLISHED |
| [GHSA-q6fm-xwxf-37r5](https://github.com/pi-hole/FTL/security/advisories/GHSA-q6fm-xwxf-37r5) | CVE-2025-62165 RESERVED -> PUBLISHED |
| [GHSA-r7hw-jx6r-756g](https://github.com/simplesamlphp/saml2/security/advisories/GHSA-r7hw-jx6r-756g) | CVE-2026-110782 RESERVED -> PUBLISHED |
| [GHSA-rjvf-fxv5-x87j](https://github.com/espressif/esp-idf/security/advisories/GHSA-rjvf-fxv5-x87j) | CVE-2026-113781 RESERVED -> PUBLISHED |
| [GHSA-rvfr-cqwq-rc4j](https://github.com/libp2p/js-libp2p/security/advisories/GHSA-rvfr-cqwq-rc4j) | CVE-2026-110789 RESERVED -> PUBLISHED |
| [GHSA-vxf4-mrgm-vp43](https://github.com/LabRedesCefetRJ/WeGIA/security/advisories/GHSA-vxf4-mrgm-vp43) | CVE-2026-69188 RESERVED -> PUBLISHED |

…and 135 more.

## Longest waiting, published in the last 90 days

| Advisory | Package | Severity | CVE | Days | Fixed in |
|---|---|---|---|---:|---|
| [GHSA-7vcx-mhxq-9j96](https://github.com/directus/directus/security/advisories/GHSA-7vcx-mhxq-9j96) | `npm:directus` | high | no CVE anywhere | 89 | `12.2.0` |
| [GHSA-4jw7-6mqj-vrhq](https://github.com/directus/directus/security/advisories/GHSA-4jw7-6mqj-vrhq) | `npm:directus` | high | no CVE anywhere | 89 | `12.2.0` |
| [GHSA-gwvv-rr68-cmv6](https://github.com/directus/directus/security/advisories/GHSA-gwvv-rr68-cmv6) | `npm:directus` | high | no CVE anywhere | 89 | `12.2.0` |
| [GHSA-jj85-wvj2-r86m](https://github.com/TryGhost/Ghost/security/advisories/GHSA-jj85-wvj2-r86m) | `npm:ghost` | medium | CVE published by another CNA, not cited (`CVE-2026-103273`) | 89 | `v6.58.0` |
| [GHSA-5ppm-p957-x46r](https://github.com/TryGhost/Ghost/security/advisories/GHSA-5ppm-p957-x46r) | `npm:ghost` | medium | CVE published by another CNA, not cited (`CVE-2026-103274`) | 89 | `v6.58.0` |

609 advisories in limbo have waited more than a year.

## Coverage

Watchlist 67,748 repositories; 67,748 up to date on their schedule (daily for repos with an advisory in limbo, every 3 days for other repos with advisories, every 30 days and after each release for the rest); 6,845 checked in the last 24 hours; 37,834 reviewed advisories known. Every number is a floor: the tracker only sees repositories on its watchlist. Version ranges are as entered by maintainers and unreviewed.

_Advisory metadata from published GitHub repository security advisories and the GitHub Advisory Database (https://github.com/advisories, CC BY 4.0); CVE state from CVE Services; OSV.dev; NVD API (this product uses the NVD API but is not endorsed or certified by the NVD). Compiled by Limbowatch (https://limbo.watch), CC BY 4.0._
