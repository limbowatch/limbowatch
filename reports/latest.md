# Limbo Tracker daily report — 2026-11-25

Generated 2026-11-25 17:42:16 UTC; changes since 2026-11-24 18:21:52 UTC.

## Now

- **12,278 advisories in limbo** (+230 since the last report: 225 newly published, 12 older ones found for the first time, 7 left limbo): published by maintainers on GitHub, in ecosystems GitHub reviews, but not yet in GitHub's reviewed database or OSV.
  - 7,251 with no CVE anywhere · 560 citing a CVE that's still only reserved · 1,558 with a CVE from another CNA they don't cite
  - severity: 1,085 critical, 4,749 high, 5,211 medium, 1,233 low · median wait so far 52.9 days
- **16,586 more are likely permanent** (+130 since the last report: 97 newly published, 33 older ones found for the first time, 0 left limbo): in ecosystems GitHub doesn't review, so GitHub-based scanners will probably never see them.

## Since the last report

- **225 newly published** advisories entered limbo.
- 12 older advisories were found for the first time (4 in newly watched repos).
- **Left limbo** (likely permanent included): 7 reviewed by GitHub, 0 found to duplicate a reviewed advisory, 0 withdrawn or unpublished. GitHub reviewed 8 advisories in all in this period, from any repository.
- **CVE changes:** 40 (19 reserved CVEs published, 14 new CVEs from other CNAs).

## Newly published, in limbo

| Advisory | Package | Severity | CVE | Days | Fixed in |
|---|---|---|---|---:|---|
| [GHSA-5g7p-q5gj-xqqx](https://github.com/CopilotKit/CopilotKit/security/advisories/GHSA-5g7p-q5gj-xqqx) | `npm:@copilotkit/bot-teams, npm:@copilotkit/channels, npm:…` | critical | no CVE anywhere | 0 | `0.12.0` |
| [GHSA-87w3-phwh-q8vx](https://github.com/opencast/opencast/security/advisories/GHSA-87w3-phwh-q8vx) | `maven:org.opencastproject:opencast-common` | critical | no CVE anywhere | 0 | `19.11, 20.6, 21.0` |
| [GHSA-2grc-qr7q-6m36](https://github.com/gogs/gogs/security/advisories/GHSA-2grc-qr7q-6m36) | `go:gogs.io/gogs` | critical | CVE reserved (RBP) (`CVE-2026-82401`) | 0 | `0.14.4` |
| [GHSA-hc35-pcqw-5xjq](https://github.com/gogs/gogs/security/advisories/GHSA-hc35-pcqw-5xjq) | `go:gogs.io/gogs` | critical | no CVE anywhere | 0 | `–` |
| [GHSA-h8fv-vm7c-r6fh](https://github.com/simplesamlphp/saml2/security/advisories/GHSA-h8fv-vm7c-r6fh) | `composer:simplesamlphp/saml2` | critical | no CVE anywhere | 0 | `v7.0.0-rc6, v6.3.5, v6.2.9, v6.1.10, v5.` |
| [GHSA-jc3w-j4gj-pxfw](https://github.com/openedx/openedx-platform/security/advisories/GHSA-jc3w-j4gj-pxfw) | `pip:openedx-platform` | critical | no CVE anywhere | 0 | `>= ulmo` |
| [GHSA-73j7-6jvw-2v7g](https://github.com/hanami/hanami-router/security/advisories/GHSA-73j7-6jvw-2v7g) | `rubygems:hanami-router` | high | no CVE anywhere | 1 | `3.0.1` |
| [GHSA-qxv3-3w54-whwp](https://github.com/hanami/hanami-webconsole/security/advisories/GHSA-qxv3-3w54-whwp) | `rubygems:hanami-webconsole` | high | no CVE anywhere | 1 | `3.0.1` |
| [GHSA-qjj5-3932-qh6q](https://github.com/ag-ui-protocol/ag-ui/security/advisories/GHSA-qjj5-3932-qh6q) | `npm:@ag-ui/langgraph, pip:ag-ui-langgraph` | high | no CVE anywhere | 0 | `0.0.48, 0.0.47` |
| [GHSA-3w7c-xq6m-jjwx](https://github.com/CopilotKit/CopilotKit/security/advisories/GHSA-3w7c-xq6m-jjwx) | `npm:@copilotkit/bot, npm:@copilotkit/channels, npm:@copil…` | high | no CVE anywhere | 0 | `0.12.0` |
| [GHSA-9wvp-77p3-9wf3](https://github.com/CopilotKit/CopilotKit/security/advisories/GHSA-9wvp-77p3-9wf3) | `npm:@copilotkit/runtime` | high | no CVE anywhere | 0 | `1.90.1` |
| [GHSA-qrr7-2g7f-r9rg](https://github.com/wasmi-labs/wasmi/security/advisories/GHSA-qrr7-2g7f-r9rg) | `rust:wasmi, rust:wasmi_ir` | high | no CVE anywhere | 0 | `2.0.3` |
| [GHSA-gr3h-hxr8-phqm](https://github.com/opencast/opencast/security/advisories/GHSA-gr3h-hxr8-phqm) | `maven:org.opencastproject:opencast-common` | high | no CVE anywhere | 0 | `19.11, 20.6, 21.0` |
| [GHSA-23xg-544j-3rjf](https://github.com/appium/appium/security/advisories/GHSA-23xg-544j-3rjf) | `npm:@appium/storage-plugin` | high | no CVE anywhere | 0 | `3.0.1` |
| [GHSA-fwrq-76wv-7mvf](https://github.com/Admidio/admidio/security/advisories/GHSA-fwrq-76wv-7mvf) | `composer:admidio/admidio` | high | no CVE anywhere | 0 | `5.0.19` |
| [GHSA-w5mq-phvp-8pqm](https://github.com/cel-rust/cel-rust/security/advisories/GHSA-w5mq-phvp-8pqm) | `rust:cel` | high | no CVE anywhere | 0 | `0.15.1, 0.16.1` |
| [GHSA-hr26-3fq5-9365](https://github.com/gogs/gogs/security/advisories/GHSA-hr26-3fq5-9365) | `go:gogs.io/gogs` | high | no CVE anywhere | 0 | `–` |
| [GHSA-vhf5-f34f-vhq9](https://github.com/gogs/gogs/security/advisories/GHSA-vhf5-f34f-vhq9) | `go:gogs.io/gogs` | high | no CVE anywhere | 0 | `–` |
| [GHSA-799r-mx22-r63q](https://github.com/gogs/gogs/security/advisories/GHSA-799r-mx22-r63q) | `go:gogs.io/gogs` | high | no CVE anywhere | 0 | `–` |
| [GHSA-pmfh-wh5m-gmjm](https://github.com/gogs/gogs/security/advisories/GHSA-pmfh-wh5m-gmjm) | `go:gogs.io/gogs` | high | no CVE anywhere | 0 | `–` |
| [GHSA-f9cv-gfvg-3464](https://github.com/gogs/gogs/security/advisories/GHSA-f9cv-gfvg-3464) | `go:gogs.io/gogs` | high | no CVE anywhere | 0 | `–` |
| [GHSA-4grx-p93p-25w8](https://github.com/getgrav/grav/security/advisories/GHSA-4grx-p93p-25w8) | `composer:getgrav/grav-plugin-form` | high | no CVE anywhere | 0 | `9.2.4` |
| [GHSA-v8r8-3hq6-qgff](https://github.com/getgrav/grav/security/advisories/GHSA-v8r8-3hq6-qgff) | `composer:getgrav/grav-plugin-admin` | high | no CVE anywhere | 0 | `1.10.65` |
| [GHSA-fmmw-m59r-c4pf](https://github.com/getsentry/sentry/security/advisories/GHSA-fmmw-m59r-c4pf) | `pip:sentry` | high | no CVE anywhere | 0 | `26.11.0` |
| [GHSA-cxw8-j6xv-42hc](https://github.com/luben/zstd-jni/security/advisories/GHSA-cxw8-j6xv-42hc) | `maven:com.github.luben:zstd-jni` | high | no CVE anywhere | 0 | `1.5.7-29` |

…and 200 more: [the tracker](https://limbo.watch/tracker/) lists them all, newest first.

## CVE changes

| Advisory | Change |
|---|---|
| [GHSA-mwr6-g4xq-4rvp](https://github.com/Significant-Gravitas/AutoGPT/security/advisories/GHSA-mwr6-g4xq-4rvp) | CVE-2026-133453 RESERVED -> PUBLISHED |
| [GHSA-8vm3-rxfw-5867](https://github.com/Significant-Gravitas/AutoGPT/security/advisories/GHSA-8vm3-rxfw-5867) | CVE-2026-132264 RESERVED -> PUBLISHED |
| [GHSA-pc98-63jj-97gm](https://github.com/Significant-Gravitas/AutoGPT/security/advisories/GHSA-pc98-63jj-97gm) | CVE-2026-133456 RESERVED -> PUBLISHED |
| [GHSA-rjgp-whm3-w5mj](https://github.com/Significant-Gravitas/AutoGPT/security/advisories/GHSA-rjgp-whm3-w5mj) | CVE-2026-133462 RESERVED -> PUBLISHED |
| [GHSA-35gg-95rx-c8fm](https://github.com/Significant-Gravitas/AutoGPT/security/advisories/GHSA-35gg-95rx-c8fm) | CVE-2026-130171 RESERVED -> PUBLISHED |
| [GHSA-458m-58gm-8cr9](https://github.com/Significant-Gravitas/AutoGPT/security/advisories/GHSA-458m-58gm-8cr9) | CVE-2026-132254 RESERVED -> PUBLISHED |
| [GHSA-4jw5-mmcx-c2rr](https://github.com/Significant-Gravitas/AutoGPT/security/advisories/GHSA-4jw5-mmcx-c2rr) | CVE-2026-132255 RESERVED -> PUBLISHED |
| [GHSA-5238-wm28-5fvf](https://github.com/Significant-Gravitas/AutoGPT/security/advisories/GHSA-5238-wm28-5fvf) | CVE-2026-132256 RESERVED -> PUBLISHED |
| [GHSA-6jc8-g72m-gf95](https://github.com/Significant-Gravitas/AutoGPT/security/advisories/GHSA-6jc8-g72m-gf95) | CVE-2026-132260 RESERVED -> PUBLISHED |
| [GHSA-6rqh-v5w3-r7h4](https://github.com/rsyslog/rsyslog/security/advisories/GHSA-6rqh-v5w3-r7h4) | CVE-2026-129832 RESERVED -> PUBLISHED |
| [GHSA-85fj-w7cw-38fv](https://github.com/rsyslog/rsyslog/security/advisories/GHSA-85fj-w7cw-38fv) | CVE-2026-132145 RESERVED -> PUBLISHED |
| [GHSA-cg8j-rwxh-vrg3](https://github.com/rsyslog/rsyslog/security/advisories/GHSA-cg8j-rwxh-vrg3) | CVE-2026-129839 RESERVED -> PUBLISHED |
| [GHSA-f4f5-9hp8-cprw](https://github.com/Significant-Gravitas/AutoGPT/security/advisories/GHSA-f4f5-9hp8-cprw) | CVE-2026-132271 RESERVED -> PUBLISHED |
| [GHSA-fp4g-p7j5-v6pw](https://github.com/Significant-Gravitas/AutoGPT/security/advisories/GHSA-fp4g-p7j5-v6pw) | CVE-2026-129317 RESERVED -> PUBLISHED |
| [GHSA-hp9v-vh5x-5jv3](https://github.com/Significant-Gravitas/AutoGPT/security/advisories/GHSA-hp9v-vh5x-5jv3) | CVE-2026-133449 RESERVED -> PUBLISHED |
| [GHSA-qx75-7566-5phx](https://github.com/Significant-Gravitas/AutoGPT/security/advisories/GHSA-qx75-7566-5phx) | CVE-2026-133458 RESERVED -> PUBLISHED |
| [GHSA-qxw2-mr3h-jf6g](https://github.com/Significant-Gravitas/AutoGPT/security/advisories/GHSA-qxw2-mr3h-jf6g) | CVE-2026-133459 RESERVED -> PUBLISHED |
| [GHSA-r2xf-4rwf-26r7](https://github.com/Significant-Gravitas/AutoGPT/security/advisories/GHSA-r2xf-4rwf-26r7) | CVE-2026-133460 RESERVED -> PUBLISHED |
| [GHSA-r87r-9p73-r6v6](https://github.com/Significant-Gravitas/AutoGPT/security/advisories/GHSA-r87r-9p73-r6v6) | CVE-2026-133461 RESERVED -> PUBLISHED |
| [GHSA-hwmh-rhj6-2qh4](https://github.com/EGroupware/egroupware/security/advisories/GHSA-hwmh-rhj6-2qh4) | cites CVE-2026-136245 (was none) |
| [GHSA-q2j3-83cg-vg83](https://github.com/EGroupware/egroupware/security/advisories/GHSA-q2j3-83cg-vg83) | cites CVE-2026-136249 (was none) |
| [GHSA-4cpq-xg9v-36cj](https://github.com/leepeuker/movary/security/advisories/GHSA-4cpq-xg9v-36cj) | cites CVE-2026-136180 (was none) |
| [GHSA-w766-5x43-whvw](https://github.com/modelcontextprotocol/servers/security/advisories/GHSA-w766-5x43-whvw) | cites CVE-2026-134465 (was none) |
| [GHSA-3rxj-6jhw-qfv7](https://github.com/modelcontextprotocol/servers/security/advisories/GHSA-3rxj-6jhw-qfv7) | cites CVE-2026-134492 (was none) |
| [GHSA-4826-gphh-vw3x](https://github.com/rabbitmq/rabbitmq-server/security/advisories/GHSA-4826-gphh-vw3x) | cites CVE-2026-136252 (was none) |

…and 15 more.

## Longest waiting, published in the last 90 days

| Advisory | Package | Severity | CVE | Days | Fixed in |
|---|---|---|---|---:|---|
| [GHSA-78w7-2h8c-8252](https://github.com/gotify/server/security/advisories/GHSA-78w7-2h8c-8252) | `go:github.com/gotify/server` | medium | no CVE anywhere | 89 | `3.1.0` |
| [GHSA-r58q-vf9r-vxfc](https://github.com/mongodb/mongo-rust-driver/security/advisories/GHSA-r58q-vf9r-vxfc) | `rust:mongodb` | medium | CVE published, cited (`CVE-2026-81526`) | 89 | `3.8.2` |
| [GHSA-v86x-jf74-vqfx](https://github.com/mongodb/mongo-go-driver/security/advisories/GHSA-v86x-jf74-vqfx) | `go:go.mongodb.org/mongo-driver/v2/mongo` | high | CVE published, cited (`CVE-2026-81521`) | 89 | `2.8.2, 2.9.2` |
| [GHSA-93xj-pqc8-f28v](https://github.com/mongodb/mongo-csharp-driver/security/advisories/GHSA-93xj-pqc8-f28v) | `nuget:MongoDB.Driver` | high | CVE published, cited (`CVE-2026-81529`) | 89 | `3.11.1` |
| [GHSA-7jhm-4g3c-cf75](https://github.com/mongodb/mongo-csharp-driver/security/advisories/GHSA-7jhm-4g3c-cf75) | `nuget:MongoDB.Driver` | medium | CVE published, cited (`CVE-2026-81530`) | 89 | `3.11.1` |

624 advisories in limbo have waited more than a year.

## Coverage

Watchlist 68,128 repositories; 68,127 up to date on their schedule (daily for repos with an advisory in limbo, every 3 days for other repos with advisories, every 30 days and after each release for the rest); 7,382 checked in the last 24 hours; 38,007 reviewed advisories known. Every number is a floor: the tracker only sees repositories on its watchlist. Version ranges are as entered by maintainers and unreviewed.

_Advisory metadata from published GitHub repository security advisories and the GitHub Advisory Database (https://github.com/advisories, CC BY 4.0); CVE state from CVE Services; OSV.dev; NVD API (this product uses the NVD API but is not endorsed or certified by the NVD). Compiled by Limbowatch (https://limbo.watch), CC BY 4.0._
