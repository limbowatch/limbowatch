# Limbo Tracker daily report — 2026-10-29

Generated 2026-10-29 13:19:53 UTC; changes since 2026-10-28 13:11:43 UTC.

## Now

- **6,272 advisories in limbo** (+144 since the last report): published by maintainers on GitHub, in ecosystems GitHub reviews, but not yet in GitHub's reviewed database or OSV.
  - 3,435 with no CVE anywhere · 481 citing a CVE that's still only reserved · 982 with a CVE from another CNA they don't cite
  - severity: 549 critical, 2,528 high, 2,606 medium, 589 low · median wait so far 48.5 days
- **3,746 more are likely permanent** (+330 since the last report): in ecosystems GitHub doesn't review, so GitHub-based scanners will probably never see them.

## Since the last report

- **93 newly published** advisories entered limbo.
- 140 older advisories were found for the first time (newly watched repos).
- **Left limbo:** 88 reviewed by GitHub, 0 found to duplicate a reviewed advisory, 0 withdrawn or unpublished.
- **CVE changes:** 98 (8 reserved CVEs published, 44 new CVEs from other CNAs).

## Newly published, in limbo

| Advisory | Package | Severity | CVE | Days | Fixed in |
|---|---|---|---|---:|---|
| [GHSA-p3vr-xp4c-r8fh](https://github.com/grpc/grpc/security/advisories/GHSA-p3vr-xp4c-r8fh) | `rubygems:grpc` | critical | no CVE anywhere | 0 | 1.84.1 |
| [GHSA-gvrc-7wf9-p7hg](https://github.com/grpc/grpc/security/advisories/GHSA-gvrc-7wf9-p7hg) | `composer:grpc/grpc` | critical | no CVE anywhere | 0 | 1.84.1 |
| [GHSA-qw5g-hcm8-9jcj](https://github.com/givanz/Vvveb/security/advisories/GHSA-qw5g-hcm8-9jcj) | `composer: givanz/vvveb` | critical | CVE reserved (RBP) (CVE-2026-110799) | 0 | 1.0.8.7 |
| [GHSA-hg48-r64v-9rvq](https://github.com/givanz/Vvveb/security/advisories/GHSA-hg48-r64v-9rvq) | `composer: givanz/vvveb` | critical | CVE reserved (RBP) (CVE-2026-112905) | 0 | 1.0.8.7 |
| [GHSA-2mq4-4q7r-q52q](https://github.com/givanz/Vvveb/security/advisories/GHSA-2mq4-4q7r-q52q) | `composer:givanz/Vvveb` | critical | no CVE anywhere | 0 | – |
| [GHSA-9p7v-45m2-wxgj](https://github.com/n8n-io/n8n/security/advisories/GHSA-9p7v-45m2-wxgj) | `npm:n8n` | high | no CVE anywhere | 1 | >= 2.42.6; >= 2.43.3; >= 3.0.1 |
| [GHSA-f2cw-9483-7vcp](https://github.com/n8n-io/n8n/security/advisories/GHSA-f2cw-9483-7vcp) | `npm:n8n` | high | no CVE anywhere | 1 | >= 1.123.89; >= 2.45.5; >= 2.46.1; >= 3. |
| [GHSA-gx3v-3x3v-f8r5](https://github.com/n8n-io/n8n/security/advisories/GHSA-gx3v-3x3v-f8r5) | `npm:n8n` | high | no CVE anywhere | 1 | >= 1.123.89; >= 2.45.5; >= 2.46.1; >= 3. |
| [GHSA-qg6q-pp92-r5q6](https://github.com/QwikDev/qwik/security/advisories/GHSA-qg6q-pp92-r5q6) | `npm:@builder.io/qwik-city` | high | no CVE anywhere | 1 | 1.20.3 |
| [GHSA-2v54-72rw-xh94](https://github.com/QwikDev/qwik/security/advisories/GHSA-2v54-72rw-xh94) | `npm:@qwik.dev/core` | high | no CVE anywhere | 1 | 2.0.0-rc.4 |
| [GHSA-cvf2-p22x-xw37](https://github.com/QwikDev/qwik/security/advisories/GHSA-cvf2-p22x-xw37) | `npm:@builder.io/qwik-city` | high | no CVE anywhere | 1 | 1.20.3, 2.0.0-rc.4 |
| [GHSA-gv27-f6wr-7fjq](https://github.com/QwikDev/qwik/security/advisories/GHSA-gv27-f6wr-7fjq) | `npm:@builder.io/qwik-lab` | high | no CVE anywhere | 1 | 1.20.3, 2.0.0-rc.4 |
| [GHSA-x955-mxjx-g5cj](https://github.com/goharbor/harbor/security/advisories/GHSA-x955-mxjx-g5cj) | `go:github.com/goharbor/harbor` | high | no CVE anywhere | 1 | 2.15.3, 2.14.6 |
| [GHSA-gg6q-4562-83ww](https://github.com/milvus-io/milvus/security/advisories/GHSA-gg6q-4562-83ww) | `go:github.com/milvus-io/milvus` | high | no CVE anywhere | 1 | 2.6.25; 3.0.3 |
| [GHSA-hr46-v5qw-wr2q](https://github.com/milvus-io/milvus/security/advisories/GHSA-hr46-v5qw-wr2q) | `go:github.com/milvus-io/milvus` | high | no CVE anywhere | 1 | 2.6.23; 3.0.1 |
| [GHSA-3pfx-gxff-vg76](https://github.com/lxsmnsyc/seroval/security/advisories/GHSA-3pfx-gxff-vg76) | `npm:seroval` | high | no CVE anywhere | 1 | 1.7.2 |
| [GHSA-34rr-qrr4-397f](https://github.com/ckan/ckan/security/advisories/GHSA-34rr-qrr4-397f) | `pip:ckan` | high | no CVE anywhere | 1 | 2.11.7, 2.12.1 |
| [GHSA-pxjf-g536-7r93](https://github.com/mtrudel/bandit/security/advisories/GHSA-pxjf-g536-7r93) | `erlang:bandit` | high | CVE published, cited (CVE-2026-116078) | 0 | 1.14.1 |
| [GHSA-pc58-q9c8-wh7j](https://github.com/ome/omero-web/security/advisories/GHSA-pc58-q9c8-wh7j) | `pip:omero-web` | high | no CVE anywhere | 0 | 5.33.3 |
| [GHSA-p7x3-j7x2-jmc4](https://github.com/bytecodealliance/jco/security/advisories/GHSA-p7x3-j7x2-jmc4) | `npm:@bytecodealliance/jco, npm:@bytecodealliance/jco-tran…` | high | no CVE anywhere | 0 | – |
| [GHSA-69q9-v8p6-xvx3](https://github.com/dani-garcia/vaultwarden/security/advisories/GHSA-69q9-v8p6-xvx3) | `rust:vaultwarden` | high | no CVE anywhere | 0 | 1.37.4 |
| [GHSA-7x4h-3p32-rrc3](https://github.com/nektos/act/security/advisories/GHSA-7x4h-3p32-rrc3) | `go:github.com/nektos/act` | high | no CVE anywhere | 0 | 0.2.92 |
| [GHSA-mj9p-fq5h-mw8h](https://github.com/fleetdm/fleet/security/advisories/GHSA-mj9p-fq5h-mw8h) | `go:github.com/fleetdm/fleet` | high | no CVE anywhere | 0 | >= 4.89.0 |
| [GHSA-mjrh-3v6h-8g5p](https://github.com/fleetdm/fleet/security/advisories/GHSA-mjrh-3v6h-8g5p) | `go:github.com/fleetdm/fleet` | high | no CVE anywhere | 0 | >= 4.86.2 |
| [GHSA-v8fw-q2g9-8j47](https://github.com/archesproject/arches/security/advisories/GHSA-v8fw-q2g9-8j47) | `pip:arches` | high | no CVE anywhere | 0 | 7.6.27,8.1.6 |

…and 68 more (see the feed).

## CVE changes

| Advisory | Change |
|---|---|
| [GHSA-23wf-92cp-8pcj](https://github.com/labstack/echo/security/advisories/GHSA-23wf-92cp-8pcj) | new CVE from another CNA: CVE-2026-118658 |
| [GHSA-246p-cpwv-v3jq](https://github.com/labstack/echo/security/advisories/GHSA-246p-cpwv-v3jq) | new CVE from another CNA: CVE-2026-118653 |
| [GHSA-24vh-q7rg-243w](https://github.com/coder/coder/security/advisories/GHSA-24vh-q7rg-243w) | new CVE from another CNA: CVE-2026-118687 |
| [GHSA-297p-4mj8-28wm](https://github.com/WWBN/AVideo-Encoder/security/advisories/GHSA-297p-4mj8-28wm) | CVE-2026-61571 RESERVED -> PUBLISHED |
| [GHSA-2ffq-g2xg-c22p](https://github.com/labstack/echo/security/advisories/GHSA-2ffq-g2xg-c22p) | new CVE from another CNA: CVE-2026-118657 |
| [GHSA-2h26-836q-4jh2](https://github.com/open-webui/open-webui/security/advisories/GHSA-2h26-836q-4jh2) | cites CVE-2026-109293 (was none) |
| [GHSA-2rr4-q6pg-m5g3](https://github.com/open-webui/open-webui/security/advisories/GHSA-2rr4-q6pg-m5g3) | cites CVE-2026-109283 (was none) |
| [GHSA-2rrq-xf8q-3qpf](https://github.com/WWBN/AVideo-Encoder/security/advisories/GHSA-2rrq-xf8q-3qpf) | CVE-2026-61569 RESERVED -> PUBLISHED |
| [GHSA-35rr-xwfh-x789](https://github.com/highcharts/highcharts/security/advisories/GHSA-35rr-xwfh-x789) | cites CVE-2026-118246 (was none) |
| [GHSA-375p-5qhx-8wq4](https://github.com/labstack/echo/security/advisories/GHSA-375p-5qhx-8wq4) | new CVE from another CNA: CVE-2026-118650 |
| [GHSA-3c3p-5959-3ghr](https://github.com/n8n-io/n8n/security/advisories/GHSA-3c3p-5959-3ghr) | new CVE from another CNA: CVE-2026-118679 |
| [GHSA-3cmx-xjww-583x](https://github.com/i18next/i18next-http-backend/security/advisories/GHSA-3cmx-xjww-583x) | new CVE from another CNA: CVE-2026-118258 |
| [GHSA-3fx2-cqw9-xr3c](https://github.com/langchain-ai/langgraph/security/advisories/GHSA-3fx2-cqw9-xr3c) | new CVE from another CNA: CVE-2026-118667 |
| [GHSA-3pmx-cf9f-34xr](https://github.com/labstack/echo/security/advisories/GHSA-3pmx-cf9f-34xr) | new CVE from another CNA: CVE-2026-118654 |
| [GHSA-434m-5hcj-pxf3](https://github.com/ardatan/graphql-tools/security/advisories/GHSA-434m-5hcj-pxf3) | new CVE from another CNA: CVE-2026-118665 |
| [GHSA-43v8-hjhm-chjp](https://github.com/n8n-io/n8n/security/advisories/GHSA-43v8-hjhm-chjp) | new CVE from another CNA: CVE-2026-118640 |
| [GHSA-4hm6-w6qq-w73v](https://github.com/langchain-ai/langgraph/security/advisories/GHSA-4hm6-w6qq-w73v) | new CVE from another CNA: CVE-2026-118668 |
| [GHSA-4w32-qx5g-cpwv](https://github.com/SignalK/signalk-server/security/advisories/GHSA-4w32-qx5g-cpwv) | new CVE from another CNA: CVE-2026-118690 |
| [GHSA-5793-x2q3-c3q7](https://github.com/highcharts/highcharts/security/advisories/GHSA-5793-x2q3-c3q7) | cites CVE-2026-118251 (was none) |
| [GHSA-58g7-7f52-h92c](https://github.com/highcharts/highcharts/security/advisories/GHSA-58g7-7f52-h92c) | cites CVE-2026-118253 (was none) |
| [GHSA-5fpq-26gf-qwcr](https://github.com/capricorn86/happy-dom/security/advisories/GHSA-5fpq-26gf-qwcr) | cites CVE-2026-118661 (was none) |
| [GHSA-5ghw-9mgr-jvx2](https://github.com/highcharts/highcharts/security/advisories/GHSA-5ghw-9mgr-jvx2) | cites CVE-2026-116797 (was none) |
| [GHSA-5hw5-4q87-m6x9](https://github.com/ChromeDevTools/chrome-devtools-mcp/security/advisories/GHSA-5hw5-4q87-m6x9) | new CVE from another CNA: CVE-2026-106484 |
| [GHSA-5w58-mwmh-vf2m](https://github.com/open-webui/open-webui/security/advisories/GHSA-5w58-mwmh-vf2m) | cites CVE-2026-109299 (was none) |
| [GHSA-65hg-cf3f-5m39](https://github.com/highcharts/highcharts/security/advisories/GHSA-65hg-cf3f-5m39) | cites CVE-2026-118244 (was none) |

…and 73 more.

## Longest waiting

| Advisory | Package | Severity | CVE | Days | Fixed in |
|---|---|---|---|---:|---|
| [GHSA-6pc9-r5gr-m9c9](https://github.com/rschultheis/many_versioned_gem/security/advisories/GHSA-6pc9-r5gr-m9c9) | `rubygems:many_versioned_gem` | medium | no CVE anywhere | 2814 | 0.1.1 |
| [GHSA-3wjh-93gr-chh6](https://github.com/flarum/framework/security/advisories/GHSA-3wjh-93gr-chh6) | `composer:flarum/core` | high | CVE published, cited (CVE-2019-13183) | 2673 | 0.1.0-beta.9 |
| [GHSA-jchv-x857-q8fq](https://github.com/apple/swift-nio-http2/security/advisories/GHSA-jchv-x857-q8fq) | `swift:swift-nio-http2` | high | no CVE anywhere | 2633 | 1.5.0 |
| [GHSA-hv27-vjg3-m59x](https://github.com/apple/swift-nio-http2/security/advisories/GHSA-hv27-vjg3-m59x) | `swift:swift-nio-http2` | high | CVE published, cited (CVE-2019-9515) | 2633 | 1.5.0 |
| [GHSA-9cqv-v2w2-7j52](https://github.com/apple/swift-nio-http2/security/advisories/GHSA-9cqv-v2w2-7j52) | `swift:swift-nio-http2` | high | CVE published, cited (CVE-2019-9516) | 2633 | 1.5.0 |

## Coverage

Watchlist 16,474 repositories; 16,474 up to date on their schedule (daily for repos with an advisory in limbo, every 3 to 7 days for the rest); 1,394 checked in the last 24 hours; 37,412 reviewed advisories known. Every number is a floor: the tracker only sees repositories on its watchlist. Version ranges are as entered by maintainers and unreviewed.

_Advisory metadata from published GitHub repository security advisories and the GitHub Advisory Database (https://github.com/advisories, CC BY 4.0); CVE state from CVE Services; OSV.dev; NVD API (this product uses the NVD API but is not endorsed or certified by the NVD). Compiled by Limbowatch (https://limbo.watch), CC BY 4.0._
