# Limbo Tracker daily report — 2026-11-10

Generated 2026-11-10 15:18:34 UTC; changes since 2026-11-09 16:52:18 UTC.

## Now

- **9,929 advisories in limbo** (+362 since the last report: 138 newly published, 260 older ones found for the first time, 36 left limbo): published by maintainers on GitHub, in ecosystems GitHub reviews, but not yet in GitHub's reviewed database or OSV.
  - 5,475 with no CVE anywhere · 618 citing a CVE that's still only reserved · 1,218 with a CVE from another CNA they don't cite
  - severity: 946 critical, 3,889 high, 4,158 medium, 936 low · median wait so far 54.7 days
- **14,632 more are likely permanent** (+108 since the last report: 77 newly published, 40 older ones found for the first time, 9 left limbo): in ecosystems GitHub doesn't review, so GitHub-based scanners will probably never see them.

## Since the last report

- **138 newly published** advisories entered limbo.
- 260 older advisories were found for the first time (199 in newly watched repos).
- **Left limbo** (likely permanent included): 44 reviewed by GitHub, 0 found to duplicate a reviewed advisory, 1 withdrawn or unpublished.
- **CVE changes:** 47 (9 reserved CVEs published, 9 new CVEs from other CNAs).

## Newly published, in limbo

| Advisory | Package | Severity | CVE | Days | Fixed in |
|---|---|---|---|---:|---|
| [GHSA-2qcf-f968-jcq3](https://github.com/kcp-dev/kcp/security/advisories/GHSA-2qcf-f968-jcq3) | `go:github.com/kcp-dev/kcp` | critical | no CVE anywhere | 1 | 0.33.6 |
| [GHSA-gfv3-m769-5xm3](https://github.com/Arize-ai/phoenix/security/advisories/GHSA-gfv3-m769-5xm3) | `pip:arize-phoenix` | critical | CVE reserved (RBP) (CVE-2026-53998) | 0 | v15.7.0 |
| [GHSA-952q-f292-vvwr](https://github.com/yuzutech/kroki/security/advisories/GHSA-952q-f292-vvwr) | `maven:io.kroki:kroki-server` | critical | no CVE anywhere | 0 | 0.36.0 |
| [GHSA-q9xq-w3q4-p9jc](https://github.com/zalando/skipper/security/advisories/GHSA-q9xq-w3q4-p9jc) | `go:github.com/zalando/skipper` | critical | no CVE anywhere | 0 | v0.28.74 |
| [GHSA-cw34-7fm4-63g6](https://github.com/seaweedfs/seaweedfs/security/advisories/GHSA-cw34-7fm4-63g6) | `go:github.com/seaweedfs/seaweedfs` | critical | no CVE anywhere | 0 | – |
| [GHSA-pxfv-j39p-qh4j](https://github.com/seaweedfs/seaweedfs/security/advisories/GHSA-pxfv-j39p-qh4j) | `go:github.com/seaweedfs/seaweedfs` | critical | no CVE anywhere | 0 | – |
| [GHSA-88vg-f4wx-grq3](https://github.com/seaweedfs/seaweedfs/security/advisories/GHSA-88vg-f4wx-grq3) | `go:github.com/seaweedfs/seaweedfs` | critical | no CVE anywhere | 0 | – |
| [GHSA-m3m8-mrgq-hf9h](https://github.com/seaweedfs/seaweedfs/security/advisories/GHSA-m3m8-mrgq-hf9h) | `go:github.com/seaweedfs/seaweedfs` | critical | no CVE anywhere | 0 | – |
| [GHSA-mv76-wx4x-68pm](https://github.com/seaweedfs/seaweedfs/security/advisories/GHSA-mv76-wx4x-68pm) | `go:github.com/seaweedfs/seaweedfs` | critical | no CVE anywhere | 0 | – |
| [GHSA-f6rh-hw92-h9rx](https://github.com/seaweedfs/seaweedfs/security/advisories/GHSA-f6rh-hw92-h9rx) | `go:github.com/seaweedfs/seaweedfs` | critical | no CVE anywhere | 0 | – |
| [GHSA-47fc-cj9r-ghpm](https://github.com/seaweedfs/seaweedfs/security/advisories/GHSA-47fc-cj9r-ghpm) | `go:github.com/seaweedfs/seaweedfs` | critical | no CVE anywhere | 0 | – |
| [GHSA-jq8h-9mjh-xv8f](https://github.com/seaweedfs/seaweedfs/security/advisories/GHSA-jq8h-9mjh-xv8f) | `go:github.com/seaweedfs/seaweedfs` | critical | no CVE anywhere | 0 | – |
| [GHSA-p983-2j86-34vj](https://github.com/seaweedfs/seaweedfs/security/advisories/GHSA-p983-2j86-34vj) | `go:github.com/seaweedfs/seaweedfs` | critical | no CVE anywhere | 0 | – |
| [GHSA-25hp-4mw7-9c75](https://github.com/seaweedfs/seaweedfs/security/advisories/GHSA-25hp-4mw7-9c75) | `go:github.com/seaweedfs/seaweedfs` | critical | no CVE anywhere | 0 | – |
| [GHSA-r66f-3q22-grc4](https://github.com/parse-community/parse-server/security/advisories/GHSA-r66f-3q22-grc4) | `npm:parse-server` | critical | no CVE anywhere | 0 | 9.11.1-alpha.4, 8.6.123 |
| [GHSA-p4f5-76q4-ffq7](https://github.com/vitejs/vite/security/advisories/GHSA-p4f5-76q4-ffq7) | `npm:vite, npm:vite-plus` | critical | no CVE anywhere | 0 | 8.3.7, 8.2.5, 8.1.7, 7.3.8, 6.4.6, 1.5.1 |
| [GHSA-3rp8-rxj8-mvjw](https://github.com/aio-libs/aiohttp/security/advisories/GHSA-3rp8-rxj8-mvjw) | `pip:aiohttp` | high | no CVE anywhere | 1 | 3.14.4 |
| [GHSA-3g7x-x96g-62gq](https://github.com/kcp-dev/kcp/security/advisories/GHSA-3g7x-x96g-62gq) | `go:github.com/kcp-dev/kcp` | high | no CVE anywhere | 1 | 0.33.6 |
| [GHSA-rj35-2mmm-h9h9](https://github.com/kcp-dev/kcp/security/advisories/GHSA-rj35-2mmm-h9h9) | `go:github.com/kcp-dev/kcp` | high | no CVE anywhere | 1 | 0.33.2 |
| [GHSA-2h54-wjqv-9qqp](https://github.com/kcp-dev/kcp/security/advisories/GHSA-2h54-wjqv-9qqp) | `go:github.com/kcp-dev/kcp` | high | no CVE anywhere | 1 | 0.33.2 |
| [GHSA-rvjr-8rxg-gw76](https://github.com/kcp-dev/kcp/security/advisories/GHSA-rvjr-8rxg-gw76) | `go:github.com/kcp-dev/kcp` | high | no CVE anywhere | 1 | 0.33.1 |
| [GHSA-f72f-v52v-99g2](https://github.com/a2aproject/a2a-java/security/advisories/GHSA-f72f-v52v-99g2) | `maven:org.a2aproject.sdk:a2a-java-sdk-http-client` | high | no CVE anywhere | 1 | 1.5.0.Final |
| [GHSA-w377-w7c6-c8hr](https://github.com/a2aproject/a2a-java/security/advisories/GHSA-w377-w7c6-c8hr) | `maven:org.a2aproject.sdk:a2a-java-sdk-http-client-vertx` | high | no CVE anywhere | 1 | 1.5.0.Final |
| [GHSA-jj29-x8v4-w733](https://github.com/messense/dav-server-rs/security/advisories/GHSA-jj29-x8v4-w733) | `rust:dav-server` | high | no CVE anywhere | 1 | 0.12.0 |
| [GHSA-5qr3-w62x-jmwx](https://github.com/voidzero-dev/vite-plus/security/advisories/GHSA-5qr3-w62x-jmwx) | `npm:vite-plus` | high | no CVE anywhere | 1 | 1.5.1 |

…and 113 more (see the feed).

## CVE changes

| Advisory | Change |
|---|---|
| [GHSA-gmhw-vmwr-wrxh](https://github.com/nasa-jpl/ION-DTN/security/advisories/GHSA-gmhw-vmwr-wrxh) | new CVE from another CNA: CVE-2026-123999 |
| [GHSA-h28r-fr59-c79c](https://github.com/nasa-jpl/ION-DTN/security/advisories/GHSA-h28r-fr59-c79c) | new CVE from another CNA: CVE-2026-124000 |
| [GHSA-mw4c-w54x-248r](https://github.com/thorvg/thorvg/security/advisories/GHSA-mw4c-w54x-248r) | new CVE from GitHub's CNA, not cited: CVE-2026-123367 |
| [GHSA-p623-mxf7-qxjm](https://github.com/OctoPrint/OctoPrint/security/advisories/GHSA-p623-mxf7-qxjm) | new CVE from GitHub's CNA, not cited: CVE-2026-123364 |
| [GHSA-rcqq-5qmv-7fxp](https://github.com/nasa-jpl/ION-DTN/security/advisories/GHSA-rcqq-5qmv-7fxp) | new CVE from another CNA: CVE-2026-124001 |
| [GHSA-4xm8-rg9h-jhq2](https://github.com/SignalK/signalk-server/security/advisories/GHSA-4xm8-rg9h-jhq2) | new CVE from GitHub's CNA, not cited: CVE-2026-123807 |
| [GHSA-cphv-qx83-x397](https://github.com/titraio/titra/security/advisories/GHSA-cphv-qx83-x397) | CVE-2026-63497 RESERVED -> PUBLISHED |
| [GHSA-2j8w-xcrc-x985](https://github.com/rack/rack/security/advisories/GHSA-2j8w-xcrc-x985) | new CVE from GitHub's CNA, not cited: CVE-2026-125109 |
| [GHSA-3qm5-22pm-wqg9](https://github.com/xddxdd/bird-lg-go/security/advisories/GHSA-3qm5-22pm-wqg9) | CVE-2026-63644 RESERVED -> PUBLISHED |
| [GHSA-5v64-555j-wjxm](https://github.com/rack/rack/security/advisories/GHSA-5v64-555j-wjxm) | new CVE from GitHub's CNA, not cited: CVE-2026-125111 |
| [GHSA-8332-j7wj-wjw4](https://github.com/Automattic/mongoose/security/advisories/GHSA-8332-j7wj-wjw4) | new CVE from GitHub's CNA, not cited: CVE-2026-125117 |
| [GHSA-cxqf-vgrr-xxrv](https://github.com/owasp-modsecurity/ModSecurity/security/advisories/GHSA-cxqf-vgrr-xxrv) | CVE-2026-61812 RESERVED -> PUBLISHED |
| [GHSA-f42p-wjw5-97qh](https://github.com/zizmorcore/zizmor/security/advisories/GHSA-f42p-wjw5-97qh) | CVE-2026-102289 RESERVED -> PUBLISHED |
| [GHSA-jx3r-phvx-2jmj](https://github.com/owasp-modsecurity/ModSecurity/security/advisories/GHSA-jx3r-phvx-2jmj) | CVE-2026-73857 RESERVED -> PUBLISHED |
| [GHSA-p8x9-v4hv-2w4g](https://github.com/rack/rack/security/advisories/GHSA-p8x9-v4hv-2w4g) | new CVE from GitHub's CNA, not cited: CVE-2026-125108 |
| [GHSA-q8m6-9rfx-39rf](https://github.com/ronf/asyncssh/security/advisories/GHSA-q8m6-9rfx-39rf) | CVE-2026-77473 RESERVED -> PUBLISHED |
| [GHSA-qrch-pjfr-9g47](https://github.com/owasp-modsecurity/ModSecurity/security/advisories/GHSA-qrch-pjfr-9g47) | CVE-2026-104259 RESERVED -> PUBLISHED |
| [GHSA-w29m-45fc-22v9](https://github.com/ronf/asyncssh/security/advisories/GHSA-w29m-45fc-22v9) | CVE-2026-102643 RESERVED -> PUBLISHED |
| [GHSA-wr5m-5jph-8m96](https://github.com/Automattic/mongoose/security/advisories/GHSA-wr5m-5jph-8m96) | new CVE from GitHub's CNA, not cited: CVE-2026-125116 |
| [GHSA-wvg4-6p58-3gh3](https://github.com/rack/rack/security/advisories/GHSA-wvg4-6p58-3gh3) | new CVE from GitHub's CNA, not cited: CVE-2026-125110 |
| [GHSA-42qf-m3j9-837r](https://github.com/Intermesh/groupoffice/security/advisories/GHSA-42qf-m3j9-837r) | new CVE from another CNA: CVE-2026-125388 |
| [GHSA-52gw-p4j3-v53c](https://github.com/Intermesh/groupoffice/security/advisories/GHSA-52gw-p4j3-v53c) | new CVE from another CNA: CVE-2026-125389 |
| [GHSA-6972-9mcm-vhwj](https://github.com/Automattic/mongoose/security/advisories/GHSA-6972-9mcm-vhwj) | new CVE from GitHub's CNA, not cited: CVE-2026-125118 |
| [GHSA-9c4j-cjw3-r3xx](https://github.com/craftcms/cms/security/advisories/GHSA-9c4j-cjw3-r3xx) | new CVE from another CNA: CVE-2026-115934 |
| [GHSA-fw6x-h8gw-778w](https://github.com/FreeRDP/FreeRDP/security/advisories/GHSA-fw6x-h8gw-778w) | new CVE from another CNA: CVE-2026-125394 |

…and 22 more.

## Longest waiting, published in the last 90 days

| Advisory | Package | Severity | CVE | Days | Fixed in |
|---|---|---|---|---:|---|
| [GHSA-46f2-xhpw-8vh3](https://github.com/zauberzeug/nicegui/security/advisories/GHSA-46f2-xhpw-8vh3) | `pip:nicegui` | medium | no CVE anywhere | 89 | 3.16.0 |
| [GHSA-955g-h32v-mvrr](https://github.com/zauberzeug/nicegui/security/advisories/GHSA-955g-h32v-mvrr) | `pip:nicegui` | medium | no CVE anywhere | 89 | 3.16.0 |
| [GHSA-vf9h-87xm-g767](https://github.com/TryGhost/Ghost/security/advisories/GHSA-vf9h-87xm-g767) | `npm:ghost` | medium | CVE published by another CNA, not cited (CVE-2026-103282) | 89 | v6.23.0 |
| [GHSA-q98w-jm4q-wch7](https://github.com/TryGhost/Ghost/security/advisories/GHSA-q98w-jm4q-wch7) | `npm:ghost` | medium | CVE published by another CNA, not cited (CVE-2026-103281) | 89 | v6.23.0 |
| [GHSA-xqhm-7xhv-6ppj](https://github.com/cilium/cilium/security/advisories/GHSA-xqhm-7xhv-6ppj) | `go:github.com/cilium/cilium` | high | CVE reserved (RBP) (CVE-2026-77531) | 89 | v1.17.18, v1.18.12, v1.19.6 |

605 advisories in limbo have waited more than a year.

## Coverage

Watchlist 64,048 repositories; 64,048 up to date on their schedule (daily for repos with an advisory in limbo, every 3 days for other repos with advisories, every 30 days and after each release for the rest); 32,341 checked in the last 24 hours; 37,587 reviewed advisories known. Every number is a floor: the tracker only sees repositories on its watchlist. Version ranges are as entered by maintainers and unreviewed.

_Advisory metadata from published GitHub repository security advisories and the GitHub Advisory Database (https://github.com/advisories, CC BY 4.0); CVE state from CVE Services; OSV.dev; NVD API (this product uses the NVD API but is not endorsed or certified by the NVD). Compiled by Limbowatch (https://limbo.watch), CC BY 4.0._
