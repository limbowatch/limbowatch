# Limbo Tracker daily report — 2026-11-09

Generated 2026-11-09 16:52:18 UTC; changes since 2026-11-08 13:49:37 UTC.

## Now

- **9,567 advisories in limbo** (+162 since the last report: 115 newly published, 47 older ones found for the first time, 0 left limbo): published by maintainers on GitHub, in ecosystems GitHub reviews, but not yet in GitHub's reviewed database or OSV.
  - 5,152 with no CVE anywhere · 605 citing a CVE that's still only reserved · 1,225 with a CVE from another CNA they don't cite
  - severity: 915 critical, 3,741 high, 4,016 medium, 895 low · median wait so far 54.4 days
- **14,524 more are likely permanent** (+89 since the last report: 87 newly published, 2 older ones found for the first time, 0 left limbo): in ecosystems GitHub doesn't review, so GitHub-based scanners will probably never see them.

## Since the last report

- **115 newly published** advisories entered limbo.
- 47 older advisories were found for the first time (17 in newly watched repos).
- **Left limbo** (likely permanent included): 0 reviewed by GitHub, 0 found to duplicate a reviewed advisory, 0 withdrawn or unpublished.
- **CVE changes:** 9 (4 reserved CVEs published, 3 new CVEs from other CNAs).

## Newly published, in limbo

| Advisory | Package | Severity | CVE | Days | Fixed in |
|---|---|---|---|---:|---|
| [GHSA-cf68-pxw7-c8fr](https://github.com/sooperset/mcp-atlassian/security/advisories/GHSA-cf68-pxw7-c8fr) | `pip:mcp-atlassian` | critical | no CVE anywhere | 1 | 0.24.1 |
| [GHSA-75q6-qrv2-96rx](https://github.com/laradashboard/laradashboard/security/advisories/GHSA-75q6-qrv2-96rx) | `actions:laradashboard/laradashboard` | critical | no CVE anywhere | 1 | – |
| [GHSA-2wmw-5fmc-m25v](https://github.com/thymeleaf/thymeleaf/security/advisories/GHSA-2wmw-5fmc-m25v) | `maven:org.thymeleaf:thymeleaf, maven:org.thymeleaf:thymel…` | critical | no CVE anywhere | 0 | 3.1.6.RELEASE |
| [GHSA-gfg4-7mg4-wpm2](https://github.com/logto-io/logto/security/advisories/GHSA-gfg4-7mg4-wpm2) | `npm:@logto/connector-apple, other:logto-io/logto` | critical | no CVE anywhere | 0 | 1.6.11, 1.46.0 |
| [GHSA-c5vw-gpq8-wq2q](https://github.com/Intermesh/groupoffice/security/advisories/GHSA-c5vw-gpq8-wq2q) | `composer:groupoffice` | critical | no CVE anywhere | 0 | 26.0.57, 25.0.115, 6.8.180 |
| [GHSA-wrv8-h9rp-6fqq](https://github.com/funstory-ai/BabelDOC/security/advisories/GHSA-wrv8-h9rp-6fqq) | `pip:babeldoc` | high | CVE published by another CNA, not cited (CVE-2026-124553) | 1 | 0.7.0 |
| [GHSA-h972-phhq-7368](https://github.com/funstory-ai/BabelDOC/security/advisories/GHSA-h972-phhq-7368) | `pip:babeldoc` | high | no CVE anywhere | 1 | 0.7.0 |
| [GHSA-w8w6-94hg-2qpm](https://github.com/wneessen/go-mail/security/advisories/GHSA-w8w6-94hg-2qpm) | `go:github.com/wneessen/go-mail` | high | no CVE anywhere | 1 | 0.8.2 |
| [GHSA-f82v-42xw-72cj](https://github.com/wneessen/go-mail/security/advisories/GHSA-f82v-42xw-72cj) | `go:github.com/wneessen/go-mail` | high | no CVE anywhere | 1 | 0.8.2 |
| [GHSA-rh5v-38gg-q3jj](https://github.com/sooperset/mcp-atlassian/security/advisories/GHSA-rh5v-38gg-q3jj) | `pip:mcp-atlassian` | high | no CVE anywhere | 1 | 0.24.1 |
| [GHSA-3c6h-qwx8-hjcm](https://github.com/sooperset/mcp-atlassian/security/advisories/GHSA-3c6h-qwx8-hjcm) | `pip:mcp-atlassian` | high | no CVE anywhere | 1 | 0.24.1 |
| [GHSA-qh7q-jmc7-rc7j](https://github.com/sooperset/mcp-atlassian/security/advisories/GHSA-qh7q-jmc7-rc7j) | `pip:mcp-atlassian` | high | CVE reserved (RBP) (CVE-2026-124503) | 1 | 0.24.1 |
| [GHSA-xv8h-26ch-vfh9](https://github.com/sooperset/mcp-atlassian/security/advisories/GHSA-xv8h-26ch-vfh9) | `pip:mcp-atlassian` | high | no CVE anywhere | 1 | 0.24.1 |
| [GHSA-29v7-6x3j-r97q](https://github.com/laradashboard/laradashboard/security/advisories/GHSA-29v7-6x3j-r97q) | `actions:laradashboard/laradashboard` | high | no CVE anywhere | 0 | – |
| [GHSA-47pj-m4xp-74g5](https://github.com/laradashboard/laradashboard/security/advisories/GHSA-47pj-m4xp-74g5) | `actions:laradashboard/laradashboard` | high | no CVE anywhere | 0 | – |
| [GHSA-fp49-5rww-88pv](https://github.com/horilla/horilla-hr/security/advisories/GHSA-fp49-5rww-88pv) | `pip:horilla/horilla-hr` | high | no CVE anywhere | 0 | 2.3.1 |
| [GHSA-mvwv-34qr-qx5x](https://github.com/thymeleaf/thymeleaf/security/advisories/GHSA-mvwv-34qr-qx5x) | `maven:org.thymeleaf:thymeleaf` | high | no CVE anywhere | 0 | 3.1.6.RELEASE |
| [GHSA-6xr7-8ph3-q2g2](https://github.com/thymeleaf/thymeleaf/security/advisories/GHSA-6xr7-8ph3-q2g2) | `maven:org.thymeleaf:thymeleaf` | high | no CVE anywhere | 0 | 3.1.6.RELEASE |
| [GHSA-7258-5hpf-xq6w](https://github.com/siyuan-note/siyuan/security/advisories/GHSA-7258-5hpf-xq6w) | `npm:siyuan` | high | no CVE anywhere | 0 | v3.8.10 |
| [GHSA-cr4j-qhrf-249w](https://github.com/logto-io/logto/security/advisories/GHSA-cr4j-qhrf-249w) | `npm:@logto/tunnel` | high | no CVE anywhere | 0 | 0.3.12 |
| [GHSA-h5r8-hvhq-8hxp](https://github.com/avo-hq/avo/security/advisories/GHSA-h5r8-hvhq-8hxp) | `rubygems:avo` | high | no CVE anywhere | 0 | 3.34.1, 4.3.13 |
| [GHSA-5qw6-cmw6-2ppj](https://github.com/MaaAssistantArknights/MaaAssistantArknights/security/advisories/GHSA-5qw6-cmw6-2ppj) | `actions:MaaAssistantArknights/tools/OptimizeTemplates/opt…` | high | no CVE anywhere | 0 | – |
| [GHSA-qcp3-r37v-7p8j](https://github.com/crate/crate/security/advisories/GHSA-qcp3-r37v-7p8j) | `maven:io.crate:crate` | high | no CVE anywhere | 0 | 6.4.7, 6.5.1 |
| [GHSA-ppqq-957g-9jpc](https://github.com/crate/crate/security/advisories/GHSA-ppqq-957g-9jpc) | `npm:crate` | high | no CVE anywhere | 0 | 6.4.7, 6.5.1 |
| [GHSA-2676-hc74-gg7v](https://github.com/PrestaShop/PrestaShop/security/advisories/GHSA-2676-hc74-gg7v) | `composer:prestashop/prestashop` | high | no CVE anywhere | 0 | 9.2.1, 8.2.9 |

…and 90 more (see the feed).

## CVE changes

| Advisory | Change |
|---|---|
| [GHSA-5835-q8qp-whcc](https://github.com/Qiskit/qiskit/security/advisories/GHSA-5835-q8qp-whcc) | CVE-2026-116501 RESERVED -> PUBLISHED |
| [GHSA-5c3q-hp86-xjr8](https://github.com/OpenIdentityPlatform/OpenAM/security/advisories/GHSA-5c3q-hp86-xjr8) | new CVE from another CNA: CVE-2026-121825 |
| [GHSA-5wqw-q7gh-j65v](https://github.com/meeting-room-booking-system/mrbs-code/security/advisories/GHSA-5wqw-q7gh-j65v) | new CVE from another CNA: CVE-2026-124474 |
| [GHSA-8m5v-wh4r-5j96](https://github.com/tektoncd/pipelines-as-code/security/advisories/GHSA-8m5v-wh4r-5j96) | new CVE from another CNA: CVE-2026-50240 |
| [GHSA-9g9r-qpqr-c8fr](https://github.com/Qiskit/qiskit/security/advisories/GHSA-9g9r-qpqr-c8fr) | CVE-2026-116500 RESERVED -> PUBLISHED |
| [GHSA-gv36-fx3r-29p5](https://github.com/hibernate/hibernate-validator/security/advisories/GHSA-gv36-fx3r-29p5) | CVE-2026-93879 RESERVED -> PUBLISHED |
| [GHSA-vmvm-99w5-56j6](https://github.com/Qiskit/qiskit/security/advisories/GHSA-vmvm-99w5-56j6) | CVE-2026-116499 RESERVED -> PUBLISHED |
| [GHSA-w264-5p9f-hfwm](https://github.com/frappe/erpnext/security/advisories/GHSA-w264-5p9f-hfwm) | cites CVE-2026-124314 (was none) |
| [GHSA-w3rc-76j9-46jq](https://github.com/frappe/erpnext/security/advisories/GHSA-w3rc-76j9-46jq) | cites CVE-2026-124316 (was none) |

## Longest waiting, published in the last 90 days

| Advisory | Package | Severity | CVE | Days | Fixed in |
|---|---|---|---|---:|---|
| [GHSA-vr9m-jx6f-hhj6](https://github.com/flightphp/core/security/advisories/GHSA-vr9m-jx6f-hhj6) | `composer:flightphp/core` | high | no CVE anywhere | 89 | 3.19.1 |
| [GHSA-xwgf-4rc5-p4m4](https://github.com/apple/container/security/advisories/GHSA-xwgf-4rc5-p4m4) | `swift:apple/container` | medium | CVE reserved (RBP) (CVE-2026-64786) | 89 | 1.2.0 |
| [GHSA-8c5h-wx78-2cfg](https://github.com/better-auth/better-auth/security/advisories/GHSA-8c5h-wx78-2cfg) | `npm:@better-auth/sso` | high | CVE published by another CNA, not cited (CVE-2026-80192) | 89 | 1.4.8, 1.6.27, 1.7.0-rc.5 |
| [GHSA-mhp7-gmqr-h56w](https://github.com/nimiq/core-rs-albatross/security/advisories/GHSA-mhp7-gmqr-h56w) | `rust:nimiq-primitives` | high | no CVE anywhere | 89 | v1.5.0 |
| [GHSA-6wq5-5w43-xfc2](https://github.com/nimiq/core-rs-albatross/security/advisories/GHSA-6wq5-5w43-xfc2) | `rust:nimiq-consensus` | medium | no CVE anywhere | 89 | v1.5.0 |

599 advisories in limbo have waited more than a year.

## Coverage

Watchlist 44,658 repositories; 39,538 up to date on their schedule (daily for repos with an advisory in limbo, every 3 days for other repos with advisories, every 30 days and after each release for the rest); 5,906 checked in the last 24 hours; 37,542 reviewed advisories known. Every number is a floor: the tracker only sees repositories on its watchlist. Version ranges are as entered by maintainers and unreviewed.

_Advisory metadata from published GitHub repository security advisories and the GitHub Advisory Database (https://github.com/advisories, CC BY 4.0); CVE state from CVE Services; OSV.dev; NVD API (this product uses the NVD API but is not endorsed or certified by the NVD). Compiled by Limbowatch (https://limbo.watch), CC BY 4.0._
