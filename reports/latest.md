# Limbo Tracker daily report — 2026-11-07

Generated 2026-11-07 10:14:39 UTC; changes since 2026-11-06 14:35:20 UTC.

## Now

- **8,908 advisories in limbo** (+105 since the last report: 3 newly published, 105 older ones found for the first time, 3 left limbo): published by maintainers on GitHub, in ecosystems GitHub reviews, but not yet in GitHub's reviewed database or OSV.
  - 4,707 with no CVE anywhere · 583 citing a CVE that's still only reserved · 1,082 with a CVE from another CNA they don't cite
  - severity: 891 critical, 3,500 high, 3,713 medium, 804 low · median wait so far 57.4 days
- **14,322 more are likely permanent** (+1 since the last report: 0 newly published, 5 older ones found for the first time, 4 left limbo): in ecosystems GitHub doesn't review, so GitHub-based scanners will probably never see them.

## Since the last report

- **3 newly published** advisories entered limbo.
- 105 older advisories were found for the first time (103 in newly watched repos).
- **Left limbo** (likely permanent included): 7 reviewed by GitHub, 0 found to duplicate a reviewed advisory, 0 withdrawn or unpublished.
- **CVE changes:** 64 (47 reserved CVEs published, 16 new CVEs from other CNAs).

## Newly published, in limbo

| Advisory | Package | Severity | CVE | Days | Fixed in |
|---|---|---|---|---:|---|
| [GHSA-64m2-4gp9-7cqx](https://github.com/python-rope/rope/security/advisories/GHSA-64m2-4gp9-7cqx) | `pip:rope` | high | no CVE anywhere | 1 | 1.15.2 |
| [GHSA-wvq4-f5wr-7hj4](https://github.com/Riverline/multipart-parser/security/advisories/GHSA-wvq4-f5wr-7hj4) | `composer:riverline/multipart-parser` | high | no CVE anywhere | 1 | 2.3.0 |
| [GHSA-6xq4-gr25-qg2x](https://github.com/open-telemetry/opentelemetry-dotnet-contrib/security/advisories/GHSA-6xq4-gr25-qg2x) | `nuget:OpenTelemetry.Instrumentation.AspNetCore` | high | no CVE anywhere | 0 | 1.20.2 |

## CVE changes

| Advisory | Change |
|---|---|
| [GHSA-22mh-gmrh-gpwg](https://github.com/Bubka/2FAuth/security/advisories/GHSA-22mh-gmrh-gpwg) | CVE-2026-63440 RESERVED -> PUBLISHED |
| [GHSA-2g42-f97q-973x](https://github.com/freescout-help-desk/freescout/security/advisories/GHSA-2g42-f97q-973x) | CVE-2026-85742 RESERVED -> PUBLISHED |
| [GHSA-2x3p-x74g-442x](https://github.com/siyuan-note/siyuan/security/advisories/GHSA-2x3p-x74g-442x) | new CVE from another CNA: CVE-2026-123492 |
| [GHSA-34w8-j94f-8c5w](https://github.com/EricLBuehler/mistral.rs/security/advisories/GHSA-34w8-j94f-8c5w) | new CVE from another CNA: CVE-2026-124028 |
| [GHSA-36rp-hhp4-wh83](https://github.com/randombit/botan/security/advisories/GHSA-36rp-hhp4-wh83) | CVE-2026-104267 RESERVED -> PUBLISHED |
| [GHSA-3chp-cr6f-hp63](https://github.com/chartbrew/chartbrew/security/advisories/GHSA-3chp-cr6f-hp63) | CVE-2026-85708 RESERVED -> PUBLISHED |
| [GHSA-3gq8-gg8f-5h8h](https://github.com/wazuh/wazuh/security/advisories/GHSA-3gq8-gg8f-5h8h) | CVE-2026-112335 RESERVED -> PUBLISHED |
| [GHSA-3mh2-26h4-wrqc](https://github.com/randombit/botan/security/advisories/GHSA-3mh2-26h4-wrqc) | CVE-2026-48057 RESERVED -> PUBLISHED |
| [GHSA-4q3v-5r7x-58q2](https://github.com/chartbrew/chartbrew/security/advisories/GHSA-4q3v-5r7x-58q2) | CVE-2026-68935 RESERVED -> PUBLISHED |
| [GHSA-4wj7-9gq7-mrr2](https://github.com/chartbrew/chartbrew/security/advisories/GHSA-4wj7-9gq7-mrr2) | CVE-2026-54349 RESERVED -> PUBLISHED |
| [GHSA-5c97-hp95-vg56](https://github.com/open-quantum-safe/liboqs/security/advisories/GHSA-5c97-hp95-vg56) | CVE-2026-44519 RESERVED -> PUBLISHED |
| [GHSA-5jff-8h8q-r5qx](https://github.com/symfony/symfony/security/advisories/GHSA-5jff-8h8q-r5qx) | new CVE from another CNA: CVE-2026-123824 |
| [GHSA-6gv3-8wxh-6vfq](https://github.com/chartbrew/chartbrew/security/advisories/GHSA-6gv3-8wxh-6vfq) | CVE-2026-85712 RESERVED -> PUBLISHED |
| [GHSA-6m7q-jmp7-3vw8](https://github.com/chartbrew/chartbrew/security/advisories/GHSA-6m7q-jmp7-3vw8) | CVE-2026-54589 RESERVED -> PUBLISHED |
| [GHSA-6w6h-fwqm-6hjj](https://github.com/wazuh/wazuh/security/advisories/GHSA-6w6h-fwqm-6hjj) | CVE-2026-112336 RESERVED -> PUBLISHED |
| [GHSA-6w8v-qp43-vg2h](https://github.com/freescout-help-desk/freescout/security/advisories/GHSA-6w8v-qp43-vg2h) | CVE-2026-85743 RESERVED -> PUBLISHED |
| [GHSA-7rvv-9467-96mc](https://github.com/wazuh/wazuh/security/advisories/GHSA-7rvv-9467-96mc) | CVE-2026-112340 RESERVED -> PUBLISHED |
| [GHSA-9492-427f-466x](https://github.com/parse-community/parse-server/security/advisories/GHSA-9492-427f-466x) | new CVE from another CNA: CVE-2026-123487 |
| [GHSA-9fpx-fr6j-2vh6](https://github.com/GeoNode/geonode/security/advisories/GHSA-9fpx-fr6j-2vh6) | CVE-2026-33050 RESERVED -> PUBLISHED |
| [GHSA-9hq4-hm3j-jmph](https://github.com/ddev/ddev/security/advisories/GHSA-9hq4-hm3j-jmph) | new CVE from GitHub's CNA, not cited: CVE-2026-108262 |
| [GHSA-9ph7-f3hc-95gg](https://github.com/freescout-help-desk/freescout/security/advisories/GHSA-9ph7-f3hc-95gg) | CVE-2026-62855 RESERVED -> PUBLISHED |
| [GHSA-cp25-j9x5-p5xm](https://github.com/urwid/urwid/security/advisories/GHSA-cp25-j9x5-p5xm) | CVE-2026-103022 RESERVED -> PUBLISHED |
| [GHSA-cr68-27qv-p5m4](https://github.com/freescout-help-desk/freescout/security/advisories/GHSA-cr68-27qv-p5m4) | CVE-2026-103984 RESERVED -> PUBLISHED |
| [GHSA-crwc-vx5f-mh8x](https://github.com/chartbrew/chartbrew/security/advisories/GHSA-crwc-vx5f-mh8x) | CVE-2026-68933 RESERVED -> PUBLISHED |
| [GHSA-f4pj-j296-jwp2](https://github.com/wazuh/wazuh/security/advisories/GHSA-f4pj-j296-jwp2) | CVE-2026-112334 RESERVED -> PUBLISHED |

…and 39 more.

## Longest waiting, published in the last 90 days

| Advisory | Package | Severity | CVE | Days | Fixed in |
|---|---|---|---|---:|---|
| [GHSA-phc5-m6cm-5c9f](https://github.com/YAFNET/YAFNET/security/advisories/GHSA-phc5-m6cm-5c9f) | `nuget:YAFNET.Core, other:YAFNET.Core` | high | no CVE anywhere | 89 | 4.0.8, 3.2.15 |
| [GHSA-j548-9grx-fh4f](https://github.com/rustfs/rustfs/security/advisories/GHSA-j548-9grx-fh4f) | `rust:rustfs` | high | CVE published, cited (CVE-2026-73288) | 89 | 1.0.0-rc.1 |
| [GHSA-x298-9x87-fvjq](https://github.com/rustfs/rustfs/security/advisories/GHSA-x298-9x87-fvjq) | `rust:rustfs` | medium | CVE published, cited (CVE-2026-73290) | 89 | 1.0.0-beta.12 |
| [GHSA-6r96-hmgc-726c](https://github.com/rustfs/rustfs/security/advisories/GHSA-6r96-hmgc-726c) | `rust:rustfs` | high | CVE published, cited (CVE-2026-73286) | 89 | 1.0.0-beta.12 |
| [GHSA-v9cp-qfw9-9pfp](https://github.com/rustfs/rustfs/security/advisories/GHSA-v9cp-qfw9-9pfp) | `rust:rustfs` | high | CVE published, cited (CVE-2026-73289) | 89 | 1.0.0-beta.12 |

591 advisories in limbo have waited more than a year.

## Coverage

Watchlist 22,038 repositories; 16,122 up to date on their schedule (daily for repos with an advisory in limbo, every 3 to 7 days for the rest); 9,776 checked in the last 24 hours; the last run stopped early (budget); 37,542 reviewed advisories known. Every number is a floor: the tracker only sees repositories on its watchlist. Version ranges are as entered by maintainers and unreviewed.

_Advisory metadata from published GitHub repository security advisories and the GitHub Advisory Database (https://github.com/advisories, CC BY 4.0); CVE state from CVE Services; OSV.dev; NVD API (this product uses the NVD API but is not endorsed or certified by the NVD). Compiled by Limbowatch (https://limbo.watch), CC BY 4.0._
