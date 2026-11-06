# Limbo Tracker daily report — 2026-11-06

Generated 2026-11-06 14:35:20 UTC; changes since 2026-11-05 14:54:42 UTC.

## Now

- **8,803 advisories in limbo** (+200 since the last report: 191 newly published, 12 older ones found for the first time, 3 left limbo): published by maintainers on GitHub, in ecosystems GitHub reviews, but not yet in GitHub's reviewed database or OSV.
  - 4,658 with no CVE anywhere · 597 citing a CVE that's still only reserved · 1,065 with a CVE from another CNA they don't cite
  - severity: 888 critical, 3,459 high, 3,655 medium, 801 low · median wait so far 56.6 days
- **14,321 more are likely permanent** (+207 since the last report: 189 newly published, 19 older ones found for the first time, 1 left limbo): in ecosystems GitHub doesn't review, so GitHub-based scanners will probably never see them.

## Since the last report

- **191 newly published** advisories entered limbo.
- 12 older advisories were found for the first time (5 in newly watched repos).
- **Left limbo** (likely permanent included): 4 reviewed by GitHub, 0 found to duplicate a reviewed advisory, 0 withdrawn or unpublished.
- **CVE changes:** 191 (133 reserved CVEs published, 2 new CVEs from other CNAs).

## Newly published, in limbo

| Advisory | Package | Severity | CVE | Days | Fixed in |
|---|---|---|---|---:|---|
| [GHSA-hqf9-xcvr-7xj5](https://github.com/roxy-wi/roxy-wi/security/advisories/GHSA-hqf9-xcvr-7xj5) | `pip:roxy-wi` | critical | no CVE anywhere | 1 | – |
| [GHSA-5pxg-x8g8-fw4j](https://github.com/ruvnet/ruflo/security/advisories/GHSA-5pxg-x8g8-fw4j) | `npm:@claude-flow/cli, npm:claude-flow, npm:ruflo` | critical | no CVE anywhere | 1 | 3.71.4 |
| [GHSA-c522-hqhp-v2qq](https://github.com/uutils/coreutils/security/advisories/GHSA-c522-hqhp-v2qq) | `rust:uucore` | critical | no CVE anywhere | 1 | 0.12.0 |
| [GHSA-h4fq-8pff-cq4v](https://github.com/eduMFA/eduMFA/security/advisories/GHSA-h4fq-8pff-cq4v) | `pip:edumfa` | high | no CVE anywhere | 1 | 2.9.6 |
| [GHSA-gqm8-ccgr-7r67](https://github.com/eduMFA/eduMFA/security/advisories/GHSA-gqm8-ccgr-7r67) | `pip:edumfa` | high | no CVE anywhere | 1 | 2.9.6 |
| [GHSA-5gqf-g35x-qxgp](https://github.com/dadrus/heimdall/security/advisories/GHSA-5gqf-g35x-qxgp) | `go:github.com/dadrus/heimdall` | high | no CVE anywhere | 1 | 0.17.28 |
| [GHSA-w577-2rfp-8gph](https://github.com/zip-rs/zip2/security/advisories/GHSA-w577-2rfp-8gph) | `rust:zip` | high | no CVE anywhere | 1 | 9.1.0 |
| [GHSA-9xrf-c4rq-h4gw](https://github.com/markmhendrickson/neotoma/security/advisories/GHSA-9xrf-c4rq-h4gw) | `npm:neotoma` | high | no CVE anywhere | 1 | 0.27.0 |
| [GHSA-5f24-43wm-7gr2](https://github.com/openvm-org/openvm/security/advisories/GHSA-5f24-43wm-7gr2) | `rust:openvm` | high | no CVE anywhere | 1 | 2.1.0 |
| [GHSA-6p9w-9j7q-867r](https://github.com/openvm-org/openvm/security/advisories/GHSA-6p9w-9j7q-867r) | `rust:openvm-rv32im-transpiler` | high | no CVE anywhere | 1 | 2.1.0 |
| [GHSA-2rxj-6v32-2v6j](https://github.com/parse-community/parse-server/security/advisories/GHSA-2rxj-6v32-2v6j) | `npm:parse-server` | high | no CVE anywhere | 1 | 9.11.1-alpha.1, 8.6.121 |
| [GHSA-6pgq-xpqq-rmjx](https://github.com/ArcadeData/arcadedb/security/advisories/GHSA-6pgq-xpqq-rmjx) | `maven:com.arcadedb:arcadedb-server` | high | no CVE anywhere | 1 | 26.11.1 |
| [GHSA-97h7-j68g-w3r2](https://github.com/ArcadeData/arcadedb/security/advisories/GHSA-97h7-j68g-w3r2) | `maven:com.arcadedb:arcadedb-server` | high | no CVE anywhere | 1 | 26.11.1 |
| [GHSA-jxwp-5ghh-f385](https://github.com/ArcadeData/arcadedb/security/advisories/GHSA-jxwp-5ghh-f385) | `maven:com.arcadedb:arcadedb-server` | high | no CVE anywhere | 1 | 26.11.1 |
| [GHSA-pcqw-hm7v-9m96](https://github.com/ArcadeData/arcadedb/security/advisories/GHSA-pcqw-hm7v-9m96) | `maven:com.arcadedb:arcadedb-mongodbw` | high | no CVE anywhere | 1 | 26.11.1 |
| [GHSA-g8hp-rhg7-hff5](https://github.com/stevereiner/flexible-graphrag/security/advisories/GHSA-g8hp-rhg7-hff5) | `pip:flexible-graphrag` | high | no CVE anywhere | 1 | 0.9.1 |
| [GHSA-3c56-jj76-gvhm](https://github.com/stevereiner/flexible-graphrag/security/advisories/GHSA-3c56-jj76-gvhm) | `pip:flexible-graphrag` | high | no CVE anywhere | 1 | 0.9.1 |
| [GHSA-mv9c-5phh-p8xr](https://github.com/stevereiner/flexible-graphrag/security/advisories/GHSA-mv9c-5phh-p8xr) | `pip:flexible-graphrag` | high | no CVE anywhere | 1 | 0.9.1 |
| [GHSA-2558-gvg9-whcx](https://github.com/stevereiner/flexible-graphrag/security/advisories/GHSA-2558-gvg9-whcx) | `pip:flexible-graphrag` | high | no CVE anywhere | 1 | 0.9.1 |
| [GHSA-c3q5-67f6-rx5w](https://github.com/gopacket/gopacket/security/advisories/GHSA-c3q5-67f6-rx5w) | `go:github.com/gopacket/gopacket` | high | no CVE anywhere | 1 | 1.7.6 |
| [GHSA-27q8-99gx-2jhw](https://github.com/gopacket/gopacket/security/advisories/GHSA-27q8-99gx-2jhw) | `go:github.com/gopacket/gopacket` | high | no CVE anywhere | 1 | 1.7.6 |
| [GHSA-63gp-f575-ch7c](https://github.com/gopacket/gopacket/security/advisories/GHSA-63gp-f575-ch7c) | `go:github.com/gopacket/gopacket` | high | no CVE anywhere | 1 | 1.7.6 |
| [GHSA-rrrf-6rxv-5554](https://github.com/gopacket/gopacket/security/advisories/GHSA-rrrf-6rxv-5554) | `go:github.com/gopacket/gopacket` | high | no CVE anywhere | 1 | 1.7.6 |
| [GHSA-vqpp-qh58-2p7h](https://github.com/ruvnet/ruflo/security/advisories/GHSA-vqpp-qh58-2p7h) | `npm:@claude-flow/cli, npm:claude-flow, npm:ruflo` | high | no CVE anywhere | 1 | 3.71.4 |
| [GHSA-6rwv-52g2-vx7j](https://github.com/ruvnet/ruflo/security/advisories/GHSA-6rwv-52g2-vx7j) | `npm:@claude-flow/cli, npm:claude-flow, npm:ruflo` | high | no CVE anywhere | 1 | 3.71.4 |

…and 166 more (see the feed).

## CVE changes

| Advisory | Change |
|---|---|
| [GHSA-22rh-qc6x-cvgw](https://github.com/SuiteCRM/SuiteCRM/security/advisories/GHSA-22rh-qc6x-cvgw) | CVE-2026-100359 RESERVED -> PUBLISHED |
| [GHSA-239h-ffjr-v957](https://github.com/SuiteCRM/SuiteCRM/security/advisories/GHSA-239h-ffjr-v957) | CVE-2026-71548 RESERVED -> PUBLISHED |
| [GHSA-26jm-9qfw-89w7](https://github.com/ntop/ntopng/security/advisories/GHSA-26jm-9qfw-89w7) | CVE-2026-97371 RESERVED -> PUBLISHED |
| [GHSA-294g-hq4w-c275](https://github.com/signalwire/freeswitch/security/advisories/GHSA-294g-hq4w-c275) | CVE-2026-116570 RESERVED -> PUBLISHED |
| [GHSA-2c8m-q484-jv7m](https://github.com/ArcadeData/arcadedb/security/advisories/GHSA-2c8m-q484-jv7m) | cites CVE-2026-93594 (was none) |
| [GHSA-2gp7-f34j-j4xw](https://github.com/signalwire/freeswitch/security/advisories/GHSA-2gp7-f34j-j4xw) | CVE-2026-116568 RESERVED -> PUBLISHED |
| [GHSA-2h4w-29cv-2cmv](https://github.com/ag2ai/ag2/security/advisories/GHSA-2h4w-29cv-2cmv) | CVE-2026-113663 RESERVED -> PUBLISHED |
| [GHSA-2hv5-wj8h-mv8m](https://github.com/SuiteCRM/SuiteCRM/security/advisories/GHSA-2hv5-wj8h-mv8m) | CVE-2026-97377 RESERVED -> PUBLISHED |
| [GHSA-2p6g-9c8q-232p](https://github.com/signalwire/freeswitch/security/advisories/GHSA-2p6g-9c8q-232p) | CVE-2026-116780 RESERVED -> PUBLISHED |
| [GHSA-2vqc-36qp-ccmw](https://github.com/owasp-modsecurity/ModSecurity/security/advisories/GHSA-2vqc-36qp-ccmw) | CVE-2026-61813 RESERVED -> PUBLISHED |
| [GHSA-2xwh-426q-42c5](https://github.com/kubeflow/pipelines/security/advisories/GHSA-2xwh-426q-42c5) | CVE-2026-88982 RESERVED -> PUBLISHED |
| [GHSA-35g6-9fjv-rmx5](https://github.com/rclone/rclone/security/advisories/GHSA-35g6-9fjv-rmx5) | cites CVE-2026-116187 (was none) |
| [GHSA-3g9m-rv3r-w5w2](https://github.com/nodejs/undici/security/advisories/GHSA-3g9m-rv3r-w5w2) | CVE-2026-120222 RESERVED -> PUBLISHED |
| [GHSA-3h74-qh4c-64gg](https://github.com/poweradmin/poweradmin/security/advisories/GHSA-3h74-qh4c-64gg) | cites CVE-2026-121699 (was none) |
| [GHSA-3mjp-45mc-3256](https://github.com/SuiteCRM/SuiteCRM/security/advisories/GHSA-3mjp-45mc-3256) | CVE-2026-69136 RESERVED -> PUBLISHED |
| [GHSA-3pcj-8j5w-jmxq](https://github.com/kubeflow/pipelines/security/advisories/GHSA-3pcj-8j5w-jmxq) | CVE-2026-88981 RESERVED -> PUBLISHED |
| [GHSA-3phg-q9w9-4pqw](https://github.com/SuiteCRM/SuiteCRM/security/advisories/GHSA-3phg-q9w9-4pqw) | CVE-2026-69134 RESERVED -> PUBLISHED |
| [GHSA-3rqf-7h69-gg5v](https://github.com/rclone/rclone/security/advisories/GHSA-3rqf-7h69-gg5v) | cites CVE-2026-116190 (was none) |
| [GHSA-3vxh-3pcx-9m8q](https://github.com/rclone/rclone/security/advisories/GHSA-3vxh-3pcx-9m8q) | cites CVE-2026-93986 (was none) |
| [GHSA-3xjq-2xjr-22gq](https://github.com/poweradmin/poweradmin/security/advisories/GHSA-3xjq-2xjr-22gq) | cites CVE-2026-121693 (was none) |
| [GHSA-4269-grc6-qr62](https://github.com/openemr/openemr/security/advisories/GHSA-4269-grc6-qr62) | CVE-2026-104135 RESERVED -> PUBLISHED |
| [GHSA-44pm-2q5p-fm63](https://github.com/rclone/rclone/security/advisories/GHSA-44pm-2q5p-fm63) | cites CVE-2026-116191 (was none) |
| [GHSA-45cp-v5ph-2jhm](https://github.com/requarks/wiki/security/advisories/GHSA-45cp-v5ph-2jhm) | cites CVE-2026-120698 (was none) |
| [GHSA-4773-c8fh-3rww](https://github.com/SuiteCRM/SuiteCRM/security/advisories/GHSA-4773-c8fh-3rww) | CVE-2026-100358 RESERVED -> PUBLISHED |
| [GHSA-49xv-q9pm-v2qm](https://github.com/tinyhumansai/openhuman/security/advisories/GHSA-49xv-q9pm-v2qm) | CVE-2026-49393 RESERVED -> PUBLISHED |

…and 166 more.

## Longest waiting, published in the last 90 days

| Advisory | Package | Severity | CVE | Days | Fixed in |
|---|---|---|---|---:|---|
| [GHSA-p2pf-q7wv-c9p7](https://github.com/getformwork/formwork/security/advisories/GHSA-p2pf-q7wv-c9p7) | `composer:getformwork/formwork` | medium | no CVE anywhere | 89 | 2.3.10 |
| [GHSA-vff9-46ww-fjjm](https://github.com/blakeblackshear/frigate/security/advisories/GHSA-vff9-46ww-fjjm) | `pip:frigate` | medium | no CVE anywhere | 89 | 0.18.0-beta3 |
| [GHSA-4xp7-86rr-9758](https://github.com/blakeblackshear/frigate/security/advisories/GHSA-4xp7-86rr-9758) | `blakeblackshear/frigate` | medium | no CVE anywhere | 89 | – |
| [GHSA-xv89-94jf-8vx2](https://github.com/LeJamon/go-xrpl/security/advisories/GHSA-xv89-94jf-8vx2) | `go:github.com/LeJamon/go-xrpl` | high | CVE reserved (RBP) (CVE-2026-61693) | 89 | 0.0.0-20260624144500-2dbc15f79469 |
| [GHSA-pqr4-rxgp-hv2m](https://github.com/wekan/wekan/security/advisories/GHSA-pqr4-rxgp-hv2m) | `actions:wekan/wekan` | medium | no CVE anywhere | 89 | 10.74 |

591 advisories in limbo have waited more than a year.

## Coverage

Watchlist 18,678 repositories; 12,592 up to date on their schedule (daily for repos with an advisory in limbo, every 3 to 7 days for the rest); 10,440 checked in the last 24 hours; the last run stopped early (budget); 37,526 reviewed advisories known. Every number is a floor: the tracker only sees repositories on its watchlist. Version ranges are as entered by maintainers and unreviewed.

_Advisory metadata from published GitHub repository security advisories and the GitHub Advisory Database (https://github.com/advisories, CC BY 4.0); CVE state from CVE Services; OSV.dev; NVD API (this product uses the NVD API but is not endorsed or certified by the NVD). Compiled by Limbowatch (https://limbo.watch), CC BY 4.0._
