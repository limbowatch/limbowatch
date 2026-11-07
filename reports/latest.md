# Limbo Tracker daily report — 2026-11-07

Generated 2026-11-07 13:24:27 UTC; changes since 2026-11-07 12:06:24 UTC.

## Now

- **9,127 advisories in limbo** (+128 since the last report: 82 newly published, 46 older ones found for the first time, 0 left limbo): published by maintainers on GitHub, in ecosystems GitHub reviews, but not yet in GitHub's reviewed database or OSV.
  - 4,910 with no CVE anywhere · 588 citing a CVE that's still only reserved · 1,076 with a CVE from another CNA they don't cite
  - severity: 895 critical, 3,576 high, 3,810 medium, 846 low · median wait so far 56.0 days
- **14,413 more are likely permanent** (+43 since the last report: 42 newly published, 1 older ones found for the first time, 0 left limbo): in ecosystems GitHub doesn't review, so GitHub-based scanners will probably never see them.

## Since the last report

- **82 newly published** advisories entered limbo.
- 46 older advisories were found for the first time (0 in newly watched repos).
- **Left limbo** (likely permanent included): 0 reviewed by GitHub, 0 found to duplicate a reviewed advisory, 0 withdrawn or unpublished.
- **CVE changes:** 15 (0 reserved CVEs published, 0 new CVEs from other CNAs).

## Newly published, in limbo

| Advisory | Package | Severity | CVE | Days | Fixed in |
|---|---|---|---|---:|---|
| [GHSA-6vhm-j9h7-f9gh](https://github.com/LuckyPennySoftware/AutoMapper/security/advisories/GHSA-6vhm-j9h7-f9gh) | `nuget:AutoMapper` | high | no CVE anywhere | 1 | 16.3.0, 15.1.4 |
| [GHSA-gpwp-5797-mjff](https://github.com/LuckyPennySoftware/AutoMapper/security/advisories/GHSA-gpwp-5797-mjff) | `nuget:AutoMapper` | high | no CVE anywhere | 1 | 16.3.0, 15.1.4 |
| [GHSA-f923-62v2-x6c9](https://github.com/gardener/gardenctl-v2/security/advisories/GHSA-f923-62v2-x6c9) | `go:github.com/gardener/gardenctl-v2` | high | no CVE anywhere | 1 | v2.19.0 |
| [GHSA-vx6q-cr5q-945g](https://github.com/elixir-grpc/grpc/security/advisories/GHSA-vx6q-cr5q-945g) | `erlang:grpc_server` | high | CVE published, cited (CVE-2026-71397) | 0 | 1.0.6 |
| [GHSA-66qv-66mg-9h74](https://github.com/rclone/rclone/security/advisories/GHSA-66qv-66mg-9h74) | `go:github.com/rclone/rclone` | high | no CVE anywhere | 0 | v1.76.0 |
| [GHSA-p6r2-mcj6-x237](https://github.com/haraka/Haraka/security/advisories/GHSA-p6r2-mcj6-x237) | `npm:haraka` | high | no CVE anywhere | 0 | 3.4.0 |
| [GHSA-72px-vh6m-89wc](https://github.com/lxsmnsyc/seroval/security/advisories/GHSA-72px-vh6m-89wc) | `npm:seroval` | high | no CVE anywhere | 0 | 1.7.9 |
| [GHSA-mgwh-j6v5-5mf8](https://github.com/theagentrouter/agent-router/security/advisories/GHSA-mgwh-j6v5-5mf8) | `go:github.com/theagentrouter/agent-router` | high | no CVE anywhere | 0 | 1.2.1 |
| [GHSA-34hg-fxr9-v95r](https://github.com/solspace/craft-freeform/security/advisories/GHSA-34hg-fxr9-v95r) | `composer:solspace/craft-freeform` | high | no CVE anywhere | 0 | 5.17.8 |
| [GHSA-635j-qv98-9275](https://github.com/istio/istio/security/advisories/GHSA-635j-qv98-9275) | `go:istio.io/istio` | high | no CVE anywhere | 0 | 1.31.4, 1.30.8 |
| [GHSA-cxwg-46mx-q8hf](https://github.com/istio/istio/security/advisories/GHSA-cxwg-46mx-q8hf) | `go:istio.io/istio` | high | no CVE anywhere | 0 | 1.31.4, 1.30.8 |
| [GHSA-rr2c-p22p-6r9r](https://github.com/istio/istio/security/advisories/GHSA-rr2c-p22p-6r9r) | `go:istio.io/istio` | high | no CVE anywhere | 0 | 1.31.4, 1.30.8 |
| [GHSA-jrxf-9jh4-86w7](https://github.com/QWED-AI/qwed-verification/security/advisories/GHSA-jrxf-9jh4-86w7) | `pip:qwed` | high | no CVE anywhere | 0 | 9.0.0 |
| [GHSA-qrp4-p44j-m484](https://github.com/QWED-AI/qwed-verification/security/advisories/GHSA-qrp4-p44j-m484) | `pip:qwed` | high | no CVE anywhere | 0 | 9.0.0 |
| [GHSA-p75q-7rg5-ff46](https://github.com/QWED-AI/qwed-verification/security/advisories/GHSA-p75q-7rg5-ff46) | `pip:qwed` | high | no CVE anywhere | 0 | 9.0.0 |
| [GHSA-pr6c-cqg8-6w5r](https://github.com/QWED-AI/qwed-verification/security/advisories/GHSA-pr6c-cqg8-6w5r) | `pip:qwed` | high | no CVE anywhere | 0 | 9.0.0 |
| [GHSA-3gcq-q292-8cfp](https://github.com/flarum/framework/security/advisories/GHSA-3gcq-q292-8cfp) | `composer:flarum/mentions` | high | no CVE anywhere | 0 | 2.0.3, 1.8.7 |
| [GHSA-8rhq-hrph-r3p4](https://github.com/ChurchCRM/CRM/security/advisories/GHSA-8rhq-hrph-r3p4) | `composer:churchcrm/crm` | high | no CVE anywhere | 0 | 7.8.3 |
| [GHSA-gp7m-9622-gcw9](https://github.com/Admidio/admidio/security/advisories/GHSA-gp7m-9622-gcw9) | `composer:admidio` | high | no CVE anywhere | 0 | 5.0.18 |
| [GHSA-mpq2-6jf2-x7m5](https://github.com/versity/versitygw/security/advisories/GHSA-mpq2-6jf2-x7m5) | `go:github.com/versity/versitygw` | high | no CVE anywhere | 0 | 1.11.0 |
| [GHSA-6rgc-8hxm-rj7p](https://github.com/agronholm/cbor2/security/advisories/GHSA-6rgc-8hxm-rj7p) | `pip:cbor2` | high | no CVE anywhere | 0 | 6.2.1 |
| [GHSA-4mwh-6232-9frp](https://github.com/siyuan-note/siyuan/security/advisories/GHSA-4mwh-6232-9frp) | `npm:SiYuan` | high | no CVE anywhere | 0 | v3.8.10 |
| [GHSA-qf2w-mm2p-jmg9](https://github.com/SignalK/signalk-server/security/advisories/GHSA-qf2w-mm2p-jmg9) | `npm:signalk-server` | high | no CVE anywhere | 0 | 2.37.0 |
| [GHSA-7fqv-4rff-v232](https://github.com/ZenHive/mpp/security/advisories/GHSA-7fqv-4rff-v232) | `erlang:mpp` | high | no CVE anywhere | 0 | 0.22.3 |
| [GHSA-c36r-65p6-q3m9](https://github.com/ether/etherpad/security/advisories/GHSA-c36r-65p6-q3m9) | `npm:ep_etherpad-lite` | high | no CVE anywhere | 0 | 3.3.16 |

…and 57 more (see the feed).

## CVE changes

| Advisory | Change |
|---|---|
| [GHSA-52wv-cgfg-4j6x](https://github.com/kestra-io/kestra/security/advisories/GHSA-52wv-cgfg-4j6x) | cites CVE-2026-123350 (was none) |
| [GHSA-59cq-p2m6-hh23](https://github.com/sysadminsmedia/homebox/security/advisories/GHSA-59cq-p2m6-hh23) | cites CVE-2026-123352 (was none) |
| [GHSA-5jff-8h8q-r5qx](https://github.com/symfony/symfony/security/advisories/GHSA-5jff-8h8q-r5qx) | cites CVE-2026-123824 (was none) |
| [GHSA-6wcq-4vx6-rx53](https://github.com/kestra-io/kestra/security/advisories/GHSA-6wcq-4vx6-rx53) | cites CVE-2026-123349 (was none) |
| [GHSA-754m-5j7m-8wfv](https://github.com/sysadminsmedia/homebox/security/advisories/GHSA-754m-5j7m-8wfv) | cites CVE-2026-123351 (was none) |
| [GHSA-88fj-95f7-w68m](https://github.com/Linuxfabrik/monitoring-plugins/security/advisories/GHSA-88fj-95f7-w68m) | cites CVE-2026-123358 (was none) |
| [GHSA-9gp7-896w-m3r7](https://github.com/kestra-io/kestra/security/advisories/GHSA-9gp7-896w-m3r7) | cites CVE-2026-122263 (was none) |
| [GHSA-frv7-262w-24q9](https://github.com/docmost/docmost/security/advisories/GHSA-frv7-262w-24q9) | cites CVE-2026-123353 (was none) |
| [GHSA-gq53-v8w2-gjhj](https://github.com/symfony/symfony/security/advisories/GHSA-gq53-v8w2-gjhj) | cites CVE-2026-121971 (was none) |
| [GHSA-hqp2-7rr8-hf26](https://github.com/symfony/symfony/security/advisories/GHSA-hqp2-7rr8-hf26) | cites CVE-2026-122053 (was none) |
| [GHSA-hv7r-p86q-wg5f](https://github.com/beyonders-studio/initiative/security/advisories/GHSA-hv7r-p86q-wg5f) | cites CVE-2026-120695 (was none) |
| [GHSA-hwfg-qwvh-2wfx](https://github.com/symfony/symfony/security/advisories/GHSA-hwfg-qwvh-2wfx) | cites CVE-2026-123792 (was none) |
| [GHSA-pxj9-jh84-vhm5](https://github.com/symfony/symfony/security/advisories/GHSA-pxj9-jh84-vhm5) | cites CVE-2026-121623 (was none) |
| [GHSA-wg5q-m2ww-f3c9](https://github.com/symfony/symfony/security/advisories/GHSA-wg5q-m2ww-f3c9) | cites CVE-2026-123339 (was none) |
| [GHSA-wq8c-j948-fxjx](https://github.com/kestra-io/kestra/security/advisories/GHSA-wq8c-j948-fxjx) | cites CVE-2026-122262 (was none) |

## Longest waiting, published in the last 90 days

| Advisory | Package | Severity | CVE | Days | Fixed in |
|---|---|---|---|---:|---|
| [GHSA-j548-9grx-fh4f](https://github.com/rustfs/rustfs/security/advisories/GHSA-j548-9grx-fh4f) | `rust:rustfs` | high | CVE published, cited (CVE-2026-73288) | 89 | 1.0.0-rc.1 |
| [GHSA-x298-9x87-fvjq](https://github.com/rustfs/rustfs/security/advisories/GHSA-x298-9x87-fvjq) | `rust:rustfs` | medium | CVE published, cited (CVE-2026-73290) | 89 | 1.0.0-beta.12 |
| [GHSA-6r96-hmgc-726c](https://github.com/rustfs/rustfs/security/advisories/GHSA-6r96-hmgc-726c) | `rust:rustfs` | high | CVE published, cited (CVE-2026-73286) | 89 | 1.0.0-beta.12 |
| [GHSA-v9cp-qfw9-9pfp](https://github.com/rustfs/rustfs/security/advisories/GHSA-v9cp-qfw9-9pfp) | `rust:rustfs` | high | CVE published, cited (CVE-2026-73289) | 89 | 1.0.0-beta.12 |
| [GHSA-2w7f-x78f-89q2](https://github.com/kimai/kimai/security/advisories/GHSA-2w7f-x78f-89q2) | `composer:kimai/kimai2` | medium | CVE published by another CNA, not cited (CVE-2026-80193) | 89 | 2.62.0 |

591 advisories in limbo have waited more than a year.

## Coverage

Watchlist 22,038 repositories; 22,038 up to date on their schedule (daily for repos with an advisory in limbo, every 3 to 7 days for the rest); 16,177 checked in the last 24 hours; 37,542 reviewed advisories known. Every number is a floor: the tracker only sees repositories on its watchlist. Version ranges are as entered by maintainers and unreviewed.

_Advisory metadata from published GitHub repository security advisories and the GitHub Advisory Database (https://github.com/advisories, CC BY 4.0); CVE state from CVE Services; OSV.dev; NVD API (this product uses the NVD API but is not endorsed or certified by the NVD). Compiled by Limbowatch (https://limbo.watch), CC BY 4.0._
