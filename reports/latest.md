# Limbo Tracker daily report — 2026-11-16

Generated 2026-11-16 16:31:38 UTC; changes since 2026-11-15 14:34:50 UTC.

## Now

- **10,703 advisories in limbo** (+153 since the last report: 164 newly published, 9 older ones found for the first time, 20 left limbo): published by maintainers on GitHub, in ecosystems GitHub reviews, but not yet in GitHub's reviewed database or OSV.
  - 6,044 with no CVE anywhere · 624 citing a CVE that's still only reserved · 1,317 with a CVE from another CNA they don't cite
  - severity: 1,004 critical, 4,210 high, 4,488 medium, 1,001 low · median wait so far 53.4 days
- **15,462 more are likely permanent** (+123 since the last report: 123 newly published, 0 older ones found for the first time, 0 left limbo): in ecosystems GitHub doesn't review, so GitHub-based scanners will probably never see them.

## Since the last report

- **164 newly published** advisories entered limbo.
- 9 older advisories were found for the first time (4 in newly watched repos).
- **Left limbo** (likely permanent included): 20 reviewed by GitHub, 0 found to duplicate a reviewed advisory, 0 withdrawn or unpublished. GitHub reviewed 22 advisories in all in this period, from any repository.
- **CVE changes:** 20 (6 reserved CVEs published, 8 new CVEs from other CNAs).

## Newly published, in limbo

| Advisory | Package | Severity | CVE | Days | Fixed in |
|---|---|---|---|---:|---|
| [GHSA-q48q-3338-9mwh](https://github.com/yamcs/yamcs/security/advisories/GHSA-q48q-3338-9mwh) | `maven:org.yamcs:yamcs-core` | critical | no CVE anywhere | 1 | `5.14.1` |
| [GHSA-hrfr-7729-443m](https://github.com/libp2p/py-libp2p/security/advisories/GHSA-hrfr-7729-443m) | `pip:libp2p` | critical | no CVE anywhere | 0 | `–` |
| [GHSA-7h2h-f5h3-mjg5](https://github.com/agentfront/enclave/security/advisories/GHSA-7h2h-f5h3-mjg5) | `npm:@enclave-vm/core` | critical | no CVE anywhere | 0 | `2.19.0` |
| [GHSA-6pfj-2xp3-j4mm](https://github.com/pterodactyl/wings/security/advisories/GHSA-6pfj-2xp3-j4mm) | `go:github.com/pterodactyl/wings` | critical | no CVE anywhere | 0 | `1.13.4` |
| [GHSA-8rw4-fw83-3rv7](https://github.com/pterodactyl/wings/security/advisories/GHSA-8rw4-fw83-3rv7) | `go:github.com/pterodactyl/wings` | critical | no CVE anywhere | 0 | `1.13.4` |
| [GHSA-324w-x2q6-3288](https://github.com/pterodactyl/wings/security/advisories/GHSA-324w-x2q6-3288) | `go:github.com/pterodactyl/wings` | critical | no CVE anywhere | 0 | `1.13.4` |
| [GHSA-45cr-g945-4263](https://github.com/boxlite-ai/boxlite/security/advisories/GHSA-45cr-g945-4263) | `rust:boxlite-cli` | critical | no CVE anywhere | 0 | `0.10.0` |
| [GHSA-gfq6-89vx-q4j7](https://github.com/zip-rs/zip2/security/advisories/GHSA-gfq6-89vx-q4j7) | `rust:zip` | critical | no CVE anywhere | 0 | `–` |
| [GHSA-cm63-4mhh-887h](https://github.com/zip-rs/zip2/security/advisories/GHSA-cm63-4mhh-887h) | `rust:zip` | critical | no CVE anywhere | 0 | `9.2.2` |
| [GHSA-2v5m-57pq-r9j3](https://github.com/MervinPraison/PraisonAI/security/advisories/GHSA-2v5m-57pq-r9j3) | `pip:aiui` | critical | no CVE anywhere | 0 | `0.3.155` |
| [GHSA-x9jw-j844-v24h](https://github.com/nuxt/ui/security/advisories/GHSA-x9jw-j844-v24h) | `npm:@nuxt/ui` | critical | no CVE anywhere | 0 | `4.12.2` |
| [GHSA-5jxx-2336-22p8](https://github.com/elct9620/kobako/security/advisories/GHSA-5jxx-2336-22p8) | `rubygems:kobako` | critical | no CVE anywhere | 0 | `0.25.0` |
| [GHSA-26f3-4cp2-gg6m](https://github.com/elct9620/kobako/security/advisories/GHSA-26f3-4cp2-gg6m) | `rubygems:kobako` | critical | no CVE anywhere | 0 | `0.23.0` |
| [GHSA-x462-9fp3-ghjp](https://github.com/xwiki/xwiki-platform/security/advisories/GHSA-x462-9fp3-ghjp) | `maven:org.xwiki.platform:xwiki-platform-user-directory-ui` | critical | CVE reserved (RBP) (`CVE-2026-53967`) | 0 | `18.5.0-rc-1, 18.4.1, 17.10.10, 16.10.18` |
| [GHSA-3m97-hv84-whgc](https://github.com/quarkusio/quarkus/security/advisories/GHSA-3m97-hv84-whgc) | `maven:io.quarkus:quarkus-hibernate-orm-rest-data-panache` | critical | CVE published, cited (`CVE-2026-87744`) | 0 | `3.27.6.1, 3.33.4.1, 3.40.2` |
| [GHSA-cp32-fxxm-95fh](https://github.com/yamcs/yamcs/security/advisories/GHSA-cp32-fxxm-95fh) | `maven:org.yamcs:yamcs-core` | high | no CVE anywhere | 1 | `5.14.1` |
| [GHSA-wcv6-98jm-hjq5](https://github.com/yamcs/yamcs/security/advisories/GHSA-wcv6-98jm-hjq5) | `maven:org.yamcs:yamcs-core` | high | no CVE anywhere | 1 | `5.14.1` |
| [GHSA-cf8w-8983-rvx4](https://github.com/yamcs/yamcs/security/advisories/GHSA-cf8w-8983-rvx4) | `maven:org.yamcs:yamcs-core` | high | no CVE anywhere | 1 | `5.14.1` |
| [GHSA-2f3q-8v3v-2392](https://github.com/yamcs/yamcs/security/advisories/GHSA-2f3q-8v3v-2392) | `maven:org.yamcs:yamcs-core` | high | no CVE anywhere | 0 | `5.14.1` |
| [GHSA-3g4m-8x4r-93wj](https://github.com/agentfront/enclave/security/advisories/GHSA-3g4m-8x4r-93wj) | `npm:@enclave-vm/core` | high | no CVE anywhere | 0 | `2.19.0` |
| [GHSA-jq48-63vx-hqr2](https://github.com/agentfront/enclave/security/advisories/GHSA-jq48-63vx-hqr2) | `npm:@enclave-vm/core` | high | no CVE anywhere | 0 | `2.19.0` |
| [GHSA-fr7f-8g6p-64vc](https://github.com/agentfront/enclave/security/advisories/GHSA-fr7f-8g6p-64vc) | `npm:@enclave-vm/core` | high | no CVE anywhere | 0 | `2.19.0` |
| [GHSA-vjfq-8ph3-j33m](https://github.com/agentfront/enclave/security/advisories/GHSA-vjfq-8ph3-j33m) | `npm:@enclave-vm/core` | high | no CVE anywhere | 0 | `2.19.0` |
| [GHSA-p863-6mhw-7w5j](https://github.com/agentfront/enclave/security/advisories/GHSA-p863-6mhw-7w5j) | `npm:@enclave-vm/ast` | high | no CVE anywhere | 0 | `2.19.0` |
| [GHSA-g44v-4432-4r48](https://github.com/agentfront/enclave/security/advisories/GHSA-g44v-4432-4r48) | `npm:@enclave-vm/core` | high | no CVE anywhere | 0 | `2.19.0` |

…and 139 more: [the tracker](https://limbo.watch/tracker/) lists them all, newest first.

## CVE changes

| Advisory | Change |
|---|---|
| [GHSA-c94f-87xg-65wf](https://github.com/silverstripe/silverstripe-framework/security/advisories/GHSA-c94f-87xg-65wf) | CVE-2026-91115 RESERVED -> PUBLISHED |
| [GHSA-3qh3-54qg-gpq3](https://github.com/silverstripe/silverstripe-framework/security/advisories/GHSA-3qh3-54qg-gpq3) | CVE-2026-88989 RESERVED -> PUBLISHED |
| [GHSA-4qv2-g5vp-wjjw](https://github.com/silverstripe/silverstripe-framework/security/advisories/GHSA-4qv2-g5vp-wjjw) | CVE-2026-91113 RESERVED -> PUBLISHED |
| [GHSA-qqrg-8jpm-8mph](https://github.com/silverstripe/silverstripe-framework/security/advisories/GHSA-qqrg-8jpm-8mph) | CVE-2026-88987 RESERVED -> PUBLISHED |
| [GHSA-rg72-5958-c65m](https://github.com/silverstripe/silverstripe-framework/security/advisories/GHSA-rg72-5958-c65m) | CVE-2026-91112 RESERVED -> PUBLISHED |
| [GHSA-xwg4-8hqh-79jq](https://github.com/silverstripe/silverstripe-framework/security/advisories/GHSA-xwg4-8hqh-79jq) | CVE-2026-88988 RESERVED -> PUBLISHED |
| [GHSA-vvf4-9x63-8xvv](https://github.com/rthalley/dnspython/security/advisories/GHSA-vvf4-9x63-8xvv) | cites CVE-2026-128089 (was none) |
| [GHSA-4fqr-96q8-xrfx](https://github.com/sparklemotion/sqlite3-ruby/security/advisories/GHSA-4fqr-96q8-xrfx) | cites CVE-2026-128084 (was none) |
| [GHSA-cpgf-5mjf-73p7](https://github.com/rails/rails-html-sanitizer/security/advisories/GHSA-cpgf-5mjf-73p7) | cites CVE-2026-128068 (was none) |
| [GHSA-h7wh-q2qr-458c](https://github.com/rails/rails-html-sanitizer/security/advisories/GHSA-h7wh-q2qr-458c) | cites CVE-2026-128069 (was none) |
| [GHSA-q7gw-24fr-5p69](https://github.com/open-telemetry/opentelemetry-go/security/advisories/GHSA-q7gw-24fr-5p69) | cites CVE-2026-128085 (was none) |
| [GHSA-rrfc-gjm9-cgrj](https://github.com/open-telemetry/opentelemetry-go/security/advisories/GHSA-rrfc-gjm9-cgrj) | cites CVE-2026-128086 (was none) |
| [GHSA-m9h5-c637-cpcg](https://github.com/kiwitcms/kiwitcms/security/advisories/GHSA-m9h5-c637-cpcg) | new CVE from another CNA: CVE-2026-129882 |
| [GHSA-46vh-v2q6-wrcv](https://github.com/sandboxie-plus/Sandboxie/security/advisories/GHSA-46vh-v2q6-wrcv) | new CVE from another CNA: CVE-2026-129956 |
| [GHSA-7q68-ch46-pxmc](https://github.com/PrestaShop/PrestaShop/security/advisories/GHSA-7q68-ch46-pxmc) | new CVE from another CNA: CVE-2026-129957 |
| [GHSA-939f-xh28-2q48](https://github.com/seaweedfs/seaweedfs/security/advisories/GHSA-939f-xh28-2q48) | new CVE from another CNA: CVE-2026-129851, CVE-2026-129852 |
| [GHSA-5wcf-p378-fmwr](https://github.com/frappe/crm/security/advisories/GHSA-5wcf-p378-fmwr) | new CVE from another CNA: CVE-2026-129864 |
| [GHSA-jwh8-j584-79hp](https://github.com/yuzutech/kroki/security/advisories/GHSA-jwh8-j584-79hp) | new CVE from another CNA: CVE-2026-129485 |
| [GHSA-rr6m-92cx-w69q](https://github.com/wallabag/wallabag/security/advisories/GHSA-rr6m-92cx-w69q) | new CVE from another CNA: CVE-2026-129856 |
| [GHSA-xp94-px2v-f7f2](https://github.com/yuzutech/kroki/security/advisories/GHSA-xp94-px2v-f7f2) | new CVE from another CNA: CVE-2026-129484 |

## Longest waiting, published in the last 90 days

| Advisory | Package | Severity | CVE | Days | Fixed in |
|---|---|---|---|---:|---|
| [GHSA-rh46-vc3j-w2w3](https://github.com/openbao/openbao/security/advisories/GHSA-rh46-vc3j-w2w3) | `go:github.com/openbao/openbao` | critical | CVE reserved (RBP) (`CVE-2026-104088`) | 89 | `2.6.2` |
| [GHSA-g892-p242-8g86](https://github.com/openbao/openbao/security/advisories/GHSA-g892-p242-8g86) | `go:github.com/openbao/openbao` | low | CVE published by another CNA, not cited (`CVE-2026-115369`) | 89 | `2.6.2` |
| [GHSA-7g9f-57qp-jhgx](https://github.com/zalando/skipper/security/advisories/GHSA-7g9f-57qp-jhgx) | `go:github.com/zalando/skipper` | medium | no CVE anywhere | 89 | `v0.27.59` |
| [GHSA-v9vv-w45w-rppw](https://github.com/zalando/skipper/security/advisories/GHSA-v9vv-w45w-rppw) | `go:github.com/zalando/skipper` | medium | no CVE anywhere | 89 | `v0.27.60` |
| [GHSA-822f-6gg9-whr5](https://github.com/amazon-ion/ion-java/security/advisories/GHSA-822f-6gg9-whr5) | `maven:ion-java` | high | CVE published, cited (`CVE-2026-75935`) | 89 | `1.12.0` |

607 advisories in limbo have waited more than a year.

## Coverage

Watchlist 67,643 repositories; 67,643 up to date on their schedule (daily for repos with an advisory in limbo, every 3 days for other repos with advisories, every 30 days and after each release for the rest); 5,917 checked in the last 24 hours; 37,802 reviewed advisories known. Every number is a floor: the tracker only sees repositories on its watchlist. Version ranges are as entered by maintainers and unreviewed.

_Advisory metadata from published GitHub repository security advisories and the GitHub Advisory Database (https://github.com/advisories, CC BY 4.0); CVE state from CVE Services; OSV.dev; NVD API (this product uses the NVD API but is not endorsed or certified by the NVD). Compiled by Limbowatch (https://limbo.watch), CC BY 4.0._
