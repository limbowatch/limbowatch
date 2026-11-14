# Limbo Tracker daily report — 2026-11-14

Generated 2026-11-14 14:11:44 UTC; changes since 2026-11-13 15:19:39 UTC.

## Now

- **10,463 advisories in limbo** (+53 since the last report: 90 newly published, 3 older ones found for the first time, 32 left limbo, 1 moved in from likely permanent, 9 moved to likely permanent): published by maintainers on GitHub, in ecosystems GitHub reviews, but not yet in GitHub's reviewed database or OSV.
  - 5,856 with no CVE anywhere · 600 citing a CVE that's still only reserved · 1,314 with a CVE from another CNA they don't cite
  - severity: 984 critical, 4,111 high, 4,388 medium, 980 low · median wait so far 52.8 days
- **15,319 more are likely permanent** (+44 since the last report: 35 newly published, 3 older ones found for the first time, 2 left limbo, 9 moved in from the in-limbo count, 1 moved to the in-limbo count): in ecosystems GitHub doesn't review, so GitHub-based scanners will probably never see them.

## Since the last report

- **90 newly published** advisories entered limbo.
- 3 older advisories were found for the first time (2 in newly watched repos).
- **Left limbo** (likely permanent included): 34 reviewed by GitHub, 0 found to duplicate a reviewed advisory, 0 withdrawn or unpublished. GitHub reviewed 43 advisories in all in this period, from any repository.
- **CVE changes:** 76 (31 reserved CVEs published, 4 new CVEs from other CNAs).

## Newly published, in limbo

| Advisory | Package | Severity | CVE | Days | Fixed in |
|---|---|---|---|---:|---|
| [GHSA-gj7w-2hmm-q26q](https://github.com/wintercms/winter/security/advisories/GHSA-gj7w-2hmm-q26q) | `composer:winter/wn-backend-module` | critical | no CVE anywhere | 1 | `1.2.15` |
| [GHSA-7wrr-qcrp-4hhf](https://github.com/neos/flow-development-collection/security/advisories/GHSA-7wrr-qcrp-4hhf) | `composer:neos/flow` | critical | no CVE anywhere | 1 | `8.3.22, 8.4.7, 9.0.10, 9.1.5, 9.2.3` |
| [GHSA-rg57-5c8r-3p43](https://github.com/WeblateOrg/weblate/security/advisories/GHSA-rg57-5c8r-3p43) | `pip:weblate` | critical | no CVE anywhere | 0 | `2026.11.2` |
| [GHSA-r5p9-7834-rqr3](https://github.com/WeblateOrg/weblate/security/advisories/GHSA-r5p9-7834-rqr3) | `pip:weblate` | critical | no CVE anywhere | 0 | `2026.11` |
| [GHSA-hp98-8hvc-643h](https://github.com/WeblateOrg/weblate/security/advisories/GHSA-hp98-8hvc-643h) | `pip:weblate` | critical | no CVE anywhere | 0 | `2026.11` |
| [GHSA-6hph-c9x9-4mcv](https://github.com/WeblateOrg/weblate/security/advisories/GHSA-6hph-c9x9-4mcv) | `pip:weblate` | critical | no CVE anywhere | 0 | `2026.11` |
| [GHSA-37g9-w4hg-h9qr](https://github.com/websockets/ws/security/advisories/GHSA-37g9-w4hg-h9qr) | `npm:ws` | high | no CVE anywhere | 1 | `5.2.8, 6.2.7, 7.5.14, 8.23.0` |
| [GHSA-rf6g-xhmp-gm7v](https://github.com/puma/puma/security/advisories/GHSA-rf6g-xhmp-gm7v) | `rubygems:puma` | high | no CVE anywhere | 1 | `7.2.2, 8.0.3` |
| [GHSA-xw3h-pgr9-3vg7](https://github.com/puma/puma/security/advisories/GHSA-xw3h-pgr9-3vg7) | `rubygems:puma` | high | no CVE anywhere | 1 | `8.0.3, 7.2.2` |
| [GHSA-x646-wp7c-h9mg](https://github.com/puma/puma/security/advisories/GHSA-x646-wp7c-h9mg) | `rubygems:puma` | high | no CVE anywhere | 1 | `7.2.2, 8.0.3` |
| [GHSA-86xc-wrr9-xmmq](https://github.com/puma/puma/security/advisories/GHSA-86xc-wrr9-xmmq) | `rubygems:puma` | high | no CVE anywhere | 1 | `7.2.2, 8.0.3` |
| [GHSA-q4v7-v68c-x6hx](https://github.com/wallabag/wallabag/security/advisories/GHSA-q4v7-v68c-x6hx) | `composer:wallabag/wallabag` | high | no CVE anywhere | 1 | `2.6.16, 2.7.0` |
| [GHSA-xc5v-89vq-hv5m](https://github.com/elixir-grpc/grpc/security/advisories/GHSA-xc5v-89vq-hv5m) | `erlang:grpc, erlang:grpc_server` | high | CVE published, cited (`CVE-2026-124278`) | 0 | `1.1.0, 1.0.0` |
| [GHSA-736x-r87j-jhcm](https://github.com/elixir-grpc/grpc/security/advisories/GHSA-736x-r87j-jhcm) | `erlang:grpc_server` | high | CVE published, cited (`CVE-2026-124279`) | 0 | `1.1.0` |
| [GHSA-c2h9-f9cc-27xh](https://github.com/elixir-grpc/grpc/security/advisories/GHSA-c2h9-f9cc-27xh) | `erlang:grpc, erlang:grpc_server` | high | CVE published, cited (`CVE-2026-121809`) | 0 | `1.0.0, 1.1.0` |
| [GHSA-r43p-22px-2mvm](https://github.com/modoboa/modoboa/security/advisories/GHSA-r43p-22px-2mvm) | `pip:modoboa` | high | no CVE anywhere | 0 | `2.13.0` |
| [GHSA-3vvv-hfx8-4jhm](https://github.com/modoboa/modoboa/security/advisories/GHSA-3vvv-hfx8-4jhm) | `pip:modoboa` | high | no CVE anywhere | 0 | `2.13.0` |
| [GHSA-fxxr-gqx3-p253](https://github.com/TryGhost/Ghost/security/advisories/GHSA-fxxr-gqx3-p253) | `npm:ghost` | high | no CVE anywhere | 0 | `6.76.0` |
| [GHSA-h7m4-392w-vpjj](https://github.com/OpenHands/software-agent-sdk/security/advisories/GHSA-h7m4-392w-vpjj) | `pip:openhands-agent-server` | high | no CVE anywhere | 0 | `1.61.0` |
| [GHSA-f55r-3mcp-7vvh](https://github.com/OpenHands/software-agent-sdk/security/advisories/GHSA-f55r-3mcp-7vvh) | `pip:openhands-agent-server` | high | no CVE anywhere | 0 | `1.61.0` |
| [GHSA-h5qc-9ccp-2jpr](https://github.com/WeblateOrg/weblate/security/advisories/GHSA-h5qc-9ccp-2jpr) | `pip:weblate` | high | no CVE anywhere | 0 | `2026.11` |
| [GHSA-58m4-xqvh-78xj](https://github.com/WeblateOrg/weblate/security/advisories/GHSA-58m4-xqvh-78xj) | `pip:weblate` | high | no CVE anywhere | 0 | `2026.11` |
| [GHSA-r6wp-8gf8-82fx](https://github.com/WeblateOrg/weblate/security/advisories/GHSA-r6wp-8gf8-82fx) | `pip:weblate` | high | no CVE anywhere | 0 | `2026.11.1` |
| [GHSA-946j-ggg5-f8jh](https://github.com/WeblateOrg/weblate/security/advisories/GHSA-946j-ggg5-f8jh) | `pip:weblate` | high | no CVE anywhere | 0 | `2026.11.2` |
| [GHSA-655x-rwmw-vcv8](https://github.com/WeblateOrg/weblate/security/advisories/GHSA-655x-rwmw-vcv8) | `pip:weblate` | high | no CVE anywhere | 0 | `2026.11.2` |

…and 65 more: [the tracker](https://limbo.watch/tracker/) lists them all, newest first.

## CVE changes

| Advisory | Change |
|---|---|
| [GHSA-2c8x-f46r-8phh](https://github.com/bacnet-stack/bacnet-stack/security/advisories/GHSA-2c8x-f46r-8phh) | CVE-2026-62974 RESERVED -> PUBLISHED |
| [GHSA-32jj-x86x-w98w](https://github.com/bacnet-stack/bacnet-stack/security/advisories/GHSA-32jj-x86x-w98w) | CVE-2026-62976 RESERVED -> PUBLISHED |
| [GHSA-3f36-4qv4-vfgh](https://github.com/PrestaShop/PrestaShop/security/advisories/GHSA-3f36-4qv4-vfgh) | CVE-2026-71531 RESERVED -> PUBLISHED |
| [GHSA-3xxw-jfwm-rq9c](https://github.com/bacnet-stack/bacnet-stack/security/advisories/GHSA-3xxw-jfwm-rq9c) | CVE-2026-62973 RESERVED -> PUBLISHED |
| [GHSA-4fgg-fghm-jm43](https://github.com/bacnet-stack/bacnet-stack/security/advisories/GHSA-4fgg-fghm-jm43) | CVE-2026-52787 RESERVED -> PUBLISHED |
| [GHSA-4p4w-m434-jrhj](https://github.com/bacnet-stack/bacnet-stack/security/advisories/GHSA-4p4w-m434-jrhj) | CVE-2026-58498 RESERVED -> PUBLISHED |
| [GHSA-4rf9-4vgq-5gcw](https://github.com/bacnet-stack/bacnet-stack/security/advisories/GHSA-4rf9-4vgq-5gcw) | CVE-2026-52789 RESERVED -> PUBLISHED |
| [GHSA-4vgv-v5ph-rmxr](https://github.com/bacnet-stack/bacnet-stack/security/advisories/GHSA-4vgv-v5ph-rmxr) | CVE-2026-100403 RESERVED -> PUBLISHED |
| [GHSA-7r8r-2rj2-5wvr](https://github.com/bacnet-stack/bacnet-stack/security/advisories/GHSA-7r8r-2rj2-5wvr) | CVE-2026-49341 RESERVED -> PUBLISHED |
| [GHSA-8456-m9x4-j6mc](https://github.com/bacnet-stack/bacnet-stack/security/advisories/GHSA-8456-m9x4-j6mc) | CVE-2026-82414 RESERVED -> PUBLISHED |
| [GHSA-8759-hx7g-94qx](https://github.com/bacnet-stack/bacnet-stack/security/advisories/GHSA-8759-hx7g-94qx) | CVE-2026-49990 RESERVED -> PUBLISHED |
| [GHSA-92q2-p4vr-fvmp](https://github.com/bacnet-stack/bacnet-stack/security/advisories/GHSA-92q2-p4vr-fvmp) | CVE-2026-102612 RESERVED -> PUBLISHED |
| [GHSA-gr74-333w-7wg8](https://github.com/bacnet-stack/bacnet-stack/security/advisories/GHSA-gr74-333w-7wg8) | CVE-2026-97692 RESERVED -> PUBLISHED |
| [GHSA-h57f-c9j4-577x](https://github.com/indico/indico/security/advisories/GHSA-h57f-c9j4-577x) | CVE-2026-107398 RESERVED -> PUBLISHED |
| [GHSA-hg85-pmm3-jfcf](https://github.com/bacnet-stack/bacnet-stack/security/advisories/GHSA-hg85-pmm3-jfcf) | CVE-2026-104204 RESERVED -> PUBLISHED |
| [GHSA-hjwq-7qvv-qxj4](https://github.com/PrestaShop/PrestaShop/security/advisories/GHSA-hjwq-7qvv-qxj4) | CVE-2026-71519 RESERVED -> PUBLISHED |
| [GHSA-jgm4-2wg9-jwfg](https://github.com/bacnet-stack/bacnet-stack/security/advisories/GHSA-jgm4-2wg9-jwfg) | CVE-2026-102537 RESERVED -> PUBLISHED |
| [GHSA-jr7p-rm2x-739x](https://github.com/bacnet-stack/bacnet-stack/security/advisories/GHSA-jr7p-rm2x-739x) | CVE-2026-52790 RESERVED -> PUBLISHED |
| [GHSA-rf83-3rr5-v4mj](https://github.com/bacnet-stack/bacnet-stack/security/advisories/GHSA-rf83-3rr5-v4mj) | CVE-2026-52788 RESERVED -> PUBLISHED |
| [GHSA-xxp9-7hp4-rqwp](https://github.com/elixir-grpc/grpc/security/advisories/GHSA-xxp9-7hp4-rqwp) | CVE-2026-121808 RESERVED -> PUBLISHED |
| [GHSA-7x9q-vvph-rjcr](https://github.com/elixir-grpc/grpc/security/advisories/GHSA-7x9q-vvph-rjcr) | CVE-2026-123635 RESERVED -> PUBLISHED |
| [GHSA-9hq3-w3pc-8385](https://github.com/bacnet-stack/bacnet-stack/security/advisories/GHSA-9hq3-w3pc-8385) | CVE-2026-62972 RESERVED -> PUBLISHED |
| [GHSA-cf8g-hp9m-9fvv](https://github.com/bacnet-stack/bacnet-stack/security/advisories/GHSA-cf8g-hp9m-9fvv) | CVE-2026-62975 RESERVED -> PUBLISHED |
| [GHSA-hxqr-h35w-2898](https://github.com/gittuf/gittuf/security/advisories/GHSA-hxqr-h35w-2898) | CVE-2026-128034 RESERVED -> PUBLISHED |
| [GHSA-j66x-fr38-r7m5](https://github.com/bacnet-stack/bacnet-stack/security/advisories/GHSA-j66x-fr38-r7m5) | CVE-2026-58265 RESERVED -> PUBLISHED |

…and 51 more.

## Longest waiting, published in the last 90 days

| Advisory | Package | Severity | CVE | Days | Fixed in |
|---|---|---|---|---:|---|
| [GHSA-54cf-28h8-9p23](https://github.com/PyTables/PyTables/security/advisories/GHSA-54cf-28h8-9p23) | `pip:tables` | high | no CVE anywhere | 89 | `3.12.0` |
| [GHSA-6mmx-p77c-4hmr](https://github.com/PyTables/PyTables/security/advisories/GHSA-6mmx-p77c-4hmr) | `pip:tables` | high | no CVE anywhere | 89 | `3.12.0` |
| [GHSA-rf3w-rj48-jxcc](https://github.com/wekan/wekan/security/advisories/GHSA-rf3w-rj48-jxcc) | `actions:wekan/wekan` | high | no CVE anywhere | 89 | `10.98` |
| [GHSA-fjvm-966v-hmm2](https://github.com/LearningCircuit/local-deep-research/security/advisories/GHSA-fjvm-966v-hmm2) | `pip:local-deep-research` | critical | no CVE anywhere | 89 | `1.10.4` |
| [GHSA-wcrr-jh84-fchg](https://github.com/moquette-io/moquette/security/advisories/GHSA-wcrr-jh84-fchg) | `maven:io.moquette:moquette-broker` | medium | no CVE anywhere | 89 | `0.18.2, 0.19.0` |

607 advisories in limbo have waited more than a year.

## Coverage

Watchlist 67,513 repositories; 67,513 up to date on their schedule (daily for repos with an advisory in limbo, every 3 days for other repos with advisories, every 30 days and after each release for the rest); 7,820 checked in the last 24 hours; 37,780 reviewed advisories known. Every number is a floor: the tracker only sees repositories on its watchlist. Version ranges are as entered by maintainers and unreviewed.

_Advisory metadata from published GitHub repository security advisories and the GitHub Advisory Database (https://github.com/advisories, CC BY 4.0); CVE state from CVE Services; OSV.dev; NVD API (this product uses the NVD API but is not endorsed or certified by the NVD). Compiled by Limbowatch (https://limbo.watch), CC BY 4.0._
