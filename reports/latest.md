# Limbo Tracker daily report — 2026-11-17

Generated 2026-11-17 16:42:45 UTC; changes since 2026-11-16 16:31:38 UTC.

## Now

- **10,843 advisories in limbo** (+140 since the last report: 127 newly published, 30 older ones found for the first time, 17 left limbo): published by maintainers on GitHub, in ecosystems GitHub reviews, but not yet in GitHub's reviewed database or OSV.
  - 6,137 with no CVE anywhere · 612 citing a CVE that's still only reserved · 1,343 with a CVE from another CNA they don't cite
  - severity: 1,011 critical, 4,263 high, 4,550 medium, 1,019 low · median wait so far 53.6 days
- **15,592 more are likely permanent** (+130 since the last report: 121 newly published, 9 older ones found for the first time, 0 left limbo): in ecosystems GitHub doesn't review, so GitHub-based scanners will probably never see them.

## Since the last report

- **127 newly published** advisories entered limbo.
- 30 older advisories were found for the first time (30 in newly watched repos).
- **Left limbo** (likely permanent included): 17 reviewed by GitHub, 0 found to duplicate a reviewed advisory, 0 withdrawn or unpublished. GitHub reviewed 21 advisories in all in this period, from any repository.
- **CVE changes:** 119 (33 reserved CVEs published, 56 new CVEs from other CNAs).

## Newly published, in limbo

| Advisory | Package | Severity | CVE | Days | Fixed in |
|---|---|---|---|---:|---|
| [GHSA-mv65-jhg4-3qh6](https://github.com/DuendeSoftware/products/security/advisories/GHSA-mv65-jhg4-3qh6) | `nuget:Duende.IdentityServer` | critical | no CVE anywhere | 0 | `8.0.11, 7.4.15, 7.3.6, 7.2.6, 7.1.4, 7.0` |
| [GHSA-qqfr-626g-64rp](https://github.com/DuendeSoftware/products/security/advisories/GHSA-qqfr-626g-64rp) | `nuget:Duende.IdentityServer` | critical | no CVE anywhere | 0 | `8.0.11, 7.4.15, 7.3.6, 7.2.6, 7.1.4, 7.0` |
| [GHSA-4w3c-x4jp-hp8w](https://github.com/openwallet-foundation/acapy/security/advisories/GHSA-4w3c-x4jp-hp8w) | `pip:acapy-agent` | critical | no CVE anywhere | 0 | `1.3.6, 1.6.2, 1.7.0` |
| [GHSA-rjr3-9pq9-5wm4](https://github.com/grpc/grpc/security/advisories/GHSA-rjr3-9pq9-5wm4) | `nuget:Grpc.Core` | critical | no CVE anywhere | 0 | `–` |
| [GHSA-3x7g-4rhf-5r97](https://github.com/TYPO3/typo3/security/advisories/GHSA-3x7g-4rhf-5r97) | `composer:typo3/cms-install` | critical | CVE published, cited (`CVE-2026-119623`) | 0 | `14.3.12, 13.4.40, 12.4.52, 11.5.57, 10.4` |
| [GHSA-4j89-qjx2-3wcr](https://github.com/chamilo/chamilo-lms/security/advisories/GHSA-4j89-qjx2-3wcr) | `composer:chamilo/chamilo-lms` | critical | no CVE anywhere | 0 | `3.0.0` |
| [GHSA-x99m-vxr3-6j4w](https://github.com/simple-salesforce/simple-salesforce/security/advisories/GHSA-x99m-vxr3-6j4w) | `pip:simple-salesforce` | high | no CVE anywhere | 1 | `1.12.11` |
| [GHSA-h3wv-rf2m-mh72](https://github.com/Sustainsys/Saml2/security/advisories/GHSA-h3wv-rf2m-mh72) | `nuget:Sustainsys.Saml2` | high | no CVE anywhere | 1 | `1.0.4, 2.11.1` |
| [GHSA-66qr-wxvc-jhg9](https://github.com/Sustainsys/Saml2/security/advisories/GHSA-66qr-wxvc-jhg9) | `nuget:Sustainsys.Saml2` | high | no CVE anywhere | 1 | `1.0.4, 2.11.1` |
| [GHSA-6gxg-chg2-rm9v](https://github.com/DuendeSoftware/products/security/advisories/GHSA-6gxg-chg2-rm9v) | `nuget:Duende.BFF` | high | no CVE anywhere | 0 | `4.3.4, 4.2.2, 4.1.4, 4.0.5` |
| [GHSA-rhcf-m7hh-vpm7](https://github.com/DuendeSoftware/products/security/advisories/GHSA-rhcf-m7hh-vpm7) | `nuget:Duende.AspNetCore.Authentication.JwtBearer` | high | no CVE anywhere | 0 | `1.0.3` |
| [GHSA-wcc6-7mjx-g6j5](https://github.com/DuendeSoftware/products/security/advisories/GHSA-wcc6-7mjx-g6j5) | `nuget:Duende.IdentityServer` | high | no CVE anywhere | 0 | `8.0.11` |
| [GHSA-84rm-mhfq-f476](https://github.com/DuendeSoftware/foss/security/advisories/GHSA-84rm-mhfq-f476) | `nuget:Duende.AspNetCore.Authentication.OAuth2Introspection` | high | no CVE anywhere | 0 | `–` |
| [GHSA-xf3w-qp3m-fp62](https://github.com/deepjavalibrary/djl/security/advisories/GHSA-xf3w-qp3m-fp62) | `maven:ai.djl:api` | high | CVE published, cited (`CVE-2026-129266`) | 0 | `0.40.0` |
| [GHSA-p27c-f9fr-4jmw](https://github.com/gogs/gogs/security/advisories/GHSA-p27c-f9fr-4jmw) | `go:gogs.io/gogs` | high | no CVE anywhere | 0 | `0.15.0` |
| [GHSA-2r24-fqfc-2222](https://github.com/solspace/craft-freeform/security/advisories/GHSA-2r24-fqfc-2222) | `composer:solspace/craft-freeform` | high | no CVE anywhere | 0 | `5.18.4` |
| [GHSA-m9pr-74q6-w362](https://github.com/fallow-rs/fallow/security/advisories/GHSA-m9pr-74q6-w362) | `npm:fallow, rust:fallow-cli` | high | no CVE anywhere | 0 | `3.43.2` |
| [GHSA-w62c-p8c7-w6f7](https://github.com/onikienko/7zip-min/security/advisories/GHSA-w62c-p8c7-w6f7) | `npm:7zip-min` | high | no CVE anywhere | 0 | `3.0.2` |
| [GHSA-jv3v-q542-9c26](https://github.com/jeremyevans/rodauth/security/advisories/GHSA-jv3v-q542-9c26) | `rubygems:rodauth` | high | no CVE anywhere | 0 | `–` |
| [GHSA-943r-7vgw-m4m9](https://github.com/amphp/http-server/security/advisories/GHSA-943r-7vgw-m4m9) | `composer:amphp/http-server` | high | no CVE anywhere | 0 | `3.4.9` |
| [GHSA-5fv7-wh8q-cmfj](https://github.com/modoboa/modoboa/security/advisories/GHSA-5fv7-wh8q-cmfj) | `pip:modoboa` | high | no CVE anywhere | 0 | `2.13.0` |
| [GHSA-7457-w8c8-jh29](https://github.com/umbraco/Umbraco.Workflow.Issues/security/advisories/GHSA-7457-w8c8-jh29) | `nuget:Umbraco.Workflow` | high | no CVE anywhere | 0 | `13.5.5, 17.6.0, 18.3.0` |
| [GHSA-vw5g-jmgg-hw78](https://github.com/umbraco/Umbraco.Workflow.Issues/security/advisories/GHSA-vw5g-jmgg-hw78) | `nuget:Umbraco.Workflow` | high | no CVE anywhere | 0 | `13.5.5, 17.6.0, 18.3.0` |
| [GHSA-gq5w-hprc-q59x](https://github.com/umbraco/Umbraco.Engage.Issues/security/advisories/GHSA-gq5w-hprc-q59x) | `nuget:Umbraco.Engage` | high | no CVE anywhere | 0 | `13.8.3, EoL, 17.6.0, 18.3.0` |
| [GHSA-j8gf-c4rj-6jv5](https://github.com/ZcashFoundation/zebra/security/advisories/GHSA-j8gf-c4rj-6jv5) | `rust:zebra-state, rust:zebrad` | high | no CVE anywhere | 0 | `7.1.0, 17.0.0` |

…and 102 more: [the tracker](https://limbo.watch/tracker/) lists them all, newest first.

## CVE changes

| Advisory | Change |
|---|---|
| [GHSA-gfv3-m769-5xm3](https://github.com/Arize-ai/phoenix/security/advisories/GHSA-gfv3-m769-5xm3) | CVE-2026-53998 RESERVED -> PUBLISHED |
| [GHSA-2j49-g9h3-75hp](https://github.com/OpenCTI-Platform/opencti/security/advisories/GHSA-2j49-g9h3-75hp) | CVE-2026-63477 RESERVED -> PUBLISHED |
| [GHSA-3mgh-93r5-r7jf](https://github.com/codewhale-hq/Codewhale/security/advisories/GHSA-3mgh-93r5-r7jf) | CVE-2026-83816 RESERVED -> PUBLISHED |
| [GHSA-3w48-r8r5-mf8c](https://github.com/glpi-project/glpi/security/advisories/GHSA-3w48-r8r5-mf8c) | CVE-2026-57150 RESERVED -> PUBLISHED |
| [GHSA-45cp-v5ph-2jhm](https://github.com/requarks/wiki/security/advisories/GHSA-45cp-v5ph-2jhm) | CVE-2026-120698 RESERVED -> PUBLISHED |
| [GHSA-5v87-m222-qr94](https://github.com/HKUDS/nanobot/security/advisories/GHSA-5v87-m222-qr94) | CVE-2026-121864 RESERVED -> PUBLISHED |
| [GHSA-8hp3-xxrg-v9c8](https://github.com/codewhale-hq/Codewhale/security/advisories/GHSA-8hp3-xxrg-v9c8) | CVE-2026-83817 RESERVED -> PUBLISHED |
| [GHSA-8jgr-3543-vfvv](https://github.com/OpenCTI-Platform/opencti/security/advisories/GHSA-8jgr-3543-vfvv) | CVE-2026-121708 RESERVED -> PUBLISHED |
| [GHSA-98c8-px3r-68c6](https://github.com/requarks/wiki/security/advisories/GHSA-98c8-px3r-68c6) | CVE-2026-120697 RESERVED -> PUBLISHED |
| [GHSA-hg87-wf6q-3m38](https://github.com/HKUDS/nanobot/security/advisories/GHSA-hg87-wf6q-3m38) | CVE-2026-121865 RESERVED -> PUBLISHED |
| [GHSA-mhhg-77qx-qf26](https://github.com/glpi-project/glpi/security/advisories/GHSA-mhhg-77qx-qf26) | CVE-2026-57151 RESERVED -> PUBLISHED |
| [GHSA-mwfc-578p-fccc](https://github.com/OpenCTI-Platform/opencti/security/advisories/GHSA-mwfc-578p-fccc) | CVE-2026-76823 RESERVED -> PUBLISHED |
| [GHSA-qx49-fqc8-xw99](https://github.com/modelcontextprotocol/python-sdk/security/advisories/GHSA-qx49-fqc8-xw99) | CVE-2026-115563 RESERVED -> PUBLISHED |
| [GHSA-vp2w-7xxj-jvxr](https://github.com/git/git/security/advisories/GHSA-vp2w-7xxj-jvxr) | CVE-2026-111760 RESERVED -> PUBLISHED |
| [GHSA-232j-24c2-m823](https://github.com/silverstripe/silverstripe-framework/security/advisories/GHSA-232j-24c2-m823) | CVE-2026-91114 RESERVED -> PUBLISHED |
| [GHSA-398q-73w6-v5gj](https://github.com/wpengine/faustjs/security/advisories/GHSA-398q-73w6-v5gj) | CVE-2026-69221 RESERVED -> PUBLISHED |
| [GHSA-3h55-hq8v-989m](https://github.com/OpenCTI-Platform/opencti/security/advisories/GHSA-3h55-hq8v-989m) | CVE-2026-104253 RESERVED -> PUBLISHED |
| [GHSA-5gxq-gqvj-wccm](https://github.com/OpenCTI-Platform/opencti/security/advisories/GHSA-5gxq-gqvj-wccm) | CVE-2026-104258 RESERVED -> PUBLISHED |
| [GHSA-74jw-q47r-q5pv](https://github.com/OpenCTI-Platform/opencti/security/advisories/GHSA-74jw-q47r-q5pv) | CVE-2026-104840 RESERVED -> PUBLISHED |
| [GHSA-7qx7-33qx-rqx2](https://github.com/vercel/next.js/security/advisories/GHSA-7qx7-33qx-rqx2) | CVE-2026-119347 RESERVED -> PUBLISHED |
| [GHSA-f3mh-rxg3-f5g2](https://github.com/vercel/next.js/security/advisories/GHSA-f3mh-rxg3-f5g2) | CVE-2026-119346 RESERVED -> PUBLISHED |
| [GHSA-fh34-63w7-r782](https://github.com/OpenCTI-Platform/opencti/security/advisories/GHSA-fh34-63w7-r782) | CVE-2026-114505 RESERVED -> PUBLISHED |
| [GHSA-m5w3-5gq7-2crg](https://github.com/silverstripe/silverstripe-framework/security/advisories/GHSA-m5w3-5gq7-2crg) | CVE-2026-91110 RESERVED -> PUBLISHED |
| [GHSA-mfr8-8qww-v76h](https://github.com/vercel/next.js/security/advisories/GHSA-mfr8-8qww-v76h) | CVE-2026-119790 RESERVED -> PUBLISHED |
| [GHSA-pc58-hwjq-p385](https://github.com/vercel/next.js/security/advisories/GHSA-pc58-hwjq-p385) | CVE-2026-119348 RESERVED -> PUBLISHED |

…and 94 more.

## Longest waiting, published in the last 90 days

| Advisory | Package | Severity | CVE | Days | Fixed in |
|---|---|---|---|---:|---|
| [GHSA-9w98-5239-39c2](https://github.com/mosparo/mosparo/security/advisories/GHSA-9w98-5239-39c2) | `composer:mosparo/mosparo` | medium | no CVE anywhere | 89 | `1.5.5` |
| [GHSA-947w-pxjj-c7m9](https://github.com/luben/zstd-jni/security/advisories/GHSA-947w-pxjj-c7m9) | `maven:zstd-jni` | high | CVE published, cited (`CVE-2026-87825`) | 89 | `1.5.7-14` |
| [GHSA-2jw3-mg7f-vw4q](https://github.com/luben/zstd-jni/security/advisories/GHSA-2jw3-mg7f-vw4q) | `maven:zstd-jni` | high | CVE published, cited (`CVE-2026-87877`) | 89 | `1.5.7-14` |
| [GHSA-xcfm-m684-6vfm](https://github.com/flyfish-dev/file-viewer/security/advisories/GHSA-xcfm-m684-6vfm) | `npm:@file-viewer/renderer-text` | high | no CVE anywhere | 89 | `2.2.9` |
| [GHSA-w8pw-h853-frw2](https://github.com/jdx/mise/security/advisories/GHSA-w8pw-h853-frw2) | `rust:mise` | medium | no CVE anywhere | 89 | `2026.8.9` |

608 advisories in limbo have waited more than a year.

## Coverage

Watchlist 67,732 repositories; 67,732 up to date on their schedule (daily for repos with an advisory in limbo, every 3 days for other repos with advisories, every 30 days and after each release for the rest); 5,834 checked in the last 24 hours; 37,823 reviewed advisories known. Every number is a floor: the tracker only sees repositories on its watchlist. Version ranges are as entered by maintainers and unreviewed.

_Advisory metadata from published GitHub repository security advisories and the GitHub Advisory Database (https://github.com/advisories, CC BY 4.0); CVE state from CVE Services; OSV.dev; NVD API (this product uses the NVD API but is not endorsed or certified by the NVD). Compiled by Limbowatch (https://limbo.watch), CC BY 4.0._
