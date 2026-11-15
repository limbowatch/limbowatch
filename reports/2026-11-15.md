# Limbo Tracker daily report — 2026-11-15

Generated 2026-11-15 14:34:50 UTC; changes since 2026-11-14 14:11:44 UTC.

## Now

- **10,550 advisories in limbo** (+87 since the last report: 70 newly published, 17 older ones found for the first time, 0 left limbo): published by maintainers on GitHub, in ecosystems GitHub reviews, but not yet in GitHub's reviewed database or OSV.
  - 5,920 with no CVE anywhere · 619 citing a CVE that's still only reserved · 1,312 with a CVE from another CNA they don't cite
  - severity: 987 critical, 4,147 high, 4,432 medium, 984 low · median wait so far 53.0 days
- **15,339 more are likely permanent** (+20 since the last report: 20 newly published, 0 older ones found for the first time, 0 left limbo): in ecosystems GitHub doesn't review, so GitHub-based scanners will probably never see them.

## Since the last report

- **70 newly published** advisories entered limbo.
- 17 older advisories were found for the first time (13 in newly watched repos).
- **Left limbo** (likely permanent included): 0 reviewed by GitHub, 0 found to duplicate a reviewed advisory, 0 withdrawn or unpublished. **GitHub reviewed no advisories at all in this period.**
- **CVE changes:** 22 (1 reserved CVEs published, 1 new CVEs from other CNAs).

## Newly published, in limbo

| Advisory | Package | Severity | CVE | Days | Fixed in |
|---|---|---|---|---:|---|
| [GHSA-2v77-pvhx-25c3](https://github.com/AcademySoftwareFoundation/openexr/security/advisories/GHSA-2v77-pvhx-25c3) | `pip:openexr` | critical | no CVE anywhere | 0 | `3.3.16, 3.4.18, 3.5.4` |
| [GHSA-mf3p-hrx2-rmf7](https://github.com/moquette-io/moquette/security/advisories/GHSA-mf3p-hrx2-rmf7) | `maven:io.moquette:moquette-broker` | critical | no CVE anywhere | 0 | `0.18.2, 0.19.0` |
| [GHSA-x8q7-6c7m-52gw](https://github.com/nltk/nltk/security/advisories/GHSA-x8q7-6c7m-52gw) | `pip:nltk` | critical | CVE reserved (RBP) (`CVE-2026-128138`) | 0 | `3.10.4` |
| [GHSA-9gg7-283r-5gm9](https://github.com/TryGhost/express-hbs/security/advisories/GHSA-9gg7-283r-5gm9) | `npm:express-hbs` | high | no CVE anywhere | 1 | `2.5.1, 4.0.2` |
| [GHSA-rhr2-p2j3-8jjj](https://github.com/laravolt/laravolt/security/advisories/GHSA-rhr2-p2j3-8jjj) | `composer:laravolt/laravolt` | high | no CVE anywhere | 1 | `8.3.3` |
| [GHSA-vc3f-72gv-5pgp](https://github.com/laravolt/laravolt/security/advisories/GHSA-vc3f-72gv-5pgp) | `composer:laravolt/laravolt` | high | no CVE anywhere | 1 | `8.3.3` |
| [GHSA-pg34-5xcr-7jrp](https://github.com/laravolt/laravolt/security/advisories/GHSA-pg34-5xcr-7jrp) | `composer:laravolt/laravolt` | high | no CVE anywhere | 1 | `8.3.3` |
| [GHSA-c62c-wjcx-gjxx](https://github.com/luben/zstd-jni/security/advisories/GHSA-c62c-wjcx-gjxx) | `maven:com.github.luben:zstd-jni` | high | no CVE anywhere | 1 | `1.5.7-27` |
| [GHSA-779h-x4xj-2f4f](https://github.com/luben/zstd-jni/security/advisories/GHSA-779h-x4xj-2f4f) | `maven:com.github.luben:zstd-jni` | high | no CVE anywhere | 1 | `–` |
| [GHSA-f9fw-76m6-wc75](https://github.com/authorizerdev/authorizer/security/advisories/GHSA-f9fw-76m6-wc75) | `go:github.com/authorizerdev/authorizer` | high | no CVE anywhere | 0 | `2.4.5` |
| [GHSA-93q4-j2hq-5qgg](https://github.com/authorizerdev/authorizer/security/advisories/GHSA-93q4-j2hq-5qgg) | `go:github.com/authorizerdev/authorizer` | high | no CVE anywhere | 0 | `2.4.5` |
| [GHSA-h5xf-qc2v-94w6](https://github.com/zip-rs/zip2/security/advisories/GHSA-h5xf-qc2v-94w6) | `rust:zip` | high | no CVE anywhere | 0 | `9.2.0` |
| [GHSA-mpc8-q7jp-wjrf](https://github.com/zip-rs/zip2/security/advisories/GHSA-mpc8-q7jp-wjrf) | `rust:zip` | high | no CVE anywhere | 0 | `9.2.0` |
| [GHSA-98qm-p6jx-5wj2](https://github.com/facelessuser/soupsieve/security/advisories/GHSA-98qm-p6jx-5wj2) | `pip:soupsieve` | high | no CVE anywhere | 0 | `4.1.1` |
| [GHSA-fpjv-w4vg-qmfm](https://github.com/astropy/astropy/security/advisories/GHSA-fpjv-w4vg-qmfm) | `pip:astropy` | high | no CVE anywhere | 0 | `7.3.2, 8.0.2, 8.1.0` |
| [GHSA-32w6-43vp-5fmg](https://github.com/inducer/relate/security/advisories/GHSA-32w6-43vp-5fmg) | `pip:relate-courseware` | high | no CVE anywhere | 0 | `d6bead4df2085f4900cbf774a0726509b19616c5` |
| [GHSA-w8p9-5v6q-h9ch](https://github.com/doobidoo/mcp-memory-service/security/advisories/GHSA-w8p9-5v6q-h9ch) | `pip:mcp-memory-service` | high | no CVE anywhere | 0 | `12.10.0` |
| [GHSA-5wpc-45jc-6ccc](https://github.com/petergoldstein/dalli/security/advisories/GHSA-5wpc-45jc-6ccc) | `rubygems:dalli` | high | no CVE anywhere | 0 | `3.2.16, 4.3.11, 5.0.15, 5.1.9, 5.2.9, 5.` |
| [GHSA-67rw-6x6r-23jr](https://github.com/getarcaneapp/arcane/security/advisories/GHSA-67rw-6x6r-23jr) | `go:github.com/getarcaneapp/arcane/backend/v2` | high | no CVE anywhere | 0 | `v3.0.` |
| [GHSA-2pfr-pfcp-pv44](https://github.com/MobSF/Mobile-Security-Framework-MobSF/security/advisories/GHSA-2pfr-pfcp-pv44) | `pip:mobsf` | high | no CVE anywhere | 0 | `4.6.6` |
| [GHSA-q882-9g6p-v5f2](https://github.com/MobSF/Mobile-Security-Framework-MobSF/security/advisories/GHSA-q882-9g6p-v5f2) | `pip:mobsf` | high | no CVE anywhere | 0 | `4.6.6` |
| [GHSA-6p6x-gx77-3gv3](https://github.com/MobSF/Mobile-Security-Framework-MobSF/security/advisories/GHSA-6p6x-gx77-3gv3) | `pip:mobsf` | high | no CVE anywhere | 0 | `4.6.6` |
| [GHSA-mjcw-gfh6-3cxm](https://github.com/i18next/i18next-http-middleware/security/advisories/GHSA-mjcw-gfh6-3cxm) | `npm:i18next-http-middleware` | high | no CVE anywhere | 0 | `3.10.1` |
| [GHSA-xxvx-vcj6-rjq5](https://github.com/i18next/i18next-http-middleware/security/advisories/GHSA-xxvx-vcj6-rjq5) | `npm:i18next-http-middleware` | high | no CVE anywhere | 0 | `3.10.2` |
| [GHSA-3jj8-q2mj-cg7q](https://github.com/moquette-io/moquette/security/advisories/GHSA-3jj8-q2mj-cg7q) | `maven:io.moquette:moquette-broker` | high | no CVE anywhere | 0 | `–` |

…and 45 more: [the tracker](https://limbo.watch/tracker/) lists them all, newest first.

## CVE changes

| Advisory | Change |
|---|---|
| [GHSA-93j3-gf96-8376](https://github.com/wp-graphql/wp-graphql/security/advisories/GHSA-93j3-gf96-8376) | CVE-2026-123707 RESERVED -> PUBLISHED |
| [GHSA-73v3-wf97-vpgj](https://github.com/msgpack/msgpack-ruby/security/advisories/GHSA-73v3-wf97-vpgj) | cites CVE-2026-126366 (was none) |
| [GHSA-89p3-fcch-88ph](https://github.com/nltk/nltk/security/advisories/GHSA-89p3-fcch-88ph) | cites CVE-2026-126299 (was none) |
| [GHSA-qph8-7859-gq2f](https://github.com/actix/actix-web/security/advisories/GHSA-qph8-7859-gq2f) | cites CVE-2026-128242 (was none) |
| [GHSA-r53h-rw34-8h97](https://github.com/nltk/nltk/security/advisories/GHSA-r53h-rw34-8h97) | cites CVE-2026-126298 (was none) |
| [GHSA-v8f3-6phw-6mh9](https://github.com/nltk/nltk/security/advisories/GHSA-v8f3-6phw-6mh9) | cites CVE-2026-126297 (was none) |
| [GHSA-xcvg-w56q-r89m](https://github.com/python-pillow/Pillow/security/advisories/GHSA-xcvg-w56q-r89m) | cites CVE-2026-128067 (was none) |
| [GHSA-345x-3rq2-jfrm](https://github.com/flavorjones/loofah/security/advisories/GHSA-345x-3rq2-jfrm) | cites CVE-2026-126208 (was none) |
| [GHSA-59f9-gqg8-mqpj](https://github.com/nltk/nltk/security/advisories/GHSA-59f9-gqg8-mqpj) | cites CVE-2026-126296 (was none) |
| [GHSA-ffr9-mgrr-wcvr](https://github.com/nltk/nltk/security/advisories/GHSA-ffr9-mgrr-wcvr) | cites CVE-2026-126300 (was none) |
| [GHSA-fg9w-wfp5-j933](https://github.com/nltk/nltk/security/advisories/GHSA-fg9w-wfp5-j933) | cites CVE-2026-126295 (was none) |
| [GHSA-gg5j-6742-v827](https://github.com/grpc/grpc-node/security/advisories/GHSA-gg5j-6742-v827) | cites CVE-2026-128065 (was none) |
| [GHSA-gpwc-27cw-rh9r](https://github.com/nltk/nltk/security/advisories/GHSA-gpwc-27cw-rh9r) | cites CVE-2026-126301 (was none) |
| [GHSA-h6v6-rg66-fqj4](https://github.com/flavorjones/loofah/security/advisories/GHSA-h6v6-rg66-fqj4) | cites CVE-2026-126203 (was none) |
| [GHSA-m3x9-938q-5767](https://github.com/flavorjones/loofah/security/advisories/GHSA-m3x9-938q-5767) | cites CVE-2026-126207 (was none) |
| [GHSA-mf2j-8f84-cc9q](https://github.com/flavorjones/loofah/security/advisories/GHSA-mf2j-8f84-cc9q) | cites CVE-2026-126205 (was none) |
| [GHSA-r7hq-q2xm-6c5m](https://github.com/grpc/grpc-node/security/advisories/GHSA-r7hq-q2xm-6c5m) | cites CVE-2026-126367 (was none) |
| [GHSA-wqgw-9xfh-qf2g](https://github.com/python-pillow/Pillow/security/advisories/GHSA-wqgw-9xfh-qf2g) | cites CVE-2026-128066 (was none) |
| [GHSA-xmfg-f9cm-w86q](https://github.com/nltk/nltk/security/advisories/GHSA-xmfg-f9cm-w86q) | cites CVE-2026-126302 (was none) |
| [GHSA-jcff-cj73-4w4f](https://github.com/flavorjones/loofah/security/advisories/GHSA-jcff-cj73-4w4f) | cites CVE-2026-126206 (was none) |
| [GHSA-p9wj-w8xq-vjx6](https://github.com/flavorjones/loofah/security/advisories/GHSA-p9wj-w8xq-vjx6) | cites CVE-2026-126209 (was none) |
| [GHSA-fr36-wcx2-7gfq](https://github.com/yuzutech/kroki/security/advisories/GHSA-fr36-wcx2-7gfq) | new CVE from another CNA: CVE-2026-129447 |

## Longest waiting, published in the last 90 days

| Advisory | Package | Severity | CVE | Days | Fixed in |
|---|---|---|---|---:|---|
| [GHSA-rmxg-5p3r-j6hh](https://github.com/rmosolgo/graphql-ruby/security/advisories/GHSA-rmxg-5p3r-j6hh) | `rubygems:graphql` | high | no CVE anywhere | 89 | `2.6.9` |
| [GHSA-9gmj-q25w-vq6x](https://github.com/kyndryl-open-source/hashi-vault-js/security/advisories/GHSA-9gmj-q25w-vq6x) | `npm:hashi-vault-js` | critical | no CVE anywhere | 89 | `0.5.3` |
| [GHSA-x69f-q4wj-vx72](https://github.com/nautobot/nautobot/security/advisories/GHSA-x69f-q4wj-vx72) | `pip:nautobot` | medium | no CVE anywhere | 89 | `2.4.40, 3.2.3` |
| [GHSA-qfwj-vfxf-92j2](https://github.com/quinn-rs/quinn/security/advisories/GHSA-qfwj-vfxf-92j2) | `rust:quinn-proto` | high | no CVE anywhere | 89 | `0.11.17` |
| [GHSA-2hv7-gw8g-gpq5](https://github.com/quinn-rs/quinn/security/advisories/GHSA-2hv7-gw8g-gpq5) | `rust:quinn-proto` | high | no CVE anywhere | 89 | `0.11.17` |

607 advisories in limbo have waited more than a year.

## Coverage

Watchlist 67,591 repositories; 67,591 up to date on their schedule (daily for repos with an advisory in limbo, every 3 days for other repos with advisories, every 30 days and after each release for the rest); 4,949 checked in the last 24 hours; 37,780 reviewed advisories known. Every number is a floor: the tracker only sees repositories on its watchlist. Version ranges are as entered by maintainers and unreviewed.

_Advisory metadata from published GitHub repository security advisories and the GitHub Advisory Database (https://github.com/advisories, CC BY 4.0); CVE state from CVE Services; OSV.dev; NVD API (this product uses the NVD API but is not endorsed or certified by the NVD). Compiled by Limbowatch (https://limbo.watch), CC BY 4.0._
