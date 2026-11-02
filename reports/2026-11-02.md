# Limbo Tracker daily report — 2026-11-02

Generated 2026-11-02 16:20:56 UTC; changes since 2026-11-01 13:43:24 UTC.

## Now

- **8,232 advisories in limbo** (+65 since the last report: 65 newly published, 0 older ones found for the first time, 0 left limbo): published by maintainers on GitHub, in ecosystems GitHub reviews, but not yet in GitHub's reviewed database or OSV.
  - 4,252 with no CVE anywhere · 574 citing a CVE that's still only reserved · 1,035 with a CVE from another CNA they don't cite
  - severity: 870 critical, 3,288 high, 3,360 medium, 714 low · median wait so far 56.4 days
- **13,989 more are likely permanent** (+77 since the last report: 77 newly published, 0 older ones found for the first time, 0 left limbo): in ecosystems GitHub doesn't review, so GitHub-based scanners will probably never see them.

## Since the last report

- **65 newly published** advisories entered limbo.
- 0 older advisories were found for the first time.
- **Left limbo** (likely permanent included): 0 reviewed by GitHub, 0 found to duplicate a reviewed advisory, 0 withdrawn or unpublished.
- **CVE changes:** 15 (2 reserved CVEs published, 11 new CVEs from other CNAs).

## Newly published, in limbo

| Advisory | Package | Severity | CVE | Days | Fixed in |
|---|---|---|---|---:|---|
| [GHSA-r2pq-mqwg-m575](https://github.com/cuga-project/cuga-agent/security/advisories/GHSA-r2pq-mqwg-m575) | `pip:cuga` | critical | no CVE anywhere | 1 | 0.4.4 |
| [GHSA-c5x3-wvxj-7cgr](https://github.com/laradashboard/laradashboard/security/advisories/GHSA-c5x3-wvxj-7cgr) | `actions:laradashboard/laradashboard` | critical | no CVE anywhere | 0 | – |
| [GHSA-h3vp-4jfr-v364](https://github.com/fastify/fastify-http-proxy/security/advisories/GHSA-h3vp-4jfr-v364) | `npm:@fastify/http-proxy` | critical | CVE published, cited (CVE-2026-120213) | 0 | 11.6.6 |
| [GHSA-v2h8-j899-r676](https://github.com/wasmerio/wasmer/security/advisories/GHSA-v2h8-j899-r676) | `rust:wasmer-compiler-singlepass` | critical | no CVE anywhere | 0 | – |
| [GHSA-4cj6-vfwp-8pq7](https://github.com/cuga-project/cuga-agent/security/advisories/GHSA-4cj6-vfwp-8pq7) | `pip:cuga` | high | no CVE anywhere | 1 | 0.4.4 |
| [GHSA-25rf-99hr-7pmr](https://github.com/codeigniter4/CodeIgniter4/security/advisories/GHSA-25rf-99hr-7pmr) | `composer:codeigniter4/framework` | high | no CVE anywhere | 1 | 4.7.6 |
| [GHSA-9gg9-jh9p-fw37](https://github.com/laradashboard/laradashboard/security/advisories/GHSA-9gg9-jh9p-fw37) | `composer:laradashboard/laradashboard` | high | CVE published by another CNA, not cited (CVE-2026-120488) | 0 | not yet |
| [GHSA-c2hf-g6w4-jrj6](https://github.com/conventional-changelog/conventional-changelog/security/advisories/GHSA-c2hf-g6w4-jrj6) | `npm:conventional-commits-parser` | high | no CVE anywhere | 0 | 7.1.4 |
| [GHSA-f3fg-34g9-v7jx](https://github.com/authlib/authlib/security/advisories/GHSA-f3fg-34g9-v7jx) | `pip:authlib` | high | no CVE anywhere | 0 | 1.9.2 |
| [GHSA-ggh8-3chg-48w7](https://github.com/adminneo-org/adminneo/security/advisories/GHSA-ggh8-3chg-48w7) | `composer:adminneo-org/adminneo` | high | no CVE anywhere | 0 | 5.9.0 |
| [GHSA-66c7-5wxm-rfgj](https://github.com/adminneo-org/adminneo/security/advisories/GHSA-66c7-5wxm-rfgj) | `composer:adminneo-org/adminneo` | high | no CVE anywhere | 0 | 5.9.0 |
| [GHSA-rgjx-wcgv-pw7g](https://github.com/adminneo-org/adminneo/security/advisories/GHSA-rgjx-wcgv-pw7g) | `composer:adminneo-org/adminneo` | high | no CVE anywhere | 0 | 5.9.0 |
| [GHSA-8cwc-qmwg-m56v](https://github.com/emiago/sipgo/security/advisories/GHSA-8cwc-qmwg-m56v) | `go:github.com/emiago/sipgo` | high | no CVE anywhere | 0 | v1.7.1 |
| [GHSA-vq8m-9xp3-76fg](https://github.com/WWBN/AVideo/security/advisories/GHSA-vq8m-9xp3-76fg) | `composer:wwbn/avideo` | high | no CVE anywhere | 0 | – |
| [GHSA-p5c5-p2gx-h6q6](https://github.com/SpectoLabs/hoverfly/security/advisories/GHSA-p5c5-p2gx-h6q6) | `go:github.com/SpectoLabs/hoverfly` | high | no CVE anywhere | 0 | 1.12.17 |
| [GHSA-jfvw-g6vg-jqvf](https://github.com/JanssenProject/jans/security/advisories/GHSA-jfvw-g6vg-jqvf) | `maven:io.jans:jans-config-api-server` | high | no CVE anywhere | 0 | 0.0.0-nightly, 2.6.0 |
| [GHSA-c6m5-4xrm-4x39](https://github.com/Finsys/dockhand/security/advisories/GHSA-c6m5-4xrm-4x39) | `npm:dockhand` | high | no CVE anywhere | 0 | 1.0.55 |
| [GHSA-jg6j-7fgr-6jm7](https://github.com/Finsys/dockhand/security/advisories/GHSA-jg6j-7fgr-6jm7) | `npm:dockhand` | high | no CVE anywhere | 0 | 1.0.55 |
| [GHSA-v9qw-r94g-95qv](https://github.com/Bubka/2FAuth/security/advisories/GHSA-v9qw-r94g-95qv) | `composer:bubka/2fauth` | high | no CVE anywhere | 0 | 9.0.1 |
| [GHSA-qwr6-x466-fv4r](https://github.com/Bubka/2FAuth/security/advisories/GHSA-qwr6-x466-fv4r) | `composer:bubka/2fauth` | high | no CVE anywhere | 0 | 9.0.1 |
| [GHSA-vp2r-3vgv-32g9](https://github.com/fastify/fastify-reply-from/security/advisories/GHSA-vp2r-3vgv-32g9) | `npm:@fastify/reply-from` | high | CVE published, cited (CVE-2026-117518) | 0 | 12.8.1 |
| [GHSA-xv5x-242w-7hf7](https://github.com/traefik/traefik/security/advisories/GHSA-xv5x-242w-7hf7) | `go:github.com/traefik/traefik/v2, go:github.com/traefik/t…` | high | no CVE anywhere | 0 | v2.11.61, v3.7.17 |
| [GHSA-7chr-fvfr-cp98](https://github.com/modoboa/modoboa/security/advisories/GHSA-7chr-fvfr-cp98) | `pip:modoboa` | high | no CVE anywhere | 0 | 2.11.1 |
| [GHSA-w3p9-g4p2-h3rr](https://github.com/phpseclib/phpseclib/security/advisories/GHSA-w3p9-g4p2-h3rr) | `composer:phpseclib/phpseclib` | high | no CVE anywhere | 0 | 4.0.3, 3.0.58, 2.0.56, 1.0.31 |
| [GHSA-gc3f-vmqj-j7hw](https://github.com/daptin/daptin/security/advisories/GHSA-gc3f-vmqj-j7hw) | `go:github.com/daptin/daptin` | high | no CVE anywhere | 0 | 0.13.45 |

…and 40 more (see the feed).

## CVE changes

| Advisory | Change |
|---|---|
| [GHSA-2g9j-v25c-4j97](https://github.com/lobehub/lobehub/security/advisories/GHSA-2g9j-v25c-4j97) | new CVE from another CNA: CVE-2026-120315 |
| [GHSA-2rcp-jc67-vq74](https://github.com/parse-community/parse-server/security/advisories/GHSA-2rcp-jc67-vq74) | new CVE from another CNA: CVE-2026-120310 |
| [GHSA-5mm5-4mh4-6gm6](https://github.com/Jovancoding/Network-AI/security/advisories/GHSA-5mm5-4mh4-6gm6) | new CVE from another CNA: CVE-2026-120313 |
| [GHSA-9xx4-xjpj-xqcf](https://github.com/http4k/http4k/security/advisories/GHSA-9xx4-xjpj-xqcf) | new CVE from another CNA: CVE-2026-120317 |
| [GHSA-f9gf-wh3x-jx3v](https://github.com/rancher/rancher/security/advisories/GHSA-f9gf-wh3x-jx3v) | CVE-2026-88809 RESERVED -> PUBLISHED |
| [GHSA-ghwv-vrp2-2975](https://github.com/ultravioletrs/cocos/security/advisories/GHSA-ghwv-vrp2-2975) | cites CVE-2026-119345 (was none) |
| [GHSA-h6ff-rw9x-5mq2](https://github.com/outline/outline/security/advisories/GHSA-h6ff-rw9x-5mq2) | new CVE from another CNA: CVE-2026-120489 |
| [GHSA-mfxv-jg44-xj48](https://github.com/Jovancoding/Network-AI/security/advisories/GHSA-mfxv-jg44-xj48) | new CVE from another CNA: CVE-2026-120312 |
| [GHSA-qfmw-gw96-ffcr](https://github.com/rancher/fleet/security/advisories/GHSA-qfmw-gw96-ffcr) | CVE-2026-94290 RESERVED -> PUBLISHED |
| [GHSA-qvf5-9prv-7r9c](https://github.com/Jovancoding/Network-AI/security/advisories/GHSA-qvf5-9prv-7r9c) | new CVE from another CNA: CVE-2026-120314 |
| [GHSA-rq53-m97j-f2pg](https://github.com/outline/outline/security/advisories/GHSA-rq53-m97j-f2pg) | new CVE from another CNA: CVE-2026-120449 |
| [GHSA-v5m8-5wxc-vjgp](https://github.com/ultravioletrs/cocos/security/advisories/GHSA-v5m8-5wxc-vjgp) | cites CVE-2026-119344 (was none) |
| [GHSA-v64j-mc7x-c7x7](https://github.com/Jovancoding/Network-AI/security/advisories/GHSA-v64j-mc7x-c7x7) | new CVE from another CNA: CVE-2026-120311 |
| [GHSA-w7gw-66vg-99gq](https://github.com/nuxt/nuxt/security/advisories/GHSA-w7gw-66vg-99gq) | new CVE from another CNA: CVE-2026-120309 |
| [GHSA-wq4x-r858-gmmj](https://github.com/http4k/http4k/security/advisories/GHSA-wq4x-r858-gmmj) | new CVE from another CNA: CVE-2026-120316 |

## Longest waiting, published in the last 90 days

| Advisory | Package | Severity | CVE | Days | Fixed in |
|---|---|---|---|---:|---|
| [GHSA-f8pr-32pp-mp7h](https://github.com/thorsten/phpMyFAQ/security/advisories/GHSA-f8pr-32pp-mp7h) | `composer:thorsten/phpmyfaq` | medium | CVE published by another CNA, not cited (CVE-2026-76206) | 89 | 4.1.7 |
| [GHSA-hvj7-4fmg-53cr](https://github.com/thorsten/phpMyFAQ/security/advisories/GHSA-hvj7-4fmg-53cr) | `thorsten/phpmyfaq` | high | CVE published by another CNA, not cited (CVE-2026-76207) | 89 | 4.1.7 |
| [GHSA-8pr3-q3cw-q234](https://github.com/thorsten/phpMyFAQ/security/advisories/GHSA-8pr3-q3cw-q234) | `thorsten/phpmyfaq` | high | CVE published by another CNA, not cited (CVE-2026-76208) | 89 | 4.1.7 |
| [GHSA-7gh7-qh7c-9r8m](https://github.com/thorsten/phpMyFAQ/security/advisories/GHSA-7gh7-qh7c-9r8m) | `composer:phpmyfaq/phpmyfaq` | medium | CVE published by another CNA, not cited (CVE-2026-76211) | 89 | 4.1.7 |
| [GHSA-5hx6-c293-588h](https://github.com/thorsten/phpMyFAQ/security/advisories/GHSA-5hx6-c293-588h) | `composer:phpmyfaq/phpmyfaq` | medium | CVE published by another CNA, not cited (CVE-2026-76212) | 89 | 4.1.7 |

589 advisories in limbo have waited more than a year.

## Coverage

Watchlist 18,656 repositories; 18,656 up to date on their schedule (daily for repos with an advisory in limbo, every 3 to 7 days for the rest); 2,877 checked in the last 24 hours; 37,507 reviewed advisories known. Every number is a floor: the tracker only sees repositories on its watchlist. Version ranges are as entered by maintainers and unreviewed.

_Advisory metadata from published GitHub repository security advisories and the GitHub Advisory Database (https://github.com/advisories, CC BY 4.0); CVE state from CVE Services; OSV.dev; NVD API (this product uses the NVD API but is not endorsed or certified by the NVD). Compiled by Limbowatch (https://limbo.watch), CC BY 4.0._
