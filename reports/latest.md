# Limbo Tracker daily report — 2026-11-11

Generated 2026-11-11 14:51:29 UTC; changes since 2026-11-10 15:18:34 UTC.

## Now

- **10,059 advisories in limbo** (+130 since the last report: 167 newly published, 21 older ones found for the first time, 58 left limbo): published by maintainers on GitHub, in ecosystems GitHub reviews, but not yet in GitHub's reviewed database or OSV.
  - 5,589 with no CVE anywhere · 613 citing a CVE that's still only reserved · 1,236 with a CVE from another CNA they don't cite
  - severity: 964 critical, 3,954 high, 4,207 medium, 934 low · median wait so far 54.6 days
- **15,045 more are likely permanent** (+413 since the last report: 170 newly published, 244 older ones found for the first time, 1 left limbo): in ecosystems GitHub doesn't review, so GitHub-based scanners will probably never see them.

## Since the last report

- **167 newly published** advisories entered limbo.
- 21 older advisories were found for the first time (14 in newly watched repos).
- **Left limbo** (likely permanent included): 59 reviewed by GitHub, 0 found to duplicate a reviewed advisory, 0 withdrawn or unpublished.
- **CVE changes:** 95 (17 reserved CVEs published, 9 new CVEs from other CNAs).

## Newly published, in limbo

| Advisory | Package | Severity | CVE | Days | Fixed in |
|---|---|---|---|---:|---|
| [GHSA-m9c3-99x3-77g6](https://github.com/PyMySQL/mysqlclient/security/advisories/GHSA-m9c3-99x3-77g6) | `pip:mysqlclient` | critical | no CVE anywhere | 1 | 2.3.1 |
| [GHSA-92qw-564p-pmg6](https://github.com/plone/Products.CMFPlone/security/advisories/GHSA-92qw-564p-pmg6) | `pip:products-cmfplone` | critical | no CVE anywhere | 1 | 6.2.3, 6.1.6, 6.0.16 |
| [GHSA-5rq2-4mjm-m7q2](https://github.com/Budibase/budibase/security/advisories/GHSA-5rq2-4mjm-m7q2) | `npm:@budibase/server` | critical | no CVE anywhere | 0 | 4.0.0 |
| [GHSA-wr7j-r9v4-6rjh](https://github.com/Budibase/budibase/security/advisories/GHSA-wr7j-r9v4-6rjh) | `npm:@budibase/server` | critical | no CVE anywhere | 0 | 4.0.0 |
| [GHSA-q4f7-c337-92c9](https://github.com/Budibase/budibase/security/advisories/GHSA-q4f7-c337-92c9) | `npm:@budibase/server` | critical | no CVE anywhere | 0 | 4.0.0 |
| [GHSA-6wc7-w493-mw5m](https://github.com/Budibase/budibase/security/advisories/GHSA-6wc7-w493-mw5m) | `npm:@budibase/server` | critical | no CVE anywhere | 0 | 4.0.0 |
| [GHSA-p7c8-m379-jf3x](https://github.com/Budibase/budibase/security/advisories/GHSA-p7c8-m379-jf3x) | `npm:@budibase/server` | critical | no CVE anywhere | 0 | 4.0.0 |
| [GHSA-x4w8-596q-fmh7](https://github.com/Budibase/budibase/security/advisories/GHSA-x4w8-596q-fmh7) | `npm:@budibase/server` | critical | no CVE anywhere | 0 | 4.0.0 |
| [GHSA-jm85-crv2-88px](https://github.com/Budibase/budibase/security/advisories/GHSA-jm85-crv2-88px) | `npm:@budibase/server` | critical | no CVE anywhere | 0 | 4.0.0 |
| [GHSA-3cfg-jpcr-gfp3](https://github.com/gradle/gradle/security/advisories/GHSA-3cfg-jpcr-gfp3) | `maven:org.gradle:gradle-core` | critical | no CVE anywhere | 0 | 8.14.7, 9.9.1 |
| [GHSA-mm6c-35cm-g4x2](https://github.com/risc0/risc0-ethereum/security/advisories/GHSA-mm6c-35cm-g4x2) | `other:RiscZeroGroth16Verifier.sol, rust:risc0-ethereum-co…` | critical | no CVE anywhere | 0 | 3.1.0 |
| [GHSA-g6qg-9j8p-7j87](https://github.com/risc0/risc0/security/advisories/GHSA-g6qg-9j8p-7j87) | `rust:risc0-circuit-recursion, rust:risc0-groth16, rust:ri…` | critical | no CVE anywhere | 0 | 3.1.0, 4.1.0, 3.0.6 |
| [GHSA-5mw8-wv8h-h6hx](https://github.com/contao/contao/security/advisories/GHSA-5mw8-wv8h-h6hx) | `composer:contao/core-bundle` | critical | no CVE anywhere | 0 | 5.7.17, 6.0.6 |
| [GHSA-cfqv-cv4g-hw85](https://github.com/gotenberg/gotenberg/security/advisories/GHSA-cfqv-cv4g-hw85) | `go:github.com/gotenberg/gotenberg/v8` | critical | no CVE anywhere | 0 | 8.40.0 |
| [GHSA-gpf4-wmvf-cgjw](https://github.com/gotenberg/gotenberg/security/advisories/GHSA-gpf4-wmvf-cgjw) | `go:github.com/gotenberg/gotenberg/v8` | critical | no CVE anywhere | 0 | 8.39.0 |
| [GHSA-pc2r-hvrc-f4v6](https://github.com/contao/contao/security/advisories/GHSA-pc2r-hvrc-f4v6) | `composer:contao/core-bundle` | critical | no CVE anywhere | 0 | 5.3.54, 5.7.17, 6.0.6 |
| [GHSA-xh3r-77ch-frm3](https://github.com/contao/contao/security/advisories/GHSA-xh3r-77ch-frm3) | `composer:contao/core-bundle` | critical | no CVE anywhere | 0 | 5.3.54, 5.7.17, 6.0.6 |
| [GHSA-225x-m3g7-h3fc](https://github.com/micronaut-projects/micronaut-security/security/advisories/GHSA-225x-m3g7-h3fc) | `maven:io.micronaut.security:micronaut-security` | critical | no CVE anywhere | 0 | – |
| [GHSA-5gmg-jhq8-8f46](https://github.com/micronaut-projects/micronaut-security/security/advisories/GHSA-5gmg-jhq8-8f46) | `maven:io.micronaut.security:micronaut-security` | critical | no CVE anywhere | 0 | – |
| [GHSA-9p96-xfm5-fhrr](https://github.com/micronaut-projects/micronaut-security/security/advisories/GHSA-9p96-xfm5-fhrr) | `maven:io.micronaut.security:micronaut-security` | critical | no CVE anywhere | 0 | – |
| [GHSA-qrww-3xmv-qhgm](https://github.com/open-telemetry/opentelemetry-js/security/advisories/GHSA-qrww-3xmv-qhgm) | `npm:@opentelemetry/resources` | high | no CVE anywhere | 1 | 2.12.1, 3.1.1 |
| [GHSA-fjgr-79gp-rwm8](https://github.com/OP-Engineering/link-preview-js/security/advisories/GHSA-fjgr-79gp-rwm8) | `npm:link-preview-js` | high | no CVE anywhere | 0 | 6.0.0 |
| [GHSA-4wq9-grf3-qg2p](https://github.com/awslabs/mcp/security/advisories/GHSA-4wq9-grf3-qg2p) | `pip:awslabs-aws-api-mcp-server` | high | CVE published, cited (CVE-2026-125271) | 0 | 1.5.1 |
| [GHSA-622v-wwmm-7xrf](https://github.com/Budibase/budibase/security/advisories/GHSA-622v-wwmm-7xrf) | `npm:@budibase/server` | high | no CVE anywhere | 0 | 4.0.0 |
| [GHSA-r2q3-7m4h-63qg](https://github.com/Budibase/budibase/security/advisories/GHSA-r2q3-7m4h-63qg) | `npm:@budibase/server` | high | CVE reserved (RBP) (CVE-2026-122244) | 0 | 4.0.0 |

…and 142 more (see the feed).

## CVE changes

| Advisory | Change |
|---|---|
| [GHSA-233c-vfmw-6rw9](https://github.com/WWBN/AVideo/security/advisories/GHSA-233c-vfmw-6rw9) | new CVE from another CNA: CVE-2026-126541 |
| [GHSA-2586-8ghr-69fj](https://github.com/rails/rails/security/advisories/GHSA-2586-8ghr-69fj) | new CVE from GitHub's CNA, not cited: CVE-2026-126076 |
| [GHSA-2gff-2mmg-m73p](https://github.com/rails/rails/security/advisories/GHSA-2gff-2mmg-m73p) | new CVE from GitHub's CNA, not cited: CVE-2026-126083 |
| [GHSA-2p2f-4rq4-gjwc](https://github.com/rails/rails/security/advisories/GHSA-2p2f-4rq4-gjwc) | new CVE from GitHub's CNA, not cited: CVE-2026-126079 |
| [GHSA-2w9f-fxwj-w2qf](https://github.com/rails/rails/security/advisories/GHSA-2w9f-fxwj-w2qf) | new CVE from GitHub's CNA, not cited: CVE-2026-126075 |
| [GHSA-3cc4-3294-vgjf](https://github.com/digitalbazaar/forge/security/advisories/GHSA-3cc4-3294-vgjf) | new CVE from GitHub's CNA, not cited: CVE-2026-125336 |
| [GHSA-3cp5-q6fp-mqf5](https://github.com/Intermesh/groupoffice/security/advisories/GHSA-3cp5-q6fp-mqf5) | CVE-2026-63653 RESERVED -> PUBLISHED |
| [GHSA-3f4q-8x5m-76v8](https://github.com/rails/rails/security/advisories/GHSA-3f4q-8x5m-76v8) | new CVE from GitHub's CNA, not cited: CVE-2026-126188 |
| [GHSA-3w22-6jfg-527w](https://github.com/sparklemotion/nokogiri/security/advisories/GHSA-3w22-6jfg-527w) | new CVE from GitHub's CNA, not cited: CVE-2026-126064 |
| [GHSA-3w93-6hmw-whh4](https://github.com/rails/rails/security/advisories/GHSA-3w93-6hmw-whh4) | new CVE from GitHub's CNA, not cited: CVE-2026-126084 |
| [GHSA-3w98-8958-84rh](https://github.com/WWBN/AVideo/security/advisories/GHSA-3w98-8958-84rh) | new CVE from another CNA: CVE-2026-126545 |
| [GHSA-474x-hrwr-fgx4](https://github.com/NaturalIntelligence/fast-xml-parser/security/advisories/GHSA-474x-hrwr-fgx4) | new CVE from GitHub's CNA, not cited: CVE-2026-126066 |
| [GHSA-48qj-5wxh-m8hc](https://github.com/cakephp/twig-view/security/advisories/GHSA-48qj-5wxh-m8hc) | CVE-2026-59192 RESERVED -> PUBLISHED |
| [GHSA-4m9w-3p93-6cwx](https://github.com/Intermesh/groupoffice/security/advisories/GHSA-4m9w-3p93-6cwx) | CVE-2026-63011 RESERVED -> PUBLISHED |
| [GHSA-4p39-36wj-23h4](https://github.com/sparklemotion/nokogiri/security/advisories/GHSA-4p39-36wj-23h4) | new CVE from GitHub's CNA, not cited: CVE-2026-126063 |
| [GHSA-4v2w-w6g6-f8f8](https://github.com/rails/rails/security/advisories/GHSA-4v2w-w6g6-f8f8) | new CVE from GitHub's CNA, not cited: CVE-2026-126071 |
| [GHSA-5957-c7qm-m469](https://github.com/rails/rails/security/advisories/GHSA-5957-c7qm-m469) | new CVE from GitHub's CNA, not cited: CVE-2026-126068 |
| [GHSA-5gg3-9jhh-xf86](https://github.com/WWBN/AVideo/security/advisories/GHSA-5gg3-9jhh-xf86) | new CVE from another CNA: CVE-2026-126543 |
| [GHSA-6828-c7cx-hvqm](https://github.com/jellyfin/jellyfin/security/advisories/GHSA-6828-c7cx-hvqm) | new CVE from another CNA: CVE-2026-126499 |
| [GHSA-6889-vf6x-f3g5](https://github.com/digitalbazaar/forge/security/advisories/GHSA-6889-vf6x-f3g5) | new CVE from GitHub's CNA, not cited: CVE-2026-125335 |
| [GHSA-68p9-83h6-5wpj](https://github.com/rails/rails/security/advisories/GHSA-68p9-83h6-5wpj) | new CVE from GitHub's CNA, not cited: CVE-2026-126069 |
| [GHSA-6cv4-p8m7-4r25](https://github.com/digitalbazaar/forge/security/advisories/GHSA-6cv4-p8m7-4r25) | new CVE from GitHub's CNA, not cited: CVE-2026-125333 |
| [GHSA-6f4g-xm8v-pgv6](https://github.com/tmatens/compose-lint/security/advisories/GHSA-6f4g-xm8v-pgv6) | new CVE from GitHub's CNA, not cited: CVE-2026-125121 |
| [GHSA-7583-9cqv-j9rf](https://github.com/mcdope/pam_usb/security/advisories/GHSA-7583-9cqv-j9rf) | CVE-2026-64668 RESERVED -> PUBLISHED |
| [GHSA-7w4v-2c9r-q94v](https://github.com/openobserve/openobserve/security/advisories/GHSA-7w4v-2c9r-q94v) | new CVE from GitHub's CNA, not cited: CVE-2026-126065 |

…and 70 more.

## Longest waiting, published in the last 90 days

| Advisory | Package | Severity | CVE | Days | Fixed in |
|---|---|---|---|---:|---|
| [GHSA-xv5m-gpmp-m72c](https://github.com/WWBN/AVideo/security/advisories/GHSA-xv5m-gpmp-m72c) | `composer:wwbn/avideo` | medium | CVE published by another CNA, not cited (CVE-2026-81732) | 89 | – |
| [GHSA-mf3j-vxq2-vmc4](https://github.com/TryGhost/Ghost/security/advisories/GHSA-mf3j-vxq2-vmc4) | `npm:ghost` | medium | CVE published by another CNA, not cited (CVE-2026-103285) | 89 | v6.57.1 |
| [GHSA-q55r-w7fh-rmh6](https://github.com/TryGhost/Ghost/security/advisories/GHSA-q55r-w7fh-rmh6) | `npm:ghost` | high | CVE published by another CNA, not cited (CVE-2026-103283) | 89 | v6.57.1 |
| [GHSA-vm82-r49m-224q](https://github.com/TryGhost/Ghost/security/advisories/GHSA-vm82-r49m-224q) | `npm:ghost` | medium | CVE published by another CNA, not cited (CVE-2026-103284) | 89 | v6.57.1 |
| [GHSA-5685-hwm9-62cg](https://github.com/TryGhost/Ghost/security/advisories/GHSA-5685-hwm9-62cg) | `npm:ghost` | medium | CVE published by another CNA, not cited (CVE-2026-103280) | 89 | v6.23.0 |

606 advisories in limbo have waited more than a year.

## Coverage

Watchlist 67,471 repositories; 67,471 up to date on their schedule (daily for repos with an advisory in limbo, every 3 days for other repos with advisories, every 30 days and after each release for the rest); 10,174 checked in the last 24 hours; 37,686 reviewed advisories known. Every number is a floor: the tracker only sees repositories on its watchlist. Version ranges are as entered by maintainers and unreviewed.

_Advisory metadata from published GitHub repository security advisories and the GitHub Advisory Database (https://github.com/advisories, CC BY 4.0); CVE state from CVE Services; OSV.dev; NVD API (this product uses the NVD API but is not endorsed or certified by the NVD). Compiled by Limbowatch (https://limbo.watch), CC BY 4.0._
