# Limbo Tracker daily report — 2026-11-05

Generated 2026-11-05 14:54:42 UTC; changes since 2026-11-04 14:51:55 UTC.

## Now

- **8,603 advisories in limbo** (+85 since the last report: 47 newly published, 40 older ones found for the first time, 2 left limbo): published by maintainers on GitHub, in ecosystems GitHub reviews, but not yet in GitHub's reviewed database or OSV.
  - 4,494 with no CVE anywhere · 591 citing a CVE that's still only reserved · 1,096 with a CVE from another CNA they don't cite
  - severity: 886 critical, 3,394 high, 3,557 medium, 766 low · median wait so far 56.9 days
- **14,114 more are likely permanent** (+18 since the last report: 0 newly published, 19 older ones found for the first time, 1 left limbo): in ecosystems GitHub doesn't review, so GitHub-based scanners will probably never see them.

## Since the last report

- **47 newly published** advisories entered limbo.
- 40 older advisories were found for the first time (27 in newly watched repos).
- **Left limbo** (likely permanent included): 3 reviewed by GitHub, 0 found to duplicate a reviewed advisory, 0 withdrawn or unpublished.
- **CVE changes:** 80 (33 reserved CVEs published, 47 new CVEs from other CNAs).

## Newly published, in limbo

| Advisory | Package | Severity | CVE | Days | Fixed in |
|---|---|---|---|---:|---|
| [GHSA-x994-x7gh-x573](https://github.com/OP-Engineering/link-preview-js/security/advisories/GHSA-x994-x7gh-x573) | `npm:link-preview-js` | critical | no CVE anywhere | 1 | 5.0.1 |
| [GHSA-f3w6-w445-fwh9](https://github.com/rails/rails/security/advisories/GHSA-f3w6-w445-fwh9) | `rubygems:activestorage` | critical | CVE published by another CNA, not cited (CVE-2026-122006) | 1 | 8.1.4.1, 8.0.5.2 |
| [GHSA-23w8-wx9r-vm57](https://github.com/better-auth/better-call/security/advisories/GHSA-23w8-wx9r-vm57) | `npm:better-call` | high | no CVE anywhere | 1 | 1.4.5 |
| [GHSA-vvf4-9x63-8xvv](https://github.com/rthalley/dnspython/security/advisories/GHSA-vvf4-9x63-8xvv) | `pip:dnspython` | high | no CVE anywhere | 1 | 2.9.2 |
| [GHSA-qv26-43gx-2qp2](https://github.com/OP-Engineering/link-preview-js/security/advisories/GHSA-qv26-43gx-2qp2) | `npm:link-preview-js` | high | no CVE anywhere | 1 | 5.0.2 |
| [GHSA-pr9p-r5xm-659j](https://github.com/OP-Engineering/link-preview-js/security/advisories/GHSA-pr9p-r5xm-659j) | `npm:link-preview-js` | high | no CVE anywhere | 1 | 5.0.1 |
| [GHSA-2gff-2mmg-m73p](https://github.com/rails/rails/security/advisories/GHSA-2gff-2mmg-m73p) | `rubygems:actionpack` | high | no CVE anywhere | 1 | 8.1.4.1 |
| [GHSA-8474-xrp6-wh69](https://github.com/rails/rails/security/advisories/GHSA-8474-xrp6-wh69) | `rubygems:activesupport` | high | no CVE anywhere | 1 | 8.1.4.1, 8.0.5.2 |
| [GHSA-v924-7rp8-4mxh](https://github.com/rails/rails/security/advisories/GHSA-v924-7rp8-4mxh) | `rubygems:activestorage` | high | no CVE anywhere | 1 | 8.1.4.1, 8.0.5.2 |
| [GHSA-wm3x-v3qw-4jh3](https://github.com/rails/rails/security/advisories/GHSA-wm3x-v3qw-4jh3) | `rubygems:actionpack` | high | no CVE anywhere | 1 | 8.1.4.1, 8.0.5.2 |
| [GHSA-77g6-g2mq-wxw4](https://github.com/open-telemetry/opentelemetry-dotnet-contrib/security/advisories/GHSA-77g6-g2mq-wxw4) | `nuget:OpenTelemetry.Exporter.InfluxDB` | high | no CVE anywhere | 0 | 1.0.0-alpha.17 |
| [GHSA-mqg3-3v4r-cm32](https://github.com/nodejs/undici/security/advisories/GHSA-mqg3-3v4r-cm32) | `npm:undici` | high | CVE reserved (RBP) (CVE-2026-116592) | 0 | 7.30.2, 8.12.4 |
| [GHSA-mfr8-8qww-v76h](https://github.com/vercel/next.js/security/advisories/GHSA-mfr8-8qww-v76h) | `npm:next` | medium | CVE reserved (RBP) (CVE-2026-119790) | 1 | – |
| [GHSA-vc7v-qv4w-wrv8](https://github.com/vercel/next.js/security/advisories/GHSA-vc7v-qv4w-wrv8) | `npm:next` | medium | CVE reserved (RBP) (CVE-2026-119351) | 1 | 16.4.2 |
| [GHSA-vvgp-ww4w-46vf](https://github.com/vercel/next.js/security/advisories/GHSA-vvgp-ww4w-46vf) | `npm:next` | medium | CVE reserved (RBP) (CVE-2026-119350) | 1 | – |
| [GHSA-rhh4-g77r-r9qj](https://github.com/vercel/next.js/security/advisories/GHSA-rhh4-g77r-r9qj) | `npm:next` | medium | CVE reserved (RBP) (CVE-2026-119349) | 1 | – |
| [GHSA-pc58-hwjq-p385](https://github.com/vercel/next.js/security/advisories/GHSA-pc58-hwjq-p385) | `npm:next` | medium | CVE reserved (RBP) (CVE-2026-119348) | 1 | – |
| [GHSA-7qx7-33qx-rqx2](https://github.com/vercel/next.js/security/advisories/GHSA-7qx7-33qx-rqx2) | `npm:next` | medium | CVE reserved (RBP) (CVE-2026-119347) | 1 | – |
| [GHSA-f3mh-rxg3-f5g2](https://github.com/vercel/next.js/security/advisories/GHSA-f3mh-rxg3-f5g2) | `npm:next` | medium | CVE reserved (RBP) (CVE-2026-119346) | 1 | – |
| [GHSA-fw37-f9mw-x9rx](https://github.com/better-auth/better-call/security/advisories/GHSA-fw37-f9mw-x9rx) | `npm:better-call` | medium | no CVE anywhere | 1 | 1.4.5 |
| [GHSA-3grv-rf6r-fj3x](https://github.com/opennextjs/opennextjs-cloudflare/security/advisories/GHSA-3grv-rf6r-fj3x) | `npm:@opennextjs/cloudflare` | medium | no CVE anywhere | 1 | 1.20.16 |
| [GHSA-5crp-j778-fgmr](https://github.com/opennextjs/opennextjs-cloudflare/security/advisories/GHSA-5crp-j778-fgmr) | `npm:@opennextjs/cloudflare` | medium | no CVE anywhere | 1 | 1.20.16 |
| [GHSA-x3c9-3g43-37gg](https://github.com/The-40-Thieves/obsidian-tc/security/advisories/GHSA-x3c9-3g43-37gg) | `npm:obsidian-tc` | medium | no CVE anywhere | 1 | 1.34.0 |
| [GHSA-4f57-v2rv-34vw](https://github.com/The-40-Thieves/obsidian-tc/security/advisories/GHSA-4f57-v2rv-34vw) | `npm:obsidian-tc` | medium | no CVE anywhere | 1 | 1.34.0 |
| [GHSA-x9f8-2hw3-553w](https://github.com/The-40-Thieves/obsidian-tc/security/advisories/GHSA-x9f8-2hw3-553w) | `npm:obsidian-tc` | medium | no CVE anywhere | 1 | 1.34.0 |

…and 22 more (see the feed).

## CVE changes

| Advisory | Change |
|---|---|
| [GHSA-24cc-9745-hxfc](https://github.com/kyverno/kyverno/security/advisories/GHSA-24cc-9745-hxfc) | new CVE from another CNA: CVE-2026-122315 |
| [GHSA-2557-79qc-6gfr](https://github.com/FreeRDP/FreeRDP/security/advisories/GHSA-2557-79qc-6gfr) | new CVE from another CNA: CVE-2026-121956 |
| [GHSA-2r43-6962-xcw5](https://github.com/kyverno/kyverno/security/advisories/GHSA-2r43-6962-xcw5) | new CVE from another CNA: CVE-2026-122321 |
| [GHSA-338x-hgrv-626h](https://github.com/kyverno/kyverno/security/advisories/GHSA-338x-hgrv-626h) | new CVE from another CNA: CVE-2026-122305 |
| [GHSA-373r-678h-hjc6](https://github.com/coder/coder/security/advisories/GHSA-373r-678h-hjc6) | new CVE from another CNA: CVE-2026-121967 |
| [GHSA-3f2c-hfj8-542w](https://github.com/kyverno/kyverno/security/advisories/GHSA-3f2c-hfj8-542w) | new CVE from another CNA: CVE-2026-122322 |
| [GHSA-3m37-hwq6-jrj8](https://github.com/zulip/zulip/security/advisories/GHSA-3m37-hwq6-jrj8) | CVE-2026-115574 RESERVED -> PUBLISHED |
| [GHSA-3pg4-5r42-wxvj](https://github.com/FreeRDP/FreeRDP/security/advisories/GHSA-3pg4-5r42-wxvj) | new CVE from another CNA: CVE-2026-121960 |
| [GHSA-3xfv-vq8x-qhg4](https://github.com/kyverno/kyverno/security/advisories/GHSA-3xfv-vq8x-qhg4) | new CVE from another CNA: CVE-2026-122310 |
| [GHSA-493q-9xvg-9xf3](https://github.com/kyverno/kyverno/security/advisories/GHSA-493q-9xvg-9xf3) | new CVE from another CNA: CVE-2026-122320 |
| [GHSA-49x8-xqjg-2pjg](https://github.com/espressif/esp-idf/security/advisories/GHSA-49x8-xqjg-2pjg) | CVE-2026-113780 RESERVED -> PUBLISHED |
| [GHSA-4j3p-7hp7-xw73](https://github.com/veracrypt/VeraCrypt/security/advisories/GHSA-4j3p-7hp7-xw73) | CVE-2026-77372 RESERVED -> PUBLISHED |
| [GHSA-4pqm-wqq6-h9q2](https://github.com/kyverno/kyverno/security/advisories/GHSA-4pqm-wqq6-h9q2) | new CVE from another CNA: CVE-2026-122311 |
| [GHSA-4qq4-qwxq-49m8](https://github.com/FreeRDP/FreeRDP/security/advisories/GHSA-4qq4-qwxq-49m8) | new CVE from another CNA: CVE-2026-121951 |
| [GHSA-4x3x-65c5-8hx4](https://github.com/zammad/zammad/security/advisories/GHSA-4x3x-65c5-8hx4) | CVE-2026-102345 RESERVED -> PUBLISHED |
| [GHSA-5j7x-r6vf-jhq2](https://github.com/git-for-windows/git/security/advisories/GHSA-5j7x-r6vf-jhq2) | CVE-2026-100408 RESERVED -> PUBLISHED |
| [GHSA-5qgv-9jcx-wph7](https://github.com/glpi-project/glpi/security/advisories/GHSA-5qgv-9jcx-wph7) | CVE-2026-53631 RESERVED -> PUBLISHED |
| [GHSA-6wqx-rv3q-vcxp](https://github.com/FreeRDP/FreeRDP/security/advisories/GHSA-6wqx-rv3q-vcxp) | new CVE from another CNA: CVE-2026-121953 |
| [GHSA-773r-585g-6vc3](https://github.com/blueprintue/blueprintue-self-hosted-edition/security/advisories/GHSA-773r-585g-6vc3) | new CVE from another CNA: CVE-2026-122138 |
| [GHSA-7v5q-w6f3-2v8p](https://github.com/glpi-project/glpi/security/advisories/GHSA-7v5q-w6f3-2v8p) | CVE-2026-57152 RESERVED -> PUBLISHED |
| [GHSA-8mrj-27wr-599g](https://github.com/kyverno/kyverno/security/advisories/GHSA-8mrj-27wr-599g) | new CVE from another CNA: CVE-2026-122306 |
| [GHSA-95hp-82c6-25q5](https://github.com/parse-community/parse-server/security/advisories/GHSA-95hp-82c6-25q5) | new CVE from another CNA: CVE-2026-121965 |
| [GHSA-95xv-3c54-c3pw](https://github.com/openedx/openedx-platform/security/advisories/GHSA-95xv-3c54-c3pw) | CVE-2026-97702 RESERVED -> PUBLISHED |
| [GHSA-983v-jp34-f3fm](https://github.com/FreeRDP/FreeRDP/security/advisories/GHSA-983v-jp34-f3fm) | new CVE from another CNA: CVE-2026-121955 |
| [GHSA-c26h-gm53-qg83](https://github.com/espressif/esp-idf/security/advisories/GHSA-c26h-gm53-qg83) | CVE-2026-113782 RESERVED -> PUBLISHED |

…and 55 more.

## Longest waiting, published in the last 90 days

| Advisory | Package | Severity | CVE | Days | Fixed in |
|---|---|---|---|---:|---|
| [GHSA-xmr7-549p-98w3](https://github.com/style-dictionary/style-dictionary/security/advisories/GHSA-xmr7-549p-98w3) | `npm:style-dictionary` | high | no CVE anywhere | 89 | 5.5.1 |
| [GHSA-464h-4j8h-q5mf](https://github.com/mganss/HtmlSanitizer/security/advisories/GHSA-464h-4j8h-q5mf) | `nuget:HtmlSanitizer` | high | CVE reserved (RBP) (CVE-2026-102529) | 89 | 9.0.967, 9.1.968-beta |
| [GHSA-8f95-jfm5-jjmr](https://github.com/markmhendrickson/neotoma/security/advisories/GHSA-8f95-jfm5-jjmr) | `npm:neotoma` | high | no CVE anywhere | 89 | 0.21.4 |
| [GHSA-33x4-v5cf-2hfj](https://github.com/markmhendrickson/neotoma/security/advisories/GHSA-33x4-v5cf-2hfj) | `npm:neotoma` | critical | no CVE anywhere | 89 | 0.21.4 |
| [GHSA-2745-m2g5-p3mw](https://github.com/uutils/coreutils/security/advisories/GHSA-2745-m2g5-p3mw) | `rust:uu_chmod` | high | no CVE anywhere | 89 | 0.10.0 |

591 advisories in limbo have waited more than a year.

## Coverage

Watchlist 18,671 repositories; 7,943 up to date on their schedule (daily for repos with an advisory in limbo, every 3 to 7 days for the rest); 4,194 checked in the last 24 hours; the last run stopped early (budget); 37,522 reviewed advisories known. Every number is a floor: the tracker only sees repositories on its watchlist. Version ranges are as entered by maintainers and unreviewed.

_Advisory metadata from published GitHub repository security advisories and the GitHub Advisory Database (https://github.com/advisories, CC BY 4.0); CVE state from CVE Services; OSV.dev; NVD API (this product uses the NVD API but is not endorsed or certified by the NVD). Compiled by Limbowatch (https://limbo.watch), CC BY 4.0._
