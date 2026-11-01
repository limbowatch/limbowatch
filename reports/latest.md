# Limbo Tracker daily report — 2026-11-01

Generated 2026-11-01 13:43:24 UTC; changes since 2026-10-31 12:52:32 UTC.

## Now

- **8,167 advisories in limbo** (+179 since the last report: 127 newly published, 52 older ones found for the first time, 0 left limbo): published by maintainers on GitHub, in ecosystems GitHub reviews, but not yet in GitHub's reviewed database or OSV.
  - 4,202 with no CVE anywhere · 575 citing a CVE that's still only reserved · 1,025 with a CVE from another CNA they don't cite
  - severity: 866 critical, 3,260 high, 3,341 medium, 700 low · median wait so far 56.2 days
- **13,912 more are likely permanent** (+60 since the last report: 58 newly published, 2 older ones found for the first time, 0 left limbo): in ecosystems GitHub doesn't review, so GitHub-based scanners will probably never see them.

## Since the last report

- **127 newly published** advisories entered limbo.
- 52 older advisories were found for the first time (0 in newly watched repos).
- **Left limbo** (likely permanent included): 0 reviewed by GitHub, 0 found to duplicate a reviewed advisory, 0 withdrawn or unpublished.
- **CVE changes:** 5 (0 reserved CVEs published, 1 new CVEs from other CNAs).

## Newly published, in limbo

| Advisory | Package | Severity | CVE | Days | Fixed in |
|---|---|---|---|---:|---|
| [GHSA-94f5-6j6w-r3rh](https://github.com/fleetdm/fleet/security/advisories/GHSA-94f5-6j6w-r3rh) | `go:github.com/fleetdm/fleet` | critical | no CVE anywhere | 1 | 4.88.2, 4.89.3, 4.90.3, 4.91.2, 4.92.3 |
| [GHSA-v6jx-8m6q-xm2r](https://github.com/cabraviva/path-sanitizer/security/advisories/GHSA-v6jx-8m6q-xm2r) | `npm:path-sanitizer` | critical | no CVE anywhere | 1 | 5.0.0 |
| [GHSA-rwjg-p967-7224](https://github.com/cabraviva/path-sanitizer/security/advisories/GHSA-rwjg-p967-7224) | `npm:path-sanitizer` | critical | no CVE anywhere | 1 | 4.0.3 |
| [GHSA-m2mr-hhjj-p3v2](https://github.com/getgrav/grav/security/advisories/GHSA-m2mr-hhjj-p3v2) | `composer:getgrav/grav` | critical | no CVE anywhere | 0 | 2.2.18, 1.7.53.7 |
| [GHSA-g275-mf26-qx9r](https://github.com/siyuan-note/siyuan/security/advisories/GHSA-g275-mf26-qx9r) | `npm:SiYuan` | critical | no CVE anywhere | 0 | v3.8.10 |
| [GHSA-h4x8-v7vh-37h6](https://github.com/Paymenter/Paymenter/security/advisories/GHSA-h4x8-v7vh-37h6) | `composer:paymenter/paymenter` | high | no CVE anywhere | 1 | 1.5.9 |
| [GHSA-p5qc-4qfj-2rq7](https://github.com/Paymenter/Paymenter/security/advisories/GHSA-p5qc-4qfj-2rq7) | `composer:paymenter/paymenter` | high | no CVE anywhere | 1 | 1.5.9 |
| [GHSA-3f94-vm6x-3jv3](https://github.com/superradcompany/microsandbox/security/advisories/GHSA-3f94-vm6x-3jv3) | `rust:microsandbox-runtime` | high | no CVE anywhere | 1 | – |
| [GHSA-32cw-mf7w-gpqr](https://github.com/directus/directus/security/advisories/GHSA-32cw-mf7w-gpqr) | `npm:directus` | high | no CVE anywhere | 1 | 12.5.0 |
| [GHSA-48r9-g6f9-x3gm](https://github.com/prest/prest/security/advisories/GHSA-48r9-g6f9-x3gm) | `go:github.com/prest/prest/v2` | high | no CVE anywhere | 1 | 2.5.3 |
| [GHSA-r867-ghgv-mrp9](https://github.com/prest/prest/security/advisories/GHSA-r867-ghgv-mrp9) | `go:github.com/prest/prest` | high | no CVE anywhere | 1 | 2.5.3 |
| [GHSA-h25q-9rmj-646h](https://github.com/prest/prest/security/advisories/GHSA-h25q-9rmj-646h) | `go:github.com/prest/prest` | high | no CVE anywhere | 1 | 2.5.3 |
| [GHSA-qf89-6xm4-66wm](https://github.com/unjs/ipx/security/advisories/GHSA-qf89-6xm4-66wm) | `npm:ipx` | high | no CVE anywhere | 1 | 3.1.3, 2.1.2, 4.1.0 |
| [GHSA-5hvw-9x27-hvfh](https://github.com/graphiti-api/graphiti/security/advisories/GHSA-5hvw-9x27-hvfh) | `rubygems:graphiti` | high | no CVE anywhere | 1 | – |
| [GHSA-5vr5-74q2-mfg4](https://github.com/fleetdm/fleet/security/advisories/GHSA-5vr5-74q2-mfg4) | `go:github.com/fleetdm/fleet` | high | no CVE anywhere | 1 | 4.92.0 |
| [GHSA-2r75-q53f-v8px](https://github.com/fleetdm/fleet/security/advisories/GHSA-2r75-q53f-v8px) | `go:github.com/fleetdm/fleet/v4` | high | no CVE anywhere | 1 | 4.92.0 |
| [GHSA-3qx5-8m9j-pmrp](https://github.com/fleetdm/fleet/security/advisories/GHSA-3qx5-8m9j-pmrp) | `go:github.com/fleetdm/fleet` | high | no CVE anywhere | 1 | 4.86.2 |
| [GHSA-x2cq-c87r-5mfx](https://github.com/zip-rs/zip2/security/advisories/GHSA-x2cq-c87r-5mfx) | `rust:zip` | high | no CVE anywhere | 1 | 9.0.4 |
| [GHSA-x3hf-v55x-jcp6](https://github.com/obot-platform/obot/security/advisories/GHSA-x3hf-v55x-jcp6) | `go:github.com/obot-platform/obot` | high | no CVE anywhere | 1 | v0.27.0 |
| [GHSA-57qx-69p6-3w3g](https://github.com/obot-platform/obot/security/advisories/GHSA-57qx-69p6-3w3g) | `go:github.com/obot-platform/obot` | high | no CVE anywhere | 1 | v0.27.0 |
| [GHSA-j2mc-vg6q-w75p](https://github.com/amodm/webbrowser-rs/security/advisories/GHSA-j2mc-vg6q-w75p) | `rust:webbrowser` | high | no CVE anywhere | 1 | v1.2.6 |
| [GHSA-j265-mg9q-wpv9](https://github.com/web-token/jwt-framework/security/advisories/GHSA-j265-mg9q-wpv9) | `composer:web-token/jwt-encryption, composer:web-token/jwt…` | high | no CVE anywhere | 1 | 3.4.11, 4.0.8, 4.1.10, 4.2.4 |
| [GHSA-5pj7-wx9m-cjh6](https://github.com/web-token/jwt-framework/security/advisories/GHSA-5pj7-wx9m-cjh6) | `composer:web-token/jwt-encryption-algorithm-ecdh-es, comp…` | high | no CVE anywhere | 1 | 3.4.12, 4.0.8, 4.1.10, 4.2.4 |
| [GHSA-6xj4-4chr-656w](https://github.com/starman69/mcp-sanitizer/security/advisories/GHSA-6xj4-4chr-656w) | `npm:mcp-sanitizer` | high | no CVE anywhere | 1 | 1.4.2 |
| [GHSA-v25x-53wq-6r99](https://github.com/starman69/mcp-sanitizer/security/advisories/GHSA-v25x-53wq-6r99) | `npm:mcp-sanitizer` | high | no CVE anywhere | 1 | 1.4.2 |

…and 102 more (see the feed).

## CVE changes

| Advisory | Change |
|---|---|
| [GHSA-358w-w75h-x6rx](https://github.com/gopacket/gopacket/security/advisories/GHSA-358w-w75h-x6rx) | cites CVE-2026-119299 (was none) |
| [GHSA-6pmg-vc6m-6wrr](https://github.com/frappe/frappe/security/advisories/GHSA-6pmg-vc6m-6wrr) | cites CVE-2026-119144 (was none) |
| [GHSA-ccrj-gw8r-854m](https://github.com/open-telemetry/opentelemetry-java/security/advisories/GHSA-ccrj-gw8r-854m) | cites CVE-2026-118259 (was none) |
| [GHSA-gg6h-894w-4m9c](https://github.com/le0pard/re2js/security/advisories/GHSA-gg6h-894w-4m9c) | cites CVE-2026-116795 (was none) |
| [GHSA-x8r2-mggj-j6wr](https://github.com/strukturag/libheif/security/advisories/GHSA-x8r2-mggj-j6wr) | new CVE from another CNA: CVE-2026-120208 |

## Longest waiting, published in the last 90 days

| Advisory | Package | Severity | CVE | Days | Fixed in |
|---|---|---|---|---:|---|
| [GHSA-v4m9-jvvr-83cx](https://github.com/redaxo/core/security/advisories/GHSA-v4m9-jvvr-83cx) | `composer:redaxo/source` | high | CVE published by another CNA, not cited (CVE-2026-116897) | 89 | 5.21.4 |
| [GHSA-j9mx-x52f-48cw](https://github.com/redaxo/core/security/advisories/GHSA-j9mx-x52f-48cw) | `composer:redaxo/source` | high | CVE published by another CNA, not cited (CVE-2026-116898) | 89 | 5.21.4 |
| [GHSA-5m63-c3qx-wq8v](https://github.com/redaxo/core/security/advisories/GHSA-5m63-c3qx-wq8v) | `composer:redaxo/source` | high | CVE published by another CNA, not cited (CVE-2026-116899) | 89 | 5.21.4 |
| [GHSA-5wmj-5x79-rr87](https://github.com/redaxo/core/security/advisories/GHSA-5wmj-5x79-rr87) | `composer:redaxo/source` | medium | CVE published by another CNA, not cited (CVE-2026-116900) | 89 | 5.21.4 |
| [GHSA-2p3g-jr7p-qwwx](https://github.com/redaxo/core/security/advisories/GHSA-2p3g-jr7p-qwwx) | `composer:redaxo/source` | medium | CVE published by another CNA, not cited (CVE-2026-117533) | 89 | 5.21.4 |

589 advisories in limbo have waited more than a year.

## Coverage

Watchlist 18,656 repositories; 18,656 up to date on their schedule (daily for repos with an advisory in limbo, every 3 to 7 days for the rest); 3,966 checked in the last 24 hours; 37,507 reviewed advisories known. Every number is a floor: the tracker only sees repositories on its watchlist. Version ranges are as entered by maintainers and unreviewed.

_Advisory metadata from published GitHub repository security advisories and the GitHub Advisory Database (https://github.com/advisories, CC BY 4.0); CVE state from CVE Services; OSV.dev; NVD API (this product uses the NVD API but is not endorsed or certified by the NVD). Compiled by Limbowatch (https://limbo.watch), CC BY 4.0._
