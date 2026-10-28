# Limbo Tracker daily report — 2026-10-28

Generated 2026-10-28 02:37:54 UTC; first report.

## Now

- **25 advisories in limbo**: published by maintainers on GitHub, in ecosystems GitHub reviews, but not yet in GitHub's reviewed database or OSV.
  - 18 with no CVE anywhere · 2 citing a CVE that's still only reserved · 0 with a CVE from another CNA they don't cite
  - severity: 2 critical, 11 high, 9 medium, 3 low · median wait so far 27.4 days
- **0 more are likely permanent**: in ecosystems GitHub doesn't review, so GitHub-based scanners will probably never see them.

## Since the last report

- **2 newly published** advisories entered limbo.
- 23 older advisories were found for the first time (newly watched repos).
- **Left limbo:** 0 reviewed by GitHub, 0 found to duplicate a reviewed advisory, 0 withdrawn or unpublished.
- **CVE changes:** 0.

## Newly published, in limbo

| Advisory | Package | Severity | CVE | Days | Fixed in |
|---|---|---|---|---:|---|
| [GHSA-jh2m-fhpj-3vr7](https://github.com/bytecodealliance/rustix/security/advisories/GHSA-jh2m-fhpj-3vr7) | `rust:rustix` | high | no CVE anywhere | 1 | – |
| [GHSA-c9gr-gmg4-2vqv](https://github.com/andybalholm/brotli/security/advisories/GHSA-c9gr-gmg4-2vqv) | `go:github.com/andybalholm/brotli` | low | no CVE anywhere | 1 | 1.2.7 |

## Longest waiting

| Advisory | Package | Severity | CVE | Days | Fixed in |
|---|---|---|---|---:|---|
| [GHSA-3jcv-796g-cpjg](https://github.com/aws/aws-sdk-go-v2/security/advisories/GHSA-3jcv-796g-cpjg) | `go:github.com/aws/aws-sdk-go-v2/service/accessanalyzer, g…` | low | no CVE anywhere | 291 | v1.0.0-preview.90; v1.0.13; v1.10.10; v1 |
| [GHSA-hvx2-4ghc-j37m](https://github.com/apostrophecms/apostrophe/security/advisories/GHSA-hvx2-4ghc-j37m) | `npm:apostrophe` | high | CVE published, cited (CVE-2026-45014) | 167 | – |
| [GHSA-5jhw-7jv7-qcqq](https://github.com/authlib/joserfc/security/advisories/GHSA-5jhw-7jv7-qcqq) | `pip:joserfc` | low | CVE published, cited (CVE-2026-62995) | 106 | 1.7.2 |
| [GHSA-xmpp-f9v3-r7qh](https://github.com/apostrophecms/apostrophe/security/advisories/GHSA-xmpp-f9v3-r7qh) | `npm:apostrophe` | medium | CVE reserved (RBP) (CVE-2026-63668) | 76 | >=4.32.0 |
| [GHSA-73hm-ghh3-g73r](https://github.com/apostrophecms/apostrophe/security/advisories/GHSA-73hm-ghh3-g73r) | `npm:sanitize-html` | medium | no CVE anywhere | 76 | >= 2.17.6 |

## Coverage

Watchlist 8,850 repositories; 533 polled in the last 24 hours; the last run stopped early (budget); 37,320 reviewed advisories known. Every number is a floor: the tracker only sees repositories on its watchlist. Version ranges are as entered by maintainers and unreviewed.

_Advisory metadata from published GitHub repository security advisories and the GitHub Advisory Database (https://github.com/advisories, CC BY 4.0); CVE state from CVE Services; OSV.dev; NVD API (this product uses the NVD API but is not endorsed or certified by the NVD). Compiled by Limbowatch (https://limbo.watch), CC BY 4.0._
