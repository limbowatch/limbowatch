# Limbo Tracker daily report — 2026-11-08

Generated 2026-11-08 13:49:37 UTC; changes since 2026-11-07 13:24:27 UTC.

## Now

- **9,405 advisories in limbo** (+278 since the last report: 87 newly published, 159 older ones found for the first time, 0 left limbo, +32 other changes): published by maintainers on GitHub, in ecosystems GitHub reviews, but not yet in GitHub's reviewed database or OSV.
  - 4,997 with no CVE anywhere · 606 citing a CVE that's still only reserved · 1,222 with a CVE from another CNA they don't cite
  - severity: 908 critical, 3,682 high, 3,943 medium, 872 low · median wait so far 55.2 days
- **14,435 more are likely permanent** (+22 since the last report: 24 newly published, 30 older ones found for the first time, 0 left limbo, −32 other changes): in ecosystems GitHub doesn't review, so GitHub-based scanners will probably never see them.

## Since the last report

- **87 newly published** advisories entered limbo.
- 159 older advisories were found for the first time (156 in newly watched repos).
- **Left limbo** (likely permanent included): 0 reviewed by GitHub, 0 found to duplicate a reviewed advisory, 0 withdrawn or unpublished.
- **CVE changes:** 180 (0 reserved CVEs published, 180 new CVEs from other CNAs).

## Newly published, in limbo

| Advisory | Package | Severity | CVE | Days | Fixed in |
|---|---|---|---|---:|---|
| [GHSA-5wm9-6g4v-jq7c](https://github.com/zip-rs/zip2/security/advisories/GHSA-5wm9-6g4v-jq7c) | `rust:zip` | critical | no CVE anywhere | 0 | 9.1.0 |
| [GHSA-wc8g-r527-q23h](https://github.com/benoitc/erlang_quic/security/advisories/GHSA-wc8g-r527-q23h) | `erlang:quic` | critical | no CVE anywhere | 0 | 2.4.1 |
| [GHSA-8xqp-qv6c-p5r8](https://github.com/austintoddj/canvas/security/advisories/GHSA-8xqp-qv6c-p5r8) | `composer:austintoddj/canvas` | high | no CVE anywhere | 1 | 7.2.7 |
| [GHSA-q7wc-mr9r-gcjh](https://github.com/scrapy/scrapy/security/advisories/GHSA-q7wc-mr9r-gcjh) | `pip:scrapy` | high | no CVE anywhere | 1 | 2.20.0 |
| [GHSA-j72p-v7rm-cwm3](https://github.com/scrapy/scrapy/security/advisories/GHSA-j72p-v7rm-cwm3) | `pip:scrapy` | high | no CVE anywhere | 1 | 2.20.0 |
| [GHSA-466x-p45j-m4fx](https://github.com/scrapy/scrapy/security/advisories/GHSA-466x-p45j-m4fx) | `pip:scrapy` | high | no CVE anywhere | 1 | 2.20.0 |
| [GHSA-fwm7-29m4-rrj9](https://github.com/scrapy/scrapy/security/advisories/GHSA-fwm7-29m4-rrj9) | `pip:scrapy` | high | no CVE anywhere | 1 | 2.20.0 |
| [GHSA-qqw6-q3r5-cxg7](https://github.com/uniget-org/cli/security/advisories/GHSA-qqw6-q3r5-cxg7) | `go:gitlab.com/uniget-org/cli` | high | no CVE anywhere | 0 | 0.30.2 |
| [GHSA-h2qx-fxx7-7r6j](https://github.com/benoitc/erlang_quic/security/advisories/GHSA-h2qx-fxx7-7r6j) | `erlang:quic` | high | no CVE anywhere | 0 | 2.2.0 |
| [GHSA-28pp-7fjp-8v32](https://github.com/voku/anti-xss/security/advisories/GHSA-28pp-7fjp-8v32) | `composer:voku/anti-xss` | high | no CVE anywhere | 0 | – |
| [GHSA-m3j8-84mj-fw9q](https://github.com/zip-rs/zip2/security/advisories/GHSA-m3j8-84mj-fw9q) | `rust:zip` | high | no CVE anywhere | 0 | 9.1.0 |
| [GHSA-224p-pchv-5r3r](https://github.com/benoitc/erlang_quic/security/advisories/GHSA-224p-pchv-5r3r) | `erlang:quic` | high | no CVE anywhere | 0 | 2.3.0 |
| [GHSA-9r7q-mx75-hcj7](https://github.com/QWED-AI/qwed-verification/security/advisories/GHSA-9r7q-mx75-hcj7) | `pip:qwed` | high | no CVE anywhere | 0 | 9.1.0 |
| [GHSA-7r34-rm5p-4wjv](https://github.com/zip-rs/zip2/security/advisories/GHSA-7r34-rm5p-4wjv) | `rust:zip` | high | no CVE anywhere | 0 | 9.1.0 |
| [GHSA-w2w4-j3wm-rrpp](https://github.com/zip-rs/zip2/security/advisories/GHSA-w2w4-j3wm-rrpp) | `zip-rs/zip2` | high | no CVE anywhere | 0 | 9.1.0 |
| [GHSA-vqm7-rm7v-qq3f](https://github.com/scriban/scriban/security/advisories/GHSA-vqm7-rm7v-qq3f) | `nuget:Scriban, nuget:Scriban.Signed` | high | no CVE anywhere | 0 | 7.6.0 |
| [GHSA-jhv7-5x5p-vh8w](https://github.com/scriban/scriban/security/advisories/GHSA-jhv7-5x5p-vh8w) | `nuget:Scriban, nuget:Scriban.Signed` | high | no CVE anywhere | 0 | 7.6.0 |
| [GHSA-28wr-xhqr-9mf4](https://github.com/scriban/scriban/security/advisories/GHSA-28wr-xhqr-9mf4) | `nuget:Scriban, nuget:Scriban.Signed` | high | no CVE anywhere | 0 | 7.6.0 |
| [GHSA-vhvh-mqjm-8vpg](https://github.com/scriban/scriban/security/advisories/GHSA-vhvh-mqjm-8vpg) | `nuget:Scriban, nuget:Scriban.Signed` | high | no CVE anywhere | 0 | 7.6.0 |
| [GHSA-pg73-hfg9-25rc](https://github.com/scriban/scriban/security/advisories/GHSA-pg73-hfg9-25rc) | `nuget:Scriban, nuget:Scriban.Signed` | high | no CVE anywhere | 0 | 7.6.0 |
| [GHSA-rc4x-x73r-6v9w](https://github.com/starman69/mcp-sanitizer/security/advisories/GHSA-rc4x-x73r-6v9w) | `npm:mcp-sanitizer` | high | no CVE anywhere | 0 | 1.4.3 |
| [GHSA-fqrp-x74j-x4r8](https://github.com/starman69/mcp-sanitizer/security/advisories/GHSA-fqrp-x74j-x4r8) | `npm:mcp-sanitizer` | high | no CVE anywhere | 0 | 1.4.3 |
| [GHSA-48p4-xj33-4fw4](https://github.com/actix/actix-web/security/advisories/GHSA-48p4-xj33-4fw4) | `rust:actix-multipart` | high | no CVE anywhere | 0 | 0.8.7 |
| [GHSA-5v87-m222-qr94](https://github.com/HKUDS/nanobot/security/advisories/GHSA-5v87-m222-qr94) | `pip:nanobot-ai` | high | CVE reserved (RBP) (CVE-2026-121864) | 0 | 0.4.1 |
| [GHSA-hg87-wf6q-3m38](https://github.com/HKUDS/nanobot/security/advisories/GHSA-hg87-wf6q-3m38) | `pip:nanobot-ai` | high | CVE reserved (RBP) (CVE-2026-121865) | 0 | 0.4.1 |

…and 62 more (see the feed).

## CVE changes

| Advisory | Change |
|---|---|
| [GHSA-hf2q-xhq6-q394](https://github.com/frappe/erpnext/security/advisories/GHSA-hf2q-xhq6-q394) | new CVE from another CNA: CVE-2026-124313 |
| [GHSA-w264-5p9f-hfwm](https://github.com/frappe/erpnext/security/advisories/GHSA-w264-5p9f-hfwm) | new CVE from another CNA: CVE-2026-124314 |
| [GHSA-w3rc-76j9-46jq](https://github.com/frappe/erpnext/security/advisories/GHSA-w3rc-76j9-46jq) | new CVE from another CNA: CVE-2026-124316 |
| [GHSA-w587-ghqf-6jpp](https://github.com/frappe/erpnext/security/advisories/GHSA-w587-ghqf-6jpp) | new CVE from another CNA: CVE-2026-124315 |
| [GHSA-29q9-p769-j8gq](https://github.com/hickory-dns/hickory-dns/security/advisories/GHSA-29q9-p769-j8gq) | new CVE from another CNA: CVE-2026-123598 |
| [GHSA-2f4m-fq7w-mrgx](https://github.com/hickory-dns/hickory-dns/security/advisories/GHSA-2f4m-fq7w-mrgx) | new CVE from another CNA: CVE-2026-123576 |
| [GHSA-2f75-93c9-xf32](https://github.com/go-vikunja/vikunja/security/advisories/GHSA-2f75-93c9-xf32) | new CVE from another CNA: CVE-2026-123515 |
| [GHSA-2gwf-vxp5-f9v2](https://github.com/OpenIdentityPlatform/OpenAM/security/advisories/GHSA-2gwf-vxp5-f9v2) | new CVE from another CNA: CVE-2026-123546 |
| [GHSA-2hxp-x833-73f7](https://github.com/hickory-dns/hickory-dns/security/advisories/GHSA-2hxp-x833-73f7) | new CVE from another CNA: CVE-2026-123602 |
| [GHSA-2vgh-3wfw-qj7c](https://github.com/hickory-dns/hickory-dns/security/advisories/GHSA-2vgh-3wfw-qj7c) | new CVE from another CNA: CVE-2026-123605 |
| [GHSA-2w9f-9wx8-f5c8](https://github.com/ZcashFoundation/zebra/security/advisories/GHSA-2w9f-9wx8-f5c8) | new CVE from another CNA: CVE-2026-123558 |
| [GHSA-3j2f-qhrc-rjfj](https://github.com/OpenIdentityPlatform/OpenAM/security/advisories/GHSA-3j2f-qhrc-rjfj) | new CVE from another CNA: CVE-2026-123550 |
| [GHSA-3jvh-8vj5-65rq](https://github.com/hickory-dns/hickory-dns/security/advisories/GHSA-3jvh-8vj5-65rq) | new CVE from another CNA: CVE-2026-123600 |
| [GHSA-3r6v-f3jh-vvqm](https://github.com/hickory-dns/hickory-dns/security/advisories/GHSA-3r6v-f3jh-vvqm) | new CVE from another CNA: CVE-2026-123596 |
| [GHSA-3rrq-h284-5vpx](https://github.com/go-vikunja/vikunja/security/advisories/GHSA-3rrq-h284-5vpx) | new CVE from another CNA: CVE-2026-123499 |
| [GHSA-3w89-7rx5-hpwx](https://github.com/hickory-dns/hickory-dns/security/advisories/GHSA-3w89-7rx5-hpwx) | new CVE from another CNA: CVE-2026-123578 |
| [GHSA-3x3m-2j93-w46j](https://github.com/go-vikunja/vikunja/security/advisories/GHSA-3x3m-2j93-w46j) | new CVE from another CNA: CVE-2026-123523 |
| [GHSA-494m-4556-wf5p](https://github.com/imgproxy/imgproxy/security/advisories/GHSA-494m-4556-wf5p) | new CVE from another CNA: CVE-2026-123615 |
| [GHSA-49pj-52x6-8gpj](https://github.com/go-vikunja/vikunja/security/advisories/GHSA-49pj-52x6-8gpj) | new CVE from another CNA: CVE-2026-123521 |
| [GHSA-4jwp-xjwm-333g](https://github.com/hickory-dns/hickory-dns/security/advisories/GHSA-4jwp-xjwm-333g) | new CVE from another CNA: CVE-2026-123603 |
| [GHSA-4qvp-948j-4cgv](https://github.com/go-vikunja/vikunja/security/advisories/GHSA-4qvp-948j-4cgv) | new CVE from another CNA: CVE-2026-123528 |
| [GHSA-4rph-pmrw-mwpw](https://github.com/hickory-dns/hickory-dns/security/advisories/GHSA-4rph-pmrw-mwpw) | new CVE from another CNA: CVE-2026-123574 |
| [GHSA-545c-rm35-2jj2](https://github.com/OpenIdentityPlatform/OpenAM/security/advisories/GHSA-545c-rm35-2jj2) | new CVE from another CNA: CVE-2026-123545 |
| [GHSA-57pw-897j-v4j6](https://github.com/hickory-dns/hickory-dns/security/advisories/GHSA-57pw-897j-v4j6) | new CVE from another CNA: CVE-2026-123590 |
| [GHSA-586f-48mj-3rwr](https://github.com/go-vikunja/vikunja/security/advisories/GHSA-586f-48mj-3rwr) | new CVE from another CNA: CVE-2026-123504 |

…and 155 more.

## Longest waiting, published in the last 90 days

| Advisory | Package | Severity | CVE | Days | Fixed in |
|---|---|---|---|---:|---|
| [GHSA-gpr2-2wqr-7rgp](https://github.com/AiondaDotCom/mcp-ssh/security/advisories/GHSA-gpr2-2wqr-7rgp) | `npm:@aiondadotcom/mcp-ssh` | high | no CVE anywhere | 89 | 1.3.9 |
| [GHSA-pj6m-cx2p-44gh](https://github.com/AiondaDotCom/mcp-ssh/security/advisories/GHSA-pj6m-cx2p-44gh) | `npm:@aiondadotcom/mcp-ssh` | high | no CVE anywhere | 89 | 1.3.9 |
| [GHSA-r9w7-5h94-wq5x](https://github.com/xenocrat/chyrp-lite/security/advisories/GHSA-r9w7-5h94-wq5x) | `composer:xenocrat/chyrp-lite` | high | CVE reserved (RBP) (CVE-2026-53768) | 89 | 2026.02 |
| [GHSA-8h86-c24h-5jp3](https://github.com/xenocrat/chyrp-lite/security/advisories/GHSA-8h86-c24h-5jp3) | `composer:xenocrat/chyrp-lite` | critical | CVE reserved (RBP) (CVE-2026-53767) | 89 | 2026.02 |
| [GHSA-49qj-7hqj-6whp](https://github.com/avo-hq/avo/security/advisories/GHSA-49qj-7hqj-6whp) | `rubygems:avo` | high | no CVE anywhere | 89 | 3.32.2, 4.1.5 |

599 advisories in limbo have waited more than a year.

## Coverage

Watchlist 44,560 repositories; 37,038 up to date on their schedule (daily for repos with an advisory in limbo, every 3 days for other repos with advisories, every 30 days and after each release for the rest); 19,283 checked in the last 24 hours; 37,542 reviewed advisories known. Every number is a floor: the tracker only sees repositories on its watchlist. Version ranges are as entered by maintainers and unreviewed.

_Advisory metadata from published GitHub repository security advisories and the GitHub Advisory Database (https://github.com/advisories, CC BY 4.0); CVE state from CVE Services; OSV.dev; NVD API (this product uses the NVD API but is not endorsed or certified by the NVD). Compiled by Limbowatch (https://limbo.watch), CC BY 4.0._
