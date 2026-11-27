# Limbo Tracker daily report — 2026-11-27

Generated 2026-11-27 17:08:26 UTC; changes since 2026-11-26 17:22:40 UTC.

## Now

- **12,647 advisories in limbo** (+177 since the last report: 171 newly published, 4 older ones found for the first time, 0 left limbo, 2 moved in from likely permanent): published by maintainers on GitHub, in ecosystems GitHub reviews, but not yet in GitHub's reviewed database or OSV.
  - 7,475 with no CVE anywhere · 557 citing a CVE that's still only reserved · 1,653 with a CVE from another CNA they don't cite
  - severity: 1,120 critical, 4,903 high, 5,360 medium, 1,264 low · median wait so far 52.4 days
- **16,750 more are likely permanent** (+85 since the last report: 87 newly published, 0 older ones found for the first time, 0 left limbo, 2 moved to the in-limbo count): in ecosystems GitHub doesn't review, so GitHub-based scanners will probably never see them.

## Since the last report

- **171 newly published** advisories entered limbo.
- 4 older advisories were found for the first time (1 in newly watched repos).
- **Left limbo** (likely permanent included): 0 reviewed by GitHub, 0 found to duplicate a reviewed advisory, 0 withdrawn or unpublished. **GitHub reviewed no advisories at all in this period.**
- **CVE changes:** 27 (2 reserved CVEs published, 24 new CVEs from other CNAs).

## Newly published, in limbo

| Advisory | Package | Severity | CVE | Days | Fixed in |
|---|---|---|---|---:|---|
| [GHSA-wwwx-gph4-x9hq](https://github.com/katalyst/koi/security/advisories/GHSA-wwwx-gph4-x9hq) | `rubygems:katalyst-koi` | critical | no CVE anywhere | 1 | `5.13.3` |
| [GHSA-7w8w-q94c-cq62](https://github.com/SignalK/signalk-server/security/advisories/GHSA-7w8w-q94c-cq62) | `npm:signalk-server` | critical | no CVE anywhere | 0 | `2.38.0` |
| [GHSA-fvhv-5r5f-xx7c](https://github.com/canonical/lxd/security/advisories/GHSA-fvhv-5r5f-xx7c) | `go:github.com/canonical/lxd` | critical | CVE published, cited (`CVE-2026-137114`) | 0 | `6.10.2, 5.21.10, 5.0.12, 4.0.16` |
| [GHSA-8gf7-9vvc-x36m](https://github.com/canonical/lxd/security/advisories/GHSA-8gf7-9vvc-x36m) | `go:github.com/canonical/lxd` | critical | CVE published, cited (`CVE-2026-136972`) | 0 | `4.0.16, 5.0.12, 5.21.10, 6.10.2` |
| [GHSA-hfwr-h8hx-pw2g](https://github.com/canonical/lxd/security/advisories/GHSA-hfwr-h8hx-pw2g) | `go:github.com/canonical/lxd` | critical | CVE published, cited (`CVE-2026-115843`) | 0 | `4.0.16, 5.0.12, 5.21.10, 6.10.2` |
| [GHSA-h48h-p7xx-x84p](https://github.com/canonical/lxd/security/advisories/GHSA-h48h-p7xx-x84p) | `go:github.com/canonical/lxd` | critical | CVE published, cited (`CVE-2026-136974`) | 0 | `6.10.2, 5.21.10, 5.0.12, 4.0.16` |
| [GHSA-6g53-h3wf-jm7j](https://github.com/walinejs/waline/security/advisories/GHSA-6g53-h3wf-jm7j) | `npm:@waline/vercel` | critical | no CVE anywhere | 0 | `1.43.7` |
| [GHSA-28m6-7v43-rr8m](https://github.com/lxc/incus/security/advisories/GHSA-28m6-7v43-rr8m) | `go:github.com/lxc/incus/v7/cmd/incusd` | critical | no CVE anywhere | 0 | `v7.7.0` |
| [GHSA-42x8-664j-84w8](https://github.com/lxc/incus/security/advisories/GHSA-42x8-664j-84w8) | `go:github.com/lxc/incus/v7/cmd/incusd` | critical | no CVE anywhere | 0 | `v7.7.0` |
| [GHSA-4375-qwr5-8vjj](https://github.com/lxc/incus/security/advisories/GHSA-4375-qwr5-8vjj) | `go:github.com/lxc/incus/v7/cmd/incusd` | critical | no CVE anywhere | 0 | `v7.7.0` |
| [GHSA-992p-fqxp-43w6](https://github.com/lxc/incus/security/advisories/GHSA-992p-fqxp-43w6) | `go:github.com/lxc/incus/v7/cmd/incusd` | critical | no CVE anywhere | 0 | `v7.7.0` |
| [GHSA-9m5m-cr24-m367](https://github.com/lxc/incus/security/advisories/GHSA-9m5m-cr24-m367) | `go:github.com/lxc/incus/v7/cmd/incusd` | critical | no CVE anywhere | 0 | `v7.7.0` |
| [GHSA-cm79-v2v8-5grh](https://github.com/lxc/incus/security/advisories/GHSA-cm79-v2v8-5grh) | `go:github.com/lxc/incus/v7/cmd/incusd` | critical | no CVE anywhere | 0 | `v7.7.0` |
| [GHSA-fg2p-r659-c4q8](https://github.com/lxc/incus/security/advisories/GHSA-fg2p-r659-c4q8) | `go:github.com/lxc/incus/v7/cmd/incusd` | critical | no CVE anywhere | 0 | `v7.7.0` |
| [GHSA-hm9p-jjr8-3jp8](https://github.com/lxc/incus/security/advisories/GHSA-hm9p-jjr8-3jp8) | `go:github.com/lxc/incus/v7/cmd/incusd` | critical | no CVE anywhere | 0 | `v7.7.0` |
| [GHSA-hw96-p258-g4jg](https://github.com/lxc/incus/security/advisories/GHSA-hw96-p258-g4jg) | `go:github.com/lxc/incus/v7/cmd/incusd` | critical | no CVE anywhere | 0 | `v7.7.0` |
| [GHSA-mmh3-jfjc-6vc2](https://github.com/lxc/incus/security/advisories/GHSA-mmh3-jfjc-6vc2) | `go:github.com/lxc/incus/v7/cmd/incusd` | critical | no CVE anywhere | 0 | `v7.7.0` |
| [GHSA-xw8w-vwh3-9w5v](https://github.com/lxc/incus/security/advisories/GHSA-xw8w-vwh3-9w5v) | `go:github.com/lxc/incus/v7/cmd/incusd` | critical | no CVE anywhere | 0 | `v7.7.0` |
| [GHSA-58vc-fxv9-grp7](https://github.com/lxc/incus/security/advisories/GHSA-58vc-fxv9-grp7) | `go:github.com/lxc/incus/v6/cmd/incusd` | critical | no CVE anywhere | 0 | `v6.0.8` |
| [GHSA-jcv5-c6xq-3p9g](https://github.com/siyuan-note/siyuan/security/advisories/GHSA-jcv5-c6xq-3p9g) | `go:github.com/siyuan-note/siyuan` | critical | no CVE anywhere | 0 | `3.9.0` |
| [GHSA-2c63-crpq-2pr2](https://github.com/python-social-auth/social-core/security/advisories/GHSA-2c63-crpq-2pr2) | `pip:social-auth-core` | critical | no CVE anywhere | 0 | `7.3.0` |
| [GHSA-v2r4-wqw2-5562](https://github.com/python-social-auth/social-core/security/advisories/GHSA-v2r4-wqw2-5562) | `pip:social-auth-core` | critical | no CVE anywhere | 0 | `7.3.0` |
| [GHSA-hjv8-29vw-3xrr](https://github.com/python-social-auth/social-core/security/advisories/GHSA-hjv8-29vw-3xrr) | `pip:social-auth-core` | critical | no CVE anywhere | 0 | `7.3.0` |
| [GHSA-f5r3-7fq4-pmfw](https://github.com/simplesamlphp/simplesamlphp/security/advisories/GHSA-f5r3-7fq4-pmfw) | `composer:simplesamlphp/simplesamlphp` | high | no CVE anywhere | 1 | `2.5.5, 2.4.12` |
| [GHSA-35g3-g3m8-4xvv](https://github.com/grosser/fast_gettext/security/advisories/GHSA-35g3-g3m8-4xvv) | `rubygems:fast_gettext` | high | no CVE anywhere | 1 | `4.3.0` |

…and 146 more: [the tracker](https://limbo.watch/tracker/) lists them all, newest first.

## CVE changes

| Advisory | Change |
|---|---|
| [GHSA-5jrj-948r-2wx6](https://github.com/flatpak/flatpak/security/advisories/GHSA-5jrj-948r-2wx6) | CVE-2026-133845 RESERVED -> PUBLISHED |
| [GHSA-p4mw-6jfq-r82r](https://github.com/flatpak/flatpak/security/advisories/GHSA-p4mw-6jfq-r82r) | CVE-2026-133842 RESERVED -> PUBLISHED |
| [GHSA-59mq-hx4p-fw48](https://github.com/HarnessRouter/harnessrouter/security/advisories/GHSA-59mq-hx4p-fw48) | cites CVE-2026-136182 (was none) |
| [GHSA-3x7w-j75x-ppq5](https://github.com/sparkle-project/Sparkle/security/advisories/GHSA-3x7w-j75x-ppq5) | new CVE from another CNA: CVE-2026-137938 |
| [GHSA-4v99-qgq9-6pxp](https://github.com/sparkle-project/Sparkle/security/advisories/GHSA-4v99-qgq9-6pxp) | new CVE from another CNA: CVE-2026-137939 |
| [GHSA-27wf-8499-p469](https://github.com/WWBN/AVideo/security/advisories/GHSA-27wf-8499-p469) | new CVE from another CNA: CVE-2026-137956 |
| [GHSA-32pj-j526-963j](https://github.com/LibreChat-AI/LibreChat/security/advisories/GHSA-32pj-j526-963j) | new CVE from another CNA: CVE-2026-137656 |
| [GHSA-4xqp-vfh8-4fv7](https://github.com/Budibase/budibase/security/advisories/GHSA-4xqp-vfh8-4fv7) | new CVE from another CNA: CVE-2026-137961 |
| [GHSA-527h-2p2v-g388](https://github.com/michaelrsweet/pdfio/security/advisories/GHSA-527h-2p2v-g388) | new CVE from another CNA: CVE-2026-137937 |
| [GHSA-74h3-686h-cmvf](https://github.com/ToolJet/ToolJet/security/advisories/GHSA-74h3-686h-cmvf) | new CVE from another CNA: CVE-2026-137964 |
| [GHSA-8wqw-xg9x-89h8](https://github.com/Budibase/budibase/security/advisories/GHSA-8wqw-xg9x-89h8) | new CVE from another CNA: CVE-2026-137962 |
| [GHSA-c772-hjfp-gfc2](https://github.com/n8n-io/n8n/security/advisories/GHSA-c772-hjfp-gfc2) | new CVE from another CNA: CVE-2026-137957 |
| [GHSA-fh5h-x2xg-6gq8](https://github.com/ToolJet/ToolJet/security/advisories/GHSA-fh5h-x2xg-6gq8) | new CVE from another CNA: CVE-2026-137970 |
| [GHSA-g333-hr44-g82p](https://github.com/n8n-io/n8n/security/advisories/GHSA-g333-hr44-g82p) | new CVE from another CNA: CVE-2026-137958 |
| [GHSA-g6p9-6gm4-cj6m](https://github.com/payloadcms/payload/security/advisories/GHSA-g6p9-6gm4-cj6m) | new CVE from another CNA: CVE-2026-137936 |
| [GHSA-h59h-rf6m-7jp5](https://github.com/n8n-io/n8n/security/advisories/GHSA-h59h-rf6m-7jp5) | new CVE from another CNA: CVE-2026-137959 |
| [GHSA-hhvf-v27f-g7c7](https://github.com/heymrun/heym/security/advisories/GHSA-hhvf-v27f-g7c7) | new CVE from another CNA: CVE-2026-137973 |
| [GHSA-m2mm-7xvw-9623](https://github.com/Budibase/budibase/security/advisories/GHSA-m2mm-7xvw-9623) | new CVE from another CNA: CVE-2026-137960 |
| [GHSA-qmm2-755w-926f](https://github.com/ToolJet/ToolJet/security/advisories/GHSA-qmm2-755w-926f) | new CVE from another CNA: CVE-2026-137967 |
| [GHSA-qw9q-v8f8-v2pj](https://github.com/ToolJet/ToolJet/security/advisories/GHSA-qw9q-v8f8-v2pj) | new CVE from another CNA: CVE-2026-137971 |
| [GHSA-r38q-3g6w-gc58](https://github.com/LibreChat-AI/LibreChat/security/advisories/GHSA-r38q-3g6w-gc58) | new CVE from another CNA: CVE-2026-137588 |
| [GHSA-v64h-hqhj-2h7r](https://github.com/ToolJet/ToolJet/security/advisories/GHSA-v64h-hqhj-2h7r) | new CVE from another CNA: CVE-2026-137965 |
| [GHSA-v93v-c4v6-cqw9](https://github.com/ToolJet/ToolJet/security/advisories/GHSA-v93v-c4v6-cqw9) | new CVE from another CNA: CVE-2026-137968 |
| [GHSA-vcr4-8492-6c9x](https://github.com/ToolJet/ToolJet/security/advisories/GHSA-vcr4-8492-6c9x) | new CVE from another CNA: CVE-2026-137969 |
| [GHSA-wm89-9qp9-fmp8](https://github.com/ToolJet/ToolJet/security/advisories/GHSA-wm89-9qp9-fmp8) | new CVE from another CNA: CVE-2026-137966 |

…and 2 more.

## Longest waiting, published in the last 90 days

| Advisory | Package | Severity | CVE | Days | Fixed in |
|---|---|---|---|---:|---|
| [GHSA-3886-rcwf-vqjh](https://github.com/roxy-wi/roxy-wi/security/advisories/GHSA-3886-rcwf-vqjh) | `pip:roxy-wi` | critical | CVE reserved (RBP) (`CVE-2026-83820`) | 89 | `–` |
| [GHSA-3wqc-vcrv-gfgr](https://github.com/roxy-wi/roxy-wi/security/advisories/GHSA-3wqc-vcrv-gfgr) | `pip:roxy-wi` | critical | CVE reserved (RBP) (`CVE-2026-83819`) | 89 | `–` |
| [GHSA-5hgx-fmqx-rcg8](https://github.com/roxy-wi/roxy-wi/security/advisories/GHSA-5hgx-fmqx-rcg8) | `pip:roxy-wi` | critical | CVE reserved (RBP) (`CVE-2026-83818`) | 89 | `–` |
| [GHSA-9xc3-25r9-425m](https://github.com/roxy-wi/roxy-wi/security/advisories/GHSA-9xc3-25r9-425m) | `pip:roxy-wi` | high | CVE reserved (RBP) (`CVE-2026-83821`) | 89 | `–` |
| [GHSA-frpv-2xgv-wxpq](https://github.com/go-gitea/gitea/security/advisories/GHSA-frpv-2xgv-wxpq) | `go:gitea.dev` | medium | CVE published, cited (`CVE-2026-78433`) | 89 | `1.27.3` |

624 advisories in limbo have waited more than a year.

## Coverage

Watchlist 68,203 repositories; 68,203 up to date on their schedule (daily for repos with an advisory in limbo, every 3 days for other repos with advisories, every 30 days and after each release for the rest); 6,822 checked in the last 24 hours; 38,014 reviewed advisories known. Every number is a floor: the tracker only sees repositories on its watchlist. Version ranges are as entered by maintainers and unreviewed.

_Advisory metadata from published GitHub repository security advisories and the GitHub Advisory Database (https://github.com/advisories, CC BY 4.0); CVE state from CVE Services; OSV.dev; NVD API (this product uses the NVD API but is not endorsed or certified by the NVD). Compiled by Limbowatch (https://limbo.watch), CC BY 4.0._
