# Limbo Tracker daily report — 2026-11-23

Generated 2026-11-23 18:49:38 UTC; changes since 2026-11-22 15:07:14 UTC.

## Now

- **11,860 advisories in limbo** (+164 since the last report: 158 newly published, 2 older ones found for the first time, 2 left limbo, 11 moved in from likely permanent, 5 moved to likely permanent): published by maintainers on GitHub, in ecosystems GitHub reviews, but not yet in GitHub's reviewed database or OSV.
  - 6,931 with no CVE anywhere · 535 citing a CVE that's still only reserved · 1,549 with a CVE from another CNA they don't cite
  - severity: 1,063 critical, 4,600 high, 5,019 medium, 1,178 low · median wait so far 53.9 days
- **16,377 more are likely permanent** (+167 since the last report: 92 newly published, 81 older ones found for the first time, 0 left limbo, 5 moved in from the in-limbo count, 11 moved to the in-limbo count): in ecosystems GitHub doesn't review, so GitHub-based scanners will probably never see them.

## Since the last report

- **158 newly published** advisories entered limbo.
- 2 older advisories were found for the first time (0 in newly watched repos).
- **Left limbo** (likely permanent included): 2 reviewed by GitHub, 0 found to duplicate a reviewed advisory, 0 withdrawn or unpublished. GitHub reviewed 3 advisories in all in this period, from any repository.
- **CVE changes:** 33 (1 reserved CVEs published, 27 new CVEs from other CNAs).

## Newly published, in limbo

| Advisory | Package | Severity | CVE | Days | Fixed in |
|---|---|---|---|---:|---|
| [GHSA-9hh3-mgwh-gpj4](https://github.com/nette/latte/security/advisories/GHSA-9hh3-mgwh-gpj4) | `composer:latte/latte` | critical | no CVE anywhere | 0 | `3.1.10, 3.0.28` |
| [GHSA-jpg6-j246-v2jh](https://github.com/froxlor/froxlor/security/advisories/GHSA-jpg6-j246-v2jh) | `composer:froxlor/froxlor` | critical | no CVE anywhere | 0 | `2.3.17` |
| [GHSA-phqc-rj3p-h366](https://github.com/froxlor/froxlor/security/advisories/GHSA-phqc-rj3p-h366) | `composer:froxlor/froxlor` | critical | no CVE anywhere | 0 | `2.3.17` |
| [GHSA-h3wg-3xfc-p3hh](https://github.com/vmoranv/jshookmcp/security/advisories/GHSA-h3wg-3xfc-p3hh) | `npm:@jshookmcp/jshook` | critical | no CVE anywhere | 0 | `0.4.9` |
| [GHSA-h657-8j5c-6jfx](https://github.com/refinery/refinerycms/security/advisories/GHSA-h657-8j5c-6jfx) | `rubygems:refinerycms-dragonfly, rubygems:refinerycms-reso…` | high | no CVE anywhere | 1 | `4.1.1, 4.0.4, 1.1.1, 1.0.2` |
| [GHSA-wxg8-cr2g-cjwc](https://github.com/aiortc/aioquic/security/advisories/GHSA-wxg8-cr2g-cjwc) | `pip:aioquic` | high | no CVE anywhere | 1 | `1.9.0` |
| [GHSA-mjr6-3h9r-qpmv](https://github.com/aiortc/aioquic/security/advisories/GHSA-mjr6-3h9r-qpmv) | `pip:aioquic` | high | no CVE anywhere | 1 | `1.9.0` |
| [GHSA-8q7m-77xq-6wgc](https://github.com/jupytext/jupytext/security/advisories/GHSA-8q7m-77xq-6wgc) | `jupytext/jupytext` | high | no CVE anywhere | 1 | `acb4447275dbc5b341adf7cb387c13ef19cdb4e9` |
| [GHSA-54pj-4qc4-fgmw](https://github.com/ssato/python-anyconfig/security/advisories/GHSA-54pj-4qc4-fgmw) | `pip:anyconfig` | high | no CVE anywhere | 1 | `0.16.1` |
| [GHSA-whf5-5qcj-v9m8](https://github.com/ag2ai/ag2/security/advisories/GHSA-whf5-5qcj-v9m8) | `pip:ag2, pip:autogen` | high | no CVE anywhere | 1 | `1.3.4` |
| [GHSA-3r6w-7pcg-c4x2](https://github.com/ag2ai/ag2/security/advisories/GHSA-3r6w-7pcg-c4x2) | `pip:ag2` | high | no CVE anywhere | 1 | `1.3.4` |
| [GHSA-hvp5-3mrg-q5hg](https://github.com/chimurai/http-proxy-middleware/security/advisories/GHSA-hvp5-3mrg-q5hg) | `npm:http-proxy-middleware` | high | no CVE anywhere | 0 | `2.0.12, 3.0.11, 4.2.2` |
| [GHSA-7267-5929-54c6](https://github.com/john-broadway/pacioli/security/advisories/GHSA-7267-5929-54c6) | `pip:pacioli-guard` | high | no CVE anywhere | 0 | `0.18.0` |
| [GHSA-vw33-xvhq-6vvp](https://github.com/pdovhomilja/nextcrm-app/security/advisories/GHSA-vw33-xvhq-6vvp) | `npm:nextcrm-app` | high | no CVE anywhere | 0 | `0.42.1` |
| [GHSA-r7f5-r6gv-p5q7](https://github.com/pdovhomilja/nextcrm-app/security/advisories/GHSA-r7f5-r6gv-p5q7) | `npm:nextcrm-app` | high | no CVE anywhere | 0 | `0.42.1` |
| [GHSA-34m8-8x26-hhf7](https://github.com/WWBN/AVideo/security/advisories/GHSA-34m8-8x26-hhf7) | `composer:wwbn/avideo` | high | no CVE anywhere | 0 | `29.9.0` |
| [GHSA-vpqj-26g5-4qqm](https://github.com/simplesamlphp/saml2/security/advisories/GHSA-vpqj-26g5-4qqm) | `composer:simplesamlphp/saml2, composer:simplesamlphp/saml…` | high | no CVE anywhere | 0 | `–` |
| [GHSA-vwq2-6445-7w22](https://github.com/xyproto/algernon/security/advisories/GHSA-vwq2-6445-7w22) | `go:github.com/xyproto/algernon` | high | no CVE anywhere | 0 | `1.18.0` |
| [GHSA-7395-733q-q47j](https://github.com/nette/latte/security/advisories/GHSA-7395-733q-q47j) | `composer:latte/latte` | high | no CVE anywhere | 0 | `3.1.10, 3.0.28` |
| [GHSA-4c7q-gfc8-47vh](https://github.com/GitoxideLabs/gitoxide/security/advisories/GHSA-4c7q-gfc8-47vh) | `rust:gix, rust:gix-config, rust:gix-submodule, rust:gix-v…` | high | no CVE anywhere | 0 | `> 0.90.0, > 0.36.1, > 0.62.2, > 0.13.1` |
| [GHSA-vgc5-jvp9-hxjm](https://github.com/froxlor/froxlor/security/advisories/GHSA-vgc5-jvp9-hxjm) | `composer:froxlor/froxlor` | high | no CVE anywhere | 0 | `2.3.17` |
| [GHSA-c3p2-6762-cf9j](https://github.com/goshs-labs/goshs/security/advisories/GHSA-c3p2-6762-cf9j) | `go:goshs.de/goshs/v2` | high | no CVE anywhere | 0 | `v2.1.8` |
| [GHSA-qwpj-g46h-59wx](https://github.com/goshs-labs/goshs/security/advisories/GHSA-qwpj-g46h-59wx) | `go:goshs.de/goshs/v2` | high | no CVE anywhere | 0 | `v2.1.8` |
| [GHSA-3w28-5hpf-fxgx](https://github.com/ether/etherpad/security/advisories/GHSA-3w28-5hpf-fxgx) | `npm:ep_etherpad-lite` | high | no CVE anywhere | 0 | `3.3.22` |
| [GHSA-q62j-wr4j-w9m8](https://github.com/ether/etherpad/security/advisories/GHSA-q62j-wr4j-w9m8) | `npm:ep_etherpad-lite` | high | no CVE anywhere | 0 | `3.3.22` |

…and 133 more: [the tracker](https://limbo.watch/tracker/) lists them all, newest first.

## CVE changes

| Advisory | Change |
|---|---|
| [GHSA-jcrj-xmp8-8hqf](https://github.com/rsyslog/rsyslog/security/advisories/GHSA-jcrj-xmp8-8hqf) | CVE-2026-129830 RESERVED -> PUBLISHED |
| [GHSA-q9rj-8p2j-whg4](https://github.com/seaweedfs/seaweedfs/security/advisories/GHSA-q9rj-8p2j-whg4) | cites CVE-2026-133464 (was none) |
| [GHSA-hrp4-xjp5-cq7j](https://github.com/AcademySoftwareFoundation/openexr/security/advisories/GHSA-hrp4-xjp5-cq7j) | cites CVE-2026-133466 (was none) |
| [GHSA-56xw-p9qm-r437](https://github.com/nicolargo/glances/security/advisories/GHSA-56xw-p9qm-r437) | cites CVE-2026-133465 (was none) |
| [GHSA-hgmx-cr7v-p3c7](https://github.com/notepad-plus-plus/notepad-plus-plus/security/advisories/GHSA-hgmx-cr7v-p3c7) | cites CVE-2026-134011 (was none) |
| [GHSA-qmx6-fpcw-q3xg](https://github.com/seaweedfs/seaweedfs/security/advisories/GHSA-qmx6-fpcw-q3xg) | cites CVE-2026-133463 (was none) |
| [GHSA-3c52-7fc8-c39j](https://github.com/kerberos-io/agent/security/advisories/GHSA-3c52-7fc8-c39j) | new CVE from another CNA: CVE-2026-135208 |
| [GHSA-6hph-c9x9-4mcv](https://github.com/WeblateOrg/weblate/security/advisories/GHSA-6hph-c9x9-4mcv) | new CVE from another CNA: CVE-2026-134838 |
| [GHSA-p5q8-2wc4-g5hg](https://github.com/tolgee/tolgee-platform/security/advisories/GHSA-p5q8-2wc4-g5hg) | new CVE from another CNA: CVE-2026-135154 |
| [GHSA-3fwm-h59w-j268](https://github.com/hedgedoc/hedgedoc/security/advisories/GHSA-3fwm-h59w-j268) | new CVE from another CNA: CVE-2026-134794 |
| [GHSA-67p7-xj24-jfm9](https://github.com/faye/permessage-deflate-node/security/advisories/GHSA-67p7-xj24-jfm9) | new CVE from another CNA: CVE-2026-134813 |
| [GHSA-9mj6-f434-pgcg](https://github.com/sigstore/sigstore-js/security/advisories/GHSA-9mj6-f434-pgcg) | new CVE from another CNA: CVE-2026-134816 |
| [GHSA-cp73-7mxf-xj5j](https://github.com/sgoudelis/ground-station/security/advisories/GHSA-cp73-7mxf-xj5j) | new CVE from another CNA: CVE-2026-134764 |
| [GHSA-g6q3-mf7c-27jh](https://github.com/getkirby/kirby/security/advisories/GHSA-g6q3-mf7c-27jh) | new CVE from another CNA: CVE-2026-134765 |
| [GHSA-h4v2-5hq4-wc2g](https://github.com/electerm/electerm/security/advisories/GHSA-h4v2-5hq4-wc2g) | new CVE from another CNA: CVE-2026-134793 |
| [GHSA-q8xp-3229-5p37](https://github.com/TandoorRecipes/recipes/security/advisories/GHSA-q8xp-3229-5p37) | new CVE from another CNA: CVE-2026-134834 |
| [GHSA-qvxq-53gh-64f6](https://github.com/zitadel/zitadel/security/advisories/GHSA-qvxq-53gh-64f6) | new CVE from another CNA: CVE-2026-135175 |
| [GHSA-rv37-gcpm-x55f](https://github.com/lissy93/dashy/security/advisories/GHSA-rv37-gcpm-x55f) | new CVE from another CNA: CVE-2026-134836 |
| [GHSA-xmxc-6c22-m377](https://github.com/keichi/binary-parser/security/advisories/GHSA-xmxc-6c22-m377) | new CVE from another CNA: CVE-2026-134814 |
| [GHSA-348f-9mg8-rhv4](https://github.com/umbraco/Umbraco-CMS/security/advisories/GHSA-348f-9mg8-rhv4) | new CVE from another CNA: CVE-2026-135166 |
| [GHSA-6c57-xm2f-23fg](https://github.com/portainer/portainer/security/advisories/GHSA-6c57-xm2f-23fg) | new CVE from another CNA: CVE-2026-134804 |
| [GHSA-6h5x-f3qr-cp23](https://github.com/oasdiff/oasdiff/security/advisories/GHSA-6h5x-f3qr-cp23) | new CVE from another CNA: CVE-2026-134818 |
| [GHSA-76c4-7552-ffhv](https://github.com/FreeRDP/FreeRDP/security/advisories/GHSA-76c4-7552-ffhv) | new CVE from another CNA: CVE-2026-134763 |
| [GHSA-qwhj-rchj-58mg](https://github.com/penpot/penpot/security/advisories/GHSA-qwhj-rchj-58mg) | new CVE from another CNA: CVE-2026-134828 |
| [GHSA-qxx6-9833-92r5](https://github.com/nektos/act/security/advisories/GHSA-qxx6-9833-92r5) | new CVE from another CNA: CVE-2026-134824 |

…and 8 more.

## Longest waiting, published in the last 90 days

| Advisory | Package | Severity | CVE | Days | Fixed in |
|---|---|---|---|---:|---|
| [GHSA-r4c4-vmqp-vxf2](https://github.com/dnnsoftware/Dnn.Platform/security/advisories/GHSA-r4c4-vmqp-vxf2) | `nuget:DotNetNuke.Core` | medium | no CVE anywhere | 89 | `10.3.3` |
| [GHSA-683v-j9wx-qrw3](https://github.com/mesop-dev/mesop/security/advisories/GHSA-683v-j9wx-qrw3) | `pip:mesop` | critical | no CVE anywhere | 89 | `1.3.5` |
| [GHSA-fpr5-67pq-3hf5](https://github.com/dnnsoftware/Dnn.Platform/security/advisories/GHSA-fpr5-67pq-3hf5) | `nuget:DotNetNuke.Core` | critical | no CVE anywhere | 89 | `10.3.3` |
| [GHSA-hxc3-xv8x-w2g3](https://github.com/dnnsoftware/Dnn.Platform/security/advisories/GHSA-hxc3-xv8x-w2g3) | `nuget:DotNetNuke.Core` | high | no CVE anywhere | 89 | `10.3.3` |
| [GHSA-9574-292w-9wmw](https://github.com/go-gitea/gitea/security/advisories/GHSA-9574-292w-9wmw) | `go:code.gitea.io/gitea` | medium | CVE published, cited (`CVE-2026-25946`) | 89 | `1.27.0` |

624 advisories in limbo have waited more than a year.

## Coverage

Watchlist 68,047 repositories; 68,047 up to date on their schedule (daily for repos with an advisory in limbo, every 3 days for other repos with advisories, every 30 days and after each release for the rest); 5,666 checked in the last 24 hours; 37,992 reviewed advisories known. Every number is a floor: the tracker only sees repositories on its watchlist. Version ranges are as entered by maintainers and unreviewed.

_Advisory metadata from published GitHub repository security advisories and the GitHub Advisory Database (https://github.com/advisories, CC BY 4.0); CVE state from CVE Services; OSV.dev; NVD API (this product uses the NVD API but is not endorsed or certified by the NVD). Compiled by Limbowatch (https://limbo.watch), CC BY 4.0._
