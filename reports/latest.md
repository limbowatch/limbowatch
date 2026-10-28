# Limbo Tracker daily report — 2026-10-28

Generated 2026-10-28 09:53:48 UTC; changes since 2026-10-28 02:37:54 UTC.

## Now

- **6,124 advisories in limbo** (+6,099 since the last report): published by maintainers on GitHub, in ecosystems GitHub reviews, but not yet in GitHub's reviewed database or OSV.
  - 3,355 with no CVE anywhere · 469 citing a CVE that's still only reserved · 982 with a CVE from another CNA they don't cite
  - severity: 533 critical, 2,477 high, 2,531 medium, 583 low · median wait so far 47.4 days
- **3,416 more are likely permanent** (+3,416 since the last report): in ecosystems GitHub doesn't review, so GitHub-based scanners will probably never see them.

## Since the last report

- **282 newly published** advisories entered limbo.
- 5,817 older advisories were found for the first time (newly watched repos).
- **Left limbo:** 0 reviewed by GitHub, 0 found to duplicate a reviewed advisory, 0 withdrawn or unpublished.
- **CVE changes:** 0.

## Newly published, in limbo

| Advisory | Package | Severity | CVE | Days | Fixed in |
|---|---|---|---|---:|---|
| [GHSA-mxjf-pghx-h299](https://github.com/mautic/mautic/security/advisories/GHSA-mxjf-pghx-h299) | `composer:mautic/core` | critical | CVE published, cited (CVE-2026-115188) | 1 | 7.2.2 |
| [GHSA-grrq-9gq2-vm55](https://github.com/OpenMage/magento-lts/security/advisories/GHSA-grrq-9gq2-vm55) | `composer:openmage/magento-lts` | critical | no CVE anywhere | 1 | 20.18.2, 20.19.0; 21.0.0-beta3 |
| [GHSA-2xm2-c8xx-p9vh](https://github.com/grpc/grpc/security/advisories/GHSA-2xm2-c8xx-p9vh) | `pip:grpcio` | critical | no CVE anywhere | 1 | 1.84.1 |
| [GHSA-6h42-57hq-9746](https://github.com/fastify/fastify-express/security/advisories/GHSA-6h42-57hq-9746) | `npm:@fastify/express` | critical | CVE published, cited (CVE-2026-112362) | 1 | 4.0.9 |
| [GHSA-mc8w-wjhw-45x5](https://github.com/ether/etherpad/security/advisories/GHSA-mc8w-wjhw-45x5) | `npm:etherpad-lite` | critical | CVE reserved (RBP) (CVE-2026-114516) | 0 | 3.3.3 |
| [GHSA-w4c7-34wj-hqm8](https://github.com/BerriAI/litellm/security/advisories/GHSA-w4c7-34wj-hqm8) | `pip:litellm` | critical | no CVE anywhere | 0 | 1.103.10; 1.104.8; 1.105.6; 1.106.5 |
| [GHSA-5wxg-mj2c-p9p2](https://github.com/free5gc/free5gc/security/advisories/GHSA-5wxg-mj2c-p9p2) | `go:github.com/free5gc/bsf` | critical | CVE reserved (RBP) (CVE-2026-115926) | 0 | – |
| [GHSA-89p3-fcch-88ph](https://github.com/nltk/nltk/security/advisories/GHSA-89p3-fcch-88ph) | `pip:nltk` | high | no CVE anywhere | 1 | 3.10.4 |
| [GHSA-7mxv-7h3q-9324](https://github.com/nltk/nltk/security/advisories/GHSA-7mxv-7h3q-9324) | `pip:nltk` | high | no CVE anywhere | 1 | 3.10.4 |
| [GHSA-h7pm-79gc-8867](https://github.com/mautic/mautic/security/advisories/GHSA-h7pm-79gc-8867) | `composer:mautic/core` | high | CVE published, cited (CVE-2026-115189) | 1 | 5.2.12; 6.0.10; 7.2.2 |
| [GHSA-5r63-8h35-j3mw](https://github.com/mautic/mautic/security/advisories/GHSA-5r63-8h35-j3mw) | `composer:mautic/core` | high | CVE published, cited (CVE-2026-115190) | 1 | 5.2.12; 6.0.10; 7.2.0 |
| [GHSA-fj8v-c9c3-7q26](https://github.com/mautic/mautic/security/advisories/GHSA-fj8v-c9c3-7q26) | `composer:mautic/core` | high | CVE published, cited (CVE-2026-115191) | 1 | 5.2.12; 6.0.10; 7.2.2 |
| [GHSA-qpmx-7pq3-5q2v](https://github.com/mautic/mautic/security/advisories/GHSA-qpmx-7pq3-5q2v) | `composer:mautic/core` | high | CVE published, cited (CVE-2026-115192) | 1 | 5.2.12; 6.0.10; 7.2.2 |
| [GHSA-3295-vq3p-93rw](https://github.com/mautic/mautic/security/advisories/GHSA-3295-vq3p-93rw) | `composer:mautic/core` | high | CVE published, cited (CVE-2026-115193) | 1 | 7.2.2 |
| [GHSA-hm48-5chc-q85f](https://github.com/fedora-python/lxml_html_clean/security/advisories/GHSA-hm48-5chc-q85f) | `pip:lxml_html_clean` | high | no CVE anywhere | 1 | 0.4.6 |
| [GHSA-5xjx-9qx6-jcrv](https://github.com/anthropics/claude-code/security/advisories/GHSA-5xjx-9qx6-jcrv) | `npm:@anthropic-ai/claude-code` | high | CVE reserved (RBP) (CVE-2026-88968) | 1 | 2.1.251 |
| [GHSA-945x-c8pg-7g7f](https://github.com/ts-graphviz/ts-graphviz/security/advisories/GHSA-945x-c8pg-7g7f) | `npm:@ts-graphviz/ast, npm:ts-graphviz` | high | no CVE anywhere | 1 | 3.0.10; 3.0.12 |
| [GHSA-c3g7-2pg5-qvwh](https://github.com/mtrudel/bandit/security/advisories/GHSA-c3g7-2pg5-qvwh) | `erlang:bandit` | high | CVE published, cited (CVE-2026-108525) | 1 | 1.14.0 |
| [GHSA-p2qv-vx88-385x](https://github.com/mtrudel/bandit/security/advisories/GHSA-p2qv-vx88-385x) | `erlang:bandit` | high | CVE published, cited (CVE-2026-115269) | 1 | 1.14.0 |
| [GHSA-47x4-3fxf-82fr](https://github.com/mtrudel/bandit/security/advisories/GHSA-47x4-3fxf-82fr) | `erlang:bandit` | high | CVE published, cited (CVE-2026-110499) | 1 | 1.14.0 |
| [GHSA-2238-pgfc-w82m](https://github.com/mtrudel/bandit/security/advisories/GHSA-2238-pgfc-w82m) | `erlang:bandit` | high | CVE published, cited (CVE-2026-111103) | 1 | 1.14.0 |
| [GHSA-j363-h72p-296m](https://github.com/mtrudel/bandit/security/advisories/GHSA-j363-h72p-296m) | `erlang:bandit` | high | CVE published, cited (CVE-2026-108529) | 1 | 1.14.0 |
| [GHSA-7gfj-7gvq-3xqj](https://github.com/mtrudel/bandit/security/advisories/GHSA-7gfj-7gvq-3xqj) | `erlang:bandit` | high | CVE published, cited (CVE-2026-109584) | 1 | 1.14.0 |
| [GHSA-jwh3-j29h-qfmw](https://github.com/mtrudel/bandit/security/advisories/GHSA-jwh3-j29h-qfmw) | `erlang:bandit` | high | CVE published, cited (CVE-2026-111101) | 1 | 1.14.0 |
| [GHSA-29cr-8477-rg6r](https://github.com/mtrudel/bandit/security/advisories/GHSA-29cr-8477-rg6r) | `erlang:bandit` | high | CVE published, cited (CVE-2026-113436) | 1 | 1.14.0 |

…and 257 more (see the feed).

## Longest waiting

| Advisory | Package | Severity | CVE | Days | Fixed in |
|---|---|---|---|---:|---|
| [GHSA-6pc9-r5gr-m9c9](https://github.com/rschultheis/many_versioned_gem/security/advisories/GHSA-6pc9-r5gr-m9c9) | `rubygems:many_versioned_gem` | medium | no CVE anywhere | 2813 | 0.1.1 |
| [GHSA-3wjh-93gr-chh6](https://github.com/flarum/framework/security/advisories/GHSA-3wjh-93gr-chh6) | `composer:flarum/core` | high | CVE published, cited (CVE-2019-13183) | 2671 | 0.1.0-beta.9 |
| [GHSA-jchv-x857-q8fq](https://github.com/apple/swift-nio-http2/security/advisories/GHSA-jchv-x857-q8fq) | `swift:swift-nio-http2` | high | no CVE anywhere | 2632 | 1.5.0 |
| [GHSA-hv27-vjg3-m59x](https://github.com/apple/swift-nio-http2/security/advisories/GHSA-hv27-vjg3-m59x) | `swift:swift-nio-http2` | high | CVE published, cited (CVE-2019-9515) | 2632 | 1.5.0 |
| [GHSA-9cqv-v2w2-7j52](https://github.com/apple/swift-nio-http2/security/advisories/GHSA-9cqv-v2w2-7j52) | `swift:swift-nio-http2` | high | CVE published, cited (CVE-2019-9516) | 2632 | 1.5.0 |

## Coverage

Watchlist 16,431 repositories; 16,431 up to date on their schedule (daily for repos with an advisory in limbo, every 3 to 7 days for the rest); 16,431 checked in the last 24 hours; 37,320 reviewed advisories known. Every number is a floor: the tracker only sees repositories on its watchlist. Version ranges are as entered by maintainers and unreviewed.

_Advisory metadata from published GitHub repository security advisories and the GitHub Advisory Database (https://github.com/advisories, CC BY 4.0); CVE state from CVE Services; OSV.dev; NVD API (this product uses the NVD API but is not endorsed or certified by the NVD). Compiled by Limbowatch (https://limbo.watch), CC BY 4.0._
