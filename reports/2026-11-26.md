# Limbo Tracker daily report — 2026-11-26

Generated 2026-11-26 17:22:40 UTC; changes since 2026-11-25 17:42:16 UTC.

## Now

- **12,470 advisories in limbo** (+192 since the last report: 183 newly published, 12 older ones found for the first time, 3 left limbo): published by maintainers on GitHub, in ecosystems GitHub reviews, but not yet in GitHub's reviewed database or OSV.
  - 7,325 with no CVE anywhere · 556 citing a CVE that's still only reserved · 1,640 with a CVE from another CNA they don't cite
  - severity: 1,096 critical, 4,825 high, 5,296 medium, 1,253 low · median wait so far 52.3 days
- **16,665 more are likely permanent** (+79 since the last report: 83 newly published, 0 older ones found for the first time, 4 left limbo): in ecosystems GitHub doesn't review, so GitHub-based scanners will probably never see them.

## Since the last report

- **183 newly published** advisories entered limbo.
- 12 older advisories were found for the first time (4 in newly watched repos).
- **Left limbo** (likely permanent included): 7 reviewed by GitHub, 0 found to duplicate a reviewed advisory, 0 withdrawn or unpublished. GitHub reviewed 7 advisories in all in this period, from any repository.
- **CVE changes:** 158 (14 reserved CVEs published, 120 new CVEs from other CNAs).

## Newly published, in limbo

| Advisory | Package | Severity | CVE | Days | Fixed in |
|---|---|---|---|---:|---|
| [GHSA-mgp3-vjcp-p65v](https://github.com/robotraconteur/robotraconteur/security/advisories/GHSA-mgp3-vjcp-p65v) | `nuget:RobotRaconteurNET, other:RobotRaconteur.jar, other:…` | critical | no CVE anywhere | 1 | `1.3.0` |
| [GHSA-425j-4pc4-9rf5](https://github.com/robotraconteur/robotraconteur/security/advisories/GHSA-425j-4pc4-9rf5) | `nuget:RobotRaconteurNET, other:RobotRaconteur.jar, other:…` | critical | no CVE anywhere | 1 | `1.3.0` |
| [GHSA-7hgq-37pf-9jfp](https://github.com/AlaSQL/alasql/security/advisories/GHSA-7hgq-37pf-9jfp) | `npm:alasql` | critical | no CVE anywhere | 0 | `4.2.8, 4.3.4, 4.4.1, 4.5.3, 4.6.7, 4.7.1` |
| [GHSA-7h7w-m82c-x2xg](https://github.com/rubygems/rubygems.org/security/advisories/GHSA-7h7w-m82c-x2xg) | `rubygems:Registry` | critical | no CVE anywhere | 0 | `–` |
| [GHSA-w686-5683-v8gq](https://github.com/lintsinghua/DeepAudit/security/advisories/GHSA-w686-5683-v8gq) | `pip:deepaudit-backend` | critical | no CVE anywhere | 0 | `3.8.4` |
| [GHSA-264q-8pq4-cq45](https://github.com/openremote/core/security/advisories/GHSA-264q-8pq4-cq45) | `maven:io.openremote:openremote-manager` | critical | no CVE anywhere | 0 | `1.35.0` |
| [GHSA-fjgc-vj2f-77hm](https://github.com/langflow-ai/langflow/security/advisories/GHSA-fjgc-vj2f-77hm) | `npm:langflow` | critical | CVE published, cited (`CVE-2026-9103`) | 0 | `1.13.0` |
| [GHSA-qh46-886x-f524](https://github.com/jaylfc/taOS/security/advisories/GHSA-qh46-886x-f524) | `pip:tinyagentos` | critical | no CVE anywhere | 0 | `1.0.0-beta.60` |
| [GHSA-9q82-wjpr-32jm](https://github.com/OliveTin/OliveTin/security/advisories/GHSA-9q82-wjpr-32jm) | `go:github.com/OliveTin/OliveTin` | critical | no CVE anywhere | 0 | `–` |
| [GHSA-f9qf-hfc5-7xpj](https://github.com/fastify/fastify-express/security/advisories/GHSA-f9qf-hfc5-7xpj) | `npm:@fastify/express` | critical | CVE published, cited (`CVE-2026-135279`) | 0 | `4.0.14` |
| [GHSA-x684-539w-8w6w](https://github.com/RyanDFIR/unfurl/security/advisories/GHSA-x684-539w-8w6w) | `pip:dfir-unfurl` | high | no CVE anywhere | 1 | `20261124` |
| [GHSA-p8gc-r535-3cjm](https://github.com/RyanDFIR/unfurl/security/advisories/GHSA-p8gc-r535-3cjm) | `pip:dfir-unfurl` | high | no CVE anywhere | 1 | `20261124` |
| [GHSA-w5fw-j7jw-8977](https://github.com/tobychui/zoraxy/security/advisories/GHSA-w5fw-j7jw-8977) | `go:github.com/tobychui/zoraxy` | high | CVE published, cited (`CVE-2026-105304`) | 1 | `3.3.5-rc2` |
| [GHSA-4vq7-jqv7-j374](https://github.com/vuejs/core/security/advisories/GHSA-4vq7-jqv7-j374) | `npm:@vue/shared` | high | no CVE anywhere | 1 | `3.5.46, 3.6.0-rc.15` |
| [GHSA-vc49-xjm8-cjjg](https://github.com/tonytonyjan/jaro_winkler/security/advisories/GHSA-vc49-xjm8-cjjg) | `rubygems:jaro_winkler` | high | no CVE anywhere | 1 | `1.7.1` |
| [GHSA-mp86-55qw-3rfh](https://github.com/robotraconteur/robotraconteur/security/advisories/GHSA-mp86-55qw-3rfh) | `nuget:RobotRaconteurNET, other:RobotRaconteur.jar, other:…` | high | no CVE anywhere | 1 | `1.3.0` |
| [GHSA-8v2r-442p-mf5w](https://github.com/robotraconteur/robotraconteur/security/advisories/GHSA-8v2r-442p-mf5w) | `nuget:RobotRaconteurNET, other:RobotRaconteur.jar, other:…` | high | no CVE anywhere | 1 | `1.3.0` |
| [GHSA-48rm-6vg7-256j](https://github.com/robotraconteur/robotraconteur/security/advisories/GHSA-48rm-6vg7-256j) | `nuget:RobotRaconteurNET, other:RobotRaconteur.jar, other:…` | high | no CVE anywhere | 1 | `1.3.0` |
| [GHSA-m382-jpv5-65xp](https://github.com/robotraconteur/robotraconteur/security/advisories/GHSA-m382-jpv5-65xp) | `nuget:RobotRaconteurNET, other:RobotRaconteur.jar, other:…` | high | no CVE anywhere | 1 | `1.3.0` |
| [GHSA-3pqc-w4mg-24xc](https://github.com/robotraconteur/robotraconteur/security/advisories/GHSA-3pqc-w4mg-24xc) | `pip:robotraconteur` | high | no CVE anywhere | 1 | `1.3.0` |
| [GHSA-h28g-9r66-578q](https://github.com/robotraconteur/robotraconteur/security/advisories/GHSA-h28g-9r66-578q) | `nuget:RobotRaconteurNET, other:RobotRaconteur.jar, other:…` | high | no CVE anywhere | 1 | `1.3.0` |
| [GHSA-jq4p-r3m3-v763](https://github.com/robotraconteur/robotraconteur/security/advisories/GHSA-jq4p-r3m3-v763) | `nuget:RobotRaconteurNET, other:RobotRaconteur.jar, other:…` | high | no CVE anywhere | 1 | `1.3.0` |
| [GHSA-h8vq-fpqm-595x](https://github.com/mongodb/bson-ruby/security/advisories/GHSA-h8vq-fpqm-595x) | `rubygems:bson` | high | CVE published, cited (`CVE-2026-135226`) | 1 | `5.2.1` |
| [GHSA-8mcm-rpf2-v8x9](https://github.com/aiortc/aiortc/security/advisories/GHSA-8mcm-rpf2-v8x9) | `pip:aiortc` | high | no CVE anywhere | 0 | `1.17.0` |
| [GHSA-76f6-683g-w69p](https://github.com/mongodb/mongo-python-driver/security/advisories/GHSA-76f6-683g-w69p) | `pip:pymongo` | high | CVE published, cited (`CVE-2026-135898`) | 0 | `4.20.2` |

…and 158 more: [the tracker](https://limbo.watch/tracker/) lists them all, newest first.

## CVE changes

| Advisory | Change |
|---|---|
| [GHSA-q9rj-8p2j-whg4](https://github.com/seaweedfs/seaweedfs/security/advisories/GHSA-q9rj-8p2j-whg4) | CVE-2026-133464 RESERVED -> PUBLISHED |
| [GHSA-55w2-5j5j-6q97](https://github.com/nocodb/nocodb/security/advisories/GHSA-55w2-5j5j-6q97) | CVE-2026-116681 RESERVED -> PUBLISHED |
| [GHSA-hrp4-xjp5-cq7j](https://github.com/AcademySoftwareFoundation/openexr/security/advisories/GHSA-hrp4-xjp5-cq7j) | CVE-2026-133466 RESERVED -> PUBLISHED |
| [GHSA-qcpp-8vwj-hhwr](https://github.com/netbirdio/netbird/security/advisories/GHSA-qcpp-8vwj-hhwr) | CVE-2026-115576 RESERVED -> PUBLISHED |
| [GHSA-56xw-p9qm-r437](https://github.com/nicolargo/glances/security/advisories/GHSA-56xw-p9qm-r437) | CVE-2026-133465 RESERVED -> PUBLISHED |
| [GHSA-597m-w632-p8qv](https://github.com/HKUDS/LightRAG/security/advisories/GHSA-597m-w632-p8qv) | CVE-2026-114507 RESERVED -> PUBLISHED |
| [GHSA-98g6-r386-569h](https://github.com/Significant-Gravitas/AutoGPT/security/advisories/GHSA-98g6-r386-569h) | CVE-2026-132265 RESERVED -> PUBLISHED |
| [GHSA-g87v-g79r-whvj](https://github.com/pydantic/pydantic-ai/security/advisories/GHSA-g87v-g79r-whvj) | CVE-2026-136638 RESERVED -> PUBLISHED |
| [GHSA-jqh7-c84w-36vf](https://github.com/Significant-Gravitas/AutoGPT/security/advisories/GHSA-jqh7-c84w-36vf) | CVE-2026-133451 RESERVED -> PUBLISHED |
| [GHSA-qmx6-fpcw-q3xg](https://github.com/seaweedfs/seaweedfs/security/advisories/GHSA-qmx6-fpcw-q3xg) | CVE-2026-133463 RESERVED -> PUBLISHED |
| [GHSA-9gp7-896w-m3r7](https://github.com/kestra-io/kestra/security/advisories/GHSA-9gp7-896w-m3r7) | CVE-2026-122263 RESERVED -> PUBLISHED |
| [GHSA-gcpp-8php-g682](https://github.com/makeplane/plane/security/advisories/GHSA-gcpp-8php-g682) | CVE-2026-102987 RESERVED -> PUBLISHED |
| [GHSA-h48f-pxp7-c4mj](https://github.com/gogs/gogs/security/advisories/GHSA-h48f-pxp7-c4mj) | CVE-2026-52803 RESERVED -> PUBLISHED |
| [GHSA-w259-2hhm-9vr7](https://github.com/rsyslog/rsyslog/security/advisories/GHSA-w259-2hhm-9vr7) | CVE-2026-129838 RESERVED -> PUBLISHED |
| [GHSA-2xw3-7h62-v4gf](https://github.com/hestiacp/hestiacp/security/advisories/GHSA-2xw3-7h62-v4gf) | cites CVE-2026-137009 (was none) |
| [GHSA-5h8w-vg25-fw38](https://github.com/openremote/core/security/advisories/GHSA-5h8w-vg25-fw38) | cites CVE-2026-114661 (was none) |
| [GHSA-8353-5qhw-8hfw](https://github.com/pipeboard-co/meta-ads-mcp/security/advisories/GHSA-8353-5qhw-8hfw) | cites CVE-2026-136266 (was none) |
| [GHSA-cfqc-c682-93mm](https://github.com/rabbitmq/rabbitmq-server/security/advisories/GHSA-cfqc-c682-93mm) | cites CVE-2026-137016 (was none) |
| [GHSA-f4q9-j22m-xqq9](https://github.com/valkey-io/valkey/security/advisories/GHSA-f4q9-j22m-xqq9) | cites CVE-2026-136156 (was none) |
| [GHSA-fq2f-crmw-q97r](https://github.com/valkey-io/valkey/security/advisories/GHSA-fq2f-crmw-q97r) | cites CVE-2026-136155 (was none) |
| [GHSA-gf33-2772-8gw3](https://github.com/openremote/core/security/advisories/GHSA-gf33-2772-8gw3) | cites CVE-2026-124436 (was none) |
| [GHSA-jcj7-v34w-v9vv](https://github.com/valkey-io/valkey/security/advisories/GHSA-jcj7-v34w-v9vv) | cites CVE-2026-136157 (was none) |
| [GHSA-rg4f-xvhj-mw22](https://github.com/ProfessionalWiki/Maps/security/advisories/GHSA-rg4f-xvhj-mw22) | cites CVE-2026-137015 (was none) |
| [GHSA-wg5h-vcgv-74pv](https://github.com/ZoneMinder/zoneminder/security/advisories/GHSA-wg5h-vcgv-74pv) | cites CVE-2026-136260 (was none) |
| [GHSA-448w-h27c-w53m](https://github.com/datasharingframework/dsf/security/advisories/GHSA-448w-h27c-w53m) | cites CVE-2026-137014 (was none) |

…and 133 more.

## Longest waiting, published in the last 90 days

| Advisory | Package | Severity | CVE | Days | Fixed in |
|---|---|---|---|---:|---|
| [GHSA-99f2-hwrc-gvq8](https://github.com/vllm-project/vllm/security/advisories/GHSA-99f2-hwrc-gvq8) | `pip:vllm` | medium | CVE published, cited (`CVE-2026-90555`) | 89 | `0.28.0` |
| [GHSA-mqvm-jv87-w7rx](https://github.com/aws/amazon-ssm-agent/security/advisories/GHSA-mqvm-jv87-w7rx) | `go:github.com/aws/amazon-ssm-agent` | high | CVE published, cited (`CVE-2026-81849`) | 89 | `3.3.4515.0` |
| [GHSA-936p-m5pv-vvjf](https://github.com/vllm-project/vllm/security/advisories/GHSA-936p-m5pv-vvjf) | `pip:vllm` | medium | CVE published, cited (`CVE-2026-90554`) | 89 | `0.28.0` |
| [GHSA-3c86-2m5g-59q7](https://github.com/vllm-project/vllm/security/advisories/GHSA-3c86-2m5g-59q7) | `pip:vllm` | high | CVE published, cited (`CVE-2026-90553`) | 89 | `0.28.0` |
| [GHSA-7wjf-49rm-77gx](https://github.com/vercel/vercel/security/advisories/GHSA-7wjf-49rm-77gx) | `npm:@vercel/react-router` | high | no CVE anywhere | 89 | `1.3.4` |

624 advisories in limbo have waited more than a year.

## Coverage

Watchlist 68,177 repositories; 68,177 up to date on their schedule (daily for repos with an advisory in limbo, every 3 days for other repos with advisories, every 30 days and after each release for the rest); 7,869 checked in the last 24 hours; 38,014 reviewed advisories known. Every number is a floor: the tracker only sees repositories on its watchlist. Version ranges are as entered by maintainers and unreviewed.

_Advisory metadata from published GitHub repository security advisories and the GitHub Advisory Database (https://github.com/advisories, CC BY 4.0); CVE state from CVE Services; OSV.dev; NVD API (this product uses the NVD API but is not endorsed or certified by the NVD). Compiled by Limbowatch (https://limbo.watch), CC BY 4.0._
