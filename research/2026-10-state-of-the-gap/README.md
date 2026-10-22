# State of the Gap: security advisories in limbo (October 2026)

**DRAFT for review, not published.** Snapshot taken 2026-10-21. Limbowatch research.

> When a maintainer publishes a security advisory on GitHub, most dependency scanners can't see it until GitHub reviews it into the global Advisory Database. We measured that waiting period, which we call **limbo**, across the dependencies of five popular open-source projects.

## Key numbers

- **1 in 7 upstream advisories is in limbo.** Of 1,949 published advisories in the 310 upstream repos (of 3,357 polled) behind five popular projects, **294 (15.1%)** are in neither GitHub's reviewed database nor OSV. Excluding likely duplicates gives **271 (13.9%)**.
- **The median wait for review is 27 days.** For 992 advisories GitHub reviewed between 2026-09-22 and 2026-10-21, **94% waited longer than 72 hours and 48% longer than 30 days.**
- **Every project we checked ships affected versions that a scanner reports as clean.** Across the five projects, **59 package-versions** are affected by advisories in limbo that OSV-Scanner reports as **clean** (no known vulnerability at all). That includes three in Kubernetes and four in Gitea.
- **17 CVE IDs are "reserved but public".** The advisory is published, but the CVE record isn't. 15 of them are past the CVE Program's 72-hour expectation, and the oldest has waited 113 days.

## What "limbo" means

```
 maintainer publishes          CVE record            GitHub review →          OSV imports it;
 a repository advisory         published             global Advisory DB       scanners update
        │                          │                        │                       │
────────●──────────────────────────●────────────────────────●───────────────────────●──────▶
        │◀────────────── in limbo: invisible to Dependabot, npm audit, ────────────▶│
                         pip-audit, OSV-Scanner and other scanners that
                         read the global databases
```

GitHub lets maintainers publish a security advisory directly in their repository. Dependabot, OSV and most scanners read GitHub's *global* Advisory Database instead, and an advisory only gets there after GitHub reviews it. GitHub says that "since mid-April… we have not consistently met our internal goals for publication" and that repository advisories rose "to more than 5,000/week" ([GitHub blog, June 2026](https://github.blog/security/supply-chain-security/inside-the-advisory-database-and-what-happens-when-vulnerability-volume-breaks-records/)). The advisory is public and the fix is usually released, but scanners stay silent.

These events don't happen in a fixed order. Some advisories get a CVE first and some never get one. Some reserve a CVE ID that stays unpublished, and some are reviewed under a different GHSA ID. We record each fact separately.

## Finding 1: about one in seven upstream advisories is in limbo

<picture>
  <source media="(prefers-color-scheme: dark)" srcset="charts/fig1-advisory-states-dark.svg">
  <img alt="Bar chart: of 1,949 upstream advisories, 199 are in limbo with no CVE, 17 in limbo with a reserved CVE, 78 in limbo with a published CVE, 200 reviewed without a CVE, and 1,455 reviewed with a CVE." src="charts/fig1-advisory-states-light.svg">
</picture>

| State | Advisories | Share |
|---|---:|---:|
| In limbo, no CVE | 199 | 10.2% |
| In limbo, CVE reserved but public (RBP) | 17 | 0.9% |
| In limbo, CVE published | 78 | 4.0% |
| Reviewed, no CVE | 200 | 10.3% |
| Reviewed, with CVE | 1,455 | 74.7% |
| **Total** | **1,949** | |

- **Confirmed directly.** Each of the 294 advisories missing from OSV also returned *not found* from GitHub's global advisory API, so none of them is merely an OSV sync delay. In a random sample of 200 advisories present in OSV, all 200 were reviewed.
- **No CVE yet, for most.** 199 of the 294 (68%) have no CVE ID at all. Tools keyed on CVE IDs can't track them either.
- **A long tail.** 37 have been in limbo for more than three months, and one for over seven years. Five list an ecosystem GitHub doesn't review (e.g. C++), so they will likely never be reviewed.
- **Mostly high or medium severity.** By the maintainers' own rating: 12 critical, 116 high, 134 medium, 32 low. Ecosystems: npm 138, pip 120, Go 25, Rust 9, plus a few in other or unspecified ecosystems (one advisory can list several).

## Finding 2: the median wait for review is 27 days

<picture>
  <source media="(prefers-color-scheme: dark)" srcset="charts/fig2-review-lag-dark.svg">
  <img alt="Column chart of review lag for 992 advisories: 58 under 3 days, 98 at 3–7 days, 112 at 1–2 weeks, 249 at 2–4 weeks, 241 at 1–2 months, 133 at 2–3 months, 101 over 3 months." src="charts/fig2-review-lag-light.svg">
</picture>

We took the 1,000 most recently reviewed advisories, reviewed between 2026-09-22 and 2026-10-21. 992 of them (99.2%) began as repository advisories. For each, we compared the time the maintainer published it with the time GitHub reviewed it.

| Wait until review | Advisories |
|---|---:|
| < 3 days (within GitHub's 72-hour target) | 58 |
| 3–7 days | 98 |
| 1–2 weeks | 112 |
| 2–4 weeks | 249 |
| 1–2 months | 241 |
| 2–3 months | 133 |
| > 3 months | 101 |

Median **26.6 days**, p25 13.3, p75 58.6, p90 90.7. The CVE usually isn't the bottleneck: 90% of the CVEs (780 of 866) were published *before* the review, a median of one day earlier. The CVE itself took a median of 18 days after the repository advisory. 114 of the 1,000 reviewed advisories (11.4%) have no CVE at all.

## Finding 3: most advisories in limbo are recent, but some are old

<picture>
  <source media="(prefers-color-scheme: dark)" srcset="charts/fig3-limbo-age-dark.svg">
  <img alt="Column chart of how long the 294 advisories in limbo have waited: 37 under 3 days, 73 at 3–7 days, 49 at 1–2 weeks, 50 at 2–4 weeks, 30 at 1–2 months, 14 at 2–3 months, 37 over 3 months." src="charts/fig3-limbo-age-light.svg">
</picture>

| Waiting so far | In limbo |
|---|---:|
| < 3 days | 37 |
| 3–7 days | 73 |
| 1–2 weeks | 49 |
| 2–4 weeks | 50 |
| 1–2 months | 30 |
| 2–3 months | 14 |
| > 3 months | 37 |

Median 10 days so far, p90 98 days. This is a snapshot of advisories still waiting, so the ages keep growing and aren't directly comparable to Finding 2.

## Finding 4: real projects ship affected versions that a scanner reports as clean

<picture>
  <source media="(prefers-color-scheme: dark)" srcset="charts/fig4-projects-dark.svg">
  <img alt="Grouped bar chart per project of package-versions affected by an advisory in limbo, and how many OSV-Scanner reports clean: gitea 6 and 4, kubernetes 3 and 3, langchain 22 and 20, n8n 29 and 23, open-webui 18 and 9." src="charts/fig4-projects-light.svg">
</picture>

We read every lockfile of five popular projects with OSV-Scanner v2.7.0 (11,959 package entries in all). We then matched each package to its upstream repository and checked that repository's advisories against the exact version in use.

| Project (commit) | Package entries | Affected package-versions | …reported clean by OSV-Scanner | Advisories in limbo affecting it | of which high/critical |
|---|---:|---:|---:|---:|---:|
| [go-gitea/gitea](https://github.com/go-gitea/gitea) (`7e164fe`) | 1,197 | 6 | 4 | 15 | 9 |
| [kubernetes/kubernetes](https://github.com/kubernetes/kubernetes) (`006cdf8`) | 2,042 | 3 | 3 | 3 | 3 |
| [langchain-ai/langchain](https://github.com/langchain-ai/langchain) (`45dae8c`) | 2,513 | 22 | 20 | 59 | 25 |
| [n8n-io/n8n](https://github.com/n8n-io/n8n) (`58f11bf`) | 4,124 | 29 | 23 | 43 | 20 |
| [open-webui/open-webui](https://github.com/open-webui/open-webui) (`91ea4e3`) | 2,083 | 18 | 9 | 61 | 23 |

Likely duplicates are excluded. "Reported clean" means OSV-Scanner reports *no* vulnerability at all for that package-version. A package can also have other, known vulnerabilities and still miss the advisory in limbo.

**Examples, each re-checked on 2026-10-21:** still absent from GitHub's global database, not reported by OSV-Scanner for that version, and not a likely duplicate.

| Package@version (ecosystem) | Used by | Advisory | Severity | CVE status | Days in limbo | Fixed in |
|---|---|---|---|---|---:|---|
| `github.com/dlclark/regexp2/v2@2.2.1` (Go) | kubernetes | [GHSA-wq9v-j77v-qr26](https://github.com/dlclark/regexp2/security/advisories/GHSA-wq9v-j77v-qr26) | high | reserved (RBP), CVE-2026-77299 | 102 | 2.3.0 |
| `github.com/go-jose/go-jose/v4@4.1.5` (Go) | kubernetes | [GHSA-mgcc-cww5-fp2q](https://github.com/go-jose/go-jose/security/advisories/GHSA-mgcc-cww5-fp2q) | high | no CVE | 6 | 4.1.6 |
| `github.com/anishathalye/porcupine@1.3.0` (Go) | kubernetes | [GHSA-v76q-fhj2-wh42](https://github.com/anishathalye/porcupine/security/advisories/GHSA-v76q-fhj2-wh42) | high | no CVE | 13 | 1.3.1 |
| `@sinclair/typebox@0.27.10` (npm) | gitea | [GHSA-976x-prgx-qv35](https://github.com/sinclairzx81/sinclair-typebox/security/advisories/GHSA-976x-prgx-qv35) | high | reserved (RBP), CVE-2026-77356 | 61 | 0.27.12 |
| `seroval@1.5.4` (npm) | gitea | [GHSA-9355-h2pj-8fqj](https://github.com/lxsmnsyc/seroval/security/advisories/GHSA-9355-h2pj-8fqj) | high | no CVE | 23 | 1.6.4 |
| `@redocly/cli@1.34.21` (npm) | n8n | [GHSA-xw2f-5386-m542](https://github.com/Redocly/redocly-cli/security/advisories/GHSA-xw2f-5386-m542) | high | published, CVE-2026-63325 | 86 | 2.33.0 |
| `gitpython@3.1.50` (PyPI) | open-webui | [GHSA-f9j4-qggq-h239](https://github.com/gitpython-developers/GitPython/security/advisories/GHSA-f9j4-qggq-h239) | critical | no CVE | 21 | 3.2.0 |
| `authlib@1.7.2` (PyPI) | langchain, open-webui | [GHSA-6v38-4h7w-rj9h](https://github.com/authlib/authlib/security/advisories/GHSA-6v38-4h7w-rj9h) | critical | published, CVE-2026-96760 | 7 | 1.9.0 |
| `pillow@12.3.0` (PyPI) | langchain, open-webui | [GHSA-v9pv-5gc8-w2m6](https://github.com/python-pillow/Pillow/security/advisories/GHSA-v9pv-5gc8-w2m6) | critical | published, CVE-2026-96639 | 4 | 13.0.0 |
| `ty@0.0.29` (PyPI) | langchain | [GHSA-vxvm-j4xq-q7m4](https://github.com/astral-sh/ty/security/advisories/GHSA-vxvm-j4xq-q7m4) | high | no CVE | 27 | 0.0.84 |

"Affected" means the version falls within the range the maintainer published. It doesn't mean the vulnerability can be exploited in that project, and a lockfile can include development or optional dependencies.

## Finding 5: CVE and NVD data lag too

- **Reserved but public (RBP).** 17 advisories in limbo cite a CVE ID whose record is still `RESERVED`, which you can check with CVE Services' public `cve-id` endpoint. The median wait is 11 days, 15 are past the 72 hours the CVE Program's RBP policy expects (see [rbptracker.org](https://rbptracker.org)), and the oldest has waited 113 days.
- **NVD.** NVD has no record for 10 of the 65 published CVEs on advisories in limbo, and 38 more aren't enriched (Received, Awaiting/Undergoing Analysis or Deferred). Even after GitHub review, 27 of a random 60 CVEs on reviewed advisories have neither NIST CVSS nor CPE data (3 of them are rejected CVEs). Tools that match on NVD CPEs miss them too.

## What to do about it

**If you run a dependency scanner:**
- Treat a clean scan as "nothing reviewed yet", not as "nothing published".
- Check the advisories of your direct and critical upstream repos. These tools do it today:
  - [blindspot](https://github.com/munimtechnologies/advisory-import-census) (lockfile → upstream advisories → OSV check; GitHub Action);
  - Safeguard's [`advisory_gap.py`](https://safeguard.sh/resources/blog/github-repository-advisories-missing-from-advisory-database-2026-data).
- Limbowatch's live tracker and open feed are next (see [Limbowatch](../../README.md)).

**If you maintain a package:**
1. Fill in the advisory's ecosystem, exact package name and version range in standard syntax (`>= 1.0.0, < 1.2.3`). In our data, 4.7% of ranges couldn't be read by a machine, and some named packages that don't exist on the registry.
2. Always set the fixed version.
3. Request a CVE in the advisory form, and make sure it gets published, not just reserved.
4. Announce the release in your changelog, so people learn about it before scanners do.

**For the ecosystem:** we'd welcome a way for scanners to see published repository advisories before review, clearly labeled *unreviewed*, so teams can choose to act on them. **[Draft note: before publication, share the draft with GitHub's Advisory Database team and the OSV maintainers for comment. Not done yet.]**

## Method

| Step | What we did |
|---|---|
| Projects | gitea, kubernetes, n8n, open-webui, langchain at the commits above (Go, npm, PyPI, Cargo). |
| Inventory | Sparse clone of every lockfile (`package-lock.json`, `pnpm-lock.yaml`, `yarn.lock`, `uv.lock`, `poetry.lock`, `requirements*.txt`, `go.mod`, `Cargo.lock`, …), excluding `testdata/`, `fixtures/` and `vendor/`; [OSV-Scanner](https://github.com/google/osv-scanner) v2.7.0 `--all-packages`. 11,959 entries. |
| Mapping | Go `github.com/` module paths, otherwise [deps.dev](https://deps.dev) `SOURCE_REPO` (attested provenance preferred). 6,659 of 6,922 unique package-versions (96.2%) mapped to 3,357 GitHub repos. The 426 entries we couldn't check (no version, no repo) are listed in `unresolved.csv`, not dropped. |
| Advisories | `GET /repos/{owner}/{repo}/security-advisories?state=published` for every repo. 3,332 answered; 25 returned 404. |
| Status | OSV `GET /v1/vulns/{GHSA}` for every advisory. GitHub `GET /advisories/{GHSA}` for every one missing from OSV, plus 200 random present ones. CVE Services `cve` and `cve-id`. NVD API 2.0 for every published CVE on an advisory in limbo, plus a random 60 on reviewed ones. |
| Matching | Advisory package (ecosystem + normalized name) and the advisory's repo had to equal our mapped repo. The maintainer's range was evaluated against the exact version with [univers](https://github.com/aboutcode-org/univers) comparators. The parser accepts GHSA, npm-semver, hyphen, `;`/`\|\|` alternatives and common typos; anything else is "unknown" (65 of 1,397 package matches, plus 116 advisories without package data). |
| Duplicates | For advisories in limbo that match our dependencies (163), we compared each against reviewed advisories of the same package: same CVE, same fix commit/PR, or summary similarity ≥ 0.6. That flagged 23 (14%) as likely duplicates reviewed under another GHSA ID. |
| Review lag | The 1,000 most recently reviewed advisories. Repo advisory `published_at` vs global `github_reviewed_at` (the global `published_at` equals the review time). |

## Limitations

- **Small sample.** Five projects and their upstream repos are a sample, not a census. Repos that never publish advisories contribute nothing.
- **Maintainer data can be wrong.** Ranges and package names in unreviewed advisories are entered by maintainers. Fixing that is part of what GitHub's review does.
- **Duplicates are estimated.** Duplicate detection is heuristic, and we checked only the 163 advisories matching our dependencies, so the true limbo share is somewhere between 13.9% and 15.1%.
- **OSV-Scanner stands in for "scanners".** Other tools have their own databases and may cover some of these (Snyk, Socket and GitLab's advisory database were not tested; GitLab's terms don't allow automated querying).
- **NVD figures are sampled.** NVD numbers come from the CVEs we sampled. Every number is as of 2026-10-21 and will drift.

## Prior work and credits

This independently replicates findings by others and adds the dependency-level view:
- **Safeguard**, [*GitHub Repository Advisories Missing From the Database (2026)*](https://safeguard.sh/resources/blog/github-repository-advisories-missing-from-advisory-database-2026-data): 30.7% of 2,486 repository advisories missing as of 2026-10-18.
- **Munim, Inc.**, [*advisory-import-census*](https://github.com/munimtechnologies/advisory-import-census) and blindspot: 31.6% for self-hosted AI tools.
- **RogoLabs** (Jerry Gamblin): [RBP tracker](https://rbptracker.org), [GhostCVEs](https://github.com/RogoLabs/GhostCVEs) and [consensus-engine](https://github.com/RogoLabs/consensus-engine).

## Data and reproducing

Everything is in [`data/2026-10-21/`](data/2026-10-21/). It has IDs, states, dates, ranges and links, but no advisory text.

| File | Contents |
|---|---|
| `summary.json` | every number in this report |
| `advisories.csv` | 1,949 upstream advisories with state, CVE status, OSV / global presence and duplicate signal |
| `findings.csv` | advisory × project × package-version matches, including OSV-Scanner's verdict |
| `review_lag.csv` | 992 reviewed advisories: publication, review, CVE dates |
| `nvd.csv` | NVD status of sampled CVEs |
| `unresolved.csv` | entries we couldn't check, with the reason |

To rerun (needs `uv`, `go` and `git`; a GitHub token from `gh auth token` or `GITHUB_TOKEN`; optional `NVD_API_KEY`):

```sh
cd research/2026-10-state-of-the-gap/scripts
export SNAPSHOT_DATE=$(date +%F)
uv run s1_inventory.py && uv run s2_map.py && uv run s3_poll.py && \
uv run s4_status.py && uv run s5_review_lag.py && uv run s6_analyze.py && uv run s7_charts.py
```

A full run takes about 5,000 GitHub API requests and roughly 30 minutes (NVD without a key is the slow part). Raw responses are cached in `.cache/` and aren't committed.

## License and attribution

- **Data:** [CC BY 4.0](data/LICENSE). **Code:** Apache-2.0.
- **Advisory metadata** comes from the [GitHub Advisory Database](https://github.com/advisories) (CC BY 4.0) and published repository advisories on GitHub.
- **Other sources:** vulnerability presence from [OSV.dev](https://osv.dev), CVE state from [CVE Services](https://www.cve.org), NVD status from the [NVD API](https://nvd.nist.gov) (this product uses the NVD API but is not endorsed or certified by the NVD), and package→repo mapping from [deps.dev](https://deps.dev).
