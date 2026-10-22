# Limbowatch

**Published. Not reviewed. Not scanned. In limbo.**

Limbowatch measures, and will help close, the gap between a maintainer publishing a security advisory and your scanner being able to see it.

When a maintainer publishes a security advisory in their GitHub repository, Dependabot, npm audit, OSV-Scanner and most other dependency scanners stay silent until GitHub reviews that advisory into its global Advisory Database. Until then, the advisory is **in limbo**: public, usually already fixed upstream, and invisible to the tools teams rely on.

## The October 2026 report

📊 **[State of the Gap (October 2026)](research/2026-10-state-of-the-gap/README.md)**, *draft*. Main findings (snapshot 2026-10-21):

- **About 1 in 7 upstream advisories is in limbo.** That's 294 of 1,949 advisories (15.1%) in the upstream repos of five popular projects, or 14.7–15.1% after automated duplicate checks. All 294 were verified automatically against primary sources.
- **The median wait for GitHub review is 27 days.** 94% of advisories wait longer than GitHub's 72-hour target, and 48% longer than 30 days.
- **Every project checked ships affected versions that a scanner reports as clean.** That's 62 package-versions across gitea, kubernetes, n8n, open-webui and langchain that OSV-Scanner reports as having no known vulnerabilities.
- **CVEs lag too.** 17 CVE IDs are reserved but public, the oldest for 113 days. Many CVEs on these advisories also aren't enriched in NVD.

The methods, open dataset (CC BY 4.0) and scripts to reproduce it are in the [report folder](research/2026-10-state-of-the-gap/).

## Terms

| Term | Meaning |
|---|---|
| **In limbo** | A published repository advisory that isn't yet in GitHub's reviewed Advisory Database or in OSV |
| `LIMBO_ADVISORY` | In limbo, with no public CVE |
| `LIMBO_ADVISORY` + `RBP` | In limbo; its CVE ID is *reserved but public* (the CVE Program's term) |
| `LIMBO_CVE` | In limbo, but its CVE record is published |
| `NO_CVE` | Reviewed by GitHub, but no CVE, so tools keyed on CVE IDs miss it |

## Roadmap

| Phase | Status |
|---|---|
| 1. "State of the Gap" report | **draft for review** |
| 2. Live Limbo Tracker and an open **limbo feed** (OSV schema) | planned |
| 3. Contributions to existing tools ([blindspot](https://github.com/munimtechnologies/advisory-import-census), OSV-Scanner) | planned |
| 4. Limbowatch watcher for GitLab and Gitea: CI component, issues that update as advisories move through review, org-wide watch | planned |
| 5–6. More ecosystems (Maven/Gradle first), then C/C++ and vendored code | planned |

Limbowatch builds only what existing tools don't do. See [the plan](docs/PHASE0_PLAN.md) and [research findings](docs/FINDINGS.md).

## Prior work

This builds on work by [Safeguard](https://safeguard.sh/resources/blog/github-repository-advisories-missing-from-advisory-database-2026-data), [Munim, Inc. (advisory-import-census / blindspot)](https://github.com/munimtechnologies/advisory-import-census) and [RogoLabs](https://rbptracker.org) (Jerry Gamblin).

## License

- **Code:** [Apache-2.0](LICENSE).
- **Research data:** [CC BY 4.0](research/2026-10-state-of-the-gap/data/LICENSE).
- **Advisory data** comes from the [GitHub Advisory Database](https://github.com/advisories) (CC BY 4.0) and [OSV](https://osv.dev).
