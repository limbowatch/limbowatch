<p align="center">
  <picture>
    <source media="(prefers-color-scheme: dark)" srcset="brand/assets/wordmark-transparent-light-text.png">
    <img alt="limbo.watch" src="brand/assets/wordmark-transparent-dark-text.png" width="420">
  </picture>
</p>

# Limbowatch

**Published. Not reviewed. Not scanned. In limbo.**

Limbowatch measures, and will help close, the gap between a maintainer publishing a security advisory and your scanner being able to see it.

When a maintainer publishes a security advisory in their GitHub repository, Dependabot, npm audit, OSV-Scanner and most other dependency scanners stay silent until GitHub reviews that advisory into its global Advisory Database. Until then, the advisory is **in limbo**: public, usually already fixed upstream, and invisible to the tools teams rely on.

## Why this exists

In June 2026 I reported a critical vulnerability in [NationalSecurityAgency/skills-service](https://github.com/NationalSecurityAgency/skills-service/security/advisories/GHSA-hqfg-c8wf-w2g8). The advisory was published on 16 June, but its CVE stayed reserved for 85 days, and four months later scanners that read GitHub's database, OSV or NVD still can't match it. I wanted to know how many other advisories are stuck the same way. The answer is thousands. [The full story](https://limbo.watch/why/).

## The October 2026 report

📊 **[State of the Gap (October 2026)](research/2026-10-state-of-the-gap/README.md)**, *draft*. Main findings (snapshot 2026-10-22, 15 projects on GitHub, GitLab, Codeberg, Tor, GNOME, Framagit and SourceHut):

- **About 1 in 6 upstream advisories is in limbo.** That's 415 of 2,517 unique advisories (16.5%) in the upstream repos of fifteen popular projects, each verified automatically against primary sources.
- **The median wait for GitHub review is 23 days.** 94% of advisories wait longer than GitHub's 72-hour target, and 44% longer than 30 days.
- **13 of 14 readable projects ship affected versions that a scanner reports as clean.** That's 105 package-versions that OSV-Scanner reports as having no known vulnerabilities, including in GitLab, Forgejo, Gitea and Kubernetes. Hosting your code off GitHub doesn't help: your dependencies' advisories are still stuck there.
- **CVE data is out of sync too.** 27 CVE IDs are reserved but public, the oldest for 119 days. 23 advisories have a VulnCheck- or Tenable-assigned CVE they don't cite. Many CVEs aren't enriched in NVD.

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
