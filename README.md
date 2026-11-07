<p align="center">
  <picture>
    <source media="(prefers-color-scheme: dark)" srcset="brand/assets/wordmark-transparent-light-text.png">
    <img alt="limbo.watch" src="brand/assets/wordmark-transparent-dark-text.png" width="420">
  </picture>
</p>

# Limbowatch

**Published. Not reviewed. Not scanned. In limbo.**

Limbowatch measures the gap between a maintainer publishing a security advisory and your scanner being able to see it, and closes it in your CI.

When a maintainer publishes a security advisory in their GitHub repository, Dependabot, npm audit, OSV-Scanner and most other dependency scanners stay silent until GitHub reviews that advisory into its global Advisory Database. Until then, the advisory is **in limbo**: public, usually already fixed upstream, and invisible to the tools teams rely on.

## Scan your project

`limbowatch scan` checks your lockfiles against every advisory in limbo and shows what it finds where your team already looks: GitLab merge requests (Code Quality), GitHub pull requests (code scanning), and issues in GitLab, Gitea or Forgejo.

```yaml
# GitLab CI
include:
  - component: $CI_SERVER_FQDN/limbowatch/limbowatch-component/limbowatch@0.1.0
    inputs:
      fail_on: high
```

```yaml
# GitHub, Gitea or Forgejo Actions
- uses: actions/checkout@v4
- uses: limbowatch/limbowatch/integrations/action@v0.1.0
  with:
    fail-on: high
    sarif: limbowatch.sarif
```

What it finds, measured 2026-11-05 to 11-07 against the live feed:

- **269 affected package-versions in 13 of 14 popular projects** (GitLab alone 125), which scanners reading GitHub's database or OSV report as clean. Of 657 findings checked live, none was contradicted.
- **16 vs 0 on a demo app** with real npm, Go, pip and Bundler lockfiles: Limbowatch found 16 advisories in limbo; OSV-Scanner and GitHub's Dependabot alerts reported none of them. See the [demo pull request](https://github.com/limbowatch/demo-app/pull/1): 51 new alerts, inline on the line that adds the package. [Evidence: all 16 rechecked against GitHub and OSV](research/2026-11-demo-evidence/), 1.6 to 23.5 days in limbo.

Guide: [docs/WATCHER.md](docs/WATCHER.md) · [limbo.watch/scan](https://limbo.watch/scan/). Version 0.1.0 is being released to PyPI and the GitLab CI/CD Catalog; until then, install from GitHub as the guide shows.

## Why this exists

In June 2026 I reported a critical vulnerability in [NationalSecurityAgency/skills-service](https://github.com/NationalSecurityAgency/skills-service/security/advisories/GHSA-hqfg-c8wf-w2g8). The advisory was published on 16 June, but its CVE stayed reserved for 85 days, and four months later scanners that read GitHub's database, OSV or NVD still can't match it. I wanted to know how many other advisories are stuck the same way. The answer is thousands. [The full story](https://limbo.watch/why/).

## The October 2026 report

📊 **[State of the Gap (October 2026)](research/2026-10-state-of-the-gap/README.md)**, *draft*. Main findings (snapshot 2026-10-22, 15 projects on GitHub, GitLab, Codeberg, Tor, GNOME, Framagit and SourceHut):

- **About 1 in 6 upstream advisories is in limbo.** That's 415 of 2,517 unique advisories (16.5%) in the upstream repos of fifteen popular projects, each verified automatically against primary sources.
- **The median wait for GitHub review is 23 days.** 94% of advisories wait longer than GitHub's 72-hour target, and 44% longer than 30 days.
- **13 of 14 readable projects ship affected versions that a scanner reports as clean.** That's 105 package-versions that OSV-Scanner reports as having no known vulnerabilities, including in GitLab, Forgejo, Gitea and Kubernetes. Hosting your code off GitHub doesn't help: your dependencies' advisories are still stuck there.
- **CVE data is out of sync too.** 27 CVE IDs are reserved but public, the oldest for 119 days. 23 advisories have a VulnCheck- or Tenable-assigned CVE they don't cite. Many CVEs aren't enriched in NVD.

The methods, open dataset (CC BY 4.0) and scripts to reproduce it are in the [report folder](research/2026-10-state-of-the-gap/).

## Use it

- **[limbo.watch](https://limbo.watch):** the live tracker. It lists every advisory in limbo across about 18,600 watched repos, updated daily.
- **[The limbo feed](https://limbo.watch/feed/):** the same advisories as OSV-schema records. The released OSV-Scanner can already scan against it.
- **The watcher**, `limbowatch scan`: checks your project's dependencies against advisories in limbo, in CI or locally. One scan writes any of ten formats (table, JSON, Markdown, HTML, SARIF, GitLab Code Quality, JUnit, CSV, CycloneDX, GitHub annotations), and it keeps one issue per finding up to date in GitLab or Gitea/Forgejo. `pip install limbowatch-cli`. See the [guide](docs/WATCHER.md), the [GitLab CI/CD component](https://gitlab.com/limbowatch/limbowatch-component) and the [Actions action](integrations/action/action.yml).

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
| 1. "State of the Gap" report | draft for review |
| 2. Live Limbo Tracker and an open **limbo feed** (OSV schema) | **live** at [limbo.watch](https://limbo.watch) |
| 3. Contributions to existing tools ([blindspot](https://github.com/munimtechnologies/advisory-import-census), OSV-Scanner) | prepared, not sent ([drafts](docs/outreach/)) |
| 4. Limbowatch watcher for GitLab and Gitea: CI component, issues that update as advisories move through review | **released** as 0.1.0 ([PyPI](https://pypi.org/project/limbowatch-cli/), [GitLab CI/CD Catalog](https://gitlab.com/explore/catalog/limbowatch/limbowatch-component)) |
| 5. Org-wide watch, more ecosystems (Maven/Gradle first) | planned |
| 6. C/C++ and vendored code | planned |

Limbowatch builds only what existing tools don't do. See [the plan](docs/PHASE0_PLAN.md) and [research findings](docs/FINDINGS.md).

## Prior work

This builds on work by [Safeguard](https://safeguard.sh/resources/blog/github-repository-advisories-missing-from-advisory-database-2026-data), [Munim, Inc. (advisory-import-census / blindspot)](https://github.com/munimtechnologies/advisory-import-census) and [RogoLabs](https://rbptracker.org) (Jerry Gamblin).

## License

- **Code:** [Apache-2.0](LICENSE).
- **Research data:** [CC BY 4.0](research/2026-10-state-of-the-gap/data/LICENSE).
- **Advisory data** comes from the [GitHub Advisory Database](https://github.com/advisories) (CC BY 4.0) and [OSV](https://osv.dev).
