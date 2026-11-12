# limbo.watch redesign: site map and content (Phase 8, step 1)

For review before any code. Wireframes: [wireframes/](wireframes/). Plan: [PHASE0_PLAN.md §13.21](../PHASE0_PLAN.md). Numbers are from 2026-11-12 and will be generated from live data, never typed in.

## The story

Every page tells the same three steps:

1. **Day 0.** The maintainers publish the advisory and ship the fix. It's public: anyone, attackers included, can read what's broken and which version fixes it.
2. **Weeks of silence.** The advisory waits for GitHub's review. Until then Dependabot, npm audit and OSV-Scanner report nothing, so there's no alert, no ticket, no deadline and no upgrade. Teams upgrade when an alert tells them to.
3. **Limbowatch alerts on the next build,** so the clock starts when the risk does.

Tone: the maintainers did their part, and the review queue is the delay. Never blame a maintainer or GitHub's reviewers.

## Site map

Navigation goes from 8 items to 5:

| Nav | Page | Change |
|---|---|---|
| Scan | `/scan/` | Rebuilt: tabs for GitHub, GitLab, Gitea and the CLI; output generated from the current release |
| Tracker | `/tracker/` | Restyled; new "fix released" filter |
| Check | `/check/` | Restyled |
| Learn (menu) | `/compliance/` (new), `/why/`, `/methodology/`, `/press/`, `/feed/`, `/quality/` | Restyled; compliance is new |
| GitHub | repository link | |

Home is `/`. The 25,000 advisory pages (`/advisory/<GHSA>/`) get a new template.

## Home

**Hero**

- Eyebrow: Open source · GitHub, GitLab, Gitea and Forgejo
- Headline: **Fixed upstream. Still clean in your scanner.**
- Lead: Right now **10,059** security advisories are published by maintainers but not yet in the databases Dependabot, npm audit and OSV-Scanner read. **93%** already list a fix. Until GitHub reviews them, nothing alerts you, so nothing gets upgraded.
- Actions: **Add to your CI** · Check a package
- Meta: Live count, re-checked daily, updated 2026-11-12 07:32 UTC.

**Real packages, right now** (generated each run; F-157 rules)

Cards, one per package: name, ecosystem, severity, "fix released N days ago", "advisory published N days ago", "scanner databases: not yet", and a link to the advisory. Today's would be:

| Package | Severity | Fix released | Advisory waiting | Dependabot on that version |
|---|---|---|---|---|
| @sinclair/typebox (npm) | high | 124 days ago | 83 days | no alerts |
| nats-server (Go) | high | 176 days ago | 136 days | no alerts |
| go-openapi/spec (Go) | critical | 115 days ago | 114 days | no alerts |
| rubyntlm (RubyGems) | critical | 64 days ago | 64 days | no alerts |
| go-toml/v2 (Go) | high | 130 days ago | 128 days | no alerts |
| mustache (RubyGems) | critical | 84 days ago | 84 days | no alerts |

Not used, though in limbo: jackson-core, vm2, mistune and netty-handler. Reviewed advisories on those versions (in GitHub's database or OSV) already ask for an upgrade to the limbo fix or past it, so scanner users get it by coincidence (F-158, F-159). The generated list skips such versions.

Caption: The maintainers published each advisory and shipped the fix. None is in GitHub's reviewed database or OSV yet, so the scanners above don't report it. Re-checked daily; a package leaves this list when GitHub reviews it.

Proof line: "We pinned these versions in a test repository. Dependabot raised 95 alerts on the control packages and none on these." (F-158)

**The clock starts late** (today's slider, simplified)

- Day 0: advisory and fix published. Your scanner: nothing.
- Day 23: GitHub reviews it (October's median). Your scanner alerts; your policy's 30-day clock starts.
- Day 53: you fix it, on time by your policy. Exposed for 53 days.
- Under PCI DSS the month runs from the fix's release: the alert arrives with 7 days left, and 44% of October's reviews took longer than 30 days.
- Link: For security and compliance leads →

**The numbers** (live)

- 10,059 advisories in limbo · 4,918 critical or high · median wait so far 55 days
- Last 7 days: 847 published, 107 reviewed
- Dependabot: 0 alerts for 1,080 confirmed findings in limbo across 13 real projects (F-112)

**How it works**

1. **Track.** 67,471 repositories checked on schedule for published advisories.
2. **Publish.** An open feed in OSV format that any scanner can read.
3. **Alert.** `limbowatch scan` in your CI: annotations, a job summary, SARIF, and issues that update as advisories move through review.

**Close:** Add it to your CI in two lines (GitHub Action and GitLab component snippets) · Check a package · Open source, Apache-2.0.

## Compliance (new, `/compliance/`)

- Headline: **Compliant, and exposed.**
- Lead: Remediation deadlines usually start when your scanner detects a vulnerability. For an advisory in limbo, that's weeks after it went public.
- **SOC 2.** CC7.1 asks you to detect "susceptibilities to newly discovered vulnerabilities" and remediate "on a timely basis". It sets no number of days: your policy does, usually counted from the scanner's alert (F-134).
- **PCI DSS.** Requirement 6.3.3: critical patches "within one month of release" (PCI SSC FAQ 1597). Counted from the fix, so limbo uses up the month (F-134).
- **US federal agencies, BOD 26-04.** The clock starts at the first of identification on an asset or a listing in CISA's KEV catalog; 3 to 60 days by exposure and impact (F-156).
- Chart: three clocks on a 60-day axis, as on today's home page.
- What helps: alert at publication, not review (Limbowatch in CI); keep the reports (SARIF, JUnit, JSON, each with dates) as evidence; track advisories in limbo as findings.
- Footer: How the frameworks are worded, with sources. Not audit advice.

## Scan (`/scan/`)

- Headline: **Find what your scanner can't see yet.**
- Tabs: **GitHub** (Action, PR annotations, job summary, issues with the job's token) · **GitLab** (component, MR widget, Code Quality, confidential issues) · **Gitea/Forgejo** · **CLI**.
- Each tab: a two-line setup snippet, then a screenshot or terminal output generated from the current release, never older output.
- "What it reports": the table per lockfile, the upgrade that clears each package, and "can't be checked" entries, never silently dropped.

## Advisory page template (`/advisory/<GHSA>/`)

- Title: package, ecosystem, severity.
- Banner, leading with the fix: **Fixed in 2.18.10, released 2026-08-16 (88 days ago).** Not yet in GitHub's reviewed database or OSV, so Dependabot, npm audit and OSV-Scanner don't report it.
- Status timeline: published by the maintainers → CVE state → GitHub review (waiting N days).
- Affected and fixed versions, as the maintainers entered them.
- "Are you affected?": the scan command and the Action snippet.
- Links: the advisory on GitHub, the CVE; attribution (CC BY 4.0). No advisory text (F-047).

## Other pages

Why, Methodology, Press, Feed and Data quality keep their content and get the new design. Press gains the examples table as CSV.
