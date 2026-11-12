# Dependabot and Limbowatch on 13 real projects (November 2026)

**Question.** On real projects, does GitHub's Dependabot report the advisories in limbo that Limbowatch finds? If not, is that because GitHub can't see the dependencies, or because it has no reviewed advisory to alert on?

**Answer.** Dependabot reported **none** of them.
- Projects: the October report's 15 projects, at their current commits.
- Limbowatch: **1,080 confirmed findings** (277 advisories) in **13 of the 15** projects.
- Dependabot: 2,020 alerts on the same files, **0 of them for any Limbowatch finding**.
- GitHub sees every affected dependency: each package and version is in GitHub's own dependency graph for that copy. Dependabot stays silent because none of these advisories has been reviewed into the GitHub Advisory Database yet.

Checked on 2026-11-08. Details: [FINDINGS F-112](../../docs/FINDINGS.md#f-112).

## Results

| Project | Dependencies | Dependabot alerts | Limbowatch findings (advisories) | Covered by a Dependabot alert | Confirmed |
|---|---:|---:|---:|---:|---:|
| GitLab | 8,089 | 988 | 628 (117) | 0 | 616 |
| langchain | 2,456 | 115 | 206 (50) | 0 | 184 |
| n8n | 3,956 | 148 | 84 (61) | 0 | 81 |
| open-webui | 1,993 | 271 | 83 (58) | 0 | 76 |
| Forgejo | 2,137 | 72 | 24 (23) | 0 | 23 |
| GoToSocial | 1,196 | 100 | 23 (23) | 0 | 22 |
| Gitea | 1,192 | 35 | 22 (22) | 0 | 22 |
| Arti | 2,289 | 169 | 22 (21) | 0 | 18 |
| Gitaly | 588 | 85 | 16 (14) | 0 | 12 |
| Mobilizon | 898 | 34 | 14 (10) | 0 | 13 |
| GitLab Runner | 317 | 3 | 10 (10) | 0 | 9 |
| Kubernetes | 1,938 | 0 | 4 (4) | 0 | 3 |
| Fractal | 546 | 0 | 4 (4) | 0 | 1 |
| **Total** | | **2,020** | **1,140 (296 distinct)** | **0** | **1,080** |

Not in the table:
- **aerc:** 46 dependencies, no findings.
- **F-Droid server:** its only dependency file outside test fixtures is a `pyproject.toml` with no lock. Limbowatch reported "no supported lockfile or manifest found" as an unchecked dependency, instead of passing silently.

A finding is one advisory on one package version in one dependency file. The same advisory in several lockfiles of one project counts once per file.

**What "confirmed" means.** Each confirmed finding passed every check below:
- **In range by the ecosystem's own rules.** The installed version is in the maintainer's own range for that package, checked with each ecosystem's library, not Limbowatch's code:
  - npm and Rust: `semver`;
  - PyPI: `packaging`;
  - RubyGems: `Gem::Requirement`;
  - Go: `golang.org/x/mod/semver`.
- **Still published.** The advisory is still published in the upstream repository and not withdrawn.
- **Not reviewed.** It isn't in GitHub's reviewed database.
- **Not in OSV.**

The live re-checks ran just before the comparison.

The 60 other findings:
- **29 reported as "possibly affected" only.** Limbowatch never presented them as certain: the maintainer's range contradicts its own fix, or the advisory names a different major version.
- **26 depend on reading a malformed range.** Five advisories have ranges that match nothing when read literally, such as `<= 2.70.3, >= 3.0.0, <= 3.1.0` and `2.0.0,<2.14.0`. Limbowatch reads the commas as "or" ([F-085](../../docs/FINDINGS.md#f-085)). The fixed versions support that reading, but it's an interpretation.
- **5 are Limbowatch false positives.** Two Go advisories name modules that sit below another module's path but are separate modules: `go.opentelemetry.io/otel/sdk` under `go.opentelemetry.io/otel`, and `github.com/aws/aws-sdk-go-v2/service/*` under `github.com/aws/aws-sdk-go-v2`. Limbowatch matched them to the parent module and compared the parent's version against them ([F-113](../../docs/FINDINGS.md#f-113)).

Severity of the 1,080 confirmed findings: 21 critical, 241 high, 618 medium, 200 low. 95 have a CVE. They had been public for 0.6 to 424 days (median 9.6) when checked.

## Method

`compare.py` runs in three stages; `ranges.py` then checks versions independently.

1. **prepare.**
   - **Clone:** for each project, a sparse, blob-less clone of only its dependency files at the current HEAD. That means lockfiles plus the manifests next to them; test fixtures and vendored copies are left out.
   - **Scan:** `limbowatch scan` 0.1.0a3 on exactly those files, using the limbo feed of 2026-11-08 18:00 UTC.
2. **push.**
   - **Copy:** for each project with findings, a **private** repository `limbowatch/dbcmp-<project>` containing the same files and a README. It holds no source code.
   - **Turn on Dependabot:** alerts are turned on before the files are pushed. The dependency graph builds on a push ([F-090](../../docs/FINDINGS.md#f-090)).
3. **collect.**
   - **Read GitHub's data:** `GET /repos/{r}/dependabot/alerts` and `GET /repos/{r}/dependency-graph/sbom` for each copy, after the alert counts had stopped changing.
   - **Classify each finding:**
     - *alerted:* an alert for the same GHSA or CVE exists;
     - *not alerted:* the package and version are in the graph, and no such alert exists;
     - *not in graph:* the graph doesn't list that package and version.
4. **ranges.py.**
   - **Check the range:** the maintainer's ranges come from `GET /repos/{repo}/security-advisories/{ghsa}`, and each ecosystem's own library tests the installed version against them.
   - **Go paths below the matched module:** the Go module proxy (`GET https://proxy.golang.org/<path>/@v/list`) says whether each path is a package inside that module or a module of its own.

```sh
export PATH="$PWD/research/2026-10-state-of-the-gap/.cache/bin:$PATH"   # OSV-Scanner 2.7.1
python3 research/2026-11-dependabot-compare/compare.py prepare
python3 research/2026-11-dependabot-compare/compare.py push      # creates private repos in the limbowatch org
python3 research/2026-11-dependabot-compare/compare.py collect   # after Dependabot's alert counts settle
python3 research/2026-11-dependabot-compare/ranges.py
```

Committed: the scripts and `data/<date>/summary.json`, which holds counts only. The other files list dependency inventories and advisory IDs per project, and stay out of git, as with the October report.

## Observations about Dependabot

- **Timing.** The dependency graph was ready within a few minutes of the push. Alerts appeared within about 10 minutes for 11 copies. GitLab's first alerts came after about 35 minutes.
- **Kubernetes' 0 alerts are correct.** OSV knows 3 vulnerabilities in its dependencies, all from the Go vulnerability database, and none has a GitHub-reviewed advisory.
- **Dependabot found 2,020 alerts that Limbowatch doesn't report.** That's by design: they are reviewed advisories that scanners already show. Limbowatch covers what comes before review. It complements Dependabot and doesn't replace it.

## Limits

- **Alerts only.** This compares Dependabot alerts, not Dependabot security updates, on copies of the dependency files. Not tested: GitHub's behavior on the real repositories with their full trees, and Dependabot configuration that would ignore some directories.
- **Malformed and imprecise ranges are as maintainers entered them.** GitHub hasn't reviewed them. When a reviewed advisory is published later, its range may differ.
- **A head start, not a permanent difference.** As GitHub reviews these advisories, Dependabot will start alerting on them. Re-running `collect` shows when.
- **GitLab's own Dependency Scanning wasn't compared.** It reads the GitLab Advisory Database, which this project doesn't query.
- **Copies.** The private copies stay up for re-checks and will be deleted when this study ends.

*Advisory data: GitHub repository security advisories and the GitHub Advisory Database (CC BY 4.0); OSV.dev; the Go module proxy.*
