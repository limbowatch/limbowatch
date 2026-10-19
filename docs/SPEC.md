# GhostCVE — Project Spec

## What we're building
GhostCVE is an early-warning tool for dependency vulnerabilities. It is built for teams whose code lives on GitLab (SaaS or self-managed), Gitea, or a plain Git server. It finds "ghost" vulnerabilities: real, public security advisories that standard scanners miss because the advisory hasn't reached the databases those scanners read.

The tool's tagline: "Your scanner is only as fast as the slowest database. GhostCVE alerts you from the source."

## The problem (why the gap exists)
1. A maintainer can publish a repository security advisory on GitHub (github.com/{owner}/{repo}/security/advisories) before GitHub reviews it into the global Advisory Database. Until that happens, Dependabot, npm audit, OSV, and most scanners can't see it. GitHub has no global feed for these. The only way to find them is to poll each repo.
2. GHSA advisories are often published before a CVE is assigned, or without one.
3. As of April 2026, NIST NVD only enriches a prioritized subset of CVEs. About 29k older CVEs were moved to "Not Scheduled." Any scanner that relies on NVD CPE/CVSS data has blind spots.
4. Different sources disagree on affected version ranges.

The key insight: polling every GitHub repo is impossible, but polling only the upstream repos of the dependencies a team actually uses (usually a few hundred) is cheap.

## Core pipeline
1. **Inventory**: collect dependencies (name, ecosystem, resolved version) from a project.
2. **Map**: resolve each package to its upstream source repo using registry metadata.
3. **Collect**: for each dependency and upstream repo, fetch advisory data from every source.
4. **Diff**: compare the sources and classify each gap.
5. **Report / act**: output findings and push them into GitLab.

## Tech stack
- Python 3.12+, `uv` for project management, `ruff` + `mypy --strict`, `pytest`.
- `httpx` (async) for all HTTP. Requests with concurrency limits, retries with exponential backoff, and rate-limit awareness.
- SQLAlchemy 2.0 with SQLite for the MVP (keep Postgres-compatible).
- `typer` for the CLI, `pydantic` v2 for models.
- `univers` (aboutcode) or `packaging` for version and range comparison across ecosystems. Never compare versions as strings.
- `python-gitlab` for GitLab integration (must work with a custom base URL for self-managed instances).
- FastAPI + a React/TypeScript dashboard come later. Don't build them now, but keep the core logic in a library package so an API can wrap it.

## Data sources (verify current API docs before implementing each one)
- **GitHub repository advisories**: `GET /repos/{owner}/{repo}/security-advisories` (published advisories on public repos). This is the main "ghost" signal.
- **GitHub global advisory DB**: `GET /advisories` (filters like `ecosystem`, `affects`, `type`, `modified`) and `GET /advisories/{ghsa_id}`.
- **OSV.dev**: `POST https://api.osv.dev/v1/querybatch` and `GET /v1/vulns/{id}`.
- **NVD API 2.0**: `https://services.nvd.nist.gov/rest/json/cves/2.0?cveId=...`. Store `vulnStatus` as a raw string, and record whether CPE configurations and CVSS metrics are present. Support an optional NVD API key.
- **CVE record**: CVE.org / cvelistV5 to check whether a CVE ID exists and is published, regardless of NVD status.
- **Registry metadata for repo mapping (MVP: npm, PyPI, Go)**:
  - npm: `registry.npmjs.org/{pkg}` → `repository.url`
  - PyPI: `pypi.org/pypi/{pkg}/json` → `info.project_urls` / `home_page`
  - Go: module path (handle `github.com/...` directly, and vanity import paths via `?go-get=1`)
  - Design the mapper as a plugin interface so crates.io, Maven (POM `scm`), and RubyGems can be added later.
  - Normalize repo URLs (git+https, .git suffix, ssh forms, monorepo subdirectories). Store a mapping confidence score, and allow manual overrides via a config file.

**Hard rules:**
- Do NOT ingest or scrape the GitLab Advisory Database (its terms prohibit third-party tool use).
- GHSA data is CC-BY 4.0. Include attribution in reports.
- Use a GitHub token (PAT or GitHub App) from env vars. Never log tokens.
- Use ETag / `If-None-Match` conditional requests on GitHub (304 responses don't count against the rate limit), and cache responses in the DB with timestamps.

## Inventory inputs (MVP)
- CycloneDX JSON SBOM (universal input, so users can generate it with syft, cdxgen, etc.)
- Native parsers: `package-lock.json` (v2/v3, including workspaces and hoisted deps), `requirements.txt` / `poetry.lock` / `uv.lock`, `go.mod` + `go.sum`.
- Use the resolved versions from lockfiles, not declared ranges. If only a range is available, flag it as "unresolved" instead of silently skipping it. Silent skips are exactly the failure mode this product exists to fix.

## Finding classifications
Each finding links one dependency+version to one vulnerability, with the evidence from each source:
- `REPO_ONLY`: published repo advisory affects this version, but it's not in the global GHSA DB. (Highest priority.)
- `NO_CVE`: GHSA exists and affects this version, but has no CVE alias yet.
- `OSV_MISSING`: in GHSA, not yet in OSV.
- `NVD_UNENRICHED`: CVE exists, but NVD has no CPE configs and/or CVSS (scanners matching on NVD will miss or mis-score it).
- `RANGE_DRIFT`: sources disagree on whether this specific version is affected. Show each source's range.
- `UNRESOLVED`: a dependency we couldn't check (no resolved version, or no repo mapping). Always reported, never dropped.

Severity should use the best available score in this order: repo advisory → GHSA → CNA score in the CVE record → NVD. Record which source the score came from.

## CLI (MVP)
- `ghostcve scan <path>`: inventory → map → collect → diff → report.
- `ghostcve scan --sbom bom.json`
- Output formats: `--format table|json|markdown|sarif`. Use SARIF so GitLab and other tools can ingest it.
- Exit codes: non-zero when findings at or above `--fail-on <severity>` exist, so it can gate CI.
- `ghostcve watch --config ghostcve.yml`: polls on a schedule, stores state, and only alerts on new or changed findings.
- Provide a ready-to-use `.gitlab-ci.yml` template that runs `ghostcve scan` and uploads the SARIF/JSON artifact.

## GitLab integration (Phase 4)
- Use a configurable GitLab base URL and token.
- For new `REPO_ONLY` / `NO_CVE` findings, open a GitLab issue in the affected project with labels such as `ghostcve`, `security`, and the classification. Deduplicate by a stable finding key. When a finding later appears in the global DB/OSV/NVD, update the issue (comment noting it "has now reached scanners") instead of opening a new one.

## Phases (stop at the end of each phase for my review)
- **Phase 0, Plan:** read this spec, propose the repo layout, module boundaries, DB schema, and the order of work. List any spec assumptions you think are wrong. Don't write code until I approve.
- **Phase 1, Inventory + mapping:** lockfile/SBOM parsers and the registry → repo mapper for npm, PyPI, and Go, with tests.
- **Phase 2, Collectors:** GitHub repo advisories, GitHub global DB, OSV, NVD, CVE record. Include caching, ETags, rate limiting, and retries.
- **Phase 3, Diff engine:** version-range evaluation and the classifications above. This is the core of the product, so it needs the most thorough tests.
- **Phase 4, Reporting + CI + GitLab:** output formats, exit codes, the GitLab CI template, and issue creation.
- **Phase 5, Watch mode:** scheduling, state, and change detection.

## Engineering rules
- Tests must not hit the live network. Use recorded fixtures (`respx` or similar) built from real API response shapes. Include fixtures for each classification, especially a real-world-shaped `REPO_ONLY` case.
- Use typed models end to end. Keep the core library separate from the CLI.
- Use structured logging. Use a `--verbose` flag to show the source evidence for each decision.
- Keep a README that explains the problem, the classifications, and setup for GitLab SaaS and self-managed.
- When an API's behavior or schema is uncertain, check the official docs and tell me what you found. Don't guess.
