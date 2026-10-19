# Phase 0 Plan

Status: **proposed, awaiting approval** (2026-10-19). See [SPEC.md](SPEC.md) for the original spec.

## 1. Verified API facts

Checked against official docs and, where docs were silent, read-only probes of the live endpoints on 2026-10-19.

| Claim | Finding |
|---|---|
| `GET /repos/{o}/{r}/security-advisories` works without auth on public repos | **Yes.** Live probe returned 200 with an `ETag`; anonymous limit is 60/hr. Docs: "Anyone can access any published security advisory on a public repository." Fields include `vulnerabilities[].package{ecosystem,name}`, `vulnerable_version_range`, `patched_versions`, `cve_id` (nullable), `cvss_severities`, `state` (incl. `withdrawn`). |
| `GET /advisories` returns everything | **No.** "By default… will only return reviewed advisories that are not malware." `type=unreviewed` and `type=malware` must be requested explicitly. Pagination is cursor-based via the `Link` header, max 100 per page. |
| 304s are free | Only for authenticated requests. A token is effectively required beyond ~60 repos. |
| OSV `querybatch` returns full records | **No.** It returns only `id` + `modified`. Pagination is per query (`next_page_token`) once a query exceeds 1,000 results or a batch exceeds 3,000. Records are hydrated via `/v1/vulns/{id}`. |
| NVD April 2026 change | Confirmed by secondary sources: from 2026-04-15, enrichment is prioritized to KEV, federal-use software and EO 14028 critical software, and the backlog moved to "Not Scheduled". Unconfirmed whether "Not Scheduled" is an API `vulnStatus` value (one blog maps it to `Deferred`), so `vulnStatus` is stored as a raw string. |
| NVD "has CVSS" | Needs nuance. A live record had both `Primary` (NIST) and `Secondary` (CNA) metrics. A CVE NIST never enriched can still carry a CNA score in NVD. |
| CVE record lookup | `https://cveawg.mitre.org/api/cve/{id}` returned 200 without auth (observed behavior; no official doc found). Preferred over cloning cvelistV5. |
| Go vanity paths | `proxy.golang.org/{mod}/@v/{ver}.info` returns `Origin.URL` (for `golang.org/x/net` → `https://go.googlesource.com/net`). `?go-get=1` meta tag is the fallback. |
| GitLab ingests SARIF | With caveats: `artifacts:reports:sarif` requires **Ultimate**; flag in 18.11, GA in 19.2. Only identifiers drive classification: a finding is dependency scanning only if it carries a CVE, otherwise SAST. |

**Unverified core premise:** whether a published repo advisory stays absent from `/advisories/{ghsa_id}` until GitHub reviews it. No doc describes that pipeline. Phase 2 will test it against a recently published real advisory and record the result as the `REPO_ONLY` fixture. If the advisory appears immediately as `unreviewed`, `REPO_ONLY` is redefined as "not *reviewed* in the global DB". That definition is the useful one anyway, because Dependabot doesn't alert on unreviewed advisories.

## 2. Proposed spec changes

1. **Classifications are flags, not one exclusive value.** Each finding has a set of flags plus a `primary` (highest priority) for sorting and gating. Flags already implied by another are hidden (`REPO_ONLY` implies `OSV_MISSING`).
2. **`UNRESOLVED` is per check, not per dependency.** A package with no repo mapping is still checked against GHSA and OSV. Only the repo-advisory check is skipped, and that gap is reported. Upstreams not on GitHub get a recorded reason.
3. **`go.sum` is not an inventory.** It contains hashes for modules outside the build list.
   - Use `go.mod` with `replace`/`exclude` applied. Since Go 1.17, graph pruning lists every needed dep as `// indirect`.
   - Flag pre-1.17 modules as incomplete.
   - Optionally use `go list -m all` when the toolchain is present.
   - Use `go.sum` only to cross-check.
4. **`NVD_UNENRICHED`** means "no NIST `Primary` metrics and/or no `configurations`". It defaults to informational, because language-package scanners don't match on NVD CPEs.
5. **`RANGE_DRIFT`** compares only repo advisory, GHSA and OSV. NVD CPE ranges describe products, not packages, so they're shown as context only. OSV event ranges and GitHub range strings each get their own evaluator, on a shared per-ecosystem comparator.
6. **`OSV_MISSING` checks aliases** (`GO-…` and `PYSEC-…` records carry GHSA aliases).
7. **Registry metadata is fetched per version** (`registry.npmjs.org/{pkg}/{version}`, `pypi.org/pypi/{pkg}/{version}/json`). npm `repository` may be shorthand or an object with `directory`.
8. **Monorepos:** repo advisories match on `vulnerabilities[].package`, not on the repo alone. Advisories with null or `other` package data become low-confidence findings rather than being dropped.
9. **Severity order:** GHSA-reviewed, then repo advisory, then CNA, then NVD (curators sometimes correct scores after review), always recording the source. Unscored findings are `unknown`, and gating uses an explicit `--fail-on-unknown`.
10. **CVE records** come from cveawg; cvelistV5 is an optional offline mode later.
11. **Withdrawn advisories** are excluded and recorded as a finding change.
12. **CI state:** use `scan --state <db>` with a GitLab cache or artifact; `watch` is for long-running hosts.
13. **Small additions:** parse `package-lock` v1; mark marker- and extras-scoped Python deps; add Alembic migrations.

## 3. Repo layout (uv workspace)

```
GhostCVE/
├─ pyproject.toml                 # workspace root; ruff, mypy --strict, pytest, import-linter
├─ packages/
│  ├─ core/src/ghostcve/
│  │  ├─ models/                  # pydantic v2 domain models
│  │  ├─ inventory/               # cyclonedx, npm_lock, requirements, poetry_lock, uv_lock, gomod
│  │  ├─ mapping/                 # RepoMapper protocol + registry; npm, pypi, go; url_normalize; overrides
│  │  ├─ http/                    # async client: limits, backoff, rate limits, ETag cache, token redaction
│  │  ├─ sources/                 # github_repo, github_global, osv, nvd, cve_record → SourceRecord
│  │  ├─ versions/                # per-ecosystem comparators; github_range + osv_events evaluators
│  │  ├─ diff/                    # PURE: alias graph, evaluate, classify, severity
│  │  ├─ report/                  # table, json, markdown, sarif (+ GHSA CC-BY attribution)
│  │  ├─ integrations/gitlab/
│  │  ├─ store/                   # SQLAlchemy 2.0 models, repositories, alembic/
│  │  ├─ watch/
│  │  ├─ config.py
│  │  └─ pipeline.py              # scan(): public API surface
│  └─ cli/src/ghostcve_cli/       # typer CLI, formats, exit codes, --verbose evidence
├─ tests/{fixtures,scenarios}/
├─ scripts/record_fixture.py      # only code touching the live network; run manually
├─ templates/.gitlab-ci.yml
└─ README.md
```

**Boundary rules, enforced with import-linter:**
- `diff/` and `versions/` do no I/O.
- `sources/` never classifies.
- core never imports cli.
- Only `http/` builds requests.

## 4. DB schema

| Table | Key columns |
|---|---|
| `http_cache` | `key` (unique), `etag`, `last_modified`, `status`, `body`, `fetched_at`, `expires_at` |
| `packages` | `id`, `ecosystem`, `name`, `purl` (unique) |
| `repo_mappings` | `package_id`, `host`, `owner`, `repo`, `subdir`, `confidence`, `method`, `evidence`, `resolved_at` |
| `projects` | `id`, `name`, `path_or_url`, `gitlab_base_url`, `gitlab_project_id` |
| `scans` | `id`, `project_id`, `started_at`, `finished_at`, `input_kind`, `input_ref`, `tool_version` |
| `scan_dependencies` | `scan_id`, `package_id`, `version`, `declared_spec`, `resolution`, `direct`, `dev`, `source_file` |
| `source_records` | unique(`source`, `source_id`), `modified_at`, `fetched_at`, `raw`, `normalized` |
| `record_aliases` | `record_id`, `alias` (indexed) |
| `record_affected` | `record_id`, `ecosystem`, `package_name`, `range_kind`, `range_data` |
| `findings` | `finding_key` (unique: sha256(project, ecosystem, package, canonical_vuln_id)), `flags`, `primary_class`, `severity`, `severity_source`, `status`, `first_seen`, `last_seen`, `evidence` |
| `finding_events` | `finding_id`, `scan_id`, `event`, `diff`, `at` |
| `gitlab_issues` | `finding_id`, `base_url`, `project_id`, `issue_iid`, `last_synced_at` |

The finding key leaves out the version on purpose: upgrading from one affected version to another updates the existing issue instead of opening a new one.

## 5. Order of work

1. **Phase 1:** scaffold and CI for this repo, then models and version comparators, then parsers, URL normalizer, mappers with overrides, and the `http/` layer.
2. **Phase 2:** the five collectors, the ETag cache, rate-limit handling, and the `REPO_ONLY` premise check.
3. **Phase 3:** alias graph, both range evaluators, classification and severity, with table-driven and property-based tests.
4. **Phase 4:** reporters, exit codes, CI template, GitLab issues.
5. **Phase 5:** watch mode and change detection.

## 6. Open questions

1. GitLab tier and version: add `--format codequality` (works on every tier) alongside SARIF?
2. Malware advisories: defer past MVP?
3. Should unscored `REPO_ONLY` findings fail CI by default (`--fail-on-unknown=true`)?
4. Approve the deviations in §2, especially #2, #3 and #9?

## Sources

- [GitHub REST: global advisories](https://docs.github.com/en/rest/security-advisories/global-advisories)
- [GitHub REST: repository advisories](https://docs.github.com/en/rest/security-advisories/repository-advisories)
- [About the GitHub Advisory Database](https://docs.github.com/en/code-security/security-advisories/working-with-global-security-advisories-from-the-github-advisory-database/about-the-github-advisory-database)
- [OSV querybatch](https://google.github.io/osv.dev/post-v1-querybatch/)
- [GitLab SARIF reports](https://docs.gitlab.com/user/application_security/detect/sarif/)
- [NVD vulnerability status](https://nvd.nist.gov/vuln/vulnerability-status)
- [SecurityWeek: NIST prioritizes NVD enrichment](https://www.securityweek.com/nist-prioritizes-nvd-enrichment-for-cves-in-cisa-kev-critical-software/amp/)
- [CSA research note on NVD enrichment](https://labs.cloudsecurityalliance.org/research/csa-research-note-nist-nvd-enrichment-changes-enterprise-vul/)
- [lilting.ch on Deferred/Not Scheduled](https://lilting.ch/en/articles/nist-nvd-risk-based-cve-enrichment)
- [Go `mod_list_issue61423` test script (Origin)](https://go.dev/src/cmd/go/testdata/script/mod_list_issue61423.txt)
