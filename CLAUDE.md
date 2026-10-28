# Limbowatch

Makes the advisory review gap visible, then closes it: tracks published security advisories stuck **in limbo** (published by maintainers, not yet reviewed into the databases scanners read), and alerts teams whose dependencies are affected. Formerly "GhostCVE"; renamed 2026-10-21 because "Ghost CVE" already means *reserved but public CVE* (FINDINGS F-037). Use the term "limbo", not "ghost". Open source. GitLab first; the end goal is any repo host and any language, so keep ecosystem- and host-specific code behind plugin interfaces.

- [docs/SPEC.md](docs/SPEC.md): original spec (source of requirements)
- [docs/PHASE0_PLAN.md](docs/PHASE0_PLAN.md): architecture plan (layout, module boundaries, DB schema, order of work)
- [docs/FINDINGS.md](docs/FINDINGS.md): research findings report (source of truth for verified API and ecosystem facts)

## Working in phases

Work proceeds in the phases defined in [docs/PHASE0_PLAN.md §10](docs/PHASE0_PLAN.md) (report → tracker + limbo feed → upstream contributions → watcher). Don't rebuild what blindspot, OSV-Scanner or RogoLabs already do; contribute instead (FINDINGS F-036 to F-039). **Stop at the end of each phase for the user's review.** Do not start the next phase without approval. Phase 0 = plan only, no product code.

## Findings report (docs/FINDINGS.md)

Anything learned while building, whether from docs, live API probes, data measurements or surprises in API behavior, goes into the findings report, not just into chat.

**Add.** When you verify or measure something, append a log entry right away (next `F-NNN` ID). Each entry has:
- date, question, method (exact endpoints/queries, sample size and window), result (numbers), caveats, status, implication, sources
- status values: `confirmed` (official docs or direct observation), `tentative` (small sample or secondary source), `superseded by F-NNN`, `refuted`

**Never silently rewrite results.** If a later finding contradicts an earlier one, add a new entry and mark the old one `superseded by` / `refuted`. Typo and link fixes are fine.

**Clean up and summarize** at the end of each phase, or when the user asks:
- Refresh the **Summary** section at the top so it states the current understanding, with links to entries.
- Merge duplicates and move superseded or refuted entries to the **Archive** section.
- Update **Open questions**. Close the ones that were answered and link the answering entry.
- Keep numbers dated. These facts drift (review backlogs, NVD policy, API changes).

Mention in chat when you add entries, and cite IDs (e.g. "see F-012").

## Verifying external behavior

- When an API's behavior or schema is uncertain, check the official docs. If they are silent, probe the live API with read-only requests and record what you found. Don't guess.
- Live probes are for research only. Tests never hit the network; they use recorded fixtures.
- Use `gh api` for authenticated GitHub calls. Never print, log or commit tokens.
- Verify claims automatically from primary sources (GitHub, OSV, CVE Services/CVE List, NVD), never from web search or AI summaries, which mis-pair IDs (F-049). Don't ask people to verify by hand.
- Keep raw probe output in the session scratchpad. Commit only the summarized results, or small fixtures once the test suite exists.

## Hard rules (from SPEC)

- Never ingest, scrape or query the GitLab Advisory Database (its terms prohibit third-party tool use).
- GHSA data is CC-BY 4.0. Reports must include attribution.
- Never compare versions as strings.
- Never silently drop a dependency. Report unresolved ones.

## Git

Private repo `git@github.com:limbowatch/limbowatch.git` in the **limbowatch** GitHub org (moved from blueandhack/Limbowatch on 2026-10-22; old URLs redirect; the local checkout directory may still be named GhostCVE). The user has authorized committing and pushing to it. Org profile repo: `limbowatch/.github`. Domain: limbo.watch.

## Commands

Product code: a uv workspace (`packages/core` = library `limbowatch`, `packages/cli` = `limbowatch` command). From the repo root:

```sh
uv sync
uv run ruff check packages tests && uv run ruff format --check packages tests
uv run mypy                      # strict
uv run lint-imports              # module boundaries: pure modules do no I/O, sources never classify, core never imports cli
uv run pytest -q                 # recorded fixtures only; tests never hit the network
uv run limbowatch track --state tracker/state --seed tracker/seeds/popular-upstreams.txt --seed tracker/seeds/top100-upstreams.txt --budget 4000
uv run limbowatch publish --state tracker/state --out tracker/site
uv run limbowatch report --state tracker/state --out tracker/reports   # daily Markdown report
```

See [tracker/README.md](tracker/README.md) for how the live tracker works. Only `limbowatch.http` builds requests, and `limbowatch.normalize` drops advisory text and personal data before anything is stored.

Research pipeline (Phase 1 report), from `research/2026-10-state-of-the-gap/scripts/`. It needs uv, go and git, plus a GitHub token via `gh auth token` or `GITHUB_TOKEN`; `NVD_API_KEY` is optional.

```sh
export SNAPSHOT_DATE=2026-10-22   # or $(date +%F); add PROJECT_SET=offgithub for the off-GitHub projects (snapshot name e.g. 2026-10-22-offgithub, CHARTS_SUBDIR=<name> for s7)
uv run s1_inventory.py && uv run s2_map.py && uv run s3_poll.py && uv run s4_status.py \
  && uv run s5_review_lag.py && uv run s8_verify.py && uv run s6_analyze.py && uv run s7_charts.py
# s8 needs the CVE List bulk export at research/2026-10-state-of-the-gap/.cache/cvelist/all.zip.zip (cvelistV5 releases)
SNAPSHOT_DATE=2026-10-22 CVELIST_RELEASE=cve_<date>_<time>Z uv run s9_followup.py   # later re-check of a snapshot's limbo advisories (download that CVE List release first)
uv run --with httpx --with univers python common.py   # range-parser self-check
uvx ruff check --line-length 140 --select E,F,W,B --ignore E501,B905,B007 .
```

HTTP responses are cached in `research/**/.cache/` (gitignored). Intermediate `data/**/*.json` (except `summary.json`) holds advisory text and personal data (F-047). It's gitignored and must never be committed.
