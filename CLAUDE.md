# GhostCVE

Early-warning tool for "ghost" dependency vulnerabilities: public advisories that standard scanners miss because they haven't reached the databases those scanners read. Open source. GitLab first; the end goal is any repo host and any language, so keep ecosystem- and host-specific code behind plugin interfaces.

- [docs/SPEC.md](docs/SPEC.md): original spec (source of requirements)
- [docs/PHASE0_PLAN.md](docs/PHASE0_PLAN.md): architecture plan (layout, module boundaries, DB schema, order of work)
- [docs/FINDINGS.md](docs/FINDINGS.md): research findings report (source of truth for verified API and ecosystem facts)

## Working in phases

Work proceeds in phases 0–5 (see SPEC). **Stop at the end of each phase for the user's review.** Do not start the next phase without approval. Phase 0 = plan only, no product code.

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
- Keep raw probe output in the session scratchpad. Commit only the summarized results, or small fixtures once the test suite exists.

## Hard rules (from SPEC)

- Never ingest, scrape or query the GitLab Advisory Database (its terms prohibit third-party tool use).
- GHSA data is CC-BY 4.0. Reports must include attribution.
- Never compare versions as strings.
- Never silently drop a dependency. Report unresolved ones.

## Git

Private repo `git@github.com:blueandhack/GhostCVE.git`. The user has authorized committing and pushing to it.

## Commands

None yet. Phase 1 scaffolds uv/ruff/mypy/pytest. Add the exact commands here then.
