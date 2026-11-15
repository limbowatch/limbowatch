# Screenshots

The scan page (limbo.watch/scan/) and the README show five screenshots of the demo, each in dark and light:
`docs/screenshots/<name>.png` (dark) and `<name>-light.png` (light), the same size. The site shows the one that matches
the visitor's theme; the README uses `<picture>` with `prefers-color-scheme`. `tests/test_site.py` checks that every
file exists at the size `SCREENS` in `publish/site.py` declares.

| Name | What | Made by |
|---|---|---|
| `terminal` | `limbowatch scan . --fail-on high` on the demo | `scripts/screenshots.py --demo` |
| `html-report` | the HTML report from the demo pull request's CI run | `scripts/screenshots.py --report` |
| `github-pr-inline` | code scanning alerts on the line the demo pull request adds | signed-in browser |
| `github-job-summary` | the Actions job summary of that run | signed-in browser |
| `gitlab-mr-widgets` | the GitLab demo merge request's pipeline, Code Quality and test summary widgets | signed-in browser |
| `home` | the top of limbo.watch's home page (README and the org profile; dark in both themes, so one file) | `scripts/screenshots.py --site` |

The home page shot comes from a local build of the live data without analytics, so it has no consent banner:

```sh
gh run download <latest showcase run> -R limbowatch/limbowatch -n showcase -D /tmp/showcase
git -C <checkout> archive origin/tracker-data state | tar -x -C /tmp/tracker
uv run limbowatch publish --state /tmp/tracker/state --showcase /tmp/showcase/showcase.json --out /tmp/site
uv run scripts/screenshots.py --site /tmp/site
```

Refresh it when the hero changes, and update the date and numbers in its alt text (README, org profile).

## When to refresh

Refresh after a release that changes what these show: the table, the summary, the report, the GitHub or GitLab
output. Refresh all ten from one run, so the numbers agree with each other and with the captions in `scan()`.

## How

1. **Run the demos on the release.** Bump `limbowatch/demo-app` on GitHub (`.github/workflows/limbowatch.yml`,
   `limbowatch/limbowatch-action@v<version>`) and on GitLab (`.gitlab-ci.yml`, `limbowatch@<semver>`) on `main`, then merge
   `main` into `add-scapy` in both. That reruns the pull request (GitHub #1) and the merge request (GitLab !1).
2. **Own output** (no login). Download the pull request run's report, then generate:

   ```sh
   gh run download <run> -R limbowatch/demo-app -n limbowatch-report -D /tmp/report
   PATH="$PWD/research/2026-10-state-of-the-gap/.cache/bin:$PATH" \
     uv run scripts/screenshots.py --demo <demo-app checkout at add-scapy> --report /tmp/report
   ```

   It runs the released CLI (`uvx --from limbowatch-cli==<version>`), so the terminal shows what users get.
3. **GitHub and GitLab** (a signed-in Chrome). Switch the theme in the page itself, not in the account settings:
   - **GitHub:** load the light theme's stylesheet if the account uses dark (`link[data-color-theme=light]` has only
     `data-href` until it's used), then set `document.documentElement.dataset.colorMode` to `light` or `dark`
     (`dataset.darkTheme = 'dark_colorblind'` matches the existing dark shots).
   - **GitLab:** swap `link[href*="/assets/application"]` between `application-<hash>.css` and
     `application_dark-<hash>.css`, and `link[href*="/highlight/themes/"]` between `white-` and `dark-`. Toggle the
     `gl-dark` class on `<html>`. A signed-out page of the same deployment (`fetch('/gitlab-org/gitlab',
     {credentials: 'omit'})`) lists the current hashes.
   - **Frame like the existing shots:** narrow the element in the page (the diff entry to 980 CSS px, the narrowest
     at which GitHub's alert cards fit their "View details" button; `job-summary` to 800; the merge request widgets'
     container, `.issuable-discussion`, to 743), keep the page at its natural scroll position (scrolling makes the
     sticky headers overlap), move the pointer away, and capture the region at about 2×.
   - **Capture in tiles:** the browser extension's region zoom returns at most about 1,570 px wide and 1.2 megapixels,
     so a whole region comes out at about 1.2×. Zoom two halves of the region (top and bottom, same width), save
     each, and stack them with Pillow; crop the last tile at a gap between blocks.
4. **Update the site.** Put the files in `docs/screenshots/`, update their sizes and alt text in `SCREENS`, and check
   the captions in `scan()` against the run's `report.json` (findings, failing findings, advisories per package).
   `uv run pytest tests/test_site.py` catches a size mismatch or a missing variant.

The last refresh: 2026-11-15, on 0.1.0a15, with the action from GitHub Marketplace and the component from the GitLab
CI/CD Catalog (GitHub run 43693090565, GitLab pipeline 3070036485): 64 advisories in limbo in 4 packages, 7 failing the
build, 54 for scapy. All ten were captured again. dnspython 2.9.1 no longer has an advisory in limbo (GitHub reviewed it on 2026-11-13, FINDINGS F-199), so the pull
request shows only the code scanning alerts on the added scapy line, and the To fix list has four upgrades. The
browser shots were captured in two tiles each (the pull request diff about 1.6×, the job summary and the merge
request widgets about 2×).
