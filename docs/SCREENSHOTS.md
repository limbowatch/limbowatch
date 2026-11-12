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
   - **Frame like the existing shots:** narrow the element in the page (the diff entry to 784 CSS px, `job-summary` to
     800, the merge request widgets' container to 743), keep the page at its natural scroll position (scrolling makes
     the sticky headers overlap), move the pointer away, and capture the region at 2× or more.
4. **Update the site.** Put the files in `docs/screenshots/`, update their sizes and alt text in `SCREENS`, and check
   the captions in `scan()` against the run's `report.json` (findings, failing findings, advisories per package).
   `uv run pytest tests/test_site.py` catches a size mismatch or a missing variant.

The last refresh: 2026-11-12, on 0.1.0a13, with the action from GitHub Marketplace and the component from the GitLab
CI/CD Catalog (GitHub run 43258602783, GitLab pipeline 3060569992): 63 advisories in limbo in 5 packages, 8 failing the
build, 52 for scapy. rack's and nokogiri's advisories had been reviewed since 2026-11-10, so they left the demo's
findings, and the pull request's diff now also shows the annotation on dnspython's line. The browser shots were
captured with the browser extension's region zoom, about 1.5×.
