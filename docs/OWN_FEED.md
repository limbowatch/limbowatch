# Your own limbo feed

`limbowatch scan` normally reads the [limbo feed](https://limbo.watch/feed/), which limbo.watch's tracker builds every day. If your team can't fetch it, or your policy says vulnerability data must come from systems you run, you have two options:

- **No feed:** `--feed none`. Each scan reads the advisories of every dependency's source repository on GitHub itself. There's nothing to set up, but every scan makes more requests and some facts are missing ([WATCHER.md: No feed](WATCHER.md#no-feed)).
- **Your own feed**, covered on this page. You run the same tracker limbo.watch runs, on your own CI, and host its feed wherever your scans can reach it. Scans then use `--feed <your URL or directory>` and don't contact limbo.watch.

The feed you build is the same kind of file as limbo.watch's (`all.zip` and `watchlist.json`, in OSV's format), made by the same code from the same public sources: GitHub's advisories, the CVE List and CVE Services, OSV, and optionally NVD. Your feed's data doesn't come from limbo.watch. The only thing taken from the Limbowatch repository is its seed lists: names of popular repositories to watch, at the release you pin. You can replace them with your own.

## Set it up

It needs Limbowatch 0.1.0a17 or later: the first release with `publish --feed-only` and `--feed <URL or directory>`. Take the pipeline files from 0.1.0a18 or later: 0.1.0a17's GitHub pipeline fails in a private repository whose plan doesn't include attestations.

Pick the pipeline for your CI and copy it into a repository or project of your own (an empty one is fine):

| CI | File | Feed URL |
|---|---|---|
| GitHub Actions | [deploy/own-feed/github/limbo-feed.yml](../deploy/own-feed/github/limbo-feed.yml) → `.github/workflows/limbo-feed.yml` | `https://<owner>.github.io/<repo>/feed/` (GitHub Pages) |
| GitLab CI | [deploy/own-feed/gitlab/.gitlab-ci.yml](../deploy/own-feed/gitlab/.gitlab-ci.yml) → `.gitlab-ci.yml`, plus a daily pipeline schedule | Your Pages URL with `/feed/` (Deploy → Pages; new projects get a unique domain such as `https://<project>-<id>.gitlab.io`) |

The comments at the top of each file list what to set. In short:
- **A GitHub token** (`LIMBOWATCH_GITHUB_TOKEN`): a fine-grained token with read access to public repositories. GitHub allows 5,000 requests an hour with one. Without one, GitHub Actions' job token allows 1,000, and GitLab CI has only GitHub's anonymous 60, which is too few.
- **Your own seeds** (optional): `tracker-seeds/*.txt` in the same repository, one `owner/repo` per line, such as the source repositories of the dependencies you care about most.
- **What to watch:** popular repositories, like limbo.watch, or only your own projects' dependencies. See [Popular or focused](#popular-or-focused).
- **Hosting:** both pipelines can publish to Pages. On GitHub, the feed can instead be kept in a branch of the same repository, which your scan jobs check out: see [In a repository](#in-a-repository). Any static HTTPS server works too: S3, GCS, or an internal web server. The feed is the `feed/` folder of the output. On GitLab, Pages follows the project's visibility settings (Settings → General → Visibility → Pages), and scans need to reach it without signing in. In a private project, use a host your scan jobs can reach, or download the feed with a token and pass the directory.

Each run:
1. Restores the tracker's state from the last successful run: a `limbo-feed-state` branch on GitHub, a generic package `limbo-feed-state` in the project's package registry on GitLab. On GitLab the job's own token reads and writes it, and only the two newest copies are kept. Job artifacts would be simpler, but on GitLab Free a job's token can't download an earlier pipeline's artifacts (F-220).
2. On the first run only, downloads the CVE List's bulk export (about 650 MB) so CVEs that name an advisory are known.
3. Runs `limbowatch track`. It syncs GitHub's reviewed advisories and new CVEs, then polls the watched repositories that are due, within a request budget.
4. Runs `limbowatch publish --feed-only`. It writes `feed/` (all.zip, watchlist.json, index.json, SHA256SUMS.txt, one JSON per advisory), `osv/` (the same advisories in OSV-Scanner's download layout) and `metrics.json`.
5. Saves the state and publishes the feed. On GitHub, it also attests the feed files with the workflow's build provenance. In a private repository that works only if your GitHub plan includes attestations for private repositories: on the Free plan, GitHub refuses ("Feature not available … upgrade the billing plan, or make this repository public"), so the step warns and the feed is published unattested. GitHub Pages for a private repository also depends on the plan; the `branch` option works on any plan.

Everything runs in the Limbowatch image of the release you pin, by digest, the same image the scanner uses. To verify the image first: `gh attestation verify oci://ghcr.io/limbowatch/limbowatch:<tag> --owner limbowatch`.

## Popular or focused

| | Popular (default) | Focused |
|---|---|---|
| Watches | The release's seed lists: about 67,000 repositories behind the most-used packages, plus repositories the tracker finds (reviewed advisories' origins, GitHub's CVEs, packages that release) | Only the source repositories of your own projects' dependencies, listed again each run by `limbowatch repos` |
| Size | Like limbo.watch | A few thousand repositories at most |
| First full pass | About four weeks of daily runs (2,500 new repositories a run) | The first run |
| Daily run | Up to 50 minutes | Minutes |
| For | A feed others use too, or projects you can't list | Your own scans |

Set it with the repository variable `LIMBO_FEED_WATCH` (GitHub) or the variable `WATCH` (GitLab), and name the organizations or groups whose projects to list: `LIMBO_FEED_ORGS` (GitHub, default this repository's owner) or `FOCUS_GROUPS` (GitLab, default this project's group). Private projects need a read token, `LIMBOWATCH_SOURCE_TOKEN`.

A focused feed still syncs GitHub's reviewed advisories and the CVE List, so its facts are complete: which advisories are reviewed, which are duplicates, which CVEs are assigned. A dependency added since the last run, or one whose repository the feed hasn't checked in 10 days, is read on GitHub during the scan, as always.

One thing is weaker: a dependency with no known source repository on GitHub (listed at the end of `repos.txt`) is matched against the feed by package name only. A focused feed holds only advisories from your dependencies' repositories, so it can hardly ever match such a package, while the limbo feed, from about 67,000 repositories, sometimes can. Scans report these dependencies as checked by name only either way, never as clean.

The same steps by hand:

```sh
limbowatch repos --github-org acme --out repos.txt     # or project directories, SBOMs, --gitlab-group, --gitea-org
limbowatch track --state state --seed repos.txt --only-seeds
limbowatch publish --state state --out site --feed-only
```

`limbowatch repos` maps each dependency to its source repository the way `scan` does: Go module paths, deps.dev, rubygems.org, Packagist, ecosyste.ms, and a POM's `<scm>`. It sends package names, never files. Dependencies with no GitHub repository are listed at the end of the file, as comments. `track --only-seeds` watches exactly the seed files' repositories: none are added from other sources, and any left in the state from before are no longer polled.

## Use it

```sh
limbowatch scan . --feed https://acme.github.io/limbo-feed/feed/
LIMBOWATCH_FEED=https://acme.github.io/limbo-feed/feed/ limbowatch scan .   # the same
limbowatch scan . --feed ./feed                                              # a directory with all.zip and watchlist.json
```

- **GitHub Actions:** set `LIMBOWATCH_FEED` in the action step's `env`; the action passes it into its container.
- **GitLab:** set it as a CI/CD variable; the component's job uses it as it is.

The URL can point to the folder or to its `all.zip`; `watchlist.json` must be next to it. Only `https://` is accepted, or `http://` to the same machine: anyone on the network could change a feed sent in the clear. If your host needs credentials, download the two files yourself (for example with `curl` and your token), then pass the directory.

### In a repository

With `LIMBO_FEED_PUBLISH` set to `branch`, the GitHub pipeline commits `all.zip`, `watchlist.json`, `index.json` and `SHA256SUMS.txt` to the `limbo-feed` branch of its repository. Each run replaces the branch with a single commit, because a feed's history would grow the repository by about 28 MB a day. Scan jobs check the branch out and pass the directory:

```yaml
- uses: actions/checkout@v7          # pin it by commit, as your other actions
  with:
    repository: acme/limbo-feed
    ref: limbo-feed
    path: limbo-feed
    token: ${{ secrets.LIMBO_FEED_READ_TOKEN }}   # only if the repository is private
- uses: limbowatch/limbowatch-action@v0.1.0a18
  env:
    LIMBOWATCH_FEED: limbo-feed/feed
```

On GitLab CI, clone it the same way in the job before the scan (`git clone --depth 1 --branch limbo-feed https://…`, with a deploy token for a private repository) and set `LIMBOWATCH_FEED` to the directory.

Check the branch out rather than downloading the two files from `raw.githubusercontent.com`:
- raw URLs of a private repository need a token, and `--feed <URL>` sends none;
- GitHub caches raw files for 5 minutes, so a scan could get a new `watchlist.json` with yesterday's `all.zip`. The scan would then skip repositories the new watchlist says were just checked, and could miss a day of advisories. A checkout takes both files from one commit.

What changes from the limbo feed:
- **The report credits your feed.** The table's header names it, the JSON's `feed` holds its URL or directory, and the attribution reads "via a feed built with Limbowatch".
- **No attestation check.** The scan verifies limbo.watch's feed against limbo.watch's build attestation, which says nothing about your feed. With your feed, `--verify-feed auto` skips the check and `require` is refused. Your feed lives on your host, inside your trust boundary. On GitHub, if the run attested it, check its provenance with `gh attestation verify all.zip --repo <owner>/<repo>`.
- **The same age check.** A feed more than 3 days old gets a warning: it means your pipeline stopped running.
- **Holes are filled at scan time,** as with the limbo feed. A dependency's source repository that your feed doesn't watch, or hasn't checked in 10 days, is read on GitHub during the scan. A new feed with a small watchlist still gives complete results, at the cost of GitHub requests per scan, and those drop as your watchlist grows.

## How long it takes

A tracker that starts from nothing first syncs GitHub's reviewed advisories (about 380 requests) and, from then on, the CVEs published each day. Its watchlist then grows from four sources:
- the seed lists (about 66,000 repositories with the release's lists);
- the repositories where reviewed advisories originated (about 3,700);
- repositories named by CVEs from GitHub's CNA;
- repositories of packages that release with many dependents.

Each run polls at most `MAX_NEW` (`max-new`) repositories for the first time, 2,500 by default, so as not to starve the daily re-checks. With the default seeds, the whole watchlist is first polled after about four weeks of daily runs. To get there sooner, run it a few times on the first day with a higher `max-new`: each run polls up to about 3,500 repositories with a token.

Measured on 2026-11-17 with the GitLab pipeline's script in the image (FINDINGS F-215):
- **First run, from nothing:** about 19 minutes. That covers downloading the CVE List (650 MB) and importing its 30,685 CVE records that name an advisory, syncing 37,881 reviewed advisories, and watching 67,350 repositories (with `MAX_NEW` 50, only 50 were polled). Most of the time went to the release checks, mostly 7,387 requests to Maven Central.
- **Next run:** 40 seconds. It restored the state, took the advisories reviewed since, and polled 50 more repositories.
- **Focused, first run** (F-216): the GitHub pipeline listed the limbowatch organization's 5 projects (210 repositories, 7 seconds), then polled all 210 in an 11-minute first run, most of it reading 2,220 changed CVE records one request each. From 0.1.0a19 a new tracker reads only the changes since the bulk export it imported (164 records instead of 2,265 on 2026-11-17, F-220). Scans against a focused feed of three projects' 1,511 repositories found everything the limbo feed did, with 0 to 4 GitHub requests each instead of about 500, in 1.6 to 7.5 seconds.

## Licenses

GitHub's advisory data is CC BY 4.0, so your feed carries GitHub's attribution, as limbo.watch's does. The `top-packages.txt` seed list ranks packages from ecosyste.ms (CC BY-SA 4.0), so a watchlist built from it carries that license too. Leave that list out if you don't want this.
