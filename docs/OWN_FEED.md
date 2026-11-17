# Your own limbo feed

`limbowatch scan` normally reads the [limbo feed](https://limbo.watch/feed/), which limbo.watch's tracker builds every day. If your team can't fetch it, or your policy says vulnerability data must come from systems you run, you have two options:

- **No feed:** `--feed none`. Each scan reads the advisories of every dependency's source repository on GitHub itself. There's nothing to set up, but every scan makes more requests and some facts are missing ([WATCHER.md: No feed](WATCHER.md#no-feed)).
- **Your own feed**, covered on this page. You run the same tracker limbo.watch runs, on your own CI, and host its feed wherever your scans can reach it. Scans then use `--feed <your URL or directory>` and don't contact limbo.watch.

The feed you build is the same kind of file as limbo.watch's (`all.zip` and `watchlist.json`, in OSV's format), made by the same code from the same public sources: GitHub's advisories, the CVE List and CVE Services, OSV, and optionally NVD. Your feed's data doesn't come from limbo.watch. The only thing taken from the Limbowatch repository is its seed lists: names of popular repositories to watch, at the release you pin. You can replace them with your own.

## Set it up

It needs Limbowatch 0.1.0a17 or later: the first release with `publish --feed-only` and `--feed <URL or directory>`.

Pick the pipeline for your CI and copy it into a repository or project of your own (an empty one is fine):

| CI | File | Feed URL |
|---|---|---|
| GitHub Actions | [deploy/own-feed/github/limbo-feed.yml](../deploy/own-feed/github/limbo-feed.yml) → `.github/workflows/limbo-feed.yml` | `https://<owner>.github.io/<repo>/feed/` (GitHub Pages) |
| GitLab CI | [deploy/own-feed/gitlab/.gitlab-ci.yml](../deploy/own-feed/gitlab/.gitlab-ci.yml) → `.gitlab-ci.yml`, plus a daily pipeline schedule | `https://<namespace>.gitlab.io/<project>/feed/` (GitLab Pages) |

The comments at the top of each file list what to set. In short:
- **A GitHub token** (`LIMBOWATCH_GITHUB_TOKEN`): a fine-grained token with read access to public repositories. GitHub allows 5,000 requests an hour with one. Without one, GitHub Actions' job token allows 1,000, and GitLab CI has only GitHub's anonymous 60, which is too few.
- **Your own seeds** (optional): `tracker-seeds/*.txt` in the same repository, one `owner/repo` per line, such as the source repositories of the dependencies you care about most.
- **Hosting:** both pipelines publish to Pages. Any static HTTPS server works instead: S3, GCS, an internal web server, or an artifact your scan jobs download. The feed is the `feed/` folder of the output.

Each run:
1. Restores the tracker's state from the last successful run: a `limbo-feed-state` branch on GitHub, the job's artifacts on GitLab.
2. On the first run only, downloads the CVE List's bulk export (about 650 MB) so CVEs that name an advisory are known.
3. Runs `limbowatch track`. It syncs GitHub's reviewed advisories and new CVEs, then polls the watched repositories that are due, within a request budget.
4. Runs `limbowatch publish --feed-only`. It writes `feed/` (all.zip, watchlist.json, index.json, SHA256SUMS.txt, one JSON per advisory), `osv/` (the same advisories in OSV-Scanner's download layout) and `metrics.json`.
5. Saves the state and publishes the feed. On GitHub, it also attests the feed files with the workflow's build provenance.

Everything runs in the Limbowatch image of the release you pin, by digest, the same image the scanner uses. To verify the image first: `gh attestation verify oci://ghcr.io/limbowatch/limbowatch:<tag> --owner limbowatch`.

## Use it

```sh
limbowatch scan . --feed https://acme.github.io/limbo-feed/feed/
LIMBOWATCH_FEED=https://acme.github.io/limbo-feed/feed/ limbowatch scan .   # the same
limbowatch scan . --feed ./feed                                              # a directory with all.zip and watchlist.json
```

- **GitHub Actions:** set `LIMBOWATCH_FEED` in the action step's `env`; the action passes it into its container.
- **GitLab:** set it as a CI/CD variable; the component's job uses it as it is.

The URL can point to the folder or to its `all.zip`; `watchlist.json` must be next to it. Only `https://` is accepted, or `http://` to the same machine: anyone on the network could change a feed sent in the clear. If your host needs credentials, download the two files yourself (for example with `curl` and your token), then pass the directory.

What changes from the limbo feed:
- **The report credits your feed.** The table's header names it, the JSON's `feed` holds its URL or directory, and the attribution reads "via a feed built with Limbowatch".
- **No attestation check.** The scan verifies limbo.watch's feed against limbo.watch's build attestation, which says nothing about your feed. With your feed, `--verify-feed auto` skips the check and `require` is refused. Your feed lives on your host, inside your trust boundary. On GitHub, check its provenance with `gh attestation verify all.zip --repo <owner>/<repo>`.
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

## Licenses

GitHub's advisory data is CC BY 4.0, so your feed carries GitHub's attribution, as limbo.watch's does. The `top-packages.txt` seed list ranks packages from ecosyste.ms (CC BY-SA 4.0), so a watchlist built from it carries that license too. Leave that list out if you don't want this.
