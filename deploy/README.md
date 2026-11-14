# Deploying limbo.watch

The public site is the static output of `limbowatch publish`, served from the Cloudflare R2 bucket `limbowatch-site` on the custom domain limbo.watch, at $0 a month ([docs/HOSTING_PLAN.md](../docs/HOSTING_PLAN.md)). Until 2026-11-14 nginx served it from a k3s cluster (FINDINGS F-184).

## How an update reaches the site

1. The daily `tracker` workflow updates the state on the `tracker-data` branch.
2. When it succeeds, the `site` workflow:
   - publishes the site from that state, keeping each feed record's `modified` unless it changed (F-174);
   - uploads the files that changed to R2 (`scripts/sync_r2.py`), each with its `Content-Type` and `Cache-Control: max-age=300`. It refuses to delete more than 2% of the bucket.

   `site` also runs when the site code changes, or on demand: `gh workflow run site.yml`.
3. Cloudflare serves the bucket behind its cache. A daily deploy takes about 2 minutes (F-185).

## What serves what

| Part | Where | What it does |
|---|---|---|
| Bucket `limbowatch-site` | R2, custom domain `limbo.watch` (minimum TLS 1.2) | Holds and serves the built site |
| Zone rules | [`cloudflare/rules.json`](cloudflare/rules.json), applied by `scripts/cf_rules.py` | `/x/` → `x/index.html`; `/x` → `/x/`; www → apex; the security headers; CORS on `/feed/`, `/osv/` and `/metrics.json`; caching |
| Worker `limbowatch-site` | [`worker/`](worker/), on `limbo.watch/osv/*` | Adds `X-Goog-Hash` for OSV-Scanner (F-073). Fails open: past the free 100,000 requests a day, R2 answers without it |
| `www.limbo.watch` | CNAME to limbo.watch, proxied | Redirected to the apex by a zone rule |

Nothing in this repository names a Cloudflare account. Moving to another account is the checklist in docs/HOSTING_PLAN.md, "Moving to another Cloudflare account".

## Credentials

| Credential | Where | Can do |
|---|---|---|
| R2 token `limbowatch-r2-sync` (account token, expires 2027-11) | GitHub environment `site` (main only): `R2_ACCESS_KEY_ID`, `R2_SECRET_ACCESS_KEY`; plus `CF_ACCOUNT_ID` and the variable `R2_BUCKET` | Read and write objects in `limbowatch-site`, nothing else |
| Maintainer token (user token, short-lived) | Your keychain only (`limbowatch-cf-maintainer`) | Zone rules, the Worker and its routes on limbo.watch |

## Changing the Worker or the rules

```sh
export CLOUDFLARE_ACCOUNT_ID=… CLOUDFLARE_API_TOKEN="$(security find-generic-password -s limbowatch-cf-maintainer -w)"
(cd deploy/worker && npx vitest run && npx wrangler deploy)
uv run python scripts/cf_rules.py --zone limbo.watch --host limbo.watch --www www.limbo.watch   # --dry-run first
```

**Run `cf_rules.py` after every `wrangler deploy`.** A deploy turns the route back to failing closed, and `cf_rules.py` sets it to fail open again (F-183). The Worker's tests run in CI (`ci.yml`, job `worker`).

To try a change before it reaches limbo.watch, connect a second hostname to the bucket (for example `next.limbo.watch`) and pass it to `cf_rules.py` and `wrangler.jsonc` as well. Then compare the two hosts with `uv run python scripts/check_hosting.py --old https://limbo.watch --new https://next.limbo.watch`.

## Analytics

Google Analytics is off unless the repository variable `LIMBOWATCH_GA_ID` (Settings → Secrets and variables → Actions → Variables) holds a GA4 measurement ID (`G-…`). It isn't a secret: it appears in every page.

With it set, every page loads Google Analytics in Consent Mode:
- every storage type is denied until a visitor clicks **Allow cookies** on the banner. Until then, and after **No thanks**, Google gets only cookieless pings;
- ad storage is never granted;
- the choice is kept in the visitor's browser, and the footer's **Cookie settings** link changes it.

The Content-Security-Policy, in `cloudflare/rules.json` and `worker/src/serve.js`, allows `www.googletagmanager.com`, `*.google-analytics.com` and `*.google.com` (Google's list for Analytics without Ads features). Remove them from both if analytics is turned off for good.

## Checking it

```sh
curl -sI https://limbo.watch/osv/PyPI/all.zip    # X-Goog-Hash, Access-Control-Allow-Origin, the security headers
uv run python scripts/cf_rules.py --zone limbo.watch --host limbo.watch --www www.limbo.watch --dry-run   # nothing to change
gh run list --workflow site.yml --limit 3
```
