# Plan: serve limbo.watch from Cloudflare R2, at $0 a month

Status: approved 2026-11-14 (the $0 setup); steps 1 and 2 done. Replaces the nginx image on the k3s cluster ([deploy/README.md](../deploy/README.md)). Facts and numbers: FINDINGS F-171 to F-180.

## Goals

1. Serve the site and feed as nginx does today: same URLs, headers that matter to clients, ETags, `HEAD`, 304s and ranges. Pinned old watchers keep working.
2. No limit due within a year: no 1 GB site cap, no file-count cap, no 25 MiB file cap, no daily request cap that can take the site down.
3. **$0 a month** at today's traffic and far beyond it.
4. **Portable:** moving to another Cloudflare account is a checklist, not a project.
5. **Safe in a public repo:** the Cloudflare credential in GitHub can do as little as possible, and misuse can be detected.

## Design

```
GitHub Actions (site.yml)                     Cloudflare account (Free plan)
  limbowatch publish ──scripts/sync_r2.py──▶  R2 bucket "limbowatch-site"
                                                   ▲
  visitors, watchers ──https──▶ limbo.watch ──────┤ R2 custom domain, behind Cloudflare's cache and zone rules
                                  /osv/* only ──▶ Worker "limbowatch-site" (X-Goog-Hash; fails open to R2)
```

- **R2 holds the built site**, uploaded as-is, and serves it directly on the custom domain. It's a copy, not the source: everything can be rebuilt from the `tracker-data` branch. No data ever needs migrating.
- **Each file's `Content-Type` and `Cache-Control` are set when it's uploaded**, by `scripts/sync_r2.py`: nginx's types (including `text/csv; charset=utf-8` and `application/atom+xml`), and `max-age=300` because the data changes daily.
- **Zone rules do the rest of nginx's job.** They're kept in `deploy/cloudflare/rules.json` and applied by `scripts/cf_rules.py`, so they move with the repo, not with the account:

  | Rule | Kind | What it does |
  |---|---|---|
  | index | URL rewrite | a path ending in `/` → the same path + `index.html` |
  | slash | redirect, 301 | a path without `/` at the end and without `.` → the same path + `/`, keeping the query (all site files have an extension; pages are directories) |
  | www | redirect, 301 | `www.limbo.watch` → `https://limbo.watch`, same path and query |
  | security | response headers | CSP, HSTS, nosniff, Referrer-Policy, Permissions-Policy on every response, 404s included |
  | cors | response headers | `Access-Control-Allow-Origin: *` on `/feed/`, `/osv/` and `/metrics.json` |
  | cache | cache rule | cache everything, honouring each file's `max-age=300`, so most requests never read R2 |

  That's 3 of the Free plan's 10 Transform Rules, 2 of its 10 redirect rules, and 1 cache rule.
- **The Worker runs only on `limbo.watch/osv/*`**, to add `X-Goog-Hash` from `osv/crc32c.map` (F-073). It's the code from step 2 (`deploy/worker/`), set to **fail open**: past the free 100,000 requests a day, requests skip it and R2 answers without the header. No client needs that header yet: OSV-Scanner can't be pointed at limbo.watch until upstream adds a host option (F-073).
- **ETags, 304s, byte ranges and `HEAD`** come from R2 and Cloudflare, as standard.
- **What changes for visitors:**
  - a 404 shows R2's plain error page, not nginx's;
  - a missing path without a file extension (`/nope`) is first redirected to `/nope/`, then 404s;
  - redirects use `https`;
  - ETags change format, so each watcher with a cached feed downloads it once after the switch.

### Search and the package checker

Both run in the visitor's browser, so they work unchanged:
- **The tracker's search** loads `tracker/data.json` (4.7 MB, 1.27 MB as transferred today) and filters in the browser.
- **The checker** loads `check/index.json` (1.4 MB, 0.29 MB transferred) and asks deps.dev, from the browser, for the package's dependency tree. That traffic goes to Google's free API, not to limbo.watch.

Each costs one or two cached file requests per visit, and the CSP keeps `connect-src` open to `api.deps.dev`. If `tracker/data.json` gets heavy as the tracker grows, it can be split (by ecosystem, or recent versus older), still as static files.

### Cost

| Item | Use | Free tier |
|---|---|---|
| R2 storage | about 0.5 GB | 10 GB a month |
| R2 writes (Class A) | about 3,100 a day since step 1 (F-178), about 93,000 a month | 1 million a month |
| R2 reads (Class B) | cache misses only; at most about 180,000 a month today (F-175) | 10 million a month |
| Bandwidth | 14.58 GB in the last 30 days | not charged |
| Worker (`/osv/*` only) | a few hundred requests a day | 100,000 a day, then it fails open |
| Zone rules | 6 rules | Free plan |
| GitHub Actions | about 2,300 minutes a month | free for public repos (F-180) |

So **$0 a month**. Beyond the free tier, R2 charges $0.36 per million reads, and only cache misses read R2. Fallback: if the free rules prove insufficient, the step 2 Worker can serve the whole site on Workers Paid ($5 a month, F-176) with one config change.

## Moving to another Cloudflare account

The design keeps everything that belongs to one account out of the code:

- **No account values in the repo.** The account ID, bucket name and hostname are GitHub Actions *variables* (`CF_ACCOUNT_ID`, `R2_BUCKET`, `SITE_HOST`). `wrangler.jsonc` leaves out `account_id`, so wrangler reads `CLOUDFLARE_ACCOUNT_ID`.
- **The zone rules are files in the repo**, applied by a script, not clicked together in the dashboard.
- **Account-owned tokens** (`cfat_…`), not user tokens: they belong to the account, keep working if a person leaves, and are made again in the new account.
- **No data to copy:** the first sync to a new bucket uploads the whole site (about 52,000 writes, inside the free tier).
- **The zone is the only slow part.** Moving `limbo.watch` means adding it to the new account and changing the nameservers at the registrar (Spaceship). Certificates aren't carried over, and Cloudflare issues new ones. DNSSEC is off.

Checklist, kept in `deploy/README.md`:
1. In the new account: add the zone; create the bucket; create the tokens (below).
2. In GitHub: update the variables and the `site` environment's secret.
3. Run `site.yml` (a full sync). Apply the rules with `scripts/cf_rules.py`, connect the bucket's custom domain, and deploy the Worker route.
4. Change the nameservers at the registrar. When the zone is active, run the parity check (step 4).
5. After a week, delete the old account's bucket, Worker and tokens.

**Rehearsal:** the first setup follows this checklist word for word, on the test hostname first (step 4).

## Credentials in a public repo

Secrets in a public repo are safe if they reach only trusted code, can do little, and misuse would show. The repo already does this for `LIMBOWATCH_GITHUB_TOKEN` and `NVD_API_KEY`.

**Who can read a secret.** GitHub doesn't pass secrets to workflows run from forks, and this repo never uses `pull_request_target`. So only code already on `main` runs with secrets. `site.yml` runs on `workflow_run` from `tracker`, checks out `main`, and runs no code from a pull request.

**One token in GitHub; the others stay with you:**

| Token | Permission | Where | Used by |
|---|---|---|---|
| `R2_SYNC` (account token) | R2 **Object Read & Write**, on bucket `limbowatch-site` only; expires after a year | GitHub environment `site`, limited to `main` | `site.yml`, daily |
| Worker deploy (account token) | Workers Scripts Edit; Workers Routes Edit on `limbo.watch`; expires after 90 days | not in GitHub: used from your machine, only when `deploy/worker/` changes | `npx wrangler deploy` |
| Zone rules (account token) | Transform Rules, Single Redirect and Cache Rules Edit on `limbo.watch`; short expiry | not in GitHub: used from your machine | `scripts/cf_rules.py` |

- The worst case for `R2_SYNC`: someone who ran code on `main` could replace site files. That's the same power the workflow's own `GITHUB_TOKEN` has today, since it pushes the site image and commits the deploy tag. It can't change DNS, rules, the Worker or the account.
- The feed is also protected by the checksums published on GitHub (the feed-integrity work). A tampered feed fails the watchers' check and `scripts/audit.py`.

**Repo hardening** (done 2026-11-13): secret scanning and push protection; approval for outside contributors' workflow runs; actions pinned to a full SHA, enforced; ruleset `protect main` (no force pushes, no deletion). Still to do: run `zizmor` (a static checker for GitHub workflows) in `ci.yml`. The new design also ends the bot's daily `ci: deploy site` commits to `main`. Scripts read credentials from the environment and never print them.

**Detection:** Cloudflare's audit log records token, rule and Worker changes. The audit compares the live feed's digests with the ones on GitHub.

## Steps

Each step ends in a working state; nothing changes for users until step 5.

0. **Inputs** (you):
   - Done: traffic checked (F-175); the personal account for now (decided 2026-11-13).
   - Create the bucket `limbowatch-site`. R2 may ask for a payment method even on the free tier.
   - Create the `R2_SYNC` token; add it to the GitHub environment `site`; add the variables.
   - Make the Worker-deploy and zone-rules tokens when steps 3 and 4 need them.
   - No Workers Paid subscription.
1. **Stable feed `modified`** (done 2026-11-14, F-178): changed files a day went from 27,615 to 3,112.
2. **Worker** in `deploy/worker/`, with tests in workerd (done 2026-11-14, F-179). In the $0 setup it serves `/osv/*` only. Next: a route in `wrangler.jsonc`, and fail open.
3. **Sync and rules** (code done 2026-11-14; `site.yml` uploads once the `site` environment has `R2_BUCKET` and the R2 secrets):
   - `scripts/sync_r2.py`: list the bucket, compare MD5s, upload changed files with their `Content-Type` and `Cache-Control`, upload the big zips and `crc32c.map` last, and delete removed files. It refuses to delete more than 2%, so a broken build can't wipe the site. Tested offline with a stubbed S3 client.
   - `deploy/cloudflare/rules.json` and `scripts/cf_rules.py` (Rulesets API): idempotent, `--dry-run` shows the diff, and the hostnames are a parameter.
4. **Test hostname and parity check** (done 2026-11-14, F-183: 165 paths, 0 differ):
   - Connect the bucket to `next.limbo.watch` as well, with the rules and the `/osv/*` route on both hostnames.
   - First confirm the Free plan accepts the rewrite and redirect rules (F-180 leaves this open).
   - `scripts/check_hosting.py` compares `limbo.watch` (nginx) and `next.limbo.watch` path by path: status, headers, body digest, `HEAD`, 304, ranges and `X-Goog-Hash`.
   - Old watcher releases and OSV-Scanner's refresh path run against `next`.
   - The tracker search and the checker are tried in a browser.
5. **Switch:**
   - Connect `limbo.watch` and `www.limbo.watch` to the bucket, replacing the DNS records that point at the cluster.
   - Keep the cluster serving for a week as the fallback. Going back means restoring those DNS records.
6. **Retire:**
   - Remove `deploy/site`, `deploy/k8s`, `deploy/argocd-app.yaml`, the site image build, the Argo CD app and the ghcr package.
   - Rewrite `deploy/README.md`, and remove `next.limbo.watch`.

## Open questions

- ~~Do dynamic URL rewrites and redirects work on the Free plan?~~ Yes (F-183).
- ~~Can a route's fail-open be set by config?~~ Through the API (`request_limit_fail_open`), which `cf_rules.py` does. `wrangler deploy` resets it, so run `cf_rules.py` after every deploy (F-183).
- Does Cloudflare accept GitHub's OIDC tokens in place of a stored API token? Nothing found yet.
- ~~**AI crawlers**~~ Decided 2026-11-13: allow them (F-175). In the $0 setup they cost nothing.
