# Plan: serve limbo.watch from Cloudflare R2 and a Worker

Status: proposed, 2026-11-13. Replaces the nginx image on the k3s cluster ([deploy/README.md](../deploy/README.md)). Facts and numbers: FINDINGS F-171 to F-174.

## Goals

1. Serve the site and feed exactly as nginx does today: same URLs, headers, ETags, `HEAD` and 304s. Pinned old watchers keep working.
2. No limit due within a year: no 1 GB site cap, no file-count cap, no 25 MiB file cap.
3. **Portable:** moving to another Cloudflare account is a checklist, not a project.
4. **Safe in a public repo:** the Cloudflare credentials in GitHub can do as little as possible, and misuse can be detected.
5. Cost: $0 to $5 a month.

## Design

```
GitHub Actions (site.yml)                Cloudflare account
  limbowatch publish ──rclone sync──▶  R2 bucket "limbowatch-site"
                                            ▲ read
  visitors, watchers ──https──▶ limbo.watch ─▶ Worker "limbowatch-site" (cache API in front of R2)
```

- **R2 holds the built site**, uploaded as-is. It's a copy, not the source: everything can be rebuilt from the `tracker-data` branch. No data ever needs migrating.
- **The Worker serves it**, doing what nginx does today:
  - path → key: `/` → `index.html`, `/x/` → `x/index.html`; `/x` → 301 to `/x/` when `x/index.html` exists; otherwise 404;
  - `GET` and `HEAD` only; `ETag`, `If-None-Match` → 304, `Last-Modified`;
  - the headers in `deploy/site/nginx.conf`: CSP, HSTS, nosniff, Referrer-Policy, Permissions-Policy; CORS `*` on `/feed/`, `/osv/` and `/metrics.json`; `text/csv; charset=utf-8`; `Cache-Control: max-age=300`;
  - `X-Goog-Hash` on `/osv/**/all.zip` and `osv/limbo-db.zip`, read from `osv/crc32c.map` (already published) and kept in memory per isolate (F-073);
  - `www.limbo.watch` → 301 to `limbo.watch` (Traefik does this today);
  - the Cache API in front of R2, so most requests never read R2.
- **Everything is in the repo:** the Worker in `deploy/worker/` (JavaScript, no build step), its `wrangler.jsonc`, and the sync step in `site.yml`. The zone needs no settings beyond the Worker's custom domains: no page rules, cache rules, Transform Rules or other dashboard settings.

### Cost (F-171, F-173, F-174)

| Item | Use | Free tier | Expected |
|---|---|---|---|
| R2 storage | about 0.5 GB | 10 GB | $0 |
| R2 writes (Class A) | 27,600 a day today, about 830,000 a month; about 2,500 a day once feed `modified` is fixed (step 1) | 1 million a month | $0 |
| R2 reads (Class B) | cache misses only | 10 million a month | $0 |
| Worker requests | every request: 175,880 in the last 30 days, 63,000 on the busiest recent day, about 80% crawlers (F-175) | 100,000 a day, then error 1027 until midnight UTC | **$5/month (Workers Paid, 10 million a month)** |

The free daily limit is too close: one crawler burst would take the site down for the rest of the day, because the Worker is the only origin and there's nothing to fail open to. So the plan budgets Workers Paid, $5 a month. Blocking AI crawlers (below) would cut requests by about 60%, but wouldn't remove the risk.

## Moving to another Cloudflare account

The design keeps everything that belongs to one account out of the code:

- **No account values in the repo.** The account ID, bucket name and hostname are GitHub Actions *variables* (`CF_ACCOUNT_ID`, `R2_BUCKET`, `SITE_HOST`). `wrangler.jsonc` leaves out `account_id`, so wrangler reads `CLOUDFLARE_ACCOUNT_ID`.
- **Account-owned tokens** (`cfat_…`), not user tokens: they belong to the account, keep working if a person leaves, and are made again in the new account.
- **No data to copy:** the first sync to a new bucket uploads the whole site (about 52,000 writes, inside the free tier).
- **The zone is the only slow part.** Moving `limbo.watch` to another account means adding it there and changing the nameservers at the registrar (Spaceship). Certificates aren't carried over, and Cloudflare issues new ones. DNSSEC is off, so there's nothing to remove first.

Checklist, kept in `deploy/README.md`:
1. In the new account: add the zone `limbo.watch`; create the R2 bucket; create the two account tokens (see below).
2. In GitHub: update the variables and the two environment secrets.
3. Run `site.yml` (a full sync), then the Worker deploy, on a `workers.dev` address first. Run the parity check (step 4) against it.
4. Change the nameservers at the registrar. When the zone is active, attach the custom domains (`wrangler deploy`).
5. After a week, delete the old account's Worker, bucket and tokens.

**Rehearsal:** the first setup follows this checklist word for word. Then steps 1 to 3 are rehearsed in a second, free account against `workers.dev`, which proves everything except the DNS switch.

**Simpler still:** make a Cloudflare account for the project now and move the zone into it once, while nothing else depends on it. Then later changes are about *people*: add or remove members, with no move.

## Credentials in a public repo

Secrets in a public repo are safe if they reach only trusted code, can do little, and misuse would show. The repo already does this for `LIMBOWATCH_GITHUB_TOKEN` and `NVD_API_KEY`.

**Who can read a secret.** GitHub doesn't pass secrets to workflows run from forks, and this repo never uses `pull_request_target`. So only code already on `main` runs with secrets. `site.yml` runs on `workflow_run` from `tracker`, checks out `main`, and runs no code from a pull request.

**Two tokens, each as small as possible:**

| Token | Permission | Where | Used by |
|---|---|---|---|
| `R2_SYNC` (account token) | R2 **Object Read & Write**, on bucket `limbowatch-site` only | GitHub environment `site`, limited to `main` | `site.yml`, daily |
| `WORKER_DEPLOY` (account token) | Workers Scripts Edit; Workers Routes Edit on `limbo.watch` (whether attaching a custom domain also needs DNS Edit is checked in step 0) | GitHub environment `worker`, limited to `main`, **a required reviewer must approve each run** | `worker.yml`, only when `deploy/worker/**` changes |

- Both expire, the deploy token after 90 days and the sync token after a year. A calendar reminder is added to the release checklist.
- Neither token can change DNS, the zone or the account, or read anything else.
- The worst case for `R2_SYNC`: someone who ran code on `main` could replace site files. That's the same power the workflow's own `GITHUB_TOKEN` has today, since it pushes the site image and commits the deploy tag.
- The feed is also protected by the checksums published on GitHub (the feed-integrity work). A tampered feed fails the watchers' check and `scripts/audit.py`.

**Repo hardening that goes with it:**
- Turn on secret scanning and push protection (free for public repos; `cfat_` tokens are detectable).
- Require outside contributors' workflow runs to be approved (today only first-time contributors' are).
- Require actions pinned to a full SHA (the workflows already do this; the setting enforces it).
- Add a ruleset on `main`: no force pushes, no deletion. The new design also ends the bot's daily `ci: deploy site` commits to `main`.
- Never print a secret: rclone and wrangler read credentials from the environment; no `set -x` in steps that have them.
- Run `zizmor` (a static checker for GitHub workflows) in `ci.yml`.

**Detection:** Cloudflare's audit log records token and Worker changes; alerts on them are set up where Cloudflare offers them (checked in step 0). The audit compares the live feed's digests with the ones on GitHub.

## Steps

Each step ends in a working state; nothing changes for users until step 5.

0. **Inputs** (you): traffic checked (F-175); the personal account for now (decided 2026-11-13), moved later with the checklist above; decide whether to allow AI crawlers; subscribe to Workers Paid; create the bucket and two tokens; add the GitHub variables and environments.
1. **Stable feed `modified`** (product): set each feed record's `modified` to when its content last changed, not the build time. Today every build rewrites all 25,692 feed JSON files (F-174), which also defeats ETags for anyone mirroring them. It's a semantic fix in the OSV schema's sense; test pinned old releases against it.
2. **Worker** in `deploy/worker/`, with tests in `workerd` (`@cloudflare/vitest-pool-workers`): every nginx behaviour above, against a fake bucket. No network.
3. **Sync** in `site.yml`: pinned rclone (checksum verified), `rclone sync --checksum --max-delete 2%`, uploading the big feed zips and `crc32c.map` last. The 2% cap stops a broken build from wiping the site.
4. **Parity check** (`scripts/check_hosting.py`, network): for a sample of URLs of each kind, compare the old and new hosts' status, headers, body digest, `HEAD`, 304 and `X-Goog-Hash`. Run OSV-Scanner's refresh path and each pinned old watcher release against the `workers.dev` address.
5. **Switch:** attach `limbo.watch` and `www.limbo.watch` to the Worker. Keep the cluster serving for a week as the fallback; going back means detaching the custom domain.
6. **Retire:** remove `deploy/site`, `deploy/k8s`, `deploy/argocd-app.yaml`, the site image build, the Argo CD app and the ghcr package; rewrite `deploy/README.md` and fix the stale line in `tracker/README.md`.

## Open questions

- **AI crawlers:** ClaudeBot and GPTBot made 58% of requests in the last 30 days (F-175). Letting them crawl helps AI assistants know about Limbowatch; blocking them (Cloudflare's AI Crawl Control) cuts load. It's your call, and either way works on R2.

- Do responses served from the Cache API count as Worker requests? (Yes as far as known: the Worker runs first.) Step 0's traffic numbers say whether this matters.
- Does Cloudflare accept GitHub's OIDC tokens in place of a stored API token? Nothing found yet; checked before step 0.
- The site grew by 550 files in one day (F-174). If that's typical, it's about 16,500 a month, which matters for any host with a file cap, not for R2.
