# Deploying limbo.watch

The public site is the static output of `limbowatch publish`, served by nginx on the k3s cluster (skylion, skycat).

## How an update reaches the site

1. The daily `tracker` workflow updates the state on the `tracker-data` branch.
2. When it succeeds, the `site` workflow:
   - publishes the site from that state;
   - builds `deploy/site/` into `ghcr.io/limbowatch/limbowatch-site:<date>-<run id>`;
   - commits the new tag to `deploy/k8s/deployment.yaml`.

   `site` also runs when the site code changes, or on demand: `gh workflow run site.yml`.
3. Argo CD (app `limbowatch-site`) syncs `deploy/k8s` from main and rolls out the new image.

GitHub holds no credentials for the cluster. The cluster pulls from GitHub.

## Cluster resources

| Resource | Purpose |
|---|---|
| namespace `limbowatch` | Deployment, Service, Ingresses, Traefik Middleware (www → apex redirect) |
| `argocd/limbowatch-site` | Argo CD Application, from `deploy/argocd-app.yaml` (applied once by hand) |
| `argocd/repo-limbowatch-ssh` | Read-only deploy key for this repo (GitHub: Settings → Deploy keys, "argocd-skylion") |
| `limbowatch/ghcr-pull-secret` | Pulls the private image; a copy of the cluster's existing GHCR pull secret |
| `limbowatch/limbowatch-tls` | Let's Encrypt certificate for limbo.watch and www.limbo.watch (cert-manager, `letsencrypt-http`) |

## Node config

Every deploy leaves the previous site image on the node, so the kubelet garbage-collects images ([`node/20-image-gc.conf`](node/20-image-gc.conf)). It starts when the image disk is 75% full and stops at 65%, and it also removes images left unused for 14 days. This is kubelet config, not a cluster resource. Argo CD doesn't manage it, so install it by hand on each node (skylion, skycat):

```sh
scp deploy/node/20-image-gc.conf root@<node>:/tmp/
ssh root@<node> 'install -D -m 0644 /tmp/20-image-gc.conf /var/lib/rancher/k3s/agent/etc/kubelet.conf.d/20-image-gc.conf && systemctl restart k3s'
```

skycat is an agent-only node: restart `k3s-agent` there instead of `k3s`, and run `kubectl` from skylion. Both nodes have had it since 2026-11-06 (k3s v1.36.6). The kubelet reads only files ending in `.conf` from that directory, and `imageMaximumGCAge` needs Kubernetes 1.30 or later. To check that the kubelet loaded it:

```sh
ssh root@skylion 'kubectl get --raw /api/v1/nodes/<node>/proxy/configz' | jq '.kubeletconfig | {imageGCHighThresholdPercent, imageGCLowThresholdPercent, imageMaximumGCAge}'
```

## Analytics

Google Analytics is off unless the repository variable `LIMBOWATCH_GA_ID` (Settings → Secrets and variables → Actions → Variables) holds a GA4 measurement ID (`G-…`). It isn't a secret: it appears in every page.

With it set, every page loads Google Analytics in Consent Mode:
- every storage type is denied until a visitor clicks **Allow cookies** on the banner. Until then, and after **No thanks**, Google gets only cookieless pings;
- ad storage is never granted;
- the choice is kept in the visitor's browser, and the footer's **Cookie settings** link changes it.

The Content-Security-Policy in `site/nginx.conf` allows `www.googletagmanager.com`, `*.google-analytics.com` and `*.google.com` (Google's list for Analytics without Ads features). Remove them if analytics is turned off for good.

## Checking it

```sh
ssh root@skylion kubectl -n argocd get application limbowatch-site
ssh root@skylion kubectl -n limbowatch get deploy,pods,certificate
curl -sI https://limbo.watch/
```

## Next: Cloudflare R2 and a Worker

The R2 setup ([docs/HOSTING_PLAN.md](../docs/HOSTING_PLAN.md)) runs alongside the cluster on `next.limbo.watch` until the switch. `site.yml` uploads each build to the bucket `limbowatch-site` (`scripts/sync_r2.py`). The zone rules are in `deploy/cloudflare/rules.json`. `deploy/worker/` is the Worker on `/osv/*`. Its tests run in CI (`ci.yml`, job `worker`) and locally:

```sh
cd deploy/worker && npm ci --ignore-scripts && npx vitest run
```

To deploy the Worker or change the rules, use a maintainer token kept in your keychain (docs/HOSTING_PLAN.md, "Credentials"). **Run `cf_rules.py` after every `wrangler deploy`**: a deploy turns the route back to failing closed (FINDINGS F-183).

```sh
export CLOUDFLARE_ACCOUNT_ID=… CLOUDFLARE_API_TOKEN="$(security find-generic-password -s limbowatch-cf-maintainer -w)"
(cd deploy/worker && npx wrangler deploy)
uv run python scripts/cf_rules.py --zone limbo.watch --host next.limbo.watch    # --dry-run first if unsure
uv run python scripts/check_hosting.py                                         # limbo.watch vs next.limbo.watch
```
