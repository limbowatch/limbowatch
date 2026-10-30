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
