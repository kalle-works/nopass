# Deploying nopwd

nopwd runs on the k3s cluster managed in `hetzner-k3s-flux-mail`. This repo
holds the manifests (`k8s/`); Flux applies them. Nothing is deployed by hand.

## Release flow

1. Merge to `main`. CI must be green.
2. Push a version tag: `git tag v0.3.0 && git push origin v0.3.0`.
3. The **Publish images** workflow builds three images and pushes them to GHCR:
   `nopwd-api`, `nopwd-web` and `nopwd-ops` (the backup and restore-drill
   tooling), all tagged with the version.
4. The same workflow opens a PR, `chore(release): deploy v0.3.0 images`, that
   pins the tag and the image digest in `k8s/kustomization.yaml` (the
   `images:` block, rewritten by `scripts/bump-images.sh`).
5. Merge that PR. The `nopwd` Flux Kustomization (flux-system namespace, path
   `./k8s`, interval 5 minutes) applies it, rolls the Deployments and waits for
   `nopwd-api` and `nopwd-web` to become healthy.

The cluster pulls images by digest, so a re-pushed tag cannot change what runs.
To deploy sooner than the 5 minute interval, ask the cluster operator to run
`flux reconcile kustomization nopwd --with-source`.

One-time repository setting: **Settings, Actions, General, Allow GitHub Actions
to create and approve pull requests** must be on, or the bump job fails after
the images are already pushed (re-run the failed job once fixed). PRs opened
with the workflow token do not start CI on their own. The PR only touches the
images block and the tagged commit already passed CI.

Rolling back: revert the deploy PR, or merge a PR that re-pins the previous tag
and digest (both are in the git history of `k8s/kustomization.yaml`). Database
migrations only move forward; a release that adds a migration needs a forward
fix, not a rollback of the images alone.

### Replicas and state

Both Deployments run two replicas with `maxUnavailable: 0`. The API holds no
session state in memory: SRP handshakes and recovery tokens live in Postgres
(since v0.1.3), so any replica can finish a login another one started and
rollouts do not drop in-flight logins. The web pod is stateless. A
PodDisruptionBudget keeps one web pod up during node drains.

Migrations run on API start, from every replica; Postgres serialises them.

### Secrets

All secrets are SealedSecrets in `k8s/`, sealed against the cluster's
controller key. Never commit a plain Secret.

| Secret | Keys | Used by |
| --- | --- | --- |
| `nopwd-secrets` | `database-url`, `session-secret` | api, backup |
| `nopwd-backup-secrets` | `passphrase`, `deploy-key` | backup, restore drill |
| `ghcr-pull-secret` | `.dockerconfigjson` | image pulls (rotate with `scripts/rotate-ghcr-pull-secret.sh` in the infra repo) |

The backup `passphrase` encrypts every dump. Keep a copy outside the cluster
(the password manager); without it the backups are unreadable. The
`deploy-key` is a write deploy key on `kalle-works/nopwd-backups`.

Stripe (`STRIPE_SECRET_KEY`, `STRIPE_WEBHOOK_SECRET`, `STRIPE_*_PRICE_ID`) is
optional and not configured today. To enable billing, add the keys to
`nopwd-secrets` and reference them in `api-deployment.yaml`.

### API configuration

Non-secret settings are in `k8s/configmap.yaml`:

- `NOPASS_ALLOWED_ORIGINS`: exact origins, never `*`.
- `NOPASS_TRUSTED_PROXIES`: the pod CIDR `10.42.0.0/16`. Traefik pods change IP
  on every reschedule, so a narrower list goes stale. This is safe only
  because `k8s/network-policies.yaml` lets nothing but the `traefik` namespace
  reach the API pods. Rate limiting and the activity log read the client IP
  from `X-Forwarded-For` only when the peer is in this list.

### Metrics

The API serves Prometheus metrics on port 9100 (`NOPASS_METRICS_PORT`, `0`
disables), a listener separate from the public one. Only the
`nopwd-api-metrics` Service and the ServiceMonitor point at it, and the network
policy lets only Prometheus in. Exposed: `nopass_http_requests_total`,
`nopass_http_request_duration_seconds` (labelled by route template, not raw
path) and `nopass_login_failures_total`.

### Network policies

`k8s/network-policies.yaml` denies all ingress and egress in the namespace and
allows: Traefik to api (3001) and web (3000), Prometheus to the api metrics
port (9100), api to Postgres (5432) and
Stripe (443), backup to Postgres and GitHub SSH (22), and DNS for everyone.
The restore drill gets no network at all.

Policies add up, so the namespace-wide `default-deny-ingress` for `nopwd` in
`hetzner-k3s-flux-mail` (`network-policies/default-deny.yaml`) allows only
Traefik and Prometheus and carries no pod-CIDR `ipBlock`. If a pod-CIDR or
same-namespace rule comes back, any pod in the cluster can reach the API again
and the policies here do nothing for ingress. After a
policy change, check that the pods stay Ready and that `curl
https://api.nopwd.dev/v1/health` answers.

## Backups

| Layer | What | Schedule | RPO | Kept |
| --- | --- | --- | --- | --- |
| Nightly dump (`nopwd-backup` CronJob) | `pg_dump`, AES-256 encrypted, on the Hetzner volume | 03:20 UTC | 24 h | 14 newest |
| Offsite copy | the same dumps pushed to `kalle-works/nopwd-backups` over SSH | with the dump | 24 h | 7 newest, one rolling commit |
| Continuous WAL archive (shared Postgres, wal-g) | WAL plus daily base backup in the `bsp-meta-backup` bucket | continuous, `archive_timeout` 5 min | about 5 min | 30 days |

The backup job fails, and `NopwdBackupFailed` fires, if the dump does not
decrypt and list, if the offsite push fails, or if the remote does not point at
the pushed commit afterwards. The offsite push pins GitHub's SSH host keys in
the `nopwd-backup-known-hosts` ConfigMap and refuses an unknown host. When
GitHub rotates its keys, replace the lines from `gh api meta --jq .ssh_keys`
and check them against GitHub's published fingerprints.

The last success is `kube_cronjob_status_last_successful_time` for
`nopwd-backup`; `NopwdBackupMissing` fires when it is older than 28 hours.

### Point-in-time recovery

The shared Postgres in the `postgresql` namespace archives WAL continuously
with wal-g (manifests and alerts in `hetzner-k3s-flux-mail`, restore drill in
the backupsyncpro.com repo, `docs/postgres-backup.md`). If the nopwd database
lives on that instance, it already has a recovery point of about 5 minutes. The
`database-url` secret is sealed, so confirm the host before relying on this:
decode the secret as the cluster operator and check that it points at
`postgresql.postgresql.svc`.

What this layer does not give you: wal-g restores the whole instance, which
holds other applications' databases. Recovering only nopwd means restoring to a
side instance at the chosen time, then `pg_dump` of the nopwd database and
`pg_restore` into production. The nightly encrypted dump stays as the second,
independent path (different storage, different key, different provider).

If nopwd turns out not to be on the WAL-archived instance, the gap is a 24 hour
recovery point. The plan then is to enable WAL archiving on that instance with
the same wal-g setup; do not build a second mechanism inside this repo.

### Restore drill

The `nopwd-restore-drill` CronJob runs on the 1st of each month at 05:40 UTC.
It decrypts the newest dump on the volume, restores it into a throwaway
Postgres inside the pod, and fails if any check fails: the dump is older than
36 hours, decryption or `pg_restore` errors, no migrations are recorded or one
failed, there are no users, or a user is missing key material. Alerts:
`NopwdRestoreDrillFailed` and `NopwdRestoreDrillStale` (no success in 35 days).

Run it on demand:

```bash
kubectl -n nopwd create job --from=cronjob/nopwd-restore-drill drill-manual
kubectl -n nopwd logs -f job/drill-manual
```

### Restoring for real

Choose the dump: the newest file on the volume (`/backups/nopwd-*.dump.enc`, on
`k3s-production-ci-1`) or, if the volume is lost, the files in the
`kalle-works/nopwd-backups` repository.

```bash
# decrypt (passphrase from the password manager)
openssl enc -d -aes-256-cbc -pbkdf2 -iter 200000 \
  -in nopwd-YYYYMMDD-HHMMSS.dump.enc -out nopwd.dump -pass env:BACKUP_PASSPHRASE

# restore into an empty database, never over a live one
createdb nopwd_restored
pg_restore -d nopwd_restored --no-owner --no-privileges --exit-on-error nopwd.dump
```

Then point `database-url` at the restored database (reseal the secret), roll
the API Deployment, and run the smoke test below. Users keep their vaults:
the server only ever stored ciphertext, so no key material is needed to
restore it.

## Alerts

`hetzner-k3s-flux-mail`, `kubernetes/base/infrastructure/monitoring/nopwd-alerts.yaml`.
Everything in the `nopwd` namespace is mailed to the operator.

## Browser extension (Chrome Web Store)

```bash
./scripts/package-extension.sh https://api.nopwd.dev
# writes apps/extension/nopwd-extension.zip (untracked build output)
```

CI builds the same artifact on every push (`nopwd-extension` artifact). Upload
it at https://chrome.google.com/webstore/devconsole. Listing copy:
`apps/extension/STORE_LISTING.md`. Review usually takes one to three business
days; the `world: MAIN` content script and broad host permissions trigger a
manual review, and the justification text in the listing doc addresses it.

## CLI (npm)

```bash
cd apps/cli && pnpm build && npm publish --access public
```

Check that the package name `nopwd` is still free at publish time.

## Smoke test after a deploy

```bash
curl https://api.nopwd.dev/v1/health        # ok
kubectl -n nopwd get pods                   # 2 api, 2 web, all Ready
```

Then register a throwaway account in the web app, add an item, share it,
generate a recovery kit, and recover on a second browser profile.

## Building locally

```bash
docker build -f crates/nopass-api/Dockerfile -t nopwd-api:local .
docker build -f apps/web/Dockerfile \
  --build-arg NEXT_PUBLIC_API_URL=https://api.nopwd.dev -t nopwd-web:local .
docker build -f ops/Dockerfile -t nopwd-ops:local .
```

The web image bakes in `NEXT_PUBLIC_API_URL`, and the CSP `connect-src` derives
from it.
