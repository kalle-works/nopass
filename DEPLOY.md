# Deploying nopwd

Everything below is prepared; each step needs only your go-ahead and
credentials. Nothing here has been executed against production.

## 1. API (api.nopwd.dev)

```bash
# Build (from repo root)
docker build -f crates/nopass-api/Dockerfile -t nopwd-api:$(git rev-parse --short HEAD) .

# Required environment
DATABASE_URL=postgres://…                 # managed Postgres, TLS on
NOPASS_SESSION_SECRET=$(openssl rand -base64 32)
NOPASS_HOST=0.0.0.0
NOPASS_PORT=3001
NOPASS_ALLOWED_ORIGINS=https://nopwd.dev  # exact origins, never *
NOPASS_TRUSTED_PROXIES=<ingress IPs>      # required for correct rate limiting + activity IPs
# Optional billing: STRIPE_SECRET_KEY, STRIPE_WEBHOOK_SECRET, STRIPE_*_PRICE_ID
```

Migrations run automatically on startup. The container is non-root and
stateless — scale horizontally behind TLS (the in-memory SRP/recovery session
maps mean a single replica OR sticky sessions until those move to Postgres).

**Pre-launch checklist**
- [ ] TLS terminated at the ingress; HSTS already set by the app
- [ ] Postgres backups + point-in-time recovery enabled (ciphertext only, but losing it loses vaults)
- [ ] `NOPASS_TRUSTED_PROXIES` matches the actual ingress, otherwise rate
      limiting keys on the proxy IP and one user can lock out everyone

## 2. Web app (nopwd.dev)

```bash
docker build -f apps/web/Dockerfile \
  --build-arg NEXT_PUBLIC_API_URL=https://api.nopwd.dev \
  -t nopwd-web:$(git rev-parse --short HEAD) .
```

Serves on :3000. CSP `connect-src` derives from the build-arg automatically.

## 3. Browser extension (Chrome Web Store)

```bash
./scripts/package-extension.sh https://api.nopwd.dev
# → apps/extension/nopwd-extension.zip
```

Upload at https://chrome.google.com/webstore/devconsole ($5 one-time
registration). Listing copy: `apps/extension/STORE_LISTING.md`.
Review usually takes 1–3 business days; the `world: MAIN` content script and
broad host permissions will trigger a manual review — the justification text
in the listing doc addresses it.

## 4. CLI (npm)

```bash
cd apps/cli && pnpm build && npm publish --access public
```

(Package name `nopwd` availability needs checking at publish time.)

## 5. Smoke test after deploy

```bash
curl https://api.nopwd.dev/v1/health        # → ok
# register a throwaway account in the web app, add an item, share it,
# generate a recovery kit, recover on a second browser profile
```
