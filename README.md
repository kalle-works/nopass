# nopwd

A zero-knowledge password manager for individuals. Logins, passkeys, cards,
notes, and SSH keys are encrypted on your device before they leave it — the
server stores ciphertext it cannot read. Not as a promise: as math.

**Crypto**: Argon2id → HKDF subkeys → AES-256-GCM + HMAC-SHA256, OPAQUE
(RFC 9807) login: your password never crosses the wire, and a stolen server
database can't be used to test password guesses ([docs/auth.md](docs/auth.md)). The full design,
including what nopwd deliberately *cannot* protect you from, is on the
[landing page threat model](apps/web/src/app/(marketing)/page.tsx) and in
[DESIGN.md](DESIGN.md).

## What it does

- **Vault** — logins, secure notes, cards, identities, SSH keys; encrypted
  tags; favorites; multiple vaults; instant search
- **Passkeys** — the browser extension is a software WebAuthn authenticator;
  passkeys sync inside your encrypted vault (conformance-tested against a
  real relying-party library)
- **2FA** — TOTP codes next to your passwords
- **Recovery kit** — a one-time offline code that can restore your vault if
  you forget the master password, without weakening zero-knowledge
- **One-time sharing** — expiring links whose decryption key travels only in
  the URL fragment
- **Security auditing** — HaveIBeenPwned breach checks (k-anonymity),
  password health score, trusted-device list, account activity log
- **Surfaces** — web app, Chrome extension (autofill + passkeys), CLI
  (`nopwd run` injects secrets into processes; `--via-socket` keeps them out
  of the environment entirely; `nopwd adopt` moves a secret out of a `.env`
  file into the vault and leaves a `nopwd://` reference that
  `nopwd run --dotenv` resolves), Tauri desktop with biometric unlock and an
  SSH agent
- **Import** — lossless 1Password `.1pux`

## Self-hosting (quickstart)

```bash
cp .env.example .env
# set NOPASS_OPAQUE_SERVER_SETUP and NOPASS_EMAIL_LOOKUP_KEY (see .env.example)
docker compose up -d            # Postgres + API on :3001
```

Then build the web app against your API and run it:

```bash
docker build -f apps/web/Dockerfile --build-arg NEXT_PUBLIC_API_URL=http://localhost:3001 -t nopwd-web .
docker run -p 3000:3000 nopwd-web
```

Browser extension against your own API:

```bash
./scripts/package-extension.sh http://localhost:3001
# load apps/extension/dist as an unpacked extension in chrome://extensions
```

Production hardening (TLS, trusted proxies, backups) is covered in
[DEPLOY.md](DEPLOY.md).

## Development

```bash
docker compose up -d postgres        # Postgres on :5441
cargo run -p nopass-api              # API on :3001 (migrations run on start)
pnpm install
pnpm --filter @nopass/web dev        # web on :3000 (use -p 4020 to match CORS)
```

Tests:

```bash
cargo test --workspace               # needs DATABASE_URL pointing at the dev Postgres
pnpm turbo run typecheck test build --filter='!@nopass/desktop'
```

The crypto package's integration suites probe a live API at `:3001` and skip
cleanly when it isn't running.

## Repository layout

| Path | What |
|---|---|
| `crates/nopass-api` | Rust (Axum) API — auth, vaults, shares, recovery, activity |
| `crates/nopass-crypto`, `crates/nopass-models` | server-side crypto + shared types |
| `apps/web` | Next.js vault + marketing site |
| `apps/cli` | `nopwd` CLI |
| `apps/extension` | Chrome MV3 extension (autofill + WebAuthn authenticator) |
| `apps/desktop` | Tauri desktop app |
| `packages/crypto` | client crypto: KDF, OPAQUE login, AES-GCM, recovery, shares, WebAuthn |
| `packages/types`, `packages/ui` | shared TypeScript types and React components |
