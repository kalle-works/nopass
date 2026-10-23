# Authentication

nopwd logs in with OPAQUE (RFC 9807). The server never sees the master
password or anything that lets it test password guesses offline on its own.

## Scheme

- Server: `opaque-ke` 4.0.1. Client: `@serenity-kit/opaque` 1.1.0, a wasm build
  of the same library, so both sides run the same code.
- Cipher suite: Ristretto255 OPRF, TripleDH over Ristretto255 with SHA-512,
  Argon2id as the key-stretching function (KSF). The KSF runs on the client
  with the account's `kdf_params`, the same parameters as the vault KDF.
- Credential identifier: the client email hash
  (`SHA-256("nopass-v1-email:" + lowercase(email))`, hex).
- The test `crates/nopass-crypto/tests/opaque_compat.rs` replays a record and a
  login response made by the wasm client against the Rust suite. If the
  suite, the KSF or the serialization drifts, it fails.

### Vault keys stay on the existing Argon2id derivation

Vault items are encrypted directly under keys derived from
`Argon2id(password, SHA-256("nopass-v1-kdf:" + email))`. Deriving them from
the OPAQUE `export_key` would mean re-encrypting every item of every account
during migration. So the vault derivation is unchanged and `export_key` goes
unused. The two derivations are still domain-separated: the OPAQUE KSF
stretches the OPRF output, a value only the server's OPRF key can produce,
while the vault KDF stretches the password with an email salt. Learning one
says nothing about the other.

What this costs: a login runs Argon2id twice on the client, once inside
OPAQUE and once for the vault keys.

### What a database thief gets

Before this change, the SRP verifier was `g^SHA256(salt || SHA256(email:password))`.
A database dump was enough to test guesses at SHA-256 speed.

Now the login record is no longer a shortcut. With the database alone, a
thief can't test a guess against the OPAQUE record at all, because every
check needs the OPRF key derived from `NOPASS_OPAQUE_SERVER_SETUP`. With that
secret as well, each guess costs one Argon2id run at the vault KDF's
parameters.

That leaves the attack OPAQUE can't remove. Anyone holding the database who
also knows a user's email can test guesses against that user's wrapped vault
key (`protected_symmetric_key`, AES-GCM under a key derived with Argon2id
from the password and email). Each guess costs a full Argon2id run. The
marketing copy says exactly this.

## Endpoints

| Route | Purpose |
|---|---|
| `POST /v1/auth/opaque/register/start`, `/finish` | New account |
| `POST /v1/auth/opaque/login/start`, `/finish` | Login |
| `POST /v1/auth/opaque/reregister/start`, `/finish` (session) | SRP → OPAQUE migration |
| `POST /v1/auth/password/start`, `/finish` (session) | Change the master password |
| `POST /v1/auth/recovery/opaque/start` | New credential during recovery; the record is sent with `recovery/complete` |
| `POST /v1/auth/srp/init`, `/verify` | Legacy, only for accounts not yet migrated |
| `POST /v1/auth/register` | Returns 410; SRP registration is gone |

Re-registration only works for an account that still has an SRP verifier, and
only from a session created in the last 10 minutes. Otherwise a stolen session
token could be used to replace the login credential.

## Changing the master password

A session token alone can't change the password. `password/start` runs a
full OPAQUE login for the current password next to a registration for the new
one, and `password/finish` only goes ahead if that login proof checks out.
Starts count against the per-account throttle like any login.

Vault items are encrypted directly under keys derived from the master
password, so the keys can't simply be re-wrapped: the client decrypts and
re-encrypts every item (tombstones included) and re-wraps the vault key and
the org private key. In one transaction, `finish` then:

- stores the new OPAQUE record,
- swaps in the re-encrypted items, after checking that no item was left
  under the old keys,
- clears the recovery kit, which wrapped the old keys,
- revokes every session except the one making the change.

Web: Settings → Master password. CLI: `nopwd passwd`, which also writes the
new vault keys into the local session file. The desktop app has no settings
screen, so it has no password change; its users can change the password on
the web.

## Migrating SRP accounts

1. The client tries OPAQUE first. An account that hasn't migrated yet gets the
   same fake response as an unknown account, so the client fails locally.
2. The client then falls back to SRP. For an unknown or already-migrated
   account, `srp/init` returns a fake challenge with a stable fake salt, and
   `srp/verify` fails with the same 401 a wrong password gets.
3. Once SRP succeeds, the client immediately runs `reregister/start` and
   `reregister/finish` with the new session token. The server stores the
   OPAQUE record and sets `srp_salt` and `srp_verifier` to NULL in the same
   statement.
4. If the upgrade fails (network, app closed), the login itself still counts,
   and the upgrade is retried on the next login.

Recovery from a client released before OPAQUE still sends SRP credentials.
These are accepted, so such a recovery can still finish, and the account
migrates on its next login.

### Removing SRP

Track two numbers, weekly from release:

```sql
-- Unmigrated accounts: still on SRP
SELECT COUNT(*) AS unmigrated,
       COUNT(*) FILTER (WHERE recovery_auth_hash IS NULL) AS unmigrated_without_kit
FROM users WHERE srp_verifier IS NOT NULL;
```

plus the count of `event="srp_migrated"` log lines per week.

SRP goes when **both** of these hold:

1. At least 90 days have passed since the release, and the last 4 weeks saw
   no `srp_migrated` events. Every account that is still in use has migrated
   by then, because any login upgrades it.
2. `unmigrated_without_kit` has been reviewed and the product owner accepts
   locking those accounts out. Accounts with a kit can still get in through
   recovery, which sets an OPAQUE record.

Whichever comes later sets the date, and in any case no later than 12 months
after the release: by then every remaining account has gone a year without a
login. Steps:

1. Ship this release and its clients.
2. Once the criteria hold, announce the date in the app and by changelog
   30 days ahead.
3. Remove `/v1/auth/srp/*`, the SRP fallback in `packages/crypto/src/password-login.ts`,
   `srp-client.ts`, `crates/nopass-crypto/src/srp.rs`, the legacy recovery
   fields, and the `srp` crate. Then add a migration that drops
   `pending_srp_sessions`, `users.srp_salt` and `users.srp_verifier`, and makes
   `opaque_record` NOT NULL.

## Account enumeration

| Probe | Result |
|---|---|
| `opaque/login/start` | Known, unknown and not-yet-migrated accounts return the same status and JSON shape, with an equal-length `loginResponse`. opaque-ke derives the fake record from the server setup, so it stays stable across requests. All three paths do the same lookup, throttle write, `ServerLogin::start` and pending-row insert. |
| `opaque/login/finish` | Same 401 `authentication failed` for a wrong password, an unknown account, and an expired or unknown `loginId`. |
| `srp/init`, `srp/verify` | Same shape for all accounts. Same 401 on verify. |
| `opaque/register/start` | Does no lookup, so it says nothing. |
| `recovery/init` | Same 401 for an unknown account, no kit, or a wrong code (unchanged). |

What still leaks:

- `opaque/register/finish` returns 409 for an email that is already
  registered. The server never has the plaintext email, so it can't send a
  "you already have an account" mail instead. The per-IP limiter is the only
  mitigation.
- `kdfParams` in the login response are the account's own. Unknown accounts
  get the defaults, so an account with non-default parameters can be told
  apart. Today every client registers with the defaults.
- Timing: the fake `srp/init` path skips one INSERT. It is sub-millisecond,
  but measurable with enough samples. It goes away with SRP.

### Keyed email lookup

`users.email_hash` now holds `HMAC-SHA256(NOPASS_EMAIL_LOOKUP_KEY, client email hash)`.
Before, it held the client hash itself, which anyone can compute from an email
address, so a dump confirmed membership for any address list. Existing rows
are rewritten at API startup. The housekeeping task also rewrites any row an
older replica writes during a rolling deploy. The `email_hash_keyed` column
marks which rows are done. The old, unused `NOPASS_SESSION_SECRET` is gone.

## Throttling

- Per IP: 60 requests a minute, burst 30, on every public `/auth` route. This
  was 20 with a burst of 10, but a login now takes two requests (three with
  the SRP fallback), and guessing is bounded per account below.
- Per account, keyed by the keyed email hash whether the account exists or
  not, so the throttle reveals nothing. It counts every login start
  (OPAQUE or SRP) and every registration start that isn't followed by a
  successful finish. A wrong OPAQUE password is detected on the client, which
  then never calls finish, so the start is all the server ever sees. A
  registration start is an OPRF evaluation under the account's key, and
  together with one login response that is enough to test a guess, so it
  counts too.
- The first 10 attempts are free. After that the account waits 30 s, doubling
  with each further attempt, capped at 15 minutes, with a 429 and
  `Retry-After`. The counter resets on success and decays after 24 h without
  attempts. The SRP fallback means a wrong password costs two attempts while
  SRP exists.
- Remaining risk: anyone who knows an address can keep that account in backoff
  for up to 15 minutes at a time. The cap keeps this a nuisance, not a lockout.

### Alerting

The API logs JSON when `LOG_FORMAT=json`. Each event carries `account` (a
12-character prefix of the keyed hash, which can't be reversed without the
secret) and `ip`.

| `event` | Meaning |
|---|---|
| `login_failed` | Server rejected a login proof (OPAQUE finish or SRP verify) |
| `login_backoff` | An account crossed the free-attempt threshold |
| `login_throttled` | A start was refused by the per-account backoff |
| `srp_migrated` | An account moved from SRP to OPAQUE |

Alert on the rate of `login_backoff` and `login_throttled` across accounts. A
spike over many accounts points to credential stuffing; a steady stream on one
account points to a targeted attempt. `login_failed` is rare with OPAQUE
because the client catches wrong passwords first.

## Pending handshakes

Each login start writes one row to `pending_opaque_logins` (or
`pending_srp_sessions`). Only the five newest per account are kept, rows expire
after 5 minutes, and the housekeeping task deletes expired rows every minute.
Combined with the per-IP limiter, this bounds the table.

## Secrets

| Variable | Generate | Notes |
|---|---|---|
| `NOPASS_OPAQUE_SERVER_SETUP` | `nopass-api generate-opaque-setup` | Required. Replacing it invalidates every OPAQUE record. |
| `NOPASS_EMAIL_LOOKUP_KEY` | `openssl rand -base64 32` | Required, at least 32 bytes. Replacing it orphans every account. |

Neither secret can be rotated without re-registering everyone, so back both up
next to the database backups. They are worthless without the database, and the
database is much weaker without them.
