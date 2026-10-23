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
  (`SHA-256("nopass-v1-email:" + lowercase(email))`, hex), deliberately the
  unkeyed one. The client has to send the same value at registration and
  login, before the server knows the account. The OPRF key it feeds is
  derived from the secret OPRF seed, so knowing the identifier gives an
  attacker nothing. The identifier is also independent of
  `NOPASS_EMAIL_LOOKUP_KEY`, so the two secrets stay separate: the lookup key
  only keys the stored account key, and the OPAQUE setup only keys OPAQUE.
- **KDF floor:** the client refuses `kdfParams` below the defaults
  (64 MiB, 3 passes), at login, in password proofs, at password change and
  during upgrade. Otherwise a malicious server could make what the client
  sends cheaper to brute-force.
- **Downgrade memory:** each client remembers locally, per email hash, that
  an account uses OPAQUE and that its account key is wrapped (web and desktop:
  localStorage; extension: storage.local; CLI: `~/.nopwd/account-state.json`).
  After that it never falls back to SRP for the account, and it refuses a
  login response without the wrapped key instead of deriving legacy keys
  (`packages/crypto/src/account-state.ts`).
- The test `crates/nopass-crypto/tests/opaque_compat.rs` replays a record and a
  login response made by the wasm client against the Rust suite. If the
  suite, the KSF or the serialization drifts, it fails.

### The account key

Items are encrypted under an **account key** (the vault enc + mac keys) that
doesn't depend on the password. For accounts created before the account key
existed, it is exactly the pair the password used to derive:

    masterKey = Argon2id(password, SHA-256("nopass-v1-kdf:" + email))   (unchanged)
    enc, mac  = HKDF(masterKey, "nopass-v1-enc" / "nopass-v1-mac")     (legacy derivation)

So migration re-encrypts nothing. The server stores the account key wrapped
under a key-encryption key derived from the password:

    KEK     = HKDF-SHA256(masterKey, salt = email, info = "nopass-v2-account-kek")
    wrapped = AES-256-GCM(KEK, enc || mac, AAD = "nopass-v2-account-key:" + emailHash)
    smk     = HKDF-SHA256(enc || mac, info = "nopass-v2-smk")

The AAD binds the blob to its purpose and to the account. The account is
named by the email hash, which the client computes itself, not by a user id
the server supplies, so the server can't choose what the client checks
against. A blob made for another account fails to open twice over: under a
different KEK (email salt) and a different AAD. The smk (wraps the RSA private key and the protected
symmetric key) is now derived from the account key too, so nothing depends on
the password except the KEK. Code: `packages/crypto/src/account-key.ts`.

- **Unlock:** log in, derive the KEK, unwrap. A legacy account (no
  `wrappedAccountKey` in the login response) derives the old way and wraps
  those keys. The private key moves from the password-derived smk to the
  account-key smk in the same request. An OPAQUE account sends this to
  `POST /auth/account-key` with a fresh password proof; an SRP account sends
  it with its upgrade (below). The server accepts it once per account. If
  anything fails, the unlock fails; the client never continues on
  half-migrated keys.
- **Recovery kit:** the kit wraps smk ‖ enc ‖ mac. enc ‖ mac is the account
  key, so every kit, including kits made before migration, stays valid across
  password changes. Recovery ignores the kit's smk except to open a private
  key that is still under the legacy wrap. Nothing needs regenerating.
- **Domain separation from OPAQUE:** the OPAQUE KSF stretches the OPRF output
  and `export_key` goes unused, while the KEK comes from the password with an
  email salt and its own HKDF label. A login therefore runs Argon2id twice on
  the client, once inside OPAQUE and once for the KEK.

### What a database thief gets

Before this change, the SRP verifier was `g^SHA256(salt || SHA256(email:password))`.
A database dump was enough to test guesses at SHA-256 speed.

Now the login record is no longer a shortcut. With the database alone, a
thief can't test a guess against the OPAQUE record at all, because every
check needs the OPRF key derived from `NOPASS_OPAQUE_SERVER_SETUP`. With that
secret as well, each guess costs one Argon2id run at the vault KDF's
parameters.

That leaves the attack OPAQUE can't remove. Anyone holding the database who
also knows a user's email can test guesses against that user's wrapped
account key (`wrapped_account_key`, AES-GCM under a KEK derived with Argon2id
from the password and email). For legacy accounts the same holds for
`protected_symmetric_key`. Each guess costs a full Argon2id run. The
marketing copy says exactly this.

## Endpoints

| Route | Purpose |
|---|---|
| `POST /v1/auth/opaque/register/start`, `/finish` | New account |
| `POST /v1/auth/opaque/login/start`, `/finish` | Login |
| `POST /v1/auth/upgrade/start`, `/finish` (session) | SRP → OPAQUE upgrade with a fresh SRP proof |
| `POST /v1/auth/proof/start` (session) | Fresh password proof for `account-key` and the first `keys/identity` publish |
| `POST /v1/auth/account-key` (session + proof) | One-time move of an OPAQUE account to the wrapped account key |
| `POST /v1/auth/password/start`, `/finish` (session) | Change the master password |
| `POST /v1/auth/recovery/opaque/start` | New credential during recovery; the record is sent with `recovery/complete` |
| `POST /v1/auth/srp/init`, `/verify` | Legacy, only for accounts not yet migrated |
| `POST /v1/auth/register` | Returns 410; SRP registration is gone |

A session token proves the caller logged in at some point. It is never
enough on its own to replace key material. Every request that does needs the
password again:

- **Upgrade:** a fresh SRP proof.
- **Account key, first identity-key publish, password change:** a fresh OPAQUE
  proof. `proof/start` (or `password/start`) begins an OPAQUE login bound to
  the session's account. The request then carries `{proofId,
  finishLoginRequest}`, which the server checks like a login finish and burns.

## Changing the master password

A session token alone can't change the password, and neither can an old
one: the session must be less than 15 minutes old (else 403, sign in again).
`password/start` runs a
full OPAQUE login for the current password next to a registration for the new
one, and returns the current account-key wrap. `password/finish` only goes
ahead if the login proof checks out. Starts count against the login throttle.

The client opens the account key with the current password and wraps it under
the new one. In one transaction, `finish` then stores the new OPAQUE record and
the new wrap, and revokes every session except the one making the change. No
item is touched, the vault keys in memory stay valid, and the recovery kit keeps
working. A legacy account must unlock once (which migrates it) before it can
change its password; until then the server answers 409.

Web: Settings → Master password. Desktop: the Account tab (same shared
component). CLI: `nopwd passwd`.

Recovery works the same way. The client takes the account key from the kit,
wraps it under the new password, and sends it with the new OPAQUE record and a
replacement kit; items stay as they are. Clients released before this
change re-encrypt every item instead, and the server still accepts that.

## Migrating SRP accounts

1. The client tries OPAQUE first. An account that hasn't migrated yet gets the
   same fake response as an unknown account, so the client fails locally.
2. The client then falls back to SRP. For an unknown or already-migrated
   account, `srp/init` returns a fake challenge with a stable fake salt, and
   `srp/verify` fails with the same 401 a wrong password gets.
3. Once SRP succeeds, the client upgrades in the new session.
   `upgrade/start` returns a fresh SRP challenge and an OPAQUE registration
   response. `upgrade/finish` carries the SRP proof, the OPAQUE record and the
   wrapped account key. In one transaction the server checks the proof, then:
   - stores the OPAQUE record and the wrapped key, and sets `srp_salt` and
     `srp_verifier` to NULL (`WHERE srp_verifier IS NOT NULL`, exactly one row);
   - drops the account's pending handshakes;
   - revokes every other session.
4. If the upgrade fails, the unlock fails and nothing changes; the next login
   tries again.

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
| `opaque/register/start` | Same response for every email. For an existing account the OPRF evaluation uses a decoy key derived from the lookup key, so it is no guessing oracle against the real one, and nothing is charged to the account. |
| `recovery/init` | Same 401 for an unknown account, no kit, or a wrong code (unchanged). A recovery token dies when the kit is replaced or disabled, or when the password changes. |

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


The rekey can't break a rolling deploy. Replicas take turns through an
advisory lock, and each row is rekeyed in its own savepoint. A row whose keyed
form already exists (an older replica registered the same address again
mid-rollout) is logged as `email_rekey_conflict` for a manual merge and
skipped, and the rest are still keyed. A failure at startup is logged and
retried by the housekeeping task; it never stops the API. Until a row is
keyed, register and login also match the raw hash, so old and new replicas
can't each see a different set of accounts.

## Throttling

- Per IP: 60 requests a minute, burst 30, on every public `/auth` route. This
  was 20 with a burst of 10, but a login now takes two requests (three with
  the SRP fallback), and guessing is bounded per account below.
- Per account, keyed by the keyed email hash whether the account exists or
  not, so the throttle reveals nothing. It counts every login start
  (OPAQUE or SRP), every proof, upgrade and password-change start that isn't
  followed by a successful finish. A wrong OPAQUE password is detected on the
  client, which then never calls finish, so the start is all the server ever
  sees. Registration starts are not counted: for existing accounts they
  evaluate under a decoy key (see enumeration), so they can't be used to lock
  the owner out.
- Two counters per account, with 429 and `Retry-After`:
  - **Per (account, client network)**, where the network is the client's /24
    for IPv4 or /64 for IPv6. 10 free attempts, then 30 s, doubling, capped at
    15 minutes.
  - **Account-wide**, across all networks: 100 free attempts, then 60 s,
    doubling, capped at 1 hour.
- A successful proof resets both counters, and records the network as
  **trusted** for the account. The record is keyed with the lookup key, so a
  dump doesn't reveal where people log in from, and it expires after 90 days
  without a login from that network. Starts from a trusted network use only
  their per-network budget and never touch the account-wide counter. Counters
  decay after 24 h without attempts. The SRP fallback means a wrong password
  costs two attempts while SRP exists.
- So a stranger can lock out only their own networks. With ten or more /24s
  they can also lock out networks the owner hasn't used in 90 days, for up to
  an hour at a time. They can never lock out the owner on a network the owner
  has used.
- Not done: an escalating proof-of-work instead of the hard lock on new
  networks. Every client (web, desktop, extension, CLI) would need a solver,
  and the trusted-network budget already removes the lockout that matters. If
  traveling users get locked out in practice, this is the next step.

### Alerting

The API logs JSON when `LOG_FORMAT=json`. Each event carries `account` (a
12-character prefix of the keyed hash, which can't be reversed without the
secret) and `ip`.

| `event` | Meaning |
|---|---|
| `login_failed` | Server rejected a login proof (OPAQUE finish or SRP verify) |
| `login_backoff` | A counter crossed its free-attempt threshold (`scope` = `network` or `account`) |
| `login_throttled` | A start was refused by the per-account backoff |
| `srp_migrated` | An account moved from SRP to OPAQUE |
| `account_key_migrated` | An account moved to the wrapped account key |

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

Keep them as two separate secrets: they protect different things, and
neither is derived from the other. Neither can be rotated without
re-registering everyone, so back both up next to the database backups. They are worthless without the database, and the
database is much weaker without them.
