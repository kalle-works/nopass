-- OPAQUE (RFC 9807) replaces SRP. The SRP verifier was g^SHA256(salt||SHA256(email:password)),
-- so a database thief could test password guesses at SHA-256 speed. Accounts move to OPAQUE
-- lazily: the first SRP login after this release re-registers with OPAQUE and the SRP columns
-- are cleared. A row with srp_verifier IS NULL is OPAQUE-only.
ALTER TABLE users
    ALTER COLUMN srp_salt DROP NOT NULL,
    ALTER COLUMN srp_verifier DROP NOT NULL,
    ADD COLUMN opaque_record BYTEA,
    -- email_hash used to hold the client's SHA-256 email hash verbatim. It now holds
    -- HMAC-SHA256(NOPASS_EMAIL_LOOKUP_KEY, client hash), so a dump alone can't confirm
    -- whether a known address has an account. Existing rows are rewritten by the API at
    -- startup (the key is not available to SQL); the flag marks rows already rewritten.
    -- The default stays FALSE so rows written by a not-yet-upgraded replica during a
    -- rolling deploy get picked up by the periodic backfill instead of being mislabelled.
    ADD COLUMN email_hash_keyed BOOLEAN NOT NULL DEFAULT FALSE,
    ADD CONSTRAINT users_srp_pair CHECK ((srp_salt IS NULL) = (srp_verifier IS NULL)),
    ADD CONSTRAINT users_has_credential CHECK (opaque_record IS NOT NULL OR srp_verifier IS NOT NULL);

CREATE INDEX users_email_hash_unkeyed ON users(id) WHERE NOT email_hash_keyed;

-- Server AKE state between login start and finish. user_id is NULL for unknown or
-- not-yet-migrated accounts, which get a fake (but indistinguishable) response.
CREATE TABLE pending_opaque_logins (
    id           UUID PRIMARY KEY,
    account_key  TEXT NOT NULL,
    user_id      UUID REFERENCES users(id) ON DELETE CASCADE,
    server_state BYTEA NOT NULL,
    created_at   TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX pending_opaque_created ON pending_opaque_logins(created_at);
CREATE INDEX pending_opaque_account ON pending_opaque_logins(account_key, created_at);
CREATE INDEX pending_srp_user ON pending_srp_sessions(user_id, created_at);

-- Per-account login throttle, keyed by the keyed email hash (whether or not the account
-- exists, so throttling reveals nothing). `failures` counts login starts not followed by a
-- successful finish: with OPAQUE a wrong password is detected on the client, which then
-- never calls finish, so the start is the only thing the server sees.
CREATE TABLE login_throttle (
    account_key  TEXT PRIMARY KEY,
    failures     INTEGER NOT NULL,
    locked_until TIMESTAMPTZ,
    updated_at   TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX login_throttle_updated ON login_throttle(updated_at);
