-- One-time / expiring item shares. The blob is an AES-256-GCM encrypted
-- snapshot of a single item's plaintext; the key travels only in the share
-- URL fragment, which never reaches the server. The server can expire and
-- count views but never read the secret.
CREATE TABLE shares (
    id          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id     UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    blob        BYTEA NOT NULL,
    blob_iv     BYTEA NOT NULL,
    -- Encrypted display label so the owner can tell shares apart in a list
    label_blob  BYTEA NOT NULL,
    label_iv    BYTEA NOT NULL,
    max_views   INT NOT NULL,
    view_count  INT NOT NULL DEFAULT 0,
    expires_at  TIMESTAMPTZ NOT NULL,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX shares_user_id_idx ON shares(user_id);
CREATE INDEX shares_expires_at_idx ON shares(expires_at);
