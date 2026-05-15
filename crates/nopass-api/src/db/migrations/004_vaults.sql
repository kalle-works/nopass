CREATE TABLE vaults (
    id          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id     UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    name_blob   BYTEA NOT NULL,
    name_iv     BYTEA NOT NULL,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX vaults_user_id ON vaults(user_id);

CREATE TABLE vault_items (
    id          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    vault_id    UUID NOT NULL REFERENCES vaults(id) ON DELETE CASCADE,
    user_id     UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    item_type   TEXT NOT NULL,    -- login | note | card | identity
    blob        BYTEA NOT NULL,   -- AES-256-GCM ciphertext of the entire item JSON
    blob_iv     BYTEA NOT NULL,
    blob_mac    BYTEA NOT NULL,   -- HMAC-SHA256(iv || ciphertext)
    version     BIGINT NOT NULL DEFAULT 1,
    deleted_at  TIMESTAMPTZ,      -- soft delete / tombstone for CRDT
    created_at  TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at  TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX vault_items_vault_id ON vault_items(vault_id);
CREATE INDEX vault_items_user_id ON vault_items(user_id);
CREATE INDEX vault_items_updated_at ON vault_items(updated_at);
