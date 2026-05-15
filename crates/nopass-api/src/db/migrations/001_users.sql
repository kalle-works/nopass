CREATE TABLE users (
    id                          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    -- SHA-256("nopass-v1-email:" || lowercase(email)) — server never stores plaintext email
    email_hash                  TEXT NOT NULL UNIQUE,
    srp_salt                    BYTEA NOT NULL,
    srp_verifier                BYTEA NOT NULL,
    -- {"type":"argon2id","memory_kib":65536,"iterations":3,"parallelism":4}
    kdf_params                  JSONB NOT NULL,
    -- AES-256-GCM encrypted vault key, encrypted with stretchedMasterKey on client
    protected_symmetric_key     BYTEA NOT NULL,
    protected_symmetric_key_iv  BYTEA NOT NULL,
    created_at                  TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at                  TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
