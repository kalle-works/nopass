-- Account recovery kit. The client derives an auth key and a wrap key from a
-- random recovery code; we store only SHA-256(auth key) plus the wrap-key
-- encrypted copy of the vault subkeys. The server can gate access to the blob
-- but can never decrypt it.
ALTER TABLE users
    ADD COLUMN recovery_auth_hash  BYTEA,
    ADD COLUMN recovery_blob       BYTEA,
    ADD COLUMN recovery_blob_iv    BYTEA,
    ADD COLUMN recovery_updated_at TIMESTAMPTZ;
