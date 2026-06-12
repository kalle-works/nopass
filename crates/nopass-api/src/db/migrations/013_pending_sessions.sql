-- SRP handshakes and recovery tokens used to live in process memory, which
-- forced a single API replica and dropped in-flight logins on every restart.
CREATE TABLE pending_srp_sessions (
    id                 UUID PRIMARY KEY,
    user_id            UUID NOT NULL,
    srp_verifier       BYTEA NOT NULL,
    server_ephemeral_b BYTEA NOT NULL,
    client_public_a    BYTEA NOT NULL,
    created_at         TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE pending_recovery_sessions (
    token      UUID PRIMARY KEY,
    user_id    UUID NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX pending_srp_created ON pending_srp_sessions(created_at);
CREATE INDEX pending_recovery_created ON pending_recovery_sessions(created_at);
