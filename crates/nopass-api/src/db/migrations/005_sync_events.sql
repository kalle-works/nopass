CREATE TABLE sync_events (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id         UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    device_id       UUID NOT NULL REFERENCES devices(id) ON DELETE CASCADE,
    -- Monotonically increasing per-device Lamport clock
    sequence_number BIGINT NOT NULL,
    event_type      TEXT NOT NULL,   -- upsert | delete
    item_id         UUID NOT NULL,
    -- Optional AES-GCM encrypted field-level delta (for partial updates)
    encrypted_delta BYTEA,
    delta_iv        BYTEA,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE(device_id, sequence_number)
);

-- Fast delta sync: "give me all events after sequence X from any device for user Y"
CREATE INDEX sync_events_user_seq ON sync_events(user_id, sequence_number);
CREATE INDEX sync_events_item_id ON sync_events(item_id);
