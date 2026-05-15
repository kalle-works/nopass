CREATE TABLE devices (
    id                      UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id                 UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    device_name             TEXT NOT NULL,
    device_type             TEXT NOT NULL, -- desktop_mac | android | web | extension
    device_public_key       BYTEA NOT NULL,
    -- vault key re-encrypted for biometric unlock on this device (optional)
    protected_device_key    BYTEA,
    protected_device_key_iv BYTEA,
    last_seen_at            TIMESTAMPTZ,
    created_at              TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX devices_user_id ON devices(user_id);

-- Add FK to sessions now that devices table exists
ALTER TABLE sessions ADD CONSTRAINT sessions_device_id_fk
    FOREIGN KEY (device_id) REFERENCES devices(id) ON DELETE SET NULL;
