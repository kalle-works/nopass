-- Security activity log. Metadata only — event type, source IP, device —
-- never item contents or names. Gives individuals the audit trail to spot
-- an account compromise: unknown logins, recovery attempts, new devices.
CREATE TABLE activity_events (
    id          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id     UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    event_type  TEXT NOT NULL,
    ip          TEXT,
    device_id   UUID,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX activity_events_user_created ON activity_events(user_id, created_at DESC);
