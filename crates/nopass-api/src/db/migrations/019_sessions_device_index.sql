-- no-transaction
-- CONCURRENTLY cannot run inside a transaction, or alongside other statements
-- in one simple query, so this file holds exactly this statement. If a build
-- is interrupted Postgres leaves an INVALID index behind; drop it and rerun.
CREATE INDEX CONCURRENTLY IF NOT EXISTS sessions_device_id ON sessions(device_id);
