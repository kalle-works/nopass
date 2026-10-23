-- no-transaction
-- CONCURRENTLY cannot run inside a transaction, or alongside other statements
-- in one simple query, so this file holds exactly this statement.
CREATE INDEX CONCURRENTLY sessions_device_id ON sessions(device_id);
