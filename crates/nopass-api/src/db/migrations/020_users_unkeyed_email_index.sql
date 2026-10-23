-- no-transaction
-- CONCURRENTLY cannot run inside a transaction, or alongside other statements
-- in one simple query, so this file holds exactly this statement. If a build
-- is interrupted Postgres leaves an INVALID index behind; drop it and rerun.
CREATE INDEX CONCURRENTLY IF NOT EXISTS users_email_hash_unkeyed ON users(id) WHERE NOT email_hash_keyed;
