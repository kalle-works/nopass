-- no-transaction
-- CONCURRENTLY cannot run inside a transaction, or alongside other statements
-- in one simple query, so this file holds exactly this statement. If a build
-- is interrupted Postgres leaves an INVALID index behind; drop it and rerun.
CREATE UNIQUE INDEX CONCURRENTLY IF NOT EXISTS vault_items_user_id_id ON vault_items(user_id, id);
