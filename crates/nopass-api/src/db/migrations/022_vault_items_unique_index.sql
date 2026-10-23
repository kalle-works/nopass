-- no-transaction
-- CONCURRENTLY cannot run inside a transaction, or alongside other statements
-- in one simple query, so this file holds exactly this statement.
CREATE UNIQUE INDEX CONCURRENTLY vault_items_user_id_id ON vault_items(user_id, id);
