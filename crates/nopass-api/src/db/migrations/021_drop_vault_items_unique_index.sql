-- no-transaction
-- CONCURRENTLY cannot run inside a transaction, or alongside other statements
-- in one simple query, so this file holds exactly this statement.
-- An interrupted build leaves an INVALID index behind. The create below has no
-- IF NOT EXISTS, so this drop (a migration of its own, it must be the only
-- statement) clears any leftover before every attempt.
DROP INDEX CONCURRENTLY IF EXISTS vault_items_user_id_id;
