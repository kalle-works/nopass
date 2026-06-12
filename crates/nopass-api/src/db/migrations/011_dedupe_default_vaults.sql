-- Registration used to create the default vault twice (once inside
-- create_user, once in the register route), leaving every account with a
-- phantom empty vault. Remove empty non-first vaults that existed before
-- multi-vault support shipped — at migration time these can only be phantoms.
DELETE FROM vaults v
WHERE NOT EXISTS (SELECT 1 FROM vault_items i WHERE i.vault_id = v.id)
  AND v.id <> (
      SELECT v2.id FROM vaults v2
      WHERE v2.user_id = v.user_id
      ORDER BY v2.created_at, v2.id
      LIMIT 1
  );
