-- HMAC under the account's vault MAC key saying every item is in the v2
-- envelope format. Opaque to the server; clients verify it and then refuse v1
-- items, so an old v1 blob cannot be replayed on a fresh device.
ALTER TABLE users
    ADD COLUMN vault_format_marker TEXT;

-- Org key version each wrap was signed for (part of the signed message).
-- NULL on legacy unsigned wraps, which clients refuse until the owner re-signs.
ALTER TABLE organization_members
    ADD COLUMN key_epoch INTEGER CHECK (key_epoch >= 1);
