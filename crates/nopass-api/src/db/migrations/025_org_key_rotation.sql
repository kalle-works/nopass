-- Current org key epoch. A rotation (on member removal or by the owner)
-- re-encrypts every org item and re-wraps the key for every remaining member
-- at key_epoch + 1 in one transaction; wraps for any other epoch are refused.
ALTER TABLE organizations
    ADD COLUMN key_epoch INTEGER NOT NULL DEFAULT 1 CHECK (key_epoch >= 1);
