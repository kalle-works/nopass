-- Password-independent account key. The vault keys (enc + mac) a user's
-- password derived at the time become the account key; the client stores them
-- AES-GCM-wrapped under a KEK derived from the password (AAD binds user id and
-- purpose). Changing the password re-wraps this blob instead of re-encrypting
-- items. NULL until the account's client has migrated on unlock.
ALTER TABLE users
    ADD COLUMN wrapped_account_key    BYTEA,
    ADD COLUMN wrapped_account_key_iv BYTEA,
    ADD CONSTRAINT users_account_key_pair
        CHECK ((wrapped_account_key IS NULL) = (wrapped_account_key_iv IS NULL));
