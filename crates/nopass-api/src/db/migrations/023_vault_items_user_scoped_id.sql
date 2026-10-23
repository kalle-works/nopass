-- Item ids are chosen by the client, so a globally unique id let a create
-- reveal (via 409) that another user already holds that id. Uniqueness is now
-- per user: every query already filters on user_id and nothing references
-- vault_items(id). Swapping the primary key onto the prebuilt index (021-022) is a
-- metadata change with a momentary lock.
ALTER TABLE vault_items
    DROP CONSTRAINT vault_items_pkey,
    ADD CONSTRAINT vault_items_pkey PRIMARY KEY USING INDEX vault_items_user_id_id;
