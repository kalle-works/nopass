-- Ed25519 identity key per user, derived client-side from the RSA private key.
-- public_key_signature is the identity key's signature over the user's key
-- bundle (user id + RSA public key), so an inviter can tell a server-substituted
-- RSA key from the real one once they have pinned or compared the identity key.
ALTER TABLE users
    ADD COLUMN identity_public_key  TEXT,
    ADD COLUMN public_key_signature TEXT;
