-- RSA-OAEP-256 key pair per user, used for encrypting org vault keys.
-- The private key is stored encrypted with the user's stretchedMasterKey (AES-256-GCM),
-- exactly like protected_symmetric_key. The public key is stored in SPKI DER, base64-encoded.
ALTER TABLE users
    ADD COLUMN public_key                   TEXT,
    ADD COLUMN protected_private_key        TEXT,
    ADD COLUMN protected_private_key_iv     TEXT;
