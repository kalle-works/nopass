-- Ed25519 identity key per user, derived client-side from the RSA private key.
-- public_key_signature is the identity key's signature over the user's key
-- bundle (user id + RSA public key), so an inviter can tell a server-substituted
-- RSA key from the real one once they have pinned or compared the identity key.
ALTER TABLE users
    ADD COLUMN identity_public_key  TEXT,
    ADD COLUMN public_key_signature TEXT;

-- Inviter's identity-key signature over (org, recipient, inviter, role,
-- encrypted_org_key). The signer is invited_by, or the member themselves when
-- invited_by is NULL (an org creator's own wrap). NULL on rows created before
-- signed wraps existed.
ALTER TABLE organization_members
    ADD COLUMN wrap_signature TEXT;
