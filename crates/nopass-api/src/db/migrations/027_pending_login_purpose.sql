-- What a pending OPAQUE handshake may be redeemed for. A password proof
-- started for one change (say, the identity key) must not authorize
-- another (the account key), and none of them may finish as a login.
ALTER TABLE pending_opaque_logins
    ADD COLUMN purpose TEXT NOT NULL DEFAULT 'login'
        CHECK (purpose IN ('login', 'account_key', 'identity_key', 'password_change'));
