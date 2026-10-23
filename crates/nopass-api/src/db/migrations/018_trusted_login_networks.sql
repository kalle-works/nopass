-- Networks (/24 or /64) an account has successfully logged in from. Logins
-- from these get their own backoff budget that the account-wide ceiling
-- doesn't consume, so a stranger guessing from elsewhere can't lock the owner
-- out. network_hash is HMAC(email lookup key, account key | network), so a
-- dump doesn't reveal where users log in from.
CREATE TABLE trusted_login_networks (
    account_key     TEXT NOT NULL,
    network_hash    TEXT NOT NULL,
    last_success_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    PRIMARY KEY (account_key, network_hash)
);

CREATE INDEX trusted_login_networks_seen ON trusted_login_networks(last_success_at);
