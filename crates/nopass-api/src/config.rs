use anyhow::{bail, Context, Result};
use base64::{
    engine::general_purpose::{STANDARD as B64, URL_SAFE_NO_PAD as B64URL},
    Engine,
};

/// Secret key material; `Debug` is redacted so a logged `Config` can't leak it.
#[derive(Clone)]
pub struct SecretBytes(pub Vec<u8>);

impl std::fmt::Debug for SecretBytes {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("[redacted]")
    }
}

#[derive(Debug, Clone)]
pub struct Config {
    pub database_url: String,
    pub host: String,
    pub port: u16,
    /// Allowed CORS origins, e.g. ["https://nopass.app", "http://localhost:4020"]
    pub allowed_origins: Vec<String>,
    /// Trusted proxy CIDRs — only trust X-Forwarded-For from these IPs.
    /// Leave empty to always use the direct TCP connection IP (safe default).
    pub trusted_proxies: Vec<ipnet::IpNet>,
    /// Per-IP request budget per minute for the auth endpoints; the burst is
    /// half of it. The default (20) is the production setting; browser e2e
    /// runs raise it because every test signs in from 127.0.0.1. Limiters
    /// live in process memory: each replica enforces its own budget, so N
    /// replicas allow up to N times this per IP.
    pub auth_rate_limit_per_minute: u32,

    /// Serialized OPAQUE ServerSetup (OPRF seed + server keypair). Losing or
    /// rotating it invalidates every OPAQUE registration record.
    pub opaque_server_setup: SecretBytes,
    /// HMAC key for the stored email lookup hash. Rotating it orphans every
    /// account, so it is set once per deployment like the OPAQUE setup.
    pub email_lookup_key: SecretBytes,

    // ─── Stripe (optional — billing routes return 503 when unset) ────────────
    pub stripe_secret_key: Option<String>,
    pub stripe_webhook_secret: Option<String>,
    /// Price IDs from the Stripe dashboard.
    pub stripe_pro_monthly_price_id: Option<String>,
    pub stripe_pro_annual_price_id: Option<String>,
    pub stripe_teams_price_id: Option<String>,
}

impl Config {
    pub fn from_env() -> Result<Self> {
        let database_url =
            std::env::var("DATABASE_URL").context("DATABASE_URL must be set")?;

        let host = std::env::var("NOPASS_HOST").unwrap_or_else(|_| "127.0.0.1".into());
        let port = std::env::var("NOPASS_PORT")
            .unwrap_or_else(|_| "3001".into())
            .parse::<u16>()
            .context("NOPASS_PORT must be a valid port number")?;

        // NOPASS_ALLOWED_ORIGINS: comma-separated list of allowed CORS origins.
        // Default to localhost dev origin; in production set to https://nopass.app
        let allowed_origins = std::env::var("NOPASS_ALLOWED_ORIGINS")
            .unwrap_or_else(|_| "http://localhost:4020".into())
            .split(',')
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty())
            .collect();

        // NOPASS_TRUSTED_PROXIES: comma-separated proxy IPs or CIDRs allowed to
        // set X-Forwarded-For. CIDRs matter behind in-cluster ingress (Traefik
        // pod IPs are dynamic). Leave unset (default) when not behind a proxy.
        let trusted_proxies = std::env::var("NOPASS_TRUSTED_PROXIES")
            .unwrap_or_default()
            .split(',')
            .map(|s| s.trim())
            .filter(|s| !s.is_empty())
            .filter_map(|s| {
                s.parse::<ipnet::IpNet>()
                    .ok()
                    .or_else(|| s.parse::<std::net::IpAddr>().ok().map(ipnet::IpNet::from))
            })
            .collect();

        let auth_rate_limit_per_minute = std::env::var("NOPASS_AUTH_RATE_LIMIT_PER_MIN")
            .unwrap_or_else(|_| "60".into())
            .parse::<u32>()
            .ok()
            .filter(|n| *n >= 2)
            .context("NOPASS_AUTH_RATE_LIMIT_PER_MIN must be an integer >= 2")?;
        // Both auth secrets are mandatory: without them the API can't
        // authenticate anyone, so refuse to start rather than fail per request.
        let opaque_server_setup = std::env::var("NOPASS_OPAQUE_SERVER_SETUP")
            .context("NOPASS_OPAQUE_SERVER_SETUP must be set (generate: nopass-api generate-opaque-setup)")?;
        let opaque_server_setup = B64URL
            .decode(opaque_server_setup.trim())
            .context("NOPASS_OPAQUE_SERVER_SETUP must be base64url")?;
        nopass_crypto::opaque::parse_server_setup(&opaque_server_setup)
            .context("NOPASS_OPAQUE_SERVER_SETUP is not a valid OPAQUE server setup")?;

        let email_lookup_key = std::env::var("NOPASS_EMAIL_LOOKUP_KEY")
            .context("NOPASS_EMAIL_LOOKUP_KEY must be set (generate: openssl rand -base64 32)")?;
        let email_lookup_key = B64
            .decode(email_lookup_key.trim())
            .context("NOPASS_EMAIL_LOOKUP_KEY must be base64")?;
        if email_lookup_key.len() < 32 {
            bail!("NOPASS_EMAIL_LOOKUP_KEY must decode to at least 32 bytes");
        }

        let stripe_secret_key = std::env::var("STRIPE_SECRET_KEY").ok();
        let stripe_webhook_secret = std::env::var("STRIPE_WEBHOOK_SECRET").ok();
        let stripe_pro_monthly_price_id = std::env::var("STRIPE_PRO_MONTHLY_PRICE_ID").ok();
        let stripe_pro_annual_price_id = std::env::var("STRIPE_PRO_ANNUAL_PRICE_ID").ok();
        let stripe_teams_price_id = std::env::var("STRIPE_TEAMS_PRICE_ID").ok();

        Ok(Config {
            database_url,
            host,
            port,
            allowed_origins,
            trusted_proxies,
            auth_rate_limit_per_minute,
            opaque_server_setup: SecretBytes(opaque_server_setup),
            email_lookup_key: SecretBytes(email_lookup_key),
            stripe_secret_key,
            stripe_webhook_secret,
            stripe_pro_monthly_price_id,
            stripe_pro_annual_price_id,
            stripe_teams_price_id,
        })
    }

    pub fn bind_addr(&self) -> String {
        format!("{}:{}", self.host, self.port)
    }
}
