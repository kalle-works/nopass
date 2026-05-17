use anyhow::{Context, Result};

#[derive(Debug, Clone)]
pub struct Config {
    pub database_url: String,
    pub host: String,
    pub port: u16,
    /// Allowed CORS origins, e.g. ["https://nopass.app", "http://localhost:4020"]
    pub allowed_origins: Vec<String>,
    /// Trusted proxy CIDRs — only trust X-Forwarded-For from these IPs.
    /// Leave empty to always use the direct TCP connection IP (safe default).
    pub trusted_proxies: Vec<std::net::IpAddr>,
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

        // NOPASS_TRUSTED_PROXIES: comma-separated list of proxy IP addresses that are
        // allowed to set X-Forwarded-For. Leave unset (default) when not behind a proxy.
        let trusted_proxies = std::env::var("NOPASS_TRUSTED_PROXIES")
            .unwrap_or_default()
            .split(',')
            .map(|s| s.trim())
            .filter(|s| !s.is_empty())
            .filter_map(|s| s.parse::<std::net::IpAddr>().ok())
            .collect();

        Ok(Config {
            database_url,
            host,
            port,
            allowed_origins,
            trusted_proxies,
        })
    }

    pub fn bind_addr(&self) -> String {
        format!("{}:{}", self.host, self.port)
    }
}
