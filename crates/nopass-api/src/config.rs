use anyhow::{Context, Result};

#[derive(Debug, Clone)]
pub struct Config {
    pub database_url: String,
    pub host: String,
    pub port: u16,
    /// 32-byte secret for signing session tokens
    pub session_secret: [u8; 32],
    /// Allowed CORS origins, e.g. ["https://nopwd.dev", "http://localhost:4020"]
    pub allowed_origins: Vec<String>,
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

        let secret_str =
            std::env::var("NOPASS_SESSION_SECRET").context("NOPASS_SESSION_SECRET must be set")?;

        anyhow::ensure!(
            secret_str.len() >= 32,
            "NOPASS_SESSION_SECRET must be at least 32 characters"
        );

        let mut session_secret = [0u8; 32];
        session_secret.copy_from_slice(&secret_str.as_bytes()[..32]);

        // NOPASS_ALLOWED_ORIGINS: comma-separated list of allowed CORS origins.
        // Default to localhost dev origin; in production set to https://nopwd.dev
        let allowed_origins = std::env::var("NOPASS_ALLOWED_ORIGINS")
            .unwrap_or_else(|_| "http://localhost:4020".into())
            .split(',')
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty())
            .collect();

        Ok(Config {
            database_url,
            host,
            port,
            session_secret,
            allowed_origins,
        })
    }

    pub fn bind_addr(&self) -> String {
        format!("{}:{}", self.host, self.port)
    }
}
