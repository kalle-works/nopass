use std::{collections::HashMap, net::IpAddr, num::NonZeroU32, sync::Arc};

use governor::{DefaultKeyedRateLimiter, Quota};
use sqlx::PgPool;
use tokio::sync::Mutex;
use uuid::Uuid;

use crate::{config::Config, stripe::StripeClient};

/// In-memory pending SRP sessions (step 1 → step 2).
/// Entries are removed on successful verify or after expiry.
/// The background cleanup task sweeps for sessions older than 5 minutes.
#[derive(Debug, Clone)]
pub struct SrpPendingSession {
    pub user_id: Uuid,
    pub verifier: Vec<u8>,
    pub server_ephemeral_b: Vec<u8>,
    /// Client's public ephemeral A, received in step 1 and used to verify M1 in step 2.
    /// Stored server-side so the client cannot substitute a different A in step 2.
    pub client_public_a: Vec<u8>,
    pub created_at: std::time::Instant,
}

#[derive(Clone)]
pub struct AppState {
    pub db: PgPool,
    pub config: Config,
    pub srp_sessions: Arc<Mutex<HashMap<Uuid, SrpPendingSession>>>,
    /// Per-IP rate limiter for auth endpoints (20 req/min, burst 10).
    pub auth_rate_limiter: Arc<DefaultKeyedRateLimiter<IpAddr>>,
    /// Stripe client — `None` when STRIPE_SECRET_KEY / STRIPE_WEBHOOK_SECRET are not set.
    pub stripe: Option<StripeClient>,
}

impl AppState {
    pub fn new(db: PgPool, config: Config) -> Self {
        let auth_rate_limiter = Arc::new(DefaultKeyedRateLimiter::keyed(
            Quota::per_minute(NonZeroU32::new(20).expect("non-zero"))
                .allow_burst(NonZeroU32::new(10).expect("non-zero")),
        ));

        let stripe = match (&config.stripe_secret_key, &config.stripe_webhook_secret) {
            (Some(key), Some(secret)) => {
                StripeClient::new(key.clone(), secret.clone())
                    .map_err(|e| tracing::warn!("Stripe client init failed: {e}"))
                    .ok()
            }
            _ => {
                tracing::info!("Stripe keys not set — billing routes will return 503");
                None
            }
        };

        Self {
            db,
            config,
            srp_sessions: Arc::new(Mutex::new(HashMap::new())),
            auth_rate_limiter,
            stripe,
        }
    }

    /// Spawn a background task that evicts expired SRP sessions every 60 seconds.
    /// Without this, an attacker who calls srp/init repeatedly can exhaust server memory.
    pub fn spawn_srp_cleanup(self: &Arc<Self>) {
        let sessions = self.srp_sessions.clone();
        tokio::spawn(async move {
            let mut interval = tokio::time::interval(tokio::time::Duration::from_secs(60));
            loop {
                interval.tick().await;
                let mut map = sessions.lock().await;
                let before = map.len();
                map.retain(|_, s| s.created_at.elapsed().as_secs() < 300);
                let removed = before.saturating_sub(map.len());
                if removed > 0 {
                    tracing::debug!("evicted {removed} expired SRP sessions");
                }
            }
        });
    }
}
