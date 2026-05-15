use std::{collections::HashMap, net::IpAddr, num::NonZeroU32, sync::Arc};

use governor::{DefaultKeyedRateLimiter, Quota};
use sqlx::PgPool;
use tokio::sync::Mutex;
use uuid::Uuid;

use crate::config::Config;

/// In-memory pending SRP sessions (step 1 → step 2).
/// In production this should be Redis with a short TTL.
#[derive(Debug, Clone)]
pub struct SrpPendingSession {
    pub user_id: Uuid,
    pub verifier: Vec<u8>,
    pub server_ephemeral_b: Vec<u8>,
    /// Client's public ephemeral A, received in step 1 and used to verify M1 in step 2.
    pub client_public_a: Vec<u8>,
    pub created_at: std::time::Instant,
}

#[derive(Clone)]
pub struct AppState {
    pub db: PgPool,
    pub config: Config,
    pub srp_sessions: Arc<Mutex<HashMap<Uuid, SrpPendingSession>>>,
    /// Per-IP rate limiter for auth endpoints (20 req/min)
    pub auth_rate_limiter: Arc<DefaultKeyedRateLimiter<IpAddr>>,
}

impl AppState {
    pub fn new(db: PgPool, config: Config) -> Self {
        let auth_rate_limiter = Arc::new(DefaultKeyedRateLimiter::keyed(
            Quota::per_minute(NonZeroU32::new(20).expect("non-zero"))
                .allow_burst(NonZeroU32::new(10).expect("non-zero")),
        ));
        Self {
            db,
            config,
            srp_sessions: Arc::new(Mutex::new(HashMap::new())),
            auth_rate_limiter,
        }
    }
}
