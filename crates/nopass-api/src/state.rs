use std::{collections::HashMap, sync::Arc};

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
    pub created_at: std::time::Instant,
}

#[derive(Clone)]
pub struct AppState {
    pub db: PgPool,
    pub config: Config,
    pub srp_sessions: Arc<Mutex<HashMap<Uuid, SrpPendingSession>>>,
}

impl AppState {
    pub fn new(db: PgPool, config: Config) -> Self {
        Self {
            db,
            config,
            srp_sessions: Arc::new(Mutex::new(HashMap::new())),
        }
    }
}
