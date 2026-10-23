use std::{net::IpAddr, num::NonZeroU32, sync::Arc};

use governor::{DefaultKeyedRateLimiter, Quota};
use hmac::{Hmac, Mac};
use nopass_crypto::opaque::{self, ServerSetup};
use sha2::Sha256;
use sqlx::PgPool;

use crate::{config::Config, stripe::StripeClient};

/// Pending login handshakes and recovery tokens live in Postgres
/// (pending_opaque_logins / pending_srp_sessions / pending_recovery_sessions)
/// so any replica can finish a flow another replica started, and restarts
/// don't drop logins. Handshake TTL — start → finish must complete within it.
pub const SRP_SESSION_TTL_SECS: u64 = 300;
pub const OPAQUE_LOGIN_TTL_SECS: u64 = 300;

/// Recovery completion involves client-side re-encryption of the whole vault,
/// so the window is longer than the SRP handshake's 5 minutes.
pub const RECOVERY_SESSION_TTL_SECS: u64 = 600;

#[derive(Clone)]
pub struct AppState {
    pub db: PgPool,
    pub config: Config,
    /// Per-IP rate limiter for auth endpoints (60 req/min, burst 30). A login
    /// is two requests (three with the SRP fallback), and guessing is bounded
    /// per account by the login throttle, so this only has to stop floods.
    pub auth_rate_limiter: Arc<DefaultKeyedRateLimiter<IpAddr>>,
    /// Stripe client — `None` when STRIPE_SECRET_KEY / STRIPE_WEBHOOK_SECRET are not set.
    pub stripe: Option<StripeClient>,
    pub opaque_setup: Arc<ServerSetup>,
}

impl AppState {
    pub fn new(db: PgPool, config: Config) -> Self {
        let auth_rate_limiter = Arc::new(DefaultKeyedRateLimiter::keyed(
            Quota::per_minute(NonZeroU32::new(60).expect("non-zero"))
                .allow_burst(NonZeroU32::new(30).expect("non-zero")),
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

        let opaque_setup = Arc::new(
            opaque::parse_server_setup(&config.opaque_server_setup.0)
                .expect("OPAQUE server setup is validated in Config::from_env"),
        );

        Self {
            db,
            config,
            auth_rate_limiter,
            stripe,
            opaque_setup,
        }
    }

    /// The account's database key: HMAC-SHA256(email lookup key, client email
    /// hash). Lowercased first because the client sends hex and the HMAC is
    /// over the string.
    pub fn account_key(&self, email_hash: &str) -> String {
        account_key(&self.config.email_lookup_key.0, email_hash)
    }

    /// Spawn the periodic housekeeping task: evicts expired login handshakes
    /// every 60 seconds (each start writes a row, so an attacker calling start
    /// repeatedly would otherwise grow the table without bound), keys email
    /// hashes left behind by older replicas, and runs hourly pruning.
    pub fn spawn_housekeeping(self: &Arc<Self>) {
        let db = self.db.clone();
        let lookup_key = self.config.email_lookup_key.0.clone();
        tokio::spawn(async move {
            let mut interval = tokio::time::interval(tokio::time::Duration::from_secs(60));
            let mut ticks: u64 = 0;
            loop {
                interval.tick().await;
                ticks += 1;
                match crate::db::auth::key_email_hashes(&db, |h| account_key(&lookup_key, h)).await {
                    Ok(n) if n > 0 => tracing::info!("keyed {n} legacy email hashes"),
                    Ok(_) => {}
                    Err(e) => tracing::warn!("email hash keying failed: {e}"),
                }
                match crate::db::pending::prune_expired(
                    &db,
                    OPAQUE_LOGIN_TTL_SECS.max(SRP_SESSION_TTL_SECS) as i64,
                    RECOVERY_SESSION_TTL_SECS as i64,
                )
                .await
                {
                    Ok(n) if n > 0 => tracing::debug!("pruned {n} expired pending sessions"),
                    Ok(_) => {}
                    Err(e) => tracing::warn!("pending-session prune failed: {e}"),
                }
                // Hourly housekeeping off the hot path
                if ticks.is_multiple_of(60) {
                    match crate::db::shares::delete_expired(&db).await {
                        Ok(n) if n > 0 => tracing::debug!("deleted {n} expired shares"),
                        Ok(_) => {}
                        Err(e) => tracing::warn!("expired-share cleanup failed: {e}"),
                    }
                    match crate::db::activity::prune_old(&db).await {
                        Ok(n) if n > 0 => tracing::debug!("pruned {n} old activity events"),
                        Ok(_) => {}
                        Err(e) => tracing::warn!("activity prune failed: {e}"),
                    }
                    match crate::db::sessions::prune_expired(&db).await {
                        Ok(n) if n > 0 => tracing::debug!("pruned {n} expired sessions"),
                        Ok(_) => {}
                        Err(e) => tracing::warn!("session prune failed: {e}"),
                    }
                    match crate::db::throttle::prune_stale(&db).await {
                        Ok(n) if n > 0 => tracing::debug!("pruned {n} stale login throttle rows"),
                        Ok(_) => {}
                        Err(e) => tracing::warn!("login throttle prune failed: {e}"),
                    }
                }
            }
        });
    }
}

pub fn account_key(lookup_key: &[u8], email_hash: &str) -> String {
    let mut mac = Hmac::<Sha256>::new_from_slice(lookup_key).expect("HMAC accepts any key length");
    mac.update(email_hash.to_ascii_lowercase().as_bytes());
    hex::encode(mac.finalize().into_bytes())
}
