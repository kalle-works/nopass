use std::{net::IpAddr, num::NonZeroU32, sync::Arc};

use governor::{DefaultKeyedRateLimiter, Quota};
use sqlx::PgPool;
use uuid::Uuid;

use crate::{config::Config, stripe::StripeClient};

/// Pending SRP handshakes and recovery tokens live in Postgres
/// (pending_srp_sessions / pending_recovery_sessions) so any replica can
/// finish a flow another replica started, and restarts don't drop logins.
/// SRP handshake TTL — init → verify must complete within this window.
pub const SRP_SESSION_TTL_SECS: u64 = 300;

/// Recovery completion involves client-side re-encryption of the whole vault,
/// so the window is longer than the SRP handshake's 5 minutes.
pub const RECOVERY_SESSION_TTL_SECS: u64 = 600;

/// Per-IP auth limiter: `per_minute` requests per minute, burst of half that
/// (20/min with burst 10 by default).
fn auth_limiter(per_minute: u32) -> DefaultKeyedRateLimiter<IpAddr> {
    let per_minute = NonZeroU32::new(per_minute.max(2)).expect("non-zero");
    let burst = NonZeroU32::new(per_minute.get() / 2).expect("non-zero");
    DefaultKeyedRateLimiter::keyed(Quota::per_minute(per_minute).allow_burst(burst))
}

#[derive(Clone)]
pub struct AppState {
    pub db: PgPool,
    pub config: Config,
    /// Per-IP rate limiter for auth endpoints (20 req/min, burst 10).
    pub auth_rate_limiter: Arc<DefaultKeyedRateLimiter<IpAddr>>,
    /// Per-share limiter for the public view endpoint (6 req/min, burst 3).
    pub share_rate_limiter: Arc<DefaultKeyedRateLimiter<Uuid>>,
    /// Stripe client — `None` when STRIPE_SECRET_KEY / STRIPE_WEBHOOK_SECRET are not set.
    pub stripe: Option<StripeClient>,
}

impl AppState {
    pub fn new(db: PgPool, config: Config) -> Self {
        let auth_rate_limiter = Arc::new(auth_limiter(config.auth_rate_limit_per_minute));

        let share_rate_limiter = Arc::new(DefaultKeyedRateLimiter::keyed(
            Quota::per_minute(NonZeroU32::new(6).expect("non-zero"))
                .allow_burst(NonZeroU32::new(3).expect("non-zero")),
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
            auth_rate_limiter,
            share_rate_limiter,
            stripe,
        }
    }

    /// Spawn a background task that evicts expired SRP sessions every 60 seconds.
    /// Without this, an attacker who calls srp/init repeatedly can exhaust server memory.
    pub fn spawn_srp_cleanup(self: &Arc<Self>) {
        let db = self.db.clone();
        tokio::spawn(async move {
            let mut interval = tokio::time::interval(tokio::time::Duration::from_secs(60));
            let mut ticks: u64 = 0;
            loop {
                interval.tick().await;
                ticks += 1;
                match crate::db::pending::prune_expired(
                    &db,
                    SRP_SESSION_TTL_SECS as i64,
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
                }
            }
        });
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn allowed_in_a_row(limiter: &DefaultKeyedRateLimiter<IpAddr>) -> usize {
        let ip: IpAddr = "127.0.0.1".parse().unwrap();
        (0..2000).take_while(|_| limiter.check_key(&ip).is_ok()).count()
    }

    #[test]
    fn auth_limiter_default_is_burst_ten_and_override_raises_it() {
        assert_eq!(allowed_in_a_row(&auth_limiter(20)), 10);
        assert_eq!(allowed_in_a_row(&auth_limiter(1000)), 500);
    }
}
