use std::{net::IpAddr, num::NonZeroU32, sync::Arc};

use governor::{DefaultKeyedRateLimiter, Quota};
use hmac::{Hmac, Mac};
use nopass_crypto::opaque::{self, ServerSetup};
use sha2::Sha256;
use sqlx::PgPool;
use uuid::Uuid;

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

/// Drop limiter entries whose quota has fully replenished; they are
/// indistinguishable from a key never seen. Without this every IP or share id
/// that ever hit a limiter stays in memory until restart.
fn prune_limiter<K: std::hash::Hash + Eq + Clone>(limiter: &DefaultKeyedRateLimiter<K>) {
    limiter.retain_recent();
    limiter.shrink_to_fit();
}

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
    /// Per-IP rate limiter for auth endpoints (NOPASS_AUTH_RATE_LIMIT_PER_MIN,
    /// default 60/min, burst half that). A login
    /// is two requests (three with the SRP fallback), and guessing is bounded
    /// per account by the login throttle, so this only has to stop floods.
    pub auth_rate_limiter: Arc<DefaultKeyedRateLimiter<IpAddr>>,
    /// Per-share limiter for the public view endpoint (6 req/min, burst 3).
    /// Like the auth limiter it lives in process memory, so each replica
    /// enforces its own budget: with N replicas the effective limit is up to N
    /// times the configured one.
    pub share_rate_limiter: Arc<DefaultKeyedRateLimiter<Uuid>>,
    /// Stripe client — `None` when STRIPE_SECRET_KEY / STRIPE_WEBHOOK_SECRET are not set.
    pub stripe: Option<StripeClient>,
    pub opaque_setup: Arc<ServerSetup>,
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

        let opaque_setup = Arc::new(
            opaque::parse_server_setup(&config.opaque_server_setup.0)
                .expect("OPAQUE server setup is validated in Config::from_env"),
        );

        Self {
            db,
            config,
            auth_rate_limiter,
            share_rate_limiter,
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
        let auth_limiter = self.auth_rate_limiter.clone();
        let share_limiter = self.share_rate_limiter.clone();
        tokio::spawn(async move {
            let mut interval = tokio::time::interval(tokio::time::Duration::from_secs(60));
            let mut ticks: u64 = 0;
            loop {
                interval.tick().await;
                ticks += 1;
                // Keyed limiters add an entry per IP / share id ever seen
                prune_limiter(&auth_limiter);
                prune_limiter(&share_limiter);
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

#[cfg(test)]
mod tests {
    use super::*;

    fn allowed_in_a_row(limiter: &DefaultKeyedRateLimiter<IpAddr>) -> usize {
        let ip: IpAddr = "127.0.0.1".parse().unwrap();
        (0..2000).take_while(|_| limiter.check_key(&ip).is_ok()).count()
    }

    #[test]
    fn prune_limiter_drops_replenished_keys_only() {
        // 1000/s replenishes in a millisecond; the slow key stays throttled
        let fast: DefaultKeyedRateLimiter<u8> =
            DefaultKeyedRateLimiter::keyed(Quota::per_second(NonZeroU32::new(1000).unwrap()));
        let slow: DefaultKeyedRateLimiter<u8> =
            DefaultKeyedRateLimiter::keyed(Quota::per_hour(NonZeroU32::new(1).unwrap()));
        for k in 0..50u8 {
            fast.check_key(&k).unwrap();
            slow.check_key(&k).unwrap();
        }
        std::thread::sleep(std::time::Duration::from_millis(50));
        prune_limiter(&fast);
        prune_limiter(&slow);
        assert_eq!(fast.len(), 0);
        assert_eq!(slow.len(), 50);
    }

    #[test]
    fn auth_limiter_default_is_burst_thirty_and_override_raises_it() {
        assert_eq!(allowed_in_a_row(&auth_limiter(60)), 30);
        assert_eq!(allowed_in_a_row(&auth_limiter(1000)), 500);
    }
}
