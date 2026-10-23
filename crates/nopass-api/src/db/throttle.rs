use anyhow::Result;
use chrono::{DateTime, Utc};
use sqlx::PgPool;

/// Backoff schedule for one throttle key: `free` unsuccessful starts, then a
/// lock of `base_secs` doubling per further start, capped at `max_secs`.
#[derive(Debug, Clone, Copy)]
pub struct Policy {
    pub free: i32,
    pub base_secs: i64,
    pub max_secs: i64,
}

/// Per (account, client network): what one attacker location gets. Clients
/// fall back from OPAQUE to SRP on failure while SRP accounts remain, so one
/// wrong password can cost two attempts.
pub const PER_NETWORK: Policy = Policy { free: 10, base_secs: 30, max_secs: 15 * 60 };
/// Per account across all networks: a much higher ceiling, so a stranger on
/// one network can't lock the owner out, while a distributed guesser still
/// hits a wall.
pub const PER_ACCOUNT: Policy = Policy { free: 100, base_secs: 60, max_secs: 60 * 60 };

/// An account with no attempts for this long starts from zero again.
const DECAY_SECS: i64 = 24 * 60 * 60;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Attempt {
    /// Proceed; `failures` counts unsuccessful starts including this one.
    Allowed { failures: i32 },
    Locked { retry_after_secs: i64 },
}

fn lock_secs(policy: Policy, failures: i32) -> Option<i64> {
    let over = failures - policy.free;
    if over < 0 {
        return None;
    }
    Some(policy.base_secs.saturating_mul(1i64 << over.min(30)).min(policy.max_secs))
}

/// Count a login (or registration) start against the account. Every start is
/// presumed failed until `reset` is called on success.
pub async fn record_attempt(pool: &PgPool, key: &str, policy: Policy) -> Result<Attempt> {
    let mut tx = pool.begin().await?;

    sqlx::query(
        "INSERT INTO login_throttle (account_key, failures) VALUES ($1, 0) ON CONFLICT DO NOTHING",
    )
    .bind(key)
    .execute(&mut *tx)
    .await?;

    let (failures, locked_until, updated_at) =
        sqlx::query_as::<_, (i32, Option<DateTime<Utc>>, DateTime<Utc>)>(
            "SELECT failures, locked_until, updated_at FROM login_throttle WHERE account_key = $1 FOR UPDATE",
        )
        .bind(key)
        .fetch_one(&mut *tx)
        .await?;

    let now = Utc::now();
    if let Some(until) = locked_until.filter(|until| *until > now) {
        tx.commit().await?;
        return Ok(Attempt::Locked {
            retry_after_secs: (until - now).num_seconds().max(1),
        });
    }

    let failures = if (now - updated_at).num_seconds() > DECAY_SECS { 1 } else { failures + 1 };
    let locked_until = lock_secs(policy, failures).map(|secs| now + chrono::Duration::seconds(secs));

    sqlx::query(
        "UPDATE login_throttle SET failures = $2, locked_until = $3, updated_at = NOW() WHERE account_key = $1",
    )
    .bind(key)
    .bind(failures)
    .bind(locked_until)
    .execute(&mut *tx)
    .await?;
    tx.commit().await?;

    // The attempt that trips the lock still goes through; the next one waits.
    Ok(Attempt::Allowed { failures })
}

pub async fn reset(pool: &PgPool, keys: &[&str]) -> Result<()> {
    sqlx::query("DELETE FROM login_throttle WHERE account_key = ANY($1)")
        .bind(keys)
        .execute(pool)
        .await?;
    Ok(())
}

/// A network the account has logged in from before. Expires after a quarter
/// without a successful login from it.
const TRUSTED_NETWORK_TTL_SECS: i64 = 90 * 24 * 60 * 60;

pub async fn is_trusted_network(pool: &PgPool, account_key: &str, network_hash: &str) -> Result<bool> {
    let trusted = sqlx::query_scalar::<_, bool>(
        r#"
        SELECT EXISTS (
            SELECT 1 FROM trusted_login_networks
            WHERE account_key = $1 AND network_hash = $2
              AND last_success_at > NOW() - ($3 * INTERVAL '1 second'))
        "#,
    )
    .bind(account_key)
    .bind(network_hash)
    .bind(TRUSTED_NETWORK_TTL_SECS)
    .fetch_one(pool)
    .await?;
    Ok(trusted)
}

pub async fn trust_network(pool: &PgPool, account_key: &str, network_hash: &str) -> Result<()> {
    sqlx::query(
        r#"
        INSERT INTO trusted_login_networks (account_key, network_hash) VALUES ($1, $2)
        ON CONFLICT (account_key, network_hash) DO UPDATE SET last_success_at = NOW()
        "#,
    )
    .bind(account_key)
    .bind(network_hash)
    .execute(pool)
    .await?;
    Ok(())
}

pub async fn prune_stale(pool: &PgPool) -> Result<u64> {
    let result = sqlx::query(
        r#"
        DELETE FROM login_throttle
        WHERE updated_at < NOW() - ($1 * INTERVAL '1 second')
          AND (locked_until IS NULL OR locked_until < NOW())
        "#,
    )
    .bind(DECAY_SECS)
    .execute(pool)
    .await?;
    let trusted = sqlx::query("DELETE FROM trusted_login_networks WHERE last_success_at < NOW() - ($1 * INTERVAL '1 second')")
        .bind(TRUSTED_NETWORK_TTL_SECS)
        .execute(pool)
        .await?;
    Ok(result.rows_affected() + trusted.rows_affected())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn backoff_starts_at_threshold_doubles_and_caps() {
        let p = PER_NETWORK;
        assert_eq!(lock_secs(p, p.free - 1), None);
        assert_eq!(lock_secs(p, p.free), Some(p.base_secs));
        assert_eq!(lock_secs(p, p.free + 1), Some(2 * p.base_secs));
        assert_eq!(lock_secs(p, p.free + 100), Some(p.max_secs));
    }
}
