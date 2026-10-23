use anyhow::Result;
use chrono::{DateTime, Utc};
use sqlx::PgPool;

/// Login starts allowed per account before backoff kicks in. Clients fall back
/// from OPAQUE to SRP on failure while SRP accounts remain, so one wrong
/// password can cost two attempts.
pub const FREE_ATTEMPTS: i32 = 10;
/// First lockout; doubles with every further unsuccessful start.
const BASE_LOCK_SECS: i64 = 30;
/// Cap, so someone who only knows the address can delay but not shut out the
/// owner for long.
const MAX_LOCK_SECS: i64 = 15 * 60;
/// An account with no attempts for this long starts from zero again.
const DECAY_SECS: i64 = 24 * 60 * 60;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Attempt {
    /// Proceed; `failures` counts unsuccessful starts including this one.
    Allowed { failures: i32 },
    Locked { retry_after_secs: i64 },
}

fn lock_secs(failures: i32) -> Option<i64> {
    let over = failures - FREE_ATTEMPTS;
    if over < 0 {
        return None;
    }
    Some(BASE_LOCK_SECS.saturating_mul(1i64 << over.min(30)).min(MAX_LOCK_SECS))
}

/// Count a login (or registration) start against the account. Every start is
/// presumed failed until `reset` is called on success.
pub async fn record_attempt(pool: &PgPool, account_key: &str) -> Result<Attempt> {
    let mut tx = pool.begin().await?;

    sqlx::query(
        "INSERT INTO login_throttle (account_key, failures) VALUES ($1, 0) ON CONFLICT DO NOTHING",
    )
    .bind(account_key)
    .execute(&mut *tx)
    .await?;

    let (failures, locked_until, updated_at) =
        sqlx::query_as::<_, (i32, Option<DateTime<Utc>>, DateTime<Utc>)>(
            "SELECT failures, locked_until, updated_at FROM login_throttle WHERE account_key = $1 FOR UPDATE",
        )
        .bind(account_key)
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
    let locked_until = lock_secs(failures).map(|secs| now + chrono::Duration::seconds(secs));

    sqlx::query(
        "UPDATE login_throttle SET failures = $2, locked_until = $3, updated_at = NOW() WHERE account_key = $1",
    )
    .bind(account_key)
    .bind(failures)
    .bind(locked_until)
    .execute(&mut *tx)
    .await?;
    tx.commit().await?;

    // The attempt that trips the lock still goes through; the next one waits.
    Ok(Attempt::Allowed { failures })
}

pub async fn reset(pool: &PgPool, account_key: &str) -> Result<()> {
    sqlx::query("DELETE FROM login_throttle WHERE account_key = $1")
        .bind(account_key)
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
    Ok(result.rows_affected())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn backoff_starts_at_threshold_doubles_and_caps() {
        assert_eq!(lock_secs(FREE_ATTEMPTS - 1), None);
        assert_eq!(lock_secs(FREE_ATTEMPTS), Some(BASE_LOCK_SECS));
        assert_eq!(lock_secs(FREE_ATTEMPTS + 1), Some(2 * BASE_LOCK_SECS));
        assert_eq!(lock_secs(FREE_ATTEMPTS + 100), Some(MAX_LOCK_SECS));
    }
}
