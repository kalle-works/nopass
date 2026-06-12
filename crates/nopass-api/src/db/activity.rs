use anyhow::Result;
use chrono::{DateTime, Utc};
use sqlx::{FromRow, PgPool};
use uuid::Uuid;

#[derive(Debug, Clone, FromRow)]
pub struct ActivityEvent {
    pub id: Uuid,
    pub user_id: Uuid,
    pub event_type: String,
    pub ip: Option<String>,
    pub device_id: Option<Uuid>,
    pub created_at: DateTime<Utc>,
}

/// Best-effort: activity logging must never fail the operation it describes.
/// Callers use `let _ = record(...)` semantics via this wrapper.
pub async fn record(pool: &PgPool, user_id: Uuid, event_type: &str, ip: Option<&str>, device_id: Option<Uuid>) {
    let result = sqlx::query(
        "INSERT INTO activity_events (user_id, event_type, ip, device_id) VALUES ($1, $2, $3, $4)",
    )
    .bind(user_id)
    .bind(event_type)
    .bind(ip)
    .bind(device_id)
    .execute(pool)
    .await;

    if let Err(e) = result {
        tracing::warn!("failed to record activity event {event_type}: {e}");
    }
}

pub async fn list_for_user(pool: &PgPool, user_id: Uuid, limit: i64) -> Result<Vec<ActivityEvent>> {
    let events = sqlx::query_as::<_, ActivityEvent>(
        "SELECT * FROM activity_events WHERE user_id = $1 ORDER BY created_at DESC LIMIT $2",
    )
    .bind(user_id)
    .bind(limit)
    .fetch_all(pool)
    .await?;
    Ok(events)
}

/// Retention: drop events older than 90 days. Runs from the cleanup task.
pub async fn prune_old(pool: &PgPool) -> Result<u64> {
    let result = sqlx::query("DELETE FROM activity_events WHERE created_at < NOW() - INTERVAL '90 days'")
        .execute(pool)
        .await?;
    Ok(result.rows_affected())
}
