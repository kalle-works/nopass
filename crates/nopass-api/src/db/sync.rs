use anyhow::Result;
use sqlx::PgPool;
use uuid::Uuid;

use crate::models::vault::SyncEvent;

pub async fn push_sync_events(pool: &PgPool, events: &[SyncEvent]) -> Result<()> {
    for event in events {
        sqlx::query(
            r#"
            INSERT INTO sync_events
                (id, user_id, device_id, sequence_number, event_type, item_id,
                 encrypted_delta, delta_iv, created_at)
            VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
            ON CONFLICT (device_id, sequence_number) DO NOTHING
            "#,
        )
        .bind(event.id)
        .bind(event.user_id)
        .bind(event.device_id)
        .bind(event.sequence_number)
        .bind(&event.event_type)
        .bind(event.item_id)
        .bind(event.encrypted_delta.as_deref())
        .bind(event.delta_iv.as_deref())
        .bind(event.created_at)
        .execute(pool)
        .await?;
    }
    Ok(())
}

/// Return events after the per-device checkpoints the client has seen.
pub async fn pull_sync_events(
    pool: &PgPool,
    user_id: Uuid,
    checkpoints: &[(Uuid, i64)],
) -> Result<Vec<SyncEvent>> {
    let mut all_events: Vec<SyncEvent> = Vec::new();

    for (device_id, last_seq) in checkpoints {
        let events = sqlx::query_as::<_, SyncEvent>(
            r#"
            SELECT * FROM sync_events
            WHERE user_id = $1 AND device_id = $2 AND sequence_number > $3
            ORDER BY sequence_number
            "#,
        )
        .bind(user_id)
        .bind(device_id)
        .bind(last_seq)
        .fetch_all(pool)
        .await?;
        all_events.extend(events);
    }

    if !checkpoints.is_empty() {
        let known_device_ids: Vec<Uuid> = checkpoints.iter().map(|(id, _)| *id).collect();
        let events = sqlx::query_as::<_, SyncEvent>(
            r#"
            SELECT * FROM sync_events
            WHERE user_id = $1 AND device_id != ALL($2)
            ORDER BY sequence_number
            "#,
        )
        .bind(user_id)
        .bind(&known_device_ids)
        .fetch_all(pool)
        .await?;
        all_events.extend(events);
    } else {
        let events = sqlx::query_as::<_, SyncEvent>(
            "SELECT * FROM sync_events WHERE user_id = $1 ORDER BY sequence_number",
        )
        .bind(user_id)
        .fetch_all(pool)
        .await?;
        all_events.extend(events);
    }

    Ok(all_events)
}

pub async fn get_vector_clock(pool: &PgPool, user_id: Uuid) -> Result<Vec<(Uuid, i64)>> {
    let rows = sqlx::query_as::<_, (Uuid, i64)>(
        r#"
        SELECT device_id, MAX(sequence_number)
        FROM sync_events
        WHERE user_id = $1
        GROUP BY device_id
        "#,
    )
    .bind(user_id)
    .fetch_all(pool)
    .await?;
    Ok(rows)
}
