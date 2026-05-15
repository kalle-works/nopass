use anyhow::Result;
use sqlx::PgPool;
use uuid::Uuid;

use crate::models::device::Device;

pub async fn create_device(
    pool: &PgPool,
    user_id: Uuid,
    device_name: &str,
    device_type: &str,
    device_public_key: &[u8],
    protected_device_key: Option<&[u8]>,
    protected_device_key_iv: Option<&[u8]>,
) -> Result<Device> {
    let device = sqlx::query_as::<_, Device>(
        r#"
        INSERT INTO devices
            (user_id, device_name, device_type, device_public_key,
             protected_device_key, protected_device_key_iv)
        VALUES ($1, $2, $3, $4, $5, $6)
        RETURNING *
        "#,
    )
    .bind(user_id)
    .bind(device_name)
    .bind(device_type)
    .bind(device_public_key)
    .bind(protected_device_key)
    .bind(protected_device_key_iv)
    .fetch_one(pool)
    .await?;
    Ok(device)
}

pub async fn list_devices_for_user(pool: &PgPool, user_id: Uuid) -> Result<Vec<Device>> {
    let devices =
        sqlx::query_as::<_, Device>("SELECT * FROM devices WHERE user_id = $1 ORDER BY created_at")
            .bind(user_id)
            .fetch_all(pool)
            .await?;
    Ok(devices)
}

pub async fn delete_device(pool: &PgPool, device_id: Uuid, user_id: Uuid) -> Result<bool> {
    let result = sqlx::query("DELETE FROM devices WHERE id = $1 AND user_id = $2")
        .bind(device_id)
        .bind(user_id)
        .execute(pool)
        .await?;
    Ok(result.rows_affected() > 0)
}

pub async fn touch_device(pool: &PgPool, device_id: Uuid) -> Result<()> {
    sqlx::query("UPDATE devices SET last_seen_at = NOW() WHERE id = $1")
        .bind(device_id)
        .execute(pool)
        .await?;
    Ok(())
}
