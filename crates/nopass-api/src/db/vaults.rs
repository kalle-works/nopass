use anyhow::Result;
use chrono::{DateTime, Utc};
use sqlx::PgPool;
use uuid::Uuid;

use crate::models::vault::{Vault, VaultItem};

pub async fn list_vaults_for_user(pool: &PgPool, user_id: Uuid) -> Result<Vec<Vault>> {
    let vaults =
        sqlx::query_as::<_, Vault>("SELECT * FROM vaults WHERE user_id = $1 ORDER BY created_at")
            .bind(user_id)
            .fetch_all(pool)
            .await?;
    Ok(vaults)
}

pub async fn get_vault(pool: &PgPool, vault_id: Uuid, user_id: Uuid) -> Result<Option<Vault>> {
    let vault =
        sqlx::query_as::<_, Vault>("SELECT * FROM vaults WHERE id = $1 AND user_id = $2")
            .bind(vault_id)
            .bind(user_id)
            .fetch_optional(pool)
            .await?;
    Ok(vault)
}

pub async fn list_items(
    pool: &PgPool,
    vault_id: Uuid,
    user_id: Uuid,
    since: Option<DateTime<Utc>>,
) -> Result<Vec<VaultItem>> {
    let items = if let Some(since) = since {
        sqlx::query_as::<_, VaultItem>(
            "SELECT * FROM vault_items WHERE vault_id = $1 AND user_id = $2 AND updated_at > $3 ORDER BY updated_at",
        )
        .bind(vault_id)
        .bind(user_id)
        .bind(since)
        .fetch_all(pool)
        .await?
    } else {
        sqlx::query_as::<_, VaultItem>(
            "SELECT * FROM vault_items WHERE vault_id = $1 AND user_id = $2 ORDER BY updated_at",
        )
        .bind(vault_id)
        .bind(user_id)
        .fetch_all(pool)
        .await?
    };
    Ok(items)
}

pub async fn create_item(
    pool: &PgPool,
    vault_id: Uuid,
    user_id: Uuid,
    item_type: &str,
    blob: &[u8],
    blob_iv: &[u8],
    blob_mac: &[u8],
) -> Result<VaultItem> {
    let item = sqlx::query_as::<_, VaultItem>(
        r#"
        INSERT INTO vault_items (vault_id, user_id, item_type, blob, blob_iv, blob_mac)
        VALUES ($1, $2, $3, $4, $5, $6)
        RETURNING *
        "#,
    )
    .bind(vault_id)
    .bind(user_id)
    .bind(item_type)
    .bind(blob)
    .bind(blob_iv)
    .bind(blob_mac)
    .fetch_one(pool)
    .await?;
    Ok(item)
}

pub async fn update_item(
    pool: &PgPool,
    item_id: Uuid,
    user_id: Uuid,
    blob: &[u8],
    blob_iv: &[u8],
    blob_mac: &[u8],
    expected_version: i64,
) -> Result<Option<VaultItem>> {
    let item = sqlx::query_as::<_, VaultItem>(
        r#"
        UPDATE vault_items
        SET blob = $3, blob_iv = $4, blob_mac = $5, version = version + 1, updated_at = NOW()
        WHERE id = $1 AND user_id = $2 AND version = $6
        RETURNING *
        "#,
    )
    .bind(item_id)
    .bind(user_id)
    .bind(blob)
    .bind(blob_iv)
    .bind(blob_mac)
    .bind(expected_version)
    .fetch_optional(pool)
    .await?;
    Ok(item)
}

pub async fn get_current_version(
    pool: &PgPool,
    item_id: Uuid,
    user_id: Uuid,
) -> Result<Option<i64>> {
    let row = sqlx::query_as::<_, (i64,)>(
        "SELECT version FROM vault_items WHERE id = $1 AND user_id = $2",
    )
    .bind(item_id)
    .bind(user_id)
    .fetch_optional(pool)
    .await?;
    Ok(row.map(|(v,)| v))
}

pub async fn soft_delete_item(pool: &PgPool, item_id: Uuid, user_id: Uuid) -> Result<bool> {
    let result = sqlx::query(
        "UPDATE vault_items SET deleted_at = NOW(), updated_at = NOW() WHERE id = $1 AND user_id = $2 AND deleted_at IS NULL",
    )
    .bind(item_id)
    .bind(user_id)
    .execute(pool)
    .await?;
    Ok(result.rows_affected() > 0)
}
