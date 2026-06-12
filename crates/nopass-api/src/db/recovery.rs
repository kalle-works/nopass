use anyhow::{anyhow, Result};
use sqlx::PgPool;
use uuid::Uuid;

use crate::models::vault::VaultItem;

pub async fn set_recovery(
    pool: &PgPool,
    user_id: Uuid,
    auth_hash: &[u8],
    blob: &[u8],
    blob_iv: &[u8],
) -> Result<()> {
    sqlx::query(
        r#"
        UPDATE users
        SET recovery_auth_hash = $2, recovery_blob = $3, recovery_blob_iv = $4,
            recovery_updated_at = NOW(), updated_at = NOW()
        WHERE id = $1
        "#,
    )
    .bind(user_id)
    .bind(auth_hash)
    .bind(blob)
    .bind(blob_iv)
    .execute(pool)
    .await?;
    Ok(())
}

pub async fn clear_recovery(pool: &PgPool, user_id: Uuid) -> Result<()> {
    sqlx::query(
        r#"
        UPDATE users
        SET recovery_auth_hash = NULL, recovery_blob = NULL, recovery_blob_iv = NULL,
            recovery_updated_at = NULL, updated_at = NOW()
        WHERE id = $1
        "#,
    )
    .bind(user_id)
    .execute(pool)
    .await?;
    Ok(())
}

/// Every item the user owns, including soft-deleted tombstones — those blobs
/// are encrypted with the old keys too and must be re-encrypted on recovery.
pub async fn list_all_items_for_user(pool: &PgPool, user_id: Uuid) -> Result<Vec<VaultItem>> {
    let items =
        sqlx::query_as::<_, VaultItem>("SELECT * FROM vault_items WHERE user_id = $1 ORDER BY updated_at")
            .bind(user_id)
            .fetch_all(pool)
            .await?;
    Ok(items)
}

pub struct RecoveryCompletion<'a> {
    pub srp_salt: &'a [u8],
    pub srp_verifier: &'a [u8],
    pub protected_symmetric_key: &'a [u8],
    pub protected_symmetric_key_iv: &'a [u8],
    pub protected_private_key: Option<&'a str>,
    pub protected_private_key_iv: Option<&'a str>,
    pub recovery_auth_hash: &'a [u8],
    pub recovery_blob: &'a [u8],
    pub recovery_blob_iv: &'a [u8],
}

pub struct ReencryptedItemRow {
    pub id: Uuid,
    pub blob: Vec<u8>,
    pub blob_iv: Vec<u8>,
    pub blob_mac: Vec<u8>,
}

/// Atomically rotate credentials, swap in re-encrypted item blobs, replace the
/// recovery kit, and revoke every session. All-or-nothing: a half-applied
/// password change would brick the account.
pub async fn complete_recovery(
    pool: &PgPool,
    user_id: Uuid,
    completion: RecoveryCompletion<'_>,
    items: &[ReencryptedItemRow],
) -> Result<()> {
    let mut tx = pool.begin().await?;

    sqlx::query(
        r#"
        UPDATE users
        SET srp_salt = $2, srp_verifier = $3,
            protected_symmetric_key = $4, protected_symmetric_key_iv = $5,
            protected_private_key = COALESCE($6, protected_private_key),
            protected_private_key_iv = COALESCE($7, protected_private_key_iv),
            recovery_auth_hash = $8, recovery_blob = $9, recovery_blob_iv = $10,
            recovery_updated_at = NOW(), updated_at = NOW()
        WHERE id = $1
        "#,
    )
    .bind(user_id)
    .bind(completion.srp_salt)
    .bind(completion.srp_verifier)
    .bind(completion.protected_symmetric_key)
    .bind(completion.protected_symmetric_key_iv)
    .bind(completion.protected_private_key)
    .bind(completion.protected_private_key_iv)
    .bind(completion.recovery_auth_hash)
    .bind(completion.recovery_blob)
    .bind(completion.recovery_blob_iv)
    .execute(&mut *tx)
    .await?;

    for item in items {
        let result = sqlx::query(
            r#"
            UPDATE vault_items
            SET blob = $3, blob_iv = $4, blob_mac = $5, version = version + 1, updated_at = NOW()
            WHERE id = $1 AND user_id = $2
            "#,
        )
        .bind(item.id)
        .bind(user_id)
        .bind(&item.blob)
        .bind(&item.blob_iv)
        .bind(&item.blob_mac)
        .execute(&mut *tx)
        .await?;

        if result.rows_affected() == 0 {
            return Err(anyhow!("item {} does not belong to the recovering user", item.id));
        }
    }

    // Old sessions authenticated against the old password — kill them all
    sqlx::query("DELETE FROM sessions WHERE user_id = $1")
        .bind(user_id)
        .execute(&mut *tx)
        .await?;

    tx.commit().await?;
    Ok(())
}
