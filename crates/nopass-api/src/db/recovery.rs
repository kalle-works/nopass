use anyhow::Result;
use sqlx::PgPool;
use uuid::Uuid;

use crate::models::vault::VaultItem;

/// Typed failure for recovery completion — the route maps ItemMismatch to a
/// fixed 400 (no internal IDs leaked) and Db to a 500.
#[derive(Debug)]
pub enum CompleteRecoveryError {
    ItemMismatch,
    /// Token was already consumed by a concurrent completion — replay refused
    TokenConsumed,
    Db(anyhow::Error),
}

impl From<sqlx::Error> for CompleteRecoveryError {
    fn from(e: sqlx::Error) -> Self {
        CompleteRecoveryError::Db(e.into())
    }
}

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

/// The login credential for the new master password.
pub enum NewCredential {
    Opaque(Vec<u8>),
    /// From clients that predate OPAQUE; migrates on the next login.
    Srp { salt: Vec<u8>, verifier: Vec<u8> },
}

/// Replacement recovery kit for the new keys.
pub struct NewRecoveryKit<'a> {
    pub auth_hash: &'a [u8],
    pub blob: &'a [u8],
    pub blob_iv: &'a [u8],
}

pub struct ReencryptedItemRow {
    pub id: Uuid,
    pub blob: Vec<u8>,
    pub blob_iv: Vec<u8>,
    pub blob_mac: Vec<u8>,
}

/// What a master-password rotation writes. `None` fields keep the stored value.
pub struct PasswordRotation<'a> {
    pub credential: &'a NewCredential,
    pub protected_symmetric_key: Option<(&'a [u8], &'a [u8])>,
    pub protected_private_key: Option<(&'a str, &'a str)>,
    /// The account key wrapped under the new password's KEK
    pub wrapped_account_key: Option<(&'a [u8], &'a [u8])>,
    /// The kit wraps the account key, so it survives a password change; a
    /// recovery burns the used code and brings a replacement.
    pub recovery_kit: Option<NewRecoveryKit<'a>>,
    /// Legacy recovery from clients that predate the account key: every item
    /// re-encrypted under the new password's keys.
    pub reencrypted_items: Option<&'a [ReencryptedItemRow]>,
}

/// What authorizes a master-password rotation.
pub enum RotationAuthority {
    /// Recovery: burn the token; every session is revoked.
    RecoveryToken(Uuid),
    /// Password change in a session: that session survives, all others are revoked.
    Session(Uuid),
}

/// Atomically rotate the login credential and key wraps, optionally swap in
/// re-encrypted items, and revoke sessions. All-or-nothing: a half-applied
/// password change would brick the account.
pub async fn rotate_master_password(
    pool: &PgPool,
    authority: RotationAuthority,
    user_id: Uuid,
    rotation: PasswordRotation<'_>,
) -> std::result::Result<(), CompleteRecoveryError> {
    let mut tx = pool.begin().await?;

    // Consume the token INSIDE the transaction: a concurrent completion
    // serializes on this row and sees zero rows (replay refused), while a
    // failed transaction rolls the delete back, keeping the token retryable.
    if let RotationAuthority::RecoveryToken(token) = authority {
        let consumed = sqlx::query("DELETE FROM pending_recovery_sessions WHERE token = $1")
            .bind(token)
            .execute(&mut *tx)
            .await?;
        if consumed.rows_affected() == 0 {
            return Err(CompleteRecoveryError::TokenConsumed);
        }
    }

    let (srp_salt, srp_verifier, opaque_record) = match rotation.credential {
        NewCredential::Opaque(record) => (None, None, Some(record.as_slice())),
        NewCredential::Srp { salt, verifier } => (Some(salt.as_slice()), Some(verifier.as_slice()), None),
    };
    let kit = rotation.recovery_kit.as_ref();

    sqlx::query(
        r#"
        UPDATE users
        SET srp_salt = $2, srp_verifier = $3, opaque_record = $4,
            protected_symmetric_key = COALESCE($5, protected_symmetric_key),
            protected_symmetric_key_iv = COALESCE($6, protected_symmetric_key_iv),
            protected_private_key = COALESCE($7, protected_private_key),
            protected_private_key_iv = COALESCE($8, protected_private_key_iv),
            wrapped_account_key = COALESCE($9, wrapped_account_key),
            wrapped_account_key_iv = COALESCE($10, wrapped_account_key_iv),
            recovery_auth_hash = COALESCE($11, recovery_auth_hash),
            recovery_blob = COALESCE($12, recovery_blob),
            recovery_blob_iv = COALESCE($13, recovery_blob_iv),
            recovery_updated_at = CASE WHEN $11::BYTEA IS NULL THEN recovery_updated_at ELSE NOW() END,
            updated_at = NOW()
        WHERE id = $1
        "#,
    )
    .bind(user_id)
    .bind(srp_salt)
    .bind(srp_verifier)
    .bind(opaque_record)
    .bind(rotation.protected_symmetric_key.map(|k| k.0))
    .bind(rotation.protected_symmetric_key.map(|k| k.1))
    .bind(rotation.protected_private_key.map(|k| k.0))
    .bind(rotation.protected_private_key.map(|k| k.1))
    .bind(rotation.wrapped_account_key.map(|k| k.0))
    .bind(rotation.wrapped_account_key.map(|k| k.1))
    .bind(kit.map(|k| k.auth_hash))
    .bind(kit.map(|k| k.blob))
    .bind(kit.map(|k| k.blob_iv))
    .execute(&mut *tx)
    .await?;

    if let Some(items) = rotation.reencrypted_items {
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
                return Err(CompleteRecoveryError::ItemMismatch);
            }
        }

        // Every item must have been re-encrypted: one left under the old keys
        // (or created concurrently) would be unreadable after the commit.
        let (total,): (i64,) = sqlx::query_as("SELECT COUNT(*) FROM vault_items WHERE user_id = $1")
            .bind(user_id)
            .fetch_one(&mut *tx)
            .await?;
        if total != items.len() as i64 {
            return Err(CompleteRecoveryError::ItemMismatch);
        }
    }

    // Sessions authenticated against the old password are revoked
    let keep_session = match authority {
        RotationAuthority::Session(id) => Some(id),
        RotationAuthority::RecoveryToken(_) => None,
    };
    sqlx::query("DELETE FROM sessions WHERE user_id = $1 AND id IS DISTINCT FROM $2")
        .bind(user_id)
        .bind(keep_session)
        .execute(&mut *tx)
        .await?;

    tx.commit().await?;
    Ok(())
}
