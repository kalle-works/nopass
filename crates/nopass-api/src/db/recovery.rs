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

pub struct RecoveryCompletion<'a> {
    pub credential: &'a NewCredential,
    pub protected_symmetric_key: &'a [u8],
    pub protected_symmetric_key_iv: &'a [u8],
    pub protected_private_key: Option<&'a str>,
    pub protected_private_key_iv: Option<&'a str>,
    /// None clears the kit: it wraps the old vault keys, so after a password
    /// change it would restore keys that no longer open anything.
    pub recovery_kit: Option<NewRecoveryKit<'a>>,
}

pub struct ReencryptedItemRow {
    pub id: Uuid,
    pub blob: Vec<u8>,
    pub blob_iv: Vec<u8>,
    pub blob_mac: Vec<u8>,
}

/// What authorizes a master-password rotation.
pub enum RotationAuthority {
    /// Recovery: burn the token; every session is revoked.
    RecoveryToken(Uuid),
    /// Password change in a session: that session survives, all others are revoked.
    Session(Uuid),
}

/// Atomically rotate credentials, swap in re-encrypted item blobs, replace or
/// clear the recovery kit, and revoke sessions. All-or-nothing: a
/// half-applied password change would brick the account.
pub async fn rotate_master_password(
    pool: &PgPool,
    authority: RotationAuthority,
    user_id: Uuid,
    completion: RecoveryCompletion<'_>,
    items: &[ReencryptedItemRow],
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

    let (srp_salt, srp_verifier, opaque_record) = match completion.credential {
        NewCredential::Opaque(record) => (None, None, Some(record.as_slice())),
        NewCredential::Srp { salt, verifier } => (Some(salt.as_slice()), Some(verifier.as_slice()), None),
    };

    sqlx::query(
        r#"
        UPDATE users
        SET srp_salt = $2, srp_verifier = $3, opaque_record = $11,
            protected_symmetric_key = $4, protected_symmetric_key_iv = $5,
            protected_private_key = COALESCE($6, protected_private_key),
            protected_private_key_iv = COALESCE($7, protected_private_key_iv),
            recovery_auth_hash = $8, recovery_blob = $9, recovery_blob_iv = $10,
            recovery_updated_at = CASE WHEN $8::BYTEA IS NULL THEN NULL ELSE NOW() END,
            updated_at = NOW()
        WHERE id = $1
        "#,
    )
    .bind(user_id)
    .bind(srp_salt)
    .bind(srp_verifier)
    .bind(completion.protected_symmetric_key)
    .bind(completion.protected_symmetric_key_iv)
    .bind(completion.protected_private_key)
    .bind(completion.protected_private_key_iv)
    .bind(completion.recovery_kit.as_ref().map(|k| k.auth_hash))
    .bind(completion.recovery_kit.as_ref().map(|k| k.blob))
    .bind(completion.recovery_kit.as_ref().map(|k| k.blob_iv))
    .bind(opaque_record)
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
