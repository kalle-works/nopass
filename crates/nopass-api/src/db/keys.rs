use anyhow::Result;
use sqlx::{FromRow, PgPool};
use uuid::Uuid;

/// A user's public key material as published to other users.
#[derive(Debug, FromRow)]
pub struct KeyBundle {
    pub user_id: Uuid,
    pub public_key: String,
    pub identity_public_key: Option<String>,
    pub public_key_signature: Option<String>,
}

const BUNDLE_COLUMNS: &str =
    "id AS user_id, public_key, identity_public_key, public_key_signature";

/// `account_key` is the keyed email hash (AppState::account_key).
pub async fn get_bundle_by_account_key(pool: &PgPool, account_key: &str) -> Result<Option<KeyBundle>> {
    let bundle = sqlx::query_as::<_, KeyBundle>(&format!(
        "SELECT {BUNDLE_COLUMNS} FROM users WHERE email_hash = $1 AND email_hash_keyed AND public_key IS NOT NULL"
    ))
    .bind(account_key)
    .fetch_optional(pool)
    .await?;
    Ok(bundle)
}

pub async fn get_bundle(pool: &PgPool, user_id: Uuid) -> Result<Option<KeyBundle>> {
    let bundle = sqlx::query_as::<_, KeyBundle>(&format!(
        "SELECT {BUNDLE_COLUMNS} FROM users WHERE id = $1 AND public_key IS NOT NULL"
    ))
    .bind(user_id)
    .fetch_optional(pool)
    .await?;
    Ok(bundle)
}

pub async fn get_vault_format_marker(pool: &PgPool, user_id: Uuid) -> Result<Option<String>> {
    let marker = sqlx::query_scalar::<_, Option<String>>("SELECT vault_format_marker FROM users WHERE id = $1")
        .bind(user_id)
        .fetch_one(pool)
        .await?;
    Ok(marker)
}

pub async fn set_vault_format_marker(pool: &PgPool, user_id: Uuid, marker: &str) -> Result<()> {
    sqlx::query("UPDATE users SET vault_format_marker = $2 WHERE id = $1")
        .bind(user_id)
        .bind(marker)
        .execute(pool)
        .await?;
    Ok(())
}

pub enum SetIdentityOutcome {
    Stored,
    /// The same identity was already stored — a retried migration is harmless.
    Unchanged,
    /// A different identity is already stored; it is never replaced.
    Conflict,
    /// The user has no RSA public key to vouch for yet.
    NoPublicKey,
}

/// Store the user's identity key once. It is write-once so a stolen session
/// cannot swap it and re-sign a substituted RSA key.
pub async fn set_identity(
    pool: &PgPool,
    user_id: Uuid,
    identity_public_key: &str,
    public_key_signature: &str,
) -> Result<SetIdentityOutcome> {
    let stored = sqlx::query(
        r#"UPDATE users
           SET identity_public_key = $2, public_key_signature = $3
           WHERE id = $1 AND public_key IS NOT NULL AND identity_public_key IS NULL"#,
    )
    .bind(user_id)
    .bind(identity_public_key)
    .bind(public_key_signature)
    .execute(pool)
    .await?
    .rows_affected();
    if stored == 1 {
        return Ok(SetIdentityOutcome::Stored);
    }

    let existing = get_bundle(pool, user_id).await?;
    Ok(match existing {
        None => SetIdentityOutcome::NoPublicKey,
        Some(b) if b.identity_public_key.as_deref() == Some(identity_public_key) => SetIdentityOutcome::Unchanged,
        Some(_) => SetIdentityOutcome::Conflict,
    })
}
