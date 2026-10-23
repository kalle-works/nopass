use anyhow::Result;
use serde_json::Value;
use sqlx::PgPool;
use uuid::Uuid;

use crate::models::user::User;

// `account_key` throughout is the keyed email hash (AppState::account_key),
// never the client's raw email hash.

pub async fn find_user_by_account_key(pool: &PgPool, account_key: &str) -> Result<Option<User>> {
    let user = sqlx::query_as::<_, User>(
        "SELECT * FROM users WHERE email_hash = $1 AND email_hash_keyed",
    )
    .bind(account_key)
    .fetch_optional(pool)
    .await?;
    Ok(user)
}

pub struct NewUser<'a> {
    pub account_key: &'a str,
    pub opaque_record: &'a [u8],
    pub kdf_params: Value,
    pub protected_symmetric_key: &'a [u8],
    pub protected_symmetric_key_iv: &'a [u8],
    pub public_key: Option<&'a str>,
    pub protected_private_key: Option<&'a str>,
    pub protected_private_key_iv: Option<&'a str>,
}

/// Create an OPAQUE-only account and its default vault. Returns `None` if the
/// account key is already taken.
pub async fn create_user(pool: &PgPool, new: NewUser<'_>) -> Result<Option<User>> {
    let mut tx = pool.begin().await?;

    let user = sqlx::query_as::<_, User>(
        r#"
        INSERT INTO users
            (email_hash, email_hash_keyed, opaque_record, kdf_params,
             protected_symmetric_key, protected_symmetric_key_iv,
             public_key, protected_private_key, protected_private_key_iv)
        VALUES ($1, TRUE, $2, $3, $4, $5, $6, $7, $8)
        ON CONFLICT (email_hash) DO NOTHING
        RETURNING *
        "#,
    )
    .bind(new.account_key)
    .bind(new.opaque_record)
    .bind(new.kdf_params)
    .bind(new.protected_symmetric_key)
    .bind(new.protected_symmetric_key_iv)
    .bind(new.public_key)
    .bind(new.protected_private_key)
    .bind(new.protected_private_key_iv)
    .fetch_optional(&mut *tx)
    .await?;

    let Some(user) = user else {
        return Ok(None);
    };

    sqlx::query(
        "INSERT INTO vaults (user_id, name_blob, name_iv) VALUES ($1, $2, $3)",
    )
    .bind(user.id)
    .bind(b"default" as &[u8])
    .bind(b"000000000000" as &[u8])
    .execute(&mut *tx)
    .await?;

    tx.commit().await?;
    Ok(Some(user))
}

/// Store a new OPAQUE record and drop any SRP verifier in the same write: after
/// this the account is OPAQUE-only and the brute-forceable verifier is gone.
pub async fn set_opaque_record(pool: &PgPool, user_id: Uuid, record: &[u8]) -> Result<()> {
    sqlx::query(
        r#"
        UPDATE users
        SET opaque_record = $2, srp_salt = NULL, srp_verifier = NULL, updated_at = NOW()
        WHERE id = $1
        "#,
    )
    .bind(user_id)
    .bind(record)
    .execute(pool)
    .await?;
    Ok(())
}

/// Rewrite raw client email hashes (pre-OPAQUE rows, or rows written by an
/// older replica during a rolling deploy) into keyed account keys. Idempotent
/// and safe to race: each row is only rewritten while still unkeyed.
pub async fn key_email_hashes(pool: &PgPool, key: impl Fn(&str) -> String) -> Result<u64> {
    let rows = sqlx::query_as::<_, (Uuid, String)>(
        "SELECT id, email_hash FROM users WHERE NOT email_hash_keyed",
    )
    .fetch_all(pool)
    .await?;

    let mut keyed = 0;
    for (id, email_hash) in rows {
        keyed += sqlx::query(
            "UPDATE users SET email_hash = $2, email_hash_keyed = TRUE WHERE id = $1 AND NOT email_hash_keyed",
        )
        .bind(id)
        .bind(key(&email_hash))
        .execute(pool)
        .await?
        .rows_affected();
    }
    Ok(keyed)
}

pub async fn get_user_by_id(pool: &PgPool, user_id: Uuid) -> Result<Option<User>> {
    let user = sqlx::query_as::<_, User>("SELECT * FROM users WHERE id = $1")
        .bind(user_id)
        .fetch_optional(pool)
        .await?;
    Ok(user)
}

pub async fn get_public_key_by_account_key(
    pool: &PgPool,
    account_key: &str,
) -> Result<Option<(Uuid, String)>> {
    let row = sqlx::query_as::<_, (Uuid, Option<String>)>(
        "SELECT id, public_key FROM users WHERE email_hash = $1 AND email_hash_keyed",
    )
    .bind(account_key)
    .fetch_optional(pool)
    .await?;
    Ok(row.and_then(|(id, pk)| pk.map(|k| (id, k))))
}
