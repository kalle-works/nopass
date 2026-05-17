use anyhow::Result;
use serde_json::Value;
use sqlx::PgPool;
use uuid::Uuid;

use crate::models::user::User;

pub async fn find_user_by_email_hash(pool: &PgPool, email_hash: &str) -> Result<Option<User>> {
    let user = sqlx::query_as::<_, User>("SELECT * FROM users WHERE email_hash = $1")
        .bind(email_hash)
        .fetch_optional(pool)
        .await?;
    Ok(user)
}

pub async fn create_user(
    pool: &PgPool,
    email_hash: &str,
    srp_salt: &[u8],
    srp_verifier: &[u8],
    kdf_params: Value,
    protected_symmetric_key: &[u8],
    protected_symmetric_key_iv: &[u8],
    public_key: Option<&str>,
    protected_private_key: Option<&str>,
    protected_private_key_iv: Option<&str>,
) -> Result<User> {
    let user = sqlx::query_as::<_, User>(
        r#"
        INSERT INTO users
            (email_hash, srp_salt, srp_verifier, kdf_params,
             protected_symmetric_key, protected_symmetric_key_iv,
             public_key, protected_private_key, protected_private_key_iv)
        VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
        RETURNING *
        "#,
    )
    .bind(email_hash)
    .bind(srp_salt)
    .bind(srp_verifier)
    .bind(kdf_params)
    .bind(protected_symmetric_key)
    .bind(protected_symmetric_key_iv)
    .bind(public_key)
    .bind(protected_private_key)
    .bind(protected_private_key_iv)
    .fetch_one(pool)
    .await?;

    // Create default vault for the new user
    sqlx::query(
        "INSERT INTO vaults (user_id, name_blob, name_iv) VALUES ($1, $2, $3)",
    )
    .bind(user.id)
    .bind(b"default" as &[u8])
    .bind(b"000000000000" as &[u8])
    .execute(pool)
    .await?;

    Ok(user)
}

pub async fn get_user_by_id(pool: &PgPool, user_id: Uuid) -> Result<Option<User>> {
    let user = sqlx::query_as::<_, User>("SELECT * FROM users WHERE id = $1")
        .bind(user_id)
        .fetch_optional(pool)
        .await?;
    Ok(user)
}

pub async fn get_public_key_by_email_hash(
    pool: &PgPool,
    email_hash: &str,
) -> Result<Option<(Uuid, String)>> {
    let row = sqlx::query_as::<_, (Uuid, Option<String>)>(
        "SELECT id, public_key FROM users WHERE email_hash = $1",
    )
    .bind(email_hash)
    .fetch_optional(pool)
    .await?;
    Ok(row.and_then(|(id, pk)| pk.map(|k| (id, k))))
}
