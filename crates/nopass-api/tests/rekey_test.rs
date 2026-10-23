mod helpers;

use helpers::{
    build_test_server, compute_email_hash, generate_srp_verifier, register_user, srp_login_ok, stored_account_key,
    test_kdf, EMAIL_LOOKUP_KEY,
};
use nopass_api::{db::auth::key_email_hashes, state::account_key};
use sqlx::PgPool;
use uuid::Uuid;

/// A row as an API replica from the previous release writes it during a
/// rolling deploy: SRP verifier, the client's raw email hash, unkeyed.
async fn insert_raw(pool: &PgPool, email: &str, password: &str) -> Uuid {
    let (salt, verifier) = generate_srp_verifier(email, password);
    let (id,): (Uuid,) = sqlx::query_as(
        r#"
        INSERT INTO users (email_hash, srp_salt, srp_verifier, kdf_params, protected_symmetric_key, protected_symmetric_key_iv)
        VALUES ($1, $2, $3, $4, '\x00', '\x00') RETURNING id
        "#,
    )
    .bind(compute_email_hash(email))
    .bind(&salt)
    .bind(&verifier)
    .bind(serde_json::to_value(test_kdf()).unwrap())
    .fetch_one(pool)
    .await
    .unwrap();
    sqlx::query("INSERT INTO vaults (user_id, name_blob, name_iv) VALUES ($1, 'd', '000000000000')")
        .bind(id)
        .execute(pool)
        .await
        .unwrap();
    id
}

async fn keyed(pool: &PgPool, id: Uuid) -> bool {
    sqlx::query_scalar("SELECT email_hash_keyed FROM users WHERE id = $1").bind(id).fetch_one(pool).await.unwrap()
}

/// Before the rekey reaches it, an old replica's row is still found by login.
#[sqlx::test(migrations = "src/db/migrations")]
async fn an_unkeyed_row_still_logs_in(pool: PgPool) {
    let server = build_test_server(pool.clone());
    insert_raw(&pool, "late@example.com", "pw").await;
    srp_login_ok(&server, "late@example.com", "pw").await;
}

/// An old replica registering an address that already has a keyed account
/// must not stop the rekey: that row is skipped for a manual merge, the
/// others are keyed, and the keyed account keeps working.
#[sqlx::test(migrations = "src/db/migrations")]
async fn a_duplicate_raw_row_is_skipped_not_fatal(pool: PgPool) {
    let server = build_test_server(pool.clone());
    register_user(&server, "dup@example.com", "pw").await;
    let duplicate = insert_raw(&pool, "dup@example.com", "other").await;
    let other = insert_raw(&pool, "fine@example.com", "pw").await;

    let n = key_email_hashes(&pool, |h| account_key(&EMAIL_LOOKUP_KEY, h)).await.unwrap();
    assert_eq!(n, 1);
    assert!(!keyed(&pool, duplicate).await);
    assert!(keyed(&pool, other).await);

    let owner: Uuid = sqlx::query_scalar("SELECT id FROM users WHERE email_hash = $1")
        .bind(stored_account_key("dup@example.com"))
        .fetch_one(&pool)
        .await
        .unwrap();
    assert_eq!(helpers::login(&server, "dup@example.com", "pw").await.user_id, owner);
}
