// Each test binary compiles the shared helpers on its own and uses a subset
#[allow(dead_code)]
mod helpers;

use std::path::Path;

use base64::{engine::general_purpose::STANDARD as B64, Engine};
use nopass_models::{EncryptedVaultItem, KdfParams, UpdateVaultItemRequest};
use sqlx::{migrate::Migrator, PgPool};
use uuid::Uuid;

use helpers::{build_test_server, compute_email_hash, generate_srp_verifier, login};

const EMAIL: &str = "veteran@example.com";
const PASSWORD: &str = "a password from the last release";

/// Production has accounts created under the last release's schema. Applying
/// this release's migrations on top must keep those accounts able to log in
/// and keep their items readable and writable.
///
/// The old schema comes from the migration files of the last release tag
/// (UPGRADE_FROM_MIGRATIONS_DIR); scripts/migration-upgrade-test.sh extracts
/// them and runs this test. The seed statements below use only columns that
/// exist in that schema, so they stay valid as the schema moves on.
#[sqlx::test(migrations = false)]
#[ignore = "needs UPGRADE_FROM_MIGRATIONS_DIR, run by scripts/migration-upgrade-test.sh"]
async fn accounts_and_items_from_the_last_release_survive_the_upgrade(pool: PgPool) {
    let old_migrations = std::env::var("UPGRADE_FROM_MIGRATIONS_DIR")
        .expect("UPGRADE_FROM_MIGRATIONS_DIR must point at the last release's migrations");
    Migrator::new(Path::new(&old_migrations))
        .await
        .unwrap()
        .run(&pool)
        .await
        .unwrap();

    let (salt, verifier) = generate_srp_verifier(EMAIL, PASSWORD);
    let user_id: Uuid = sqlx::query_scalar(
        "INSERT INTO users (email_hash, srp_salt, srp_verifier, kdf_params, protected_symmetric_key, protected_symmetric_key_iv)
         VALUES ($1, $2, $3, $4, $5, $6) RETURNING id",
    )
    .bind(compute_email_hash(EMAIL))
    .bind(salt)
    .bind(verifier)
    .bind(serde_json::to_value(KdfParams::default()).unwrap())
    .bind(vec![0x11u8; 48])
    .bind(vec![0x22u8; 12])
    .fetch_one(&pool)
    .await
    .unwrap();
    let vault_id: Uuid = sqlx::query_scalar(
        "INSERT INTO vaults (user_id, name_blob, name_iv) VALUES ($1, $2, $3) RETURNING id",
    )
    .bind(user_id)
    .bind(vec![0x33u8; 32])
    .bind(vec![0x44u8; 12])
    .fetch_one(&pool)
    .await
    .unwrap();
    let item_blob = vec![0xdeu8; 48];
    let item_id: Uuid = sqlx::query_scalar(
        "INSERT INTO vault_items (vault_id, user_id, item_type, blob, blob_iv, blob_mac)
         VALUES ($1, $2, 'login', $3, $4, $5) RETURNING id",
    )
    .bind(vault_id)
    .bind(user_id)
    .bind(&item_blob)
    .bind(vec![0xadu8; 12])
    .bind(vec![0xbeu8; 32])
    .fetch_one(&pool)
    .await
    .unwrap();

    sqlx::migrate!("src/db/migrations").run(&pool).await.unwrap();

    let server = build_test_server(pool);
    let session = login(&server, EMAIL, PASSWORD).await;
    assert_eq!(session.user_id, user_id);
    assert_eq!(session.default_vault_id, vault_id);

    let items: Vec<EncryptedVaultItem> = server
        .get(&format!("/v1/vaults/{vault_id}/items"))
        .authorization_bearer(&session.session_token)
        .await
        .json();
    assert_eq!(items.len(), 1);
    assert_eq!(items[0].id, item_id);
    assert_eq!(items[0].blob, B64.encode(&item_blob));

    server
        .put(&format!("/v1/vaults/{vault_id}/items/{item_id}"))
        .authorization_bearer(&session.session_token)
        .json(&UpdateVaultItemRequest {
            blob: B64.encode([0xcau8; 48]),
            blob_iv: B64.encode([0xfeu8; 12]),
            blob_mac: B64.encode([0xbau8; 32]),
            version: items[0].version,
        })
        .await
        .assert_status_ok();
}
