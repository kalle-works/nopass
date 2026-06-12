mod helpers;

use axum::http::StatusCode;
use base64::{engine::general_purpose::STANDARD as B64, Engine};
use helpers::{build_test_server, login, register_user};
use nopass_models::{CreateVaultItemRequest, EncryptedVaultItem, VaultInfo, VaultItemType};
use rand::RngCore;
use serde_json::json;
use sqlx::PgPool;

const EMAIL: &str = "vaults@example.com";
const PASSWORD: &str = "correct horse battery staple";

fn random_b64(len: usize) -> String {
    let mut bytes = vec![0u8; len];
    rand::thread_rng().fill_bytes(&mut bytes);
    B64.encode(&bytes)
}

fn name_body() -> serde_json::Value {
    json!({ "nameBlob": random_b64(24), "nameIv": random_b64(12) })
}

#[sqlx::test(migrations = "src/db/migrations")]
async fn vaults_list_create_rename(pool: PgPool) {
    let server = build_test_server(pool);
    register_user(&server, EMAIL, PASSWORD).await;
    let session = login(&server, EMAIL, PASSWORD).await;

    // Registration creates one default vault
    let vaults: Vec<VaultInfo> = server
        .get("/v1/vaults")
        .authorization_bearer(&session.session_token)
        .await
        .json();
    assert_eq!(vaults.len(), 1);

    let created: VaultInfo = server
        .post("/v1/vaults")
        .authorization_bearer(&session.session_token)
        .json(&name_body())
        .await
        .json();

    let vaults: Vec<VaultInfo> = server
        .get("/v1/vaults")
        .authorization_bearer(&session.session_token)
        .await
        .json();
    assert_eq!(vaults.len(), 2);

    server
        .put(&format!("/v1/vaults/{}", created.id))
        .authorization_bearer(&session.session_token)
        .json(&name_body())
        .await
        .assert_status(StatusCode::NO_CONTENT);
}

#[sqlx::test(migrations = "src/db/migrations")]
async fn vault_delete_rules(pool: PgPool) {
    let server = build_test_server(pool);
    register_user(&server, EMAIL, PASSWORD).await;
    let session = login(&server, EMAIL, PASSWORD).await;

    // Cannot delete the only vault
    server
        .delete(&format!("/v1/vaults/{}", session.default_vault_id))
        .authorization_bearer(&session.session_token)
        .await
        .assert_status(StatusCode::CONFLICT);

    let second: VaultInfo = server
        .post("/v1/vaults")
        .authorization_bearer(&session.session_token)
        .json(&name_body())
        .await
        .json();

    // Non-empty vaults refuse deletion
    let item: EncryptedVaultItem = server
        .post(&format!("/v1/vaults/{}/items", second.id))
        .authorization_bearer(&session.session_token)
        .json(&CreateVaultItemRequest {
            item_type: VaultItemType::Note,
            blob: random_b64(64),
            blob_iv: random_b64(12),
            blob_mac: random_b64(32),
        })
        .await
        .json();

    server
        .delete(&format!("/v1/vaults/{}", second.id))
        .authorization_bearer(&session.session_token)
        .await
        .assert_status(StatusCode::CONFLICT);

    // Move the item out, then deletion succeeds
    server
        .post(&format!("/v1/vaults/{}/items/{}/move", second.id, item.id))
        .authorization_bearer(&session.session_token)
        .json(&json!({ "toVaultId": session.default_vault_id }))
        .await
        .assert_status(StatusCode::NO_CONTENT);

    server
        .delete(&format!("/v1/vaults/{}", second.id))
        .authorization_bearer(&session.session_token)
        .await
        .assert_status(StatusCode::NO_CONTENT);

    // The moved item lives in the default vault with a bumped version
    let items: Vec<EncryptedVaultItem> = server
        .get(&format!("/v1/vaults/{}/items", session.default_vault_id))
        .authorization_bearer(&session.session_token)
        .await
        .json();
    assert_eq!(items.len(), 1);
    assert_eq!(items[0].version, item.version + 1);
}

#[sqlx::test(migrations = "src/db/migrations")]
async fn vault_move_rejects_foreign_destination(pool: PgPool) {
    let server = build_test_server(pool);
    register_user(&server, EMAIL, PASSWORD).await;
    register_user(&server, "other@example.com", PASSWORD).await;
    let owner = login(&server, EMAIL, PASSWORD).await;
    let other = login(&server, "other@example.com", PASSWORD).await;

    let item: EncryptedVaultItem = server
        .post(&format!("/v1/vaults/{}/items", owner.default_vault_id))
        .authorization_bearer(&owner.session_token)
        .json(&CreateVaultItemRequest {
            item_type: VaultItemType::Note,
            blob: random_b64(64),
            blob_iv: random_b64(12),
            blob_mac: random_b64(32),
        })
        .await
        .json();

    // Moving into another user's vault must fail
    server
        .post(&format!("/v1/vaults/{}/items/{}/move", owner.default_vault_id, item.id))
        .authorization_bearer(&owner.session_token)
        .json(&json!({ "toVaultId": other.default_vault_id }))
        .await
        .assert_status(StatusCode::NOT_FOUND);

    // Another user can't move my items either
    server
        .post(&format!("/v1/vaults/{}/items/{}/move", owner.default_vault_id, item.id))
        .authorization_bearer(&other.session_token)
        .json(&json!({ "toVaultId": other.default_vault_id }))
        .await
        .assert_status(StatusCode::NOT_FOUND);
}
