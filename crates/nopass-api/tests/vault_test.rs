mod helpers;

use axum::http::StatusCode;
use base64::{engine::general_purpose::STANDARD as B64, Engine};
use nopass_models::{CreateVaultItemRequest, UpdateVaultItemRequest, VaultItemType};
use sqlx::PgPool;
use uuid::Uuid;

use helpers::{build_test_server, login, register_user};

fn fake_blob() -> (String, String, String) {
    (B64.encode(&[0xde; 48]), B64.encode(&[0xad; 12]), B64.encode(&[0xbe; 32]))
}

// ─── Create item ──────────────────────────────────────────────────────────────

#[sqlx::test(migrations = "src/db/migrations")]
async fn create_item_returns_201(pool: PgPool) {
    let server = build_test_server(pool);
    register_user(&server, "alice@example.com", "password").await;
    let session = login(&server, "alice@example.com", "password").await;

    let (blob, blob_iv, blob_mac) = fake_blob();
    let req = CreateVaultItemRequest {
        item_type: VaultItemType::Login,
        blob,
        blob_iv,
        blob_mac,
    };

    let resp = server
        .post(&format!("/v1/vaults/{}/items", session.default_vault_id))
        .authorization_bearer(&session.session_token)
        .json(&req)
        .await;

    resp.assert_status(StatusCode::CREATED);
    let body: serde_json::Value = resp.json();
    assert!(body["id"].as_str().is_some());
    assert_eq!(body["itemType"].as_str(), Some("login"));
    assert_eq!(body["version"].as_i64(), Some(1));
    assert!(body["deletedAt"].is_null());
}

#[sqlx::test(migrations = "src/db/migrations")]
async fn create_item_requires_auth(pool: PgPool) {
    let server = build_test_server(pool);
    register_user(&server, "alice@example.com", "password").await;
    let session = login(&server, "alice@example.com", "password").await;

    let (blob, blob_iv, blob_mac) = fake_blob();
    let req = CreateVaultItemRequest { item_type: VaultItemType::Login, blob, blob_iv, blob_mac };

    server
        .post(&format!("/v1/vaults/{}/items", session.default_vault_id))
        // No auth header
        .json(&req)
        .await
        .assert_status(StatusCode::UNAUTHORIZED);
}

// ─── List items ───────────────────────────────────────────────────────────────

#[sqlx::test(migrations = "src/db/migrations")]
async fn list_items_returns_created_items(pool: PgPool) {
    let server = build_test_server(pool);
    register_user(&server, "alice@example.com", "password").await;
    let session = login(&server, "alice@example.com", "password").await;

    let vault_id = session.default_vault_id;
    let (blob, blob_iv, blob_mac) = fake_blob();

    // Create 2 items
    for _ in 0..2 {
        server
            .post(&format!("/v1/vaults/{vault_id}/items"))
            .authorization_bearer(&session.session_token)
            .json(&CreateVaultItemRequest {
                item_type: VaultItemType::Login,
                blob: blob.clone(),
                blob_iv: blob_iv.clone(),
                blob_mac: blob_mac.clone(),
            })
            .await
            .assert_status(StatusCode::CREATED);
    }

    let resp = server
        .get(&format!("/v1/vaults/{vault_id}/items"))
        .authorization_bearer(&session.session_token)
        .await;

    resp.assert_status_ok();
    let items: Vec<serde_json::Value> = resp.json();
    assert_eq!(items.len(), 2);
}

#[sqlx::test(migrations = "src/db/migrations")]
async fn list_items_cannot_access_other_users_vault(pool: PgPool) {
    let server = build_test_server(pool);

    register_user(&server, "alice@example.com", "password").await;
    register_user(&server, "bob@example.com", "password").await;

    let alice = login(&server, "alice@example.com", "password").await;
    let bob = login(&server, "bob@example.com", "password").await;

    // Bob tries to access Alice's vault
    server
        .get(&format!("/v1/vaults/{}/items", alice.default_vault_id))
        .authorization_bearer(&bob.session_token)
        .await
        .assert_status(StatusCode::NOT_FOUND);
}

// ─── Update item ──────────────────────────────────────────────────────────────

#[sqlx::test(migrations = "src/db/migrations")]
async fn update_item_increments_version(pool: PgPool) {
    let server = build_test_server(pool);
    register_user(&server, "alice@example.com", "password").await;
    let session = login(&server, "alice@example.com", "password").await;
    let vault_id = session.default_vault_id;

    let (blob, blob_iv, blob_mac) = fake_blob();
    let create_resp: serde_json::Value = server
        .post(&format!("/v1/vaults/{vault_id}/items"))
        .authorization_bearer(&session.session_token)
        .json(&CreateVaultItemRequest {
            item_type: VaultItemType::Login,
            blob: blob.clone(),
            blob_iv: blob_iv.clone(),
            blob_mac: blob_mac.clone(),
        })
        .await
        .json();

    let item_id = create_resp["id"].as_str().unwrap();
    let version = create_resp["version"].as_i64().unwrap();

    let update_resp: serde_json::Value = server
        .put(&format!("/v1/vaults/{vault_id}/items/{item_id}"))
        .authorization_bearer(&session.session_token)
        .json(&UpdateVaultItemRequest {
            blob: blob.clone(),
            blob_iv: blob_iv.clone(),
            blob_mac: blob_mac.clone(),
            version,
        })
        .await
        .json();

    assert_eq!(update_resp["version"].as_i64(), Some(version + 1));
}

#[sqlx::test(migrations = "src/db/migrations")]
async fn update_item_optimistic_locking_conflict_returns_409(pool: PgPool) {
    let server = build_test_server(pool);
    register_user(&server, "alice@example.com", "password").await;
    let session = login(&server, "alice@example.com", "password").await;
    let vault_id = session.default_vault_id;

    let (blob, blob_iv, blob_mac) = fake_blob();
    let create_resp: serde_json::Value = server
        .post(&format!("/v1/vaults/{vault_id}/items"))
        .authorization_bearer(&session.session_token)
        .json(&CreateVaultItemRequest {
            item_type: VaultItemType::Login,
            blob: blob.clone(),
            blob_iv: blob_iv.clone(),
            blob_mac: blob_mac.clone(),
        })
        .await
        .json();

    let item_id = create_resp["id"].as_str().unwrap();
    let version = create_resp["version"].as_i64().unwrap();

    // First update succeeds
    server
        .put(&format!("/v1/vaults/{vault_id}/items/{item_id}"))
        .authorization_bearer(&session.session_token)
        .json(&UpdateVaultItemRequest { blob: blob.clone(), blob_iv: blob_iv.clone(), blob_mac: blob_mac.clone(), version })
        .await
        .assert_status_ok();

    // Second update with stale version (still version=1) should 409
    server
        .put(&format!("/v1/vaults/{vault_id}/items/{item_id}"))
        .authorization_bearer(&session.session_token)
        .json(&UpdateVaultItemRequest { blob, blob_iv, blob_mac, version }) // stale version
        .await
        .assert_status(StatusCode::CONFLICT);
}

// ─── Delete item ──────────────────────────────────────────────────────────────

#[sqlx::test(migrations = "src/db/migrations")]
async fn delete_item_soft_deletes_and_returns_no_content(pool: PgPool) {
    let server = build_test_server(pool);
    register_user(&server, "alice@example.com", "password").await;
    let session = login(&server, "alice@example.com", "password").await;
    let vault_id = session.default_vault_id;

    let (blob, blob_iv, blob_mac) = fake_blob();
    let create_resp: serde_json::Value = server
        .post(&format!("/v1/vaults/{vault_id}/items"))
        .authorization_bearer(&session.session_token)
        .json(&CreateVaultItemRequest { item_type: VaultItemType::Login, blob, blob_iv, blob_mac })
        .await
        .json();

    let item_id = create_resp["id"].as_str().unwrap();

    // Delete
    server
        .delete(&format!("/v1/vaults/{vault_id}/items/{item_id}"))
        .authorization_bearer(&session.session_token)
        .await
        .assert_status(StatusCode::NO_CONTENT);

    // Item should still appear in list but with deletedAt set (soft delete)
    let items: Vec<serde_json::Value> = server
        .get(&format!("/v1/vaults/{vault_id}/items"))
        .authorization_bearer(&session.session_token)
        .await
        .json();

    let deleted_item = items.iter().find(|i| i["id"].as_str() == Some(item_id));
    assert!(deleted_item.is_some(), "soft-deleted item should still appear in list");
    assert!(
        !deleted_item.unwrap()["deletedAt"].is_null(),
        "deletedAt should be set after soft delete",
    );
}

#[sqlx::test(migrations = "src/db/migrations")]
async fn delete_nonexistent_item_returns_404(pool: PgPool) {
    let server = build_test_server(pool);
    register_user(&server, "alice@example.com", "password").await;
    let session = login(&server, "alice@example.com", "password").await;

    server
        .delete(&format!("/v1/vaults/{}/items/{}", session.default_vault_id, Uuid::new_v4()))
        .authorization_bearer(&session.session_token)
        .await
        .assert_status(StatusCode::NOT_FOUND);
}
