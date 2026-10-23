mod helpers;

use axum::http::StatusCode;
use base64::{engine::general_purpose::STANDARD as B64, Engine};
use helpers::{build_test_server, login, register_user};
use nopass_api::db::sessions;
use serde_json::{json, Value};
use sqlx::PgPool;
use uuid::Uuid;

fn item_body(id: Option<Uuid>, fill: u8) -> Value {
    json!({
        "id": id,
        "itemType": "login",
        "blob": B64.encode([fill; 48]),
        "blobIv": B64.encode([0xad; 12]),
        "blobMac": B64.encode([0xbe; 32]),
    })
}

async fn user_id(pool: &PgPool, email: &str) -> Uuid {
    sqlx::query_scalar("SELECT id FROM users WHERE email_hash = $1")
        .bind(helpers::stored_account_key(email))
        .fetch_one(pool)
        .await
        .unwrap()
}

#[sqlx::test(migrations = "src/db/migrations")]
async fn other_users_cannot_update_or_delete_my_item(pool: PgPool) {
    let server = build_test_server(pool.clone());
    register_user(&server, "a@example.com", "password").await;
    register_user(&server, "b@example.com", "password").await;
    let a = login(&server, "a@example.com", "password").await;
    let b = login(&server, "b@example.com", "password").await;

    let created: Value = server
        .post(&format!("/v1/vaults/{}/items", a.default_vault_id))
        .authorization_bearer(&a.session_token)
        .json(&item_body(None, 0xde))
        .await
        .json();
    let item_id = created["id"].as_str().unwrap().to_string();
    let url_for = |vault: Uuid| format!("/v1/vaults/{vault}/items/{item_id}");

    // B names A's vault, and also B's own vault, with A's item id
    for vault in [a.default_vault_id, b.default_vault_id] {
        server
            .put(&url_for(vault))
            .authorization_bearer(&b.session_token)
            .json(&json!({
                "blob": B64.encode([0x66; 48]),
                "blobIv": B64.encode([0xad; 12]),
                "blobMac": B64.encode([0xbe; 32]),
                "version": 1,
            }))
            .await
            .assert_status(StatusCode::NOT_FOUND);
        server
            .delete(&url_for(vault))
            .authorization_bearer(&b.session_token)
            .await
            .assert_status(StatusCode::NOT_FOUND);
    }

    // A's item is untouched: same ciphertext, version 1, not deleted
    let listed: Vec<Value> = server
        .get(&format!("/v1/vaults/{}/items", a.default_vault_id))
        .authorization_bearer(&a.session_token)
        .await
        .json();
    let item = listed.iter().find(|i| i["id"] == item_id.as_str()).expect("item still listed");
    assert_eq!(item["blob"], B64.encode([0xde; 48]));
    assert_eq!(item["version"], 1);
    assert!(item["deletedAt"].is_null());
}

#[sqlx::test(migrations = "src/db/migrations")]
async fn other_users_cannot_revoke_my_device(pool: PgPool) {
    let server = build_test_server(pool.clone());
    register_user(&server, "a@example.com", "password").await;
    register_user(&server, "b@example.com", "password").await;
    let a = login(&server, "a@example.com", "password").await;
    let b = login(&server, "b@example.com", "password").await;

    let registered: Value = server
        .post("/v1/devices")
        .authorization_bearer(&a.session_token)
        .json(&json!({
            "deviceName": "a-laptop",
            "deviceType": "desktop_mac",
            "devicePublicKey": B64.encode([7u8; 32]),
        }))
        .await
        .json();
    let device_id: Uuid = registered["deviceId"].as_str().unwrap().parse().unwrap();
    let device_token = sessions::create_session(&pool, user_id(&pool, "a@example.com").await, Some(device_id))
        .await
        .unwrap();

    server
        .delete(&format!("/v1/devices/{device_id}"))
        .authorization_bearer(&b.session_token)
        .await
        .assert_status(StatusCode::NOT_FOUND);

    // The device is still registered and its session still works
    let devices: Vec<Value> = server
        .get("/v1/devices")
        .authorization_bearer(&a.session_token)
        .await
        .json();
    assert!(devices.iter().any(|d| d["id"] == device_id.to_string()));
    server
        .get("/v1/devices")
        .authorization_bearer(&device_token)
        .await
        .assert_status(StatusCode::OK);

    // And B's device list never shows A's device
    let b_devices: Vec<Value> = server
        .get("/v1/devices")
        .authorization_bearer(&b.session_token)
        .await
        .json();
    assert!(b_devices.is_empty());
}

#[sqlx::test(migrations = "src/db/migrations")]
async fn item_ids_are_scoped_per_user(pool: PgPool) {
    let server = build_test_server(pool);
    register_user(&server, "a@example.com", "password").await;
    register_user(&server, "b@example.com", "password").await;
    let a = login(&server, "a@example.com", "password").await;
    let b = login(&server, "b@example.com", "password").await;
    let shared_id = Uuid::new_v4();

    server
        .post(&format!("/v1/vaults/{}/items", a.default_vault_id))
        .authorization_bearer(&a.session_token)
        .json(&item_body(Some(shared_id), 0xde))
        .await
        .assert_status(StatusCode::CREATED);

    // B choosing the same id neither fails nor learns that A holds it
    server
        .post(&format!("/v1/vaults/{}/items", b.default_vault_id))
        .authorization_bearer(&b.session_token)
        .json(&item_body(Some(shared_id), 0x11))
        .await
        .assert_status(StatusCode::CREATED);

    // A reusing its own id is still a conflict
    server
        .post(&format!("/v1/vaults/{}/items", a.default_vault_id))
        .authorization_bearer(&a.session_token)
        .json(&item_body(Some(shared_id), 0xde))
        .await
        .assert_status(StatusCode::CONFLICT);
}
