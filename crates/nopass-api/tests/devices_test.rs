mod helpers;

use axum::http::StatusCode;
use base64::{engine::general_purpose::STANDARD as B64, Engine};
use chrono::Utc;
use helpers::{build_test_server, login, register_user};
use nopass_api::db::sessions;
use serde_json::json;
use sqlx::PgPool;
use uuid::Uuid;

async fn register_device(server: &axum_test::TestServer, token: &str, name: &str) -> Uuid {
    let resp: serde_json::Value = server
        .post("/v1/devices")
        .authorization_bearer(token)
        .json(&json!({
            "deviceName": name,
            "deviceType": "desktop_mac",
            "devicePublicKey": B64.encode([7u8; 32]),
        }))
        .await
        .json();
    resp["deviceId"].as_str().unwrap().parse().unwrap()
}

async fn user_id(pool: &PgPool, email_hash_of: &str) -> Uuid {
    let hash = helpers::compute_email_hash(email_hash_of);
    sqlx::query_scalar("SELECT id FROM users WHERE email_hash = $1")
        .bind(hash)
        .fetch_one(pool)
        .await
        .unwrap()
}

#[sqlx::test(migrations = "src/db/migrations")]
async fn revoking_a_device_ends_its_sessions(pool: PgPool) {
    let server = build_test_server(pool.clone());
    register_user(&server, "dev@example.com", "password").await;
    let main = login(&server, "dev@example.com", "password").await;
    let device_id = register_device(&server, &main.session_token, "laptop").await;
    let uid = user_id(&pool, "dev@example.com").await;
    let device_token = sessions::create_session(&pool, uid, Some(device_id)).await.unwrap();

    server
        .get("/v1/devices")
        .authorization_bearer(&device_token)
        .await
        .assert_status(StatusCode::OK);

    server
        .delete(&format!("/v1/devices/{device_id}"))
        .authorization_bearer(&main.session_token)
        .await
        .assert_status(StatusCode::NO_CONTENT);

    server
        .get("/v1/devices")
        .authorization_bearer(&device_token)
        .await
        .assert_status(StatusCode::UNAUTHORIZED);
    // The revoker's own session is untouched
    server
        .get("/v1/devices")
        .authorization_bearer(&main.session_token)
        .await
        .assert_status(StatusCode::OK);
}

#[sqlx::test(migrations = "src/db/migrations")]
async fn sign_out_others_keeps_only_the_callers_session(pool: PgPool) {
    let server = build_test_server(pool.clone());
    register_user(&server, "dev@example.com", "password").await;
    let current = login(&server, "dev@example.com", "password").await;
    let other = login(&server, "dev@example.com", "password").await;

    server
        .post("/v1/devices/sign-out-others")
        .authorization_bearer(&current.session_token)
        .await
        .assert_status(StatusCode::OK);

    server
        .get("/v1/devices")
        .authorization_bearer(&other.session_token)
        .await
        .assert_status(StatusCode::UNAUTHORIZED);
    server
        .get("/v1/devices")
        .authorization_bearer(&current.session_token)
        .await
        .assert_status(StatusCode::OK);
}

#[sqlx::test(migrations = "src/db/migrations")]
async fn sync_push_rejects_foreign_device_and_oversize_batches(pool: PgPool) {
    let server = build_test_server(pool.clone());
    register_user(&server, "alice@example.com", "password").await;
    register_user(&server, "bob@example.com", "password").await;
    let alice = login(&server, "alice@example.com", "password").await;
    let bob = login(&server, "bob@example.com", "password").await;
    let alice_device = register_device(&server, &alice.session_token, "alice-laptop").await;
    let bob_device = register_device(&server, &bob.session_token, "bob-laptop").await;

    let event = |user: Uuid, device: Uuid, seq: i64| {
        json!({
            "id": Uuid::new_v4(),
            "userId": user,
            "deviceId": device,
            "sequenceNumber": seq,
            "eventType": "upsert",
            "itemId": Uuid::new_v4(),
            "encryptedDelta": B64.encode([1u8; 32]),
            "deltaIv": B64.encode([2u8; 12]),
            "createdAt": Utc::now(),
        })
    };

    // Alice's own device is accepted
    server
        .post("/v1/sync/events")
        .authorization_bearer(&alice.session_token)
        .json(&json!([event(alice.user_id, alice_device, 1)]))
        .await
        .assert_status(StatusCode::OK);

    // Bob's device_id in Alice's push is rejected, nothing is written
    server
        .post("/v1/sync/events")
        .authorization_bearer(&alice.session_token)
        .json(&json!([event(alice.user_id, bob_device, 1)]))
        .await
        .assert_status(StatusCode::FORBIDDEN);
    let written: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM sync_events WHERE device_id = $1")
        .bind(bob_device)
        .fetch_one(&pool)
        .await
        .unwrap();
    assert_eq!(written, 0);

    // Batch cap
    let too_many: Vec<_> = (0..501).map(|i| event(alice.user_id, alice_device, 100 + i)).collect();
    server
        .post("/v1/sync/events")
        .authorization_bearer(&alice.session_token)
        .json(&too_many)
        .await
        .assert_status(StatusCode::BAD_REQUEST);

    // Oversize delta
    let mut big = event(alice.user_id, alice_device, 2);
    big["encryptedDelta"] = json!(B64.encode(vec![0u8; 64 * 1024 + 1]));
    server
        .post("/v1/sync/events")
        .authorization_bearer(&alice.session_token)
        .json(&json!([big]))
        .await
        .assert_status(StatusCode::BAD_REQUEST);
}
