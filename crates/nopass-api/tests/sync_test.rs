mod helpers;

use axum::http::StatusCode;
use axum_test::TestServer;
use base64::{engine::general_purpose::STANDARD as B64, Engine};
use chrono::Utc;
use nopass_models::{RegisterDeviceRequest, SyncCheckpoint, SyncEvent, SyncEventType, SyncRequest, SyncResponse};
use sqlx::PgPool;
use uuid::Uuid;

use helpers::{build_test_server, login, register_user};

async fn register_device(server: &TestServer, token: &str) -> Uuid {
    let resp: serde_json::Value = server
        .post("/v1/devices")
        .authorization_bearer(token)
        .json(&RegisterDeviceRequest {
            device_name: "test device".into(),
            device_type: "web".into(),
            device_public_key: B64.encode([7u8; 32]),
            protected_device_key: None,
            protected_device_key_iv: None,
        })
        .await
        .json();
    resp["deviceId"].as_str().unwrap().parse().unwrap()
}

fn event(user_id: Uuid, device_id: Uuid, sequence_number: i64) -> SyncEvent {
    SyncEvent {
        id: Uuid::new_v4(),
        user_id,
        device_id,
        sequence_number,
        event_type: SyncEventType::Upsert,
        item_id: Uuid::new_v4(),
        encrypted_delta: Some(B64.encode([1u8; 16])),
        delta_iv: Some(B64.encode([2u8; 12])),
        created_at: Utc::now(),
    }
}

async fn pull(server: &TestServer, token: &str, checkpoints: Vec<SyncCheckpoint>) -> SyncResponse {
    server
        .post("/v1/sync")
        .authorization_bearer(token)
        .json(&SyncRequest { known_checkpoints: checkpoints })
        .await
        .json()
}

// A client that retries a push after a timeout, or two tabs flushing the same
// outbox, must not duplicate events: the (device, sequence) pair is the identity.
#[sqlx::test(migrations = "src/db/migrations")]
async fn concurrent_pushes_of_the_same_events_store_each_once(pool: PgPool) {
    let server = build_test_server(pool);
    register_user(&server, "alice@example.com", "password").await;
    let session = login(&server, "alice@example.com", "password").await;
    let device_id = register_device(&server, &session.session_token).await;

    let batch: Vec<SyncEvent> = (1..=5).map(|n| event(session.user_id, device_id, n)).collect();
    let push = || async {
        server
            .post("/v1/sync/events")
            .authorization_bearer(&session.session_token)
            .json(&batch)
            .await
            .status_code()
    };
    let (a, b, c) = tokio::join!(push(), push(), push());
    assert_eq!((a, b, c), (StatusCode::OK, StatusCode::OK, StatusCode::OK));

    let pulled = pull(&server, &session.session_token, vec![]).await;
    assert_eq!(pulled.events.len(), 5);
    assert_eq!(pulled.server_clock[&device_id.to_string()], 5);
}

#[sqlx::test(migrations = "src/db/migrations")]
async fn pull_returns_only_events_past_the_checkpoint(pool: PgPool) {
    let server = build_test_server(pool);
    register_user(&server, "alice@example.com", "password").await;
    let session = login(&server, "alice@example.com", "password").await;
    let device_id = register_device(&server, &session.session_token).await;

    let batch: Vec<SyncEvent> = (1..=4).map(|n| event(session.user_id, device_id, n)).collect();
    server
        .post("/v1/sync/events")
        .authorization_bearer(&session.session_token)
        .json(&batch)
        .await
        .assert_status_ok();

    let pulled = pull(
        &server,
        &session.session_token,
        vec![SyncCheckpoint { device_id, last_synced_sequence: 2 }],
    )
    .await;
    let sequences: Vec<i64> = pulled.events.iter().map(|e| e.sequence_number).collect();
    assert_eq!(sequences, vec![3, 4]);
}

#[sqlx::test(migrations = "src/db/migrations")]
async fn sync_never_crosses_accounts(pool: PgPool) {
    let server = build_test_server(pool);
    register_user(&server, "alice@example.com", "password").await;
    register_user(&server, "bob@example.com", "password").await;
    let alice = login(&server, "alice@example.com", "password").await;
    let bob = login(&server, "bob@example.com", "password").await;
    let alice_device = register_device(&server, &alice.session_token).await;

    server
        .post("/v1/sync/events")
        .authorization_bearer(&alice.session_token)
        .json(&vec![event(alice.user_id, alice_device, 1)])
        .await
        .assert_status_ok();

    // Bob cannot read Alice's events, with or without naming her device
    assert!(pull(&server, &bob.session_token, vec![]).await.events.is_empty());
    let named = pull(
        &server,
        &bob.session_token,
        vec![SyncCheckpoint { device_id: alice_device, last_synced_sequence: 0 }],
    )
    .await;
    assert!(named.events.is_empty());

    // Bob cannot write events under Alice's user id
    server
        .post("/v1/sync/events")
        .authorization_bearer(&bob.session_token)
        .json(&vec![event(alice.user_id, alice_device, 2)])
        .await
        .assert_status(StatusCode::UNAUTHORIZED);
}
