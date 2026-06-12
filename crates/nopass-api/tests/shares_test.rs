mod helpers;

use axum::http::StatusCode;
use base64::{engine::general_purpose::STANDARD as B64, Engine};
use helpers::{build_test_server, login, register_user};
use nopass_models::{CreateShareResponse, ShareInfo, ViewShareResponse};
use rand::RngCore;
use serde_json::json;
use sqlx::PgPool;

const EMAIL: &str = "sharer@example.com";
const PASSWORD: &str = "correct horse battery staple";

fn random_b64(len: usize) -> String {
    let mut bytes = vec![0u8; len];
    rand::thread_rng().fill_bytes(&mut bytes);
    B64.encode(&bytes)
}

fn share_body(max_views: i32, expires_in_hours: i32) -> serde_json::Value {
    json!({
        "blob": random_b64(128),
        "blobIv": random_b64(12),
        "labelBlob": random_b64(32),
        "labelIv": random_b64(12),
        "maxViews": max_views,
        "expiresInHours": expires_in_hours,
    })
}

#[sqlx::test(migrations = "src/db/migrations")]
async fn share_create_view_exhaust(pool: PgPool) {
    let server = build_test_server(pool);
    register_user(&server, EMAIL, PASSWORD).await;
    let session = login(&server, EMAIL, PASSWORD).await;

    let body = share_body(2, 24);
    let created: CreateShareResponse = server
        .post("/v1/shares")
        .authorization_bearer(&session.session_token)
        .json(&body)
        .await
        .json();

    // First view succeeds without any authentication
    let view: ViewShareResponse = server
        .post(&format!("/v1/shares/{}/view", created.share_id))
        .await
        .json();
    assert_eq!(view.blob, body["blob"].as_str().unwrap());
    assert_eq!(view.remaining_views, 1);

    // Second view exhausts it
    let view2: ViewShareResponse = server
        .post(&format!("/v1/shares/{}/view", created.share_id))
        .await
        .json();
    assert_eq!(view2.remaining_views, 0);

    // Third view: gone
    server
        .post(&format!("/v1/shares/{}/view", created.share_id))
        .await
        .assert_status(StatusCode::NOT_FOUND);
}

#[sqlx::test(migrations = "src/db/migrations")]
async fn share_list_and_revoke(pool: PgPool) {
    let server = build_test_server(pool);
    register_user(&server, EMAIL, PASSWORD).await;
    let session = login(&server, EMAIL, PASSWORD).await;

    let created: CreateShareResponse = server
        .post("/v1/shares")
        .authorization_bearer(&session.session_token)
        .json(&share_body(1, 24))
        .await
        .json();

    let shares: Vec<ShareInfo> = server
        .get("/v1/shares")
        .authorization_bearer(&session.session_token)
        .await
        .json();
    assert_eq!(shares.len(), 1);
    assert_eq!(shares[0].id, created.share_id);
    assert_eq!(shares[0].view_count, 0);

    server
        .delete(&format!("/v1/shares/{}", created.share_id))
        .authorization_bearer(&session.session_token)
        .await
        .assert_status(StatusCode::NO_CONTENT);

    // Revoked share no longer resolves
    server
        .post(&format!("/v1/shares/{}/view", created.share_id))
        .await
        .assert_status(StatusCode::NOT_FOUND);
}

#[sqlx::test(migrations = "src/db/migrations")]
async fn share_cannot_revoke_someone_elses(pool: PgPool) {
    let server = build_test_server(pool);
    register_user(&server, EMAIL, PASSWORD).await;
    register_user(&server, "other@example.com", PASSWORD).await;
    let owner = login(&server, EMAIL, PASSWORD).await;
    let other = login(&server, "other@example.com", PASSWORD).await;

    let created: CreateShareResponse = server
        .post("/v1/shares")
        .authorization_bearer(&owner.session_token)
        .json(&share_body(1, 24))
        .await
        .json();

    server
        .delete(&format!("/v1/shares/{}", created.share_id))
        .authorization_bearer(&other.session_token)
        .await
        .assert_status(StatusCode::NOT_FOUND);

    // Still resolves — the other user's delete did nothing
    server
        .post(&format!("/v1/shares/{}/view", created.share_id))
        .await
        .assert_status(StatusCode::OK);
}

#[sqlx::test(migrations = "src/db/migrations")]
async fn share_validates_limits(pool: PgPool) {
    let server = build_test_server(pool);
    register_user(&server, EMAIL, PASSWORD).await;
    let session = login(&server, EMAIL, PASSWORD).await;

    for body in [share_body(0, 24), share_body(11, 24), share_body(1, 0), share_body(1, 169)] {
        server
            .post("/v1/shares")
            .authorization_bearer(&session.session_token)
            .json(&body)
            .await
            .assert_status(StatusCode::BAD_REQUEST);
    }

    // Anonymous creation is rejected
    server
        .post("/v1/shares")
        .json(&share_body(1, 24))
        .await
        .assert_status(StatusCode::UNAUTHORIZED);
}
