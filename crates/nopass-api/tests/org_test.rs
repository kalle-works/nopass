mod helpers;

use axum::http::StatusCode;
use base64::{engine::general_purpose::STANDARD as B64, Engine};
use helpers::{build_test_server, login, register_user};
use sqlx::PgPool;

// ─── Create org ───────────────────────────────────────────────────────────────

#[sqlx::test(migrations = "src/db/migrations")]
async fn create_org_returns_201(pool: PgPool) {
    let server = build_test_server(pool);
    register_user(&server, "alice@example.com", "password").await;
    let session = login(&server, "alice@example.com", "password").await;

    let resp = server
        .post("/v1/organizations")
        .authorization_bearer(&session.session_token)
        .json(&serde_json::json!({
            "name": "Acme Corp",
            "publicKey": B64.encode(&[0u8; 256]),
            "protectedPrivateKey": B64.encode(&[0u8; 64]),
            "protectedPrivateKeyIv": B64.encode(&[0u8; 12]),
            "encryptedOrgKey": B64.encode(&[0u8; 64]),
        }))
        .await;

    resp.assert_status(StatusCode::CREATED);
    let body: serde_json::Value = resp.json();
    assert_eq!(body["name"].as_str().unwrap(), "Acme Corp");
    assert_eq!(body["role"].as_str().unwrap(), "owner");
    assert_eq!(body["memberCount"].as_i64().unwrap(), 1);
}

#[sqlx::test(migrations = "src/db/migrations")]
async fn create_org_requires_auth(pool: PgPool) {
    let server = build_test_server(pool);

    server
        .post("/v1/organizations")
        .json(&serde_json::json!({ "name": "Test" }))
        .await
        .assert_status(StatusCode::UNAUTHORIZED);
}

#[sqlx::test(migrations = "src/db/migrations")]
async fn create_org_rejects_empty_name(pool: PgPool) {
    let server = build_test_server(pool);
    register_user(&server, "alice@example.com", "password").await;
    let session = login(&server, "alice@example.com", "password").await;

    server
        .post("/v1/organizations")
        .authorization_bearer(&session.session_token)
        .json(&serde_json::json!({
            "name": "   ",
            "publicKey": B64.encode(&[0u8; 256]),
            "protectedPrivateKey": B64.encode(&[0u8; 64]),
            "protectedPrivateKeyIv": B64.encode(&[0u8; 12]),
            "encryptedOrgKey": B64.encode(&[0u8; 64]),
        }))
        .await
        .assert_status(StatusCode::BAD_REQUEST);
}

// ─── List orgs ────────────────────────────────────────────────────────────────

#[sqlx::test(migrations = "src/db/migrations")]
async fn list_orgs_returns_created_org(pool: PgPool) {
    let server = build_test_server(pool);
    register_user(&server, "alice@example.com", "password").await;
    let session = login(&server, "alice@example.com", "password").await;

    // Create an org
    server
        .post("/v1/organizations")
        .authorization_bearer(&session.session_token)
        .json(&serde_json::json!({
            "name": "My Team",
            "publicKey": B64.encode(&[0u8; 256]),
            "protectedPrivateKey": B64.encode(&[0u8; 64]),
            "protectedPrivateKeyIv": B64.encode(&[0u8; 12]),
            "encryptedOrgKey": B64.encode(&[0u8; 64]),
        }))
        .await
        .assert_status(StatusCode::CREATED);

    let resp = server
        .get("/v1/organizations")
        .authorization_bearer(&session.session_token)
        .await;

    resp.assert_status_ok();
    let body: Vec<serde_json::Value> = resp.json();
    assert_eq!(body.len(), 1);
    assert_eq!(body[0]["name"].as_str().unwrap(), "My Team");
}

#[sqlx::test(migrations = "src/db/migrations")]
async fn list_orgs_returns_empty_for_new_user(pool: PgPool) {
    let server = build_test_server(pool);
    register_user(&server, "alice@example.com", "password").await;
    let session = login(&server, "alice@example.com", "password").await;

    let body: Vec<serde_json::Value> = server
        .get("/v1/organizations")
        .authorization_bearer(&session.session_token)
        .await
        .json();

    assert!(body.is_empty());
}

// ─── Get org ──────────────────────────────────────────────────────────────────

#[sqlx::test(migrations = "src/db/migrations")]
async fn get_org_returns_details_for_owner(pool: PgPool) {
    let server = build_test_server(pool);
    register_user(&server, "alice@example.com", "password").await;
    let session = login(&server, "alice@example.com", "password").await;

    let create_resp: serde_json::Value = server
        .post("/v1/organizations")
        .authorization_bearer(&session.session_token)
        .json(&serde_json::json!({
            "name": "Acme",
            "publicKey": B64.encode(&[0u8; 256]),
            "protectedPrivateKey": B64.encode(&[0u8; 64]),
            "protectedPrivateKeyIv": B64.encode(&[0u8; 12]),
            "encryptedOrgKey": B64.encode(&[0u8; 64]),
        }))
        .await
        .json();

    let org_id = create_resp["id"].as_str().unwrap();

    let detail: serde_json::Value = server
        .get(&format!("/v1/organizations/{org_id}"))
        .authorization_bearer(&session.session_token)
        .await
        .json();

    assert_eq!(detail["name"].as_str().unwrap(), "Acme");
    assert_eq!(detail["role"].as_str().unwrap(), "owner");
    assert!(detail["members"].as_array().is_some());
    assert_eq!(detail["members"].as_array().unwrap().len(), 1);
    assert!(detail["encryptedOrgKey"].as_str().is_some());
}

#[sqlx::test(migrations = "src/db/migrations")]
async fn get_org_returns_404_for_non_member(pool: PgPool) {
    let server = build_test_server(pool);
    register_user(&server, "alice@example.com", "password").await;
    register_user(&server, "bob@example.com", "password").await;
    let alice = login(&server, "alice@example.com", "password").await;
    let bob = login(&server, "bob@example.com", "password").await;

    let create_resp: serde_json::Value = server
        .post("/v1/organizations")
        .authorization_bearer(&alice.session_token)
        .json(&serde_json::json!({
            "name": "Alice's Org",
            "publicKey": B64.encode(&[0u8; 256]),
            "protectedPrivateKey": B64.encode(&[0u8; 64]),
            "protectedPrivateKeyIv": B64.encode(&[0u8; 12]),
            "encryptedOrgKey": B64.encode(&[0u8; 64]),
        }))
        .await
        .json();

    let org_id = create_resp["id"].as_str().unwrap();

    server
        .get(&format!("/v1/organizations/{org_id}"))
        .authorization_bearer(&bob.session_token)
        .await
        .assert_status(StatusCode::NOT_FOUND);
}

// ─── Public key lookup ────────────────────────────────────────────────────────

#[sqlx::test(migrations = "src/db/migrations")]
async fn get_public_key_returns_key_after_org_creation(pool: PgPool) {
    let server = build_test_server(pool);
    register_user(&server, "alice@example.com", "password").await;
    let alice = login(&server, "alice@example.com", "password").await;

    // Create org — this stores Alice's public key
    server
        .post("/v1/organizations")
        .authorization_bearer(&alice.session_token)
        .json(&serde_json::json!({
            "name": "Acme",
            "publicKey": B64.encode(&[0xaa; 256]),
            "protectedPrivateKey": B64.encode(&[0u8; 64]),
            "protectedPrivateKeyIv": B64.encode(&[0u8; 12]),
            "encryptedOrgKey": B64.encode(&[0u8; 64]),
        }))
        .await
        .assert_status(StatusCode::CREATED);

    let email_hash = helpers::compute_email_hash("alice@example.com");
    let pk_resp: serde_json::Value = server
        .get(&format!("/v1/organizations/public-key/{email_hash}"))
        .authorization_bearer(&alice.session_token)
        .await
        .json();

    assert!(pk_resp["publicKey"].as_str().is_some());
    assert!(pk_resp["userId"].as_str().is_some());
}

#[sqlx::test(migrations = "src/db/migrations")]
async fn get_public_key_returns_404_for_unknown_email(pool: PgPool) {
    let server = build_test_server(pool);
    register_user(&server, "alice@example.com", "password").await;
    let alice = login(&server, "alice@example.com", "password").await;

    let unknown_hash = helpers::compute_email_hash("nobody@example.com");

    server
        .get(&format!("/v1/organizations/public-key/{unknown_hash}"))
        .authorization_bearer(&alice.session_token)
        .await
        .assert_status(StatusCode::NOT_FOUND);
}
