mod helpers;

use axum::http::StatusCode;
use base64::{engine::general_purpose::STANDARD as B64, Engine};
use nopass_models::{KdfParams, RegisterRequest, SrpInitRequest, SrpVerifyRequest};
use sqlx::PgPool;
use uuid::Uuid;

use helpers::{build_test_server, compute_email_hash, login, register_user};

// ─── Register ─────────────────────────────────────────────────────────────────

#[sqlx::test(migrations = "src/db/migrations")]
async fn register_returns_201_with_user_id(pool: PgPool) {
    let server = build_test_server(pool);
    let email_hash = compute_email_hash("alice@example.com");
    let (salt, verifier) = helpers::generate_srp_verifier("alice@example.com", "correct horse battery staple");

    let req = RegisterRequest {
        email_hash,
        srp_salt: B64.encode(&salt),
        srp_verifier: B64.encode(&verifier),
        kdf_params: KdfParams::default(),
        protected_symmetric_key: B64.encode(&[0u8; 32]),
        protected_symmetric_key_iv: B64.encode(&[0u8; 12]),
    };

    let resp = server.post("/v1/auth/register").json(&req).await;
    resp.assert_status(StatusCode::CREATED);

    let body: serde_json::Value = resp.json();
    assert!(body["userId"].as_str().is_some(), "userId should be present");
    // Should be a valid UUID
    Uuid::parse_str(body["userId"].as_str().unwrap()).expect("userId should be a valid UUID");
}

#[sqlx::test(migrations = "src/db/migrations")]
async fn register_duplicate_email_returns_409(pool: PgPool) {
    let server = build_test_server(pool);
    register_user(&server, "alice@example.com", "password1").await;

    // Register again with the same email
    let email_hash = compute_email_hash("alice@example.com");
    let (salt, verifier) = helpers::generate_srp_verifier("alice@example.com", "password2");

    let req = RegisterRequest {
        email_hash,
        srp_salt: B64.encode(&salt),
        srp_verifier: B64.encode(&verifier),
        kdf_params: KdfParams::default(),
        protected_symmetric_key: B64.encode(&[0u8; 32]),
        protected_symmetric_key_iv: B64.encode(&[0u8; 12]),
    };

    let resp = server.post("/v1/auth/register").json(&req).await;
    resp.assert_status(StatusCode::CONFLICT);
}

#[sqlx::test(migrations = "src/db/migrations")]
async fn register_rejects_invalid_base64(pool: PgPool) {
    let server = build_test_server(pool);

    let req = serde_json::json!({
        "emailHash": compute_email_hash("alice@example.com"),
        "srpSalt": "!!!not-valid-base64!!!",
        "srpVerifier": B64.encode(&[0u8; 32]),
        "kdfParams": { "type": "argon2id", "memoryKib": 65536, "iterations": 3, "parallelism": 4 },
        "protectedSymmetricKey": B64.encode(&[0u8; 32]),
        "protectedSymmetricKeyIv": B64.encode(&[0u8; 12]),
    });

    let resp = server.post("/v1/auth/register").json(&req).await;
    resp.assert_status(StatusCode::BAD_REQUEST);
}

// ─── SRP init ─────────────────────────────────────────────────────────────────

#[sqlx::test(migrations = "src/db/migrations")]
async fn srp_init_returns_server_public_b_and_salt(pool: PgPool) {
    let server = build_test_server(pool);
    register_user(&server, "alice@example.com", "password").await;

    let resp = server
        .post("/v1/auth/srp/init")
        .json(&SrpInitRequest {
            email_hash: compute_email_hash("alice@example.com"),
            client_public_a: B64.encode(&[0xab; 256]), // fake A for step 1
        })
        .await;

    resp.assert_status_ok();
    let body: serde_json::Value = resp.json();
    assert!(body["sessionId"].as_str().is_some());
    assert!(body["serverPublicB"].as_str().is_some());
    assert!(body["srpSalt"].as_str().is_some());
}

#[sqlx::test(migrations = "src/db/migrations")]
async fn srp_init_unknown_email_returns_401(pool: PgPool) {
    let server = build_test_server(pool);

    let resp = server
        .post("/v1/auth/srp/init")
        .json(&SrpInitRequest {
            email_hash: compute_email_hash("nonexistent@example.com"),
            client_public_a: B64.encode(&[0xab; 256]),
        })
        .await;

    resp.assert_status(StatusCode::UNAUTHORIZED);
}

// ─── SRP verify ───────────────────────────────────────────────────────────────

#[sqlx::test(migrations = "src/db/migrations")]
async fn srp_verify_full_login_flow(pool: PgPool) {
    let server = build_test_server(pool);
    register_user(&server, "alice@example.com", "correct horse battery staple").await;

    let verify_resp = login(&server, "alice@example.com", "correct horse battery staple").await;

    assert!(!verify_resp.session_token.is_empty(), "session_token should be non-empty");
    assert!(!verify_resp.server_proof_m2.is_empty(), "server_proof_m2 should be present");
}

#[sqlx::test(migrations = "src/db/migrations")]
async fn srp_verify_wrong_password_returns_401(pool: PgPool) {
    let server = build_test_server(pool);
    register_user(&server, "alice@example.com", "correct-password").await;

    let email_hash = compute_email_hash("alice@example.com");
    let init_resp: nopass_models::SrpInitResponse = server
        .post("/v1/auth/srp/init")
        .json(&SrpInitRequest {
            email_hash: email_hash.clone(),
            client_public_a: B64.encode(&[0xab; 256]),
        })
        .await
        .json();

    // Send a garbage M1 proof
    let resp = server
        .post("/v1/auth/srp/verify")
        .json(&SrpVerifyRequest {
            session_id: init_resp.session_id,
            client_proof_m1: B64.encode(&[0xde, 0xad, 0xbe, 0xef]),
        })
        .await;

    resp.assert_status(StatusCode::UNAUTHORIZED);
}

#[sqlx::test(migrations = "src/db/migrations")]
async fn srp_verify_invalid_session_returns_401(pool: PgPool) {
    let server = build_test_server(pool);

    let resp = server
        .post("/v1/auth/srp/verify")
        .json(&SrpVerifyRequest {
            session_id: Uuid::new_v4(), // no such session
            client_proof_m1: B64.encode(&[0u8; 32]),
        })
        .await;

    resp.assert_status(StatusCode::UNAUTHORIZED);
}

// ─── Logout ───────────────────────────────────────────────────────────────────

#[sqlx::test(migrations = "src/db/migrations")]
async fn logout_invalidates_session(pool: PgPool) {
    let server = build_test_server(pool);
    register_user(&server, "alice@example.com", "password").await;
    let session = login(&server, "alice@example.com", "password").await;

    // Logout
    server
        .post("/v1/auth/logout")
        .authorization_bearer(&session.session_token)
        .await
        .assert_status(StatusCode::NO_CONTENT);

    // Second logout with the same token should fail
    server
        .post("/v1/auth/logout")
        .authorization_bearer(&session.session_token)
        .await
        .assert_status(StatusCode::UNAUTHORIZED);
}
