mod helpers;

use axum::http::StatusCode;
use axum_test::TestServer;
use base64::{
    engine::general_purpose::{STANDARD as B64, URL_SAFE_NO_PAD as B64URL},
    Engine,
};
use helpers::{build_test_server, compute_email_hash, login, opaque_login_start, register_user, test_kdf};
use nopass_crypto::{opaque::Suite, Argon2Params};
use nopass_models::{CreateVaultItemRequest, PasswordChangeStartResponse, VaultItemType};
use opaque_ke::{
    ClientLogin, ClientLoginFinishParameters, ClientRegistration, ClientRegistrationFinishParameters,
    CredentialResponse, RegistrationResponse,
};
use rand::rngs::OsRng;
use serde_json::{json, Value};
use sqlx::PgPool;

const EMAIL: &str = "change@example.com";
const OLD: &str = "correct horse battery staple";
const NEW: &str = "a different long passphrase";

fn ksf() -> argon2::Argon2<'static> {
    let k = test_kdf();
    nopass_crypto::opaque::ksf(&Argon2Params {
        memory_kib: k.memory_kib,
        iterations: k.iterations,
        parallelism: k.parallelism,
    })
    .unwrap()
}

struct Started {
    resp: PasswordChangeStartResponse,
    /// Proof of `current`, or None if the client rejected the response.
    finish_login_request: Option<String>,
    registration_record: String,
}

async fn start_change(server: &TestServer, token: &str, current: &str) -> Started {
    let login = ClientLogin::<Suite>::start(&mut OsRng, current.as_bytes()).unwrap();
    let reg = ClientRegistration::<Suite>::start(&mut OsRng, NEW.as_bytes()).unwrap();
    let resp: PasswordChangeStartResponse = server
        .post("/v1/auth/password/start")
        .authorization_bearer(token)
        .json(&json!({
            "emailHash": compute_email_hash(EMAIL),
            "startLoginRequest": B64URL.encode(login.message.serialize()),
            "registrationRequest": B64URL.encode(reg.message.serialize()),
        }))
        .await
        .json();
    let ksf = ksf();
    let finish_login_request = login
        .state
        .finish(
            &mut OsRng,
            current.as_bytes(),
            CredentialResponse::deserialize(&B64URL.decode(&resp.login_response).unwrap()).unwrap(),
            ClientLoginFinishParameters::new(None, Default::default(), Some(&ksf)),
        )
        .ok()
        .map(|f| B64URL.encode(f.message.serialize()));
    let registration_record = B64URL.encode(
        reg.state
            .finish(
                &mut OsRng,
                NEW.as_bytes(),
                RegistrationResponse::deserialize(&B64URL.decode(&resp.registration_response).unwrap()).unwrap(),
                ClientRegistrationFinishParameters::new(Default::default(), Some(&ksf)),
            )
            .unwrap()
            .message
            .serialize(),
    );
    Started { resp, finish_login_request, registration_record }
}

fn finish_body(s: &Started, proof: &str) -> Value {
    json!({
        "changeId": s.resp.change_id,
        "finishLoginRequest": proof,
        "registrationRecord": s.registration_record,
        "wrappedAccountKey": B64.encode([7u8; 80]),
        "wrappedAccountKeyIv": B64.encode([7u8; 12]),
    })
}

async fn set_account_key(server: &TestServer, token: &str) -> axum_test::TestResponse {
    server
        .put("/v1/auth/account-key")
        .authorization_bearer(token)
        .json(&json!({ "wrappedAccountKey": B64.encode([5u8; 80]), "wrappedAccountKeyIv": B64.encode([5u8; 12]) }))
        .await
}

async fn items(server: &TestServer, token: &str) -> Value {
    let vaults: Vec<Value> = server.get("/v1/vaults").authorization_bearer(token).await.json();
    let id = vaults[0]["id"].as_str().unwrap().to_string();
    server.get(&format!("/v1/vaults/{id}/items")).authorization_bearer(token).await.json()
}

async fn start_change_raw(server: &TestServer, token: &str) -> axum_test::TestResponse {
    let login = ClientLogin::<Suite>::start(&mut OsRng, OLD.as_bytes()).unwrap();
    let reg = ClientRegistration::<Suite>::start(&mut OsRng, NEW.as_bytes()).unwrap();
    server
        .post("/v1/auth/password/start")
        .authorization_bearer(token)
        .json(&json!({
            "emailHash": compute_email_hash(EMAIL),
            "startLoginRequest": B64URL.encode(login.message.serialize()),
            "registrationRequest": B64URL.encode(reg.message.serialize()),
        }))
        .await
}

/// A migrated account with two items, a recovery kit, and two sessions; returns (current, other) tokens.
async fn setup(server: &TestServer) -> (String, String) {
    register_user(server, EMAIL, OLD).await;
    let current = login(server, EMAIL, OLD).await;
    let other = login(server, EMAIL, OLD).await;
    for _ in 0..2 {
        server
            .post(&format!("/v1/vaults/{}/items", current.default_vault_id))
            .authorization_bearer(&current.session_token)
            .json(&CreateVaultItemRequest {
                id: None,
                item_type: VaultItemType::Login,
                blob: B64.encode([0u8; 48]),
                blob_iv: B64.encode([0u8; 12]),
                blob_mac: B64.encode([0u8; 32]),
            })
            .await
            .assert_status(StatusCode::CREATED);
    }
    server
        .put("/v1/auth/recovery")
        .authorization_bearer(&current.session_token)
        .json(&json!({ "recoveryAuthKey": B64.encode([3u8; 32]), "recoveryBlob": B64.encode([3u8; 112]), "recoveryBlobIv": B64.encode([3u8; 12]) }))
        .await
        .assert_status(StatusCode::NO_CONTENT);
    set_account_key(server, &current.session_token).await.assert_status(StatusCode::NO_CONTENT);
    (current.session_token, other.session_token)
}

#[sqlx::test(migrations = "src/db/migrations")]
async fn password_change_rewraps_the_account_key_and_leaves_items_and_kit_alone(pool: PgPool) {
    let server = build_test_server(pool);
    let (current, other) = setup(&server).await;
    let before = items(&server, &current).await;

    let started = start_change(&server, &current, OLD).await;
    let proof = started.finish_login_request.clone().unwrap();
    server
        .post("/v1/auth/password/finish")
        .authorization_bearer(&current)
        .json(&finish_body(&started, &proof))
        .await
        .assert_status(StatusCode::NO_CONTENT);

    // New password works and hands out the re-wrapped account key; the old one doesn't.
    let fresh = login(&server, EMAIL, NEW).await;
    assert_eq!(fresh.wrapped_account_key, Some(B64.encode([7u8; 80])));
    assert!(opaque_login_start(&server, EMAIL, OLD).await.finish_request.is_none());

    // No item was touched.
    assert_eq!(items(&server, &current).await, before);

    // This session survives, the other is revoked.
    server.get("/v1/vaults").authorization_bearer(&current).await.assert_status_ok();
    server.get("/v1/vaults").authorization_bearer(&other).await.assert_status(StatusCode::UNAUTHORIZED);

    // The kit wraps the account key, so it stays.
    let status: Value = server.get("/v1/auth/recovery").authorization_bearer(&current).await.json();
    assert_eq!(status["enabled"], true);
}

#[sqlx::test(migrations = "src/db/migrations")]
async fn password_change_without_current_password_proof_changes_nothing(pool: PgPool) {
    let server = build_test_server(pool);
    let (current, other) = setup(&server).await;

    // A session holder who doesn't know the password can't open the response…
    let started = start_change(&server, &current, "not the password").await;
    assert!(started.finish_login_request.is_none());
    // …and a valid proof from a different handshake doesn't transfer.
    let unrelated = opaque_login_start(&server, EMAIL, OLD).await.finish_request.unwrap();
    server
        .post("/v1/auth/password/finish")
        .authorization_bearer(&current)
        .json(&finish_body(&started, &unrelated))
        .await
        .assert_status(StatusCode::UNAUTHORIZED);

    login(&server, EMAIL, OLD).await;
    server.get("/v1/vaults").authorization_bearer(&other).await.assert_status_ok();
}

#[sqlx::test(migrations = "src/db/migrations")]
async fn account_key_is_set_once_and_only_from_a_fresh_session(pool: PgPool) {
    let server = build_test_server(pool.clone());
    register_user(&server, EMAIL, OLD).await;
    let token = login(&server, EMAIL, OLD).await.session_token;

    // A legacy-key account can't change its password until it has migrated.
    start_change_raw(&server, &token).await.assert_status(StatusCode::CONFLICT);

    sqlx::query("UPDATE sessions SET created_at = NOW() - INTERVAL '1 hour'").execute(&pool).await.unwrap();
    set_account_key(&server, &token).await.assert_status(StatusCode::FORBIDDEN);

    let fresh = login(&server, EMAIL, OLD).await.session_token;
    set_account_key(&server, &fresh).await.assert_status(StatusCode::NO_CONTENT);
    // A second write would let a session holder swap in a key of their choosing.
    set_account_key(&server, &fresh).await.assert_status(StatusCode::CONFLICT);
}
