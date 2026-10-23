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

fn finish_body(s: &Started, proof: &str, items: Value) -> Value {
    json!({
        "changeId": s.resp.change_id,
        "finishLoginRequest": proof,
        "registrationRecord": s.registration_record,
        "protectedSymmetricKey": B64.encode([1u8; 32]),
        "protectedSymmetricKeyIv": B64.encode([1u8; 12]),
        "items": items,
    })
}

fn reencrypt_all(s: &Started) -> Value {
    s.resp
        .items
        .iter()
        .map(|i| json!({ "id": i.id, "blob": B64.encode([9u8; 48]), "blobIv": B64.encode([9u8; 12]), "blobMac": B64.encode([9u8; 32]) }))
        .collect()
}

/// An account with two items, a recovery kit, and two sessions; returns (current, other) tokens.
async fn setup(server: &TestServer) -> (String, String) {
    register_user(server, EMAIL, OLD).await;
    let current = login(server, EMAIL, OLD).await;
    let other = login(server, EMAIL, OLD).await;
    for _ in 0..2 {
        server
            .post(&format!("/v1/vaults/{}/items", current.default_vault_id))
            .authorization_bearer(&current.session_token)
            .json(&CreateVaultItemRequest {
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
    (current.session_token, other.session_token)
}

#[sqlx::test(migrations = "src/db/migrations")]
async fn password_change_rotates_credential_items_and_sessions(pool: PgPool) {
    let server = build_test_server(pool);
    let (current, other) = setup(&server).await;

    let started = start_change(&server, &current, OLD).await;
    assert_eq!(started.resp.items.len(), 2);
    let proof = started.finish_login_request.clone().unwrap();
    server
        .post("/v1/auth/password/finish")
        .authorization_bearer(&current)
        .json(&finish_body(&started, &proof, reencrypt_all(&started)))
        .await
        .assert_status(StatusCode::NO_CONTENT);

    // New password works, old one doesn't.
    let fresh = login(&server, EMAIL, NEW).await;
    assert!(opaque_login_start(&server, EMAIL, OLD).await.finish_request.is_none());

    // Items carry the re-encrypted blobs.
    let items: Vec<nopass_models::EncryptedVaultItem> = server
        .get(&format!("/v1/vaults/{}/items", fresh.default_vault_id))
        .authorization_bearer(&fresh.session_token)
        .await
        .json();
    assert!(items.iter().all(|i| i.blob == B64.encode([9u8; 48])));

    // This session survives, the other is revoked.
    server.get("/v1/vaults").authorization_bearer(&current).await.assert_status_ok();
    server.get("/v1/vaults").authorization_bearer(&other).await.assert_status(StatusCode::UNAUTHORIZED);

    // The old kit wrapped the old keys, so it is gone.
    let status: Value = server.get("/v1/auth/recovery").authorization_bearer(&current).await.json();
    assert_eq!(status["enabled"], false);
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
        .json(&finish_body(&started, &unrelated, reencrypt_all(&started)))
        .await
        .assert_status(StatusCode::UNAUTHORIZED);

    login(&server, EMAIL, OLD).await;
    server.get("/v1/vaults").authorization_bearer(&other).await.assert_status_ok();
}

#[sqlx::test(migrations = "src/db/migrations")]
async fn password_change_with_an_item_left_out_changes_nothing(pool: PgPool) {
    let server = build_test_server(pool);
    let (current, _) = setup(&server).await;

    let started = start_change(&server, &current, OLD).await;
    let mut items = reencrypt_all(&started);
    items.as_array_mut().unwrap().pop();
    let proof = started.finish_login_request.clone().unwrap();
    server
        .post("/v1/auth/password/finish")
        .authorization_bearer(&current)
        .json(&finish_body(&started, &proof, items))
        .await
        .assert_status(StatusCode::BAD_REQUEST);

    login(&server, EMAIL, OLD).await;
}
