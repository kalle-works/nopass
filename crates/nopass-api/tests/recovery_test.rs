mod helpers;

use axum::http::StatusCode;
use base64::{engine::general_purpose::STANDARD as B64, Engine};
use helpers::{build_test_server, compute_email_hash, generate_srp_verifier, login, register_user};
use nopass_models::{
    CreateVaultItemRequest, RecoveryInitResponse, RecoveryStatusResponse, VaultItemType,
};
use rand::RngCore;
use serde_json::json;
use sqlx::PgPool;

const EMAIL: &str = "recovery@example.com";
const PASSWORD: &str = "correct horse battery staple";
const NEW_PASSWORD: &str = "completely different passphrase";

fn random_b64(len: usize) -> String {
    let mut bytes = vec![0u8; len];
    rand::thread_rng().fill_bytes(&mut bytes);
    B64.encode(&bytes)
}

#[sqlx::test(migrations = "src/db/migrations")]
async fn recovery_status_disabled_by_default(pool: PgPool) {
    let server = build_test_server(pool);
    register_user(&server, EMAIL, PASSWORD).await;
    let session = login(&server, EMAIL, PASSWORD).await;

    let status: RecoveryStatusResponse = server
        .get("/v1/auth/recovery")
        .authorization_bearer(&session.session_token)
        .await
        .json();

    assert!(!status.enabled);
    assert!(status.updated_at.is_none());
}

#[sqlx::test(migrations = "src/db/migrations")]
async fn recovery_set_then_status_enabled(pool: PgPool) {
    let server = build_test_server(pool);
    register_user(&server, EMAIL, PASSWORD).await;
    let session = login(&server, EMAIL, PASSWORD).await;

    server
        .put("/v1/auth/recovery")
        .authorization_bearer(&session.session_token)
        .json(&json!({
            "recoveryAuthKey": random_b64(32),
            "recoveryBlob": random_b64(112),
            "recoveryBlobIv": random_b64(12),
        }))
        .await
        .assert_status(StatusCode::NO_CONTENT);

    let status: RecoveryStatusResponse = server
        .get("/v1/auth/recovery")
        .authorization_bearer(&session.session_token)
        .await
        .json();

    assert!(status.enabled);
    assert!(status.updated_at.is_some());
}

#[sqlx::test(migrations = "src/db/migrations")]
async fn recovery_init_rejects_wrong_code_and_unknown_email(pool: PgPool) {
    let server = build_test_server(pool);
    register_user(&server, EMAIL, PASSWORD).await;
    let session = login(&server, EMAIL, PASSWORD).await;

    server
        .put("/v1/auth/recovery")
        .authorization_bearer(&session.session_token)
        .json(&json!({
            "recoveryAuthKey": random_b64(32),
            "recoveryBlob": random_b64(112),
            "recoveryBlobIv": random_b64(12),
        }))
        .await
        .assert_status(StatusCode::NO_CONTENT);

    // Wrong auth key
    server
        .post("/v1/auth/recovery/init")
        .json(&json!({
            "emailHash": compute_email_hash(EMAIL),
            "recoveryAuthKey": random_b64(32),
        }))
        .await
        .assert_status(StatusCode::UNAUTHORIZED);

    // Unknown email — identical error
    server
        .post("/v1/auth/recovery/init")
        .json(&json!({
            "emailHash": compute_email_hash("nobody@example.com"),
            "recoveryAuthKey": random_b64(32),
        }))
        .await
        .assert_status(StatusCode::UNAUTHORIZED);
}

#[sqlx::test(migrations = "src/db/migrations")]
async fn recovery_full_flow_rotates_credentials(pool: PgPool) {
    let server = build_test_server(pool);
    register_user(&server, EMAIL, PASSWORD).await;
    let session = login(&server, EMAIL, PASSWORD).await;

    // One vault item that must survive the rotation
    let item: nopass_models::EncryptedVaultItem = server
        .post(&format!("/v1/vaults/{}/items", session.default_vault_id))
        .authorization_bearer(&session.session_token)
        .json(&CreateVaultItemRequest {
            item_type: VaultItemType::Login,
            blob: random_b64(64),
            blob_iv: random_b64(12),
            blob_mac: random_b64(32),
        })
        .await
        .json();

    let auth_key = random_b64(32);
    server
        .put("/v1/auth/recovery")
        .authorization_bearer(&session.session_token)
        .json(&json!({
            "recoveryAuthKey": auth_key,
            "recoveryBlob": random_b64(112),
            "recoveryBlobIv": random_b64(12),
        }))
        .await
        .assert_status(StatusCode::NO_CONTENT);

    // Init with the correct auth key returns the blob and all items
    let init: RecoveryInitResponse = server
        .post("/v1/auth/recovery/init")
        .json(&json!({
            "emailHash": compute_email_hash(EMAIL),
            "recoveryAuthKey": auth_key,
        }))
        .await
        .json();
    assert_eq!(init.items.len(), 1);
    assert_eq!(init.items[0].id, item.id);

    // Complete: new SRP credentials, re-encrypted item, new recovery kit
    let (new_salt, new_verifier) = generate_srp_verifier(EMAIL, NEW_PASSWORD);
    let new_auth_key = random_b64(32);
    let reencrypted_blob = random_b64(64);

    server
        .post("/v1/auth/recovery/complete")
        .json(&json!({
            "recoveryToken": init.recovery_token,
            "srpSalt": B64.encode(&new_salt),
            "srpVerifier": B64.encode(&new_verifier),
            "protectedSymmetricKey": random_b64(32),
            "protectedSymmetricKeyIv": random_b64(12),
            "items": [{
                "id": item.id,
                "blob": reencrypted_blob,
                "blobIv": random_b64(12),
                "blobMac": random_b64(32),
            }],
            "recoveryAuthKey": new_auth_key,
            "recoveryBlob": random_b64(112),
            "recoveryBlobIv": random_b64(12),
        }))
        .await
        .assert_status(StatusCode::NO_CONTENT);

    // Old session is revoked
    server
        .get("/v1/auth/recovery")
        .authorization_bearer(&session.session_token)
        .await
        .assert_status(StatusCode::UNAUTHORIZED);

    // New password logs in; the item carries the re-encrypted blob at version+1
    let new_session = login(&server, EMAIL, NEW_PASSWORD).await;
    let items: Vec<nopass_models::EncryptedVaultItem> = server
        .get(&format!("/v1/vaults/{}/items", new_session.default_vault_id))
        .authorization_bearer(&new_session.session_token)
        .await
        .json();
    assert_eq!(items.len(), 1);
    assert_eq!(items[0].blob, reencrypted_blob);
    assert_eq!(items[0].version, item.version + 1);

    // The used recovery code is burned — old auth key no longer works
    server
        .post("/v1/auth/recovery/init")
        .json(&json!({
            "emailHash": compute_email_hash(EMAIL),
            "recoveryAuthKey": auth_key,
        }))
        .await
        .assert_status(StatusCode::UNAUTHORIZED);

    // …but the replacement kit does
    server
        .post("/v1/auth/recovery/init")
        .json(&json!({
            "emailHash": compute_email_hash(EMAIL),
            "recoveryAuthKey": new_auth_key,
        }))
        .await
        .assert_status(StatusCode::OK);
}

#[sqlx::test(migrations = "src/db/migrations")]
async fn recovery_complete_rejects_partial_item_set(pool: PgPool) {
    let server = build_test_server(pool);
    register_user(&server, EMAIL, PASSWORD).await;
    let session = login(&server, EMAIL, PASSWORD).await;

    for _ in 0..2 {
        server
            .post(&format!("/v1/vaults/{}/items", session.default_vault_id))
            .authorization_bearer(&session.session_token)
            .json(&CreateVaultItemRequest {
                item_type: VaultItemType::Note,
                blob: random_b64(64),
                blob_iv: random_b64(12),
                blob_mac: random_b64(32),
            })
            .await
            .assert_status(StatusCode::CREATED);
    }

    let auth_key = random_b64(32);
    server
        .put("/v1/auth/recovery")
        .authorization_bearer(&session.session_token)
        .json(&json!({
            "recoveryAuthKey": auth_key,
            "recoveryBlob": random_b64(112),
            "recoveryBlobIv": random_b64(12),
        }))
        .await
        .assert_status(StatusCode::NO_CONTENT);

    let init: RecoveryInitResponse = server
        .post("/v1/auth/recovery/init")
        .json(&json!({
            "emailHash": compute_email_hash(EMAIL),
            "recoveryAuthKey": auth_key,
        }))
        .await
        .json();
    assert_eq!(init.items.len(), 2);

    let (new_salt, new_verifier) = generate_srp_verifier(EMAIL, NEW_PASSWORD);
    server
        .post("/v1/auth/recovery/complete")
        .json(&json!({
            "recoveryToken": init.recovery_token,
            "srpSalt": B64.encode(&new_salt),
            "srpVerifier": B64.encode(&new_verifier),
            "protectedSymmetricKey": random_b64(32),
            "protectedSymmetricKeyIv": random_b64(12),
            // Only one of the two items re-encrypted — must be rejected
            "items": [{
                "id": init.items[0].id,
                "blob": random_b64(64),
                "blobIv": random_b64(12),
                "blobMac": random_b64(32),
            }],
            "recoveryAuthKey": random_b64(32),
            "recoveryBlob": random_b64(112),
            "recoveryBlobIv": random_b64(12),
        }))
        .await
        .assert_status(StatusCode::BAD_REQUEST);

    // Old password still works — nothing was applied
    login(&server, EMAIL, PASSWORD).await;
}

#[sqlx::test(migrations = "src/db/migrations")]
async fn recovery_disable_clears_kit(pool: PgPool) {
    let server = build_test_server(pool);
    register_user(&server, EMAIL, PASSWORD).await;
    let session = login(&server, EMAIL, PASSWORD).await;

    let auth_key = random_b64(32);
    server
        .put("/v1/auth/recovery")
        .authorization_bearer(&session.session_token)
        .json(&json!({
            "recoveryAuthKey": auth_key,
            "recoveryBlob": random_b64(112),
            "recoveryBlobIv": random_b64(12),
        }))
        .await
        .assert_status(StatusCode::NO_CONTENT);

    server
        .delete("/v1/auth/recovery")
        .authorization_bearer(&session.session_token)
        .await
        .assert_status(StatusCode::NO_CONTENT);

    let status: RecoveryStatusResponse = server
        .get("/v1/auth/recovery")
        .authorization_bearer(&session.session_token)
        .await
        .json();
    assert!(!status.enabled);

    server
        .post("/v1/auth/recovery/init")
        .json(&json!({
            "emailHash": compute_email_hash(EMAIL),
            "recoveryAuthKey": auth_key,
        }))
        .await
        .assert_status(StatusCode::UNAUTHORIZED);
}
