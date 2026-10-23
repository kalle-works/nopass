mod helpers;

use axum::http::StatusCode;
use axum_test::TestServer;
use base64::{engine::general_purpose::STANDARD as B64, Engine};
use helpers::{build_test_server, compute_email_hash, login, register_user};
use sqlx::PgPool;

/// Creating an org is how a user publishes an RSA public key today.
async fn create_org(server: &TestServer, token: &str) -> String {
    let body: serde_json::Value = server
        .post("/v1/organizations")
        .authorization_bearer(token)
        .json(&serde_json::json!({
            "name": "Acme",
            "publicKey": B64.encode([7u8; 256]),
            "protectedPrivateKey": B64.encode([0u8; 64]),
            "protectedPrivateKeyIv": B64.encode([0u8; 12]),
            "encryptedOrgKey": B64.encode([0u8; 64]),
        }))
        .await
        .json();
    body["id"].as_str().unwrap().to_string()
}

fn identity(byte: u8) -> serde_json::Value {
    serde_json::json!({
        "identityPublicKey": B64.encode([byte; 32]),
        "publicKeySignature": B64.encode([byte; 64]),
    })
}

/// A published identity key can never be replaced through the API: a stolen
/// session must not be able to swap it and re-sign a substituted RSA key.
#[sqlx::test(migrations = "src/db/migrations")]
async fn identity_key_is_write_once(pool: PgPool) {
    let server = build_test_server(pool);
    register_user(&server, "alice@example.com", "password").await;
    let alice = login(&server, "alice@example.com", "password").await;
    create_org(&server, &alice.session_token).await;

    let put = |body: serde_json::Value| {
        server.put("/v1/keys/identity").authorization_bearer(&alice.session_token).json(&body)
    };
    put(identity(1)).await.assert_status(StatusCode::NO_CONTENT);
    put(identity(1)).await.assert_status(StatusCode::NO_CONTENT);
    put(identity(2)).await.assert_status(StatusCode::CONFLICT);

    let me: serde_json::Value = server.get("/v1/keys/me").authorization_bearer(&alice.session_token).await.json();
    assert_eq!(me["identityPublicKey"].as_str(), Some(B64.encode([1u8; 32]).as_str()));
}

/// Inviters and members verify keys client-side, so every place that hands
/// out an RSA key must hand out the identity key and signature with it.
#[sqlx::test(migrations = "src/db/migrations")]
async fn key_lookups_return_the_signed_bundle(pool: PgPool) {
    let server = build_test_server(pool);
    register_user(&server, "alice@example.com", "password").await;
    let alice = login(&server, "alice@example.com", "password").await;
    let org_id = create_org(&server, &alice.session_token).await;
    server
        .put("/v1/keys/identity")
        .authorization_bearer(&alice.session_token)
        .json(&identity(1))
        .await
        .assert_status(StatusCode::NO_CONTENT);

    let lookup: serde_json::Value = server
        .get(&format!("/v1/organizations/public-key/{}", compute_email_hash("alice@example.com")))
        .authorization_bearer(&alice.session_token)
        .await
        .json();
    let org: serde_json::Value = server
        .get(&format!("/v1/organizations/{org_id}"))
        .authorization_bearer(&alice.session_token)
        .await
        .json();

    for bundle in [&lookup, &org["members"][0]] {
        assert_eq!(bundle["publicKey"].as_str(), Some(B64.encode([7u8; 256]).as_str()));
        assert_eq!(bundle["identityPublicKey"].as_str(), Some(B64.encode([1u8; 32]).as_str()));
        assert_eq!(bundle["publicKeySignature"].as_str(), Some(B64.encode([1u8; 64]).as_str()));
    }
}

/// The invitee checks an invite came from the inviter before accepting, so
/// the server must store the inviter's wrap signature and hand it back with
/// the inviter's key bundle; an unsigned invite is refused outright.
#[sqlx::test(migrations = "src/db/migrations")]
async fn invites_carry_the_inviters_signature_and_bundle(pool: PgPool) {
    let server = build_test_server(pool);
    register_user(&server, "alice@example.com", "password").await;
    register_user(&server, "bob@example.com", "password").await;
    let alice = login(&server, "alice@example.com", "password").await;
    let bob = login(&server, "bob@example.com", "password").await;
    let org_id = create_org(&server, &alice.session_token).await;
    create_org(&server, &bob.session_token).await; // publishes bob's public key
    server
        .put("/v1/keys/identity")
        .authorization_bearer(&alice.session_token)
        .json(&identity(1))
        .await
        .assert_status(StatusCode::NO_CONTENT);

    let invite = |signature: Option<String>| {
        let mut body = serde_json::json!({
            "emailHash": compute_email_hash("bob@example.com"),
            "role": "member",
            "encryptedOrgKey": B64.encode([9u8; 64]),
        });
        if let Some(sig) = signature {
            body["wrapSignature"] = sig.into();
        }
        server
            .post(&format!("/v1/organizations/{org_id}/members"))
            .authorization_bearer(&alice.session_token)
            .json(&body)
    };
    assert!(invite(None).await.status_code().is_client_error());
    invite(Some(B64.encode([3u8; 64]))).await.assert_status(StatusCode::NO_CONTENT);

    let invites: serde_json::Value =
        server.get("/v1/organizations/invites").authorization_bearer(&bob.session_token).await.json();
    let pending = &invites[0];
    assert_eq!(pending["orgId"].as_str(), Some(org_id.as_str()));
    assert_eq!(pending["encryptedOrgKey"].as_str(), Some(B64.encode([9u8; 64]).as_str()));
    assert_eq!(pending["wrapSignature"].as_str(), Some(B64.encode([3u8; 64]).as_str()));
    assert_eq!(pending["inviter"]["userId"].as_str(), Some(alice.user_id.to_string().as_str()));
    assert_eq!(pending["inviter"]["identityPublicKey"].as_str(), Some(B64.encode([1u8; 32]).as_str()));
}
