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

/// The invitee verifies an invite through the chain of signed wraps up to
/// the owner, so the server must store each wrap's signature and epoch and
/// return the whole chain with each signer's key bundle; unsigned invites
/// are refused outright.
#[sqlx::test(migrations = "src/db/migrations")]
async fn invites_carry_the_signed_wrap_chain_up_to_the_owner(pool: PgPool) {
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
            "keyEpoch": 1,
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
    let chain = invites[0]["wrapChain"].as_array().unwrap();
    let alice_id = alice.user_id.to_string();

    assert_eq!(invites[0]["orgId"].as_str(), Some(org_id.as_str()));
    assert_eq!(chain.len(), 2, "bob's wrap, then the owner's self-signed wrap");
    assert_eq!(chain[0]["recipientUserId"].as_str(), Some(bob.user_id.to_string().as_str()));
    assert_eq!(chain[0]["encryptedOrgKey"].as_str(), Some(B64.encode([9u8; 64]).as_str()));
    assert_eq!(chain[0]["wrapSignature"].as_str(), Some(B64.encode([3u8; 64]).as_str()));
    assert_eq!(chain[0]["keyEpoch"].as_i64(), Some(1));
    assert_eq!(chain[0]["signer"]["identityPublicKey"].as_str(), Some(B64.encode([1u8; 32]).as_str()));
    assert_eq!(chain[1]["recipientUserId"].as_str(), Some(alice_id.as_str()));
    assert_eq!(chain[1]["signerUserId"].as_str(), Some(alice_id.as_str()));
    assert_eq!(chain[1]["role"].as_str(), Some("owner"));
}

/// Only the owner may re-sign wraps; a re-signed member's chain then leads
/// straight to the owner.
#[sqlx::test(migrations = "src/db/migrations")]
async fn only_the_owner_can_rewrap_and_rewrapped_members_chain_to_the_owner(pool: PgPool) {
    let server = build_test_server(pool);
    register_user(&server, "alice@example.com", "password").await;
    register_user(&server, "bob@example.com", "password").await;
    let alice = login(&server, "alice@example.com", "password").await;
    let bob = login(&server, "bob@example.com", "password").await;
    let org_id = create_org(&server, &alice.session_token).await;
    create_org(&server, &bob.session_token).await;
    server
        .post(&format!("/v1/organizations/{org_id}/members"))
        .authorization_bearer(&alice.session_token)
        .json(&serde_json::json!({
            "emailHash": compute_email_hash("bob@example.com"),
            "role": "admin",
            "encryptedOrgKey": B64.encode([9u8; 64]),
            "wrapSignature": B64.encode([3u8; 64]),
            "keyEpoch": 1,
        }))
        .await
        .assert_status(StatusCode::NO_CONTENT);
    server
        .post(&format!("/v1/organizations/{org_id}/accept"))
        .authorization_bearer(&bob.session_token)
        .await
        .assert_status(StatusCode::NO_CONTENT);

    let rewrap = |token: &str, user_id: uuid::Uuid| {
        server.put(&format!("/v1/organizations/{org_id}/wraps")).authorization_bearer(token).json(&serde_json::json!({
            "wraps": [{
                "userId": user_id,
                "encryptedOrgKey": B64.encode([4u8; 64]),
                "wrapSignature": B64.encode([5u8; 64]),
                "keyEpoch": 2,
            }]
        }))
    };
    rewrap(&bob.session_token, alice.user_id).await.assert_status(StatusCode::FORBIDDEN);
    rewrap(&alice.session_token, bob.user_id).await.assert_status(StatusCode::NO_CONTENT);

    let org: serde_json::Value = server
        .get(&format!("/v1/organizations/{org_id}"))
        .authorization_bearer(&bob.session_token)
        .await
        .json();
    let chain = org["wrapChain"].as_array().unwrap();
    assert_eq!(chain[0]["wrapSignature"].as_str(), Some(B64.encode([5u8; 64]).as_str()));
    assert_eq!(chain[0]["keyEpoch"].as_i64(), Some(2));
    assert_eq!(chain[0]["signerUserId"].as_str(), Some(alice.user_id.to_string().as_str()));
    assert_eq!(chain[1]["role"].as_str(), Some("owner"));
}

/// Fresh devices learn the account is v2-only from this marker, so it must be
/// stored per account and served back unchanged.
#[sqlx::test(migrations = "src/db/migrations")]
async fn vault_format_marker_round_trips_per_account(pool: PgPool) {
    let server = build_test_server(pool);
    register_user(&server, "alice@example.com", "password").await;
    register_user(&server, "bob@example.com", "password").await;
    let alice = login(&server, "alice@example.com", "password").await;
    let bob = login(&server, "bob@example.com", "password").await;
    let marker = B64.encode([5u8; 32]);

    server
        .put("/v1/keys/vault-format")
        .authorization_bearer(&alice.session_token)
        .json(&serde_json::json!({ "marker": marker }))
        .await
        .assert_status(StatusCode::NO_CONTENT);

    let mine: serde_json::Value =
        server.get("/v1/keys/vault-format").authorization_bearer(&alice.session_token).await.json();
    let theirs: serde_json::Value =
        server.get("/v1/keys/vault-format").authorization_bearer(&bob.session_token).await.json();
    assert_eq!(mine["marker"].as_str(), Some(marker.as_str()));
    assert!(theirs["marker"].is_null());
}
