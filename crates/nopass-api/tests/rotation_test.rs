mod helpers;

use axum::http::StatusCode;
use axum_test::TestServer;
use base64::{engine::general_purpose::STANDARD as B64, Engine};
use helpers::{build_test_server, compute_email_hash, login, register_user};
use sqlx::PgPool;
use uuid::Uuid;

use nopass_models::LoginResponse;

struct Org {
    server: TestServer,
    pool: PgPool,
    id: String,
    owner: LoginResponse,
    bob: LoginResponse,
    carol: LoginResponse,
    items: Vec<Uuid>,
}

fn sig(byte: u8) -> String {
    B64.encode([byte; 64])
}

/// Owner alice with active members bob and carol at epoch 1, and two org items.
async fn setup(pool: PgPool) -> Org {
    let server = build_test_server(pool.clone());
    for email in ["alice@example.com", "bob@example.com", "carol@example.com"] {
        register_user(&server, email, "password").await;
    }
    let owner = login(&server, "alice@example.com", "password").await;
    let bob = login(&server, "bob@example.com", "password").await;
    let carol = login(&server, "carol@example.com", "password").await;

    let mut org_id = String::new();
    for session in [&owner, &bob, &carol] {
        let body: serde_json::Value = server
            .post("/v1/organizations")
            .authorization_bearer(&session.session_token)
            .json(&serde_json::json!({
                "name": "Acme",
                "publicKey": B64.encode([7u8; 256]),
                "protectedPrivateKey": B64.encode([0u8; 64]),
                "protectedPrivateKeyIv": B64.encode([0u8; 12]),
                "encryptedOrgKey": B64.encode([1u8; 64]),
                "wrapSignature": sig(1),
                "keyEpoch": 1,
            }))
            .await
            .json();
        if org_id.is_empty() {
            org_id = body["id"].as_str().unwrap().to_string();
        }
    }
    for (email, session) in [("bob@example.com", &bob), ("carol@example.com", &carol)] {
        server
            .post(&format!("/v1/organizations/{org_id}/members"))
            .authorization_bearer(&owner.session_token)
            .json(&serde_json::json!({
                "emailHash": compute_email_hash(email),
                "role": "member",
                "encryptedOrgKey": B64.encode([1u8; 64]),
                "wrapSignature": sig(1),
                "keyEpoch": 1,
            }))
            .await
            .assert_status(StatusCode::NO_CONTENT);
        server
            .post(&format!("/v1/organizations/{org_id}/accept"))
            .authorization_bearer(&session.session_token)
            .await
            .assert_status(StatusCode::NO_CONTENT);
    }

    let mut items = Vec::new();
    for _ in 0..2 {
        let id = Uuid::new_v4();
        sqlx::query(
            r#"INSERT INTO vault_items (id, vault_id, user_id, org_id, item_type, blob, blob_iv, blob_mac)
               VALUES ($1, $2, $3, $4, 'login', $5, $6, '')"#,
        )
        .bind(id)
        .bind(owner.default_vault_id)
        .bind(owner.user_id)
        .bind(Uuid::parse_str(&org_id).unwrap())
        .bind(vec![0xaa_u8; 32])
        .bind(vec![0u8; 12])
        .execute(&pool)
        .await
        .unwrap();
        items.push(id);
    }
    Org { server, pool, id: org_id, owner, bob, carol, items }
}

fn rotation(epoch: i32, members: &[Uuid], items: &[Uuid], remove: Option<Uuid>) -> serde_json::Value {
    serde_json::json!({
        "newEpoch": epoch,
        "removeUserId": remove,
        "wraps": members.iter().map(|u| serde_json::json!({
            "userId": u, "encryptedOrgKey": B64.encode([2u8; 64]), "wrapSignature": sig(2), "keyEpoch": epoch,
        })).collect::<Vec<_>>(),
        "items": items.iter().map(|id| serde_json::json!({
            "id": id, "blob": B64.encode([0xbb_u8; 32]), "blobIv": B64.encode([1u8; 12]), "blobMac": "",
        })).collect::<Vec<_>>(),
    })
}

async fn item_blobs(org: &Org) -> Vec<Vec<u8>> {
    sqlx::query_scalar::<_, Vec<u8>>("SELECT blob FROM vault_items WHERE org_id = $1::uuid ORDER BY id")
        .bind(&org.id)
        .fetch_all(&org.pool)
        .await
        .unwrap()
}

async fn wrap_epoch(org: &Org, token: &str) -> Option<i64> {
    let org: serde_json::Value =
        org.server.get(&format!("/v1/organizations/{}", org.id)).authorization_bearer(token).await.json();
    org["wrapChain"][0]["keyEpoch"].as_i64()
}

/// Removing a member re-keys everything at epoch + 1 in one step: the member
/// is gone, every item is replaced, and the remaining members get new wraps.
#[sqlx::test(migrations = "src/db/migrations")]
async fn rotation_removes_the_member_and_rekeys_everything(pool: PgPool) {
    let org = setup(pool).await;
    let body = rotation(2, &[org.owner.user_id, org.bob.user_id], &org.items, Some(org.carol.user_id));
    org.server
        .post(&format!("/v1/organizations/{}/rotate", org.id))
        .authorization_bearer(&org.owner.session_token)
        .json(&body)
        .await
        .assert_status(StatusCode::NO_CONTENT);

    org.server
        .get(&format!("/v1/organizations/{}", org.id))
        .authorization_bearer(&org.carol.session_token)
        .await
        .assert_status(StatusCode::NOT_FOUND);
    assert_eq!(item_blobs(&org).await, vec![vec![0xbb_u8; 32]; 2]);
    assert_eq!(wrap_epoch(&org, &org.bob.session_token).await, Some(2));
    assert_eq!(wrap_epoch(&org, &org.owner.session_token).await, Some(2));
}

/// A rotation that misses an item, lists one twice, or misses a member
/// changes nothing at all.
#[sqlx::test(migrations = "src/db/migrations")]
async fn incomplete_rotations_change_nothing(pool: PgPool) {
    let org = setup(pool).await;
    let remaining = [org.owner.user_id, org.bob.user_id];
    let (i1, i2) = (org.items[0], org.items[1]);
    let attempts = [
        rotation(2, &remaining, &[i1], Some(org.carol.user_id)),
        rotation(2, &remaining, &[i1, i2, i2], Some(org.carol.user_id)),
        rotation(2, &[org.owner.user_id], &org.items, Some(org.carol.user_id)),
    ];
    for body in attempts {
        org.server
            .post(&format!("/v1/organizations/{}/rotate", org.id))
            .authorization_bearer(&org.owner.session_token)
            .json(&body)
            .await
            .assert_status(StatusCode::BAD_REQUEST);
    }

    assert_eq!(item_blobs(&org).await, vec![vec![0xaa_u8; 32]; 2]);
    assert_eq!(wrap_epoch(&org, &org.carol.session_token).await, Some(1), "carol must still be a member");
    assert_eq!(wrap_epoch(&org, &org.bob.session_token).await, Some(1));
}

/// Old-epoch material is refused once the org has moved on, and a member can
/// only leave through a rotation.
#[sqlx::test(migrations = "src/db/migrations")]
async fn old_epochs_and_bare_removals_are_refused(pool: PgPool) {
    let org = setup(pool).await;
    let everyone = [org.owner.user_id, org.bob.user_id, org.carol.user_id];
    let rotate = |body: serde_json::Value, token: &str| {
        org.server.post(&format!("/v1/organizations/{}/rotate", org.id)).authorization_bearer(token).json(&body)
    };

    rotate(rotation(2, &everyone, &org.items, None), &org.bob.session_token)
        .await
        .assert_status(StatusCode::FORBIDDEN);
    rotate(rotation(1, &everyone, &org.items, None), &org.owner.session_token)
        .await
        .assert_status(StatusCode::CONFLICT);
    rotate(rotation(2, &everyone, &org.items, None), &org.owner.session_token)
        .await
        .assert_status(StatusCode::NO_CONTENT);

    // Re-uploading a wrap signed for the retired epoch is refused
    org.server
        .put(&format!("/v1/organizations/{}/wraps", org.id))
        .authorization_bearer(&org.owner.session_token)
        .json(&serde_json::json!({ "wraps": [{
            "userId": org.bob.user_id, "encryptedOrgKey": B64.encode([1u8; 64]), "wrapSignature": sig(1), "keyEpoch": 1,
        }] }))
        .await
        .assert_status(StatusCode::BAD_REQUEST);
    assert_eq!(wrap_epoch(&org, &org.bob.session_token).await, Some(2));

    org.server
        .delete(&format!("/v1/organizations/{}/members/{}", org.id, org.carol.user_id))
        .authorization_bearer(&org.owner.session_token)
        .await
        .assert_status(StatusCode::CONFLICT);
}

/// An item the owner could not decrypt can be deleted as part of the
/// rotation instead of blocking it, but every item is still covered exactly
/// once: re-encrypted or deleted.
#[sqlx::test(migrations = "src/db/migrations")]
async fn rotation_can_delete_undecryptable_items_but_never_skip_them(pool: PgPool) {
    let org = setup(pool).await;
    let everyone = [org.owner.user_id, org.bob.user_id, org.carol.user_id];
    let (i1, i2) = (org.items[0], org.items[1]);
    let with_deletes = |items: &[Uuid], deletes: &[Uuid]| {
        let mut body = rotation(2, &everyone, items, None);
        body["deleteItemIds"] = serde_json::json!(deletes);
        body
    };
    let rotate = |body: serde_json::Value| {
        org.server
            .post(&format!("/v1/organizations/{}/rotate", org.id))
            .authorization_bearer(&org.owner.session_token)
            .json(&body)
    };

    rotate(with_deletes(&[i1, i2], &[i2])).await.assert_status(StatusCode::BAD_REQUEST);
    assert_eq!(item_blobs(&org).await.len(), 2);

    rotate(with_deletes(&[i1], &[i2])).await.assert_status(StatusCode::NO_CONTENT);
    assert_eq!(item_blobs(&org).await, vec![vec![0xbb_u8; 32]]);
}
