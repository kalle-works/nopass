mod helpers;

use std::collections::BTreeSet;

use axum::http::StatusCode;
use helpers::{
    build_test_server, compute_email_hash, from_random_ip, insert_legacy_srp_user, login,
    opaque_login_finish, opaque_login_start, opaque_registration, register_user, srp_login,
    srp_login_ok, stored_account_key, test_kdf,
};
use nopass_api::db::{pending::MAX_PENDING_LOGINS_PER_ACCOUNT, throttle::FREE_ATTEMPTS};
use serde_json::{json, Value};
use sqlx::PgPool;

const EMAIL: &str = "alice@example.com";
const PASSWORD: &str = "correct horse battery staple";

// ─── OPAQUE register + login ─────────────────────────────────────────────────

#[sqlx::test(migrations = "src/db/migrations")]
async fn opaque_register_then_login_opens_a_working_session(pool: PgPool) {
    let server = build_test_server(pool);
    register_user(&server, EMAIL, PASSWORD).await;

    let session = login(&server, EMAIL, PASSWORD).await;

    server
        .get("/v1/vaults")
        .authorization_bearer(&session.session_token)
        .await
        .assert_status_ok();
}

#[sqlx::test(migrations = "src/db/migrations")]
async fn wrong_password_cannot_complete_login(pool: PgPool) {
    let server = build_test_server(pool);
    register_user(&server, EMAIL, PASSWORD).await;

    let wrong = opaque_login_start(&server, EMAIL, "correct horse battery stapler").await;
    assert!(wrong.finish_request.is_none(), "client must reject the response for a wrong password");

    // Nor can a valid proof from another handshake be replayed onto this one.
    let other = opaque_login_start(&server, EMAIL, PASSWORD).await;
    opaque_login_finish(&server, wrong.login_id, &other.finish_request.unwrap())
        .await
        .assert_status(StatusCode::UNAUTHORIZED);
}

#[sqlx::test(migrations = "src/db/migrations")]
async fn duplicate_registration_returns_409(pool: PgPool) {
    let server = build_test_server(pool);
    register_user(&server, EMAIL, PASSWORD).await;

    let record = opaque_registration(&server, "/v1/auth/opaque/register/start", None, json!({}), EMAIL, "other").await;
    from_random_ip(server.post("/v1/auth/opaque/register/finish").json(&json!({
        "emailHash": compute_email_hash(EMAIL),
        "registrationRecord": record,
        "kdfParams": test_kdf(),
        "protectedSymmetricKey": "AAAA",
        "protectedSymmetricKeyIv": "AAAA",
    })))
    .await
    .assert_status(StatusCode::CONFLICT);

    // The original password still works.
    login(&server, EMAIL, PASSWORD).await;
}

#[sqlx::test(migrations = "src/db/migrations")]
async fn srp_registration_is_gone(pool: PgPool) {
    let server = build_test_server(pool);
    server
        .post("/v1/auth/register")
        .json(&json!({}))
        .await
        .assert_status(StatusCode::GONE);
}

// ─── Enumeration ─────────────────────────────────────────────────────────────

/// Every field name and the lengths of the opaque values — what an observer
/// can compare without the password.
fn shape(v: &Value) -> (BTreeSet<String>, usize, Value) {
    let keys = v.as_object().unwrap().keys().cloned().collect();
    (keys, v["loginResponse"].as_str().unwrap().len(), v["kdfParams"].clone())
}

#[sqlx::test(migrations = "src/db/migrations")]
async fn login_start_looks_the_same_for_known_unknown_and_unmigrated_accounts(pool: PgPool) {
    let server = build_test_server(pool.clone());
    register_user(&server, EMAIL, PASSWORD).await;
    insert_legacy_srp_user(&pool, "legacy@example.com", PASSWORD).await;

    let mut shapes = Vec::new();
    for email in [EMAIL, "nobody@example.com", "legacy@example.com"] {
        let started = opaque_login_start(&server, email, "some guess").await;
        shapes.push(shape(&serde_json::to_value(&started.response).unwrap()));
        // A finish attempt fails identically too.
        if let Some(finish) = started.finish_request {
            panic!("guess unexpectedly accepted for {email}: {finish}");
        }
    }
    // Registered accounts with the default parameters are the only case kdfParams can't hide.
    for s in &mut shapes {
        s.2 = Value::Null;
    }
    assert_eq!(shapes[0], shapes[1], "unknown account distinguishable from known");
    assert_eq!(shapes[0], shapes[2], "unmigrated account distinguishable from known");

    // The SRP fallback can't be used as an oracle either: unknown and
    // already-migrated accounts get a 200 challenge, and verify fails with
    // the same 401 a wrong password gets.
    let unknown = srp_login(&server, "nobody@example.com", PASSWORD).await;
    let migrated = srp_login(&server, EMAIL, PASSWORD).await;
    let wrong = srp_login(&server, "legacy@example.com", "wrong").await;
    for resp in [&unknown, &migrated, &wrong] {
        resp.assert_status(StatusCode::UNAUTHORIZED);
    }
    assert_eq!(unknown.json::<Value>(), wrong.json::<Value>());
    assert_eq!(migrated.json::<Value>(), wrong.json::<Value>());
}

// ─── SRP → OPAQUE migration ──────────────────────────────────────────────────

#[sqlx::test(migrations = "src/db/migrations")]
async fn srp_account_migrates_to_opaque_and_loses_its_verifier(pool: PgPool) {
    let server = build_test_server(pool.clone());
    let user_id = insert_legacy_srp_user(&pool, EMAIL, PASSWORD).await;

    // The old account still logs in (after its email hash was keyed at startup)…
    let srp = srp_login_ok(&server, EMAIL, PASSWORD).await;
    let token = srp.session.session_token;

    // …and re-registers with OPAQUE inside that session.
    let record = opaque_registration(&server, "/v1/auth/opaque/reregister/start", Some(&token), json!({}), EMAIL, PASSWORD).await;
    server
        .post("/v1/auth/opaque/reregister/finish")
        .authorization_bearer(&token)
        .json(&json!({ "registrationRecord": record }))
        .await
        .assert_status(StatusCode::NO_CONTENT);

    let (salt, verifier, has_record): (Option<Vec<u8>>, Option<Vec<u8>>, bool) = sqlx::query_as(
        "SELECT srp_salt, srp_verifier, opaque_record IS NOT NULL FROM users WHERE id = $1",
    )
    .bind(user_id)
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!((salt, verifier, has_record), (None, None, true));

    login(&server, EMAIL, PASSWORD).await;
    srp_login(&server, EMAIL, PASSWORD).await.assert_status(StatusCode::UNAUTHORIZED);
}

#[sqlx::test(migrations = "src/db/migrations")]
async fn reregister_needs_a_fresh_session(pool: PgPool) {
    let server = build_test_server(pool.clone());
    insert_legacy_srp_user(&pool, EMAIL, PASSWORD).await;
    let token = srp_login_ok(&server, EMAIL, PASSWORD).await.session.session_token;

    // A token stolen later must not be enough to replace the password.
    sqlx::query("UPDATE sessions SET created_at = NOW() - INTERVAL '1 hour'")
        .execute(&pool)
        .await
        .unwrap();

    server
        .post("/v1/auth/opaque/reregister/start")
        .authorization_bearer(&token)
        .json(&json!({ "emailHash": compute_email_hash(EMAIL), "registrationRequest": "AAAA" }))
        .await
        .assert_status(StatusCode::FORBIDDEN);
}

// ─── Throttling and pending-login bounds ─────────────────────────────────────

#[sqlx::test(migrations = "src/db/migrations")]
async fn per_account_throttle_trips_across_ips_and_spares_other_accounts(pool: PgPool) {
    let server = build_test_server(pool);
    register_user(&server, EMAIL, PASSWORD).await;

    // Every request comes from a different IP, so only the account key ties them together.
    for _ in 0..FREE_ATTEMPTS {
        opaque_login_start(&server, EMAIL, "guess").await;
    }
    let blocked = from_random_ip(server.post("/v1/auth/opaque/login/start").json(&json!({
        "emailHash": compute_email_hash(EMAIL),
        "startLoginRequest": "AAAA",
    })))
    .await;
    blocked.assert_status(StatusCode::TOO_MANY_REQUESTS);
    assert!(blocked.headers().contains_key("retry-after"));

    // The SRP path shares the same counter.
    from_random_ip(server.post("/v1/auth/srp/init").json(&json!({
        "emailHash": compute_email_hash(EMAIL),
        "clientPublicA": "AAAA",
    })))
    .await
    .assert_status(StatusCode::TOO_MANY_REQUESTS);

    register_user(&server, "bob@example.com", PASSWORD).await;
    login(&server, "bob@example.com", PASSWORD).await;
}

#[sqlx::test(migrations = "src/db/migrations")]
async fn successful_logins_do_not_accumulate_toward_the_throttle(pool: PgPool) {
    let server = build_test_server(pool);
    register_user(&server, EMAIL, PASSWORD).await;
    for _ in 0..=FREE_ATTEMPTS {
        login(&server, EMAIL, PASSWORD).await;
    }
}

#[sqlx::test(migrations = "src/db/migrations")]
async fn pending_logins_are_capped_per_account(pool: PgPool) {
    let server = build_test_server(pool.clone());
    for _ in 0..MAX_PENDING_LOGINS_PER_ACCOUNT + 3 {
        opaque_login_start(&server, "nobody@example.com", "guess").await;
    }
    let (count,): (i64,) = sqlx::query_as("SELECT COUNT(*) FROM pending_opaque_logins WHERE account_key = $1")
        .bind(stored_account_key("nobody@example.com"))
        .fetch_one(&pool)
        .await
        .unwrap();
    assert_eq!(count, MAX_PENDING_LOGINS_PER_ACCOUNT);
}

// ─── Logout ───────────────────────────────────────────────────────────────────

#[sqlx::test(migrations = "src/db/migrations")]
async fn logout_invalidates_session(pool: PgPool) {
    let server = build_test_server(pool);
    register_user(&server, EMAIL, PASSWORD).await;
    let session = login(&server, EMAIL, PASSWORD).await;

    server
        .post("/v1/auth/logout")
        .authorization_bearer(&session.session_token)
        .await
        .assert_status(StatusCode::NO_CONTENT);

    server
        .post("/v1/auth/logout")
        .authorization_bearer(&session.session_token)
        .await
        .assert_status(StatusCode::UNAUTHORIZED);
}
