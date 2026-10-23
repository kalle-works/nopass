mod helpers;

use std::collections::BTreeSet;

use axum::http::StatusCode;
use helpers::{
    build_test_server, compute_email_hash, from_random_ip, insert_legacy_srp_user, login,
    login_from_ip, opaque_login_finish, opaque_login_start, opaque_registration, register_user,
    srp_login, srp_login_ok, srp_upgrade, stored_account_key, test_kdf,
};
use nopass_api::db::{
    pending::MAX_PENDING_LOGINS_PER_ACCOUNT,
    throttle::{PER_ACCOUNT, PER_NETWORK},
};
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
async fn srp_account_upgrades_with_a_fresh_srp_proof_and_loses_its_verifier(pool: PgPool) {
    let server = build_test_server(pool.clone());
    let user_id = insert_legacy_srp_user(&pool, EMAIL, PASSWORD).await;

    // The old account still logs in (after its email hash was keyed at startup)…
    let token = srp_login_ok(&server, EMAIL, PASSWORD).await.session.session_token;
    let other = srp_login_ok(&server, EMAIL, PASSWORD).await.session.session_token;

    // …and upgrades in that session, proving the password again.
    srp_upgrade(&server, &token, EMAIL, PASSWORD, PASSWORD).await.assert_status_ok();

    let (salt, verifier, has_record, has_key): (Option<Vec<u8>>, Option<Vec<u8>>, bool, bool) = sqlx::query_as(
        "SELECT srp_salt, srp_verifier, opaque_record IS NOT NULL, wrapped_account_key IS NOT NULL FROM users WHERE id = $1",
    )
    .bind(user_id)
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!((salt, verifier, has_record, has_key), (None, None, true, true));

    login(&server, EMAIL, PASSWORD).await;
    srp_login(&server, EMAIL, PASSWORD).await.assert_status(StatusCode::UNAUTHORIZED);
    // The upgrade replaced the credential, so other sessions are gone.
    server.get("/v1/vaults").authorization_bearer(&token).await.assert_status_ok();
    server.get("/v1/vaults").authorization_bearer(&other).await.assert_status(StatusCode::UNAUTHORIZED);
}

/// A stolen session token alone must not be enough to replace the login
/// credential of an account still on SRP.
#[sqlx::test(migrations = "src/db/migrations")]
async fn srp_upgrade_without_the_password_changes_nothing(pool: PgPool) {
    let server = build_test_server(pool.clone());
    insert_legacy_srp_user(&pool, EMAIL, PASSWORD).await;
    let token = srp_login_ok(&server, EMAIL, PASSWORD).await.session.session_token;

    srp_upgrade(&server, &token, EMAIL, "not the password", "attacker password")
        .await
        .assert_status(StatusCode::UNAUTHORIZED);

    srp_login_ok(&server, EMAIL, PASSWORD).await;
    assert!(opaque_login_start(&server, EMAIL, "attacker password").await.finish_request.is_none());
}

async fn start_from(server: &axum_test::TestServer, path: &str, ip: &str) -> axum_test::TestResponse {
    server
        .post(path)
        .add_header("x-forwarded-for", ip.to_string())
        .json(&json!({
            "emailHash": compute_email_hash(EMAIL),
            "startLoginRequest": "AAAA",
            "clientPublicA": "AAAA",
        }))
        .await
}

#[sqlx::test(migrations = "src/db/migrations")]
async fn a_stranger_trips_only_their_own_network_and_the_owner_still_logs_in(pool: PgPool) {
    let server = build_test_server(pool);
    register_user(&server, EMAIL, PASSWORD).await;

    // Same /24, different hosts: one location.
    for host in 0..PER_NETWORK.free {
        // Charged, then rejected as malformed — never throttled yet.
        start_from(&server, "/v1/auth/opaque/login/start", &format!("203.0.113.{host}"))
            .await
            .assert_status(StatusCode::BAD_REQUEST);
    }
    let blocked = start_from(&server, "/v1/auth/opaque/login/start", "203.0.113.200").await;
    blocked.assert_status(StatusCode::TOO_MANY_REQUESTS);
    assert!(blocked.headers().contains_key("retry-after"));
    // The SRP path shares the same counter.
    start_from(&server, "/v1/auth/srp/init", "203.0.113.201")
        .await
        .assert_status(StatusCode::TOO_MANY_REQUESTS);

    // The owner, elsewhere, is unaffected.
    login(&server, EMAIL, PASSWORD).await;
}

/// Registration attempts for an existing address are answered under a decoy
/// key, so they are no guessing oracle and nothing is charged to the account.
#[sqlx::test(migrations = "src/db/migrations")]
async fn registration_attempts_do_not_lock_out_an_existing_account(pool: PgPool) {
    let server = build_test_server(pool);
    register_user(&server, EMAIL, PASSWORD).await;

    for _ in 0..=PER_NETWORK.free {
        server
            .post("/v1/auth/opaque/register/start")
            .add_header("x-forwarded-for", "203.0.113.7")
            .json(&json!({ "emailHash": compute_email_hash(EMAIL), "registrationRequest": "AAAA" }))
            .await;
    }
    login_from_ip(&server, EMAIL, PASSWORD, "203.0.113.8").await.assert_status_ok();
}

/// Once the owner has logged in from a network, guesses from everywhere else
/// can exhaust the account-wide ceiling without locking that network out.
#[sqlx::test(migrations = "src/db/migrations")]
async fn the_owners_known_network_survives_the_account_wide_ceiling(pool: PgPool) {
    let server = build_test_server(pool);
    register_user(&server, EMAIL, PASSWORD).await;
    login_from_ip(&server, EMAIL, PASSWORD, "192.0.2.10").await.assert_status_ok();

    for n in 0..PER_ACCOUNT.free {
        start_from(&server, "/v1/auth/opaque/login/start", &format!("198.{}.{}.1", n / 256, n % 256))
            .await
            .assert_status(StatusCode::BAD_REQUEST);
    }
    start_from(&server, "/v1/auth/opaque/login/start", "198.51.100.1")
        .await
        .assert_status(StatusCode::TOO_MANY_REQUESTS);
    login_from_ip(&server, EMAIL, PASSWORD, "192.0.2.11").await.assert_status_ok();
}

#[sqlx::test(migrations = "src/db/migrations")]
async fn guesses_spread_over_networks_hit_the_account_wide_ceiling(pool: PgPool) {
    let server = build_test_server(pool);
    register_user(&server, EMAIL, PASSWORD).await;

    for n in 0..PER_ACCOUNT.free {
        start_from(&server, "/v1/auth/opaque/login/start", &format!("198.{}.{}.1", n / 256, n % 256))
            .await
            .assert_status(StatusCode::BAD_REQUEST);
    }
    start_from(&server, "/v1/auth/opaque/login/start", "192.0.2.1")
        .await
        .assert_status(StatusCode::TOO_MANY_REQUESTS);
}

#[sqlx::test(migrations = "src/db/migrations")]
async fn successful_logins_do_not_accumulate_toward_the_throttle(pool: PgPool) {
    let server = build_test_server(pool);
    register_user(&server, EMAIL, PASSWORD).await;
    for _ in 0..=PER_NETWORK.free {
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
