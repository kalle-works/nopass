#![allow(dead_code)] // each test binary uses a different subset

use axum::http::StatusCode;
use axum_test::{TestRequest, TestServer};
use base64::{
    engine::general_purpose::{STANDARD as B64, URL_SAFE_NO_PAD as B64URL},
    Engine,
};
use nopass_api::{
    build_router,
    config::{Config, SecretBytes},
    state::{account_key, AppState},
};
use nopass_crypto::{
    opaque::{self, Suite},
    Argon2Params,
};
use nopass_models::{
    KdfParams, LoginResponse, OpaqueLoginStartResponse, OpaqueRegisterStartResponse,
    SrpInitRequest, SrpVerifyRequest, SrpVerifyResponse,
};
use opaque_ke::{
    ClientLogin, ClientLoginFinishParameters, ClientRegistration,
    ClientRegistrationFinishParameters, CredentialResponse, RegistrationResponse,
};
use rand::{rngs::OsRng, Rng, RngCore};
use sha2::Sha256;
use sqlx::PgPool;
use srp::{client::SrpClient, groups::G_2048};

pub const EMAIL_LOOKUP_KEY: [u8; 32] = [7u8; 32];

/// Cheapest Argon2id the API accepts — keeps tests fast; the KSF plumbing is
/// identical at any cost.
pub fn test_kdf() -> KdfParams {
    KdfParams { kdf_type: "argon2id".into(), memory_kib: 19_456, iterations: 1, parallelism: 1 }
}

pub fn test_config() -> Config {
    Config {
        database_url: String::new(), // pool is injected directly in sqlx::test
        host: "127.0.0.1".into(),
        port: 3001,
        allowed_origins: vec!["http://localhost:3000".into()],
        // Lets helpers spread auth requests over X-Forwarded-For addresses so
        // the per-IP limiter doesn't interfere with what a test is measuring.
        trusted_proxies: vec!["127.0.0.1/32".parse().unwrap()],
        auth_rate_limit_per_minute: 60,
        opaque_server_setup: SecretBytes(opaque::generate_server_setup()),
        email_lookup_key: SecretBytes(EMAIL_LOOKUP_KEY.to_vec()),
        stripe_secret_key: None,
        stripe_webhook_secret: None,
        stripe_pro_monthly_price_id: None,
        stripe_pro_annual_price_id: None,
        stripe_teams_price_id: None,
    }
}

pub fn build_test_server(pool: PgPool) -> TestServer {
    let state = AppState::new(pool, test_config());
    let router = build_router(state);
    TestServer::new(router)
}

/// Attach a random client IP (honoured because 127.0.0.1 is a trusted proxy).
pub fn from_random_ip(req: TestRequest) -> TestRequest {
    let mut rng = rand::thread_rng();
    let ip = format!("10.{}.{}.{}", rng.gen::<u8>(), rng.gen::<u8>(), rng.gen::<u8>());
    req.add_header("x-forwarded-for", ip)
}

pub fn compute_email_hash(email: &str) -> String {
    use sha2::Digest;
    let input = format!("nopass-v1-email:{}", email.to_lowercase());
    let hash = Sha256::digest(input.as_bytes());
    hex::encode(hash)
}

/// The keyed hash the users table stores for `email`.
pub fn stored_account_key(email: &str) -> String {
    account_key(&EMAIL_LOOKUP_KEY, &compute_email_hash(email))
}

fn ksf(params: &KdfParams) -> argon2::Argon2<'static> {
    opaque::ksf(&Argon2Params {
        memory_kib: params.memory_kib,
        iterations: params.iterations,
        parallelism: params.parallelism,
    })
    .unwrap()
}

/// Client side of OPAQUE registration against `start_path`; returns the
/// upload (registration record) to send to the matching finish route.
pub async fn opaque_registration(
    server: &TestServer,
    start_path: &str,
    token: Option<&str>,
    extra: serde_json::Value,
    email: &str,
    password: &str,
) -> String {
    let client = ClientRegistration::<Suite>::start(&mut OsRng, password.as_bytes()).unwrap();
    let mut body = serde_json::json!({
        "emailHash": compute_email_hash(email),
        "registrationRequest": B64URL.encode(client.message.serialize()),
    });
    body.as_object_mut().unwrap().extend(extra.as_object().unwrap().clone());

    let mut req = from_random_ip(server.post(start_path).json(&body));
    if let Some(token) = token {
        req = req.authorization_bearer(token);
    }
    let resp = req.await;
    resp.assert_status_ok();
    let start: OpaqueRegisterStartResponse = resp.json();

    let finished = client
        .state
        .finish(
            &mut OsRng,
            password.as_bytes(),
            RegistrationResponse::deserialize(&B64URL.decode(start.registration_response).unwrap())
                .unwrap(),
            ClientRegistrationFinishParameters::new(Default::default(), Some(&ksf(&test_kdf()))),
        )
        .unwrap();
    B64URL.encode(finished.message.serialize())
}

/// Registers a new OPAQUE account.
pub async fn register_user(server: &TestServer, email: &str, password: &str) {
    let record = opaque_registration(server, "/v1/auth/opaque/register/start", None, serde_json::json!({}), email, password).await;
    from_random_ip(server.post("/v1/auth/opaque/register/finish").json(&serde_json::json!({
        "emailHash": compute_email_hash(email),
        "registrationRecord": record,
        "kdfParams": test_kdf(),
        "protectedSymmetricKey": B64.encode([0u8; 32]), // placeholder for tests
        "protectedSymmetricKeyIv": B64.encode([0u8; 12]),
    })))
    .await
    .assert_status(StatusCode::CREATED);
}

pub struct StartedLogin {
    pub login_id: uuid::Uuid,
    pub response: OpaqueLoginStartResponse,
    /// The client's finish message, or None if the client rejected the server
    /// response (wrong password, unknown or unmigrated account).
    pub finish_request: Option<String>,
}

pub async fn opaque_login_start(server: &TestServer, email: &str, password: &str) -> StartedLogin {
    let client = ClientLogin::<Suite>::start(&mut OsRng, password.as_bytes()).unwrap();
    let resp = from_random_ip(server.post("/v1/auth/opaque/login/start").json(&serde_json::json!({
        "emailHash": compute_email_hash(email),
        "startLoginRequest": B64URL.encode(client.message.serialize()),
    })))
    .await;
    resp.assert_status_ok();
    let response: OpaqueLoginStartResponse = resp.json();

    let finish_request = client
        .state
        .finish(
            &mut OsRng,
            password.as_bytes(),
            CredentialResponse::deserialize(&B64URL.decode(&response.login_response).unwrap()).unwrap(),
            ClientLoginFinishParameters::new(None, Default::default(), Some(&ksf(&response.kdf_params))),
        )
        .ok()
        .map(|f| B64URL.encode(f.message.serialize()));

    StartedLogin { login_id: response.login_id, response, finish_request }
}

pub async fn opaque_login_finish(server: &TestServer, login_id: uuid::Uuid, finish_request: &str) -> axum_test::TestResponse {
    from_random_ip(server.post("/v1/auth/opaque/login/finish").json(&serde_json::json!({
        "loginId": login_id,
        "finishLoginRequest": finish_request,
    })))
    .await
}

/// Completes an OPAQUE login; panics if it fails.
pub async fn login(server: &TestServer, email: &str, password: &str) -> LoginResponse {
    let started = opaque_login_start(server, email, password).await;
    let finish = started.finish_request.expect("client rejected the login response");
    let resp = opaque_login_finish(server, started.login_id, &finish).await;
    resp.assert_status_ok();
    resp.json()
}

/// A pre-OPAQUE account exactly as the old API stored it: SRP verifier and
/// the client's raw email hash. Runs the startup keying step afterwards, as
/// the API does on boot.
pub async fn insert_legacy_srp_user(pool: &PgPool, email: &str, password: &str) -> uuid::Uuid {
    let (salt, verifier) = generate_srp_verifier(email, password);
    let (id,): (uuid::Uuid,) = sqlx::query_as(
        r#"
        INSERT INTO users (email_hash, srp_salt, srp_verifier, kdf_params,
                           protected_symmetric_key, protected_symmetric_key_iv)
        VALUES ($1, $2, $3, $4, $5, $6) RETURNING id
        "#,
    )
    .bind(compute_email_hash(email))
    .bind(&salt)
    .bind(&verifier)
    .bind(serde_json::to_value(test_kdf()).unwrap())
    .bind([0u8; 32].as_slice())
    .bind([0u8; 12].as_slice())
    .fetch_one(pool)
    .await
    .unwrap();
    sqlx::query("INSERT INTO vaults (user_id, name_blob, name_iv) VALUES ($1, 'default', '000000000000')")
        .bind(id)
        .execute(pool)
        .await
        .unwrap();

    nopass_api::db::auth::key_email_hashes(pool, |h| account_key(&EMAIL_LOOKUP_KEY, h))
        .await
        .unwrap();
    id
}

/// Legacy SRP login as old clients do it; returns the raw verify response.
pub async fn srp_login(server: &TestServer, email: &str, password: &str) -> axum_test::TestResponse {
    let client = SrpClient::<Sha256>::new(&G_2048);
    let mut a_bytes = [0u8; 64];
    rand::thread_rng().fill_bytes(&mut a_bytes);
    let client_public_a = client.compute_public_ephemeral(&a_bytes);

    let init_resp = from_random_ip(server.post("/v1/auth/srp/init").json(&SrpInitRequest {
        email_hash: compute_email_hash(email),
        client_public_a: B64.encode(&client_public_a),
    }))
    .await;
    init_resp.assert_status_ok();
    let init: nopass_models::SrpInitResponse = init_resp.json();

    let server_public_b = B64.decode(&init.server_public_b).unwrap();
    let salt = B64.decode(&init.srp_salt).unwrap();
    let verifier = client
        .process_reply(&a_bytes, email.as_bytes(), password.as_bytes(), &salt, &server_public_b)
        .expect("SRP client process_reply failed");

    from_random_ip(server.post("/v1/auth/srp/verify").json(&SrpVerifyRequest {
        session_id: init.session_id,
        client_proof_m1: B64.encode(verifier.proof()),
        device_id: None,
    }))
    .await
}

pub async fn srp_login_ok(server: &TestServer, email: &str, password: &str) -> SrpVerifyResponse {
    let resp = srp_login(server, email, password).await;
    resp.assert_status_ok();
    resp.json()
}

pub fn generate_srp_verifier(email: &str, password: &str) -> (Vec<u8>, Vec<u8>) {
    let client = SrpClient::<Sha256>::new(&G_2048);
    let mut salt = vec![0u8; 16];
    rand::thread_rng().fill_bytes(&mut salt);
    let verifier = client.compute_verifier(email.as_bytes(), password.as_bytes(), &salt);
    (salt, verifier)
}

/// A fresh password proof for `token`'s account (`/auth/proof/start` plus the
/// client's OPAQUE finalization), as the JSON object endpoints accept. With a
/// wrong password the client can't finish, so this returns a proof built from
/// a different handshake — which the server must refuse.
pub async fn password_proof(
    server: &TestServer,
    token: &str,
    email: &str,
    password: &str,
    purpose: &str,
) -> serde_json::Value {
    let client = ClientLogin::<Suite>::start(&mut OsRng, password.as_bytes()).unwrap();
    let resp = from_random_ip(server.post("/v1/auth/proof/start").authorization_bearer(token).json(&serde_json::json!({
        "emailHash": compute_email_hash(email),
        "startLoginRequest": B64URL.encode(client.message.serialize()),
        "purpose": purpose,
    })))
    .await;
    resp.assert_status_ok();
    let start: serde_json::Value = resp.json();
    let finish = client
        .state
        .finish(
            &mut OsRng,
            password.as_bytes(),
            CredentialResponse::deserialize(&B64URL.decode(start["loginResponse"].as_str().unwrap()).unwrap()).unwrap(),
            ClientLoginFinishParameters::new(None, Default::default(), Some(&ksf(&test_kdf()))),
        )
        .map(|f| B64URL.encode(f.message.serialize()))
        .unwrap_or_else(|_| B64URL.encode([0u8; 64]));
    serde_json::json!({ "proofId": start["proofId"], "finishLoginRequest": finish })
}

/// SRP → OPAQUE upgrade as the client runs it in `token`'s session: a fresh
/// SRP proof with `srp_password` and an OPAQUE registration for `password`.
pub async fn srp_upgrade(server: &TestServer, token: &str, email: &str, srp_password: &str, password: &str) -> axum_test::TestResponse {
    let srp = SrpClient::<Sha256>::new(&G_2048);
    let mut a = [0u8; 64];
    rand::thread_rng().fill_bytes(&mut a);
    let reg = ClientRegistration::<Suite>::start(&mut OsRng, password.as_bytes()).unwrap();
    let resp = from_random_ip(server.post("/v1/auth/upgrade/start").authorization_bearer(token).json(&serde_json::json!({
        "emailHash": compute_email_hash(email),
        "clientPublicA": B64.encode(srp.compute_public_ephemeral(&a)),
        "registrationRequest": B64URL.encode(reg.message.serialize()),
    })))
    .await;
    resp.assert_status_ok();
    let start: serde_json::Value = resp.json();
    let b64 = |k: &str| B64.decode(start[k].as_str().unwrap()).unwrap();
    let proof = srp
        .process_reply(&a, email.as_bytes(), srp_password.as_bytes(), &b64("srpSalt"), &b64("serverPublicB"))
        .unwrap()
        .proof()
        .to_vec();
    let record = reg
        .state
        .finish(
            &mut OsRng,
            password.as_bytes(),
            RegistrationResponse::deserialize(&B64URL.decode(start["registrationResponse"].as_str().unwrap()).unwrap())
                .unwrap(),
            ClientRegistrationFinishParameters::new(Default::default(), Some(&ksf(&test_kdf()))),
        )
        .unwrap()
        .message
        .serialize();
    from_random_ip(server.post("/v1/auth/upgrade/finish").authorization_bearer(token).json(&serde_json::json!({
        "upgradeId": start["upgradeId"],
        "clientProofM1": B64.encode(proof),
        "registrationRecord": B64URL.encode(record),
        "wrappedAccountKey": B64.encode([5u8; 80]),
        "wrappedAccountKeyIv": B64.encode([5u8; 12]),
    })))
    .await
}

/// Full OPAQUE login from a fixed client IP; returns the finish response.
pub async fn login_from_ip(server: &TestServer, email: &str, password: &str, ip: &str) -> axum_test::TestResponse {
    let client = ClientLogin::<Suite>::start(&mut OsRng, password.as_bytes()).unwrap();
    let resp = server
        .post("/v1/auth/opaque/login/start")
        .add_header("x-forwarded-for", ip.to_string())
        .json(&serde_json::json!({
            "emailHash": compute_email_hash(email),
            "startLoginRequest": B64URL.encode(client.message.serialize()),
        }))
        .await;
    if resp.status_code() != StatusCode::OK {
        return resp;
    }
    let start: OpaqueLoginStartResponse = resp.json();
    let finish = client
        .state
        .finish(
            &mut OsRng,
            password.as_bytes(),
            CredentialResponse::deserialize(&B64URL.decode(&start.login_response).unwrap()).unwrap(),
            ClientLoginFinishParameters::new(None, Default::default(), Some(&ksf(&start.kdf_params))),
        )
        .unwrap();
    server
        .post("/v1/auth/opaque/login/finish")
        .add_header("x-forwarded-for", ip.to_string())
        .json(&serde_json::json!({
            "loginId": start.login_id,
            "finishLoginRequest": B64URL.encode(finish.message.serialize()),
        }))
        .await
}
