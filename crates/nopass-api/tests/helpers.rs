use axum::http::StatusCode;
use axum_test::TestServer;
use base64::{engine::general_purpose::STANDARD as B64, Engine};
use nopass_api::{build_router, config::Config, state::AppState};
use nopass_models::{KdfParams, RegisterRequest, SrpInitRequest, SrpVerifyRequest, SrpVerifyResponse};
use rand::RngCore;
use sha2::Sha256;
use sqlx::PgPool;
use srp::{client::SrpClient, groups::G_2048};

pub fn test_config() -> Config {
    Config {
        database_url: String::new(), // pool is injected directly in sqlx::test
        host: "127.0.0.1".into(),
        port: 3001,
        allowed_origins: vec!["http://localhost:3000".into()],
        trusted_proxies: vec![],
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

/// Registers a new user and returns the email_hash used.
pub async fn register_user(server: &TestServer, email: &str, password: &str) {
    let email_hash = compute_email_hash(email);
    let (srp_salt, srp_verifier) = generate_srp_verifier(email, password);

    let req = RegisterRequest {
        email_hash,
        srp_salt: B64.encode(&srp_salt),
        srp_verifier: B64.encode(&srp_verifier),
        kdf_params: KdfParams::default(),
        protected_symmetric_key: B64.encode(&[0u8; 32]), // placeholder for tests
        protected_symmetric_key_iv: B64.encode(&[0u8; 12]),
        public_key: None,
        protected_private_key: None,
        protected_private_key_iv: None,
    };

    server
        .post("/v1/auth/register")
        .json(&req)
        .await
        .assert_status(StatusCode::CREATED);
}

/// Completes the SRP login flow and returns the SrpVerifyResponse.
pub async fn login(server: &TestServer, email: &str, password: &str) -> SrpVerifyResponse {
    let email_hash = compute_email_hash(email);
    let (srp_salt, _srp_verifier) = generate_srp_verifier(email, password);

    let client = SrpClient::<Sha256>::new(&G_2048);

    let mut a_bytes = [0u8; 64];
    rand::thread_rng().fill_bytes(&mut a_bytes);
    let client_public_a = client.compute_public_ephemeral(&a_bytes);

    // Step 1
    let init_resp: nopass_models::SrpInitResponse = server
        .post("/v1/auth/srp/init")
        .json(&SrpInitRequest {
            email_hash: email_hash.clone(),
            client_public_a: B64.encode(&client_public_a),
        })
        .await
        .json();

    let server_public_b = B64.decode(&init_resp.server_public_b).unwrap();
    let stored_salt = B64.decode(&init_resp.srp_salt).unwrap();

    // Step 2
    let client_verifier = client
        .process_reply(&a_bytes, email.as_bytes(), password.as_bytes(), &stored_salt, &server_public_b)
        .expect("SRP client process_reply failed");

    let client_proof = client_verifier.proof();
    let verify_resp: SrpVerifyResponse = server
        .post("/v1/auth/srp/verify")
        .json(&SrpVerifyRequest {
            session_id: init_resp.session_id,
            client_proof_m1: B64.encode(client_proof),
            device_id: None,
        })
        .await
        .json();

    verify_resp
}

pub fn compute_email_hash(email: &str) -> String {
    use sha2::Digest;
    let input = format!("nopass-v1-email:{}", email.to_lowercase());
    let hash = Sha256::digest(input.as_bytes());
    hex::encode(hash)
}

pub fn generate_srp_verifier(email: &str, password: &str) -> (Vec<u8>, Vec<u8>) {
    let client = SrpClient::<Sha256>::new(&G_2048);
    let mut salt = vec![0u8; 16];
    rand::thread_rng().fill_bytes(&mut salt);
    let verifier = client.compute_verifier(email.as_bytes(), password.as_bytes(), &salt);
    (salt, verifier)
}
