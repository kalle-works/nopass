use std::net::IpAddr;

use axum::{extract::State, http::StatusCode, routing::post, Extension, Json, Router};
use base64::{
    engine::general_purpose::{STANDARD as B64, URL_SAFE_NO_PAD as B64URL},
    Engine,
};
use hmac::{Hmac, Mac};
use nopass_crypto::{
    opaque,
    srp::{srp_server_init, srp_server_verify},
};
use nopass_models::{
    KdfParams, LoginResponse, OpaqueLoginFinishRequest, OpaqueLoginStartRequest,
    OpaqueLoginStartResponse, OpaqueRegisterFinishRequest, OpaqueRegisterStartRequest,
    OpaqueRegisterStartResponse, OpaqueReregisterFinishRequest, RegisterResponse, SetAccountKeyRequest,
    SrpInitRequest,
    SrpInitResponse, SrpVerifyRequest, SrpVerifyResponse,
};
use rand::RngCore;
use sha2::Sha256;
use uuid::Uuid;

use crate::{
    db::{
        activity, auth as db_auth, devices as db_devices, pending, sessions, throttle,
        vaults as db_vaults,
    },
    error::{ApiError, ApiResult},
    middleware::auth::AuthUser,
    models::user::User,
    routes::ClientIp,
    state::{AppState, OPAQUE_LOGIN_TTL_SECS, SRP_SESSION_TTL_SECS},
};

/// Re-registration replaces the account's login credential, so a stolen
/// session token must not be enough on its own: the session has to come from
/// a login moments ago (the SRP → OPAQUE migration runs right after login).
const REREGISTER_MAX_SESSION_AGE_SECS: i64 = 10 * 60;

pub fn public_router() -> Router<AppState> {
    Router::new()
        .route("/register", post(legacy_register))
        .route("/opaque/register/start", post(register_start))
        .route("/opaque/register/finish", post(register_finish))
        .route("/opaque/login/start", post(login_start))
        .route("/opaque/login/finish", post(login_finish))
        .route("/srp/init", post(srp_init))
        .route("/srp/verify", post(srp_verify))
}

pub fn protected_router() -> Router<AppState> {
    Router::new()
        .route("/logout", post(logout))
        .route("/opaque/reregister/start", post(reregister_start))
        .route("/opaque/reregister/finish", post(reregister_finish))
        .route("/account-key", axum::routing::put(set_account_key))
}

/// Same message for every credential failure so responses don't tell an
/// unknown account from a wrong password or an expired handshake.
fn auth_failed() -> ApiError {
    ApiError::Unauthorized("authentication failed".into())
}

/// The client email hash is hex SHA-256; normalising it matters because it is
/// both the lookup input and the OPAQUE credential identifier.
pub(crate) fn parse_email_hash(email_hash: &str) -> ApiResult<String> {
    if email_hash.len() != 64 || !email_hash.bytes().all(|b| b.is_ascii_hexdigit()) {
        return Err(ApiError::BadRequest("emailHash must be 64 hex characters".into()));
    }
    Ok(email_hash.to_ascii_lowercase())
}

pub(crate) fn decode_opaque(value: &str, field: &str) -> ApiResult<Vec<u8>> {
    B64URL
        .decode(value)
        .map_err(|_| ApiError::BadRequest(format!("invalid {field} base64url")))
}

fn decode_b64(value: &str, field: &str) -> ApiResult<Vec<u8>> {
    B64.decode(value)
        .map_err(|_| ApiError::BadRequest(format!("invalid {field} base64")))
}

/// Short pseudonymous handle for logs: a prefix of the keyed account key, so
/// it can't be reversed to an email without the server secret.
fn log_handle(account_key: &str) -> &str {
    &account_key[..12.min(account_key.len())]
}

/// The client's network: /24 for IPv4, /64 for IPv6 — what one attacker
/// location typically controls.
fn network_of(ip: IpAddr) -> String {
    match ip {
        IpAddr::V4(v4) => {
            let [a, b, c, _] = v4.octets();
            format!("{a}.{b}.{c}.0/24")
        }
        IpAddr::V6(v6) => {
            let s = v6.segments();
            format!("{:x}:{:x}:{:x}:{:x}::/64", s[0], s[1], s[2], s[3])
        }
    }
}

fn throttle_keys(account_key: &str, client_ip: IpAddr) -> (String, &str) {
    (format!("{account_key}|{}", network_of(client_ip)), account_key)
}

/// Count this start against the account — once for the client's network and
/// once account-wide — and refuse it while either is backed off. A stranger
/// on another network only ever moves the account-wide counter, whose
/// ceiling is ten times higher.
pub(crate) async fn throttle_account(state: &AppState, account_key: &str, client_ip: IpAddr) -> ApiResult<()> {
    let (network_key, account_wide) = throttle_keys(account_key, client_ip);
    for (key, policy, scope) in [
        (network_key.as_str(), throttle::PER_NETWORK, "network"),
        (account_wide, throttle::PER_ACCOUNT, "account"),
    ] {
        match throttle::record_attempt(&state.db, key, policy).await? {
            throttle::Attempt::Allowed { failures } => {
                if failures >= policy.free {
                    tracing::warn!(
                        event = "login_backoff",
                        scope,
                        account = log_handle(account_key),
                        failures,
                        ip = %client_ip,
                        "account entered login backoff"
                    );
                }
            }
            throttle::Attempt::Locked { retry_after_secs } => {
                tracing::warn!(
                    event = "login_throttled",
                    scope,
                    account = log_handle(account_key),
                    retry_after_secs,
                    ip = %client_ip,
                    "login attempt rejected by per-account backoff"
                );
                return Err(ApiError::Throttled { retry_after_secs });
            }
        }
    }
    Ok(())
}

/// A successful proof clears the backoff for this network and account-wide.
pub(crate) async fn reset_throttle(state: &AppState, account_key: &str, client_ip: IpAddr) -> ApiResult<()> {
    let (network_key, account_wide) = throttle_keys(account_key, client_ip);
    throttle::reset(&state.db, &[network_key.as_str(), account_wide]).await?;
    Ok(())
}

pub(crate) async fn record_login_failure(state: &AppState, user_id: Option<Uuid>, account_key: &str, method: &str, client_ip: IpAddr) {
    crate::metrics::record_login_failure();
    tracing::warn!(
        event = "login_failed",
        method,
        account = log_handle(account_key),
        ip = %client_ip,
        "login proof rejected"
    );
    if let Some(user_id) = user_id {
        activity::record(&state.db, user_id, "login_failed", Some(&client_ip.to_string()), None).await;
    }
}

fn validate_kdf_params(params: &KdfParams) -> ApiResult<()> {
    // The client runs Argon2id with these on every login; reject values that
    // are too weak to protect a vault or too large for a browser to compute.
    let ok = params.kdf_type == "argon2id"
        && (19_456..=1_048_576).contains(&params.memory_kib)
        && (1..=10).contains(&params.iterations)
        && (1..=16).contains(&params.parallelism);
    if ok {
        Ok(())
    } else {
        Err(ApiError::BadRequest("unsupported kdfParams".into()))
    }
}

pub(crate) fn user_kdf_params(user: &User) -> ApiResult<KdfParams> {
    serde_json::from_value(user.kdf_params.clone()).map_err(|e| ApiError::Internal(e.into()))
}

/// SRP registration is gone: new accounts are OPAQUE-only.
async fn legacy_register() -> ApiResult<StatusCode> {
    Err(ApiError::Gone(
        "SRP registration is no longer supported — update the app to register".into(),
    ))
}

/// Registration round 1. Deliberately does not look the account up, so it
/// says nothing about whether the email is registered. It does count against
/// the account throttle: each call is an OPRF evaluation under the account's
/// key, which together with one login response is enough to test a guess.
async fn register_start(
    State(state): State<AppState>,
    Extension(ClientIp(client_ip)): Extension<ClientIp>,
    Json(req): Json<OpaqueRegisterStartRequest>,
) -> ApiResult<Json<OpaqueRegisterStartResponse>> {
    let email_hash = parse_email_hash(&req.email_hash)?;
    let request = decode_opaque(&req.registration_request, "registrationRequest")?;
    throttle_account(&state, &state.account_key(&email_hash), client_ip).await?;

    let response = opaque::registration_start(&state.opaque_setup, &request, email_hash.as_bytes())
        .map_err(|_| ApiError::BadRequest("invalid registrationRequest".into()))?;

    Ok(Json(OpaqueRegisterStartResponse {
        registration_response: B64URL.encode(response),
    }))
}

async fn register_finish(
    State(state): State<AppState>,
    Extension(ClientIp(client_ip)): Extension<ClientIp>,
    Json(req): Json<OpaqueRegisterFinishRequest>,
) -> ApiResult<(StatusCode, Json<RegisterResponse>)> {
    let email_hash = parse_email_hash(&req.email_hash)?;
    let upload = decode_opaque(&req.registration_record, "registrationRecord")?;
    let record = opaque::registration_finish(&upload)
        .map_err(|_| ApiError::BadRequest("invalid registrationRecord".into()))?;
    validate_kdf_params(&req.kdf_params)?;
    let protected_key = decode_b64(&req.protected_symmetric_key, "protected_symmetric_key")?;
    let protected_key_iv = decode_b64(&req.protected_symmetric_key_iv, "protected_symmetric_key_iv")?;
    let kdf_params = serde_json::to_value(&req.kdf_params).map_err(|e| ApiError::Internal(e.into()))?;

    let account_key = state.account_key(&email_hash);
    // A 409 here is the one place an existing account is revealed; without the
    // plaintext email the server can't send a "you already have an account"
    // mail instead. Registration is per-IP rate limited.
    let user = db_auth::create_user(
        &state.db,
        db_auth::NewUser {
            account_key: &account_key,
            opaque_record: &record,
            kdf_params,
            protected_symmetric_key: &protected_key,
            protected_symmetric_key_iv: &protected_key_iv,
            public_key: req.public_key.as_deref(),
            protected_private_key: req.protected_private_key.as_deref(),
            protected_private_key_iv: req.protected_private_key_iv.as_deref(),
        },
    )
    .await?
    .ok_or_else(|| ApiError::Conflict("email already registered".into()))?;

    reset_throttle(&state, &account_key, client_ip).await?;
    Ok((StatusCode::CREATED, Json(RegisterResponse { user_id: user.id })))
}

/// Login round 1. Unknown accounts and accounts still on SRP get opaque-ke's
/// fake record response — same status, shape and work as a real one.
async fn login_start(
    State(state): State<AppState>,
    Extension(ClientIp(client_ip)): Extension<ClientIp>,
    Json(req): Json<OpaqueLoginStartRequest>,
) -> ApiResult<Json<OpaqueLoginStartResponse>> {
    let email_hash = parse_email_hash(&req.email_hash)?;
    let request = decode_opaque(&req.start_login_request, "startLoginRequest")?;
    let account_key = state.account_key(&email_hash);
    throttle_account(&state, &account_key, client_ip).await?;

    let user = db_auth::find_user_by_account_key(&state.db, &account_key)
        .await?
        .filter(|u| u.opaque_record.is_some());
    let kdf_params = match &user {
        Some(u) => user_kdf_params(u)?,
        None => KdfParams::default(),
    };

    let started = opaque::login_start(
        &state.opaque_setup,
        user.as_ref().and_then(|u| u.opaque_record.as_deref()),
        &request,
        email_hash.as_bytes(),
    )
    .map_err(|_| ApiError::BadRequest("invalid startLoginRequest".into()))?;

    let login_id = Uuid::new_v4();
    pending::insert_opaque_login(&state.db, login_id, &account_key, user.as_ref().map(|u| u.id), &started.state)
        .await?;

    Ok(Json(OpaqueLoginStartResponse {
        login_id,
        login_response: B64URL.encode(started.response),
        kdf_params,
    }))
}

async fn login_finish(
    State(state): State<AppState>,
    Extension(ClientIp(client_ip)): Extension<ClientIp>,
    Json(req): Json<OpaqueLoginFinishRequest>,
) -> ApiResult<Json<LoginResponse>> {
    let finalization = decode_opaque(&req.finish_login_request, "finishLoginRequest")?;
    let Some(pending) = pending::take_opaque_login(&state.db, req.login_id).await? else {
        crate::metrics::record_login_failure();
        return Err(auth_failed());
    };
    if (chrono::Utc::now() - pending.created_at).num_seconds() > OPAQUE_LOGIN_TTL_SECS as i64 {
        return Err(auth_failed());
    }

    // Run the check even for fake records so the failure costs the same.
    let verified = opaque::login_finish(&pending.server_state, &finalization).is_ok();
    let Some(user_id) = pending.user_id.filter(|_| verified) else {
        record_login_failure(&state, pending.user_id, &pending.account_key, "opaque", client_ip).await;
        return Err(auth_failed());
    };

    let user = db_auth::get_user_by_id(&state.db, user_id)
        .await?
        .ok_or_else(auth_failed)?;
    reset_throttle(&state, &pending.account_key, client_ip).await?;
    Ok(Json(issue_session(&state, &user, req.device_id, client_ip).await?))
}

/// Fake SRP salt for accounts with no SRP verifier: stable per account so
/// repeated inits look like a real account's.
fn fake_srp_salt(state: &AppState, account_key: &str) -> Vec<u8> {
    let mut mac = Hmac::<Sha256>::new_from_slice(&state.config.email_lookup_key.0)
        .expect("HMAC accepts any key length");
    mac.update(b"nopass-fake-srp-salt:");
    mac.update(account_key.as_bytes());
    mac.finalize().into_bytes().to_vec()
}

/// Legacy SRP round 1, for accounts that haven't migrated yet. Unknown and
/// already-migrated accounts get a fake challenge whose verify always fails,
/// so clients can fall back here blindly after an OPAQUE failure without the
/// server revealing which accounts are still on SRP.
async fn srp_init(
    State(state): State<AppState>,
    Extension(ClientIp(client_ip)): Extension<ClientIp>,
    Json(req): Json<SrpInitRequest>,
) -> ApiResult<Json<SrpInitResponse>> {
    let email_hash = parse_email_hash(&req.email_hash)?;
    let client_public_a = B64.decode(&req.client_public_a)
        .map_err(|_| ApiError::BadRequest("invalid client_public_a".into()))?;
    if client_public_a.is_empty() {
        return Err(ApiError::BadRequest("client_public_a must not be empty".into()));
    }

    let account_key = state.account_key(&email_hash);
    throttle_account(&state, &account_key, client_ip).await?;

    let user = db_auth::find_user_by_account_key(&state.db, &account_key).await?;
    let srp_user = user.and_then(|u| match (u.srp_salt.clone(), u.srp_verifier.clone()) {
        (Some(salt), Some(verifier)) => Some((u, salt, verifier)),
        _ => None,
    });

    let session_id = Uuid::new_v4();
    let Some((user, srp_salt, srp_verifier)) = srp_user else {
        let mut fake_verifier = vec![0u8; 256];
        rand::thread_rng().fill_bytes(&mut fake_verifier);
        let fake = srp_server_init(&fake_verifier)
            .map_err(|e| ApiError::Internal(anyhow::anyhow!("SRP init: {e}")))?;
        // Nothing is stored, so verify finds no session and fails like a wrong password.
        return Ok(Json(SrpInitResponse {
            session_id,
            server_public_b: B64.encode(&fake.server_public_b),
            srp_salt: B64.encode(fake_srp_salt(&state, &account_key)),
            kdf_params: KdfParams::default(),
        }));
    };

    let srp_result = srp_server_init(&srp_verifier)
        .map_err(|e| ApiError::Internal(anyhow::anyhow!("SRP init: {e}")))?;
    let kdf_params = user_kdf_params(&user)?;

    pending::insert_srp(
        &state.db,
        session_id,
        user.id,
        &srp_verifier,
        &srp_result.server_ephemeral_b,
        &client_public_a,
    )
    .await?;

    Ok(Json(SrpInitResponse {
        session_id,
        server_public_b: B64.encode(&srp_result.server_public_b),
        srp_salt: B64.encode(&srp_salt),
        kdf_params,
    }))
}

async fn srp_verify(
    State(state): State<AppState>,
    Extension(ClientIp(client_ip)): Extension<ClientIp>,
    Json(req): Json<SrpVerifyRequest>,
) -> ApiResult<Json<SrpVerifyResponse>> {
    // DELETE … RETURNING consumes the handshake atomically — one proof
    // attempt per init, valid across replicas and restarts
    // No session: unknown or already-migrated account (fake challenge), or an
    // expired one. Clients reach this after an OPAQUE login failed locally,
    // so for OPAQUE accounts it is where a wrong password becomes visible.
    let Some(pending) = pending::take_srp(&state.db, req.session_id).await? else {
        crate::metrics::record_login_failure();
        return Err(auth_failed());
    };

    if (chrono::Utc::now() - pending.created_at).num_seconds() > SRP_SESSION_TTL_SECS as i64 {
        return Err(auth_failed());
    }

    let client_proof_m1 = B64.decode(&req.client_proof_m1)
        .map_err(|_| ApiError::BadRequest("invalid client_proof_m1".into()))?;

    let user = db_auth::get_user_by_id(&state.db, pending.user_id)
        .await?
        .ok_or_else(auth_failed)?;

    let verify_result = match srp_server_verify(
        &pending.srp_verifier,
        &pending.server_ephemeral_b,
        &pending.client_public_a,
        &client_proof_m1,
    ) {
        Ok(r) => r,
        Err(_) => {
            record_login_failure(&state, Some(user.id), &user.email_hash, "srp", client_ip).await;
            return Err(auth_failed());
        }
    };

    reset_throttle(&state, &user.email_hash, client_ip).await?;
    let session = issue_session(&state, &user, req.device_id, client_ip).await?;

    Ok(Json(SrpVerifyResponse {
        server_proof_m2: B64.encode(&verify_result.server_proof_m2),
        session,
    }))
}

/// Create a session for a user who just proved their password.
async fn issue_session(
    state: &AppState,
    user: &User,
    device_id: Option<Uuid>,
    client_ip: IpAddr,
) -> ApiResult<LoginResponse> {
    // If the client supplied a device_id, validate it belongs to this user and link the session.
    let device_id = if let Some(did) = device_id {
        let devices = db_devices::list_devices_for_user(&state.db, user.id).await?;
        if devices.iter().any(|d| d.id == did) {
            db_devices::touch_device(&state.db, did).await?;
            Some(did)
        } else {
            // Unknown device_id — ignore silently (don't reveal enumeration info)
            None
        }
    } else {
        None
    };

    let vaults = db_vaults::list_vaults_for_user(&state.db, user.id)
        .await
        .map_err(ApiError::Internal)?;
    let default_vault_id = vaults
        .first()
        .map(|v| v.id)
        .ok_or_else(|| ApiError::Internal(anyhow::anyhow!("no vault found for user")))?;

    let session_token = sessions::create_session(&state.db, user.id, device_id).await?;
    activity::record(&state.db, user.id, "login_succeeded", Some(&client_ip.to_string()), device_id).await;

    Ok(LoginResponse {
        session_token,
        user_id: user.id,
        default_vault_id,
        protected_symmetric_key: B64.encode(&user.protected_symmetric_key),
        protected_symmetric_key_iv: B64.encode(&user.protected_symmetric_key_iv),
        protected_private_key: user.protected_private_key.clone(),
        protected_private_key_iv: user.protected_private_key_iv.clone(),
        wrapped_account_key: user.wrapped_account_key.as_ref().map(|k| B64.encode(k)),
        wrapped_account_key_iv: user.wrapped_account_key_iv.as_ref().map(|k| B64.encode(k)),
    })
}

/// The account behind a session created moments ago. One-time upgrades that
/// replace key material (SRP → OPAQUE, legacy keys → account key) run right
/// after login and require this, so a stolen older token can't do them.
async fn fresh_session_user(state: &AppState, auth: &AuthUser) -> ApiResult<User> {
    let session = sessions::find_session_by_token(&state.db, &auth.raw_token)
        .await?
        .ok_or_else(|| ApiError::Unauthorized("invalid or expired session".into()))?;
    if (chrono::Utc::now() - session.created_at).num_seconds() > REREGISTER_MAX_SESSION_AGE_SECS {
        return Err(ApiError::Forbidden("sign in again to change your login credential".into()));
    }
    let user = db_auth::get_user_by_id(&state.db, auth.user_id)
        .await?
        .ok_or_else(|| ApiError::NotFound("user not found".into()))?;
    Ok(user)
}

/// A fresh session on an account still on SRP — the only case where OPAQUE
/// re-registration is allowed (a password change proves the old password instead).
async fn migrating_user(state: &AppState, auth: &AuthUser) -> ApiResult<User> {
    let user = fresh_session_user(state, auth).await?;
    if user.srp_verifier.is_none() {
        return Err(ApiError::Conflict("account already uses OPAQUE".into()));
    }
    Ok(user)
}

async fn reregister_start(
    State(state): State<AppState>,
    Extension(auth): Extension<AuthUser>,
    Json(req): Json<OpaqueRegisterStartRequest>,
) -> ApiResult<Json<OpaqueRegisterStartResponse>> {
    let email_hash = parse_email_hash(&req.email_hash)?;
    let request = decode_opaque(&req.registration_request, "registrationRequest")?;
    let user = migrating_user(&state, &auth).await?;
    // The credential identifier must be this account's, or the record would
    // be bound to someone else's OPRF key and never verify.
    if state.account_key(&email_hash) != user.email_hash {
        return Err(ApiError::BadRequest("emailHash does not match this account".into()));
    }

    let response = opaque::registration_start(&state.opaque_setup, &request, email_hash.as_bytes())
        .map_err(|_| ApiError::BadRequest("invalid registrationRequest".into()))?;
    Ok(Json(OpaqueRegisterStartResponse {
        registration_response: B64URL.encode(response),
    }))
}

async fn reregister_finish(
    State(state): State<AppState>,
    Extension(auth): Extension<AuthUser>,
    Extension(ClientIp(client_ip)): Extension<ClientIp>,
    Json(req): Json<OpaqueReregisterFinishRequest>,
) -> ApiResult<StatusCode> {
    let upload = decode_opaque(&req.registration_record, "registrationRecord")?;
    let record = opaque::registration_finish(&upload)
        .map_err(|_| ApiError::BadRequest("invalid registrationRecord".into()))?;
    let user = migrating_user(&state, &auth).await?;

    db_auth::set_opaque_record(&state.db, user.id, &record).await?;
    tracing::info!(event = "srp_migrated", account = log_handle(&user.email_hash), "account moved from SRP to OPAQUE");
    activity::record(&state.db, user.id, "login_upgraded", Some(&client_ip.to_string()), auth.device_id).await;
    Ok(StatusCode::NO_CONTENT)
}

/// One-time move of a legacy account to the wrapped account key, sent by the
/// client right after it unlocks with the password-derived keys.
async fn set_account_key(
    State(state): State<AppState>,
    Extension(auth): Extension<AuthUser>,
    Extension(ClientIp(client_ip)): Extension<ClientIp>,
    Json(req): Json<SetAccountKeyRequest>,
) -> ApiResult<StatusCode> {
    let wrapped = decode_b64(&req.wrapped_account_key, "wrappedAccountKey")?;
    let wrapped_iv = decode_b64(&req.wrapped_account_key_iv, "wrappedAccountKeyIv")?;
    let private_key = match (&req.protected_private_key, &req.protected_private_key_iv) {
        (Some(k), Some(iv)) => Some((k.as_str(), iv.as_str())),
        (None, None) => None,
        _ => return Err(ApiError::BadRequest("send both protectedPrivateKey and its IV, or neither".into())),
    };
    let user = fresh_session_user(&state, &auth).await?;

    if !db_auth::set_account_key(&state.db, user.id, (&wrapped, &wrapped_iv), private_key).await? {
        return Err(ApiError::Conflict("account key already set".into()));
    }
    tracing::info!(event = "account_key_migrated", account = log_handle(&user.email_hash), "account moved to wrapped account key");
    activity::record(&state.db, user.id, "account_key_upgraded", Some(&client_ip.to_string()), auth.device_id).await;
    Ok(StatusCode::NO_CONTENT)
}

async fn logout(
    State(state): State<AppState>,
    Extension(auth): Extension<AuthUser>,
) -> ApiResult<StatusCode> {
    sessions::delete_session_by_token(&state.db, &auth.raw_token).await?;
    Ok(StatusCode::NO_CONTENT)
}
