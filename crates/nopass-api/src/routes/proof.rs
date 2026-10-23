use std::net::IpAddr;

use axum::{extract::State, routing::post, Extension, Json, Router};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD as B64URL, Engine};
use nopass_crypto::opaque;
use nopass_models::{PasswordProof, PasswordProofStartRequest, PasswordProofStartResponse, ProofPurpose};
use uuid::Uuid;

use crate::{
    db::{auth as db_auth, pending, sessions},
    error::{ApiError, ApiResult},
    middleware::auth::AuthUser,
    models::user::User,
    routes::{
        auth::{decode_opaque, parse_email_hash, record_login_failure, reset_throttle, throttle_account, user_kdf_params},
        ClientIp,
    },
    state::{AppState, OPAQUE_LOGIN_TTL_SECS},
};

/// Fresh password proofs for authenticated requests that replace key
/// material (account key, identity key, password). A session token says the
/// caller logged in at some point; these changes need the password now.
pub fn router() -> Router<AppState> {
    Router::new().route("/start", post(start))
}

/// The session's account, checked against the email the client derives its
/// OPAQUE credential identifier from.
pub(crate) async fn session_user(state: &AppState, auth: &AuthUser, email_hash: &str) -> ApiResult<(User, String)> {
    let email_hash = parse_email_hash(email_hash)?;
    let user = db_auth::get_user_by_id(&state.db, auth.user_id)
        .await?
        .ok_or_else(|| ApiError::NotFound("user not found".into()))?;
    if state.account_key(&email_hash) != user.email_hash {
        return Err(ApiError::BadRequest("emailHash does not match this account".into()));
    }
    Ok((user, email_hash))
}

/// Sessions older than this can't change the password, even with the
/// password: a forgotten, still-open session (or a stolen long-lived token
/// combined with a phished password) should not be enough. Sign in again.
pub(crate) const PASSWORD_CHANGE_MAX_SESSION_AGE_SECS: i64 = 15 * 60;

pub(crate) async fn require_recent_session(state: &AppState, auth: &AuthUser, max_age_secs: i64) -> ApiResult<Uuid> {
    let session = sessions::find_session_by_token(&state.db, &auth.raw_token)
        .await?
        .ok_or_else(|| ApiError::Unauthorized("invalid or expired session".into()))?;
    if (chrono::Utc::now() - session.created_at).num_seconds() > max_age_secs {
        return Err(ApiError::Forbidden("sign in again to change your password".into()));
    }
    Ok(session.id)
}

/// OPAQUE login round 1 bound to this session's account; the returned id is
/// redeemed by `verify_password_proof`. Counts against the login throttle.
pub(crate) async fn start_proof(
    state: &AppState,
    user: &User,
    email_hash: &str,
    start_login_request: &str,
    client_ip: IpAddr,
    purpose: &str,
) -> ApiResult<(Uuid, Vec<u8>)> {
    let request = decode_opaque(start_login_request, "startLoginRequest")?;
    let Some(record) = user.opaque_record.as_deref() else {
        // Every unlock upgrades SRP accounts first, so this only happens if that failed.
        return Err(ApiError::Conflict("sign in again before changing your keys".into()));
    };
    throttle_account(state, &user.email_hash, client_ip).await?;
    let started = opaque::login_start(&state.opaque_setup, Some(record), &request, email_hash.as_bytes())
        .map_err(|_| ApiError::BadRequest("invalid startLoginRequest".into()))?;
    let proof_id = Uuid::new_v4();
    pending::insert_opaque_login(&state.db, proof_id, &user.email_hash, Some(user.id), &started.state, purpose).await?;
    Ok((proof_id, started.response))
}

async fn start(
    State(state): State<AppState>,
    Extension(auth): Extension<AuthUser>,
    Extension(ClientIp(client_ip)): Extension<ClientIp>,
    Json(req): Json<PasswordProofStartRequest>,
) -> ApiResult<Json<PasswordProofStartResponse>> {
    let (user, email_hash) = session_user(&state, &auth, &req.email_hash).await?;
    let purpose = match req.purpose {
        ProofPurpose::AccountKey => pending::PURPOSE_ACCOUNT_KEY,
        ProofPurpose::IdentityKey => pending::PURPOSE_IDENTITY_KEY,
    };
    let (proof_id, response) =
        start_proof(&state, &user, &email_hash, &req.start_login_request, client_ip, purpose).await?;
    Ok(Json(PasswordProofStartResponse {
        proof_id,
        login_response: B64URL.encode(response),
        kdf_params: user_kdf_params(&user)?,
    }))
}

/// Redeems a proof: it must have been started by this session's account for
/// `purpose`, and carry a valid OPAQUE finalization. Single use.
pub(crate) async fn verify_password_proof(
    state: &AppState,
    auth: &AuthUser,
    client_ip: IpAddr,
    proof: &PasswordProof,
    purpose: &str,
) -> ApiResult<()> {
    let finalization = decode_opaque(&proof.finish_login_request, "finishLoginRequest")?;
    let wrong_password = || ApiError::Unauthorized("current password is incorrect".into());
    let Some(pending) = pending::take_opaque_login(&state.db, proof.proof_id)
        .await?
        .filter(|p| p.user_id == Some(auth.user_id) && p.purpose == purpose)
    else {
        crate::metrics::record_login_failure();
        return Err(wrong_password());
    };
    if (chrono::Utc::now() - pending.created_at).num_seconds() > OPAQUE_LOGIN_TTL_SECS as i64 {
        return Err(wrong_password());
    }
    if opaque::login_finish(&pending.server_state, &finalization).is_err() {
        record_login_failure(state, Some(auth.user_id), &pending.account_key, "password_proof", client_ip).await;
        return Err(wrong_password());
    }
    reset_throttle(state, &pending.account_key, client_ip).await
}
