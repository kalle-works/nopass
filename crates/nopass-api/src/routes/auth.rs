use axum::{
    extract::{ConnectInfo, State},
    http::StatusCode,
    routing::post,
    Extension, Json, Router,
};
use base64::{engine::general_purpose::STANDARD as B64, Engine};
use nopass_models::{
    KdfParams, RegisterRequest, RegisterResponse, SrpInitRequest, SrpInitResponse,
    SrpVerifyRequest, SrpVerifyResponse,
};
use std::net::SocketAddr;
use uuid::Uuid;

use crate::{
    db::{auth as db_auth, sessions, vaults as db_vaults},
    error::{ApiError, ApiResult},
    middleware::auth::AuthUser,
    state::{AppState, SrpPendingSession},
};
use nopass_crypto::srp::{srp_server_init, srp_server_verify};

pub fn public_router() -> Router<AppState> {
    Router::new()
        .route("/register", post(register))
        .route("/srp/init", post(srp_init))
        .route("/srp/verify", post(srp_verify))
}

pub fn protected_router() -> Router<AppState> {
    Router::new().route("/logout", post(logout))
}

/// Check rate limit for the given IP. Returns Err(TooManyRequests) if the limit is exceeded.
fn check_rate_limit(state: &AppState, addr: &SocketAddr) -> ApiResult<()> {
    state
        .auth_rate_limiter
        .check_key(&addr.ip())
        .map_err(|_| ApiError::TooManyRequests)
}

async fn register(
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    State(state): State<AppState>,
    Json(req): Json<RegisterRequest>,
) -> ApiResult<(StatusCode, Json<RegisterResponse>)> {
    check_rate_limit(&state, &addr)?;

    if db_auth::find_user_by_email_hash(&state.db, &req.email_hash)
        .await?
        .is_some()
    {
        return Err(ApiError::Conflict("email already registered".into()));
    }

    let srp_salt = B64.decode(&req.srp_salt)
        .map_err(|_| ApiError::BadRequest("invalid srp_salt base64".into()))?;
    let srp_verifier = B64.decode(&req.srp_verifier)
        .map_err(|_| ApiError::BadRequest("invalid srp_verifier base64".into()))?;
    let protected_key = B64.decode(&req.protected_symmetric_key)
        .map_err(|_| ApiError::BadRequest("invalid protected_symmetric_key base64".into()))?;
    let protected_key_iv = B64.decode(&req.protected_symmetric_key_iv)
        .map_err(|_| ApiError::BadRequest("invalid protected_symmetric_key_iv base64".into()))?;

    let kdf_params_json = serde_json::to_value(&req.kdf_params)
        .map_err(|e| ApiError::Internal(e.into()))?;

    let user = db_auth::create_user(
        &state.db,
        &req.email_hash,
        &srp_salt,
        &srp_verifier,
        kdf_params_json,
        &protected_key,
        &protected_key_iv,
        req.public_key.as_deref(),
        req.protected_private_key.as_deref(),
        req.protected_private_key_iv.as_deref(),
    )
    .await?;

    // Create the user's default vault automatically on registration
    db_vaults::create_vault(&state.db, user.id)
        .await
        .map_err(|e| ApiError::Internal(e))?;

    Ok((StatusCode::CREATED, Json(RegisterResponse { user_id: user.id })))
}

async fn srp_init(
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    State(state): State<AppState>,
    Json(req): Json<SrpInitRequest>,
) -> ApiResult<Json<SrpInitResponse>> {
    check_rate_limit(&state, &addr)?;

    let user = db_auth::find_user_by_email_hash(&state.db, &req.email_hash)
        .await?
        // Return the same error shape regardless of whether user exists (prevents enumeration)
        .ok_or_else(|| ApiError::Unauthorized("invalid credentials".into()))?;

    let client_public_a = B64.decode(&req.client_public_a)
        .map_err(|_| ApiError::BadRequest("invalid client_public_a".into()))?;

    // Reject trivially weak or empty ephemeral A
    if client_public_a.is_empty() {
        return Err(ApiError::BadRequest("client_public_a must not be empty".into()));
    }

    let srp_result = srp_server_init(&user.srp_verifier)
        .map_err(|e| ApiError::Internal(anyhow::anyhow!("SRP init: {e}")))?;

    let session_id = Uuid::new_v4();
    let kdf_params: KdfParams = serde_json::from_value(user.kdf_params.clone())
        .map_err(|e| ApiError::Internal(e.into()))?;

    {
        let mut sessions = state.srp_sessions.lock().await;
        sessions.insert(
            session_id,
            SrpPendingSession {
                user_id: user.id,
                verifier: user.srp_verifier.clone(),
                server_ephemeral_b: srp_result.server_ephemeral_b,
                client_public_a,
                created_at: std::time::Instant::now(),
            },
        );
    }

    Ok(Json(SrpInitResponse {
        session_id,
        server_public_b: B64.encode(&srp_result.server_public_b),
        srp_salt: B64.encode(&user.srp_salt),
        kdf_params,
    }))
}

async fn srp_verify(
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    State(state): State<AppState>,
    Json(req): Json<SrpVerifyRequest>,
) -> ApiResult<Json<SrpVerifyResponse>> {
    check_rate_limit(&state, &addr)?;

    let pending = {
        let mut sessions = state.srp_sessions.lock().await;
        sessions
            .remove(&req.session_id)
            .ok_or_else(|| ApiError::Unauthorized("SRP session not found or expired".into()))?
    };

    // Reject sessions older than 5 minutes
    if pending.created_at.elapsed().as_secs() > 300 {
        return Err(ApiError::Unauthorized("SRP session expired".into()));
    }

    let client_proof_m1 = B64.decode(&req.client_proof_m1)
        .map_err(|_| ApiError::BadRequest("invalid client_proof_m1".into()))?;

    // Use client_public_a stored in the pending session from step 1 — do not accept it again
    // from the request to prevent A-substitution attacks.
    let verify_result = srp_server_verify(
        &pending.verifier,
        &pending.server_ephemeral_b,
        &pending.client_public_a,
        &client_proof_m1,
    )
    .map_err(|_| ApiError::Unauthorized("authentication failed".into()))?;

    let _ = verify_result.session_key;

    let user = db_auth::get_user_by_id(&state.db, pending.user_id)
        .await?
        .ok_or_else(|| ApiError::Internal(anyhow::anyhow!("user vanished during SRP")))?;

    let vaults = db_vaults::list_vaults_for_user(&state.db, user.id)
        .await
        .map_err(|e| ApiError::Internal(e))?;
    let default_vault_id = vaults
        .first()
        .map(|v| v.id)
        .ok_or_else(|| ApiError::Internal(anyhow::anyhow!("no vault found for user")))?;

    let session_token = sessions::create_session(&state.db, user.id, None).await?;

    Ok(Json(SrpVerifyResponse {
        server_proof_m2: B64.encode(&verify_result.server_proof_m2),
        session_token,
        user_id: user.id,
        default_vault_id,
        protected_symmetric_key: B64.encode(&user.protected_symmetric_key),
        protected_symmetric_key_iv: B64.encode(&user.protected_symmetric_key_iv),
        protected_private_key: user.protected_private_key.clone(),
        protected_private_key_iv: user.protected_private_key_iv.clone(),
    }))
}

async fn logout(
    State(state): State<AppState>,
    Extension(auth): Extension<AuthUser>,
) -> ApiResult<StatusCode> {
    sessions::delete_session_by_token(&state.db, &auth.raw_token).await?;
    Ok(StatusCode::NO_CONTENT)
}
