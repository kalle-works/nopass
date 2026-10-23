use axum::{extract::State, http::StatusCode, routing::post, Extension, Json, Router};
use base64::{
    engine::general_purpose::{STANDARD as B64, URL_SAFE_NO_PAD as B64URL},
    Engine,
};
use nopass_crypto::opaque;
use nopass_models::{
    PasswordChangeFinishRequest, PasswordChangeStartRequest, PasswordChangeStartResponse,
};
use uuid::Uuid;

use crate::{
    db::{activity, auth as db_auth, pending, recovery as db_recovery, sessions, throttle},
    error::{ApiError, ApiResult},
    middleware::auth::AuthUser,
    routes::{
        auth::{decode_opaque, parse_email_hash, record_login_failure, throttle_account, user_kdf_params},
        recovery::{decode_reencrypted_items, encode_all_items, rotation_error},
        ClientIp,
    },
    state::{AppState, OPAQUE_LOGIN_TTL_SECS},
};

/// Changing the master password. A session alone is not enough: the client
/// must prove the current password with a fresh OPAQUE login inside the
/// change, so a stolen session token can't lock the owner out. Vault items are
/// encrypted under keys derived from the password, so the client re-encrypts
/// all of them; the swap, the new OPAQUE record and the revocation of every
/// other session happen in one transaction.
pub fn router() -> Router<AppState> {
    Router::new()
        .route("/start", post(start))
        .route("/finish", post(finish))
}

fn decode_b64(value: &str, field: &str) -> ApiResult<Vec<u8>> {
    B64.decode(value)
        .map_err(|_| ApiError::BadRequest(format!("invalid {field} base64")))
}

async fn start(
    State(state): State<AppState>,
    Extension(auth): Extension<AuthUser>,
    Extension(ClientIp(client_ip)): Extension<ClientIp>,
    Json(req): Json<PasswordChangeStartRequest>,
) -> ApiResult<Json<PasswordChangeStartResponse>> {
    let email_hash = parse_email_hash(&req.email_hash)?;
    let login_request = decode_opaque(&req.start_login_request, "startLoginRequest")?;
    let registration_request = decode_opaque(&req.registration_request, "registrationRequest")?;

    let user = db_auth::get_user_by_id(&state.db, auth.user_id)
        .await?
        .ok_or_else(|| ApiError::NotFound("user not found".into()))?;
    if state.account_key(&email_hash) != user.email_hash {
        return Err(ApiError::BadRequest("emailHash does not match this account".into()));
    }
    let Some(record) = user.opaque_record.as_deref() else {
        // Every login upgrades SRP accounts first, so this only happens if that upgrade failed.
        return Err(ApiError::Conflict("sign in again before changing your password".into()));
    };
    // A login response is a password-guessing oracle; it counts like any login.
    throttle_account(&state, &user.email_hash, client_ip).await?;

    let started = opaque::login_start(&state.opaque_setup, Some(record), &login_request, email_hash.as_bytes())
        .map_err(|_| ApiError::BadRequest("invalid startLoginRequest".into()))?;
    let registration_response =
        opaque::registration_start(&state.opaque_setup, &registration_request, email_hash.as_bytes())
            .map_err(|_| ApiError::BadRequest("invalid registrationRequest".into()))?;

    let change_id = Uuid::new_v4();
    pending::insert_opaque_login(&state.db, change_id, &user.email_hash, Some(user.id), &started.state).await?;

    Ok(Json(PasswordChangeStartResponse {
        change_id,
        login_response: B64URL.encode(started.response),
        kdf_params: user_kdf_params(&user)?,
        registration_response: B64URL.encode(registration_response),
        items: encode_all_items(&state, user.id).await?,
        protected_private_key: user.protected_private_key.clone(),
        protected_private_key_iv: user.protected_private_key_iv.clone(),
    }))
}

async fn finish(
    State(state): State<AppState>,
    Extension(auth): Extension<AuthUser>,
    Extension(ClientIp(client_ip)): Extension<ClientIp>,
    Json(req): Json<PasswordChangeFinishRequest>,
) -> ApiResult<StatusCode> {
    let finalization = decode_opaque(&req.finish_login_request, "finishLoginRequest")?;
    let upload = decode_opaque(&req.registration_record, "registrationRecord")?;
    let record = opaque::registration_finish(&upload)
        .map_err(|_| ApiError::BadRequest("invalid registrationRecord".into()))?;
    let protected_key = decode_b64(&req.protected_symmetric_key, "protected_symmetric_key")?;
    let protected_key_iv = decode_b64(&req.protected_symmetric_key_iv, "protected_symmetric_key_iv")?;
    let items = decode_reencrypted_items(&req.items)?;

    let wrong_password = || ApiError::Unauthorized("current password is incorrect".into());
    let pending = pending::take_opaque_login(&state.db, req.change_id)
        .await?
        .filter(|p| p.user_id == Some(auth.user_id))
        .ok_or_else(wrong_password)?;
    if (chrono::Utc::now() - pending.created_at).num_seconds() > OPAQUE_LOGIN_TTL_SECS as i64 {
        return Err(wrong_password());
    }
    if opaque::login_finish(&pending.server_state, &finalization).is_err() {
        record_login_failure(&state, Some(auth.user_id), &pending.account_key, "password_change", client_ip).await;
        return Err(wrong_password());
    }
    throttle::reset(&state.db, &pending.account_key).await?;

    let session = sessions::find_session_by_token(&state.db, &auth.raw_token)
        .await?
        .ok_or_else(|| ApiError::Unauthorized("invalid or expired session".into()))?;

    db_recovery::rotate_master_password(
        &state.db,
        db_recovery::RotationAuthority::Session(session.id),
        auth.user_id,
        db_recovery::RecoveryCompletion {
            credential: &db_recovery::NewCredential::Opaque(record),
            protected_symmetric_key: &protected_key,
            protected_symmetric_key_iv: &protected_key_iv,
            protected_private_key: req.protected_private_key.as_deref(),
            protected_private_key_iv: req.protected_private_key_iv.as_deref(),
            recovery_kit: None,
        },
        &items,
    )
    .await
    .map_err(rotation_error)?;

    activity::record(&state.db, auth.user_id, "password_changed", Some(&client_ip.to_string()), auth.device_id).await;
    Ok(StatusCode::NO_CONTENT)
}
