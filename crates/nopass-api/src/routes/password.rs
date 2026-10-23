use axum::{extract::State, http::StatusCode, routing::post, Extension, Json, Router};
use base64::{
    engine::general_purpose::{STANDARD as B64, URL_SAFE_NO_PAD as B64URL},
    Engine,
};
use nopass_crypto::opaque;
use nopass_models::{
    PasswordChangeFinishRequest, PasswordChangeStartRequest, PasswordChangeStartResponse, PasswordProof,
};

use crate::{
    db::pending::PURPOSE_PASSWORD_CHANGE,
    db::{activity, recovery as db_recovery},
    error::{ApiError, ApiResult},
    middleware::auth::AuthUser,
    routes::{
        auth::{decode_opaque, user_kdf_params},
        proof::{
            require_recent_session, session_user, start_proof, verify_password_proof,
            PASSWORD_CHANGE_MAX_SESSION_AGE_SECS,
        },
        recovery::rotation_error,
        ClientIp,
    },
    state::AppState,
};

/// Changing the master password. A session alone is not enough: the client
/// must prove the current password with a fresh OPAQUE login inside the
/// change, so a stolen session token can't lock the owner out. Items are
/// encrypted under the password-independent account key, so nothing is
/// re-encrypted: the new OPAQUE record and the account key re-wrapped under
/// the new password's KEK replace the old ones, and every other session is
/// revoked, in one transaction. The recovery kit wraps the account key and
/// stays valid.
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
    require_recent_session(&state, &auth, PASSWORD_CHANGE_MAX_SESSION_AGE_SECS).await?;
    let (user, email_hash) = session_user(&state, &auth, &req.email_hash).await?;
    let registration_request = decode_opaque(&req.registration_request, "registrationRequest")?;
    // Every unlock upgrades legacy-key accounts first, so this only fails if that did.
    let (Some(wrapped), Some(wrapped_iv)) = (user.wrapped_account_key.as_ref(), user.wrapped_account_key_iv.as_ref())
    else {
        return Err(ApiError::Conflict("sign in again before changing your password".into()));
    };
    let (change_id, login_response) =
        start_proof(&state, &user, &email_hash, &req.start_login_request, client_ip, PURPOSE_PASSWORD_CHANGE).await?;
    let registration_response =
        opaque::registration_start(&state.opaque_setup, &registration_request, email_hash.as_bytes())
            .map_err(|_| ApiError::BadRequest("invalid registrationRequest".into()))?;

    Ok(Json(PasswordChangeStartResponse {
        change_id,
        login_response: B64URL.encode(login_response),
        kdf_params: user_kdf_params(&user)?,
        registration_response: B64URL.encode(registration_response),
        wrapped_account_key: B64.encode(wrapped),
        wrapped_account_key_iv: B64.encode(wrapped_iv),
    }))
}

async fn finish(
    State(state): State<AppState>,
    Extension(auth): Extension<AuthUser>,
    Extension(ClientIp(client_ip)): Extension<ClientIp>,
    Json(req): Json<PasswordChangeFinishRequest>,
) -> ApiResult<StatusCode> {
    let session_id = require_recent_session(&state, &auth, PASSWORD_CHANGE_MAX_SESSION_AGE_SECS).await?;
    let upload = decode_opaque(&req.registration_record, "registrationRecord")?;
    let record = opaque::registration_finish(&upload)
        .map_err(|_| ApiError::BadRequest("invalid registrationRecord".into()))?;
    let wrapped = decode_b64(&req.wrapped_account_key, "wrappedAccountKey")?;
    let wrapped_iv = decode_b64(&req.wrapped_account_key_iv, "wrappedAccountKeyIv")?;

    verify_password_proof(
        &state,
        &auth,
        client_ip,
        &PasswordProof { proof_id: req.change_id, finish_login_request: req.finish_login_request.clone() },
        PURPOSE_PASSWORD_CHANGE,
    )
    .await?;


    db_recovery::rotate_master_password(
        &state.db,
        db_recovery::RotationAuthority::Session(session_id),
        auth.user_id,
        db_recovery::PasswordRotation {
            credential: &db_recovery::NewCredential::Opaque(record),
            protected_symmetric_key: None,
            protected_private_key: None,
            wrapped_account_key: Some((&wrapped, &wrapped_iv)),
            recovery_kit: None,
            reencrypted_items: None,
        },
    )
    .await
    .map_err(rotation_error)?;

    activity::record(&state.db, auth.user_id, "password_changed", Some(&client_ip.to_string()), auth.device_id).await;
    Ok(StatusCode::NO_CONTENT)
}
