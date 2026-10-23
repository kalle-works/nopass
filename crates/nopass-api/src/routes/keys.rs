use axum::{extract::State, http::StatusCode, routing::{get, put}, Extension, Json, Router};
use base64::{engine::general_purpose::STANDARD as B64, Engine};

use crate::{
    db::keys::{self as db_keys, SetIdentityOutcome},
    error::{ApiError, ApiResult},
    middleware::auth::AuthUser,
    models::org::{PublicKeyResponse, SetIdentityBody},
    state::AppState,
};

pub fn router() -> Router<AppState> {
    Router::new()
        .route("/me", get(get_own_bundle))
        .route("/identity", put(set_identity))
}

/// The caller's published key bundle, so the client can check what the server
/// hands out for it against the keys it derives locally.
async fn get_own_bundle(
    State(state): State<AppState>,
    Extension(auth): Extension<AuthUser>,
) -> ApiResult<Json<PublicKeyResponse>> {
    let bundle = db_keys::get_bundle(&state.db, auth.user_id)
        .await?
        .ok_or_else(|| ApiError::NotFound("no public key yet".into()))?;
    Ok(Json(PublicKeyResponse {
        user_id: bundle.user_id,
        public_key: bundle.public_key,
        identity_public_key: bundle.identity_public_key,
        public_key_signature: bundle.public_key_signature,
    }))
}

/// Publish the caller's identity key and bundle signature. Write-once: the
/// signature is verified by the clients that rely on it, not here.
async fn set_identity(
    State(state): State<AppState>,
    Extension(auth): Extension<AuthUser>,
    Json(body): Json<SetIdentityBody>,
) -> ApiResult<StatusCode> {
    let key_len = B64.decode(&body.identity_public_key).map(|k| k.len());
    if key_len != Ok(32) {
        return Err(ApiError::BadRequest("identityPublicKey must be 32 bytes of base64".into()));
    }
    let sig_len = B64.decode(&body.public_key_signature).map(|s| s.len());
    if sig_len != Ok(64) {
        return Err(ApiError::BadRequest("publicKeySignature must be 64 bytes of base64".into()));
    }

    match db_keys::set_identity(&state.db, auth.user_id, &body.identity_public_key, &body.public_key_signature)
        .await?
    {
        SetIdentityOutcome::Stored | SetIdentityOutcome::Unchanged => Ok(StatusCode::NO_CONTENT),
        SetIdentityOutcome::Conflict => Err(ApiError::Conflict("a different identity key is already published".into())),
        SetIdentityOutcome::NoPublicKey => Err(ApiError::BadRequest("publish a public key first".into())),
    }
}
