use axum::{
    extract::State,
    http::StatusCode,
    routing::{get, post},
    Extension, Json, Router,
};
use base64::{engine::general_purpose::STANDARD as B64, Engine};
use nopass_models::{
    EncryptedVaultItem, RecoveryCompleteRequest, RecoveryInitRequest, RecoveryInitResponse,
    RecoveryStatusResponse, SetRecoveryRequest,
};
use sha2::{Digest, Sha256};
use uuid::Uuid;

use crate::{
    db::{activity, auth as db_auth, pending, recovery as db_recovery},
    error::{ApiError, ApiResult},
    middleware::auth::AuthUser,
    routes::{vault::parse_item_type, ClientIp},
    state::{AppState, RECOVERY_SESSION_TTL_SECS},
};

pub fn public_router() -> Router<AppState> {
    Router::new()
        .route("/init", post(recovery_init))
        .route("/complete", post(recovery_complete))
}

pub fn protected_router() -> Router<AppState> {
    Router::new().route("/", get(status).put(set_recovery).delete(disable))
}

fn decode_b64(value: &str, field: &str) -> ApiResult<Vec<u8>> {
    B64.decode(value)
        .map_err(|_| ApiError::BadRequest(format!("invalid {field} base64")))
}

fn hash_auth_key(auth_key: &[u8]) -> Vec<u8> {
    Sha256::digest(auth_key).to_vec()
}

/// Constant-time equality — auth-key hashes must not be comparable by timing.
fn ct_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    a.iter().zip(b).fold(0u8, |acc, (x, y)| acc | (x ^ y)) == 0
}

async fn status(
    State(state): State<AppState>,
    Extension(auth): Extension<AuthUser>,
) -> ApiResult<Json<RecoveryStatusResponse>> {
    let user = db_auth::get_user_by_id(&state.db, auth.user_id)
        .await?
        .ok_or_else(|| ApiError::NotFound("user not found".into()))?;

    Ok(Json(RecoveryStatusResponse {
        enabled: user.recovery_auth_hash.is_some(),
        updated_at: user.recovery_updated_at,
    }))
}

async fn set_recovery(
    State(state): State<AppState>,
    Extension(auth): Extension<AuthUser>,
    Extension(ClientIp(client_ip)): Extension<ClientIp>,
    Json(req): Json<SetRecoveryRequest>,
) -> ApiResult<StatusCode> {
    let auth_key = decode_b64(&req.recovery_auth_key, "recovery_auth_key")?;
    let blob = decode_b64(&req.recovery_blob, "recovery_blob")?;
    let blob_iv = decode_b64(&req.recovery_blob_iv, "recovery_blob_iv")?;

    if auth_key.len() != 32 {
        return Err(ApiError::BadRequest("recovery_auth_key must be 32 bytes".into()));
    }

    db_recovery::set_recovery(&state.db, auth.user_id, &hash_auth_key(&auth_key), &blob, &blob_iv)
        .await?;
    activity::record(&state.db, auth.user_id, "recovery_kit_created", Some(&client_ip.to_string()), None).await;

    Ok(StatusCode::NO_CONTENT)
}

async fn disable(
    State(state): State<AppState>,
    Extension(auth): Extension<AuthUser>,
    Extension(ClientIp(client_ip)): Extension<ClientIp>,
) -> ApiResult<StatusCode> {
    db_recovery::clear_recovery(&state.db, auth.user_id).await?;
    activity::record(&state.db, auth.user_id, "recovery_kit_disabled", Some(&client_ip.to_string()), None).await;
    Ok(StatusCode::NO_CONTENT)
}

async fn recovery_init(
    State(state): State<AppState>,
    Extension(ClientIp(client_ip)): Extension<ClientIp>,
    Json(req): Json<RecoveryInitRequest>,
) -> ApiResult<Json<RecoveryInitResponse>> {
    let auth_key = decode_b64(&req.recovery_auth_key, "recovery_auth_key")?;

    // Same error for unknown email, no kit, and wrong code — no enumeration
    let invalid = || ApiError::Unauthorized("invalid recovery code".into());

    let user = db_auth::find_user_by_email_hash(&state.db, &req.email_hash)
        .await?
        .ok_or_else(invalid)?;

    let stored_hash = user.recovery_auth_hash.as_deref().ok_or_else(invalid)?;
    if !ct_eq(stored_hash, &hash_auth_key(&auth_key)) {
        return Err(invalid());
    }

    let (blob, blob_iv) = match (&user.recovery_blob, &user.recovery_blob_iv) {
        (Some(b), Some(iv)) => (b, iv),
        _ => return Err(ApiError::Internal(anyhow::anyhow!("recovery kit missing blob"))),
    };

    let items = db_recovery::list_all_items_for_user(&state.db, user.id).await?;
    let items = items
        .into_iter()
        .map(|item| {
            Ok(EncryptedVaultItem {
                id: item.id,
                vault_id: item.vault_id,
                user_id: item.user_id,
                item_type: parse_item_type(&item.item_type)?,
                blob: B64.encode(&item.blob),
                blob_iv: B64.encode(&item.blob_iv),
                blob_mac: B64.encode(&item.blob_mac),
                version: item.version,
                deleted_at: item.deleted_at,
                created_at: item.created_at,
                updated_at: item.updated_at,
            })
        })
        .collect::<ApiResult<Vec<_>>>()?;

    activity::record(&state.db, user.id, "recovery_initiated", Some(&client_ip.to_string()), None).await;
    let recovery_token = Uuid::new_v4();
    pending::insert_recovery(&state.db, recovery_token, user.id).await?;

    Ok(Json(RecoveryInitResponse {
        recovery_token: recovery_token.to_string(),
        recovery_blob: B64.encode(blob),
        recovery_blob_iv: B64.encode(blob_iv),
        protected_private_key: user.protected_private_key.clone(),
        protected_private_key_iv: user.protected_private_key_iv.clone(),
        items,
    }))
}

async fn recovery_complete(
    State(state): State<AppState>,
    Extension(ClientIp(client_ip)): Extension<ClientIp>,
    Json(req): Json<RecoveryCompleteRequest>,
) -> ApiResult<StatusCode> {
    let token: Uuid = req
        .recovery_token
        .parse()
        .map_err(|_| ApiError::Unauthorized("invalid recovery token".into()))?;

    // Peek without consuming: a transient failure (DB hiccup, bad field) must
    // leave the token usable so the client can retry without restarting the
    // whole code-entry flow. The token holder already has full recovery power,
    // so single-use isn't load-bearing; it's consumed on success below.
    let pending_session = pending::peek_recovery(&state.db, token)
        .await?
        .ok_or_else(|| ApiError::Unauthorized("recovery session not found or expired".into()))?;

    if (chrono::Utc::now() - pending_session.created_at).num_seconds() >= RECOVERY_SESSION_TTL_SECS as i64 {
        return Err(ApiError::Unauthorized("recovery session expired".into()));
    }

    let srp_salt = decode_b64(&req.srp_salt, "srp_salt")?;
    let srp_verifier = decode_b64(&req.srp_verifier, "srp_verifier")?;
    let protected_key = decode_b64(&req.protected_symmetric_key, "protected_symmetric_key")?;
    let protected_key_iv = decode_b64(&req.protected_symmetric_key_iv, "protected_symmetric_key_iv")?;
    let new_auth_key = decode_b64(&req.recovery_auth_key, "recovery_auth_key")?;
    let new_blob = decode_b64(&req.recovery_blob, "recovery_blob")?;
    let new_blob_iv = decode_b64(&req.recovery_blob_iv, "recovery_blob_iv")?;

    if new_auth_key.len() != 32 {
        return Err(ApiError::BadRequest("recovery_auth_key must be 32 bytes".into()));
    }

    // The client must re-encrypt every single item — a partial set would leave
    // the rest of the vault undecryptable under the new keys.
    let expected = db_recovery::list_all_items_for_user(&state.db, pending_session.user_id).await?;
    if expected.len() != req.items.len() {
        return Err(ApiError::BadRequest(format!(
            "expected {} re-encrypted items, got {}",
            expected.len(),
            req.items.len()
        )));
    }

    let items = req
        .items
        .iter()
        .map(|item| {
            Ok(db_recovery::ReencryptedItemRow {
                id: item.id,
                blob: decode_b64(&item.blob, "item blob")?,
                blob_iv: decode_b64(&item.blob_iv, "item blob_iv")?,
                blob_mac: decode_b64(&item.blob_mac, "item blob_mac")?,
            })
        })
        .collect::<ApiResult<Vec<_>>>()?;

    let new_auth_hash = hash_auth_key(&new_auth_key);
    db_recovery::complete_recovery(
        &state.db,
        pending_session.user_id,
        db_recovery::RecoveryCompletion {
            srp_salt: &srp_salt,
            srp_verifier: &srp_verifier,
            protected_symmetric_key: &protected_key,
            protected_symmetric_key_iv: &protected_key_iv,
            protected_private_key: req.protected_private_key.as_deref(),
            protected_private_key_iv: req.protected_private_key_iv.as_deref(),
            recovery_auth_hash: &new_auth_hash,
            recovery_blob: &new_blob,
            recovery_blob_iv: &new_blob_iv,
        },
        &items,
    )
    .await
    .map_err(|e| match e {
        db_recovery::CompleteRecoveryError::ItemMismatch => {
            ApiError::BadRequest("one or more items do not belong to this account".into())
        }
        db_recovery::CompleteRecoveryError::Db(e) => ApiError::Internal(e),
    })?;

    // Success — burn the token
    pending::delete_recovery(&state.db, token).await?;
    activity::record(&state.db, pending_session.user_id, "recovery_completed", Some(&client_ip.to_string()), None).await;

    Ok(StatusCode::NO_CONTENT)
}
