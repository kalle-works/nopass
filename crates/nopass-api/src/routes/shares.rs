use axum::{
    extract::{Path, State},
    http::StatusCode,
    routing::post,
    Extension, Json, Router,
};
use base64::{engine::general_purpose::STANDARD as B64, Engine};
use chrono::{Duration, Utc};
use nopass_models::{
    CreateShareRequest, CreateShareResponse, ShareInfo, ViewShareResponse,
};
use uuid::Uuid;

use crate::{
    db::{activity, shares as db_shares},
    error::{ApiError, ApiResult},
    middleware::auth::AuthUser,
    routes::ClientIp,
    state::AppState,
};

/// 64 KiB of ciphertext is plenty for a single item snapshot and keeps the
/// public endpoint from becoming free blob hosting.
const MAX_BLOB_BYTES: usize = 64 * 1024;
const MAX_VIEWS: i32 = 10;
const MAX_HOURS: i64 = 168; // 7 days

pub fn router() -> Router<AppState> {
    Router::new()
        .route("/", post(create_share).get(list_shares))
        .route("/{share_id}", axum::routing::delete(delete_share))
}

pub fn public_router() -> Router<AppState> {
    Router::new().route("/{share_id}/view", post(view_share))
}

fn decode_b64(value: &str, field: &str) -> ApiResult<Vec<u8>> {
    B64.decode(value)
        .map_err(|_| ApiError::BadRequest(format!("invalid {field} base64")))
}

async fn create_share(
    State(state): State<AppState>,
    Extension(auth): Extension<AuthUser>,
    Extension(ClientIp(client_ip)): Extension<ClientIp>,
    Json(req): Json<CreateShareRequest>,
) -> ApiResult<(StatusCode, Json<CreateShareResponse>)> {
    if !(1..=MAX_VIEWS).contains(&req.max_views) {
        return Err(ApiError::BadRequest(format!("maxViews must be 1–{MAX_VIEWS}")));
    }
    if !(1..=MAX_HOURS).contains(&(req.expires_in_hours as i64)) {
        return Err(ApiError::BadRequest(format!("expiresInHours must be 1–{MAX_HOURS}")));
    }

    let blob = decode_b64(&req.blob, "blob")?;
    let blob_iv = decode_b64(&req.blob_iv, "blob_iv")?;
    let label_blob = decode_b64(&req.label_blob, "label_blob")?;
    let label_iv = decode_b64(&req.label_iv, "label_iv")?;

    if blob.len() > MAX_BLOB_BYTES {
        return Err(ApiError::BadRequest("share blob too large".into()));
    }

    let expires_at = Utc::now() + Duration::hours(req.expires_in_hours as i64);
    let share_id = db_shares::create_share(
        &state.db,
        auth.user_id,
        &blob,
        &blob_iv,
        &label_blob,
        &label_iv,
        req.max_views,
        expires_at,
    )
    .await?;

    activity::record(&state.db, auth.user_id, "share_created", Some(&client_ip.to_string()), None).await;
    Ok((StatusCode::CREATED, Json(CreateShareResponse { share_id })))
}

async fn list_shares(
    State(state): State<AppState>,
    Extension(auth): Extension<AuthUser>,
) -> ApiResult<Json<Vec<ShareInfo>>> {
    let shares = db_shares::list_shares_for_user(&state.db, auth.user_id).await?;
    Ok(Json(
        shares
            .into_iter()
            .map(|s| ShareInfo {
                id: s.id,
                label_blob: B64.encode(&s.label_blob),
                label_iv: B64.encode(&s.label_iv),
                max_views: s.max_views,
                view_count: s.view_count,
                expires_at: s.expires_at,
                created_at: s.created_at,
            })
            .collect(),
    ))
}

async fn delete_share(
    State(state): State<AppState>,
    Extension(auth): Extension<AuthUser>,
    Extension(ClientIp(client_ip)): Extension<ClientIp>,
    Path(share_id): Path<Uuid>,
) -> ApiResult<StatusCode> {
    let deleted = db_shares::delete_share(&state.db, share_id, auth.user_id).await?;
    if !deleted {
        return Err(ApiError::NotFound("share not found".into()));
    }
    activity::record(&state.db, auth.user_id, "share_revoked", Some(&client_ip.to_string()), None).await;
    Ok(StatusCode::NO_CONTENT)
}

/// Public: consume one view. Missing, expired, and exhausted shares are all
/// the same 404 — a share link reveals nothing once it stops resolving.
async fn view_share(
    State(state): State<AppState>,
    Extension(ClientIp(client_ip)): Extension<ClientIp>,
    Path(share_id): Path<Uuid>,
) -> ApiResult<Json<ViewShareResponse>> {
    let share = db_shares::consume_view(&state.db, share_id)
        .await?
        .ok_or_else(|| ApiError::NotFound("share not found".into()))?;
    activity::record(&state.db, share.user_id, "share_viewed", Some(&client_ip.to_string()), None).await;

    Ok(Json(ViewShareResponse {
        blob: B64.encode(&share.blob),
        blob_iv: B64.encode(&share.blob_iv),
        remaining_views: share.max_views - share.view_count,
        expires_at: share.expires_at,
    }))
}
