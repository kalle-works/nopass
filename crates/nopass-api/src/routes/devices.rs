use axum::{
    extract::{Path, State},
    http::StatusCode,
    routing::{delete, get},
    Extension, Json, Router,
};
use base64::{engine::general_purpose::STANDARD as B64, Engine};
use nopass_models::{DeviceInfo, RegisterDeviceRequest};
use uuid::Uuid;

use crate::{
    db::activity,
    db::devices as db_devices,
    error::{ApiError, ApiResult},
    middleware::auth::AuthUser,
    routes::ClientIp,
    state::AppState,
};

pub fn router() -> Router<AppState> {
    Router::new()
        .route("/", get(list_devices).post(register_device))
        .route("/{device_id}", delete(remove_device))
}

async fn list_devices(
    State(state): State<AppState>,
    Extension(auth): Extension<AuthUser>,
) -> ApiResult<Json<Vec<DeviceInfo>>> {
    let devices = db_devices::list_devices_for_user(&state.db, auth.user_id).await?;

    let infos = devices
        .into_iter()
        .map(|d| DeviceInfo {
            id: d.id,
            device_name: d.device_name,
            device_type: d.device_type,
            last_seen_at: d.last_seen_at,
            created_at: d.created_at,
        })
        .collect();

    Ok(Json(infos))
}

async fn register_device(
    State(state): State<AppState>,
    Extension(auth): Extension<AuthUser>,
    Extension(ClientIp(client_ip)): Extension<ClientIp>,
    Json(req): Json<RegisterDeviceRequest>,
) -> ApiResult<(StatusCode, Json<serde_json::Value>)> {
    let device_public_key = B64.decode(&req.device_public_key)
        .map_err(|_| ApiError::BadRequest("invalid device_public_key".into()))?;

    let protected_device_key = req
        .protected_device_key
        .as_deref()
        .map(|k| B64.decode(k))
        .transpose()
        .map_err(|_| ApiError::BadRequest("invalid protected_device_key".into()))?;

    let protected_device_key_iv = req
        .protected_device_key_iv
        .as_deref()
        .map(|k| B64.decode(k))
        .transpose()
        .map_err(|_| ApiError::BadRequest("invalid protected_device_key_iv".into()))?;

    let device = db_devices::create_device(
        &state.db,
        auth.user_id,
        &req.device_name,
        &req.device_type,
        &device_public_key,
        protected_device_key.as_deref(),
        protected_device_key_iv.as_deref(),
    )
    .await?;
    activity::record(&state.db, auth.user_id, "device_registered", Some(&client_ip.to_string()), Some(device.id)).await;

    Ok((
        StatusCode::CREATED,
        Json(serde_json::json!({ "deviceId": device.id })),
    ))
}

async fn remove_device(
    State(state): State<AppState>,
    Extension(auth): Extension<AuthUser>,
    Extension(ClientIp(client_ip)): Extension<ClientIp>,
    Path(device_id): Path<Uuid>,
) -> ApiResult<StatusCode> {
    let deleted = db_devices::delete_device(&state.db, device_id, auth.user_id).await?;
    if deleted {
        activity::record(&state.db, auth.user_id, "device_revoked", Some(&client_ip.to_string()), Some(device_id)).await;
        Ok(StatusCode::NO_CONTENT)
    } else {
        Err(ApiError::NotFound("device not found".into()))
    }
}
