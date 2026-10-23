use axum::{extract::State, routing::post, Extension, Json, Router};
use base64::{engine::general_purpose::STANDARD as B64, Engine};
use nopass_models::{
    SyncEvent as ModelSyncEvent, SyncEventType, SyncRequest, SyncResponse,
    VectorClock,
};
use uuid::Uuid;

use crate::{
    db::{devices as db_devices, sync as db_sync},
    error::{ApiError, ApiResult},
    middleware::auth::AuthUser,
    models::vault::SyncEvent as DbSyncEvent,
    state::AppState,
};

/// Events accepted per push; larger batches are split by the client.
const MAX_EVENTS_PER_PUSH: usize = 500;
/// Ciphertext cap per event delta. Deltas are field-level, so this is generous.
const MAX_DELTA_BYTES: usize = 64 * 1024;
/// AES-GCM nonce length.
const DELTA_IV_BYTES: usize = 12;

pub fn router() -> Router<AppState> {
    Router::new()
        .route("/", post(pull_sync))
        .route("/events", post(push_events))
        .route("/clock", axum::routing::get(get_clock))
}

async fn pull_sync(
    State(state): State<AppState>,
    Extension(auth): Extension<AuthUser>,
    Json(req): Json<SyncRequest>,
) -> ApiResult<Json<SyncResponse>> {
    let checkpoints: Vec<(Uuid, i64)> = req
        .known_checkpoints
        .iter()
        .map(|c| (c.device_id, c.last_synced_sequence))
        .collect();

    let events =
        db_sync::pull_sync_events(&state.db, auth.user_id, &checkpoints).await?;

    let clock_entries = db_sync::get_vector_clock(&state.db, auth.user_id).await?;
    let server_clock: VectorClock = clock_entries
        .into_iter()
        .map(|(id, seq)| (id.to_string(), seq))
        .collect();

    let model_events = events.into_iter().map(db_to_model_event).collect();

    Ok(Json(SyncResponse {
        events: model_events,
        server_clock,
    }))
}

/// Push events from the caller's devices.
///
/// Ordering guarantee is per (device_id, sequence_number) only: the client
/// owns the sequence of each of its own devices, and the server never uses
/// sequence numbers to order events across devices or to trust one device's
/// clock over another's. Each event's device_id must be a device of the
/// authenticated user, so a caller cannot write into another user's stream.
async fn push_events(
    State(state): State<AppState>,
    Extension(auth): Extension<AuthUser>,
    Json(req): Json<Vec<ModelSyncEvent>>,
) -> ApiResult<Json<serde_json::Value>> {
    if req.len() > MAX_EVENTS_PER_PUSH {
        return Err(ApiError::BadRequest(format!(
            "at most {MAX_EVENTS_PER_PUSH} events per push"
        )));
    }

    let mut device_ids: Vec<Uuid> = Vec::new();
    for e in &req {
        // Validate event belongs to the authenticated user
        if e.user_id != auth.user_id {
            return Err(ApiError::Unauthorized(
                "event user_id does not match session".into(),
            ));
        }
        if e.sequence_number < 0 {
            return Err(ApiError::BadRequest("sequence_number must be non-negative".into()));
        }
        if !device_ids.contains(&e.device_id) {
            device_ids.push(e.device_id);
        }
    }
    for device_id in device_ids {
        if !db_devices::device_belongs_to_user(&state.db, device_id, auth.user_id).await? {
            return Err(ApiError::Forbidden("unknown device".into()));
        }
    }

    let db_events = req
        .into_iter()
        .map(model_to_db_event)
        .collect::<Result<Vec<DbSyncEvent>, ApiError>>()?;
    db_sync::push_sync_events(&state.db, &db_events).await?;

    Ok(Json(serde_json::json!({ "accepted": db_events.len() })))
}

async fn get_clock(
    State(state): State<AppState>,
    Extension(auth): Extension<AuthUser>,
) -> ApiResult<Json<serde_json::Value>> {
    let entries = db_sync::get_vector_clock(&state.db, auth.user_id).await?;
    let clock: VectorClock = entries
        .into_iter()
        .map(|(id, seq)| (id.to_string(), seq))
        .collect();
    Ok(Json(serde_json::json!({ "serverClock": clock })))
}

fn db_to_model_event(e: DbSyncEvent) -> ModelSyncEvent {
    ModelSyncEvent {
        id: e.id,
        user_id: e.user_id,
        device_id: e.device_id,
        sequence_number: e.sequence_number,
        event_type: if e.event_type == "delete" {
            SyncEventType::Delete
        } else {
            SyncEventType::Upsert
        },
        item_id: e.item_id,
        encrypted_delta: e.encrypted_delta.map(|b| B64.encode(b)),
        delta_iv: e.delta_iv.map(|b| B64.encode(b)),
        created_at: e.created_at,
    }
}

fn model_to_db_event(e: ModelSyncEvent) -> Result<DbSyncEvent, ApiError> {
    let encrypted_delta = e
        .encrypted_delta
        .as_deref()
        .map(|b| B64.decode(b))
        .transpose()
        .map_err(|_| ApiError::BadRequest("invalid encrypted_delta base64".into()))?;

    let delta_iv = e
        .delta_iv
        .as_deref()
        .map(|b| B64.decode(b))
        .transpose()
        .map_err(|_| ApiError::BadRequest("invalid delta_iv base64".into()))?;

    if encrypted_delta.as_ref().is_some_and(|d| d.len() > MAX_DELTA_BYTES) {
        return Err(ApiError::BadRequest("encrypted_delta too large".into()));
    }
    if delta_iv.as_ref().is_some_and(|iv| iv.len() != DELTA_IV_BYTES) {
        return Err(ApiError::BadRequest("delta_iv must be 12 bytes".into()));
    }

    Ok(DbSyncEvent {
        id: e.id,
        user_id: e.user_id,
        device_id: e.device_id,
        sequence_number: e.sequence_number,
        event_type: match e.event_type {
            SyncEventType::Upsert => "upsert".into(),
            SyncEventType::Delete => "delete".into(),
        },
        item_id: e.item_id,
        encrypted_delta,
        delta_iv,
        created_at: e.created_at,
    })
}
