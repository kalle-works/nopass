use axum::{extract::State, routing::post, Extension, Json, Router};
use base64::{engine::general_purpose::STANDARD as B64, Engine};
use chrono::Utc;
use nopass_models::{
    SyncCheckpoint, SyncEvent as ModelSyncEvent, SyncEventType, SyncRequest, SyncResponse,
    VectorClock,
};
use uuid::Uuid;

use crate::{
    db::sync as db_sync,
    error::{ApiError, ApiResult},
    middleware::auth::AuthUser,
    models::vault::SyncEvent as DbSyncEvent,
    state::AppState,
};

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

async fn push_events(
    State(state): State<AppState>,
    Extension(auth): Extension<AuthUser>,
    Json(req): Json<Vec<ModelSyncEvent>>,
) -> ApiResult<Json<serde_json::Value>> {
    let db_events: Result<Vec<DbSyncEvent>, ApiError> = req
        .into_iter()
        .map(|e| {
            // Validate event belongs to the authenticated user
            if e.user_id != auth.user_id {
                return Err(ApiError::Unauthorized(
                    "event user_id does not match session".into(),
                ));
            }
            model_to_db_event(e)
        })
        .collect();

    let db_events = db_events?;
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
