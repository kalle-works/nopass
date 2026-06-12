use axum::{extract::State, routing::get, Extension, Json, Router};
use nopass_models::ActivityEventInfo;

use crate::{
    db::activity as db_activity,
    error::ApiResult,
    middleware::auth::AuthUser,
    state::AppState,
};

pub fn router() -> Router<AppState> {
    Router::new().route("/", get(list_activity))
}

async fn list_activity(
    State(state): State<AppState>,
    Extension(auth): Extension<AuthUser>,
) -> ApiResult<Json<Vec<ActivityEventInfo>>> {
    let events = db_activity::list_for_user(&state.db, auth.user_id, 200).await?;
    Ok(Json(
        events
            .into_iter()
            .map(|e| ActivityEventInfo {
                id: e.id,
                event_type: e.event_type,
                ip: e.ip,
                device_id: e.device_id,
                created_at: e.created_at,
            })
            .collect(),
    ))
}
