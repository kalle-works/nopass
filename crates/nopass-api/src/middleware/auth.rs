use axum::{
    extract::{Request, State},
    middleware::Next,
    response::Response,
};
use uuid::Uuid;

use crate::{db::sessions, error::ApiError, state::AppState};

/// Extracted and validated auth context, injected as Extension into handlers
#[derive(Debug, Clone)]
pub struct AuthUser {
    pub user_id: Uuid,
    pub device_id: Option<Uuid>,
    pub raw_token: String,
}

/// Axum middleware that validates Bearer session tokens.
pub async fn require_auth(
    State(state): State<AppState>,
    mut req: Request,
    next: Next,
) -> Result<Response, ApiError> {
    let token = extract_bearer_token(req.headers())
        .ok_or_else(|| ApiError::Unauthorized("missing Bearer token".into()))?
        .to_owned();

    let session = sessions::find_session_by_token(&state.db, &token)
        .await
        .map_err(ApiError::Internal)?
        .ok_or_else(|| ApiError::Unauthorized("invalid or expired session".into()))?;

    req.extensions_mut().insert(AuthUser {
        user_id: session.user_id,
        device_id: session.device_id,
        raw_token: token,
    });

    Ok(next.run(req).await)
}

fn extract_bearer_token(headers: &axum::http::HeaderMap) -> Option<&str> {
    headers
        .get(axum::http::header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.strip_prefix("Bearer "))
}
