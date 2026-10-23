use axum::{
    http::StatusCode,
    response::{IntoResponse, Response},
    Json,
};
use nopass_models::ErrorResponse;
use tracing::error;

pub type ApiResult<T> = Result<T, ApiError>;

#[derive(Debug)]
pub enum ApiError {
    NotFound(String),
    Unauthorized(String),
    Forbidden(String),
    BadRequest(String),
    Conflict(String),
    Gone(String),
    TooManyRequests,
    /// Per-account login backoff; sets Retry-After.
    Throttled { retry_after_secs: i64 },
    Internal(anyhow::Error),
}

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        let (status, message) = match self {
            ApiError::NotFound(msg) => (StatusCode::NOT_FOUND, msg),
            ApiError::Unauthorized(msg) => (StatusCode::UNAUTHORIZED, msg),
            ApiError::Forbidden(msg) => (StatusCode::FORBIDDEN, msg),
            ApiError::BadRequest(msg) => (StatusCode::BAD_REQUEST, msg),
            ApiError::Conflict(msg) => (StatusCode::CONFLICT, msg),
            ApiError::Gone(msg) => (StatusCode::GONE, msg),
            ApiError::TooManyRequests => (
                StatusCode::TOO_MANY_REQUESTS,
                "too many requests — try again later".into(),
            ),
            ApiError::Throttled { retry_after_secs } => {
                return (
                    StatusCode::TOO_MANY_REQUESTS,
                    [(axum::http::header::RETRY_AFTER, retry_after_secs.to_string())],
                    Json(ErrorResponse {
                        error: "too many login attempts — try again later".into(),
                    }),
                )
                    .into_response();
            }
            ApiError::Internal(err) => {
                error!("internal error: {err:#}");
                (StatusCode::INTERNAL_SERVER_ERROR, "internal server error".into())
            }
        };

        (status, Json(ErrorResponse { error: message })).into_response()
    }
}

impl From<anyhow::Error> for ApiError {
    fn from(err: anyhow::Error) -> Self {
        ApiError::Internal(err)
    }
}

impl From<sqlx::Error> for ApiError {
    fn from(err: sqlx::Error) -> Self {
        ApiError::Internal(err.into())
    }
}
