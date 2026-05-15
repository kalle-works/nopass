pub mod auth;
pub mod devices;
pub mod sync;
pub mod vault;

use std::net::{IpAddr, SocketAddr};

use axum::{
    extract::{ConnectInfo, Request, State},
    http::StatusCode,
    middleware::{self, Next},
    response::IntoResponse,
    routing::get,
    Router,
};

use crate::{middleware::auth::require_auth, state::AppState};

pub fn router(state: AppState) -> Router<AppState> {
    let public = Router::new()
        .route("/health", get(health))
        .nest(
            "/auth",
            auth::public_router().route_layer(middleware::from_fn_with_state(
                state.clone(),
                auth_rate_limit,
            )),
        );

    let protected = Router::new()
        .nest("/auth", auth::protected_router())
        .nest("/devices", devices::router())
        .nest("/vaults", vault::router())
        .nest("/sync", sync::router())
        .route_layer(middleware::from_fn_with_state(state, require_auth));

    Router::new().merge(public).merge(protected)
}

/// Per-IP rate limiter middleware for auth endpoints (20 req/min).
async fn auth_rate_limit(
    State(state): State<AppState>,
    req: Request,
    next: Next,
) -> impl IntoResponse {
    let ip = extract_client_ip(&req);

    if state.auth_rate_limiter.check_key(&ip).is_err() {
        return (
            StatusCode::TOO_MANY_REQUESTS,
            axum::Json(serde_json::json!({ "error": "too many requests, please slow down" })),
        )
            .into_response();
    }

    next.run(req).await
}

fn extract_client_ip(req: &Request) -> IpAddr {
    if let Some(forwarded) = req
        .headers()
        .get("x-forwarded-for")
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.split(',').next())
        .and_then(|s| s.trim().parse::<IpAddr>().ok())
    {
        return forwarded;
    }

    req.extensions()
        .get::<ConnectInfo<SocketAddr>>()
        .map(|ci| ci.0.ip())
        .unwrap_or(IpAddr::from([127, 0, 0, 1]))
}

async fn health() -> &'static str {
    "ok"
}
