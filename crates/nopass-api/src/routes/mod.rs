pub mod activity;
pub mod auth;
pub mod billing;
pub mod devices;
pub mod orgs;
pub mod recovery;
pub mod shares;
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

/// Resolved client IP, honoring X-Forwarded-For only from trusted proxies.
/// Inserted into request extensions so handlers can log activity events.
#[derive(Debug, Clone, Copy)]
pub struct ClientIp(pub IpAddr);

async fn attach_client_ip(
    State(state): State<AppState>,
    mut req: Request,
    next: Next,
) -> impl IntoResponse {
    let ip = extract_client_ip(&req, &state.config.trusted_proxies);
    req.extensions_mut().insert(ClientIp(ip));
    next.run(req).await
}

pub fn router(state: AppState) -> Router<AppState> {
    let public = Router::new()
        .route("/health", get(health))
        .merge(billing::webhook_router())
        .nest(
            "/auth",
            auth::public_router()
                .nest("/recovery", recovery::public_router())
                .route_layer(middleware::from_fn_with_state(
                    state.clone(),
                    auth_rate_limit,
                )),
        )
        .nest(
            "/shares",
            shares::public_router().route_layer(middleware::from_fn_with_state(
                state.clone(),
                auth_rate_limit,
            )),
        );

    let protected = Router::new()
        .nest("/auth", auth::protected_router())
        .nest("/auth/recovery", recovery::protected_router())
        .nest("/shares", shares::router())
        .nest("/billing", billing::router())
        .nest("/activity", activity::router())
        .nest("/devices", devices::router())
        .nest("/organizations", orgs::router())
        .nest("/vaults", vault::router())
        .nest("/sync", sync::router())
        .route_layer(middleware::from_fn_with_state(state.clone(), require_auth));

    Router::new()
        .merge(public)
        .merge(protected)
        .layer(middleware::from_fn_with_state(state, attach_client_ip))
}

/// Per-IP rate limiter middleware for auth endpoints (20 req/min, burst 10).
async fn auth_rate_limit(
    State(state): State<AppState>,
    req: Request,
    next: Next,
) -> impl IntoResponse {
    let ip = extract_client_ip(&req, &state.config.trusted_proxies);

    if state.auth_rate_limiter.check_key(&ip).is_err() {
        return (
            StatusCode::TOO_MANY_REQUESTS,
            axum::Json(serde_json::json!({ "error": "too many requests, please slow down" })),
        )
            .into_response();
    }

    next.run(req).await
}

/// Extract the real client IP.
///
/// X-Forwarded-For is only trusted if the direct TCP peer is in `trusted_proxies`.
/// Without this check, any client can spoof arbitrary IPs and bypass rate limiting.
fn extract_client_ip(req: &Request, trusted_proxies: &[ipnet::IpNet]) -> IpAddr {
    let peer_ip = req
        .extensions()
        .get::<ConnectInfo<SocketAddr>>()
        .map(|ci| ci.0.ip())
        .unwrap_or(IpAddr::from([127, 0, 0, 1]));

    // Only honour X-Forwarded-For when the direct connection comes from a trusted proxy.
    if trusted_proxies.iter().any(|net| net.contains(&peer_ip)) {
        if let Some(forwarded) = req
            .headers()
            .get("x-forwarded-for")
            .and_then(|v| v.to_str().ok())
            .and_then(|v| v.split(',').next())
            .and_then(|s| s.trim().parse::<IpAddr>().ok())
        {
            return forwarded;
        }
    }

    peer_ip
}

async fn health() -> &'static str {
    "ok"
}
