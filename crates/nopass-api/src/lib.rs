pub mod config;
pub mod db;
pub mod error;
pub mod middleware;
pub mod models;
pub mod routes;
pub mod state;
pub mod stripe;

use std::{net::SocketAddr, sync::Arc};

use anyhow::Result;
use axum::{Router, http::{HeaderName, HeaderValue, Request}, routing::get};
use sqlx::postgres::PgPoolOptions;
use tower::ServiceBuilder;
use tower_http::{
    cors::{AllowOrigin, CorsLayer},
    limit::RequestBodyLimitLayer,
    request_id::{MakeRequestUuid, PropagateRequestIdLayer, RequestId, SetRequestIdLayer},
    set_header::SetResponseHeaderLayer,
    trace::TraceLayer,
};
use tracing::info;

use crate::{config::Config, state::AppState};

pub async fn run() -> Result<()> {
    let config = Config::from_env()?;
    let pool = PgPoolOptions::new()
        .max_connections(20)
        .connect(&config.database_url)
        .await?;

    sqlx::migrate!("src/db/migrations").run(&pool).await?;

    let state = Arc::new(AppState::new(pool, config.clone()));

    // Evict expired SRP sessions every 60s to prevent memory exhaustion.
    state.spawn_srp_cleanup();

    let app = build_router((*state).clone());

    let addr: SocketAddr = config.bind_addr().parse()?;
    info!("nopass-api listening on {addr}");

    let listener = tokio::net::TcpListener::bind(addr).await?;
    // ConnectInfo is required for the rate-limiting middleware to read the direct TCP IP.
    axum::serve(
        listener,
        app.into_make_service_with_connect_info::<SocketAddr>(),
    )
    .await?;

    Ok(())
}

async fn strip_client_request_id(
    mut req: axum::extract::Request,
    next: axum::middleware::Next,
) -> axum::response::Response {
    req.headers_mut().remove("x-request-id");
    next.run(req).await
}

pub fn build_router(state: AppState) -> Router {
    // ── CORS ─────────────────────────────────────────────────────────────────
    // Explicit allowlist — never wildcards. No allow_credentials: API uses
    // Bearer tokens only, not cookies, so credentials flag is not needed.
    let allowed_origins: Vec<HeaderValue> = state
        .config
        .allowed_origins
        .iter()
        .filter_map(|o| o.parse::<HeaderValue>().ok())
        .collect();

    let cors = CorsLayer::new()
        .allow_origin(AllowOrigin::list(allowed_origins))
        .allow_headers([
            axum::http::header::AUTHORIZATION,
            axum::http::header::CONTENT_TYPE,
        ])
        .allow_methods([
            axum::http::Method::GET,
            axum::http::Method::POST,
            axum::http::Method::PUT,
            axum::http::Method::DELETE,
            axum::http::Method::OPTIONS,
        ]);
    // Note: allow_credentials intentionally omitted — Bearer token auth does not need it.

    // ── Security headers ─────────────────────────────────────────────────────
    let security_headers = ServiceBuilder::new()
        .layer(SetResponseHeaderLayer::if_not_present(
            HeaderName::from_static("x-frame-options"),
            HeaderValue::from_static("DENY"),
        ))
        .layer(SetResponseHeaderLayer::if_not_present(
            HeaderName::from_static("x-content-type-options"),
            HeaderValue::from_static("nosniff"),
        ))
        .layer(SetResponseHeaderLayer::if_not_present(
            HeaderName::from_static("referrer-policy"),
            HeaderValue::from_static("strict-origin-when-cross-origin"),
        ))
        .layer(SetResponseHeaderLayer::if_not_present(
            HeaderName::from_static("x-xss-protection"),
            HeaderValue::from_static("0"),
        ))
        .layer(SetResponseHeaderLayer::if_not_present(
            HeaderName::from_static("permissions-policy"),
            HeaderValue::from_static("camera=(), microphone=(), geolocation=()"),
        ))
        // HSTS: enforce TLS for 1 year, include subdomains. Browsers ignore this for HTTP.
        .layer(SetResponseHeaderLayer::if_not_present(
            HeaderName::from_static("strict-transport-security"),
            HeaderValue::from_static("max-age=31536000; includeSubDomains"),
        ));

    // TraceLayer customised to stamp every span with the request ID so all
    // log lines for a single request share a common field.
    let trace_layer = TraceLayer::new_for_http().make_span_with(|req: &Request<_>| {
        let request_id = req
            .extensions()
            .get::<RequestId>()
            .and_then(|id| id.header_value().to_str().ok())
            .unwrap_or("-");
        tracing::info_span!(
            "request",
            request_id,
            method  = %req.method(),
            uri     = %req.uri(),
        )
    });

    Router::new()
        .route("/health", get(|| async { "ok" }))
        .nest("/v1", routes::router(state.clone()))
        // 2 MiB max body — AES-GCM vault blobs are small; this limits abuse.
        .layer(RequestBodyLimitLayer::new(2 * 1024 * 1024))
        .layer(security_headers)
        .layer(trace_layer)
        // Layers below run outside TraceLayer (last added = outermost).
        // SetRequestId generates a UUID first; PropagateRequestId copies it
        // to the response header so clients can quote it in bug reports.
        // The map_request layer strips any client-supplied x-request-id header so
        // log injection is not possible — server always generates the UUID.
        .layer(PropagateRequestIdLayer::x_request_id())
        .layer(SetRequestIdLayer::x_request_id(MakeRequestUuid))
        .layer(axum::middleware::from_fn(strip_client_request_id))
        .layer(cors)
        .with_state(state)
}
