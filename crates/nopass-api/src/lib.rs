pub mod config;
pub mod db;
pub mod error;
pub mod middleware;
pub mod models;
pub mod routes;
pub mod state;

use std::net::SocketAddr;

use anyhow::Result;
use axum::Router;
use axum::http::{HeaderName, HeaderValue};
use sqlx::postgres::PgPoolOptions;
use tower::ServiceBuilder;
use tower_http::{
    cors::{AllowHeaders, AllowMethods, AllowOrigin, CorsLayer},
    limit::RequestBodyLimitLayer,
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

    let state = AppState::new(pool, config.clone());
    let app = build_router(state);

    let addr: SocketAddr = config.bind_addr().parse()?;
    info!("nopass-api listening on {addr}");

    let listener = tokio::net::TcpListener::bind(addr).await?;
    // ConnectInfo is needed so rate-limiting middleware can read the client IP.
    axum::serve(
        listener,
        app.into_make_service_with_connect_info::<SocketAddr>(),
    )
    .await?;

    Ok(())
}

pub fn build_router(state: AppState) -> Router {
    // ── CORS ─────────────────────────────────────────────────────────────────
    // Only allow explicitly configured origins — never the wildcard "*".
    let allowed_origins: Vec<HeaderValue> = state
        .config
        .allowed_origins
        .iter()
        .filter_map(|o| o.parse::<HeaderValue>().ok())
        .collect();

    let cors = CorsLayer::new()
        .allow_origin(AllowOrigin::list(allowed_origins))
        .allow_headers(AllowHeaders::mirror_request())
        .allow_methods(AllowMethods::mirror_request())
        .allow_credentials(true);

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
        ));

    Router::new()
        .nest("/v1", routes::router(state.clone()))
        // 2 MiB max request body — vault item blobs are small AES-GCM ciphertexts
        .layer(RequestBodyLimitLayer::new(2 * 1024 * 1024))
        .layer(security_headers)
        .layer(TraceLayer::new_for_http())
        .layer(cors)
        .with_state(state)
}
