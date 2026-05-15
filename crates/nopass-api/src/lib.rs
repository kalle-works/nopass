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
use sqlx::postgres::PgPoolOptions;
use tower_http::{
    cors::{Any, CorsLayer},
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
    axum::serve(listener, app).await?;

    Ok(())
}

pub fn build_router(state: AppState) -> Router {
    let cors = CorsLayer::new()
        .allow_origin(Any)
        .allow_headers(Any)
        .allow_methods(Any);

    Router::new()
        .nest("/v1", routes::router(state.clone()))
        .layer(TraceLayer::new_for_http())
        .layer(cors)
        .with_state(state)
}
