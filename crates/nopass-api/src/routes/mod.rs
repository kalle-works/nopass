pub mod auth;
pub mod devices;
pub mod sync;
pub mod vault;

use axum::{middleware, routing::get, Router};

use crate::{middleware::auth::require_auth, state::AppState};

pub fn router(state: AppState) -> Router<AppState> {
    let public = Router::new().nest("/auth", auth::public_router());

    let protected = Router::new()
        .nest("/auth", auth::protected_router())
        .nest("/devices", devices::router())
        .nest("/vaults", vault::router())
        .nest("/sync", sync::router())
        .route("/health", get(health))
        .route_layer(middleware::from_fn_with_state(state, require_auth));

    Router::new().merge(public).merge(protected)
}

async fn health() -> &'static str {
    "ok"
}
