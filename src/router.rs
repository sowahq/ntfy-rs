use crate::{
    auth,
    handlers::{health, publish, subscribe},
    state::AppState,
};
use axum::{routing::{get, put}, Router};
use std::sync::Arc;
use tower_http::{cors::CorsLayer, trace::TraceLayer};

pub fn build(state: AppState) -> Router {
    let auth_layer = auth::make_auth_layer(
        state.effective_auth_db().clone(),
        Arc::clone(&state.config),
    );

    let protected = Router::new()
        .route("/:topic", put(publish::publish).post(publish::publish))
        .route("/:topic/json", get(subscribe::subscribe_sse))
        .route_layer(auth_layer)
        .with_state(state.clone());

    Router::new()
        .route("/v1/health", get(health::health))
        .route("/v1/version", get(health::version))
        .route("/v1/stats", get(health::stats))
        .with_state(state)
        .merge(protected)
        .layer(CorsLayer::permissive())
        .layer(TraceLayer::new_for_http())
}
