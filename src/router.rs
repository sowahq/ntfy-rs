use crate::{
    auth,
    handlers::{health, publish, subscribe, ws},
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

    // A single path parameter captures both "topic" and "topic1,topic2,...".
    // The handlers themselves detect commas and dispatch to single vs multi logic.
    let protected = Router::new()
        // ── publish (single topic only) ───────────────────────────────────
        .route("/:topic",      put(publish::publish).post(publish::publish))
        // ── subscribe ─────────────────────────────────────────────────────
        // NDJSON — primary format used by ntfy clients
        .route("/:topics/json", get(subscribe::subscribe_ndjson))
        // SSE — browser EventSource / legacy
        .route("/:topics/sse",  get(subscribe::subscribe_sse))
        // WebSocket — default for ntfy Android app
        .route("/:topics/ws",   get(ws::subscribe_ws))
        .route_layer(auth_layer)
        .with_state(state.clone());

    Router::new()
        .route("/v1/health",  get(health::health))
        .route("/v1/version", get(health::version))
        .route("/v1/stats",   get(health::stats))
        .with_state(state)
        .merge(protected)
        .layer(CorsLayer::permissive())
        .layer(TraceLayer::new_for_http())
}
