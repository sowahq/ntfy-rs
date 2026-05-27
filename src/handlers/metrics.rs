use axum::{http::StatusCode, response::IntoResponse};
use metrics_exporter_prometheus::PrometheusHandle;

/// `GET /metrics` — Prometheus text exposition.
///
/// Returns all registered metrics in the standard Prometheus text format.
/// The endpoint is unauthenticated; restrict access at the network level if
/// you don't want metrics to be public.
pub async fn metrics(handle: axum::extract::Extension<PrometheusHandle>) -> impl IntoResponse {
    (
        StatusCode::OK,
        [("content-type", "text/plain; version=0.0.4; charset=utf-8")],
        handle.render(),
    )
}
