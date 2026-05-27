//! HTTP handlers for the Web Push API.
//!
//! Endpoints (all under `/v1/webpush/`):
//!
//! | Method | Path                          | Description                              |
//! |--------|-------------------------------|------------------------------------------|
//! | GET    | `/v1/webpush/vapid-key`       | Return the server's VAPID public key     |
//! | POST   | `/v1/webpush/subscriptions`   | Register a browser push subscription    |
//! | DELETE | `/v1/webpush/subscriptions/:id` | Unregister a subscription              |

use crate::{
    db::webpush::{add_subscription, delete_subscription, Subscription},
    error::AppError,
    message::valid_topic,
    state::AppState,
};
use axum::{
    extract::{Path, State},
    http::StatusCode,
    response::IntoResponse,
    Json,
};
use chrono::Utc;
use serde::{Deserialize, Serialize};
use uuid::Uuid;

// ── GET /v1/webpush/vapid-key ─────────────────────────────────────────────────

#[derive(Serialize)]
struct VapidKeyResponse {
    #[serde(rename = "publicKey")]
    public_key: String,
}

/// Return the server's VAPID public key (uncompressed P-256, base64url).
///
/// Browsers use this value as the `applicationServerKey` when calling
/// `pushManager.subscribe()`.
pub async fn get_vapid_key(
    State(state): State<AppState>,
) -> Result<impl IntoResponse, AppError> {
    let vapid = state
        .vapid
        .as_ref()
        .ok_or_else(|| AppError::Internal("web push is not configured".into()))?;

    Ok(Json(VapidKeyResponse {
        public_key: vapid.public_key_b64.clone(),
    }))
}

// ── POST /v1/webpush/subscriptions ────────────────────────────────────────────

#[derive(Deserialize)]
pub struct SubscribeRequest {
    pub topic: String,
    pub endpoint: String,
    pub keys: SubscribeKeys,
}

#[derive(Deserialize)]
pub struct SubscribeKeys {
    pub p256dh: String,
    pub auth: String,
}

#[derive(Serialize)]
struct SubscribeResponse {
    id: String,
}

/// Register a new web push subscription for a topic.
///
/// The caller supplies the `PushSubscription` values obtained from the browser's
/// `pushManager.subscribe()` call. Returns the opaque subscription ID, which the
/// client must retain in order to unsubscribe.
pub async fn subscribe(
    State(state): State<AppState>,
    Json(req): Json<SubscribeRequest>,
) -> Result<impl IntoResponse, AppError> {
    if !valid_topic(&req.topic) {
        return Err(AppError::TopicInvalid);
    }

    if !req.endpoint.starts_with("https://") {
        return Err(AppError::BadRequest(
            "endpoint must use https://".into(),
        ));
    }

    if req.keys.p256dh.is_empty() || req.keys.auth.is_empty() {
        return Err(AppError::BadRequest("p256dh and auth keys are required".into()));
    }

    let sub = Subscription {
        id: Uuid::new_v4().to_string(),
        topic: req.topic,
        endpoint: req.endpoint,
        p256dh: req.keys.p256dh,
        auth: req.keys.auth,
        created: Utc::now().timestamp(),
    };

    {
        let conn = state.db.get()?;
        add_subscription(&conn, &sub).map_err(|e| AppError::Internal(e.to_string()))?;
    }

    Ok((StatusCode::CREATED, Json(SubscribeResponse { id: sub.id })))
}

// ── DELETE /v1/webpush/subscriptions/:id ─────────────────────────────────────

/// Unregister a web push subscription by its opaque ID.
///
/// Returns 204 whether or not the ID existed (idempotent).
pub async fn unsubscribe(
    State(state): State<AppState>,
    Path(id): Path<String>,
) -> Result<impl IntoResponse, AppError> {
    let conn = state.db.get()?;
    delete_subscription(&conn, &id).map_err(|e| AppError::Internal(e.to_string()))?;
    Ok(StatusCode::NO_CONTENT)
}
