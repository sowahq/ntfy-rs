use crate::{
    auth::{authorize, AuthUser, Permission},
    db::cache,
    error::AppError,
    message::{parse_topics, valid_topic, Message},
    state::AppState,
    upstream,
};
use axum::{
    body::Bytes,
    extract::{Path, State},
    http::{HeaderMap, StatusCode},
    response::IntoResponse,
    Extension, Json,
};
use std::sync::Arc;

/// PUT/POST /{topic}
pub async fn publish(
    State(state): State<AppState>,
    Path(topic): Path<String>,
    Extension(auth_user): Extension<AuthUser>,
    headers: HeaderMap,
    body: Bytes,
) -> Result<impl IntoResponse, AppError> {
    if !valid_topic(&topic) {
        return Err(AppError::TopicInvalid);
    }
    if body.len() > state.config.message_size_limit {
        return Err(AppError::MessageTooLarge);
    }

    // Rate limiting
    let visitor = state.visitors.get_or_create(auth_user.ip);
    if !visitor.request_allowed() {
        return Err(AppError::TooManyRequests);
    }

    // Authorization
    authorize(
        state.effective_auth_db(),
        &state.config,
        &auth_user,
        &topic,
        Permission::Write,
    )?;

    let body_str = String::from_utf8_lossy(&body).into_owned();
    let mut msg = Message::new_message(&topic, body_str);

    // ── parse metadata headers ────────────────────────────────────────────
    if let Some(v) = header_val(&headers, &["x-title", "title", "t"]) {
        msg.title = v;
    }
    if let Some(v) = header_val(&headers, &["x-priority", "priority", "prio", "p"]) {
        msg.priority = parse_priority(&v);
    }
    if let Some(v) = header_val(&headers, &["x-tags", "tags", "tag", "ta"]) {
        msg.tags = v.split(',').map(|s| s.trim().to_string()).collect();
    }
    if let Some(v) = header_val(&headers, &["x-click", "click"]) {
        msg.click = v;
    }
    if let Some(v) = header_val(&headers, &["x-icon", "icon"]) {
        msg.icon = v;
    }
    if let Some(v) = header_val(&headers, &["x-markdown", "markdown", "md"]) {
        if is_truthy(&v) {
            msg.content_type = "text/markdown".to_string();
        }
    }
    if let Some(v) = header_val(&headers, &["content-type"]) {
        if v.to_lowercase().contains("text/markdown") {
            msg.content_type = "text/markdown".to_string();
        }
    }

    // ── parse delay headers (X-Delay / X-At / X-In) ──────────────────────
    // Returns Some(unix_timestamp) when the message should be delivered later,
    // or None for immediate delivery.
    let deliver_at: Option<i64> =
        if let Some(v) = header_val(&headers, &["x-delay", "delay", "x-at", "at", "x-in", "in"]) {
            parse_delay(&v, state.config.max_delay_secs)
                .map_err(|_| AppError::BadRequest("invalid delay value".into()))?
        } else {
            None
        };

    let now = chrono::Utc::now().timestamp();
    let expires = now + state.config.cache_duration_secs as i64;
    msg.expires = Some(expires);

    let is_delayed = deliver_at.is_some();

    // Persist — published=1 for immediate, published=0 for delayed.
    {
        let conn = state.db.get()?;
        if let Some(fire_at) = deliver_at {
            // Store with the scheduled delivery time as `time` and published=0.
            // The manager will flip published=1 and fan-out when the time comes.
            let mut delayed = msg.clone();
            delayed.time = fire_at;
            cache::insert_delayed(&conn, &delayed)?;
        } else {
            cache::insert(&conn, &msg)?;
        }
    }

    // Fan out immediately only for non-delayed messages.
    if !is_delayed {
        state.topics.publish(&topic, Arc::new(msg.clone()));

        // iOS upstream poll-forward — fire-and-forget.
        if state.config.upstream_base_url.is_some() {
            let state2 = state.clone();
            let topic2 = topic.clone();
            tokio::spawn(async move {
                upstream::forward_poll(&state2.config, &topic2, &state2.http).await;
            });
        }
    }

    tracing::debug!(topic = %topic, id = %msg.id, delayed = is_delayed, "published");

    Ok((StatusCode::OK, Json(msg)))
}

/// POST /{topic1},{topic2},... — publish to multiple topics at once.
#[allow(dead_code)]
pub async fn publish_multi(
    State(state): State<AppState>,
    Path(topics_raw): Path<String>,
    Extension(auth_user): Extension<AuthUser>,
    headers: HeaderMap,
    body: Bytes,
) -> Result<impl IntoResponse, AppError> {
    let topics = parse_topics(&topics_raw).ok_or(AppError::TopicInvalid)?;
    for topic in &topics {
        publish(
            State(state.clone()),
            Path(topic.clone()),
            Extension(auth_user.clone()),
            headers.clone(),
            body.clone(),
        )
        .await?;
    }
    Ok((StatusCode::OK, Json(serde_json::json!({ "topics": topics }))))
}

// ── helpers ───────────────────────────────────────────────────────────────────

fn header_val(headers: &HeaderMap, names: &[&str]) -> Option<String> {
    for name in names {
        if let Some(v) = headers.get(*name) {
            if let Ok(s) = v.to_str() {
                let s = s.trim().to_string();
                if !s.is_empty() {
                    return Some(s);
                }
            }
        }
    }
    None
}

fn parse_priority(s: &str) -> i32 {
    match s.to_lowercase().as_str() {
        "1" | "min" => 1,
        "2" | "low" => 2,
        "3" | "default" => 3,
        "4" | "high" => 4,
        "5" | "urgent" | "max" => 5,
        _ => 3,
    }
}

fn is_truthy(s: &str) -> bool {
    matches!(s.to_lowercase().as_str(), "1" | "true" | "yes")
}

/// Parse a delay value into a future Unix timestamp.
///
/// Accepted formats (matching ntfy wire protocol):
/// - Unix timestamp:  `"1712345678"`
/// - RFC 3339:        `"2024-04-05T12:00:00Z"`
/// - Duration string: `"30m"`, `"2h"`, `"1d"`, `"90s"`
///
/// Returns `Err` if the value is unparseable or exceeds `max_delay_secs`.
/// Returns `Ok(None)` if the value resolves to "now or past" (treat as immediate).
fn parse_delay(s: &str, max_delay_secs: u64) -> Result<Option<i64>, ()> {
    let now = chrono::Utc::now().timestamp();

    // Try plain Unix timestamp first.
    if let Ok(ts) = s.parse::<i64>() {
        return validate_delay(ts, now, max_delay_secs);
    }

    // Try RFC 3339 / ISO 8601.
    if let Ok(dt) = chrono::DateTime::parse_from_rfc3339(s) {
        return validate_delay(dt.timestamp(), now, max_delay_secs);
    }

    // Try duration string: optional integer + unit suffix.
    if let Some(secs) = parse_duration_str(s) {
        return validate_delay(now + secs, now, max_delay_secs);
    }

    Err(())
}

/// Validate a resolved timestamp: reject past/now (return None = immediate)
/// and reject values beyond max_delay_secs (return Err).
fn validate_delay(ts: i64, now: i64, max_delay_secs: u64) -> Result<Option<i64>, ()> {
    if ts <= now {
        return Ok(None); // already in the past — deliver immediately
    }
    if (ts - now) as u64 > max_delay_secs {
        return Err(()); // too far in the future
    }
    Ok(Some(ts))
}

/// Parse simple duration strings: `"30s"`, `"5m"`, `"2h"`, `"1d"`.
/// Returns the number of seconds, or None if unrecognised.
fn parse_duration_str(s: &str) -> Option<i64> {
    let s = s.trim();
    let (num_part, unit) = if let Some(stripped) = s.strip_suffix('s') {
        (stripped, 1i64)
    } else if let Some(stripped) = s.strip_suffix('m') {
        (stripped, 60)
    } else if let Some(stripped) = s.strip_suffix('h') {
        (stripped, 3600)
    } else if let Some(stripped) = s.strip_suffix('d') {
        (stripped, 86400)
    } else {
        return None;
    };
    num_part.trim().parse::<i64>().ok().map(|n| n * unit)
}
