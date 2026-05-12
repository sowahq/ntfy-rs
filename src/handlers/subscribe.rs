use crate::{
    auth::{authorize, AuthUser, Permission},
    db::cache,
    error::AppError,
    message::{parse_topics, valid_topic, Message},
    state::AppState,
};
use axum::{
    extract::{Path, Query, State},
    response::{
        sse::{Event, KeepAlive, Sse},
        IntoResponse,
    },
    Extension,
};
use futures_util::stream::{self, Stream, StreamExt};
use serde::Deserialize;
use std::{convert::Infallible, sync::Arc, time::Duration};
use tokio::sync::broadcast;
use tokio_stream::wrappers::BroadcastStream;

/// Query parameters shared by all subscribe endpoints.
#[derive(Debug, Deserialize)]
#[allow(dead_code)]
pub struct SubscribeParams {
    #[serde(default)]
    pub poll: Option<String>,
    pub since: Option<String>,
    pub priority: Option<String>,
    pub tags: Option<String>,
    pub message: Option<String>,
    pub title: Option<String>,
}

impl SubscribeParams {
    fn is_poll(&self) -> bool {
        self.poll
            .as_deref()
            .map(|v| matches!(v, "1" | "true" | "yes"))
            .unwrap_or(false)
    }

    fn since_time(&self) -> i64 {
        match self.since.as_deref() {
            Some("all") => 0,
            Some(s) => s.parse::<i64>().unwrap_or(0),
            None => {
                if self.is_poll() {
                    chrono::Utc::now().timestamp() - 10
                } else {
                    chrono::Utc::now().timestamp()
                }
            }
        }
    }
}

// ── SSE subscribe: GET /{topic}/json ─────────────────────────────────────────

pub async fn subscribe_sse(
    State(state): State<AppState>,
    Path(topic): Path<String>,
    Query(params): Query<SubscribeParams>,
    Extension(auth_user): Extension<AuthUser>,
) -> Result<impl IntoResponse, AppError> {
    if !valid_topic(&topic) {
        return Err(AppError::TopicInvalid);
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
        Permission::Read,
    )?;

    if params.is_poll() {
        let since = params.since_time();
        let msgs = {
            let conn = state.db.get()?;
            cache::since_time(&conn, &topic, since)?
        };
        let stream = stream::iter(msgs.into_iter().map(|m| {
            let data = serde_json::to_string(&m).unwrap_or_default();
            Ok::<Event, Infallible>(Event::default().data(data))
        }));
        return Ok(Sse::new(stream).into_response());
    }

    let since = params.since_time();
    let cached = {
        let conn = state.db.get()?;
        cache::since_time(&conn, &topic, since)?
    };

    let t = state.topics.get_or_create(&topic);
    let rx = t.tx.subscribe();
    visitor.increment_subscriptions();

    // Decrement subscription count when the stream ends.
    // We wrap the stream in a guard that decrements on drop.
    let keepalive_secs = state.config.keepalive_secs;
    let visitor_clone = Arc::clone(&visitor);
    let stream = build_sse_stream(topic.clone(), cached, rx, visitor_clone);

    Ok(Sse::new(stream)
        .keep_alive(
            KeepAlive::new()
                .interval(Duration::from_secs(keepalive_secs))
                .text("keepalive"),
        )
        .into_response())
}

fn build_sse_stream(
    topic: String,
    cached: Vec<Message>,
    rx: broadcast::Receiver<Arc<Message>>,
    visitor: Arc<crate::visitor::Visitor>,
) -> impl Stream<Item = Result<Event, Infallible>> {
    let open_msg = Message::new_open(&topic);
    let open_event = stream::once(async move {
        let data = serde_json::to_string(&open_msg).unwrap_or_default();
        Ok::<Event, Infallible>(Event::default().data(data))
    });

    let cached_stream = stream::iter(cached.into_iter().map(|m| {
        let data = serde_json::to_string(&m).unwrap_or_default();
        Ok::<Event, Infallible>(Event::default().data(data))
    }));

    let live_stream = BroadcastStream::new(rx).filter_map(|result| async move {
        match result {
            Ok(msg) => {
                let data = serde_json::to_string(&*msg).unwrap_or_default();
                Some(Ok::<Event, Infallible>(Event::default().data(data)))
            }
            Err(tokio_stream::wrappers::errors::BroadcastStreamRecvError::Lagged(n)) => {
                tracing::warn!(skipped = n, "subscriber lagged");
                None
            }
        }
    });

    // Decrement subscription count when the stream is dropped (client disconnects).
    let guard_stream = stream::once(async move {
        let _guard = SubscriptionGuard(visitor);
        // Yield nothing — just hold the guard until the stream ends.
        futures_util::future::pending::<Option<Result<Event, Infallible>>>().await
    })
    .filter_map(|x| async move { x });

    open_event
        .chain(cached_stream)
        .chain(live_stream)
        .chain(guard_stream)
}

/// RAII guard that decrements the visitor's subscription count on drop.
struct SubscriptionGuard(Arc<crate::visitor::Visitor>);

impl Drop for SubscriptionGuard {
    fn drop(&mut self) {
        self.0.decrement_subscriptions();
    }
}

// ── Stubs for Phase 4 ─────────────────────────────────────────────────────────

#[allow(dead_code)]
pub async fn subscribe_json(
    State(state): State<AppState>,
    Path(topic): Path<String>,
    Query(params): Query<SubscribeParams>,
    Extension(auth_user): Extension<AuthUser>,
) -> Result<impl IntoResponse, AppError> {
    subscribe_sse(State(state), Path(topic), Query(params), Extension(auth_user)).await
}

#[allow(dead_code)]
pub async fn subscribe_multi_sse(
    State(state): State<AppState>,
    Path(topics_raw): Path<String>,
    Query(params): Query<SubscribeParams>,
    Extension(auth_user): Extension<AuthUser>,
) -> Result<impl IntoResponse, AppError> {
    let topics = parse_topics(&topics_raw).ok_or(AppError::TopicInvalid)?;
    let topic = topics.into_iter().next().ok_or(AppError::TopicInvalid)?;
    subscribe_sse(State(state), Path(topic), Query(params), Extension(auth_user)).await
}
