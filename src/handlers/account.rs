//! Self-service account endpoints.
//!
//! All routes require a valid authenticated user (enforced by the auth layer).
//! Anonymous callers receive 401.

use crate::{
    auth::{AuthUser, Role},
    db::users as db_users,
    error::AppError,
    message::generate_id,
    state::AppState,
};
use axum::{
    extract::{Path, State},
    http::StatusCode,
    response::IntoResponse,
    Extension, Json,
};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

// ── request / response types ──────────────────────────────────────────────────

#[derive(Deserialize)]
pub struct RegisterRequest {
    pub username: String,
    pub password: String,
}

#[derive(Deserialize)]
pub struct ChangePasswordRequest {
    pub password: String,
}

#[derive(Deserialize)]
pub struct CreateTokenRequest {
    #[serde(default)]
    pub label: String,
    /// Optional Unix timestamp after which the token is invalid.
    pub expires: Option<i64>,
}

#[derive(Deserialize)]
pub struct SetAccessRequest {
    pub topic: String,
    #[serde(default)]
    pub read: bool,
    #[serde(default)]
    pub write: bool,
}

#[derive(Serialize)]
pub struct TokenResponse {
    pub token: String,
    pub label: String,
    pub expires: Option<i64>,
}

// ── handlers ──────────────────────────────────────────────────────────────────

/// POST /v1/account — register a new user account.
/// Does not require authentication (open registration).
pub async fn register(
    State(state): State<AppState>,
    Json(body): Json<RegisterRequest>,
) -> Result<impl IntoResponse, AppError> {
    if body.username.is_empty() || body.password.is_empty() {
        return Err(AppError::BadRequest("username and password required".into()));
    }
    let hash = bcrypt_hash(&body.password)?;
    let id = generate_id();
    let conn = state.effective_auth_db().get()?;
    db_users::insert_user(&conn, &id, &body.username, &hash, Role::User)
        .map_err(|e| {
            if e.to_string().contains("UNIQUE") {
                AppError::BadRequest("username already exists".into())
            } else {
                AppError::Internal(e.to_string())
            }
        })?;
    Ok((StatusCode::OK, Json(json!({ "username": body.username }))))
}

/// GET /v1/account — return current user info.
pub async fn get_account(
    State(state): State<AppState>,
    Extension(auth_user): Extension<AuthUser>,
) -> Result<Json<Value>, AppError> {
    let user = require_user(&auth_user)?;
    let conn = state.effective_auth_db().get()?;
    let tokens = list_tokens_for_user(&conn, &user.id)?;
    let acl = list_acl_for_user(&conn, &user.id)?;
    Ok(Json(json!({
        "username": user.username,
        "role":     user.role.as_str(),
        "tokens":   tokens,
        "access":   acl,
    })))
}

/// DELETE /v1/account — soft-delete own account.
pub async fn delete_account(
    State(state): State<AppState>,
    Extension(auth_user): Extension<AuthUser>,
) -> Result<impl IntoResponse, AppError> {
    let user = require_user(&auth_user)?;
    let conn = state.effective_auth_db().get()?;
    db_users::delete_user(&conn, &user.id)?;
    Ok(StatusCode::OK)
}

/// PUT /v1/account/password — change own password.
pub async fn change_password(
    State(state): State<AppState>,
    Extension(auth_user): Extension<AuthUser>,
    Json(body): Json<ChangePasswordRequest>,
) -> Result<impl IntoResponse, AppError> {
    let user = require_user(&auth_user)?;
    if body.password.is_empty() {
        return Err(AppError::BadRequest("password required".into()));
    }
    let hash = bcrypt_hash(&body.password)?;
    let conn = state.effective_auth_db().get()?;
    db_users::update_password(&conn, &user.id, &hash)?;
    Ok(StatusCode::OK)
}

/// POST /v1/account/token — create a Bearer token.
pub async fn create_token(
    State(state): State<AppState>,
    Extension(auth_user): Extension<AuthUser>,
    Json(body): Json<CreateTokenRequest>,
) -> Result<Json<Value>, AppError> {
    let user = require_user(&auth_user)?;
    let token = generate_token();
    let conn = state.effective_auth_db().get()?;
    db_users::insert_token(&conn, &token, &user.id, &body.label, body.expires)?;
    Ok(Json(json!({
        "token":   token,
        "label":   body.label,
        "expires": body.expires,
    })))
}

/// DELETE /v1/account/token/:token — revoke a token.
pub async fn delete_token(
    State(state): State<AppState>,
    Extension(auth_user): Extension<AuthUser>,
    Path(token): Path<String>,
) -> Result<impl IntoResponse, AppError> {
    let user = require_user(&auth_user)?;
    let conn = state.effective_auth_db().get()?;
    db_users::delete_token(&conn, &token, &user.id)?;
    Ok(StatusCode::OK)
}

/// GET /v1/account/access — list own ACL entries.
pub async fn get_access(
    State(state): State<AppState>,
    Extension(auth_user): Extension<AuthUser>,
) -> Result<Json<Value>, AppError> {
    let user = require_user(&auth_user)?;
    let conn = state.effective_auth_db().get()?;
    let acl = list_acl_for_user(&conn, &user.id)?;
    Ok(Json(json!({ "access": acl })))
}

/// POST /v1/account/access — grant self read/write on a topic.
pub async fn set_access(
    State(state): State<AppState>,
    Extension(auth_user): Extension<AuthUser>,
    Json(body): Json<SetAccessRequest>,
) -> Result<impl IntoResponse, AppError> {
    let user = require_user(&auth_user)?;
    let conn = state.effective_auth_db().get()?;
    db_users::acl_set(&conn, &user.id, &body.topic, body.read, body.write)?;
    Ok(StatusCode::OK)
}

/// DELETE /v1/account/access/:topic — remove own ACL entry for a topic.
pub async fn delete_access(
    State(state): State<AppState>,
    Extension(auth_user): Extension<AuthUser>,
    Path(topic): Path<String>,
) -> Result<impl IntoResponse, AppError> {
    let user = require_user(&auth_user)?;
    let conn = state.effective_auth_db().get()?;
    db_users::acl_delete(&conn, &user.id, &topic)?;
    Ok(StatusCode::OK)
}

// ── helpers ───────────────────────────────────────────────────────────────────

/// Require an authenticated user, returning 401 for anonymous callers.
pub fn require_user(auth_user: &AuthUser) -> Result<&crate::auth::User, AppError> {
    auth_user.user.as_ref().ok_or(AppError::Unauthorized)
}

pub fn bcrypt_hash(password: &str) -> Result<String, AppError> {
    let p = password.to_string();
    tokio::task::block_in_place(|| {
        bcrypt::hash(&p, 10).map_err(|e| AppError::Internal(e.to_string()))
    })
}

fn generate_token() -> String {
    use rand::distributions::Alphanumeric;
    use rand::Rng;
    rand::thread_rng()
        .sample_iter(&Alphanumeric)
        .take(32)
        .map(char::from)
        .collect()
}

fn list_tokens_for_user(
    conn: &rusqlite::Connection,
    user_id: &str,
) -> Result<Vec<TokenResponse>, AppError> {
    let mut stmt = conn
        .prepare_cached(
            "SELECT token, label, expires FROM tokens WHERE user_id = ?1 ORDER BY rowid ASC",
        )
        .map_err(|e| AppError::Internal(e.to_string()))?;
    let rows = stmt
        .query_map(rusqlite::params![user_id], |row| {
            Ok(TokenResponse {
                token: row.get(0)?,
                label: row.get(1)?,
                expires: row.get(2)?,
            })
        })
        .map_err(|e| AppError::Internal(e.to_string()))?;
    rows.collect::<Result<Vec<_>, _>>()
        .map_err(|e| AppError::Internal(e.to_string()))
}

fn list_acl_for_user(
    conn: &rusqlite::Connection,
    user_id: &str,
) -> Result<Vec<Value>, AppError> {
    let mut stmt = conn
        .prepare_cached(
            "SELECT topic, read, write FROM topic_acl WHERE user_id = ?1 ORDER BY topic ASC",
        )
        .map_err(|e| AppError::Internal(e.to_string()))?;
    let rows = stmt
        .query_map(rusqlite::params![user_id], |row| {
            let topic: String = row.get(0)?;
            let read: bool = row.get::<_, i32>(1)? != 0;
            let write: bool = row.get::<_, i32>(2)? != 0;
            Ok(json!({ "topic": topic, "read": read, "write": write }))
        })
        .map_err(|e| AppError::Internal(e.to_string()))?;
    rows.collect::<Result<Vec<_>, _>>()
        .map_err(|e| AppError::Internal(e.to_string()))
}

/// Shared helper used by admin.rs to list tokens for any user.
pub fn list_tokens_for_user_pub(
    conn: &rusqlite::Connection,
    user_id: &str,
) -> Result<Vec<TokenResponse>, AppError> {
    list_tokens_for_user(conn, user_id)
}

/// Shared helper used by admin.rs to list ACL for any user.
pub fn list_acl_for_user_pub(
    conn: &rusqlite::Connection,
    user_id: &str,
) -> Result<Vec<Value>, AppError> {
    list_acl_for_user(conn, user_id)
}


