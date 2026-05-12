//! Admin-only user management endpoints.
//!
//! All routes require `role = admin`. Non-admin authenticated users receive 403.
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
use serde::Deserialize;
use serde_json::{json, Value};

use super::account::{bcrypt_hash, list_acl_for_user_pub, list_tokens_for_user_pub, require_user};

// ── request types ─────────────────────────────────────────────────────────────

#[derive(Deserialize)]
pub struct CreateUserRequest {
    pub username: String,
    pub password: String,
    #[serde(default)]
    pub role: String, // "admin" | "user" (default "user")
}

#[derive(Deserialize)]
pub struct SetRoleRequest {
    pub role: String,
}

#[derive(Deserialize)]
pub struct SetAccessRequest {
    pub topic: String,
    #[serde(default)]
    pub read: bool,
    #[serde(default)]
    pub write: bool,
}

// ── helpers ───────────────────────────────────────────────────────────────────

fn require_admin(auth_user: &AuthUser) -> Result<&crate::auth::User, AppError> {
    let user = require_user(auth_user)?;
    if !user.role.is_admin() {
        return Err(AppError::Forbidden);
    }
    Ok(user)
}

// ── handlers ──────────────────────────────────────────────────────────────────

/// GET /v1/admin/users — list all non-deleted users.
pub async fn list_users(
    State(state): State<AppState>,
    Extension(auth_user): Extension<AuthUser>,
) -> Result<Json<Value>, AppError> {
    require_admin(&auth_user)?;
    let conn = state.effective_auth_db().get()?;
    let mut stmt = conn
        .prepare_cached(
            "SELECT id, username, role FROM users WHERE deleted = 0 ORDER BY username ASC",
        )
        .map_err(|e| AppError::Internal(e.to_string()))?;
    let rows = stmt
        .query_map([], |row| {
            let id: String = row.get(0)?;
            let username: String = row.get(1)?;
            let role: String = row.get(2)?;
            Ok((id, username, role))
        })
        .map_err(|e| AppError::Internal(e.to_string()))?;

    let mut users: Vec<Value> = Vec::new();
    for row in rows {
        let (id, username, role) = row.map_err(|e| AppError::Internal(e.to_string()))?;
        let tokens = list_tokens_for_user_pub(&conn, &id)?;
        let acl = list_acl_for_user_pub(&conn, &id)?;
        users.push(json!({
            "username": username,
            "role":     role,
            "tokens":   tokens,
            "access":   acl,
        }));
    }
    Ok(Json(json!({ "users": users })))
}

/// POST /v1/admin/users — create a user (admin or regular).
pub async fn create_user(
    State(state): State<AppState>,
    Extension(auth_user): Extension<AuthUser>,
    Json(body): Json<CreateUserRequest>,
) -> Result<impl IntoResponse, AppError> {
    require_admin(&auth_user)?;
    if body.username.is_empty() || body.password.is_empty() {
        return Err(AppError::BadRequest("username and password required".into()));
    }
    let role = if body.role == "admin" { Role::Admin } else { Role::User };
    let hash = bcrypt_hash(&body.password)?;
    let id = generate_id();
    let conn = state.effective_auth_db().get()?;
    db_users::insert_user(&conn, &id, &body.username, &hash, role)
        .map_err(|e| {
            if e.to_string().contains("UNIQUE") {
                AppError::BadRequest("username already exists".into())
            } else {
                AppError::Internal(e.to_string())
            }
        })?;
    Ok((StatusCode::OK, Json(json!({ "username": body.username }))))
}

/// DELETE /v1/admin/users/:username — soft-delete a user.
pub async fn delete_user(
    State(state): State<AppState>,
    Extension(auth_user): Extension<AuthUser>,
    Path(username): Path<String>,
) -> Result<impl IntoResponse, AppError> {
    require_admin(&auth_user)?;
    let conn = state.effective_auth_db().get()?;
    let user = db_users::user_by_name(&conn, &username)?
        .ok_or(AppError::NotFound)?;
    db_users::delete_user(&conn, &user.id)?;
    Ok(StatusCode::OK)
}

/// PUT /v1/admin/users/:username/role — change a user's role.
pub async fn set_role(
    State(state): State<AppState>,
    Extension(auth_user): Extension<AuthUser>,
    Path(username): Path<String>,
    Json(body): Json<SetRoleRequest>,
) -> Result<impl IntoResponse, AppError> {
    require_admin(&auth_user)?;
    let role_str = match body.role.as_str() {
        "admin" | "user" => body.role.clone(),
        _ => return Err(AppError::BadRequest("role must be 'admin' or 'user'".into())),
    };
    let conn = state.effective_auth_db().get()?;
    let user = db_users::user_by_name(&conn, &username)?
        .ok_or(AppError::NotFound)?;
    conn.execute(
        "UPDATE users SET role = ?1 WHERE id = ?2",
        rusqlite::params![role_str, user.id],
    )
    .map_err(|e| AppError::Internal(e.to_string()))?;
    Ok(StatusCode::OK)
}

/// POST /v1/admin/users/:username/access — set ACL for a user on a topic.
pub async fn set_access(
    State(state): State<AppState>,
    Extension(auth_user): Extension<AuthUser>,
    Path(username): Path<String>,
    Json(body): Json<SetAccessRequest>,
) -> Result<impl IntoResponse, AppError> {
    require_admin(&auth_user)?;
    let conn = state.effective_auth_db().get()?;
    let user = db_users::user_by_name(&conn, &username)?
        .ok_or(AppError::NotFound)?;
    db_users::acl_set(&conn, &user.id, &body.topic, body.read, body.write)?;
    Ok(StatusCode::OK)
}

/// DELETE /v1/admin/users/:username/access/:topic — remove ACL entry.
pub async fn delete_access(
    State(state): State<AppState>,
    Extension(auth_user): Extension<AuthUser>,
    Path((username, topic)): Path<(String, String)>,
) -> Result<impl IntoResponse, AppError> {
    require_admin(&auth_user)?;
    let conn = state.effective_auth_db().get()?;
    let user = db_users::user_by_name(&conn, &username)?
        .ok_or(AppError::NotFound)?;
    db_users::acl_delete(&conn, &user.id, &topic)?;
    Ok(StatusCode::OK)
}
