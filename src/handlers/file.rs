use axum::{
    extract::{Path, State},
    http::{header, StatusCode},
    response::{IntoResponse, Response},
};

use crate::{db, error::AppError, state::AppState};

/// `GET /file/:id` — download a previously uploaded attachment.
///
/// The URL itself acts as the bearer token: anyone who knows the opaque ID can
/// fetch the file, which matches the original ntfy Go server's behaviour.
pub async fn serve_file(
    State(state): State<AppState>,
    Path(id): Path<String>,
) -> Result<Response, AppError> {
    let record = {
        let conn = state.db.get().map_err(|e| AppError::Internal(e.to_string()))?;
        db::attachments::get(&conn, &id).map_err(|e| AppError::Internal(e.to_string()))?
    };

    let record = record.ok_or(AppError::NotFound)?;

    // Treat expired attachments as gone — the cleanup task may not have run yet.
    let now = chrono::Utc::now().timestamp();
    if record.expires < now {
        return Err(AppError::NotFound);
    }

    let bytes = tokio::fs::read(&record.path)
        .await
        .map_err(|e| AppError::Internal(format!("failed to read attachment: {e}")))?;

    // Build a safe Content-Disposition filename.
    // Strip path separators, quotes, null bytes, and leading dots (hidden files / traversal).
    let safe_name: String = {
        let mut s: String = record
            .name
            .chars()
            .map(|c| {
                if c == '/' || c == '\\' || c == '"' || c == '\0' {
                    '_'
                } else {
                    c
                }
            })
            .collect();
        while s.starts_with('.') {
            s.remove(0);
        }
        s
    };

    let content_type = if record.content_type.is_empty() {
        "application/octet-stream".to_string()
    } else {
        record.content_type
    };

    let disposition = if content_type.starts_with("image/") {
        format!("inline; filename=\"{safe_name}\"")
    } else {
        format!("attachment; filename=\"{safe_name}\"")
    };

    let response = (
        StatusCode::OK,
        [
            (
                header::CONTENT_TYPE,
                content_type,
            ),
            (
                header::CONTENT_DISPOSITION,
                disposition,
            ),
        ],
        bytes,
    )
        .into_response();

    Ok(response)
}
