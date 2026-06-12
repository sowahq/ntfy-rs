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
    // Strip path separators, quotes, null bytes, control chars (CR/LF header
    // injection), and leading dots (hidden files / traversal).
    let safe_name: String = {
        let mut s: String = record
            .name
            .chars()
            .map(|c| {
                if c == '/' || c == '\\' || c == '"' || c == '\0' || c.is_control() {
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

    // The stored content_type comes verbatim from the uploader's request header,
    // so it is attacker-controlled. Serving an attacker-supplied type `inline`
    // (e.g. image/svg+xml or text/html) yields stored XSS in the server's own
    // origin. Only render `inline` for a hardcoded allowlist of inert raster
    // image types; everything else is forced to `attachment` download.
    let raw_type = if record.content_type.is_empty() {
        "application/octet-stream"
    } else {
        record.content_type.as_str()
    };
    let type_lower = raw_type.to_ascii_lowercase();
    let base_type = type_lower
        .split(';')
        .next()
        .unwrap_or("")
        .trim();
    let inline_ok = matches!(
        base_type,
        "image/png" | "image/jpeg" | "image/gif" | "image/webp" | "image/bmp"
    );

    let disposition = if inline_ok {
        format!("inline; filename=\"{safe_name}\"")
    } else {
        format!("attachment; filename=\"{safe_name}\"")
    };

    let response = (
        StatusCode::OK,
        [
            (header::CONTENT_TYPE, raw_type.to_string()),
            (header::CONTENT_DISPOSITION, disposition),
            // Stop browsers MIME-sniffing toward an executable type.
            (header::X_CONTENT_TYPE_OPTIONS, "nosniff".to_string()),
        ],
        bytes,
    )
        .into_response();

    Ok(response)
}
