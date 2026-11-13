use axum::Json;
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use serde_json::json;

pub type Result<T, E = Error> = std::result::Result<T, E>;

/// Domain and infrastructure errors. The first block are the stable error
/// codes of the MCP tool contract (contract.agentslam.mcp-tools).
#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("room_exists")]
    RoomExists,
    #[error("room_not_found")]
    RoomNotFound,
    #[error("not_a_member")]
    NotAMember,
    #[error("room_archived")]
    RoomArchived,
    #[error("invalid_text")]
    InvalidText,
    #[error("invalid_name")]
    InvalidName,
    #[error("invalid_session")]
    InvalidSession,
    #[error("unauthorized")]
    Unauthorized,

    #[error("forbidden: {0}")]
    Forbidden(String),
    #[error("bad request: {0}")]
    BadRequest(String),
    #[error("not found")]
    NotFound,
    #[error("conflict: {0}")]
    Conflict(String),
    #[error("database error: {0}")]
    Db(#[from] rusqlite::Error),
    #[error("internal error: {0}")]
    Internal(#[from] anyhow::Error),
}

impl Error {
    /// Stable machine-readable code.
    pub fn code(&self) -> &'static str {
        match self {
            Error::RoomExists => "room_exists",
            Error::RoomNotFound => "room_not_found",
            Error::NotAMember => "not_a_member",
            Error::RoomArchived => "room_archived",
            Error::InvalidText => "invalid_text",
            Error::InvalidName => "invalid_name",
            Error::InvalidSession => "invalid_session",
            Error::Unauthorized => "unauthorized",
            Error::Forbidden(_) => "forbidden",
            Error::BadRequest(_) => "bad_request",
            Error::NotFound => "not_found",
            Error::Conflict(_) => "conflict",
            Error::Db(_) | Error::Internal(_) => "internal",
        }
    }

    pub fn status(&self) -> StatusCode {
        match self {
            Error::RoomExists | Error::Conflict(_) => StatusCode::CONFLICT,
            Error::RoomNotFound | Error::NotFound => StatusCode::NOT_FOUND,
            Error::NotAMember | Error::Forbidden(_) => StatusCode::FORBIDDEN,
            Error::RoomArchived => StatusCode::CONFLICT,
            Error::InvalidText
            | Error::InvalidName
            | Error::InvalidSession
            | Error::BadRequest(_) => StatusCode::BAD_REQUEST,
            Error::Unauthorized => StatusCode::UNAUTHORIZED,
            Error::Db(_) | Error::Internal(_) => StatusCode::INTERNAL_SERVER_ERROR,
        }
    }

    /// Message safe to show to a client (no internals).
    pub fn public_message(&self) -> String {
        match self {
            Error::Db(_) | Error::Internal(_) => "internal error".to_string(),
            other => other.to_string(),
        }
    }
}

impl IntoResponse for Error {
    fn into_response(self) -> Response {
        if matches!(self, Error::Db(_) | Error::Internal(_)) {
            tracing::error!(error = %self, "request failed");
        }
        let body = json!({"error": self.code(), "message": self.public_message()});
        (self.status(), Json(body)).into_response()
    }
}
