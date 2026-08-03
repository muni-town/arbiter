//! Error type and its axum `IntoResponse` impl (XRPC error JSON envelope).

use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use serde_json::json;

#[derive(Debug, thiserror::Error)]
pub enum AppError {
    #[error("arbiter not found: {0}")]
    ArbiterNotFound(String),
    #[error("arbiter not ready (policies not loaded): {0}")]
    ArbiterNotReady(String),
    #[error("missing required header: {0}")]
    MissingHeader(&'static str),
    #[error("invalid header {0}: {1}")]
    InvalidHeader(&'static str, String),
    #[error("no #atproto_pds service for {0}")]
    MissingPdsEndpoint(String),
    #[error("unauthorized: {0}")]
    Unauthorized(String),
    #[error(transparent)]
    Other(#[from] anyhow::Error),
}

impl IntoResponse for AppError {
    fn into_response(self) -> Response {
        let status = match &self {
            AppError::ArbiterNotFound(_) => StatusCode::NOT_FOUND,
            AppError::ArbiterNotReady(_) => StatusCode::SERVICE_UNAVAILABLE,
            AppError::MissingHeader(_) | AppError::InvalidHeader(_, _) | AppError::MissingPdsEndpoint(_) => StatusCode::BAD_REQUEST,
            AppError::Unauthorized(_) => StatusCode::UNAUTHORIZED,
            AppError::Other(_) => StatusCode::INTERNAL_SERVER_ERROR,
        };
        let body = json!({
            "$type": "town.muni.arbiter.server.v1.error",
            "error": self.to_string(),
        });
        (status, axum::Json(body)).into_response()
    }
}