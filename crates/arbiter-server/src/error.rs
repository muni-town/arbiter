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
    #[error("bad request: {0}")]
    BadRequest(String),
    #[error("no #atproto_pds service for {0}")]
    MissingPdsEndpoint(String),
    #[error("unauthorized: {0}")]
    Unauthorized(String),
    #[error("forbidden: {0}")]
    Forbidden(String),
    /// The caller is not allowed to perform the operation (XRPC
    /// `ErrPermissionDenied`). Distinct from [`AppError::Forbidden`] so the
    /// error code matches the lexicon contract.
    #[error("ErrPermissionDenied: {0}")]
    PermissionDenied(String),
    /// Account creation or initial record writes failed (XRPC
    /// `ErrProvisioningFailed`).
    #[error("ErrProvisioningFailed: {0}")]
    ProvisioningFailed(String),
    /// An arbiter for this DID already exists on this server (XRPC
    /// `ErrArbiterAlreadyExists`).
    #[error("ErrArbiterAlreadyExists: {0}")]
    ArbiterAlreadyExists(String),
    /// A replacement policy failed to compile (XRPC `ErrInvalidPolicy`).
    #[error("ErrInvalidPolicy: {0}")]
    InvalidPolicy(String),
    #[error(transparent)]
    Other(#[from] anyhow::Error),
}

impl IntoResponse for AppError {
    fn into_response(self) -> Response {
        let status = match &self {
            AppError::ArbiterNotFound(_) => StatusCode::NOT_FOUND,
            AppError::ArbiterNotReady(_) => StatusCode::SERVICE_UNAVAILABLE,
            AppError::BadRequest(_) | AppError::MissingPdsEndpoint(_) => StatusCode::BAD_REQUEST,
            AppError::Unauthorized(_) => StatusCode::UNAUTHORIZED,
            AppError::Forbidden(_) | AppError::PermissionDenied(_) => StatusCode::FORBIDDEN,
            AppError::ProvisioningFailed(_) => StatusCode::INTERNAL_SERVER_ERROR,
            AppError::ArbiterAlreadyExists(_) => StatusCode::CONFLICT,
            AppError::InvalidPolicy(_) => StatusCode::BAD_REQUEST,
            AppError::Other(_) => StatusCode::INTERNAL_SERVER_ERROR,
        };
        // XRPC error envelope: `error` is the machine-readable code (matching
        // the lexicon's declared error names), `message` is the human detail.
        // Keeping them separate matters: strict `@atproto/lex` clients validate
        // `error` against `/^[\w_-]+$/`, so a combined "code: detail" string
        // would be rejected and the detail lost. The body is exactly
        // `{ error, message }` per the XRPC spec — no `$type` (it is not part
        // of the error contract and is undeclared in any lexicon).
        let (code, message): (&str, String) = match &self {
            AppError::ArbiterNotFound(m) => ("ArbiterNotFound", m.clone()),
            AppError::ArbiterNotReady(m) => ("ArbiterNotReady", m.clone()),
            AppError::BadRequest(m) => ("InvalidRequest", m.clone()),
            AppError::MissingPdsEndpoint(m) => ("MissingPdsEndpoint", m.clone()),
            AppError::Unauthorized(m) => ("Unauthorized", m.clone()),
            AppError::Forbidden(m) => ("Forbidden", m.clone()),
            AppError::PermissionDenied(m) => ("ErrPermissionDenied", m.clone()),
            AppError::ProvisioningFailed(m) => ("ErrProvisioningFailed", m.clone()),
            AppError::ArbiterAlreadyExists(m) => ("ErrArbiterAlreadyExists", m.clone()),
            AppError::InvalidPolicy(m) => ("ErrInvalidPolicy", m.clone()),
            AppError::Other(e) => ("InternalServerError", e.to_string()),
        };
        let body = json!({
            "error": code,
            "message": message,
        });
        (status, axum::Json(body)).into_response()
    }
}
