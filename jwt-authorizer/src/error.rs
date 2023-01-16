use axum::{
    http::StatusCode,
    response::{IntoResponse, Response},
};
use jsonwebtoken::Algorithm;
use thiserror::Error;

use tracing::log::warn;

#[derive(Debug, Error)]
pub enum InitError {
    #[error("Builder Error {0}")]
    BuilderError(String),

    #[error(transparent)]
    KeyFileError(#[from] std::io::Error),

    #[error(transparent)]
    KeyFileDecodingError(#[from] jsonwebtoken::errors::Error),
}

#[derive(Debug, Error)]
pub enum AuthError {
    #[error(transparent)]
    JwksSerialisationError(#[from] serde_json::Error),

    #[error(transparent)]
    JwksRefreshError(#[from] reqwest::Error),

    #[error("InvalidKey {0}")]
    InvalidKey(String),

    #[error("Invalid Kid {0}")]
    InvalidKid(String),

    #[error("Invalid Key Algorithm {0:?}")]
    InvalidKeyAlg(Algorithm),

    // #[error(transparent)]
    // InvalidTokenHeader(#[from] TypedHeaderRejection),

    #[error(transparent)]
    InvalidToken(#[from] jsonwebtoken::errors::Error),

    #[error("Invalid Claim")]
    InvalidClaims(),
}

impl IntoResponse for AuthError {
    fn into_response(self) -> Response {
         // TODO: add error code (https://datatracker.ietf.org/doc/html/rfc6750#section-3.1)               
        warn!("AuthError: {}", &self);
        let (status, error_message) = match self {
            AuthError::JwksRefreshError(e) => (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()),
            AuthError::InvalidKid(msg) => (StatusCode::UNAUTHORIZED, msg),
            // AuthError::InvalidTokenHeader(_) => (StatusCode::BAD_REQUEST, self.to_string()),
            AuthError::InvalidToken(_) => (StatusCode::UNAUTHORIZED, self.to_string()),
            AuthError::InvalidKey(msg) => (StatusCode::INTERNAL_SERVER_ERROR, msg),
            AuthError::JwksSerialisationError(e) => (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()),
            AuthError::InvalidKeyAlg(_) => (StatusCode::BAD_REQUEST, self.to_string()),
            AuthError::InvalidClaims() => (StatusCode::UNAUTHORIZED, self.to_string()),
        };
        let body = axum::Json(serde_json::json!({
            "error": error_message,
        }));
        (status, body).into_response()
    }
}
