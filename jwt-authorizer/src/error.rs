use axum::{
    body::{self, BoxBody, Empty},
    http::StatusCode,
    response::{IntoResponse, Response},
};
use http::header;
use jsonwebtoken::Algorithm;
use thiserror::Error;

use tracing::debug;

#[derive(Debug, Error)]
pub enum InitError {
    #[error("Builder Error {0}")]
    BuilderError(String),

    #[error(transparent)]
    KeyFileError(#[from] std::io::Error),

    #[error(transparent)]
    KeyDecodingError(#[from] jsonwebtoken::errors::Error),

    #[error("Builder Error {0}")]
    DiscoveryError(String),

    #[error("Builder Error {0}")]
    JwksUrlError(String),

    #[error("Jwks Parsing Error {0}")]
    JwksParsingError(#[from] serde_json::Error),
}

#[derive(Debug, Error)]
pub enum AuthError {
    #[error(transparent)]
    JwksSerialisationError(#[from] serde_json::Error),

    #[error("JwksRefreshError {0}")]
    JwksRefreshError(String),

    #[error("InvalidKey {0}")]
    InvalidKey(String),

    #[error("Invalid Kid {0}")]
    InvalidKid(String),

    #[error("Invalid Key Algorithm {0:?}")]
    InvalidKeyAlg(Algorithm),

    #[error("Missing Token")]
    MissingToken(),

    #[error(transparent)]
    InvalidToken(#[from] jsonwebtoken::errors::Error),

    #[error("Invalid Claim")]
    InvalidClaims(),

    /// Used when a claim extractor is used and no authorization layer is in front the handler
    #[error("No Authorizer Layer")]
    NoAuthorizerLayer(),
}

fn response_wwwauth(status: StatusCode, bearer: &str) -> Response<BoxBody> {
    let mut res = Response::new(body::boxed(Empty::new()));
    *res.status_mut() = status;
    let h = if bearer.is_empty() {
        "Bearer".to_owned()
    } else {
        format!("Bearer {bearer}")
    };
    res.headers_mut().insert(header::WWW_AUTHENTICATE, h.parse().unwrap());

    res
}

fn response_500() -> Response<BoxBody> {
    let mut res = Response::new(body::boxed(Empty::new()));
    *res.status_mut() = StatusCode::INTERNAL_SERVER_ERROR;

    res
}

#[cfg(feature = "tonic")]
impl From<AuthError> for Response<tonic::body::BoxBody> {
    fn from(e: AuthError) -> Self {
        match e {
            AuthError::JwksRefreshError(err) => {
                tracing::error!("AuthErrors::JwksRefreshError: {}", err);
                tonic::Status::internal("")
            }
            AuthError::InvalidKey(err) => {
                tracing::error!("AuthErrors::InvalidKey: {}", err);
                tonic::Status::internal("")
            }
            AuthError::JwksSerialisationError(err) => {
                tracing::error!("AuthErrors::JwksSerialisationError: {}", err);
                tonic::Status::internal("")
            }
            AuthError::InvalidKeyAlg(err) => {
                debug!("AuthErrors::InvalidKeyAlg: {:?}", err);
                tonic::Status::unauthenticated("error=\"invalid_token\", error_description=\"invalid key algorithm\"")
            }
            AuthError::InvalidKid(err) => {
                debug!("AuthErrors::InvalidKid: {}", err);
                tonic::Status::unauthenticated("error=\"invalid_token\", error_description=\"invalid kid\"")
            }
            AuthError::InvalidToken(err) => {
                debug!("AuthErrors::InvalidToken: {}", err);
                tonic::Status::unauthenticated("error=\"invalid_token\"")
            }
            AuthError::MissingToken() => {
                debug!("AuthErrors::MissingToken");
                tonic::Status::unauthenticated("")
            }
            AuthError::InvalidClaims() => {
                debug!("AuthErrors::InvalidClaims");
                tonic::Status::unauthenticated("error=\"insufficient_scope\"")
            }
            AuthError::NoAuthorizerLayer() => {
                debug!("AuthErrors::NoAuthorizerLayer");
                tonic::Status::unauthenticated("error=\"no_authorizer_layer\"")
            }
        }
        .to_http()
    }
}

impl From<AuthError> for Response {
    fn from(e: AuthError) -> Self {
        e.into_response()
    }
}

/// (https://datatracker.ietf.org/doc/html/rfc6750#section-3.1)
impl IntoResponse for AuthError {
    fn into_response(self) -> Response {
        match self {
            AuthError::JwksRefreshError(err) => {
                tracing::error!("AuthErrors::JwksRefreshError: {}", err);
                response_500()
            }
            AuthError::InvalidKey(err) => {
                tracing::error!("AuthErrors::InvalidKey: {}", err);
                response_500()
            }
            AuthError::JwksSerialisationError(err) => {
                tracing::error!("AuthErrors::JwksSerialisationError: {}", err);
                response_500()
            }
            AuthError::InvalidKeyAlg(err) => {
                debug!("AuthErrors::InvalidKeyAlg: {:?}", err);
                response_wwwauth(
                    StatusCode::UNAUTHORIZED,
                    "error=\"invalid_token\", error_description=\"invalid key algorithm\"",
                )
            }
            AuthError::InvalidKid(err) => {
                debug!("AuthErrors::InvalidKid: {}", err);
                response_wwwauth(
                    StatusCode::UNAUTHORIZED,
                    "error=\"invalid_token\", error_description=\"invalid kid\"",
                )
            }
            AuthError::InvalidToken(err) => {
                debug!("AuthErrors::InvalidToken: {}", err);
                response_wwwauth(StatusCode::UNAUTHORIZED, "error=\"invalid_token\"")
            }
            AuthError::MissingToken() => {
                debug!("AuthErrors::MissingToken");
                response_wwwauth(StatusCode::UNAUTHORIZED, "")
            }
            AuthError::InvalidClaims() => {
                debug!("AuthErrors::InvalidClaims");
                response_wwwauth(StatusCode::FORBIDDEN, "error=\"insufficient_scope\"")
            }
            AuthError::NoAuthorizerLayer() => {
                debug!("AuthErrors::NoAuthorizerLayer");
                // TODO: should it be a standard error?
                response_wwwauth(StatusCode::UNAUTHORIZED, "error=\"no_authorizer_layer\"")
            }
        }
    }
}
