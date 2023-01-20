use axum::{
    http::StatusCode,
    response::{IntoResponse, Response}, body::{self, Empty},
};
use http::header;
use jsonwebtoken::Algorithm;
use thiserror::Error;

use tracing::{log::warn, debug};

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

    #[error("Missing Token")]
    MissingToken(),

    #[error(transparent)]
    InvalidToken(#[from] jsonwebtoken::errors::Error),

    #[error("Invalid Claim")]
    InvalidClaims(),
}

/// (https://datatracker.ietf.org/doc/html/rfc6750#section-3.1)  
impl IntoResponse for AuthError {
    fn into_response(self) -> Response {             
        warn!("AuthError: {}", &self);
        let resp = match self {
            AuthError::JwksRefreshError(err) =>  {
                tracing::error!("AuthErrors::JwksRefreshError: {}", err);
                let mut res = Response::new(body::boxed(Empty::new()));
                *res.status_mut() = StatusCode::INTERNAL_SERVER_ERROR;
                res
            },
            AuthError::InvalidKey(err) =>  {
                tracing::error!("AuthErrors::InvalidKey: {}", err);
                let mut res = Response::new(body::boxed(Empty::new()));
                *res.status_mut() = StatusCode::INTERNAL_SERVER_ERROR;
                res
            },
            AuthError::JwksSerialisationError(err) => {
                tracing::error!("AuthErrors::JwksSerialisationError: {}", err);
                let mut res = Response::new(body::boxed(Empty::new()));
                *res.status_mut() = StatusCode::INTERNAL_SERVER_ERROR;
                res
            },
            AuthError::InvalidKeyAlg(err) => {
                debug!("AuthErrors::InvalidKeyAlg: {:?}", err);
                let mut res = Response::new(body::boxed(Empty::new()));
                *res.status_mut() = StatusCode::UNAUTHORIZED;
                res.headers_mut().insert(header::WWW_AUTHENTICATE, "Bearer error=\"invalid_token\", error_description=\"invalid key algorithm\"".parse().unwrap());
                res
            },
            AuthError::InvalidKid(err) => {
                debug!("AuthErrors::InvalidKid: {}", err);
                let mut res = Response::new(body::boxed(Empty::new()));
                *res.status_mut() = StatusCode::UNAUTHORIZED;
                res.headers_mut().insert(header::WWW_AUTHENTICATE, "Bearer error=\"invalid_token\", error_description=\"invalid kid\"".parse().unwrap());
                res
            },
            AuthError::InvalidToken(err) => {
                debug!("AuthErrors::InvalidToken: {}", err);
                let mut res = Response::new(body::boxed(Empty::new()));
                *res.status_mut() = StatusCode::UNAUTHORIZED;
                res.headers_mut().insert(header::WWW_AUTHENTICATE, "Bearer error=\"invalid_token\"".parse().unwrap());
                res
            },
            AuthError::MissingToken() => {
                // WWW-Authenticate: Bearer realm="example"
                debug!("AuthErrors::MissingToken");
                let mut res = Response::new(body::boxed(Empty::new()));
                *res.status_mut() = StatusCode::UNAUTHORIZED;
                res.headers_mut().insert(header::WWW_AUTHENTICATE, "Bearer".parse().unwrap());
                res
            },
            AuthError::InvalidClaims() => {
                // WWW-Authenticate: Bearer error="insufficient_scope"
                debug!("AuthErrors::InvalidClaims");
                let mut res = Response::new(body::boxed(Empty::new()));
                *res.status_mut() = StatusCode::UNAUTHORIZED;
                res.headers_mut().insert(header::WWW_AUTHENTICATE, "Bearer error=\"insufficient_scope\"".parse().unwrap());

                res
            },
        };
        // let body = axum::Json(serde_json::json!({
        //    "error": error_message,
        // }));

        resp
    }
}
