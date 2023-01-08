#![doc = include_str!("../docs/README.md")]

use axum::{async_trait, extract::FromRequestParts, http::request::Parts};
use jsonwebtoken::TokenData;
use serde::de::DeserializeOwned;

pub use self::error::AuthError;
pub use layer::JwtAuthorizer;

pub mod authorizer;
pub mod error;
pub mod jwks;
pub mod layer;

/// Claims serialized using T
#[derive(Debug, Clone, Copy, Default)]
pub struct JwtClaims<T>(pub T);

#[async_trait]
impl<T, S> FromRequestParts<S> for JwtClaims<T>
where
    T: DeserializeOwned + Send + Sync + Clone + 'static,
    S: Send + Sync,
{
    type Rejection = error::AuthError;

    async fn from_request_parts(parts: &mut Parts, _: &S) -> Result<Self, Self::Rejection> {
        let claims = parts.extensions.get::<TokenData<T>>().unwrap(); // TODO: unwrap -> err
        Ok(JwtClaims(claims.claims.clone())) // TODO: unwrap -> err
    }
}

#[cfg(test)]
mod tests;
