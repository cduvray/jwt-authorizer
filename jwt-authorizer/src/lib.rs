#![doc = include_str!("../docs/README.md")]

use axum::{async_trait, extract::FromRequestParts, http::request::Parts};
use jsonwebtoken::TokenData;
use serde::de::DeserializeOwned;

pub use self::error::AuthError;
pub use claims::{NumericDate, RegisteredClaims, StringList};
pub use jwks::key_store_manager::{Refresh, RefreshStrategy};
pub use layer::JwtAuthorizer;
pub use validation::Validation;

pub mod authorizer;
pub mod claims;
pub mod error;
pub mod jwks;
pub mod layer;
mod oidc;
pub mod validation;

/// Claims serialized using T
#[derive(Debug, Clone, Copy, Default)]
pub struct JwtClaims<T>(pub T);

#[async_trait]
impl<T, S> FromRequestParts<S> for JwtClaims<T>
where
    T: DeserializeOwned + Send + Sync + Clone + 'static,
    S: Send + Sync,
{
    type Rejection = AuthError;

    async fn from_request_parts(parts: &mut Parts, _: &S) -> Result<Self, Self::Rejection> {
        match parts.extensions.get::<Result<TokenData<T>, AuthError>>() {
            Some(Ok(data)) => Ok(JwtClaims(data.claims.to_owned())),
            Some(Err(e)) => Err(e.to_owned()),
            None => {
                tracing::warn!("JwtClaims extractor must be behind a jwt-authoriser layer!");
                Err(AuthError::MissingLayer)
            }
        }
    }
}
