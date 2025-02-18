#![doc = include_str!("../docs/README.md")]

use axum::{
    extract::{FromRequestParts, OptionalFromRequestParts},
    http::request::Parts,
};
use jsonwebtoken::TokenData;
use serde::de::DeserializeOwned;

pub use self::error::AuthError;
pub use authorizer::{Authorizer, IntoLayer};
pub use builder::{AuthorizerBuilder, JwtAuthorizer};
pub use claims::{NumericDate, OneOrArray, RegisteredClaims};
pub use jwks::key_store_manager::{Refresh, RefreshStrategy};
pub use validation::Validation;

pub mod authorizer;
pub mod builder;
pub mod claims;
pub mod error;
pub mod jwks;
pub mod layer;
mod oidc;
pub mod validation;

/// Claims serialized using T
#[derive(Debug, Clone, Copy, Default)]
pub struct JwtClaims<T>(pub T);

impl<T, S> FromRequestParts<S> for JwtClaims<T>
where
    T: DeserializeOwned + Send + Sync + Clone + 'static,
    S: Send + Sync,
{
    type Rejection = AuthError;

    async fn from_request_parts(parts: &mut Parts, _: &S) -> Result<Self, Self::Rejection> {
        if let Some(claims) = parts.extensions.get::<TokenData<T>>() {
            Ok(JwtClaims(claims.claims.clone()))
        } else {
            Err(AuthError::NoAuthorizerLayer())
        }
    }
}

impl<T, S> OptionalFromRequestParts<S> for JwtClaims<T>
where
    T: DeserializeOwned + Send + Sync + Clone + 'static,
    S: Send + Sync,
{
    type Rejection = AuthError;

    // Required method
    async fn from_request_parts(parts: &mut Parts, _: &S) -> Result<Option<Self>, Self::Rejection> {
        Ok(parts
            .extensions
            .get::<TokenData<T>>()
            .map(|claims| JwtClaims(claims.claims.clone())))
    }
}

#[cfg(feature = "aide")]
mod aide {

    use super::JwtClaims;
    use aide::{
        generate::GenContext,
        openapi::{HeaderStyle, Operation, Parameter, ParameterData, ParameterSchemaOrContent, SchemaObject},
        operation::add_parameters,
        OperationInput,
    };

    impl<T> OperationInput for JwtClaims<T> {
        fn operation_input(ctx: &mut GenContext, operation: &mut Operation) {
            let s = ctx.schema.subschema_for::<String>();
            add_parameters(
                ctx,
                operation,
                [Parameter::Header {
                    parameter_data: ParameterData {
                        name: "Authorization".to_string(),
                        description: Some("Jwt Bearer token".to_string()),
                        required: true,
                        format: ParameterSchemaOrContent::Schema(SchemaObject {
                            json_schema: s,
                            example: None,
                            external_docs: None,
                        }),
                        extensions: Default::default(),
                        deprecated: None,
                        example: None,
                        examples: Default::default(),
                        explode: None,
                    },
                    style: HeaderStyle::Simple,
                }],
            );
        }
    }
}
