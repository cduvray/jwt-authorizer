use std::sync::Arc;

use serde::de::DeserializeOwned;

use crate::{
    authorizer::{FnClaimsChecker, KeySourceType},
    error::InitError,
    layer::{AuthorizationLayer, JwtSource},
    Authorizer, Refresh, RefreshStrategy, RegisteredClaims, Validation,
};

/// Authorizer Layer builder
///
/// - initialisation of the Authorizer from jwks, rsa, ed, ec or secret
/// - can define a checker (jwt claims check)
pub struct AuthorizerBuilder<C = RegisteredClaims>
where
    C: Clone + DeserializeOwned,
{
    key_source_type: KeySourceType,
    refresh: Option<Refresh>,
    claims_checker: Option<FnClaimsChecker<C>>,
    validation: Option<Validation>,
    jwt_source: JwtSource,
}

/// alias for AuthorizerBuidler (backwards compatibility)
pub type JwtAuthorizer<C = RegisteredClaims> = AuthorizerBuilder<C>;

/// authorization layer builder
impl<C> AuthorizerBuilder<C>
where
    C: Clone + DeserializeOwned + Send + Sync,
{
    /// Builds Authorizer Layer from a OpenId Connect discover metadata
    pub fn from_oidc(issuer: &str) -> AuthorizerBuilder<C> {
        AuthorizerBuilder {
            key_source_type: KeySourceType::Discovery(issuer.to_string()),
            refresh: Default::default(),
            claims_checker: None,
            validation: None,
            jwt_source: JwtSource::AuthorizationHeader,
        }
    }

    /// Builds Authorizer Layer from a JWKS endpoint
    pub fn from_jwks_url(url: &str) -> AuthorizerBuilder<C> {
        AuthorizerBuilder {
            key_source_type: KeySourceType::Jwks(url.to_owned()),
            refresh: Default::default(),
            claims_checker: None,
            validation: None,
            jwt_source: JwtSource::AuthorizationHeader,
        }
    }

    /// Builds Authorizer Layer from a RSA PEM file
    pub fn from_rsa_pem(path: &str) -> AuthorizerBuilder<C> {
        AuthorizerBuilder {
            key_source_type: KeySourceType::RSA(path.to_owned()),
            refresh: Default::default(),
            claims_checker: None,
            validation: None,
            jwt_source: JwtSource::AuthorizationHeader,
        }
    }

    /// Builds Authorizer Layer from an RSA PEM raw text
    pub fn from_rsa_pem_text(text: &str) -> AuthorizerBuilder<C> {
        AuthorizerBuilder {
            key_source_type: KeySourceType::RSAString(text.to_owned()),
            refresh: Default::default(),
            claims_checker: None,
            validation: None,
            jwt_source: JwtSource::AuthorizationHeader,
        }
    }

    /// Builds Authorizer Layer from a EC PEM file
    pub fn from_ec_pem(path: &str) -> AuthorizerBuilder<C> {
        AuthorizerBuilder {
            key_source_type: KeySourceType::EC(path.to_owned()),
            refresh: Default::default(),
            claims_checker: None,
            validation: None,
            jwt_source: JwtSource::AuthorizationHeader,
        }
    }

    /// Builds Authorizer Layer from a EC PEM raw text
    pub fn from_ec_pem_text(text: &str) -> AuthorizerBuilder<C> {
        AuthorizerBuilder {
            key_source_type: KeySourceType::ECString(text.to_owned()),
            refresh: Default::default(),
            claims_checker: None,
            validation: None,
            jwt_source: JwtSource::AuthorizationHeader,
        }
    }

    /// Builds Authorizer Layer from a EC PEM file
    pub fn from_ed_pem(path: &str) -> AuthorizerBuilder<C> {
        AuthorizerBuilder {
            key_source_type: KeySourceType::ED(path.to_owned()),
            refresh: Default::default(),
            claims_checker: None,
            validation: None,
            jwt_source: JwtSource::AuthorizationHeader,
        }
    }

    /// Builds Authorizer Layer from a EC PEM raw text
    pub fn from_ed_pem_text(text: &str) -> AuthorizerBuilder<C> {
        AuthorizerBuilder {
            key_source_type: KeySourceType::EDString(text.to_owned()),
            refresh: Default::default(),
            claims_checker: None,
            validation: None,
            jwt_source: JwtSource::AuthorizationHeader,
        }
    }

    /// Builds Authorizer Layer from a secret phrase
    pub fn from_secret(secret: &str) -> AuthorizerBuilder<C> {
        AuthorizerBuilder {
            key_source_type: KeySourceType::Secret(secret.to_owned()),
            refresh: Default::default(),
            claims_checker: None,
            validation: None,
            jwt_source: JwtSource::AuthorizationHeader,
        }
    }

    /// Refreshes configuration for jwk store
    pub fn refresh(mut self, refresh: Refresh) -> AuthorizerBuilder<C> {
        if self.refresh.is_some() {
            tracing::warn!("More than one refresh configuration found!");
        }
        self.refresh = Some(refresh);
        self
    }

    /// no refresh, jwks will be loaded juste once
    pub fn no_refresh(mut self) -> AuthorizerBuilder<C> {
        if self.refresh.is_some() {
            tracing::warn!("More than one refresh configuration found!");
        }
        self.refresh = Some(Refresh {
            strategy: RefreshStrategy::NoRefresh,
            ..Default::default()
        });
        self
    }

    /// configures token content check (custom function), if false a 403 will be sent.
    /// (AuthError::InvalidClaims())
    pub fn check(mut self, checker_fn: fn(&C) -> bool) -> AuthorizerBuilder<C> {
        self.claims_checker = Some(FnClaimsChecker { checker_fn });

        self
    }

    pub fn validation(mut self, validation: Validation) -> AuthorizerBuilder<C> {
        self.validation = Some(validation);

        self
    }

    /// configures the source of the bearer token
    ///
    /// (default: AuthorizationHeader)
    pub fn jwt_source(mut self, src: JwtSource) -> AuthorizerBuilder<C> {
        self.jwt_source = src;

        self
    }

    /// Build axum layer
    #[deprecated(since = "0.10.0", note = "please use `IntoLayer::into_layer()` instead")]
    pub async fn layer(self) -> Result<AuthorizationLayer<C>, InitError> {
        let val = self.validation.unwrap_or_default();
        let auth = Arc::new(
            Authorizer::build(self.key_source_type, self.claims_checker, self.refresh, val, self.jwt_source).await?,
        );
        Ok(AuthorizationLayer::new(vec![auth]))
    }

    pub async fn build(self) -> Result<Authorizer<C>, InitError> {
        let val = self.validation.unwrap_or_default();

        Authorizer::build(self.key_source_type, self.claims_checker, self.refresh, val, self.jwt_source).await
    }
}
