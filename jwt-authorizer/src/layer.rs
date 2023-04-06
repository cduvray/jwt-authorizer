use axum::body::BoxBody;
use axum::http::Request;
use axum::response::{IntoResponse, Response};
use futures_core::ready;
use futures_util::future::BoxFuture;
use headers::authorization::Bearer;
use headers::{Authorization, HeaderMapExt};
use pin_project::pin_project;
use serde::de::DeserializeOwned;
use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};
use tower_layer::Layer;
use tower_service::Service;

use crate::authorizer::{Authorizer, FnClaimsChecker, KeySourceType};
use crate::error::InitError;
use crate::jwks::key_store_manager::Refresh;
use crate::validation::Validation;
use crate::{layer, AuthError, RefreshStrategy};

/// Authorizer Layer builder
///
/// - initialisation of the Authorizer from jwks, rsa, ed, ec or secret
/// - can define a checker (jwt claims check)
pub struct JwtAuthorizer<C>
where
    C: Clone + DeserializeOwned,
{
    key_source_type: KeySourceType,
    refresh: Option<Refresh>,
    claims_checker: Option<FnClaimsChecker<C>>,
    validation: Option<Validation>,
    jwt_source: JwtSource,
}

/// authorization layer builder
impl<C> JwtAuthorizer<C>
where
    C: Clone + DeserializeOwned + Send + Sync,
{
    /// Builds Authorizer Layer from a OpenId Connect discover metadata
    pub fn from_oidc(issuer: &str) -> JwtAuthorizer<C> {
        JwtAuthorizer {
            key_source_type: KeySourceType::Discovery(issuer.to_string()),
            refresh: Default::default(),
            claims_checker: None,
            validation: None,
            jwt_source: JwtSource::AuthorizationHeader,
        }
    }

    /// Builds Authorizer Layer from a JWKS endpoint
    pub fn from_jwks_url(url: &str) -> JwtAuthorizer<C> {
        JwtAuthorizer {
            key_source_type: KeySourceType::Jwks(url.to_owned()),
            refresh: Default::default(),
            claims_checker: None,
            validation: None,
            jwt_source: JwtSource::AuthorizationHeader,
        }
    }

    /// Builds Authorizer Layer from a RSA PEM file
    pub fn from_rsa_pem(path: &str) -> JwtAuthorizer<C> {
        JwtAuthorizer {
            key_source_type: KeySourceType::RSA(path.to_owned()),
            refresh: Default::default(),
            claims_checker: None,
            validation: None,
            jwt_source: JwtSource::AuthorizationHeader,
        }
    }

    /// Builds Authorizer Layer from an RSA PEM raw text
    pub fn from_rsa_pem_text(text: &str) -> JwtAuthorizer<C> {
        JwtAuthorizer {
            key_source_type: KeySourceType::RSAString(text.to_owned()),
            refresh: Default::default(),
            claims_checker: None,
            validation: None,
            jwt_source: JwtSource::AuthorizationHeader,
        }
    }

    /// Builds Authorizer Layer from a EC PEM file
    pub fn from_ec_pem(path: &str) -> JwtAuthorizer<C> {
        JwtAuthorizer {
            key_source_type: KeySourceType::EC(path.to_owned()),
            refresh: Default::default(),
            claims_checker: None,
            validation: None,
            jwt_source: JwtSource::AuthorizationHeader,
        }
    }

    /// Builds Authorizer Layer from a EC PEM raw text
    pub fn from_ec_pem_text(text: &str) -> JwtAuthorizer<C> {
        JwtAuthorizer {
            key_source_type: KeySourceType::ECString(text.to_owned()),
            refresh: Default::default(),
            claims_checker: None,
            validation: None,
            jwt_source: JwtSource::AuthorizationHeader,
        }
    }

    /// Builds Authorizer Layer from a EC PEM file
    pub fn from_ed_pem(path: &str) -> JwtAuthorizer<C> {
        JwtAuthorizer {
            key_source_type: KeySourceType::ED(path.to_owned()),
            refresh: Default::default(),
            claims_checker: None,
            validation: None,
            jwt_source: JwtSource::AuthorizationHeader,
        }
    }

    /// Builds Authorizer Layer from a EC PEM raw text
    pub fn from_ed_pem_text(text: &str) -> JwtAuthorizer<C> {
        JwtAuthorizer {
            key_source_type: KeySourceType::EDString(text.to_owned()),
            refresh: Default::default(),
            claims_checker: None,
            validation: None,
            jwt_source: JwtSource::AuthorizationHeader,
        }
    }

    /// Builds Authorizer Layer from a secret phrase
    pub fn from_secret(secret: &str) -> JwtAuthorizer<C> {
        JwtAuthorizer {
            key_source_type: KeySourceType::Secret(secret.to_owned()),
            refresh: Default::default(),
            claims_checker: None,
            validation: None,
            jwt_source: JwtSource::AuthorizationHeader,
        }
    }

    /// Refreshes configuration for jwk store
    pub fn refresh(mut self, refresh: Refresh) -> JwtAuthorizer<C> {
        if self.refresh.is_some() {
            tracing::warn!("More than one refresh configuration found!");
        }
        self.refresh = Some(refresh);
        self
    }

    /// no refresh, jwks will be loaded juste once
    pub fn no_refresh(mut self) -> JwtAuthorizer<C> {
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
    pub fn check(mut self, checker_fn: fn(&C) -> bool) -> JwtAuthorizer<C> {
        self.claims_checker = Some(FnClaimsChecker { checker_fn });

        self
    }

    pub fn validation(mut self, validation: Validation) -> JwtAuthorizer<C> {
        self.validation = Some(validation);

        self
    }

    /// configures the source of the bearer token
    ///
    /// (default: AuthorizationHeader)
    pub fn jwt_source(mut self, src: JwtSource) -> JwtAuthorizer<C> {
        self.jwt_source = src;

        self
    }

    /// Build axum layer
    pub async fn layer(self) -> Result<AsyncAuthorizationLayer<C>, InitError> {
        let val = self.validation.unwrap_or_default();
        let auth = Arc::new(Authorizer::build(&self.key_source_type, self.claims_checker, self.refresh, val).await?);
        Ok(AsyncAuthorizationLayer::new(auth, self.jwt_source))
    }
}
/// Trait for authorizing requests.
pub trait AsyncAuthorizer<B> {
    type RequestBody;
    type ResponseBody;
    type Future: Future<Output = Result<Request<Self::RequestBody>, Response<Self::ResponseBody>>>;

    /// Authorize the request.
    ///
    /// If the future resolves to `Ok(request)` then the request is allowed through, otherwise not.
    fn authorize(&self, request: Request<B>) -> Self::Future;
}

impl<B, S, C> AsyncAuthorizer<B> for AsyncAuthorizationService<S, C>
where
    B: Send + Sync + 'static,
    C: Clone + DeserializeOwned + Send + Sync + 'static,
{
    type RequestBody = B;
    type ResponseBody = BoxBody;
    type Future = BoxFuture<'static, Result<Request<B>, Response<Self::ResponseBody>>>;

    fn authorize(&self, mut request: Request<B>) -> Self::Future {
        let authorizer = self.auth.clone();
        let h = request.headers();

        let token = match &self.jwt_source {
            layer::JwtSource::AuthorizationHeader => {
                let bearer_o: Option<Authorization<Bearer>> = h.typed_get();
                bearer_o.map(|b| String::from(b.0.token()))
            }
            layer::JwtSource::Cookie(name) => h
                .typed_get::<headers::Cookie>()
                .and_then(|c| c.get(name.as_str()).map(String::from)),
        };
        Box::pin(async move {
            if let Some(token) = token {
                match authorizer.check_auth(token.as_str()).await {
                    Ok(token_data) => {
                        // Set `token_data` as a request extension so it can be accessed by other
                        // services down the stack.
                        request.extensions_mut().insert(token_data);

                        Ok(request)
                    }
                    Err(err) => Err(err.into_response()),
                }
            } else {
                Err(AuthError::MissingToken().into_response())
            }
        })
    }
}

// -------------- Layer -----------------

#[derive(Clone)]
pub struct AsyncAuthorizationLayer<C>
where
    C: Clone + DeserializeOwned + Send,
{
    auth: Arc<Authorizer<C>>,
    jwt_source: JwtSource,
}

impl<C> AsyncAuthorizationLayer<C>
where
    C: Clone + DeserializeOwned + Send,
{
    pub fn new(auth: Arc<Authorizer<C>>, jwt_source: JwtSource) -> AsyncAuthorizationLayer<C> {
        Self { auth, jwt_source }
    }
}

impl<S, C> Layer<S> for AsyncAuthorizationLayer<C>
where
    C: Clone + DeserializeOwned + Send + Sync,
{
    type Service = AsyncAuthorizationService<S, C>;

    fn layer(&self, inner: S) -> Self::Service {
        AsyncAuthorizationService::new(inner, self.auth.clone(), self.jwt_source.clone())
    }
}

// ----------  AsyncAuthorizationService  --------

/// Source of the bearer token
#[derive(Clone)]
pub enum JwtSource {
    /// Storing the bearer token in Authorization header
    ///
    /// (default)
    AuthorizationHeader,
    /// Cookies
    ///
    /// (be careful when using cookies, some precautions must be taken, cf. RFC6750)
    Cookie(String),
    // TODO: "Form-Encoded Content Parameter" may be added in the future (OAuth 2.1 / 5.2.1.2)
    // FormParam,
}

#[derive(Clone)]
pub struct AsyncAuthorizationService<S, C>
where
    C: Clone + DeserializeOwned + Send + Sync,
{
    pub inner: S,
    pub auth: Arc<Authorizer<C>>,
    pub jwt_source: JwtSource,
}

impl<S, C> AsyncAuthorizationService<S, C>
where
    C: Clone + DeserializeOwned + Send + Sync,
{
    pub fn get_ref(&self) -> &S {
        &self.inner
    }

    /// Gets a mutable reference to the underlying service.
    pub fn get_mut(&mut self) -> &mut S {
        &mut self.inner
    }

    /// Consumes `self`, returning the underlying service.
    pub fn into_inner(self) -> S {
        self.inner
    }
}

impl<S, C> AsyncAuthorizationService<S, C>
where
    C: Clone + DeserializeOwned + Send + Sync,
{
    /// Authorize requests using a custom scheme.
    ///
    /// The `Authorization` header is required to have the value provided.
    pub fn new(inner: S, auth: Arc<Authorizer<C>>, jwt_source: JwtSource) -> AsyncAuthorizationService<S, C> {
        Self { inner, auth, jwt_source }
    }
}

impl<ReqBody, S, C> Service<Request<ReqBody>> for AsyncAuthorizationService<S, C>
where
    ReqBody: Send + Sync + 'static,
    S: Service<Request<ReqBody>, Response = Response> + Clone,
    C: Clone + DeserializeOwned + Send + Sync + 'static,
{
    type Response = S::Response;
    type Error = S::Error;
    type Future = ResponseFuture<S, ReqBody, C>;

    fn poll_ready(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        self.inner.poll_ready(cx)
    }

    fn call(&mut self, req: Request<ReqBody>) -> Self::Future {
        let inner = self.inner.clone();
        let auth_fut = self.authorize(req);

        ResponseFuture {
            state: State::Authorize { auth_fut },
            service: inner,
        }
    }
}

#[pin_project]
/// Response future for [`AsyncAuthorizationService`].
pub struct ResponseFuture<S, ReqBody, C>
where
    S: Service<Request<ReqBody>, Response = Response>,
    ReqBody: Send + Sync + 'static,
    C: Clone + DeserializeOwned + Send + Sync + 'static,
{
    #[pin]
    state: State<<AsyncAuthorizationService<S, C> as AsyncAuthorizer<ReqBody>>::Future, S::Future>,
    service: S,
}

#[pin_project(project = StateProj)]
enum State<A, SFut> {
    Authorize {
        #[pin]
        auth_fut: A,
    },
    Authorized {
        #[pin]
        svc_fut: SFut,
    },
}

impl<S, ReqBody, C> Future for ResponseFuture<S, ReqBody, C>
where
    S: Service<Request<ReqBody>, Response = Response>,
    ReqBody: Send + Sync + 'static,
    C: Clone + DeserializeOwned + Send + Sync,
{
    type Output = Result<S::Response, S::Error>;

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        let mut this = self.project();

        loop {
            match this.state.as_mut().project() {
                StateProj::Authorize { auth_fut } => {
                    let auth = ready!(auth_fut.poll(cx));
                    match auth {
                        Ok(req) => {
                            let svc_fut = this.service.call(req);
                            this.state.set(State::Authorized { svc_fut })
                        }
                        Err(res) => {
                            tracing::info!("err: {:?}", res);
                            return Poll::Ready(Ok(res));
                        }
                    };
                }
                StateProj::Authorized { svc_fut } => {
                    return svc_fut.poll(cx);
                }
            }
        }
    }
}
