use axum::body::Body;
use axum::http::Request;
use futures_core::ready;
use futures_util::future::{self, BoxFuture};
use jsonwebtoken::TokenData;
use pin_project::pin_project;
use serde::de::DeserializeOwned;
use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};
use tokio::sync::Mutex;
use tower_layer::Layer;
use tower_service::Service;

use crate::authorizer::Authorizer;
use crate::AuthError;

/// Trait for authorizing requests.
pub trait Authorize<B> {
    type RequestBody;
    type Future: Future<Output = Result<Request<Self::RequestBody>, AuthError>>;

    /// Authorize the request.
    ///
    /// If the future resolves to `Ok(request)` then the request is allowed through, otherwise not.
    fn authorize(&self, request: Request<B>) -> Self::Future;
}

impl<B, S, C> Authorize<B> for AuthorizationService<S, C>
where
    B: Send + 'static,
    C: Clone + DeserializeOwned + Send + 'static,
{
    type RequestBody = B;
    type Future = BoxFuture<'static, Result<Request<B>, AuthError>>;

    /// The authorizers are sequentially applied (check_auth) until one of them validates the token.
    /// If no authorizer validates the token the request is rejected.
    ///
    fn authorize(&self, mut request: Request<B>) -> Self::Future {
        let tkns_auths: Vec<(String, Arc<Authorizer<C>>)> = self
            .auths
            .iter()
            .filter_map(|a| a.extract_token(request.headers()).map(|t| (t, a.clone())))
            .collect();

        if tkns_auths.is_empty() {
            return Box::pin(future::ready(Err(AuthError::MissingToken())));
        }

        Box::pin(async move {
            let mut token_data: Result<TokenData<C>, AuthError> = Err(AuthError::NoAuthorizer());
            for (token, auth) in tkns_auths {
                token_data = auth.check_auth(token.as_str()).await;
                if token_data.is_ok() {
                    break;
                }
            }
            match token_data {
                Ok(tdata) => {
                    // Set `token_data` as a request extension so it can be accessed by other
                    // services down the stack.

                    let something = Arc::new(Mutex::new(tdata));
                    request.extensions_mut().insert(something);

                    Ok(request)
                }
                Err(err) => Err(err), // TODO: error containing all errors (not just the last one) or to choose one?
            }
        })
    }
}

// -------------- Layer -----------------

#[derive(Clone)]
pub struct AuthorizationLayer<C>
where
    C: Clone + DeserializeOwned + Send,
{
    auths: Vec<Arc<Authorizer<C>>>,
}

impl<C> AuthorizationLayer<C>
where
    C: Clone + DeserializeOwned + Send,
{
    pub fn new(auths: Vec<Arc<Authorizer<C>>>) -> AuthorizationLayer<C> {
        Self { auths }
    }
}

impl<S, C> Layer<S> for AuthorizationLayer<C>
where
    C: Clone + DeserializeOwned + Send + Sync,
{
    type Service = AuthorizationService<S, C>;

    fn layer(&self, inner: S) -> Self::Service {
        AuthorizationService::new(inner, self.auths.clone())
    }
}

// ----------  AuthorizationService  --------

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
pub struct AuthorizationService<S, C>
where
    C: Clone + DeserializeOwned + Send,
{
    pub inner: S,
    pub auths: Vec<Arc<Authorizer<C>>>,
}

impl<S, C> AuthorizationService<S, C>
where
    C: Clone + DeserializeOwned + Send,
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

impl<S, C> AuthorizationService<S, C>
where
    C: Clone + DeserializeOwned + Send + Sync,
{
    /// Authorize requests using a custom scheme.
    ///
    /// The `Authorization` header is required to have the value provided.
    pub fn new(inner: S, auths: Vec<Arc<Authorizer<C>>>) -> AuthorizationService<S, C> {
        Self { inner, auths }
    }
}

impl<S, C> Service<Request<Body>> for AuthorizationService<S, C>
where
    S: Service<Request<Body>> + Clone,
    S::Response: From<AuthError>,
    C: Clone + DeserializeOwned + Send + Sync + 'static,
{
    type Response = S::Response;
    type Error = S::Error;
    type Future = ResponseFuture<S, C>;

    fn poll_ready(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        self.inner.poll_ready(cx)
    }

    fn call(&mut self, req: Request<Body>) -> Self::Future {
        let inner = self.inner.clone();
        // take the service that was ready
        let inner = std::mem::replace(&mut self.inner, inner);

        let auth_fut = self.authorize(req);

        ResponseFuture {
            state: State::Authorize { auth_fut },
            service: inner,
        }
    }
}
/*
impl<ReqBody, S, C> Service<Request<ReqBody>> for AuthorizationService<S, C>
where
    ReqBody: Send + Sync + 'static,
    S: Service<Request<ReqBody>> + Clone,
    S::Response: From<AuthError>,
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
        // take the service that was ready
        let inner = std::mem::replace(&mut self.inner, inner);

        let auth_fut = self.authorize(req);

        ResponseFuture {
            state: State::Authorize { auth_fut },
            service: inner,
        }
    }
}
*/

#[pin_project]
/// Response future for [`AuthorizationService`].
pub struct ResponseFuture<S, C>
where
    S: Service<Request<Body>>,
    C: Clone + DeserializeOwned + Send + Sync + 'static,
{
    #[pin]
    state: State<<AuthorizationService<S, C> as Authorize<Body>>::Future, S::Future>,
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

impl<S, C> Future for ResponseFuture<S, C>
where
    S: Service<Request<Body>>,
    S::Response: From<AuthError>,
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
                            return Poll::Ready(Ok(res.into()));
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

#[cfg(test)]
mod tests {
    use crate::{authorizer::Authorizer, IntoLayer, JwtAuthorizer, RegisteredClaims};

    use super::AuthorizationLayer;

    #[tokio::test]
    async fn auth_into_layer() {
        let auth1: Authorizer = JwtAuthorizer::from_secret("aaa").build().await.unwrap();
        let layer = auth1.into_layer();
        assert_eq!(1, layer.auths.len());
    }

    #[tokio::test]
    async fn auths_into_layer() {
        let auth1 = JwtAuthorizer::from_secret("aaa").build().await.unwrap();
        let auth2 = JwtAuthorizer::from_secret("bbb").build().await.unwrap();

        let layer: AuthorizationLayer<RegisteredClaims> = [auth1, auth2].into_layer();
        assert_eq!(2, layer.auths.len());
    }

    #[tokio::test]
    async fn vec_auths_into_layer() {
        let auth1 = JwtAuthorizer::from_secret("aaa").build().await.unwrap();
        let auth2 = JwtAuthorizer::from_secret("bbb").build().await.unwrap();

        let layer: AuthorizationLayer<RegisteredClaims> = vec![auth1, auth2].into_layer();
        assert_eq!(2, layer.auths.len());
    }

    #[tokio::test]
    async fn jwt_auth_to_layer() {
        let auth1: JwtAuthorizer = JwtAuthorizer::from_secret("aaa");
        #[allow(deprecated)]
        let layer = auth1.layer().await.unwrap();
        assert_eq!(1, layer.auths.len());
    }
}
