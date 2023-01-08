use axum::http::Request;
use axum::response::IntoResponse;
use axum::{body::Body, response::Response};
use futures_core::ready;
use futures_util::future::BoxFuture;
use headers::authorization::Bearer;
use headers::{Authorization, HeaderMapExt};
use http::StatusCode;
use pin_project::pin_project;
use serde::de::DeserializeOwned;
use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};
use tower_layer::Layer;
use tower_service::Service;

use crate::authorizer::{Authorizer, FnClaimsChecker};

/// Authorizer Layer builder
///
/// - initialisation of the Authorizer from jwks, rsa, ed, ec or secret
/// - can define a checker (jwt claims check)
pub struct JwtAuthorizer<C>
where
    C: Clone + DeserializeOwned,
{
    url: Option<&'static str>,
    claims_checker: Option<FnClaimsChecker<C>>,
}

/// layer builder
impl<C> JwtAuthorizer<C>
where
    C: Clone + DeserializeOwned + Send + Sync,
{
    pub fn new() -> Self {
        JwtAuthorizer {
            url: None,
            claims_checker: None,
        }
    }

    pub fn from_jwks_url(mut self, url: &'static str) -> JwtAuthorizer<C> {
        self.url = Some(url);

        self
    }

    pub fn from_rsa_pem(mut self, path: &'static str) -> JwtAuthorizer<C> {
        // TODO
        self
    }

    pub fn from_ec_der(mut self, path: &'static str) -> JwtAuthorizer<C> {
        // TODO
        self
    }

    pub fn from_ed_der(mut self, path: &'static str) -> JwtAuthorizer<C> {
        // TODO
        self
    }

    pub fn from_secret(mut self, path: &'static str) -> JwtAuthorizer<C> {
        // TODO
        self
    }

    /// layer that checks token validity and claim constraints (custom function)
    pub fn with_check(mut self, checker_fn: fn(&C) -> bool) -> JwtAuthorizer<C> {
        self.claims_checker = Some(FnClaimsChecker { checker_fn });

        self
    }

    /// build axum layer
    pub fn layer(&self) -> AsyncAuthorizationLayer<C> {
        // TODO: replace unwrap
        let auth = Arc::new(Authorizer::from_jwks_url(self.url.unwrap(), self.claims_checker.clone()).unwrap());

        AsyncAuthorizationLayer::new(auth)
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
    type ResponseBody = Body;
    type Future = BoxFuture<'static, Result<Request<B>, Response<Self::ResponseBody>>>;

    fn authorize(&self, mut request: Request<B>) -> Self::Future {
        let authorizer = self.auth.clone();
        let h = request.headers();
        let bearer: Authorization<Bearer> = h.typed_get().unwrap();
        Box::pin(async move {
            if let Ok(token_data) = authorizer.check_auth(bearer.token()).await {
                // Set `token_data` as a request extension so it can be accessed by other
                // services down the stack.
                request.extensions_mut().insert(token_data);

                Ok(request)
            } else {
                let unauthorized_response = Response::builder()
                    .status(StatusCode::UNAUTHORIZED)
                    .body(Body::empty())
                    .unwrap();

                Err(unauthorized_response)
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
}

impl<C> AsyncAuthorizationLayer<C>
where
    C: Clone + DeserializeOwned + Send,
{
    pub fn new(auth: Arc<Authorizer<C>>) -> AsyncAuthorizationLayer<C> {
        Self { auth }
    }
}

impl<S, C> Layer<S> for AsyncAuthorizationLayer<C>
where
    C: Clone + DeserializeOwned + Send + Sync,
{
    type Service = AsyncAuthorizationService<S, C>;

    fn layer(&self, inner: S) -> Self::Service {
        AsyncAuthorizationService::new(inner, self.auth.clone())
    }
}

// ----------  AsyncAuthorizationService  --------

#[derive(Clone)]
pub struct AsyncAuthorizationService<S, C>
where
    C: Clone + DeserializeOwned + Send + Sync,
{
    pub inner: S,
    pub auth: Arc<Authorizer<C>>,
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
    pub fn new(inner: S, auth: Arc<Authorizer<C>>) -> AsyncAuthorizationService<S, C> {
        Self { inner, auth }
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
                            let r = (StatusCode::FORBIDDEN, format!("Unauthorized : {:?}", res)).into_response();
                            // TODO: replace r by res (type problems: res should be already a 403 error response)
                            return Poll::Ready(Ok(r));
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
