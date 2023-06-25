use axum::http::Request;
use futures_core::ready;
use futures_util::future::BoxFuture;
use headers::authorization::Bearer;
use headers::{Authorization, HeaderMapExt};
use pin_project::pin_project;
use std::future::Future;
use std::pin::Pin;
use std::task::{Context, Poll};
use tower_layer::Layer;
use tower_service::Service;

use crate::authorizer::Authorize;
use crate::{layer, AuthError};

/// Authorizer Layer builder
pub struct AsyncAuthorizationLayerBuilder<A> {
    auth: A,
    jwt_source: JwtSource,
}

/// authorization layer builder
impl<A> AsyncAuthorizationLayerBuilder<A>
where
    A: Clone + Authorize + Send + Sync + 'static,
{
    pub fn new(auth: A) -> Self {
        AsyncAuthorizationLayerBuilder {
            auth,
            jwt_source: JwtSource::default(),
        }
    }
    /// configures the source of the bearer token
    ///
    /// (default: AuthorizationHeader)
    pub fn jwt_source(mut self, src: JwtSource) -> Self {
        self.jwt_source = src;

        self
    }

    /// Build axum layer
    pub fn build(self) -> AsyncAuthorizationLayer<A> {
        AsyncAuthorizationLayer::new(self.auth, self.jwt_source)
    }
}

/// Trait for authorizing requests.
pub trait AsyncAuthorizer<B> {
    type RequestBody;
    type Future: Future<Output = Result<Request<Self::RequestBody>, AuthError>>;

    /// Authorize the request.
    ///
    /// If the future resolves to `Ok(request)` then the request is allowed through, otherwise not.
    fn authorize(&self, request: Request<B>) -> Self::Future;
}

impl<A, B, S> AsyncAuthorizer<B> for AsyncAuthorizationService<S, A>
where
    B: Send + Sync + 'static,
    A: Clone + Authorize + Send + Sync + 'static,
{
    type RequestBody = B;
    type Future = BoxFuture<'static, Result<Request<B>, AuthError>>;

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
                authorizer.check_auth(token.as_str()).await.map(|token_data| {
                    // Set `token_data` as a request extension so it can be accessed by other
                    // services down the stack.
                    request.extensions_mut().insert(token_data);

                    request
                })
            } else {
                Err(AuthError::MissingToken())
            }
        })
    }
}

// -------------- Layer -----------------

#[derive(Clone)]
pub struct AsyncAuthorizationLayer<A>
where
    A: Clone + Authorize,
{
    auth: A,
    jwt_source: JwtSource,
}

impl<A> AsyncAuthorizationLayer<A>
where
    A: Clone + Authorize,
{
    pub fn new(auth: A, jwt_source: JwtSource) -> AsyncAuthorizationLayer<A> {
        Self { auth, jwt_source }
    }
}

impl<A, S> Layer<S> for AsyncAuthorizationLayer<A>
where
    A: Clone + Authorize,
{
    type Service = AsyncAuthorizationService<S, A>;

    fn layer(&self, inner: S) -> Self::Service {
        AsyncAuthorizationService::new(inner, self.auth.clone(), self.jwt_source.clone())
    }
}

// ----------  AsyncAuthorizationService  --------

/// Source of the bearer token
#[derive(Clone, Default)]
pub enum JwtSource {
    /// Storing the bearer token in Authorization header
    ///
    /// (default)
    #[default]
    AuthorizationHeader,
    /// Cookies
    ///
    /// (be careful when using cookies, some precautions must be taken, cf. RFC6750)
    Cookie(String),
    // TODO: "Form-Encoded Content Parameter" may be added in the future (OAuth 2.1 / 5.2.1.2)
    // FormParam,
}

#[derive(Clone)]
pub struct AsyncAuthorizationService<S, A>
where
    A: Clone + Authorize,
{
    pub inner: S,
    pub auth: A,
    pub jwt_source: JwtSource,
}

impl<S, A> AsyncAuthorizationService<S, A>
where
    A: Clone + Authorize,
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

impl<A, S> AsyncAuthorizationService<S, A>
where
    A: Clone + Authorize,
{
    /// Authorize requests using a custom scheme.
    ///
    /// The `Authorization` header is required to have the value provided.
    pub fn new(inner: S, auth: A, jwt_source: JwtSource) -> AsyncAuthorizationService<S, A> {
        Self { inner, auth, jwt_source }
    }
}

impl<ReqBody, S, A> Service<Request<ReqBody>> for AsyncAuthorizationService<S, A>
where
    ReqBody: Send + Sync + 'static,
    A: Clone + Authorize + Send + Sync + 'static,
    S: Service<Request<ReqBody>> + Clone,
    S::Response: From<AuthError>,
{
    type Response = S::Response;
    type Error = S::Error;
    type Future = ResponseFuture<S, ReqBody, A>;

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

#[pin_project]
/// Response future for [`AsyncAuthorizationService`].
pub struct ResponseFuture<S, ReqBody, A>
where
    A: Clone + Authorize + Send + Sync + 'static,
    S: Service<Request<ReqBody>>,
    ReqBody: Send + Sync + 'static,
{
    #[pin]
    state: State<<AsyncAuthorizationService<S, A> as AsyncAuthorizer<ReqBody>>::Future, S::Future>,
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

impl<S, ReqBody, A> Future for ResponseFuture<S, ReqBody, A>
where
    A: Clone + Authorize + Send + Sync,
    S: Service<Request<ReqBody>>,
    S::Response: From<AuthError>,
    ReqBody: Send + Sync + 'static,
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
