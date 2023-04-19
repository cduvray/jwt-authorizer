use std::{sync::Once, task::Poll};

use axum::body::HttpBody;
use futures_core::future::BoxFuture;
use http::header::AUTHORIZATION;
use jwt_authorizer::{layer::AsyncAuthorizationService, JwtAuthorizer};
use serde::{Deserialize, Serialize};
use tonic::{server::UnaryService, transport::NamedService, IntoRequest, Status};
use tower::Service;

use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};

use crate::common::{JWT_RSA1_OK, JWT_RSA2_OK};

mod common;

/// Static variable to ensure that logging is only initialized once.
pub static INITIALIZED: Once = Once::new();

#[derive(Debug, Deserialize, Serialize, Clone)]
struct User {
    sub: String,
}

#[derive(prost::Message)]
struct HelloMessage {
    #[prost(string, tag = "1")]
    message: String,
}

#[derive(Debug, Default, Clone)]
struct SayHelloMethod {}
impl UnaryService<HelloMessage> for SayHelloMethod {
    type Response = HelloMessage;
    type Future = BoxFuture<'static, Result<tonic::Response<Self::Response>, Status>>;

    fn call(&mut self, request: tonic::Request<HelloMessage>) -> Self::Future {
        Box::pin(async move {
            let hi = request.into_inner();
            let reply = HelloMessage {
                message: format!("Hello, {}", hi.message),
            };
            Ok(tonic::Response::new(reply))
        })
    }
}

#[derive(Debug, Default, Clone)]
struct GreeterServer {
    expected_sub: String,
}

impl Service<http::Request<tonic::transport::Body>> for GreeterServer {
    type Response = http::Response<tonic::body::BoxBody>;
    type Error = std::convert::Infallible;
    type Future = BoxFuture<'static, Result<Self::Response, Self::Error>>;

    fn poll_ready(&mut self, _cx: &mut std::task::Context<'_>) -> std::task::Poll<Result<(), Self::Error>> {
        Poll::Ready(Ok(()))
    }

    fn call(&mut self, req: http::Request<tonic::transport::Body>) -> Self::Future {
        let token = req.extensions().get::<jsonwebtoken::TokenData<User>>().unwrap();
        assert_eq!(token.claims.sub, self.expected_sub);
        match req.uri().path() {
            "/hello/SayHello" => Box::pin(async move {
                let mut grpc = tonic::server::Grpc::new(tonic::codec::ProstCodec::default());
                Ok(grpc.unary(SayHelloMethod::default(), req).await)
            }),
            p => {
                let p = p.to_string();
                Box::pin(async move { Ok(Status::unimplemented(p).to_http()) })
            }
        }
    }
}

impl NamedService for GreeterServer {
    const NAME: &'static str = "hello";
}

async fn app(
    jwt_auth: JwtAuthorizer<User>,
    expected_sub: String,
) -> AsyncAuthorizationService<tonic::transport::server::Routes, User> {
    let layer = jwt_auth.layer().await.unwrap();
    tonic::transport::Server::builder()
        .layer(layer)
        .add_service(GreeterServer { expected_sub })
        .into_service()
}

fn init_test() {
    INITIALIZED.call_once(|| {
        tracing_subscriber::registry()
            .with(tracing_subscriber::EnvFilter::new(
                std::env::var("RUST_LOG").unwrap_or_else(|_| "info,jwt-authorizer=debug,tower_http=debug".into()),
            ))
            .with(tracing_subscriber::fmt::layer())
            .init();
    });
}

// The grpc client produces a http request with a tonic boxbody that the transport is meant to sent out, while the server side
// expects to receive a http request with a hyper body.. This simple wrapper converts from one to
// the other.
struct GrpcWrapper<S>
where
    S: Service<http::Request<axum::body::Body>> + Clone,
{
    inner: S,
}

impl<S> Service<http::Request<tonic::body::BoxBody>> for GrpcWrapper<S>
where
    S: Service<http::Request<axum::body::Body>> + Clone + Send + 'static,
    S::Future: Send,
{
    type Response = S::Response;
    type Error = S::Error;
    type Future = BoxFuture<'static, Result<Self::Response, Self::Error>>;

    fn poll_ready(&mut self, cx: &mut std::task::Context<'_>) -> Poll<Result<(), Self::Error>> {
        self.inner.poll_ready(cx)
    }

    fn call(&mut self, req: http::Request<tonic::body::BoxBody>) -> Self::Future {
        let inner = self.inner.clone();
        // take the service that was ready
        let mut inner = std::mem::replace(&mut self.inner, inner);
        Box::pin(async move {
            let (parts, mut body) = req.into_parts();
            let mut data = Vec::new();
            while let Some(d) = body.data().await {
                let d = d.unwrap();
                data.extend_from_slice(&d)
            }
            inner
                .call(http::Request::from_parts(parts, axum::body::Body::from(data)))
                .await
        })
    }
}

async fn make_protected_request<S: Clone>(
    app: AsyncAuthorizationService<S, User>,
    bearer: Option<&str>,
    message: &str,
) -> Result<tonic::Response<HelloMessage>, Status>
where
    S: Service<
            http::Request<tonic::transport::Body>,
            Response = http::Response<tonic::body::BoxBody>,
            Error = tower::BoxError,
        > + Send
        + 'static,
    S::Future: Send,
{
    let mut grpc = tonic::client::Grpc::new(GrpcWrapper { inner: app });

    let mut request = HelloMessage {
        message: message.to_string(),
    }
    .into_request();

    if let Some(bearer) = bearer {
        let headers = request.metadata_mut();
        headers.insert(AUTHORIZATION.as_str(), format!("Bearer {bearer}").parse().unwrap());
    }

    grpc.ready().await.unwrap();
    grpc.unary(
        request,
        http::uri::PathAndQuery::from_static("/hello/SayHello"),
        tonic::codec::ProstCodec::default(),
    )
    .await
}

#[tokio::test]
async fn successfull_auth() {
    init_test();
    let auth: JwtAuthorizer<User> = JwtAuthorizer::from_rsa_pem("../config/rsa-public1.pem");
    let app = app(auth, "b@b.com".to_string()).await;
    let r = make_protected_request(app.clone(), Some(JWT_RSA1_OK), "world").await.unwrap();
    assert_eq!(r.get_ref().message, "Hello, world");
}

#[tokio::test]
async fn wrong_token() {
    init_test();
    let auth: JwtAuthorizer<User> = JwtAuthorizer::from_rsa_pem("../config/rsa-public1.pem");
    let app = app(auth, "b@b.com".to_string()).await;
    let status = make_protected_request(app.clone(), Some(JWT_RSA2_OK), "world")
        .await
        .unwrap_err();
    assert_eq!(status.code(), tonic::Code::Unauthenticated);
}

#[tokio::test]
async fn no_token() {
    init_test();
    let auth: JwtAuthorizer<User> = JwtAuthorizer::from_rsa_pem("../config/rsa-public1.pem");
    let app = app(auth, "b@b.com".to_string()).await;
    let status = make_protected_request(app.clone(), None, "world").await.unwrap_err();
    assert_eq!(status.code(), tonic::Code::Unauthenticated);
}
