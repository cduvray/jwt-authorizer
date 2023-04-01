use std::{
    net::{SocketAddr, TcpListener},
    sync::{
        atomic::{AtomicU16, Ordering},
        Arc, Once,
    },
    thread,
    time::Duration,
};

use axum::{response::Response, routing::get, Json, Router};
use http::{request::Builder, Request, StatusCode};
use hyper::Body;
use jwt_authorizer::{layer::JwtSource, JwtAuthorizer, JwtClaims, Refresh, RefreshStrategy};
use lazy_static::lazy_static;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use tower::Service;
use tower::ServiceExt;

use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};

use crate::common::{JWT_RSA1_OK, JWT_RSA2_OK};

mod common;

/// Static variable to ensure that logging is only initialized once.
pub static INITIALIZED: Once = Once::new();

#[derive(Debug, Deserialize, Serialize, Clone)]
struct User {
    sub: String,
}

struct Stats {
    discovery_counter: Arc<AtomicU16>,
    jwks_counter: Arc<AtomicU16>,
}

impl Stats {
    fn new() -> Self {
        Self {
            discovery_counter: Arc::new(AtomicU16::new(0)),
            jwks_counter: Arc::new(AtomicU16::new(0)),
        }
    }

    fn jwks_counter(&self) -> u16 {
        self.jwks_counter.load(Ordering::Relaxed)
    }

    fn discovery_counter(&self) -> u16 {
        self.discovery_counter.load(Ordering::Relaxed)
    }

    fn discovery(&self, uri: &str) -> Json<Value> {
        self.discovery_counter.fetch_add(1, Ordering::Relaxed);
        let d = serde_json::json!({ "jwks_uri": format!("{uri}/jwks") });

        Json(d)
    }

    fn jwks(&self) -> Json<Value> {
        self.jwks_counter.fetch_add(1, Ordering::Relaxed);
        Json(common::JWKS_RSA1.clone())
    }
}

fn run_jwks_server(stats: &Arc<Stats>) -> String {
    let listener = TcpListener::bind("0.0.0.0:0".parse::<SocketAddr>().unwrap()).unwrap();
    let addr = listener.local_addr().unwrap();
    let url = format!("http://{}:{}", addr.ip(), addr.port());

    let url2 = url.clone();

    let disc_stats = stats.clone();
    let jwks_stats = stats.clone();

    let app = Router::new()
        .route(
            "/.well-known/openid-configuration",
            get(move || {
                let disc_stats = disc_stats.clone();
                async move { disc_stats.discovery(&url2) }
            }),
        )
        .route(
            "/jwks",
            get(move || {
                let jwks_stats = jwks_stats.clone();
                async move { jwks_stats.jwks() }
            }),
        );

    tokio::spawn(async move {
        axum::Server::from_tcp(listener)
            .unwrap()
            .serve(app.into_make_service())
            .await
            .unwrap();
    });

    url
}

async fn app(jwt_auth: JwtAuthorizer<User>, source: JwtSource, auto_reject: bool) -> Router {
    async fn public_handler() -> &'static str {
        "public"
    }

    async fn protected_handler() -> &'static str {
        "protected"
    }

    async fn protected_with_user(JwtClaims(user): JwtClaims<User>) -> Json<User> {
        Json(user)
    }

    let pub_route: Router = Router::new().route("/public", get(public_handler));
    let protected_route: Router = Router::new()
        .route("/protected", get(protected_handler))
        .route("/protected-with-user", get(protected_with_user))
        .layer(jwt_auth.jwt_source(source).layer().await.unwrap().auto_reject(auto_reject));

    Router::new().merge(pub_route).merge(protected_route)
}

fn init_test() -> Arc<Stats> {
    INITIALIZED.call_once(|| {
        tracing_subscriber::registry()
            .with(tracing_subscriber::EnvFilter::new(
                std::env::var("RUST_LOG").unwrap_or_else(|_| "info,jwt-authorizer=debug,tower_http=debug".into()),
            ))
            .with(tracing_subscriber::fmt::layer())
            .init();
    });
    Arc::new(Stats::new())
}

async fn make_request(app: &mut Router, req: Request<Body>) -> Response {
    app.ready().await.unwrap().call(req).await.unwrap()
}

fn apply_token(b: Builder, source: JwtSource, token: Option<&str>) -> Builder {
    match (source.clone(), token) {
        (_, None) => b,
        (JwtSource::Cookie(name), Some(token)) => b.header("Cookie", format!("{name}={token}")),
        (JwtSource::AuthorizationHeader, Some(token)) => b.header("Authorization", format!("Bearer {token}")),
    }
}

async fn make_protected_request(app: &mut Router, source: JwtSource, token: Option<&str>) -> Response {
    make_request(
        app,
        apply_token(Request::builder().uri("/protected"), source, token)
            .body(Body::empty())
            .unwrap(),
    )
    .await
}

async fn make_protected_user_request(app: &mut Router, token: Option<&str>) -> Response {
    make_request(
        app,
        apply_token(
            Request::builder().uri("/protected-with-user"),
            JwtSource::AuthorizationHeader,
            token,
        )
        .body(Body::empty())
        .unwrap(),
    )
    .await
}

async fn make_public_request(app: &mut Router) -> Response {
    make_request(app, Request::builder().uri("/public").body(Body::empty()).unwrap()).await
}

#[tokio::test]
async fn jwk() {
    let stats = init_test();
    let url = run_jwks_server(&stats);
    let auth: JwtAuthorizer<User> = JwtAuthorizer::from_oidc(&url);
    let source = JwtSource::AuthorizationHeader;
    let mut app = app(auth, source.clone(), true).await;
    assert_eq!(1, stats.discovery_counter());
    assert_eq!(0, stats.jwks_counter());
    // NO LOADING when public request
    let r = make_public_request(&mut app).await;
    assert_eq!(StatusCode::OK, r.status());
    assert_eq!(0, stats.jwks_counter(), "sc1: public -> no loading");
    // LOADING - first jwt check
    let r = make_protected_request(&mut app, source.clone(), Some(JWT_RSA1_OK)).await;
    assert_eq!(StatusCode::OK, r.status());
    assert_eq!(1, stats.jwks_counter(), "sc1: 1st check -> loading");
    // NO RELOADING same kid with OK
    let r = make_protected_request(&mut app, source.clone(), Some(JWT_RSA1_OK)).await;
    assert_eq!(StatusCode::OK, r.status());
    assert_eq!(1, stats.jwks_counter(), "sc1: 2st check -> no loading");
    // NO RELEOADING, invalid kid, 401
    let r = make_protected_request(&mut app, source.clone(), Some(JWT_RSA2_OK)).await;
    assert_eq!(StatusCode::UNAUTHORIZED, r.status());
    assert_eq!(1, stats.jwks_counter(), "sc1: 3st check (invalid kid) -> no loading");
}

///  SCENARIO2
///
///  Refresh strategy: INTERVAL
#[tokio::test]
async fn jwk_interval() {
    let stats = init_test();
    let url = run_jwks_server(&stats);
    let refresh = Refresh {
        refresh_interval: Duration::from_millis(40),
        retry_interval: Duration::from_millis(0),
        strategy: RefreshStrategy::Interval,
    };
    let auth: JwtAuthorizer<User> = JwtAuthorizer::from_oidc(&url).refresh(refresh);
    let source = JwtSource::AuthorizationHeader;
    let mut app = app(auth, source.clone(), true).await;
    assert_eq!(1, stats.discovery_counter());
    assert_eq!(0, stats.jwks_counter());
    let r = make_protected_request(&mut app, source.clone(), Some(JWT_RSA1_OK)).await;
    assert_eq!(StatusCode::OK, r.status());
    assert_eq!(1, stats.jwks_counter());
    // NO RELOADING same kid
    let r = make_protected_request(&mut app, source.clone(), Some(JWT_RSA1_OK)).await;
    assert_eq!(StatusCode::OK, r.status());
    assert_eq!(1, stats.jwks_counter());
    // RELEOADING, same kid, refresh_interval elapsed
    thread::sleep(Duration::from_millis(41));
    let r = make_protected_request(&mut app, source.clone(), Some(JWT_RSA1_OK)).await;
    assert_eq!(StatusCode::OK, r.status());
    assert_eq!(2, stats.jwks_counter());
}

///  SCENARIO3
///
///  Refresh strategy: KeyNotFound
#[tokio::test]
async fn jwk_missing_key() {
    let stats = init_test();
    let url = run_jwks_server(&stats);
    let refresh = Refresh {
        strategy: RefreshStrategy::KeyNotFound,
        refresh_interval: Duration::from_millis(40),
        retry_interval: Duration::from_millis(0),
    };
    let auth: JwtAuthorizer<User> = JwtAuthorizer::from_oidc(&url).refresh(refresh);
    let source = JwtSource::AuthorizationHeader;
    let mut app = app(auth, source.clone(), true).await;
    assert_eq!(1, stats.discovery_counter());
    assert_eq!(0, stats.jwks_counter());
    // RELOADING getting keys first time
    let r = make_protected_request(&mut app, source.clone(), Some(JWT_RSA1_OK)).await;
    assert_eq!(StatusCode::OK, r.status());
    assert_eq!(1, stats.jwks_counter());
    thread::sleep(Duration::from_millis(21));
    // NO RELOADING refresh interval elapsed, kid OK
    let r = make_protected_request(&mut app, source.clone(), Some(JWT_RSA1_OK)).await;
    assert_eq!(StatusCode::OK, r.status());
    assert_eq!(1, stats.jwks_counter());
    // RELEOADING, unknown kid, refresh_interval elapsed
    thread::sleep(Duration::from_millis(41));
    let r = make_protected_request(&mut app, source.clone(), Some(JWT_RSA2_OK)).await;
    assert_eq!(StatusCode::UNAUTHORIZED, r.status());
    assert_eq!(2, stats.jwks_counter());
}

///  SCENARIO4
///
///  Refresh strategy: NoRefresh
#[tokio::test]
async fn jwk_no_refresh() {
    let stats = init_test();

    let url = run_jwks_server(&stats);
    let refresh = Refresh {
        strategy: RefreshStrategy::NoRefresh,
        refresh_interval: Duration::from_millis(0),
        retry_interval: Duration::from_millis(0),
    };
    let auth: JwtAuthorizer<User> = JwtAuthorizer::from_oidc(&url).refresh(refresh);
    let source = JwtSource::AuthorizationHeader;
    let mut app = app(auth, source.clone(), true).await;
    assert_eq!(1, stats.discovery_counter());
    assert_eq!(0, stats.jwks_counter());
    // RELOADING getting keys first time
    let r = make_protected_request(&mut app, source.clone(), Some(JWT_RSA1_OK)).await;
    assert_eq!(StatusCode::OK, r.status());
    assert_eq!(1, stats.jwks_counter());
    thread::sleep(Duration::from_millis(21));
    // NO RELOADING kid OK
    let r = make_protected_request(&mut app, source.clone(), Some(JWT_RSA1_OK)).await;
    assert_eq!(StatusCode::OK, r.status());
    assert_eq!(1, stats.jwks_counter());
    // NO RELEOADING, unknown kid
    thread::sleep(Duration::from_millis(41));
    let r = make_protected_request(&mut app, source.clone(), Some(JWT_RSA2_OK)).await;
    assert_eq!(StatusCode::UNAUTHORIZED, r.status());
    assert_eq!(1, stats.jwks_counter());
}

/// SCENARIO5
///
/// Read token from cookie
#[tokio::test]
async fn cookie() {
    let stats = init_test();
    let url = run_jwks_server(&stats);
    let auth: JwtAuthorizer<User> = JwtAuthorizer::from_oidc(&url);
    let source = JwtSource::Cookie("jwk".to_string());
    let mut app = app(auth, source.clone(), true).await;
    assert_eq!(1, stats.discovery_counter());
    assert_eq!(0, stats.jwks_counter());
    // NO LOADING when public request
    let r = make_public_request(&mut app).await;
    assert_eq!(StatusCode::OK, r.status());
    assert_eq!(0, stats.jwks_counter(), "sc1: public -> no loading");
    // LOADING - first jwt check
    let r = make_protected_request(&mut app, source.clone(), Some(JWT_RSA1_OK)).await;
    assert_eq!(StatusCode::OK, r.status());
    assert_eq!(1, stats.jwks_counter(), "sc1: 1st check -> loading");
    // NO RELOADING same kid with OK
    let r = make_protected_request(&mut app, source.clone(), Some(JWT_RSA1_OK)).await;
    assert_eq!(StatusCode::OK, r.status());
    assert_eq!(1, stats.jwks_counter(), "sc1: 2st check -> no loading");
    // NO RELEOADING, invalid kid, 401
    let r = make_protected_request(&mut app, source.clone(), Some(JWT_RSA2_OK)).await;
    assert_eq!(StatusCode::UNAUTHORIZED, r.status());
    assert_eq!(1, stats.jwks_counter(), "sc1: 3st check (invalid kid) -> no loading");
}

/// SCENARIO6
///
/// Do not auto-reject missing tokens when there is no extractor for it
#[tokio::test]
async fn auto_reject() {
    let stats = init_test();
    let url = run_jwks_server(&stats);
    let auth: JwtAuthorizer<User> = JwtAuthorizer::from_oidc(&url);
    let source = JwtSource::AuthorizationHeader;
    let mut app = app(auth, source.clone(), false).await;
    assert_eq!(1, stats.discovery_counter());
    assert_eq!(0, stats.jwks_counter());

    let r = make_public_request(&mut app).await;
    assert_eq!(StatusCode::OK, r.status());
    assert_eq!(0, stats.jwks_counter(), "sc1: public -> no loading");

    let r = make_protected_user_request(&mut app, None).await;
    assert_eq!(StatusCode::UNAUTHORIZED, r.status());
    assert_eq!(0, stats.jwks_counter(), "sc1: 1st check -> loading");

    let r = make_protected_request(&mut app, source.clone(), Some(JWT_RSA1_OK)).await;
    assert_eq!(StatusCode::OK, r.status());
    assert_eq!(1, stats.jwks_counter(), "sc1: 1st check -> loading");
}
