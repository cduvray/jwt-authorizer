use std::{
    net::{SocketAddr, TcpListener},
    sync::{
        atomic::{AtomicI16, Ordering},
        Arc, Once,
    },
    thread,
    time::Duration,
};

use axum::{response::Response, routing::get, Json, Router};
use http::{header::AUTHORIZATION, Request, StatusCode};
use hyper::Body;
use jwt_authorizer::{IntoLayer, JwtAuthorizer, JwtClaims, Refresh, RefreshStrategy, Validation};
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

lazy_static! {
    static ref DISCOVERY_COUNTER: Arc<AtomicI16> = Arc::new(AtomicI16::new(0));
    static ref JWKS_COUNTER: Arc<AtomicI16> = Arc::new(AtomicI16::new(0));
}

struct Stats {}

impl Stats {
    fn reset() {
        Arc::clone(&DISCOVERY_COUNTER).store(0, Ordering::Relaxed);
        Arc::clone(&JWKS_COUNTER).store(0, Ordering::Relaxed);
    }
    fn jwks_counter() -> i16 {
        Arc::clone(&JWKS_COUNTER).load(Ordering::Relaxed)
    }
    fn discovery_counter() -> i16 {
        Arc::clone(&DISCOVERY_COUNTER).load(Ordering::Relaxed)
    }
}

fn discovery(uri: &str) -> Json<Value> {
    Arc::clone(&DISCOVERY_COUNTER).fetch_add(1, Ordering::Relaxed);
    let d = serde_json::json!({ "jwks_uri": format!("{uri}/jwks") });

    Json(d)
}

async fn jwks() -> Json<Value> {
    Arc::clone(&JWKS_COUNTER).fetch_add(1, Ordering::Relaxed);

    Json(common::JWKS_RSA1.clone())
}

fn run_jwks_server() -> String {
    let listener = TcpListener::bind("0.0.0.0:0".parse::<SocketAddr>().unwrap()).unwrap();
    let addr = listener.local_addr().unwrap();
    let url = format!("http://{}:{}", addr.ip(), addr.port());

    let url2 = url.clone();

    let app = Router::new()
        .route("/.well-known/openid-configuration", get(|| async move { discovery(&url2) }))
        .route("/jwks", get(jwks));

    tokio::spawn(async move {
        axum::Server::from_tcp(listener)
            .unwrap()
            .serve(app.into_make_service())
            .await
            .unwrap();
    });

    url
}

async fn app(jwt_auth: JwtAuthorizer<User>) -> Router {
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
        .layer(
            jwt_auth
                .validation(Validation::new().aud(&["aud1"]))
                .build()
                .await
                .unwrap()
                .into_layer(),
        );

    Router::new().merge(pub_route).merge(protected_route)
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
    // reset counters
    Stats::reset();
}

async fn make_proteced_request(app: &mut Router, bearer: &str) -> Response {
    app.ready()
        .await
        .unwrap()
        .call(
            Request::builder()
                .uri("/protected")
                .header(AUTHORIZATION.as_str(), format!("Bearer {bearer}"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap()
}

async fn make_public_request(app: &mut Router) -> Response {
    app.ready()
        .await
        .unwrap()
        .call(Request::builder().uri("/public").body(Body::empty()).unwrap())
        .await
        .unwrap()
}

#[tokio::test]
async fn sequential_tests() {
    // these tests must be executed sequentially
    scenario1().await;
    scenario2().await;
    scenario3().await;
    scenario4().await;
}

async fn scenario1() {
    init_test();
    let url = run_jwks_server();
    let auth: JwtAuthorizer<User> = JwtAuthorizer::from_oidc(&url);
    let mut app = app(auth).await;
    assert_eq!(1, Stats::discovery_counter());
    assert_eq!(0, Stats::jwks_counter());
    // NO LOADING when public request
    let r = make_public_request(&mut app).await;
    assert_eq!(StatusCode::OK, r.status());
    assert_eq!(0, Stats::jwks_counter(), "sc1: public -> no loading");
    // LOADING - first jwt check
    let r = make_proteced_request(&mut app, JWT_RSA1_OK).await;
    assert_eq!(StatusCode::OK, r.status());
    assert_eq!(1, Stats::jwks_counter(), "sc1: 1st check -> loading");
    // NO RELOADING same kid with OK
    let r = make_proteced_request(&mut app, JWT_RSA1_OK).await;
    assert_eq!(StatusCode::OK, r.status());
    assert_eq!(1, Stats::jwks_counter(), "sc1: 2st check -> no loading");
    // NO RELEOADING, invalid kid, 401
    let r = make_proteced_request(&mut app, JWT_RSA2_OK).await;
    assert_eq!(StatusCode::UNAUTHORIZED, r.status());
    assert_eq!(1, Stats::jwks_counter(), "sc1: 3st check (invalid kid) -> no loading");
}

///  SCENARIO2
///
///  Refresh strategy: INTERVAL
async fn scenario2() {
    init_test();
    let url = run_jwks_server();
    let refresh = Refresh {
        refresh_interval: Duration::from_millis(40),
        retry_interval: Duration::from_millis(0),
        strategy: RefreshStrategy::Interval,
    };
    let auth: JwtAuthorizer<User> = JwtAuthorizer::from_oidc(&url).refresh(refresh);
    let mut app = app(auth).await;
    assert_eq!(1, Stats::discovery_counter());
    assert_eq!(0, Stats::jwks_counter());
    let r = make_proteced_request(&mut app, JWT_RSA1_OK).await;
    assert_eq!(StatusCode::OK, r.status());
    assert_eq!(1, Stats::jwks_counter());
    // NO RELOADING same kid
    let r = make_proteced_request(&mut app, JWT_RSA1_OK).await;
    assert_eq!(StatusCode::OK, r.status());
    assert_eq!(1, Stats::jwks_counter());
    // RELEOADING, same kid, refresh_interval elapsed
    thread::sleep(Duration::from_millis(41));
    let r = make_proteced_request(&mut app, JWT_RSA1_OK).await;
    assert_eq!(StatusCode::OK, r.status());
    assert_eq!(2, Stats::jwks_counter());
}

///  SCENARIO3
///
///  Refresh strategy: KeyNotFound
async fn scenario3() {
    init_test();
    let url = run_jwks_server();
    let refresh = Refresh {
        strategy: RefreshStrategy::KeyNotFound,
        refresh_interval: Duration::from_millis(40),
        retry_interval: Duration::from_millis(0),
    };
    let auth: JwtAuthorizer<User> = JwtAuthorizer::from_oidc(&url).refresh(refresh);
    let mut app = app(auth).await;
    assert_eq!(1, Stats::discovery_counter());
    assert_eq!(0, Stats::jwks_counter());
    // RELOADING getting keys first time
    let r = make_proteced_request(&mut app, JWT_RSA1_OK).await;
    assert_eq!(StatusCode::OK, r.status());
    assert_eq!(1, Stats::jwks_counter());
    thread::sleep(Duration::from_millis(21));
    // NO RELOADING refresh interval elapsed, kid OK
    let r = make_proteced_request(&mut app, JWT_RSA1_OK).await;
    assert_eq!(StatusCode::OK, r.status());
    assert_eq!(1, Stats::jwks_counter());
    // RELEOADING, unknown kid, refresh_interval elapsed
    thread::sleep(Duration::from_millis(41));
    let r = make_proteced_request(&mut app, JWT_RSA2_OK).await;
    assert_eq!(StatusCode::UNAUTHORIZED, r.status());
    assert_eq!(2, Stats::jwks_counter());
}

///  SCENARIO4
///
///  Refresh strategy: NoRefresh
async fn scenario4() {
    init_test();
    let url = run_jwks_server();
    let refresh = Refresh {
        strategy: RefreshStrategy::NoRefresh,
        refresh_interval: Duration::from_millis(0),
        retry_interval: Duration::from_millis(0),
    };
    let auth: JwtAuthorizer<User> = JwtAuthorizer::from_oidc(&url).refresh(refresh);
    let mut app = app(auth).await;
    assert_eq!(1, Stats::discovery_counter());
    assert_eq!(0, Stats::jwks_counter());
    // RELOADING getting keys first time
    let r = make_proteced_request(&mut app, JWT_RSA1_OK).await;
    assert_eq!(StatusCode::OK, r.status());
    assert_eq!(1, Stats::jwks_counter());
    thread::sleep(Duration::from_millis(21));
    // NO RELOADING kid OK
    let r = make_proteced_request(&mut app, JWT_RSA1_OK).await;
    assert_eq!(StatusCode::OK, r.status());
    assert_eq!(1, Stats::jwks_counter());
    // NO RELEOADING, unknown kid
    thread::sleep(Duration::from_millis(41));
    let r = make_proteced_request(&mut app, JWT_RSA2_OK).await;
    assert_eq!(StatusCode::UNAUTHORIZED, r.status());
    assert_eq!(1, Stats::jwks_counter());
}
