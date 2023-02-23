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
use http::{Request, StatusCode};
use hyper::Body;
use jwt_authorizer::{JwtAuthorizer, JwtClaims, Refresh, RefreshStrategy};
use lazy_static::lazy_static;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use tower::Service;
use tower::ServiceExt;

use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};

lazy_static! {
    static ref JWKS_RSA1: Value = json!({
        "keys": [{
            "kty": "RSA",
            "n": "2pQeZdxa7q093K7bj5h6-leIpxfTnuAxzXdhjfGEJHxmt2ekHyCBWWWXCBiDn2RTcEBcy6gZqOW45Uy_tw-5e-Px1xFj1PykGEkRlOpYSAeWsNaAWvvpGB9m4zQ0PgZeMDDXE5IIBrY6YAzmGQxV-fcGGLhJnXl0-5_z7tKC7RvBoT3SGwlc_AmJqpFtTpEBn_fDnyqiZbpcjXYLExFpExm41xDitRKHWIwfc3dV8_vlNntlxCPGy_THkjdXJoHv2IJmlhvmr5_h03iGMLWDKSywxOol_4Wc1BT7Hb6byMxW40GKwSJJ4p7W8eI5mqggRHc8jlwSsTN9LZ2VOvO-XiVShZRVg7JeraGAfWwaIgIJ1D8C1h5Pi0iFpp2suxpHAXHfyLMJXuVotpXbDh4NDX-A4KRMgaxcfAcui_x6gybksq6gF90-9nfQfmVMVJctZ6M-FvRr-itd1Nef5WAtwUp1qyZygAXU3cH3rarscajmurOsP6dE1OHl3grY_eZhQxk33VBK9lavqNKPg6Q_PLiq1ojbYBj3bcYifJrsNeQwxldQP83aWt5rGtgZTehKVJwa40Uy_Grae1iRnsDtdSy5sTJIJ6EiShnWAdMoGejdiI8vpkjrdU8SWH8lv1KXI54DsbyAuke2cYz02zPWc6JEotQqI0HwhzU0KHyoY4s",
            "e": "AQAB",
            "kid": "rsa01",
            "alg": "RS256",
            "use": "sig"
          }]
    });
    static ref JWKS_RSA2: Value = json!({
        "keys": [{
            "kty": "RSA",
            "n": "yRE6rHuNR0QbHO3H3Kt2pOKGVhQqGZXInOduQNxXzuKlvQTLUTv4l4sggh5_CYYi_cvI-SXVT9kPWSKXxJXBXd_4LkvcPuUakBoAkfh-eiFVMh2VrUyWyj3MFl0HTVF9KwRXLAcwkREiS3npThHRyIxuy0ZMeZfxVL5arMhw1SRELB8HoGfG_AtH89BIE9jDBHZ9dLelK9a184zAf8LwoPLxvJb3Il5nncqPcSfKDDodMFBIMc4lQzDKL5gvmiXLXB1AGLm8KBjfE8s3L5xqi-yUod-j8MtvIj812dkS4QMiRVN_by2h3ZY8LYVGrqZXZTcgn2ujn8uKjXLZVD5TdQ",
            "e": "AQAB",
            "kid": "rsa02",
            "alg": "RS256",
            "use": "sig"
        }]
    });
    static ref JWKS_EC1: Value = json!({
        "keys": [{
          "kty": "EC",
          "crv": "P-256",
          "x": "MZiwc5EVP_E3vkd2oKedr4lWVMN9vgdyBBpBIVFJjwY",
          "y": "1npLU75B6M0mb01zUAVoeYJSDOlQJmvjBdqLPjJvy3Y",
          "kid": "ec01",
          "alg": "ES256",
          "use": "sig"
        }]
    });
}

const JWT_RSA1_OK: &str = "Bearer eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiIsImtpZCI6InJzYTAxIn0.eyJpc3MiOiJodHRwOi8vbG9jYWxob3N0OjMwMDEiLCJzdWIiOiJiQGIuY29tIiwiZXhwIjoyMDAwMDAwMDAwLCJuYmYiOjE1MTYyMzkwMjJ9.pmm8Kdk-SvycXIGpWb1R0DuP5nlB7w4QQS7trhN_OjOpbk0A8F_lC4BdClz3rol2Pgo61lcFckJgjNBj34DQGeTGOtvxdiUXNgi1aKiXH4AyPzZeZx30PgFxa1fxhuZhBAj6xIZKBSBQvVyjeVQzAScINRCBX8zfCaXSU1ZCUkJl5vbD7zT-cYIFU76we9HcIYKRXwTiAyoNn3Lixa1H3_t5sbx3om2WlIB2x-sGpoDFDjorcuJT1yQx3grTRTBzHyRBRjZ3e8wrMbiacy-m3WoEFdkssQgYi_dSQH0hvxgacvGWayK0UqD7O5UL6EzTA2feXbgA_68o5gfvSnM8CUsPut5gZr-gwVbQKPbBdCQtl_wXIMot7UNKYEiFV38x5EmUr-ShzQcditW6fciguuY1Qav502UE1UMXvt5p8-kYxw2AaaVd6iTgQBzkBrtvywMYWzIwzGNA70RvUhI2rlgcn8GEU_51Tv_NMHjp6CjDbAxQVKa0PlcRE4pd6yk_IJSR4Nska_8BQZdPbsFn--z_XHEDoRZQ1C1M6m77xVndg3zX0sNQPXfWsttCbBmaHvMKTOp0cH9rlWB9r9nTo9fn8jcfqlak2O2IAzfzsOdVfUrES6T1UWkWobs9usGgqJuIkZHbDd4tmXyPRT4wrU7hxEyE9cuvuZPAi8GYt80";
const JWT_RSA2_OK: &str = "Bearer eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiIsImtpZCI6InJzYTAyIn0.eyJpc3MiOiJodHRwOi8vbG9jYWxob3N0OjMwMDEiLCJzdWIiOiJiQGIuY29tIiwiZXhwIjoyMDAwMDAwMDAwLCJuYmYiOjE1MTYyMzkwMjJ9.tWyA4ve2CY6GruBch_qIf8f1PgCEhqmrZ1J5XBuwO_v-P-PSLe3MWpkPAMdIDE5QE19ItUcGdJblhiyPb0tJJtrDHVYER7q8X4fOjQjY_NlFK6Bd1GtZS2DCA5EPxIX8l7Jpn8fPvbyamagLwnB_waQaYBteTGnOkLmz3F3sqC8KdO9lyu5v7BknC1f56ZOvr_DiInkTiAsTWqX4nS2KYRjcz4HcxcPO7O0CFXqcOTF_e3ntmq4rQV9LHCaEnuXj2WZtnX423CMkcG0uYzsnmWAMPB6IlDKejPnAJThMjjuJhze1gGbP1U8c53UbEhfHEZgJ2N634YEXMfsojZ5VzQ";
// const JWT_EC1_OK: &str = "Bearer eyJ0eXAiOiJKV1QiLCJhbGciOiJFUzI1NiIsImtpZCI6ImVjMDEifQ.eyJpc3MiOiJodHRwOi8vbG9jYWxob3N0OjMwMDEiLCJzdWIiOiJiQGIuY29tIiwiZXhwIjoyMDAwMDAwMDAwLCJuYmYiOjE1MTYyMzkwMjJ9.AsAX8XQdsQMI7NGNJOPE8LFFaKJ_nYXeKBwl2NZACbPhCiRj7FgxIw0UVcpmRVzK0BNbb9S4lFocaTLo9DsCeQ";
// const JWT_EC2_OK: &str = "eyJ0eXAiOiJKV1QiLCJhbGciOiJFUzI1NiIsImtpZCI6ImVjMDIifQ.eyJpc3MiOiJodHRwOi8vbG9jYWxob3N0OjMwMDEiLCJzdWIiOiJiQGIuY29tIiwiZXhwIjoyMDAwMDAwMDAwLCJuYmYiOjE1MTYyMzkwMjJ9.DJFNPyfuL5-ifcAxRCvneo7SdtDu0cfJyYmv2Gl4rmJOjKlzDx3GDamYa0cGLy8zcYYdpDMJ-s1WKzlGC_Hiyw";
// const JWT_ED1_OK: &str = "eyJ0eXAiOiJKV1QiLCJhbGciOiJFZERTQSIsImtpZCI6ImVkMDEifQ.eyJpc3MiOiJodHRwOi8vbG9jYWxob3N0OjMwMDEiLCJzdWIiOiJiQGIuY29tIiwiZXhwIjoyMDAwMDAwMDAwLCJuYmYiOjE1MTYyMzkwMjJ9.5bFOZqc-lBFy4gFifQ_CTx1A3R6Nry71gdi7KH2GGvTZQC_ZI1vNbqGnWQhpR6n_jUd9ICUc0pPI5iLCB6K1Bg";
// const JWT_ED2_OK: &str = "eyJ0eXAiOiJKV1QiLCJhbGciOiJFZERTQSIsImtpZCI6ImVkMDIifQ.eyJpc3MiOiJodHRwOi8vbG9jYWxob3N0OjMwMDEiLCJzdWIiOiJiQGIuY29tIiwiZXhwIjoyMDAwMDAwMDAwLCJuYmYiOjE1MTYyMzkwMjJ9.Yfe88E26UEJ8x13h8xv2XtBrQ7O5E5UtS9t6-hRbo_pMSxKui13X0uNleRPHaZFfzK4AO033m8gHYHxQDLkTCg";

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

    Json(JWKS_RSA1.clone())
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
        .layer(jwt_auth.layer().await.unwrap());

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
                .header("Authorization", bearer)
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
