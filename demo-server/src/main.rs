use axum::{routing::get, Router};
use jwt_authorizer::{
    error::InitError, AuthError, Authorizer, IntoLayer, JwtAuthorizer, JwtClaims, Refresh, RefreshStrategy,
};
use serde::Deserialize;
use std::net::SocketAddr;
use tower_http::trace::TraceLayer;
use tracing::info;
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};

mod oidc_provider;

/// Object representing claims
/// (a subset of deserialized claims)
#[derive(Debug, Deserialize, Clone)]
struct User {
    sub: String,
}

#[tokio::main]
async fn main() -> Result<(), InitError> {
    tracing_subscriber::registry()
        .with(tracing_subscriber::EnvFilter::new(
            std::env::var("RUST_LOG").unwrap_or_else(|_| "info,jwt_authorizer=debug,tower_http=debug".into()),
        ))
        .with(tracing_subscriber::fmt::layer())
        .init();

    // claims checker function
    fn claim_checker(u: &User) -> bool {
        info!("checking claims: {} -> {}", u.sub, u.sub.contains('@'));

        u.sub.contains('@') // must be an email
    }

    // starting oidc provider (discovery is needed by from_oidc())
    let issuer_uri = oidc_provider::run_server();

    // First let's create an authorizer builder from a Oidc Discovery
    // User is a struct deserializable from JWT claims representing the authorized user
    // let jwt_auth: JwtAuthorizer<User> = JwtAuthorizer::from_oidc("https://accounts.google.com/")
    let auth: Authorizer<User> = JwtAuthorizer::from_oidc(issuer_uri)
        // .no_refresh()
        .refresh(Refresh {
            strategy: RefreshStrategy::Interval,
            ..Default::default()
        })
        .check(claim_checker)
        .build()
        .await?;

    // actual router demo
    let api = Router::new()
        .route("/protected", get(protected))
        // adding the authorizer layer
        .layer(auth.into_layer());

    let app = Router::new()
        // public endpoint
        .route("/public", get(public_handler))
        // protected APIs
        .nest("/api", api)
        .layer(TraceLayer::new_for_http());

    let addr = SocketAddr::from(([127, 0, 0, 1], 3000));
    tracing::info!("listening on {}", addr);

    axum::Server::bind(&addr).serve(app.into_make_service()).await.unwrap();

    Ok(())
}

/// handler with injected claims object
async fn protected(JwtClaims(user): JwtClaims<User>) -> Result<String, AuthError> {
    // Send the protected data to the user
    Ok(format!("Welcome: {}", user.sub))
}

// public url handler
async fn public_handler() -> &'static str {
    "Public URL!"
}
