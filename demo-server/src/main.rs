use axum::{routing::get, Router};
use jwt_authorizer::{error::InitError, AuthError, JwtAuthorizer, JwtClaims, Refresh, RefreshStrategy};
use serde::Deserialize;
use std::{fmt::Display, net::SocketAddr};
use tower_http::trace::TraceLayer;
use tracing::info;
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};

mod oidc_provider;

#[tokio::main]
async fn main() -> Result<(), InitError> {
    tracing_subscriber::registry()
        .with(tracing_subscriber::EnvFilter::new(
            std::env::var("RUST_LOG").unwrap_or_else(|_| "info,axum_poc=debug,tower_http=debug".into()),
        ))
        .with(tracing_subscriber::fmt::layer())
        .init();

    fn claim_checker(u: &User) -> bool {
        info!("checking claims: {} -> {}", u.sub, u.sub.contains('@'));

        u.sub.contains('@') // must be an email
    }

    // starting oidc provider (discovery is needed by from_oidc())
    oidc_provider::run_server();

    // First let's create an authorizer builder from a JWKS Endpoint
    // User is a struct deserializable from JWT claims representing the authorized user
    // let jwt_auth: JwtAuthorizer<User> = JwtAuthorizer::from_oidc("https://accounts.google.com/")
    let jwt_auth: JwtAuthorizer<User> = JwtAuthorizer::from_oidc("http://localhost:3001")
        // .no_refresh()
        .refresh(Refresh {
            strategy: RefreshStrategy::Interval,
            ..Default::default()
        })
        .check(claim_checker);

    // actual router demo
    let api = Router::new()
        .route("/protected", get(protected))
        // adding the authorizer layer
        .layer(jwt_auth.layer().await?);
    // .layer(jwt_auth.check_claims(|_: User| true));

    let app = Router::new()
        // actual protected apis
        .nest("/api", api)
        .layer(TraceLayer::new_for_http());

    let addr = SocketAddr::from(([127, 0, 0, 1], 3000));
    tracing::info!("listening on {}", addr);

    axum::Server::bind(&addr).serve(app.into_make_service()).await.unwrap();

    Ok(())
}

async fn protected(JwtClaims(user): JwtClaims<User>) -> Result<String, AuthError> {
    // Send the protected data to the user
    Ok(format!("Welcome: {}", user.sub))
}

#[derive(Debug, Deserialize, Clone)]
struct User {
    sub: String,
}

impl Display for User {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "User: {:?}", self.sub)
    }
}
