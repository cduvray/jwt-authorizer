use axum::{
    routing::{get, post},
    Router,
};
use jwt_authorizer::{AuthError, JwtAuthorizer, JwtClaims};
use serde::Deserialize;
use std::{fmt::Display, net::SocketAddr};
use tower_http::trace::TraceLayer;
use tracing::info;
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};

mod oidc_provider;

#[tokio::main]
async fn main() {
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

    // First let's create an authorizer builder from a JWKS Endpoint
    // User is a struct deserializable from JWT claims representing the authorized user
    let jwt_auth: JwtAuthorizer<User> = JwtAuthorizer::new()
        .from_jwks_url("http://localhost:3000/oidc/jwks")
        .with_check(claim_checker);

    let oidc = Router::new()
        .route("/authorize", post(oidc_provider::authorize))
        .route("/jwks", get(oidc_provider::jwks))
        .route("/tokens", get(oidc_provider::tokens));

    let api = Router::new()
        .route("/protected", get(protected))
        .layer(jwt_auth.layer().unwrap());
    // .layer(jwt_auth.check_claims(|_: User| true));

    let app = Router::new()
        .nest("/oidc/", oidc)
        .nest("/api", api)
        .layer(TraceLayer::new_for_http());

    let addr = SocketAddr::from(([127, 0, 0, 1], 3000));
    tracing::info!("listening on {}", addr);

    axum::Server::bind(&addr).serve(app.into_make_service()).await.unwrap();
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
