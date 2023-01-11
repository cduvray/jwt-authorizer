# jwt-authorizer

JWT authoriser Layer for Axum.

Example:

```rust
    use jwt_authorizer::{AuthError, JwtAuthorizer, JwtClaims};
    use axum::{routing::get, Router};
    use serde::Deserialize;

    // Authorized entity, struct deserializable from JWT claims
    #[derive(Debug, Deserialize, Clone)]
    struct User {
        sub: String,
    }

    // let's create an authorizer builder from a JWKS Endpoint
    let jwt_auth: JwtAuthorizer<User> = JwtAuthorizer::new()
                .from_jwks_url("http://localhost:3000/oidc/jwks");

    // adding the authorization layer
    let app = Router::new().route("/protected", get(protected))
            .layer(jwt_auth.layer().unwrap());         

    // proteced handler with user injection (mapping some jwt claims) 
    async fn protected(JwtClaims(user): JwtClaims<User>) -> Result<String, AuthError> {
        // Send the protected data to the user
        Ok(format!("Welcome: {}", user.sub))
    }

    # async {
    axum::Server::bind(&"0.0.0.0:3000".parse().unwrap())
        .serve(app.into_make_service()).await.expect("server failed");
    # };
```