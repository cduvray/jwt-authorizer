# jwt-authorizer

JWT authoriser Layer for Axum.

## Features

- JWT token verification (Bearer)
    - Algoritms: ECDSA, RSA, EdDSA, HS
- JWKS endpoint support
    - Configurable refresh
- Claims extraction
- Claims checker


## Usage Example

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
    let jwt_auth: JwtAuthorizer<User> = 
                    JwtAuthorizer::from_jwks_url("http://localhost:3000/oidc/jwks");

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

## ClaimsChecker

A check function (mapping deserialized claims to boolean) can be added to the authorizer. 

A check failure results in a 403 (WWW-Authenticate: Bearer error="insufficient_scope") error.

Example:

```rust

    use jwt_authorizer::{JwtAuthorizer};
    use serde::Deserialize;

    // Authorized entity, struct deserializable from JWT claims
    #[derive(Debug, Deserialize, Clone)]
    struct User {
        sub: String,
    }

    let authorizer = JwtAuthorizer::from_rsa_pem("../config/jwtRS256.key.pub")
                    .check(
                        |claims: &User| claims.sub.contains('@') // must be an email
                    );
```

## JWKS Refresh

By default the jwks keys are reloaded when a request token is signed with a key (`kid` jwt header) that is not present in the store (a minimal intervale between 2 reloads is 10s by default, can be configured). 

- `JwtAuthorizer::no_refresh()` configures one and unique reload of jwks keys
- `JwtAuthorizer::refresh(refresh_configuration)` allows to define a finer configuration for jwks refreshing, for more details see the documentation of `Refresh` struct.