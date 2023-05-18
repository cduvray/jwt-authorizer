# jwt-authorizer

JWT authoriser Layer for Axum and Tonic.

## Features

- JWT token verification (Bearer)
    - Algoritms: ECDSA, RSA, EdDSA, HMAC
- JWKS endpoint support
    - Configurable refresh
    - OpenId Connect Discovery
- Validation
    - exp, nbf, iss, aud
- Claims extraction
- Claims checker
- Tracing support (error logging)


## Usage Example

```rust
# use jwt_authorizer::{AuthError, JwtAuthorizer, JwtClaims, RegisteredClaims};
# use axum::{routing::get, Router};
# use serde::Deserialize;

# async {

    // let's create an authorizer builder from a JWKS Endpoint
    // (a serializable struct can be used to represent jwt claims, JwtAuthorizer<RegisteredClaims> is the default)
    let jwt_auth: JwtAuthorizer =
                    JwtAuthorizer::from_jwks_url("http://localhost:3000/oidc/jwks");

    // adding the authorization layer
    let app = Router::new().route("/protected", get(protected))
            .layer(jwt_auth.layer().await.unwrap());

    // proteced handler with user injection (mapping some jwt claims)
    async fn protected(JwtClaims(user): JwtClaims<RegisteredClaims>) -> Result<String, AuthError> {
        // Send the protected data to the user
        Ok(format!("Welcome: {:?}", user.sub))
    }

    axum::Server::bind(&"0.0.0.0:3000".parse().unwrap())
        .serve(app.into_make_service()).await.expect("server failed");
# };
```

## Validation

Validation configuration object.

If no validation configuration is provided default values will be applyed.

docs: [`jwt-authorizer::Validation`]

```rust
# use jwt_authorizer::{JwtAuthorizer, Validation};
# use serde_json::Value;

let validation = Validation::new()
                    .iss(&["https://issuer1", "https://issuer2"])
                    .aud(&["audience1"])
                    .nbf(true)
                    .leeway(20);

let jwt_auth: JwtAuthorizer<Value> = JwtAuthorizer::from_oidc("https://accounts.google.com")
                      .validation(validation);

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

- [`JwtAuthorizer::no_refresh()`] configures one and unique reload of jwks keys
- [`JwtAuthorizer::refresh(refresh_configuration)`] allows to define a finer configuration for jwks refreshing, for more details see the documentation of `Refresh` struct.

[`jwt-authorizer::Validation`]: https://docs.rs/jwt-authorizer/latest/jwt_authorizer/validation/struct.Validation.html
[`JwtAuthorizer::no_refresh()`]: https://docs.rs/jwt-authorizer/latest/jwt_authorizer/layer/struct.JwtAuthorizer.html#method.no_refresh
[`JwtAuthorizer::refresh(refresh_configuration)`]: https://docs.rs/jwt-authorizer/latest/jwt_authorizer/layer/struct.JwtAuthorizer.html#method.refresh
