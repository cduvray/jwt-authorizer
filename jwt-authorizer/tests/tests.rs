mod common;

#[cfg(test)]
mod tests {
    use std::convert::Infallible;
    use std::sync::Arc;

    use axum::{
        body::Body,
        http::{Request, StatusCode},
        response::Response,
        routing::get,
        BoxError, Router,
    };
    use http::{header, HeaderValue};
    use jwt_authorizer::{
        authorizer::{Authorize, JwtAuthorizer},
        layer::{AsyncAuthorizationLayer, AsyncAuthorizationLayerBuilder, JwtSource},
        validation::Validation,
        JwtClaims,
    };
    use serde::Deserialize;
    use tower::{util::MapErrLayer, ServiceExt};

    use crate::common;

    #[derive(Debug, Deserialize, Clone)]
    struct User {
        sub: String,
    }

    async fn app<A>(layer: AsyncAuthorizationLayer<A>) -> Router
    where
        A: Authorize<Claims = User> + Clone + Send + Sync + 'static,
    {
        Router::new().route("/public", get(|| async { "hello" })).route(
            "/protected",
            get(|JwtClaims(user): JwtClaims<User>| async move { format!("hello: {}", user.sub) }).layer(
                tower_layer::Stack::new(
                    tower_layer::Stack::new(
                        tower::buffer::BufferLayer::new(1),
                        MapErrLayer::new(|e: BoxError| -> Infallible { panic!("{}", e) }),
                    ),
                    layer,
                ),
            ),
        )
    }

    async fn proteced_request_with_header<A>(
        auth: AsyncAuthorizationLayer<A>,
        header_name: &str,
        header_value: &str,
    ) -> Response
    where
        A: Authorize<Claims = User> + Clone + 'static,
    {
        app(auth)
            .await
            .oneshot(
                Request::builder()
                    .uri("/protected")
                    .header(header_name, header_value)
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap()
    }

    async fn make_proteced_request<A>(auth: AsyncAuthorizationLayer<A>, bearer: &str) -> Response
    where
        A: Authorize<Claims = User> + Clone + Send + Sync + 'static,
    {
        proteced_request_with_header(auth, "Authorization", &format!("Bearer {bearer}")).await
    }

    #[tokio::test]
    async fn protected_without_jwt() {
        let layer = JwtAuthorizer::from_rsa_pem("../config/rsa-public1.pem")
            .layer()
            .await
            .unwrap();

        let response = app(layer)
            .await
            .oneshot(Request::builder().uri("/protected").body(Body::empty()).unwrap())
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);

        assert!(
            response.headers().get(header::WWW_AUTHENTICATE).is_some(),
            "Must have a WWW-Authenticate header!"
        );
        assert_eq!(response.headers().get(header::WWW_AUTHENTICATE).unwrap(), &"Bearer");
        // TODO: realm="example"
    }

    #[tokio::test]
    async fn protected_with_jwt() {
        let response = make_proteced_request(
            JwtAuthorizer::from_ed_pem("../config/ed25519-public2.pem")
                .layer()
                .await
                .unwrap(),
            common::JWT_ED2_OK,
        )
        .await;
        assert_eq!(response.status(), StatusCode::OK);
        let body = hyper::body::to_bytes(response.into_body()).await.unwrap();
        assert_eq!(&body[..], b"hello: b@b.com");

        let response = make_proteced_request(
            JwtAuthorizer::from_ec_pem("../config/ecdsa-public2.pem")
                .layer()
                .await
                .unwrap(),
            common::JWT_EC2_OK,
        )
        .await;
        assert_eq!(response.status(), StatusCode::OK);
        let body = hyper::body::to_bytes(response.into_body()).await.unwrap();
        assert_eq!(&body[..], b"hello: b@b.com");

        let response = make_proteced_request(
            JwtAuthorizer::from_rsa_pem("../config/rsa-public2.pem")
                .layer()
                .await
                .unwrap(),
            common::JWT_RSA2_OK,
        )
        .await;
        assert_eq!(response.status(), StatusCode::OK);
        let body = hyper::body::to_bytes(response.into_body()).await.unwrap();
        assert_eq!(&body[..], b"hello: b@b.com");
    }

    #[tokio::test]
    async fn protected_with_bad_jwt() {
        let response = make_proteced_request(
            JwtAuthorizer::from_rsa_pem("../config/rsa-public1.pem")
                .layer()
                .await
                .unwrap(),
            "xxx.xxx.xxx",
        )
        .await;

        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
        // TODO: check error code (https://datatracker.ietf.org/doc/html/rfc6750#section-3.1)
    }

    #[tokio::test]
    async fn protected_with_claims_check() {
        let rsp_ok = make_proteced_request(
            JwtAuthorizer::from_rsa_pem("../config/rsa-public2.pem")
                .check(|_| true)
                .layer()
                .await
                .unwrap(),
            common::JWT_RSA2_OK,
        )
        .await;

        assert_eq!(rsp_ok.status(), StatusCode::OK);

        let rsp_ko = make_proteced_request(
            JwtAuthorizer::from_rsa_pem("../config/rsa-public2.pem")
                .check(|_| false)
                .layer()
                .await
                .unwrap(),
            common::JWT_RSA2_OK,
        )
        .await;

        assert_eq!(rsp_ko.status(), StatusCode::FORBIDDEN);

        let h = rsp_ko.headers().get(http::header::WWW_AUTHENTICATE);
        assert!(h.is_some(), "WWW-AUTHENTICATE header missing!");
        assert_eq!(
            h.unwrap(),
            HeaderValue::from_static("Bearer error=\"insufficient_scope\""),
            "Bad WWW-AUTHENTICATE header!"
        );
    }

    // Unreachable jwks endpoint, should build (endpoint can comme on line later ),
    // but should be 500 when checking.
    #[tokio::test]
    async fn protected_with_bad_jwks_url() {
        let response = make_proteced_request(
            JwtAuthorizer::from_jwks_url("http://bad-url/xxx/yyy").layer().await.unwrap(),
            common::JWT_RSA1_OK,
        )
        .await;

        assert_eq!(response.status(), StatusCode::INTERNAL_SERVER_ERROR);
    }

    #[tokio::test]
    async fn extract_from_public_500() {
        let app = Router::new().route(
            "/public",
            get(|JwtClaims(user): JwtClaims<User>| async move { format!("hello: {}", user.sub) }),
        );
        let response = app
            .oneshot(Request::builder().uri("/public").body(Body::empty()).unwrap())
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::INTERNAL_SERVER_ERROR);
    }

    // --------------------
    //      VALIDATION
    // ---------------------
    #[tokio::test]
    async fn validate_signature() {
        let response = make_proteced_request(
            JwtAuthorizer::from_rsa_pem("../config/rsa-public1.pem")
                .validation(Validation::new().disable_validation())
                .layer()
                .await
                .unwrap(),
            common::JWT_EC2_OK,
        )
        .await;
        assert_eq!(response.status(), StatusCode::OK);

        let response = make_proteced_request(
            JwtAuthorizer::from_rsa_pem("../config/rsa-public1.pem")
                .validation(Validation::new())
                .layer()
                .await
                .unwrap(),
            common::JWT_EC2_OK,
        )
        .await;
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn validate_iss() {
        let response = make_proteced_request(
            JwtAuthorizer::from_ec_pem("../config/ecdsa-public1.pem")
                .validation(Validation::new().iss(&["bad-iss"]))
                .layer()
                .await
                .unwrap(),
            common::JWT_EC1_OK,
        )
        .await;
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);

        let response = make_proteced_request(
            JwtAuthorizer::from_ec_pem("../config/ecdsa-public1.pem")
                .validation(Validation::new())
                .layer()
                .await
                .unwrap(),
            common::JWT_EC1_OK,
        )
        .await;
        assert_eq!(response.status(), StatusCode::OK);

        let response = make_proteced_request(
            JwtAuthorizer::from_ec_pem("../config/ecdsa-public1.pem")
                .validation(Validation::new().iss(&["http://localhost:3001"]))
                .layer()
                .await
                .unwrap(),
            common::JWT_EC1_OK,
        )
        .await;
        assert_eq!(response.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn validate_aud() {
        let response = make_proteced_request(
            JwtAuthorizer::from_ed_pem("../config/ed25519-public1.pem")
                .validation(Validation::new().aud(&["bad-aud"]))
                .layer()
                .await
                .unwrap(),
            common::JWT_ED1_OK,
        )
        .await;
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);

        let response = make_proteced_request(
            JwtAuthorizer::from_ed_pem("../config/ed25519-public1.pem")
                .validation(Validation::new())
                .layer()
                .await
                .unwrap(),
            common::JWT_ED1_OK,
        )
        .await;
        assert_eq!(response.status(), StatusCode::OK);

        let response = make_proteced_request(
            JwtAuthorizer::from_ed_pem("../config/ed25519-public1.pem")
                .validation(Validation::new().aud(&["aud1"]))
                .layer()
                .await
                .unwrap(),
            common::JWT_ED1_OK,
        )
        .await;
        assert_eq!(response.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn validate_exp() {
        // DEFAULT -> ENABLED
        let response = make_proteced_request(
            JwtAuthorizer::from_ec_pem("../config/ecdsa-public1.pem")
                .validation(Validation::new())
                .layer()
                .await
                .unwrap(),
            common::JWT_EC1_EXP_KO,
        )
        .await;
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);

        // DISABLED
        let response = make_proteced_request(
            JwtAuthorizer::from_ec_pem("../config/ecdsa-public1.pem")
                .validation(Validation::new().exp(false))
                .layer()
                .await
                .unwrap(),
            common::JWT_EC1_EXP_KO,
        )
        .await;
        assert_eq!(response.status(), StatusCode::OK);

        // ENABLED
        let response = make_proteced_request(
            JwtAuthorizer::from_ec_pem("../config/ecdsa-public1.pem")
                .validation(Validation::new().exp(true))
                .layer()
                .await
                .unwrap(),
            common::JWT_EC1_EXP_KO,
        )
        .await;
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
        let response = make_proteced_request(
            JwtAuthorizer::from_ec_pem("../config/ecdsa-public1.pem")
                .validation(Validation::new().exp(true))
                .layer()
                .await
                .unwrap(),
            common::JWT_EC1_OK,
        )
        .await;
        assert_eq!(response.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn validate_nbf() {
        // DEFAULT -> DISABLED
        let response = make_proteced_request(
            JwtAuthorizer::from_ec_pem("../config/ecdsa-public1.pem")
                .validation(Validation::new())
                .layer()
                .await
                .unwrap(),
            common::JWT_EC1_NBF_KO,
        )
        .await;
        assert_eq!(response.status(), StatusCode::OK);

        // DISABLED
        let response = make_proteced_request(
            JwtAuthorizer::from_ec_pem("../config/ecdsa-public1.pem")
                .validation(Validation::new().nbf(false))
                .layer()
                .await
                .unwrap(),
            common::JWT_EC1_NBF_KO,
        )
        .await;
        assert_eq!(response.status(), StatusCode::OK);

        // ENABLED
        let response = make_proteced_request(
            JwtAuthorizer::from_ec_pem("../config/ecdsa-public1.pem")
                .validation(Validation::new().nbf(true))
                .layer()
                .await
                .unwrap(),
            common::JWT_EC1_NBF_KO,
        )
        .await;
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);

        let response = make_proteced_request(
            JwtAuthorizer::from_ec_pem("../config/ecdsa-public1.pem")
                .validation(Validation::new().nbf(true))
                .layer()
                .await
                .unwrap(),
            common::JWT_EC1_OK,
        )
        .await;
        assert_eq!(response.status(), StatusCode::OK);
    }

    // --------------------
    //      jwt_source
    // ---------------------
    #[tokio::test]
    async fn jwt_source_cookie() {
        // OK
        let response = proteced_request_with_header(
            JwtAuthorizer::from_rsa_pem("../config/rsa-public1.pem")
                .layer_builder()
                .await
                .unwrap()
                .jwt_source(JwtSource::Cookie("ccc".to_owned()))
                .build(),
            header::COOKIE.as_str(),
            &format!("ccc={}", common::JWT_RSA1_OK),
        )
        .await;
        assert_eq!(response.status(), StatusCode::OK);

        // Cookie missing
        let response = proteced_request_with_header(
            JwtAuthorizer::from_rsa_pem("../config/rsa-public1.pem")
                .layer_builder()
                .await
                .unwrap()
                .jwt_source(JwtSource::Cookie("ccc".to_owned()))
                .build(),
            header::COOKIE.as_str(),
            &format!("bad_cookie={}", common::JWT_EC2_OK),
        )
        .await;
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
        assert_eq!(response.headers().get(header::WWW_AUTHENTICATE).unwrap(), &"Bearer");

        // Invalid Token
        let response = proteced_request_with_header(
            JwtAuthorizer::from_rsa_pem("../config/rsa-public1.pem")
                .layer_builder()
                .await
                .unwrap()
                .jwt_source(JwtSource::Cookie("ccc".to_owned()))
                .build(),
            header::COOKIE.as_str(),
            &format!("ccc={}", common::JWT_EC2_OK),
        )
        .await;
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
        assert_eq!(
            response.headers().get(header::WWW_AUTHENTICATE).unwrap(),
            &"Bearer error=\"invalid_token\""
        );
    }

    #[tokio::test]
    async fn multiple_key_sources() {
        let auths = Arc::new([
            JwtAuthorizer::from_ed_pem("../config/ed25519-public1.pem")
                .build()
                .await
                .unwrap(),
            JwtAuthorizer::from_ec_pem("../config/ecdsa-public2.pem")
                .build()
                .await
                .unwrap(),
        ]);

        let layer = AsyncAuthorizationLayerBuilder::new(auths).build();
        let response = make_proteced_request(layer.clone(), common::JWT_ED1_OK).await;
        assert_eq!(response.status(), StatusCode::OK);

        let response = make_proteced_request(layer.clone(), common::JWT_EC2_OK).await;
        assert_eq!(response.status(), StatusCode::OK);

        let response = make_proteced_request(layer.clone(), common::JWT_EC1_OK).await;
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    }
}
