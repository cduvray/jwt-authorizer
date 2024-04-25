mod common;

#[cfg(test)]
mod tests {
    use std::{convert::Infallible, sync::Arc};

    use axum::{
        body::Body,
        http::{Request, StatusCode},
        response::Response,
        routing::get,
        BoxError, Router,
    };
    use http::{header, HeaderValue};
    use jsonwebtoken::Algorithm;
    use jwt_authorizer::{
        authorizer::{Authorizer, TokenExtractorFn},
        layer::{AuthorizationLayer, JwtSource},
        validation::Validation,
        IntoLayer, JwtAuthorizer, JwtClaims,
    };
    use serde::Deserialize;
    use tower::{util::MapErrLayer, ServiceExt};

    use crate::common;
    use http_body_util::BodyExt;

    #[derive(Debug, Deserialize, Clone)]
    struct User {
        sub: String,
    }

    async fn app(layer: AuthorizationLayer<User>) -> Router {
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

    async fn proteced_request_with_header(jwt_auth: JwtAuthorizer<User>, header_name: &str, header_value: &str) -> Response {
        proteced_request_with_header_and_layer(jwt_auth.build().await.unwrap().into_layer(), header_name, header_value).await
    }

    async fn proteced_request_with_header_and_layer(
        layer: AuthorizationLayer<User>,
        header_name: &str,
        header_value: &str,
    ) -> Response {
        app(layer)
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

    async fn make_proteced_request(jwt_auth: JwtAuthorizer<User>, bearer: &str) -> Response {
        proteced_request_with_header(jwt_auth, "Authorization", &format!("Bearer {bearer}")).await
    }

    #[tokio::test]
    async fn protected_without_jwt() {
        let auth: Authorizer<User> = JwtAuthorizer::from_rsa_pem("../config/rsa-public1.pem")
            .build()
            .await
            .unwrap();

        let response = app(auth.into_layer())
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
        // ED PEM
        let response = make_proteced_request(
            JwtAuthorizer::from_ed_pem("../config/ed25519-public2.pem").validation(Validation::new().aud(&["aud1"])),
            common::JWT_ED2_OK,
        )
        .await;
        assert_eq!(response.status(), StatusCode::OK);

        let body = response.into_body().collect().await.unwrap().to_bytes();

        assert_eq!(&body[..], b"hello: b@b.com");

        // ECDSA PEM
        let response = make_proteced_request(
            JwtAuthorizer::from_ec_pem("../config/ecdsa-public2.pem").validation(Validation::new().aud(&["aud1"])),
            common::JWT_EC2_OK,
        )
        .await;
        assert_eq!(response.status(), StatusCode::OK);
        let body = response.into_body().collect().await.unwrap().to_bytes();
        assert_eq!(&body[..], b"hello: b@b.com");

        // RSA PEM
        let response =
            make_proteced_request(JwtAuthorizer::from_rsa_pem("../config/rsa-public2.pem"), common::JWT_RSA2_OK).await;
        assert_eq!(response.status(), StatusCode::OK);
        let body = response.into_body().collect().await.unwrap().to_bytes();
        assert_eq!(&body[..], b"hello: b@b.com");

        // JWKS
        let response = make_proteced_request(
            JwtAuthorizer::from_jwks("../config/public1.jwks").validation(Validation::new().aud(&["aud1"])),
            common::JWT_RSA1_OK,
        )
        .await;
        assert_eq!(response.status(), StatusCode::OK);
        let body = response.into_body().collect().await.unwrap().to_bytes();
        assert_eq!(&body[..], b"hello: b@b.com");

        let response = make_proteced_request(
            JwtAuthorizer::from_jwks("../config/public1.jwks").validation(Validation::new().aud(&["aud1"])),
            common::JWT_EC1_OK,
        )
        .await;
        assert_eq!(response.status(), StatusCode::OK);
        let body = response.into_body().collect().await.unwrap().to_bytes();
        assert_eq!(&body[..], b"hello: b@b.com");

        let response = make_proteced_request(
            JwtAuthorizer::from_jwks("../config/public1.jwks").validation(Validation::new().aud(&["aud1"])),
            common::JWT_ED1_OK,
        )
        .await;
        assert_eq!(response.status(), StatusCode::OK);
        let body = response.into_body().collect().await.unwrap().to_bytes();
        assert_eq!(&body[..], b"hello: b@b.com");

        // JWKS TEXT
        let response = make_proteced_request(
            JwtAuthorizer::from_jwks_text(include_str!("../../config/public1.jwks"))
                .validation(Validation::new().aud(&["aud1"])),
            common::JWT_ED1_OK,
        )
        .await;
        assert_eq!(response.status(), StatusCode::OK);
        let body = response.into_body().collect().await.unwrap().to_bytes();
        assert_eq!(&body[..], b"hello: b@b.com");
    }

    #[tokio::test]
    async fn protected_with_bad_jwt() {
        let response = make_proteced_request(JwtAuthorizer::from_rsa_pem("../config/rsa-public1.pem"), "xxx.xxx.xxx").await;

        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
        // TODO: check error code (https://datatracker.ietf.org/doc/html/rfc6750#section-3.1)
    }

    #[tokio::test]
    async fn protected_with_claims_check() {
        let b = true; // to test closures
        let rsp_ok = make_proteced_request(
            JwtAuthorizer::from_rsa_pem("../config/rsa-public2.pem").check(move |_| b),
            common::JWT_RSA2_OK,
        )
        .await;

        assert_eq!(rsp_ok.status(), StatusCode::OK);

        let rsp_ko = make_proteced_request(
            JwtAuthorizer::from_rsa_pem("../config/rsa-public2.pem").check(|_| false),
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
        let response =
            make_proteced_request(JwtAuthorizer::from_jwks_url("http://bad-url/xxx/yyy"), common::JWT_RSA1_OK).await;

        assert_eq!(response.status(), StatusCode::INTERNAL_SERVER_ERROR);
    }

    #[tokio::test]
    async fn extract_from_public_401() {
        let app = Router::new().route(
            "/public",
            get(|JwtClaims(user): JwtClaims<User>| async move { format!("hello: {}", user.sub) }),
        );
        let response = app
            .oneshot(Request::builder().uri("/public").body(Body::empty()).unwrap())
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn extract_from_public_optional() {
        let app = Router::new().route(
            "/public",
            get(|user: Option<JwtClaims<User>>| async move { format!("option: {}", user.is_none()) }),
        );
        let response = app
            .oneshot(Request::builder().uri("/public").body(Body::empty()).unwrap())
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);
        let body = response.into_body().collect().await.unwrap().to_bytes();
        assert_eq!(&body[..], b"option: true");
    }

    // --------------------
    //      VALIDATION
    // ---------------------
    #[tokio::test]
    async fn validate_signature() {
        let response = make_proteced_request(
            JwtAuthorizer::from_rsa_pem("../config/rsa-public1.pem")
                .validation(Validation::new().aud(&["aud1"]).disable_validation()),
            common::JWT_EC2_OK,
        )
        .await;
        assert_eq!(response.status(), StatusCode::OK);

        let response = make_proteced_request(
            JwtAuthorizer::from_rsa_pem("../config/rsa-public1.pem").validation(Validation::new()),
            common::JWT_EC2_OK,
        )
        .await;
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn validate_iss() {
        let response = make_proteced_request(
            JwtAuthorizer::from_ec_pem("../config/ecdsa-public1.pem").validation(Validation::new().iss(&["bad-iss"])),
            common::JWT_EC1_OK,
        )
        .await;
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);

        let response = make_proteced_request(
            JwtAuthorizer::from_ec_pem("../config/ecdsa-public1.pem").validation(Validation::new().aud(&["aud1"])),
            common::JWT_EC1_OK,
        )
        .await;
        assert_eq!(response.status(), StatusCode::OK);

        let response = make_proteced_request(
            JwtAuthorizer::from_ec_pem("../config/ecdsa-public1.pem")
                .validation(Validation::new().iss(&["http://localhost:3001"]).aud(&["aud1"])),
            common::JWT_EC1_OK,
        )
        .await;
        assert_eq!(response.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn validate_aud() {
        let response = make_proteced_request(
            JwtAuthorizer::from_rsa_pem("../config/rsa-public1.pem").validation(Validation::new().aud(&["bad-aud"])),
            common::JWT_RSA1_AUD1_OK,
        )
        .await;
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);

        let response = make_proteced_request(
            JwtAuthorizer::from_ed_pem("../config/ed25519-public1.pem").validation(Validation::new().aud(&["aud1"])),
            common::JWT_ED1_OK,
        )
        .await;
        assert_eq!(response.status(), StatusCode::OK);

        let response = make_proteced_request(
            JwtAuthorizer::from_ec_pem("../config/ecdsa-public1.pem").validation(Validation::new().aud(&["aud1"])),
            common::JWT_EC1_AUD1_OK,
        )
        .await;
        assert_eq!(response.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn validate_exp() {
        // DEFAULT -> ENABLED
        let response = make_proteced_request(
            JwtAuthorizer::from_ec_pem("../config/ecdsa-public1.pem").validation(Validation::new()),
            common::JWT_EC1_EXP_KO,
        )
        .await;
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);

        // DISABLED
        let response = make_proteced_request(
            JwtAuthorizer::from_ec_pem("../config/ecdsa-public1.pem").validation(Validation::new().exp(false)),
            common::JWT_EC1_EXP_KO,
        )
        .await;
        assert_eq!(response.status(), StatusCode::OK);

        // ENABLED
        let response = make_proteced_request(
            JwtAuthorizer::from_ec_pem("../config/ecdsa-public1.pem").validation(Validation::new().exp(true)),
            common::JWT_EC1_EXP_KO,
        )
        .await;
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
        let response = make_proteced_request(
            JwtAuthorizer::from_ec_pem("../config/ecdsa-public1.pem").validation(Validation::new().exp(true).aud(&["aud1"])),
            common::JWT_EC1_OK,
        )
        .await;
        assert_eq!(response.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn validate_nbf() {
        // DEFAULT -> DISABLED
        let response = make_proteced_request(
            JwtAuthorizer::from_ec_pem("../config/ecdsa-public1.pem").validation(Validation::new()),
            common::JWT_EC1_NBF_KO,
        )
        .await;
        assert_eq!(response.status(), StatusCode::OK);

        // DISABLED
        let response = make_proteced_request(
            JwtAuthorizer::from_ec_pem("../config/ecdsa-public1.pem").validation(Validation::new().nbf(false)),
            common::JWT_EC1_NBF_KO,
        )
        .await;
        assert_eq!(response.status(), StatusCode::OK);

        // ENABLED
        let response = make_proteced_request(
            JwtAuthorizer::from_ec_pem("../config/ecdsa-public1.pem").validation(Validation::new().nbf(true)),
            common::JWT_EC1_NBF_KO,
        )
        .await;
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);

        let response = make_proteced_request(
            JwtAuthorizer::from_ec_pem("../config/ecdsa-public1.pem").validation(Validation::new().nbf(true).aud(&["aud1"])),
            common::JWT_EC1_OK,
        )
        .await;
        assert_eq!(response.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn validate_algs() {
        // OK
        let response = make_proteced_request(
            JwtAuthorizer::from_rsa_pem("../config/rsa-public1.pem")
                .validation(Validation::new().algs(vec![Algorithm::RS256, Algorithm::RS384])),
            common::JWT_RSA1_OK,
        )
        .await;
        assert_eq!(response.status(), StatusCode::OK);

        let response = make_proteced_request(
            JwtAuthorizer::from_ec_pem("../config/ec384-public1.pem")
                .validation(Validation::new().algs(vec![Algorithm::ES256, Algorithm::ES384])),
            common::JWT_EC1_ES384_OK,
        )
        .await;
        assert_eq!(response.status(), StatusCode::OK);

        // NOK - Invalid Alg
        let response = make_proteced_request(
            JwtAuthorizer::from_rsa_pem("../config/rsa-public1.pem")
                .validation(Validation::new().algs(vec![Algorithm::RS512])),
            common::JWT_RSA1_OK,
        )
        .await;
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    }

    // --------------------
    //      jwt_source
    // ---------------------
    #[tokio::test]
    async fn jwt_source_cookie() {
        // OK
        let response = proteced_request_with_header(
            JwtAuthorizer::from_rsa_pem("../config/rsa-public1.pem")
                .validation(Validation::new().aud(&["aud1"]))
                .jwt_source(JwtSource::Cookie("ccc".to_owned())),
            header::COOKIE.as_str(),
            &format!("ccc={}", common::JWT_RSA1_OK),
        )
        .await;
        assert_eq!(response.status(), StatusCode::OK);

        // Cookie missing
        let response = proteced_request_with_header(
            JwtAuthorizer::from_rsa_pem("../config/rsa-public1.pem").jwt_source(JwtSource::Cookie("ccc".to_owned())),
            header::COOKIE.as_str(),
            &format!("bad_cookie={}", common::JWT_EC2_OK),
        )
        .await;
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
        assert_eq!(response.headers().get(header::WWW_AUTHENTICATE).unwrap(), &"Bearer");

        // Invalid Token
        let response = proteced_request_with_header(
            JwtAuthorizer::from_rsa_pem("../config/rsa-public1.pem").jwt_source(JwtSource::Cookie("ccc".to_owned())),
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

    // --------------------------
    //      Multiple Authorizers
    // --------------------------
    #[tokio::test]
    async fn multiple_authorizers() {
        // 1) Vec
        let auths: Vec<Authorizer<User>> = vec![
            JwtAuthorizer::from_ec_pem("../config/ecdsa-public1.pem")
                .validation(Validation::new().aud(&["aud1"]))
                .build()
                .await
                .unwrap(),
            JwtAuthorizer::from_rsa_pem("../config/rsa-public1.pem")
                .validation(Validation::new().aud(&["aud1"]))
                .jwt_source(JwtSource::Cookie("ccc".to_owned()))
                .build()
                .await
                .unwrap(),
        ];

        // OK
        let response = proteced_request_with_header_and_layer(
            auths.into_layer(),
            header::COOKIE.as_str(),
            &format!("ccc={}", common::JWT_RSA1_OK),
        )
        .await;
        assert_eq!(response.status(), StatusCode::OK);

        // 2) Slice
        let auths: [Authorizer<User>; 2] = [
            JwtAuthorizer::from_ec_pem("../config/ecdsa-public1.pem")
                .build()
                .await
                .unwrap(),
            JwtAuthorizer::from_rsa_pem("../config/rsa-public1.pem")
                .jwt_source(JwtSource::Cookie("ccc".to_owned()))
                .build()
                .await
                .unwrap(),
        ];

        // Cookie missing
        let response = proteced_request_with_header_and_layer(
            auths.into_layer(),
            header::COOKIE.as_str(),
            &format!("bad_cookie={}", common::JWT_EC2_OK),
        )
        .await;
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
        assert_eq!(response.headers().get(header::WWW_AUTHENTICATE).unwrap(), &"Bearer");

        // 3) Arc
        let auth1 = Arc::new(
            JwtAuthorizer::from_ec_pem("../config/ecdsa-public1.pem")
                .validation(Validation::new().aud(&["aud1"]))
                .build()
                .await
                .unwrap(),
        );
        let auth2 = Arc::new(
            JwtAuthorizer::from_rsa_pem("../config/rsa-public1.pem")
                .validation(Validation::new().aud(&["aud1"]))
                .jwt_source(JwtSource::Cookie("ccc".to_owned()))
                .build()
                .await
                .unwrap(),
        );

        // Slice/OK
        let response = proteced_request_with_header_and_layer(
            [auth1.clone(), auth2.clone()].into_layer(),
            header::COOKIE.as_str(),
            &format!("ccc={}", common::JWT_RSA1_OK),
        )
        .await;
        assert_eq!(response.status(), StatusCode::OK);

        // Vec/OK
        let response = proteced_request_with_header_and_layer(
            vec![auth1, auth2.clone()].into_layer(),
            header::COOKIE.as_str(),
            &format!("ccc={}", common::JWT_RSA1_OK),
        )
        .await;
        assert_eq!(response.status(), StatusCode::OK);

        // Arc/OK
        let response = proteced_request_with_header_and_layer(
            auth2.into_layer(),
            header::COOKIE.as_str(),
            &format!("ccc={}", common::JWT_RSA1_OK),
        )
        .await;
        assert_eq!(response.status(), StatusCode::OK);
    }

    // --------------------
    //      token_extractor
    // ---------------------
    #[tokio::test]
    async fn jwt_custom_token_extractor() {
        // Initialize custom token extractor
        let token_extractor: TokenExtractorFn = Arc::new(Box::new(|headers| {
            let Some(custom_header) = headers.get("X-Custom-Authorization") else {
                return None;
            };

            let Ok(custom_header_str) = custom_header.to_str() else {
                return None;
            };

            let token = custom_header_str.split("Bearer ");

            match token.last() {
                Some(t) => Some(t.to_string()),
                None => None,
            }
        }));

        // OK
        let response = proteced_request_with_header(
            JwtAuthorizer::from_rsa_pem("../config/rsa-public1.pem")
                .validation(Validation::new().aud(&["aud1"]))
                .token_extractor(token_extractor.clone()),
            "X-Custom-Authorization",
            &format!("Bearer {}", common::JWT_RSA1_OK),
        )
        .await;
        assert_eq!(response.status(), StatusCode::OK);

        // Header missing
        let response = proteced_request_with_header(
            JwtAuthorizer::from_rsa_pem("../config/rsa-public1.pem").token_extractor(token_extractor.clone()),
            "X-Custom-Authorization",
            "",
        )
        .await;
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
        assert_eq!(
            response.headers().get(header::WWW_AUTHENTICATE).unwrap(),
            &"Bearer error=\"invalid_token\""
        );

        // Invalid Token
        let response = proteced_request_with_header(
            JwtAuthorizer::from_rsa_pem("../config/rsa-public1.pem").token_extractor(token_extractor.clone()),
            "X-Custom-Authorization",
            &format!("Bearer {}", common::JWT_EC2_OK),
        )
        .await;
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
        assert_eq!(
            response.headers().get(header::WWW_AUTHENTICATE).unwrap(),
            &"Bearer error=\"invalid_token\""
        );
    }
}
