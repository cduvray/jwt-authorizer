#[cfg(test)]
mod tests {
    use axum::{
        body::Body,
        http::{Request, StatusCode},
        response::Response,
        routing::get,
        Router,
    };
    use http::{header, HeaderValue};
    use jwt_authorizer::{JwtAuthorizer, JwtClaims};
    use serde::Deserialize;
    use tower::ServiceExt;

    const JWT_RSA_OK: &str = "Bearer eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiIsImtpZCI6ImtleS1yc2EifQ.eyJzdWIiOiJiQGIuY29tIiwiZXhwIjoyMDAwMDAwMDAwfQ.K9QFjvVquRF2-Wt1QRfipOGwiYsmRs7SAwqKskHemFb9BRRZutpfV4oEoHaXMLomTUe8rH0TMjpKcweYK_H1I8D4r-mAN216oUfxCQiFWDB8T2VBI8um-efUg67i2myDZJr5VXdZH8ywj7bn9LyNS4I_xT-J3XvsngeCpuxVSRiYu4FkcUkLrPzbu2sDyBXFqYO9FOorZ8sl0Ninc93fWT2uUrEG8jRyWCa4xpoqbKbm7CN7T2tOKF7mx_xdSPTeSM-U9mUiHsMOrXi1S05IM0hvNJrBduLS6sMTFWrVhis6zqnuxDOirwZS-aN0_SgMDnZTFPsCh8dkqFde1Pv1IYjZfr5OOHjQ9QWj6UDjam6M1eWVPK6QLlxv5bU_gnlAiHm9wJX38-REwmVhIJIBzKxsgJAu1gnRBxe36OM3rkgYxpB86YvfDyOoFlqx8erdxYv38AtvJibe4HB6KLndp_QMm5XXQsbfyEXWGe8hzDwozdhGeQsJXz7PcI3KPlv19PrUM8njElFpOiyfAEXwbtp1EZTzMZ4ZNF6LLFy1fpLcosgyp05o_2YMvngltSnN3v0IPncJx50StdYsoxPN9Ac_nH8VbNlHfmPHMklD1plof0pYf5SiL8yCQP9Uiw9NrN2PeQzbveMKF1T1UNbn2tefxoxr3k6sgWiMH_g_kkk";

    #[derive(Debug, Deserialize, Clone)]
    struct User {
        sub: String,
    }

    async fn app(jwt_auth: JwtAuthorizer<User>) -> Router {
        Router::new().route("/public", get(|| async { "hello" })).route(
            "/protected",
            get(|JwtClaims(user): JwtClaims<User>| async move { format!("hello: {}", user.sub) })
                .layer(jwt_auth.layer().await.unwrap()),
        )
    }

    async fn make_proteced_request(jwt_auth: JwtAuthorizer<User>, bearer: &str) -> Response {
        app(jwt_auth)
            .await
            .oneshot(
                Request::builder()
                    .uri("/protected")
                    .header("Authorization", bearer)
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap()
    }

    #[tokio::test]
    async fn protected_without_jwt() {
        let jwt_auth: JwtAuthorizer<User> = JwtAuthorizer::from_rsa_pem("../config/jwtRS256.key.pub");

        let response = app(jwt_auth)
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
        let response = make_proteced_request(JwtAuthorizer::from_rsa_pem("../config/jwtRS256.key.pub"), JWT_RSA_OK).await;

        assert_eq!(response.status(), StatusCode::OK);

        let body = hyper::body::to_bytes(response.into_body()).await.unwrap();
        assert_eq!(&body[..], b"hello: b@b.com");
    }

    #[tokio::test]
    async fn protected_with_bad_jwt() {
        let response = make_proteced_request(JwtAuthorizer::from_rsa_pem("../config/jwtRS256.key.pub"), "xxx.xxx.xxx").await;

        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
        // TODO: check error code (https://datatracker.ietf.org/doc/html/rfc6750#section-3.1)
    }

    #[tokio::test]
    async fn protected_with_claims_check() {
        let rsp_ok = make_proteced_request(
            JwtAuthorizer::from_rsa_pem("../config/jwtRS256.key.pub").check(|_| true),
            JWT_RSA_OK,
        )
        .await;

        assert_eq!(rsp_ok.status(), StatusCode::OK);

        let rsp_ko = make_proteced_request(
            JwtAuthorizer::from_rsa_pem("../config/jwtRS256.key.pub").check(|_| false),
            JWT_RSA_OK,
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
        let response = make_proteced_request(JwtAuthorizer::from_jwks_url("http://bad-url/xxx/yyy"), JWT_RSA_OK).await;

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
}
