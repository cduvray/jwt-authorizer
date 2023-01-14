#[cfg(test)]
mod tests {
    use crate::{JwtClaims, JwtAuthorizer};
    use axum::{
        body::Body,
        http::{Request, StatusCode},
        routing::get, Router,
    };
    use serde::Deserialize;
    use tower::ServiceExt;

    const JWT_RSA_OK: &str = "Bearer eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiIsImtpZCI6ImtleS1yc2EifQ.eyJzdWIiOiJiQGIuY29tIiwiZXhwIjoyMDAwMDAwMDAwfQ.K9QFjvVquRF2-Wt1QRfipOGwiYsmRs7SAwqKskHemFb9BRRZutpfV4oEoHaXMLomTUe8rH0TMjpKcweYK_H1I8D4r-mAN216oUfxCQiFWDB8T2VBI8um-efUg67i2myDZJr5VXdZH8ywj7bn9LyNS4I_xT-J3XvsngeCpuxVSRiYu4FkcUkLrPzbu2sDyBXFqYO9FOorZ8sl0Ninc93fWT2uUrEG8jRyWCa4xpoqbKbm7CN7T2tOKF7mx_xdSPTeSM-U9mUiHsMOrXi1S05IM0hvNJrBduLS6sMTFWrVhis6zqnuxDOirwZS-aN0_SgMDnZTFPsCh8dkqFde1Pv1IYjZfr5OOHjQ9QWj6UDjam6M1eWVPK6QLlxv5bU_gnlAiHm9wJX38-REwmVhIJIBzKxsgJAu1gnRBxe36OM3rkgYxpB86YvfDyOoFlqx8erdxYv38AtvJibe4HB6KLndp_QMm5XXQsbfyEXWGe8hzDwozdhGeQsJXz7PcI3KPlv19PrUM8njElFpOiyfAEXwbtp1EZTzMZ4ZNF6LLFy1fpLcosgyp05o_2YMvngltSnN3v0IPncJx50StdYsoxPN9Ac_nH8VbNlHfmPHMklD1plof0pYf5SiL8yCQP9Uiw9NrN2PeQzbveMKF1T1UNbn2tefxoxr3k6sgWiMH_g_kkk";

    #[derive(Debug, Deserialize, Clone)]
    struct User {
        sub: String,
    }

    fn app() -> Router {

        let jwt_auth: JwtAuthorizer<User> = JwtAuthorizer::new()
                .from_rsa_pem("../config/jwtRS256.key.pub");

        Router::new()
            .route("/public", get(|| async { "hello" }))
            .route(
                    "/protected",
                    get(|JwtClaims(user): JwtClaims<User>| async move {
                        format!("hello: {}", user.sub)
                    })
                    .layer(jwt_auth.layer().unwrap()),
            )
    }

    #[tokio::test]
    async fn protected_without_jwt() {

        let response = app()
            .oneshot(Request::builder().uri("/protected").body(Body::empty()).unwrap())
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::FORBIDDEN);
        // TODO: check error code (https://datatracker.ietf.org/doc/html/rfc6750#section-3.1)
    }

    #[tokio::test]
    async fn protected_with_jwt() {

        let response = app()
            .oneshot(
                Request::builder().uri("/protected").header("Authorization", JWT_RSA_OK).body(Body::empty()).unwrap()
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);

        let body = hyper::body::to_bytes(response.into_body()).await.unwrap();
        assert_eq!(&body[..], b"hello: b@b.com");
    }

    #[tokio::test]
    async fn protected_with_bad_jwt() {

        let response = app()
            .oneshot(
                Request::builder().uri("/protected").header("Authorization", "xxx.xxx.xxx").body(Body::empty()).unwrap()
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::FORBIDDEN);
        // TODO: check error code (https://datatracker.ietf.org/doc/html/rfc6750#section-3.1)
    }

}