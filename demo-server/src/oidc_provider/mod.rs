use axum::{routing::get, Json, Router};
use josekit::jwk::{
    alg::{ec::EcCurve, ec::EcKeyPair, ed::EdKeyPair, rsa::RsaKeyPair},
    Jwk,
};
use jsonwebtoken::{encode, Algorithm, EncodingKey, Header};
use jwt_authorizer::{NumericDate, OneOrArray, RegisteredClaims};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::{net::SocketAddr, thread, time::Duration};

const ISSUER_URI: &str = "http://localhost:3001";

/// OpenId Connect discovery (simplified for test purposes)
#[derive(Serialize, Clone)]
struct OidcDiscovery {
    issuer: String,
    jwks_uri: String,
}

/// discovery url handler
async fn discovery() -> Json<Value> {
    let d = OidcDiscovery {
        issuer: ISSUER_URI.to_owned(),
        jwks_uri: format!("{ISSUER_URI}/jwks"),
    };
    Json(json!(d))
}

#[derive(Debug, Eq, PartialEq, Clone, Deserialize, Serialize)]
struct JwkSet {
    keys: Vec<Jwk>,
}

/// jwk set endpoint handler
async fn jwks() -> Json<Value> {
    let mut kset = JwkSet { keys: Vec::<Jwk>::new() };

    let keypair = RsaKeyPair::from_pem(include_bytes!("../../../config/rsa-private1.pem")).unwrap();
    let mut pk = keypair.to_jwk_public_key();
    pk.set_key_id("rsa01");
    pk.set_algorithm("RS256");
    pk.set_key_use("sig");
    kset.keys.push(pk);

    let keypair = RsaKeyPair::from_pem(include_bytes!("../../../config/rsa-private2.pem")).unwrap();
    let mut pk = keypair.to_jwk_public_key();
    pk.set_key_id("rsa02");
    pk.set_algorithm("RS256");
    pk.set_key_use("sig");
    kset.keys.push(pk);

    let keypair = EcKeyPair::from_pem(include_bytes!("../../../config/ecdsa-private1.pem"), Some(EcCurve::P256)).unwrap();
    let mut pk = keypair.to_jwk_public_key();
    pk.set_key_id("ec01");
    pk.set_algorithm("ES256");
    pk.set_key_use("sig");
    kset.keys.push(pk);

    let keypair = EcKeyPair::from_pem(include_bytes!("../../../config/ecdsa-private2.pem"), Some(EcCurve::P256)).unwrap();
    let mut pk = keypair.to_jwk_public_key();
    pk.set_key_id("ec02");
    pk.set_algorithm("ES256");
    pk.set_key_use("sig");
    kset.keys.push(pk);

    let keypair = EdKeyPair::from_pem(include_bytes!("../../../config/ed25519-private1.pem")).unwrap();
    let mut pk = keypair.to_jwk_public_key();
    pk.set_key_id("ed01");
    pk.set_algorithm("EdDSA");
    pk.set_key_use("sig");
    kset.keys.push(pk);

    let keypair = EdKeyPair::from_pem(include_bytes!("../../../config/ed25519-private2.pem")).unwrap();
    let mut pk = keypair.to_jwk_public_key();
    pk.set_key_id("ed02");
    pk.set_algorithm("EdDSA");
    pk.set_key_use("sig");
    kset.keys.push(pk);

    Json(json!(kset))
}

/// build a minimal JWT header
fn build_header(alg: Algorithm, kid: &str) -> Header {
    Header {
        typ: Some("JWT".to_string()),
        alg,
        kid: Some(kid.to_owned()),
        cty: None,
        jku: None,
        jwk: None,
        x5u: None,
        x5c: None,
        x5t: None,
        x5t_s256: None,
    }
}

/// token claims
#[derive(Debug, Serialize, Deserialize)]
struct Claims {
    iss: &'static str,
    sub: &'static str,
    exp: usize,
    nbf: usize,
}

/// handler issuing test tokens (this is not a standard endpoint)
pub async fn tokens() -> Json<Value> {
    let claims = Claims {
        iss: ISSUER_URI,
        sub: "b@b.com",
        exp: 2000000000, // May 2033
        nbf: 1516239022, // Jan 2018
    };

    let claims_with_aud = RegisteredClaims {
        iss: Some(ISSUER_URI.to_owned()),
        sub: Some("b@b.com".to_owned()),
        aud: Some(OneOrArray::Array(vec!["aud1".to_owned(), "aud2".to_owned()])),
        exp: Some(NumericDate(2000000000)), // May 2033
        nbf: Some(NumericDate(1516239022)), // Jan 2018
        iat: None,
        jti: None,
    };

    let rsa1_key = EncodingKey::from_rsa_pem(include_bytes!("../../../config/rsa-private1.pem")).unwrap();
    let rsa2_key = EncodingKey::from_rsa_pem(include_bytes!("../../../config/rsa-private2.pem")).unwrap();
    let ec1_key = EncodingKey::from_ec_pem(include_bytes!("../../../config/ecdsa-private1.pem")).unwrap();
    let ec2_key = EncodingKey::from_ec_pem(include_bytes!("../../../config/ecdsa-private2.pem")).unwrap();
    let ed1_key = EncodingKey::from_ed_pem(include_bytes!("../../../config/ed25519-private1.pem")).unwrap();
    let ed2_key = EncodingKey::from_ed_pem(include_bytes!("../../../config/ed25519-private2.pem")).unwrap();

    let rsa1_token = encode(&build_header(Algorithm::RS256, "rsa01"), &claims, &rsa1_key).unwrap();
    let rsa1_token_aud = encode(&build_header(Algorithm::RS256, "rsa01"), &claims_with_aud, &rsa1_key).unwrap();
    let rsa2_token = encode(&build_header(Algorithm::RS256, "rsa02"), &claims, &rsa2_key).unwrap();
    let ec1_token_aud = encode(&build_header(Algorithm::ES256, "ec01"), &claims_with_aud, &ec1_key).unwrap();
    let ec1_token = encode(&build_header(Algorithm::ES256, "ec01"), &claims, &ec1_key).unwrap();
    let ec2_token = encode(&build_header(Algorithm::ES256, "ec02"), &claims, &ec2_key).unwrap();
    let ed1_token = encode(&build_header(Algorithm::EdDSA, "ed01"), &claims, &ed1_key).unwrap();
    let ed2_token = encode(&build_header(Algorithm::EdDSA, "ed02"), &claims, &ed2_key).unwrap();

    Json(json!({
        "rsa01": rsa1_token,
        "rsa01_aud": rsa1_token_aud,
        "rsa02": rsa2_token,
        "ec01": ec1_token,
        "ec01_aud": ec1_token_aud,
        "ec02": ec2_token,
        "ed01": ed1_token,
        "ed02": ed2_token,
    }))
}

/// exposes some oidc "like" endpoints for test purposes
pub fn run_server() -> &'static str {
    let app = Router::new()
        .route("/.well-known/openid-configuration", get(discovery))
        .route("/jwks", get(jwks))
        .route("/tokens", get(tokens));

    tokio::spawn(async move {
        let addr = SocketAddr::from(([127, 0, 0, 1], 3001));
        tracing::info!("oidc provider starting on: {}", addr);
        axum::Server::bind(&addr).serve(app.into_make_service()).await.unwrap();
    });

    thread::sleep(Duration::from_millis(200)); // waiting oidc to start

    ISSUER_URI
}
