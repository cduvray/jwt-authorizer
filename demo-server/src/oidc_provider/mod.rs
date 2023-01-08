use axum::{
    async_trait,
    extract::{FromRequestParts, TypedHeader},
    headers::{authorization::Bearer, Authorization},
    http::{request::Parts, StatusCode},
    response::{IntoResponse, Response},
    Json,
};
use josekit::jwk::{
    alg::{ec::EcCurve, ec::EcKeyPair, ed::EdKeyPair, rsa::RsaKeyPair},
    Jwk,
};
use jsonwebtoken::{decode, encode, Algorithm, DecodingKey, EncodingKey, Header, Validation};
use once_cell::sync::Lazy;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::fmt::Display;

pub static KEYS: Lazy<Keys> = Lazy::new(|| {
    //let secret = std::env::var("JWT_SECRET").expect("JWT_SECRET must be set");
    // Keys::new("xxxxx".as_bytes())
    Keys::load_rsa()
});

pub struct Keys {
    pub alg: Algorithm,
    pub encoding: EncodingKey,
    pub decoding: DecodingKey,
}

impl Keys {
    fn new(secret: &[u8]) -> Self {
        Self {
            alg: Algorithm::HS256,
            encoding: EncodingKey::from_secret(secret),
            decoding: DecodingKey::from_secret(secret),
        }
    }
    fn load_rsa() -> Self {
        Self {
            alg: Algorithm::RS256,
            encoding: EncodingKey::from_rsa_pem(include_bytes!("../../../config/jwtRS256.key")).unwrap(),
            decoding: DecodingKey::from_rsa_pem(include_bytes!("../../../config/jwtRS256.key.pub")).unwrap(),
        }
    }
}

#[derive(Debug, Eq, PartialEq, Clone, Deserialize, Serialize)]
struct JwkSet {
    keys: Vec<Jwk>,
}

pub async fn jwks() -> Json<Value> {
    // let mut ksmap = serde_json::Map::new();

    let mut kset = JwkSet {
        keys: Vec::<Jwk>::new(),
    };

    let keypair = RsaKeyPair::from_pem(include_bytes!("../../../config/jwtRS256.key")).unwrap();
    let mut pk = keypair.to_jwk_public_key();
    pk.set_key_id("key-rsa");
    pk.set_algorithm("RS256");
    pk.set_key_use("sig");
    kset.keys.push(pk);

    let keypair = RsaKeyPair::from_pem(include_bytes!("../../../config/private_rsa_key_pkcs8.pem")).unwrap();
    let mut pk = keypair.to_jwk_public_key();
    pk.set_key_id("rsa01");
    pk.set_algorithm("RS256");
    pk.set_key_use("sig");
    kset.keys.push(pk);

    let keypair =
        EcKeyPair::from_pem(include_bytes!("../../../config/ec256-private.pem"), Some(EcCurve::P256)).unwrap();
    let mut pk = keypair.to_jwk_public_key();
    pk.set_key_id("key-ec");
    pk.set_algorithm("ES256");
    pk.set_key_use("sig");
    kset.keys.push(pk);

    let keypair = EcKeyPair::from_pem(
        include_bytes!("../../../config/private_ecdsa_key.pem"),
        Some(EcCurve::P256),
    )
    .unwrap();
    let mut pk = keypair.to_jwk_public_key();
    pk.set_key_id("ec01");
    pk.set_algorithm("ES256");
    pk.set_key_use("sig");
    kset.keys.push(pk);

    let keypair = EdKeyPair::from_pem(include_bytes!("../../../config/ed25519-private.pem")).unwrap();
    let mut pk = keypair.to_jwk_public_key();
    pk.set_key_id("key-ed");
    pk.set_algorithm("EdDSA");
    pk.set_key_use("sig");
    kset.keys.push(pk);

    let keypair = EdKeyPair::from_pem(include_bytes!("../../../config/private_ed25519_key.pem")).unwrap();
    let mut pk = keypair.to_jwk_public_key();
    pk.set_key_id("ed01");
    pk.set_algorithm("EdDSA");
    pk.set_key_use("sig");
    kset.keys.push(pk);

    Json(json!(kset))
}

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

pub async fn tokens() -> Json<Value> {
    let claims = Claims {
        sub: "b@b.com".to_owned(),
        exp: 2000000000, // May 2033
    };

    let rsa_key = EncodingKey::from_rsa_pem(include_bytes!("../../../config/jwtRS256.key")).unwrap();
    let ec_key = EncodingKey::from_ec_pem(include_bytes!("../../../config/ec256-private.pem")).unwrap();
    let ed_key = EncodingKey::from_ed_pem(include_bytes!("../../../config/ed25519-private.pem")).unwrap();

    let rsa_token = encode(&build_header(Algorithm::RS256, "key-rsa"), &claims, &rsa_key).unwrap();
    let ec_token = encode(&build_header(Algorithm::ES256, "key-ec"), &claims, &ec_key).unwrap();
    let ed_token = encode(&build_header(Algorithm::EdDSA, "key-ed"), &claims, &ed_key).unwrap();

    Json(json!({
        "rsa": rsa_token,
        "ec": ec_token,
        "ed": ed_token
    }))
}

pub async fn authorize(Json(payload): Json<AuthPayload>) -> Result<Json<AuthBody>, AuthError> {
    tracing::info!("authorizing ...");
    if payload.client_id.is_empty() || payload.client_secret.is_empty() {
        return Err(AuthError::MissingCredentials);
    }
    // Here you can check the user credentials from a database
    if payload.client_id != "foo" || payload.client_secret != "bar" {
        return Err(AuthError::WrongCredentials);
    }
    let claims = Claims {
        sub: "b@b.com".to_owned(),
        // Mandatory expiry time as UTC timestamp
        exp: 2000000000, // May 2033
    };
    // Create the authorization token
    let token = encode(&Header::new(KEYS.alg), &claims, &KEYS.encoding).map_err(|_| AuthError::TokenCreation)?;

    // Send the authorized token
    Ok(Json(AuthBody::new(token)))
}

#[derive(Debug, Serialize, Deserialize)]
struct Claims {
    sub: String,
    exp: usize,
}

#[derive(Debug, Serialize)]
pub struct AuthBody {
    access_token: String,
    token_type: String,
}

#[derive(Debug, Deserialize)]
pub struct AuthPayload {
    client_id: String,
    client_secret: String,
}

#[derive(Debug)]
pub enum AuthError {
    WrongCredentials,
    MissingCredentials,
    TokenCreation,
    InvalidToken,
}

impl Display for Claims {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "sub: {}", self.sub)
    }
}

impl AuthBody {
    fn new(access_token: String) -> Self {
        Self {
            access_token,
            token_type: "Bearer".to_string(),
        }
    }
}

impl IntoResponse for AuthError {
    fn into_response(self) -> Response {
        let (status, error_message) = match self {
            AuthError::WrongCredentials => (StatusCode::UNAUTHORIZED, "Wrong credentials"),
            AuthError::MissingCredentials => (StatusCode::BAD_REQUEST, "Missing credentials"),
            AuthError::TokenCreation => (StatusCode::INTERNAL_SERVER_ERROR, "Token creation error"),
            AuthError::InvalidToken => (StatusCode::BAD_REQUEST, "Invalid token"),
        };
        let body = Json(json!({
            "error": error_message,
        }));
        (status, body).into_response()
    }
}

#[async_trait]
impl<S> FromRequestParts<S> for Claims
where
    S: Send + Sync,
{
    type Rejection = AuthError;

    async fn from_request_parts(parts: &mut Parts, state: &S) -> Result<Self, Self::Rejection> {
        // Extract the token from the authorization header
        let TypedHeader(Authorization(bearer)) = TypedHeader::<Authorization<Bearer>>::from_request_parts(parts, state)
            .await
            .map_err(|_| AuthError::InvalidToken)?;
        let token_data = decode::<Claims>(bearer.token(), &KEYS.decoding, &Validation::default())
            .map_err(|_| AuthError::InvalidToken)?;

        Ok(token_data.claims)
    }
}
