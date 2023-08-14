use std::{io::Read, sync::Arc};

use headers::{authorization::Bearer, Authorization, HeaderMapExt};
use http::HeaderMap;
use jsonwebtoken::{decode, decode_header, jwk::JwkSet, Algorithm, DecodingKey, TokenData};
use reqwest::Url;
use serde::de::DeserializeOwned;

use crate::{
    error::{AuthError, InitError},
    jwks::{key_store_manager::KeyStoreManager, KeyData, KeySource},
    layer::{self, JwtSource},
    oidc, Refresh,
};

pub trait ClaimsChecker<C> {
    fn check(&self, claims: &C) -> bool;
}

#[derive(Clone)]
pub struct FnClaimsChecker<C>
where
    C: Clone,
{
    pub checker_fn: fn(&C) -> bool,
}

impl<C> ClaimsChecker<C> for FnClaimsChecker<C>
where
    C: Clone,
{
    fn check(&self, claims: &C) -> bool {
        (self.checker_fn)(claims)
    }
}

pub struct Authorizer<C>
where
    C: Clone,
{
    pub key_source: KeySource,
    pub claims_checker: Option<FnClaimsChecker<C>>,
    pub validation: crate::validation::Validation,
    pub jwt_source: JwtSource,
}

fn read_data(path: &str) -> Result<Vec<u8>, InitError> {
    let mut data = Vec::<u8>::new();
    let mut f = std::fs::File::open(path)?;
    f.read_to_end(&mut data)?;
    Ok(data)
}

pub enum KeySourceType {
    RSA(String),
    RSAString(String),
    EC(String),
    ECString(String),
    ED(String),
    EDString(String),
    Secret(String),
    Jwks(String),
    JwksString(String), // TODO: expose JwksString in JwtAuthorizer or remove it
    Discovery(String),
}

impl<C> Authorizer<C>
where
    C: DeserializeOwned + Clone + Send + Sync,
{
    pub(crate) async fn build(
        key_source_type: KeySourceType,
        claims_checker: Option<FnClaimsChecker<C>>,
        refresh: Option<Refresh>,
        validation: crate::validation::Validation,
        jwt_source: JwtSource,
    ) -> Result<Authorizer<C>, InitError> {
        Ok(match key_source_type {
            KeySourceType::RSA(path) => {
                let key = DecodingKey::from_rsa_pem(&read_data(path.as_str())?)?;
                Authorizer {
                    key_source: KeySource::SingleKeySource(Arc::new(KeyData {
                        kid: None,
                        alg: vec![Algorithm::RS256, Algorithm::RS384, Algorithm::RS512],
                        key,
                    })),
                    claims_checker,
                    validation,
                    jwt_source,
                }
            }
            KeySourceType::RSAString(text) => {
                let key = DecodingKey::from_rsa_pem(text.as_bytes())?;
                Authorizer {
                    key_source: KeySource::SingleKeySource(Arc::new(KeyData {
                        kid: None,
                        alg: vec![Algorithm::RS256, Algorithm::RS384, Algorithm::RS512],
                        key,
                    })),
                    claims_checker,
                    validation,
                    jwt_source,
                }
            }
            KeySourceType::EC(path) => {
                let key = DecodingKey::from_ec_pem(&read_data(path.as_str())?)?;
                Authorizer {
                    key_source: KeySource::SingleKeySource(Arc::new(KeyData {
                        kid: None,
                        alg: vec![Algorithm::ES256, Algorithm::ES384],
                        key,
                    })),
                    claims_checker,
                    validation,
                    jwt_source,
                }
            }
            KeySourceType::ECString(text) => {
                let key = DecodingKey::from_ec_pem(text.as_bytes())?;
                Authorizer {
                    key_source: KeySource::SingleKeySource(Arc::new(KeyData {
                        kid: None,
                        alg: vec![Algorithm::ES256, Algorithm::ES384],
                        key,
                    })),
                    claims_checker,
                    validation,
                    jwt_source,
                }
            }
            KeySourceType::ED(path) => {
                let key = DecodingKey::from_ed_pem(&read_data(path.as_str())?)?;
                Authorizer {
                    key_source: KeySource::SingleKeySource(Arc::new(KeyData {
                        kid: None,
                        alg: vec![Algorithm::EdDSA],
                        key,
                    })),
                    claims_checker,
                    validation,
                    jwt_source,
                }
            }
            KeySourceType::EDString(text) => {
                let key = DecodingKey::from_ed_pem(text.as_bytes())?;
                Authorizer {
                    key_source: KeySource::SingleKeySource(Arc::new(KeyData {
                        kid: None,
                        alg: vec![Algorithm::EdDSA],
                        key,
                    })),
                    claims_checker,
                    validation,
                    jwt_source,
                }
            }
            KeySourceType::Secret(secret) => {
                let key = DecodingKey::from_secret(secret.as_bytes());
                Authorizer {
                    key_source: KeySource::SingleKeySource(Arc::new(KeyData {
                        kid: None,
                        alg: vec![Algorithm::HS256, Algorithm::HS384, Algorithm::HS512],
                        key,
                    })),
                    claims_checker,
                    validation,
                    jwt_source,
                }
            }
            KeySourceType::JwksString(jwks_str) => {
                // TODO: expose it in JwtAuthorizer or remove
                let set: JwkSet = serde_json::from_str(jwks_str.as_str())?;
                // TODO: replace [0] by kid/alg search
                let k = KeyData::from_jwk(&set.keys[0]).map_err(InitError::KeyDecodingError)?;
                Authorizer {
                    key_source: KeySource::SingleKeySource(Arc::new(k)),
                    claims_checker,
                    validation,
                    jwt_source,
                }
            }
            KeySourceType::Jwks(url) => {
                let jwks_url = Url::parse(url.as_str()).map_err(|e| InitError::JwksUrlError(e.to_string()))?;
                let key_store_manager = KeyStoreManager::new(jwks_url, refresh.unwrap_or_default());
                Authorizer {
                    key_source: KeySource::KeyStoreSource(key_store_manager),
                    claims_checker,
                    validation,
                    jwt_source,
                }
            }
            KeySourceType::Discovery(issuer_url) => {
                let jwks_url = Url::parse(&oidc::discover_jwks(issuer_url.as_str()).await?)
                    .map_err(|e| InitError::JwksUrlError(e.to_string()))?;

                let key_store_manager = KeyStoreManager::new(jwks_url, refresh.unwrap_or_default());
                Authorizer {
                    key_source: KeySource::KeyStoreSource(key_store_manager),
                    claims_checker,
                    validation,
                    jwt_source,
                }
            }
        })
    }

    pub async fn check_auth(&self, token: &str) -> Result<TokenData<C>, AuthError> {
        let header = decode_header(token)?;
        // TODO: (optimisation) build & store jwt_validation in key data, to avoid rebuilding it for each check
        let val_key = self.key_source.get_key(header).await?;
        let jwt_validation = &self.validation.to_jwt_validation(val_key.alg.clone());
        let token_data = decode::<C>(token, &val_key.key, jwt_validation)?;

        if let Some(ref checker) = self.claims_checker {
            if !checker.check(&token_data.claims) {
                return Err(AuthError::InvalidClaims());
            }
        }

        Ok(token_data)
    }

    pub fn extract_token(&self, h: &HeaderMap) -> Option<String> {
        match &self.jwt_source {
            layer::JwtSource::AuthorizationHeader => {
                let bearer_o: Option<Authorization<Bearer>> = h.typed_get();
                bearer_o.map(|b| String::from(b.0.token()))
            }
            layer::JwtSource::Cookie(name) => h
                .typed_get::<headers::Cookie>()
                .and_then(|c| c.get(name.as_str()).map(String::from)),
        }
    }
}

#[cfg(test)]
mod tests {

    use jsonwebtoken::{Algorithm, Header};
    use serde_json::Value;

    use crate::{layer::JwtSource, validation::Validation};

    use super::{Authorizer, KeySourceType};

    #[tokio::test]
    async fn build_from_secret() {
        let h = Header::new(Algorithm::HS256);
        let a = Authorizer::<Value>::build(
            KeySourceType::Secret("xxxxxx".to_owned()),
            None,
            None,
            Validation::new(),
            JwtSource::AuthorizationHeader,
        )
        .await
        .unwrap();
        let k = a.key_source.get_key(h);
        assert!(k.await.is_ok());
    }

    #[tokio::test]
    async fn build_from_jwks_string() {
        let jwks = r#"
                {"keys": [{
                    "kid": "1",
                    "kty": "RSA",
                    "alg": "RS256",
                    "use": "sig",
                    "n": "2pQeZdxa7q093K7bj5h6-leIpxfTnuAxzXdhjfGEJHxmt2ekHyCBWWWXCBiDn2RTcEBcy6gZqOW45Uy_tw-5e-Px1xFj1PykGEkRlOpYSAeWsNaAWvvpGB9m4zQ0PgZeMDDXE5IIBrY6YAzmGQxV-fcGGLhJnXl0-5_z7tKC7RvBoT3SGwlc_AmJqpFtTpEBn_fDnyqiZbpcjXYLExFpExm41xDitRKHWIwfc3dV8_vlNntlxCPGy_THkjdXJoHv2IJmlhvmr5_h03iGMLWDKSywxOol_4Wc1BT7Hb6byMxW40GKwSJJ4p7W8eI5mqggRHc8jlwSsTN9LZ2VOvO-XiVShZRVg7JeraGAfWwaIgIJ1D8C1h5Pi0iFpp2suxpHAXHfyLMJXuVotpXbDh4NDX-A4KRMgaxcfAcui_x6gybksq6gF90-9nfQfmVMVJctZ6M-FvRr-itd1Nef5WAtwUp1qyZygAXU3cH3rarscajmurOsP6dE1OHl3grY_eZhQxk33VBK9lavqNKPg6Q_PLiq1ojbYBj3bcYifJrsNeQwxldQP83aWt5rGtgZTehKVJwa40Uy_Grae1iRnsDtdSy5sTJIJ6EiShnWAdMoGejdiI8vpkjrdU8SWH8lv1KXI54DsbyAuke2cYz02zPWc6JEotQqI0HwhzU0KHyoY4s",
                    "e": "AQAB"
                }]}
        "#;
        let a = Authorizer::<Value>::build(
            KeySourceType::JwksString(jwks.to_owned()),
            None,
            None,
            Validation::new(),
            JwtSource::AuthorizationHeader,
        )
        .await
        .unwrap();
        let k = a.key_source.get_key(Header::new(Algorithm::RS256));
        assert!(k.await.is_ok());
    }

    #[tokio::test]
    async fn build_from_file() {
        let a = Authorizer::<Value>::build(
            KeySourceType::RSA("../config/rsa-public1.pem".to_owned()),
            None,
            None,
            Validation::new(),
            JwtSource::AuthorizationHeader,
        )
        .await
        .unwrap();
        let k = a.key_source.get_key(Header::new(Algorithm::RS256));
        assert!(k.await.is_ok());

        let a = Authorizer::<Value>::build(
            KeySourceType::EC("../config/ecdsa-public1.pem".to_owned()),
            None,
            None,
            Validation::new(),
            JwtSource::AuthorizationHeader,
        )
        .await
        .unwrap();
        let k = a.key_source.get_key(Header::new(Algorithm::ES256));
        assert!(k.await.is_ok());

        let a = Authorizer::<Value>::build(
            KeySourceType::ED("../config/ed25519-public1.pem".to_owned()),
            None,
            None,
            Validation::new(),
            JwtSource::AuthorizationHeader,
        )
        .await
        .unwrap();
        let k = a.key_source.get_key(Header::new(Algorithm::EdDSA));
        assert!(k.await.is_ok());
    }

    #[tokio::test]
    async fn build_from_text() {
        let a = Authorizer::<Value>::build(
            KeySourceType::RSAString(include_str!("../../config/rsa-public1.pem").to_owned()),
            None,
            None,
            Validation::new(),
            JwtSource::AuthorizationHeader,
        )
        .await
        .unwrap();
        let k = a.key_source.get_key(Header::new(Algorithm::RS256));
        assert!(k.await.is_ok());

        let a = Authorizer::<Value>::build(
            KeySourceType::ECString(include_str!("../../config/ecdsa-public1.pem").to_owned()),
            None,
            None,
            Validation::new(),
            JwtSource::AuthorizationHeader,
        )
        .await
        .unwrap();
        let k = a.key_source.get_key(Header::new(Algorithm::ES256));
        assert!(k.await.is_ok());

        let a = Authorizer::<Value>::build(
            KeySourceType::EDString(include_str!("../../config/ed25519-public1.pem").to_owned()),
            None,
            None,
            Validation::new(),
            JwtSource::AuthorizationHeader,
        )
        .await
        .unwrap();
        let k = a.key_source.get_key(Header::new(Algorithm::EdDSA));
        assert!(k.await.is_ok());
    }

    #[tokio::test]
    async fn build_file_errors() {
        let a = Authorizer::<Value>::build(
            KeySourceType::RSA("./config/does-not-exist.pem".to_owned()),
            None,
            None,
            Validation::new(),
            JwtSource::AuthorizationHeader,
        )
        .await;
        println!("{:?}", a.as_ref().err());
        assert!(a.is_err());
    }

    #[tokio::test]
    async fn build_jwks_url_error() {
        let a = Authorizer::<Value>::build(
            KeySourceType::Jwks("://xxxx".to_owned()),
            None,
            None,
            Validation::default(),
            JwtSource::AuthorizationHeader,
        )
        .await;
        println!("{:?}", a.as_ref().err());
        assert!(a.is_err());
    }

    #[tokio::test]
    async fn build_discovery_url_error() {
        let a = Authorizer::<Value>::build(
            KeySourceType::Discovery("://xxxx".to_owned()),
            None,
            None,
            Validation::default(),
            JwtSource::AuthorizationHeader,
        )
        .await;
        println!("{:?}", a.as_ref().err());
        assert!(a.is_err());
    }
}
