use std::io::Read;

use jsonwebtoken::{decode, decode_header, jwk::JwkSet, DecodingKey, TokenData, Validation};
use serde::de::DeserializeOwned;

use crate::{
    error::{AuthError, InitError},
    jwks::{key_store_manager::KeyStoreManager, KeySource},
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
}

fn read_data(path: &str) -> Result<Vec<u8>, InitError> {
    let mut data = Vec::<u8>::new();
    let mut f = std::fs::File::open(path)?;
    f.read_to_end(&mut data)?;
    Ok(data)
}

pub enum KeySourceType {
    RSA(String),
    EC(String),
    ED(String),
    Secret(&'static str),
    Jwks(String),
    JwksString(String), // TODO: expose JwksString in JwtAuthorizer or remove it
    Discovery(String),
}

impl<C> Authorizer<C>
where
    C: DeserializeOwned + Clone + Send + Sync,
{
    pub(crate) async fn build(
        key_source_type: &KeySourceType,
        claims_checker: Option<FnClaimsChecker<C>>,
        refresh: Option<Refresh>,
    ) -> Result<Authorizer<C>, InitError> {
        Ok(match key_source_type {
            KeySourceType::RSA(path) => {
                let key = DecodingKey::from_rsa_pem(&read_data(path.as_str())?)?;
                Authorizer {
                    key_source: KeySource::DecodingKeySource(key),
                    claims_checker,
                }
            }
            KeySourceType::EC(path) => {
                let key = DecodingKey::from_ec_der(&read_data(path.as_str())?);
                Authorizer {
                    key_source: KeySource::DecodingKeySource(key),
                    claims_checker,
                }
            }
            KeySourceType::ED(path) => {
                let key = DecodingKey::from_ed_der(&read_data(path.as_str())?);
                Authorizer {
                    key_source: KeySource::DecodingKeySource(key),
                    claims_checker,
                }
            }
            KeySourceType::Secret(secret) => {
                let key = DecodingKey::from_secret(secret.as_bytes());
                Authorizer {
                    key_source: KeySource::DecodingKeySource(key),
                    claims_checker,
                }
            }
            KeySourceType::JwksString(jwks_str) => {
                // TODO: expose it in JwtAuthorizer or remove
                let set: JwkSet = serde_json::from_str(jwks_str)?;
                // TODO: replace [0] by kid/alg search
                let k = DecodingKey::from_jwk(&set.keys[0])?;
                Authorizer {
                    key_source: KeySource::DecodingKeySource(k),
                    claims_checker,
                }
            }
            KeySourceType::Jwks(url) => {
                let key_store_manager = KeyStoreManager::new(url, refresh.unwrap_or_default());
                Authorizer {
                    key_source: KeySource::KeyStoreSource(key_store_manager),
                    claims_checker,
                }
            }
            KeySourceType::Discovery(issuer_url) => {
                let jwks_url = oidc::discover_jwks(issuer_url).await?;
                let key_store_manager = KeyStoreManager::new(&jwks_url, refresh.unwrap_or_default());
                Authorizer {
                    key_source: KeySource::KeyStoreSource(key_store_manager),
                    claims_checker,
                }
            }
        })
    }

    pub async fn check_auth(&self, token: &str) -> Result<TokenData<C>, AuthError> {
        let header = decode_header(token)?;
        let validation = Validation::new(header.alg);
        let decoding_key = self.key_source.get_key(header).await?;
        let token_data = decode::<C>(token, &decoding_key, &validation)?;

        if let Some(ref checker) = self.claims_checker {
            if !checker.check(&token_data.claims) {
                return Err(AuthError::InvalidClaims());
            }
        }

        Ok(token_data)
    }
}

#[cfg(test)]
mod tests {

    use jsonwebtoken::{Algorithm, Header};
    use serde_json::Value;

    use super::{Authorizer, KeySourceType};

    #[tokio::test]
    async fn from_secret() {
        let h = Header::new(Algorithm::HS256);
        let a = Authorizer::<Value>::build(&KeySourceType::Secret("xxxxxx"), None, None)
            .await
            .unwrap();
        let k = a.key_source.get_key(h);
        assert!(k.await.is_ok());
    }

    #[tokio::test]
    async fn from_jwks() {
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
        let a = Authorizer::<Value>::build(&KeySourceType::JwksString(jwks.to_owned()), None, None)
            .await
            .unwrap();
        let k = a.key_source.get_key(Header::new(Algorithm::RS256));
        assert!(k.await.is_ok());
    }

    #[tokio::test]
    async fn from_file() {
        let a = Authorizer::<Value>::build(&KeySourceType::RSA("../config/jwtRS256.key.pub".to_owned()), None, None)
            .await
            .unwrap();
        let k = a.key_source.get_key(Header::new(Algorithm::RS256));
        assert!(k.await.is_ok());

        let a = Authorizer::<Value>::build(&KeySourceType::EC("../config/ec256-public.pem".to_owned()), None, None)
            .await
            .unwrap();
        let k = a.key_source.get_key(Header::new(Algorithm::ES256));
        assert!(k.await.is_ok());

        let a = Authorizer::<Value>::build(&KeySourceType::ED("../config/ed25519-public.pem".to_owned()), None, None)
            .await
            .unwrap();
        let k = a.key_source.get_key(Header::new(Algorithm::EdDSA));
        assert!(k.await.is_ok());
    }

    #[tokio::test]
    async fn from_file_errors() {
        let a = Authorizer::<Value>::build(&KeySourceType::RSA("./config/does-not-exist.pem".to_owned()), None, None).await;
        println!("{:?}", a.as_ref().err());
        assert!(a.is_err());
    }
}
