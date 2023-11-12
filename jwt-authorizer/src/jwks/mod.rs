use std::{str::FromStr, sync::Arc};

use jsonwebtoken::{errors::ErrorKind, jwk::Jwk, Algorithm, DecodingKey, Header};

use crate::error::AuthError;

use self::key_store_manager::KeyStoreManager;

pub mod key_store_manager;

#[derive(Clone)]
pub enum KeySource {
    /// KeyDataSource managing a refreshable key sets
    KeyStoreSource(KeyStoreManager),
    /// Manages public key sets, initialized on startup
    MultiKeySource(KeySet),
    /// Manages one public key, initialized on startup
    SingleKeySource(Arc<KeyData>),
}

#[derive(Clone)]
pub struct KeyData {
    pub kid: Option<String>,
    pub alg: Vec<Algorithm>,
    pub key: DecodingKey,
}

impl KeyData {
    pub fn from_jwk(key: &Jwk) -> Result<KeyData, jsonwebtoken::errors::Error> {
        Ok(KeyData {
            kid: key.common.key_id.clone(),
            alg: vec![Algorithm::from_str(
                key.common
                    .key_algorithm
                    .ok_or(jsonwebtoken::errors::Error::from(ErrorKind::MissingAlgorithm))?
                    .to_string()
                    .as_str(),
            )?],
            key: DecodingKey::from_jwk(key)?,
        })
    }
}

#[derive(Clone, Default)]
pub struct KeySet(Vec<Arc<KeyData>>);

impl From<Vec<Arc<KeyData>>> for KeySet {
    fn from(value: Vec<Arc<KeyData>>) -> Self {
        KeySet(value)
    }
}

impl KeySet {
    /// Find the key in the set that matches the given key id, if any.
    pub fn find_kid(&self, kid: &str) -> Option<&Arc<KeyData>> {
        self.0.iter().find(|k| match &k.kid {
            Some(k) => k == kid,
            None => false,
        })
    }

    /// Find the key in the set that matches the given key id, if any.
    pub fn find_alg(&self, alg: &Algorithm) -> Option<&Arc<KeyData>> {
        self.0.iter().find(|k| k.alg.contains(alg))
    }

    /// Find first key.
    pub fn first(&self) -> Option<&Arc<KeyData>> {
        self.0.first()
    }

    pub(crate) fn get_key(&self, header: &Header) -> Result<&Arc<KeyData>, AuthError> {
        let key = if let Some(ref kid) = header.kid {
            self.find_kid(kid).ok_or_else(|| AuthError::InvalidKid(kid.to_owned()))?
        } else {
            self.find_alg(&header.alg).ok_or(AuthError::InvalidKeyAlg(header.alg))?
        };
        Ok(key)
    }
}

impl KeySource {
    pub async fn get_key(&self, header: Header) -> Result<Arc<KeyData>, AuthError> {
        match self {
            KeySource::KeyStoreSource(kstore) => kstore.get_key(&header).await,
            KeySource::MultiKeySource(keys) => keys.get_key(&header).cloned(),
            KeySource::SingleKeySource(key) => Ok(key.clone()),
        }
    }
}

#[cfg(test)]
mod tests {
    use jsonwebtoken::{errors::ErrorKind, jwk::Jwk};

    use super::KeyData;

    #[test]
    fn key_data_no_alg() {
        // NO ALG should result in ErrorKind::MissingAlgorithm
        let jwk_ko: Jwk = serde_json::from_str( r#"{
            "kty": "RSA",
            "n": "2pQeZdxa7q093K7bj5h6-leIpxfTnuAxzXdhjfGEJHxmt2ekHyCBWWWXCBiDn2RTcEBcy6gZqOW45Uy_tw-5e-Px1xFj1PykGEkRlOpYSAeWsNaAWvvpGB9m4zQ0PgZeMDDXE5IIBrY6YAzmGQxV-fcGGLhJnXl0-5_z7tKC7RvBoT3SGwlc_AmJqpFtTpEBn_fDnyqiZbpcjXYLExFpExm41xDitRKHWIwfc3dV8_vlNntlxCPGy_THkjdXJoHv2IJmlhvmr5_h03iGMLWDKSywxOol_4Wc1BT7Hb6byMxW40GKwSJJ4p7W8eI5mqggRHc8jlwSsTN9LZ2VOvO-XiVShZRVg7JeraGAfWwaIgIJ1D8C1h5Pi0iFpp2suxpHAXHfyLMJXuVotpXbDh4NDX-A4KRMgaxcfAcui_x6gybksq6gF90-9nfQfmVMVJctZ6M-FvRr-itd1Nef5WAtwUp1qyZygAXU3cH3rarscajmurOsP6dE1OHl3grY_eZhQxk33VBK9lavqNKPg6Q_PLiq1ojbYBj3bcYifJrsNeQwxldQP83aWt5rGtgZTehKVJwa40Uy_Grae1iRnsDtdSy5sTJIJ6EiShnWAdMoGejdiI8vpkjrdU8SWH8lv1KXI54DsbyAuke2cYz02zPWc6JEotQqI0HwhzU0KHyoY4s",
            "e": "AQAB",
            "kid": "rsa01",
            "use": "sig"
          }"#).unwrap();
        let ks = KeyData::from_jwk(&jwk_ko);
        assert_eq!(ks.err().unwrap().kind(), &ErrorKind::MissingAlgorithm);
    }
}
