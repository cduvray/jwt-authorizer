use std::{str::FromStr, sync::Arc};

use jsonwebtoken::{jwk::Jwk, Algorithm, DecodingKey, Header};

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
            alg: vec![Algorithm::from_str(key.common.key_algorithm.unwrap().to_string().as_str())?],
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
