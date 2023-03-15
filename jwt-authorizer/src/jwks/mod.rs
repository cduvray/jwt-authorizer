use std::sync::Arc;

use jsonwebtoken::{jwk::Jwk, Algorithm, DecodingKey, Header};

use crate::error::AuthError;

use self::key_store_manager::KeyStoreManager;

pub mod key_store_manager;

#[derive(Clone)]
pub enum KeySource {
    /// KeyDataSource managing a refreshable key sets
    KeyStoreSource(KeyStoreManager),
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
            alg: vec![key.common.algorithm.unwrap_or(Algorithm::RS256)], // TODO: is this good default?
            key: DecodingKey::from_jwk(key)?,
        })
    }
}

impl KeySource {
    pub async fn get_key(&self, header: Header) -> Result<Arc<KeyData>, AuthError> {
        match self {
            KeySource::KeyStoreSource(kstore) => kstore.get_key(&header).await,
            KeySource::SingleKeySource(key) => Ok(key.clone()),
        }
    }
}
