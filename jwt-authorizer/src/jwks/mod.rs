use jsonwebtoken::{DecodingKey, Header};

use crate::error::AuthError;

use self::key_store_manager::KeyStoreManager;

pub mod key_store_manager;

#[derive(Clone)]
pub enum KeySource {
    KeyStoreSource(KeyStoreManager),
    DecodingKeySource(DecodingKey),
}

impl KeySource {
    pub async fn get_key(&self, header: Header) -> Result<DecodingKey, AuthError> {
        match self {
            KeySource::KeyStoreSource(kstore) => kstore.get_key(&header).await,
            KeySource::DecodingKeySource(key) => {
                Ok(key.clone()) // TODO: clone -> &
            }
        }
    }
}
