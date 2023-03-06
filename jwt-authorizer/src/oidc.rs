use serde::Deserialize;

use crate::error::InitError;

/// OpenId Connect discovery (simplified for test purposes)
#[derive(Deserialize, Clone)]
pub struct OidcDiscovery {
    pub jwks_uri: String,
}

pub async fn discover_jwks(issuer: &str) -> Result<String, InitError> {
    let discovery_url = reqwest::Url::parse(issuer)
        .map_err(|e| InitError::DiscoveryError(e.to_string()))?
        .join(".well-known/openid-configuration")
        .map_err(|e| InitError::DiscoveryError(e.to_string()))?;
    reqwest::Client::new()
        .get(discovery_url)
        .send()
        .await
        .map_err(|e| InitError::DiscoveryError(e.to_string()))?
        .json::<OidcDiscovery>()
        .await
        .map_err(|e| InitError::DiscoveryError(e.to_string()))
        .map(|d| d.jwks_uri)
}
