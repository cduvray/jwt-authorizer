use reqwest::{Client, Url};
use serde::Deserialize;

use crate::error::InitError;

/// OpenId Connect discovery (simplified for test purposes)
#[derive(Deserialize, Clone)]
pub struct OidcDiscovery {
    pub jwks_uri: String,
}

fn discovery_url(issuer: &str) -> Result<Url, InitError> {
    let mut url = Url::parse(issuer).map_err(|e| InitError::DiscoveryError(e.to_string()))?;

    url.path_segments_mut()
        .map_err(|_| InitError::DiscoveryError(format!("Issuer URL error! ('{issuer}' cannot be a base)")))?
        .pop_if_empty()
        .extend(&[".well-known", "openid-configuration"]);

    Ok(url)
}

pub async fn discover_jwks(issuer: &str) -> Result<String, InitError> {
    Client::new()
        .get(discovery_url(issuer)?)
        .send()
        .await
        .map_err(|e| InitError::DiscoveryError(e.to_string()))?
        .json::<OidcDiscovery>()
        .await
        .map_err(|e| InitError::DiscoveryError(e.to_string()))
        .map(|d| d.jwks_uri)
}

#[test]
fn discovery() {
    assert_eq!(
        Url::parse("http://host.com:99/xx/.well-known/openid-configuration").unwrap(),
        discovery_url("http://host.com:99/xx").unwrap()
    );
    assert_eq!(
        Url::parse("http://host.com:99/xx/.well-known/openid-configuration").unwrap(),
        discovery_url("http://host.com:99/xx/").unwrap()
    );
    assert_eq!(
        Url::parse("http://host.com:99/xx/yy/.well-known/openid-configuration").unwrap(),
        discovery_url("http://host.com:99/xx/yy").unwrap()
    );
    assert_eq!(
        Url::parse("http://host.com:99/.well-known/openid-configuration").unwrap(),
        discovery_url("http://host.com:99").unwrap()
    );
    assert!(discovery_url("xxx").is_err());
}
