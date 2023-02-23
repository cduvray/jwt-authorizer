use jsonwebtoken::{
    jwk::{Jwk, JwkSet},
    Algorithm, DecodingKey,
};
use reqwest::Url;
use std::{
    sync::Arc,
    time::{Duration, Instant},
};
use tokio::sync::Mutex;

use crate::error::AuthError;

/// Defines the strategy for the JWKS refresh.
#[derive(Clone, Copy)]
pub enum RefreshStrategy {
    /// refresh periodicaly
    Interval,

    /// refresh when kid not found in the store
    KeyNotFound,

    /// loading is triggered only once by the first use
    NoRefresh,
}

/// JWKS Refresh configuration
#[derive(Clone, Copy)]
pub struct Refresh {
    pub strategy: RefreshStrategy,
    /// After the refresh interval the store will/can be refreshed.
    ///
    /// - RefreshStrategy::KeyNotFound - refresh will be performed only if a kid is not found in the store
    ///      (if no kid is in the token header the alg is looked up)
    /// - RefreshStrategy::Interval - refresh will be performed each time the refresh interval has elapsed
    ///      (before checking a new token -> lazy behaviour)
    pub refresh_interval: Duration,
    /// don't refresh before (after an error or jwks is unawailable)
    /// (we let a little bit of time to the jwks endpoint to recover)
    pub retry_interval: Duration,
}

impl Default for Refresh {
    fn default() -> Self {
        Self {
            strategy: RefreshStrategy::KeyNotFound,
            refresh_interval: Duration::from_secs(600),
            retry_interval: Duration::from_secs(10),
        }
    }
}

#[derive(Clone)]
pub struct KeyStoreManager {
    key_url: Url,
    /// in case of fail loading (error or key not found), minimal interval
    refresh: Refresh,
    keystore: Arc<Mutex<KeyStore>>,
}

pub struct KeyStore {
    /// key set
    jwks: JwkSet,
    /// time of the last successfully loaded jwkset
    load_time: Option<Instant>,
    /// time of the last failed load
    fail_time: Option<Instant>,
}

impl KeyStoreManager {
    pub(crate) fn new(key_url: Url, refresh: Refresh) -> KeyStoreManager {
        KeyStoreManager {
            key_url,
            refresh,
            keystore: Arc::new(Mutex::new(KeyStore {
                jwks: JwkSet { keys: vec![] },
                load_time: None,
                fail_time: None,
            })),
        }
    }

    pub(crate) async fn get_key(&self, header: &jsonwebtoken::Header) -> Result<jsonwebtoken::DecodingKey, AuthError> {
        let kstore = self.keystore.clone();
        let mut ks_gard = kstore.lock().await;
        let key = match self.refresh.strategy {
            RefreshStrategy::Interval => {
                if ks_gard.can_refresh(self.refresh.refresh_interval, self.refresh.retry_interval) {
                    ks_gard.refresh(&self.key_url, &[]).await?;
                }
                if let Some(ref kid) = header.kid {
                    ks_gard.find_kid(kid).ok_or_else(|| AuthError::InvalidKid(kid.to_owned()))?
                } else {
                    ks_gard.find_alg(&header.alg).ok_or(AuthError::InvalidKeyAlg(header.alg))?
                }
            }
            RefreshStrategy::KeyNotFound => {
                if let Some(ref kid) = header.kid {
                    let jwk_opt = ks_gard.find_kid(kid);
                    if let Some(jwk) = jwk_opt {
                        jwk
                    } else if ks_gard.can_refresh(self.refresh.refresh_interval, self.refresh.retry_interval) {
                        ks_gard.refresh(&self.key_url, &[("kid", kid)]).await?;
                        ks_gard.find_kid(kid).ok_or_else(|| AuthError::InvalidKid(kid.to_owned()))?
                    } else {
                        return Err(AuthError::InvalidKid(kid.to_owned()));
                    }
                } else {
                    let jwk_opt = ks_gard.find_alg(&header.alg);
                    if let Some(jwk) = jwk_opt {
                        jwk
                    } else if ks_gard.can_refresh(self.refresh.refresh_interval, self.refresh.retry_interval) {
                        ks_gard
                            .refresh(
                                &self.key_url,
                                &[(
                                    "alg",
                                    &serde_json::to_string(&header.alg).map_err(|_| AuthError::InvalidKeyAlg(header.alg))?,
                                )],
                            )
                            .await?;
                        ks_gard
                            .find_alg(&header.alg)
                            .ok_or_else(|| AuthError::InvalidKeyAlg(header.alg))?
                    } else {
                        return Err(AuthError::InvalidKeyAlg(header.alg));
                    }
                }
            }
            RefreshStrategy::NoRefresh => {
                if ks_gard.load_time.is_none()
                    // if jwks endpoint is down for the loading, respect retry_interval
                    && ks_gard.can_refresh(self.refresh.refresh_interval, self.refresh.retry_interval)
                {
                    ks_gard.refresh(&self.key_url, &[]).await?;
                }
                if let Some(ref kid) = header.kid {
                    ks_gard.find_kid(kid).ok_or_else(|| AuthError::InvalidKid(kid.to_owned()))?
                } else {
                    ks_gard.find_alg(&header.alg).ok_or(AuthError::InvalidKeyAlg(header.alg))?
                }
            }
        };

        DecodingKey::from_jwk(key).map_err(|err| AuthError::InvalidKey(err.to_string()))
    }
}

impl KeyStore {
    fn can_refresh(&self, refresh_interval: Duration, minimal_retry: Duration) -> bool {
        if let Some(fail_tm) = self.fail_time {
            if let Some(load_tm) = self.load_time {
                fail_tm.elapsed() > minimal_retry && load_tm.elapsed() > refresh_interval
            } else {
                fail_tm.elapsed() > minimal_retry
            }
        } else if let Some(load_tm) = self.load_time {
            load_tm.elapsed() > refresh_interval
        } else {
            true
        }
    }

    async fn refresh(&mut self, key_url: &Url, qparam: &[(&str, &str)]) -> Result<(), AuthError> {
        reqwest::Client::new()
            .get(key_url.as_ref())
            .query(qparam)
            .send()
            .await
            .map_err(|e| {
                self.fail_time = Some(Instant::now());
                AuthError::JwksRefreshError(e)
            })?
            .json::<JwkSet>()
            .await
            .map(|jwks| {
                self.load_time = Some(Instant::now());
                self.jwks = jwks;
                self.fail_time = None;
                Ok(())
            })
            .map_err(|e| {
                self.fail_time = Some(Instant::now());
                AuthError::JwksRefreshError(e)
            })?
    }

    /// Find the key in the set that matches the given key id, if any.
    pub fn find_kid(&self, kid: &str) -> Option<&Jwk> {
        self.jwks.find(kid)
    }

    /// Find the key in the set that matches the given key id, if any.
    pub fn find_alg(&self, alg: &Algorithm) -> Option<&Jwk> {
        self.jwks.keys.iter().find(|jwk| {
            if let Some(ref a) = jwk.common.algorithm {
                alg == a
            } else {
                false
            }
        })
    }

    /// Find first key.
    pub fn find_first(&self) -> Option<&Jwk> {
        self.jwks.keys.get(0)
    }
}

#[cfg(test)]
mod tests {
    use std::time::{Duration, Instant};

    use jsonwebtoken::Algorithm;
    use jsonwebtoken::{jwk::Jwk, Header};
    use reqwest::Url;
    use wiremock::{
        matchers::{method, path},
        Mock, MockServer, ResponseTemplate,
    };

    use crate::jwks::key_store_manager::{KeyStore, KeyStoreManager};
    use crate::{Refresh, RefreshStrategy};

    const JWK_ED01: &str = r#"{
        "kty": "OKP",
        "use": "sig",
        "crv": "Ed25519",
        "x": "uWtSkE-I9aTMYTTvuTE1rtu0rNdxp3DU33cJ_ksL1Gk",
        "kid": "ed01",
        "alg": "EdDSA"
      }"#;

    const JWK_ED02: &str = r#"{
        "kty": "OKP",
        "use": "sig",
        "crv": "Ed25519",
        "x": "uWtSkE-I9aTMYTTvuTE1rtu0rNdxp3DU33cJ_ksL1Gk",
        "kid": "ed02",
        "alg": "EdDSA"
      }"#;

    const JWK_EC01: &str = r#"{
        "kty": "EC",
        "crv": "P-256",
        "x": "w7JAoU_gJbZJvV-zCOvU9yFJq0FNC_edCMRM78P8eQQ",
        "y": "wQg1EytcsEmGrM70Gb53oluoDbVhCZ3Uq3hHMslHVb4",
        "kid": "ec01",
        "alg": "ES256",
        "use": "sig"
      }"#;

    const JWK_EC02: &str = r#"{
        "kty": "EC",
        "crv": "P-256",
        "x": "w7JAoU_gJbZJvV-zCOvU9yFJq0FNC_edCMRM78P8eQQ",
        "y": "wQg1EytcsEmGrM70Gb53oluoDbVhCZ3Uq3hHMslHVb4",
        "kid": "ec02",
        "alg": "ES256",
        "use": "sig"
      }"#;

    #[test]
    fn keystore_can_refresh() {
        // FAIL, NO LOAD
        let ks = KeyStore {
            jwks: jsonwebtoken::jwk::JwkSet { keys: vec![] },
            fail_time: Instant::now().checked_sub(Duration::from_secs(5)),
            load_time: None,
        };
        assert!(ks.can_refresh(Duration::from_secs(0), Duration::from_secs(4)));
        assert!(!ks.can_refresh(Duration::from_secs(0), Duration::from_secs(6)));

        // NO FAIL, LOAD
        let ks = KeyStore {
            jwks: jsonwebtoken::jwk::JwkSet { keys: vec![] },
            fail_time: None,
            load_time: Instant::now().checked_sub(Duration::from_secs(5)),
        };
        assert!(ks.can_refresh(Duration::from_secs(4), Duration::from_secs(0)));
        assert!(!ks.can_refresh(Duration::from_secs(6), Duration::from_secs(0)));

        // FAIL, LOAD
        let ks = KeyStore {
            jwks: jsonwebtoken::jwk::JwkSet { keys: vec![] },
            fail_time: Instant::now().checked_sub(Duration::from_secs(5)),
            load_time: Instant::now().checked_sub(Duration::from_secs(10)),
        };
        assert!(ks.can_refresh(Duration::from_secs(6), Duration::from_secs(4)));
        assert!(!ks.can_refresh(Duration::from_secs(11), Duration::from_secs(4)));
        assert!(!ks.can_refresh(Duration::from_secs(6), Duration::from_secs(6)));
    }

    #[test]
    fn find_kid() {
        let jwk0: Jwk = serde_json::from_str(r#"{"kid":"1","kty":"RSA","alg":"RS256","n":"xxxx","e":"AQAB"}"#).unwrap();
        let jwk1: Jwk = serde_json::from_str(r#"{"kid":"2","kty":"RSA","alg":"RS256","n":"xxxx","e":"AQAB"}"#).unwrap();
        let ks = KeyStore {
            load_time: None,
            fail_time: None,
            jwks: jsonwebtoken::jwk::JwkSet { keys: vec![jwk0, jwk1] },
        };
        assert!(ks.find_kid("1").is_some());
        assert!(ks.find_kid("2").is_some());
        assert!(ks.find_kid("3").is_none());
    }

    #[test]
    fn find_alg() {
        let jwk0: Jwk = serde_json::from_str(r#"{"kty": "RSA", "alg": "RS256", "n": "xxx","e": "yyy"}"#).unwrap();
        let ks = KeyStore {
            load_time: None,
            fail_time: None,
            jwks: jsonwebtoken::jwk::JwkSet { keys: vec![jwk0] },
        };
        assert!(ks.find_alg(&Algorithm::RS256).is_some());
        assert!(ks.find_alg(&Algorithm::EdDSA).is_none());
    }

    async fn mock_jwks_response_once(mock_server: &MockServer, jwk: &str) {
        let jwk0: Jwk = serde_json::from_str(jwk).unwrap();
        let jwks = jsonwebtoken::jwk::JwkSet { keys: vec![jwk0] };
        Mock::given(method("GET"))
            .and(path("/"))
            .respond_with(ResponseTemplate::new(200).set_body_json(&jwks))
            .expect(1)
            .mount(mock_server)
            .await;
    }

    async fn mock_jwks_response_fail_once(mock_server: &MockServer) {
        Mock::given(method("GET"))
            .and(path("/"))
            .respond_with(ResponseTemplate::new(500))
            .expect(1)
            .mount(mock_server)
            .await;
    }

    fn build_header(kid: &str, alg: Algorithm) -> Header {
        let mut header = Header::new(alg);
        header.kid = Some(kid.to_owned());
        header
    }

    #[tokio::test]
    async fn strategy_interval() {
        let mock_server = MockServer::start().await;
        mock_jwks_response_once(&mock_server, JWK_ED01).await;

        let ksm = KeyStoreManager::new(
            Url::parse(&mock_server.uri()).unwrap(),
            Refresh {
                strategy: RefreshStrategy::Interval,
                refresh_interval: Duration::from_millis(10),
                retry_interval: Duration::from_millis(5),
            },
        );

        // 1st RELOAD
        let r = ksm.get_key(&Header::new(Algorithm::EdDSA)).await;
        assert!(r.is_ok());
        mock_server.verify().await;

        // NO RELOAD - inteval not elapsed
        assert!(ksm.get_key(&Header::new(Algorithm::EdDSA)).await.is_ok());

        // RELOAD - interval elapsed
        mock_server.reset().await;
        tokio::time::sleep(Duration::from_millis(11)).await;
        mock_jwks_response_once(&mock_server, JWK_ED01).await;
        assert!(ksm.get_key(&Header::new(Algorithm::EdDSA)).await.is_ok());
        mock_server.verify().await;

        // RELOAD - with fail
        mock_server.reset().await;
        tokio::time::sleep(Duration::from_millis(11)).await;
        mock_jwks_response_fail_once(&mock_server).await;
        assert!(ksm.get_key(&Header::new(Algorithm::EdDSA)).await.is_err());
        mock_server.verify().await;

        // NO RELOAD - retry not ellapsed
        assert!(ksm.get_key(&Header::new(Algorithm::EdDSA)).await.is_ok());

        // RELOAD - retry elapsed
        mock_server.reset().await;
        tokio::time::sleep(Duration::from_millis(6)).await;
        mock_jwks_response_once(&mock_server, JWK_ED01).await;
        assert!(ksm.get_key(&Header::new(Algorithm::EdDSA)).await.is_ok());
        mock_server.verify().await;
    }

    #[tokio::test]
    async fn strategy_key_not_found_with_refresh() {
        let mock_server = MockServer::start().await;
        mock_jwks_response_once(&mock_server, JWK_ED01).await;

        let ksm = KeyStoreManager::new(
            Url::parse(&mock_server.uri()).unwrap(),
            Refresh {
                strategy: RefreshStrategy::KeyNotFound,
                refresh_interval: Duration::from_millis(10),
                retry_interval: Duration::from_millis(5),
            },
        );

        // STEP 1: initial (lazy) reloading
        let r = ksm.get_key(&build_header("ed01", Algorithm::EdDSA)).await;
        assert!(r.is_ok());
        mock_server.verify().await;

        // STEP2: new kid, < refresh_interval -> reloading ksm
        mock_server.reset().await;
        mock_jwks_response_once(&mock_server, JWK_ED02).await;
        let h = build_header("ed02", Algorithm::EdDSA);
        assert!(ksm.get_key(&h).await.is_err());

        // ksm.refresh.refresh_interval = Duration::from_millis(10);
        tokio::time::sleep(Duration::from_millis(11)).await;
        assert!(ksm.get_key(&h).await.is_ok());

        mock_server.verify().await;

        // STEP3: new algorithm -> try to reload
        mock_server.reset().await;
        mock_jwks_response_once(&mock_server, JWK_EC01).await;
        let h = Header::new(Algorithm::ES256);
        assert!(ksm.get_key(&h).await.is_err());

        tokio::time::sleep(Duration::from_millis(11)).await;
        assert!(ksm.get_key(&h).await.is_ok());

        mock_server.verify().await;

        // STEP4: new key, refresh elapsed, FAIL
        mock_server.reset().await;
        tokio::time::sleep(Duration::from_millis(11)).await;
        mock_jwks_response_fail_once(&mock_server).await;
        let h = build_header("ec02", Algorithm::EdDSA);
        assert!(ksm.get_key(&h).await.is_err());
        mock_server.verify().await;

        // STEP5: retry elapsed -> reload
        mock_server.reset().await;
        tokio::time::sleep(Duration::from_millis(6)).await;
        mock_jwks_response_once(&mock_server, JWK_EC02).await;
        let h = build_header("ec02", Algorithm::EdDSA);
        assert!(ksm.get_key(&h).await.is_ok());
        mock_server.verify().await;
    }

    #[tokio::test]
    async fn strategy_no_refresh() {
        let mock_server = MockServer::start().await;
        mock_jwks_response_once(&mock_server, JWK_ED01).await;

        let ksm = KeyStoreManager::new(
            Url::parse(&mock_server.uri()).unwrap(),
            Refresh {
                strategy: RefreshStrategy::NoRefresh,
                ..Default::default()
            },
        );

        // STEP 1: initial (lazy) reloading
        let r = ksm.get_key(&build_header("ed01", Algorithm::EdDSA)).await;
        assert!(r.is_ok());
        mock_server.verify().await;

        // STEP2: new kid -> reloading ksm
        let h = build_header("ed02", Algorithm::EdDSA);
        assert!(ksm.get_key(&h).await.is_err());

        mock_server.verify().await;
    }
}
