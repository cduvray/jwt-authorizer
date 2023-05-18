use chrono::{DateTime, TimeZone, Utc};
use std::fmt;

use serde::{de, Deserialize, Deserializer};

/// Seconds since the epoch
#[derive(Deserialize, Clone, PartialEq, Eq, Debug)]
pub struct NumericDate(i64);

impl From<NumericDate> for DateTime<Utc> {
    fn from(t: NumericDate) -> Self {
        Utc.timestamp_opt(t.0, 0).unwrap()
    }
}

#[derive(PartialEq, Debug, Clone)]
pub struct StringList(Vec<String>);

/// Claims mentioned in the JWT specifications.
///
/// https://www.rfc-editor.org/rfc/rfc7519#section-4.1
#[derive(Deserialize, Clone, Debug)]
pub struct RegisteredClaims {
    pub iss: Option<String>,
    pub sub: Option<String>,
    pub aud: Option<StringList>,
    pub exp: Option<NumericDate>,
    pub nbf: Option<NumericDate>,
    pub iat: Option<NumericDate>,
    pub jti: Option<String>,
}

impl<'de> Deserialize<'de> for StringList {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        struct StringListVisitor;
        impl<'de> de::Visitor<'de> for StringListVisitor {
            type Value = StringList;

            fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                write!(formatter, "a space seperated strings")
            }

            fn visit_str<E>(self, v: &str) -> Result<Self::Value, E>
            where
                E: de::Error,
            {
                let auds: Vec<String> = v.split(' ').map(|s| s.to_owned()).collect();
                Ok(StringList(auds))
            }
        }

        deserializer.deserialize_string(StringListVisitor)
    }
}

#[cfg(test)]
mod tests {

    use chrono::{DateTime, TimeZone, Utc};
    use serde::Deserialize;
    use serde_json::json;

    use crate::claims::{NumericDate, RegisteredClaims, StringList};

    #[derive(Deserialize)]
    struct TestStruct {
        v: StringList,
    }

    #[test]
    fn rfc_claims_aud() {
        let a: TestStruct = serde_json::from_str(r#"{"v":"a b"}"#).unwrap();
        assert_eq!(a.v, StringList(vec!["a".to_owned(), "b".to_owned()]));
    }

    #[test]
    fn from_numeric_date() {
        let exp: DateTime<Utc> = NumericDate(1516239022).into();
        assert_eq!(exp, Utc.timestamp_opt(1516239022, 0).unwrap());
        assert_eq!(exp, DateTime::parse_from_rfc3339("2018-01-18T01:30:22.000Z").unwrap());
    }

    #[test]
    fn rfc_claims() {
        let jwt_json = json!({
                    "iss": "http://localhost:3001",
                    "aud": "aud1 aud2",
                    "sub": "bob",
                    "exp": 1516240122,
                    "iat": 1516239022,
                }
        );

        let claims: RegisteredClaims = serde_json::from_value(jwt_json).expect("Failed RfcClaims deserialisation");
        assert_eq!(claims.iss.unwrap(), "http://localhost:3001");
        assert_eq!(claims.aud.unwrap(), StringList(vec!["aud1".to_owned(), "aud2".to_owned()]));
        assert_eq!(claims.exp.unwrap(), NumericDate(1516240122));

        let dt: DateTime<Utc> = claims.iat.unwrap().into();
        assert_eq!(dt, Utc.timestamp_opt(1516239022, 0).unwrap());
    }
}
