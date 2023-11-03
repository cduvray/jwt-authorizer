use serde::{Deserialize, Serialize};

/// The number of seconds from 1970-01-01T00:00:00Z UTC until the specified UTC date/time ignoring leap seconds.
/// (https://www.rfc-editor.org/rfc/rfc7519#section-2)
#[derive(Deserialize, Serialize, Clone, PartialEq, Eq, Debug)]
pub struct NumericDate(i64);

/// accesses the underlying value
impl From<NumericDate> for i64 {
    fn from(t: NumericDate) -> Self {
        t.0
    }
}

#[cfg(feature = "chrono")]
use chrono::{DateTime, TimeZone, Utc};

#[cfg(feature = "chrono")]
impl From<NumericDate> for DateTime<Utc> {
    fn from(t: NumericDate) -> Self {
        Utc.timestamp_opt(t.0, 0).unwrap()
    }
}

#[cfg(feature = "time")]
use time::OffsetDateTime;

#[cfg(feature = "time")]
impl From<NumericDate> for OffsetDateTime {
    fn from(t: NumericDate) -> Self {
        OffsetDateTime::from_unix_timestamp(t.0).unwrap()
    }
}

#[derive(PartialEq, Debug, Clone, Deserialize, Serialize)]
#[serde(untagged)]
pub enum OneOrArray<T> {
    One(T),
    Array(Vec<T>),
}

impl<T> OneOrArray<T> {
    pub fn iter<'a>(&'a self) -> Box<dyn Iterator<Item = &'a T> + 'a> {
        match self {
            OneOrArray::One(v) => Box::new(std::iter::once(v)),
            OneOrArray::Array(vector) => Box::new(vector.iter()),
        }
    }
}

#[derive(PartialEq, Debug, Clone)]
pub struct StringList(Vec<String>);

/// Claims mentioned in the JWT specifications.
///
/// https://www.rfc-editor.org/rfc/rfc7519#section-4.1
#[derive(Deserialize, Serialize, Clone, Debug)]
pub struct RegisteredClaims {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub iss: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub sub: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub aud: Option<OneOrArray<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub exp: Option<NumericDate>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub nbf: Option<NumericDate>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub iat: Option<NumericDate>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub jti: Option<String>,
}

#[cfg(test)]
mod tests {

    use chrono::{DateTime, TimeZone, Utc};
    use serde::Deserialize;
    use serde_json::json;

    use crate::claims::{NumericDate, OneOrArray, RegisteredClaims};

    #[derive(Deserialize)]
    struct TestStruct {
        v: OneOrArray<String>,
    }

    #[test]
    fn one_or_array_iter() {
        let o = OneOrArray::One("aaa".to_owned());
        let mut i = o.iter();
        assert_eq!(Some(&"aaa".to_owned()), i.next());

        let a = OneOrArray::Array(vec!["aaa".to_owned()]);
        let mut i = a.iter();
        assert_eq!(Some(&"aaa".to_owned()), i.next());

        let a = OneOrArray::Array(vec!["aaa".to_owned(), "bbb".to_owned()]);
        let mut i = a.iter();
        assert_eq!(Some(&"aaa".to_owned()), i.next());
        assert_eq!(Some(&"bbb".to_owned()), i.next());
        assert_eq!(None, i.next());
    }

    #[test]
    fn rfc_claims_aud() {
        let a: TestStruct = serde_json::from_str(r#"{"v":"a"}"#).unwrap();
        assert_eq!(a.v, OneOrArray::One("a".to_owned()));

        let a: TestStruct = serde_json::from_str(r#"{"v":["a", "b"]}"#).unwrap();
        assert_eq!(a.v, OneOrArray::Array(vec!["a".to_owned(), "b".to_owned()]));
    }

    #[test]
    fn from_numeric_date() {
        let exp: i64 = NumericDate(1516239022).into();
        assert_eq!(exp, 1516239022);
    }

    #[test]
    fn chrono_from_numeric_date() {
        let exp: DateTime<Utc> = NumericDate(1516239022).into();
        assert_eq!(exp, Utc.timestamp_opt(1516239022, 0).unwrap());
        assert_eq!(exp, DateTime::parse_from_rfc3339("2018-01-18T01:30:22.000Z").unwrap());
    }

    #[cfg(feature = "time")]
    #[test]
    fn time_from_numeric_date() {
        use time::macros::datetime;
        use time::OffsetDateTime;

        let exp: OffsetDateTime = NumericDate(1516239022).into();
        assert_eq!(exp, datetime!(2018-01-18 01:30:22 UTC));
    }

    #[test]
    fn rfc_claims() {
        let jwt_json = json!({
                    "iss": "http://localhost:3001",
                    "aud": ["aud1", "aud2"],
                    "sub": "bob",
                    "exp": 1516240122,
                    "iat": 1516239022,
                }
        );

        let claims: RegisteredClaims = serde_json::from_value(jwt_json).expect("Failed RfcClaims deserialisation");
        assert_eq!(claims.iss.unwrap(), "http://localhost:3001");
        assert_eq!(
            claims.aud.unwrap(),
            OneOrArray::Array(vec!["aud1".to_owned(), "aud2".to_owned()])
        );
        assert_eq!(claims.exp.unwrap(), NumericDate(1516240122));
        assert_eq!(claims.nbf, None);

        let dt: DateTime<Utc> = claims.iat.unwrap().into();
        assert_eq!(dt, Utc.timestamp_opt(1516239022, 0).unwrap());
    }

    #[test]
    fn rfc_claims_serde() {
        let claims_str = r#"{
                    "iss": "http://localhost:3001",
                    "sub": "bob",
                    "aud": ["aud1", "aud2"],
                    "exp": 1516240122,
                    "iat": 1516239022
                }"#;

        let claims: RegisteredClaims = serde_json::from_str(claims_str).expect("Failed RfcClaims deserialisation");
        // assert_eq!(claims.iss.unwrap(), "http://localhost:3001");

        let jwt_serd = serde_json::to_string(&claims).unwrap();
        let mut trimed_claims = claims_str.to_owned();
        trimed_claims.retain(|c| !c.is_whitespace());
        assert_eq!(trimed_claims, jwt_serd);
    }
}
