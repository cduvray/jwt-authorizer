use chrono::{DateTime, TimeZone, Utc};

use serde::Deserialize;

/// Seconds since the epoch
#[derive(Deserialize, Clone, PartialEq, Eq, Debug)]
pub struct NumericDate(i64);

impl From<NumericDate> for DateTime<Utc> {
    fn from(t: NumericDate) -> Self {
        Utc.timestamp_opt(t.0, 0).unwrap()
    }
}

#[derive(PartialEq, Debug, Clone, Deserialize)]
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

/// Claims mentioned in the JWT specifications.
///
/// https://www.rfc-editor.org/rfc/rfc7519#section-4.1
#[derive(Deserialize, Clone, Debug)]
pub struct RegisteredClaims {
    pub iss: Option<String>,
    pub sub: Option<String>,
    pub aud: Option<OneOrArray<String>>,
    pub exp: Option<NumericDate>,
    pub nbf: Option<NumericDate>,
    pub iat: Option<NumericDate>,
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
        let exp: DateTime<Utc> = NumericDate(1516239022).into();
        assert_eq!(exp, Utc.timestamp_opt(1516239022, 0).unwrap());
        assert_eq!(exp, DateTime::parse_from_rfc3339("2018-01-18T01:30:22.000Z").unwrap());
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

        let dt: DateTime<Utc> = claims.iat.unwrap().into();
        assert_eq!(dt, Utc.timestamp_opt(1516239022, 0).unwrap());
    }
}
