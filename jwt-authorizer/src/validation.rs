use std::collections::HashSet;

use jsonwebtoken::Algorithm;

/// Defines the jwt validation parameters (with defaults simplifying configuration).
pub struct Validation {
    /// Add some leeway (in seconds) to the `exp` and `nbf` validation to
    /// account for clock skew.
    ///
    /// Defaults to `60`.
    pub leeway: u64,
    /// Whether to validate the `exp` field.
    ///
    /// Defaults to `true`.
    pub validate_exp: bool,
    /// Whether to validate the `nbf` field.
    ///
    /// Defaults to `false`.
    pub validate_nbf: bool,
    /// If it contains a value, the validation will check that the `aud` claim value is in the values provided.
    ///
    /// Defaults to `None`.
    pub aud: Option<Vec<String>>,
    /// If it contains a value, the validation will check that the `iss` claim value is in the values provided.
    ///
    /// Defaults to `None`.
    pub iss: Option<Vec<String>>,

    /// Whether to validate the JWT signature. Very insecure to turn that off!
    ///
    /// Defaults to true.
    pub validate_signature: bool,
}

impl Validation {
    /// new Validation with default values
    pub fn new() -> Self {
        Default::default()
    }

    /// check that the `iss` claim is a member of the values provided
    pub fn iss<T: ToString>(mut self, items: &[T]) -> Self {
        self.iss = Some(items.iter().map(|x| x.to_string()).collect());

        self
    }

    /// check that the `aud` claim is a member of the items provided
    pub fn aud<T: ToString>(mut self, items: &[T]) -> Self {
        self.aud = Some(items.iter().map(|x| x.to_string()).collect());

        self
    }

    /// enables or disables exp validation
    pub fn exp(mut self, val: bool) -> Self {
        self.validate_exp = val;

        self
    }

    /// enables or disables nbf validation
    pub fn nbf(mut self, val: bool) -> Self {
        self.validate_nbf = val;

        self
    }

    /// Add some leeway (in seconds) to the `exp` and `nbf` validation to
    /// account for clock skew.
    pub fn leeway(mut self, value: u64) -> Self {
        self.leeway = value;

        self
    }

    /// Whether to validate the JWT cryptographic signature
    /// Very insecure to turn that off, only do it if you know what you're doing.
    pub fn disable_validation(mut self) -> Self {
        self.validate_signature = false;

        self
    }

    pub(crate) fn to_jwt_validation(&self, alg: Vec<Algorithm>) -> jsonwebtoken::Validation {
        let required_claims = if self.validate_exp {
            let mut claims = HashSet::with_capacity(1);
            claims.insert("exp".to_owned());
            claims
        } else {
            HashSet::with_capacity(0)
        };

        let aud = self.aud.clone().map(HashSet::from_iter);
        let iss = self.iss.clone().map(HashSet::from_iter);

        let mut jwt_validation = jsonwebtoken::Validation::default();

        jwt_validation.required_spec_claims = required_claims;
        jwt_validation.leeway = self.leeway;
        jwt_validation.validate_exp = self.validate_exp;
        jwt_validation.validate_nbf = self.validate_nbf;
        jwt_validation.iss = iss;
        jwt_validation.aud = aud;
        jwt_validation.sub = None;
        jwt_validation.algorithms = alg;
        if !self.validate_signature {
            jwt_validation.insecure_disable_signature_validation();
        }

        jwt_validation
    }
}

impl Default for Validation {
    fn default() -> Self {
        Validation {
            leeway: 60,

            validate_exp: true,
            validate_nbf: false,

            iss: None,
            aud: None,

            validate_signature: true,
        }
    }
}
