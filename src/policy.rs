//! The policy: which client identity may send which requests.
//! It has the same shape as an entry in the policy file (YAML).

use serde::Deserialize;

/// The rules for one identity.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
#[allow(dead_code)]
pub struct Policy {
    /// A SPIFFE ID, for example `spiffe://acme/prod/payment-agent`.
    pub identity: String,
    /// The requests that this identity may send.
    pub allow: Vec<Rule>,
}

/// One allowed request: a method and a path.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
#[allow(dead_code)]
pub struct Rule {
    /// The HTTP method, for example `GET`.
    pub method: String,
    /// An exact path, or a prefix that ends with `/*`.
    pub path: String,
}
