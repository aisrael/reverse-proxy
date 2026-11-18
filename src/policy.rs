//! The policy: which client identity may send which requests.
//! It has the same shape as an entry in the policy file (YAML).

use serde::Deserialize;
use thiserror::Error;

/// The reason why we cannot load the policy file.
#[derive(Debug, Error)]
pub enum PolicyError {
    /// The file cannot be read.
    #[error("cannot read the policy file: {0}")]
    Read(#[from] std::io::Error),
    /// The file is not valid YAML, or it does not have the shape of a policy.
    #[error("cannot parse the policy file: {0}")]
    Parse(#[from] serde_saphyr::Error),
}

/// The policy file. We use this type only to load the file.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
#[allow(dead_code)]
pub struct Policies {
    pub policies: Vec<Policy>,
}

/// Read the policy file (YAML) at `path`.
pub fn load(path: &str) -> Result<Policies, PolicyError> {
    let text = std::fs::read_to_string(path)?;
    Ok(serde_saphyr::from_str(&text)?)
}

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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn loads_the_example_policy_file() {
        let path = format!("{}/policies.yaml", env!("CARGO_MANIFEST_DIR"));

        let policies = load(&path).unwrap();

        assert_eq!(policies.policies.len(), 2);
        assert_eq!(
            policies.policies[0].identity,
            "spiffe://acme/prod/payment-agent"
        );
    }
}
