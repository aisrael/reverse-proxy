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

/// The policy file: the policy of every identity.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
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
pub struct Policy {
    /// A SPIFFE ID, for example `spiffe://acme/prod/payment-agent`.
    pub identity: String,
    /// The requests that this identity may send.
    pub allow: Vec<Rule>,
}

/// One allowed request: a method and a path.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Rule {
    /// The HTTP method, for example `GET`.
    pub method: String,
    /// An exact path, or a prefix that ends with `/*`.
    pub path: String,
}

impl Policies {
    /// Return `true` if `identity` (a SPIFFE ID) may send the request.
    /// An identity with no entry may send nothing. If an identity has more than
    /// one entry, it may send what any of them allows.
    pub fn authorize(&self, identity: &str, method: &str, path: &str) -> bool {
        self.policies
            .iter()
            .filter(|policy| policy.identity == identity)
            .any(|policy| policy.authorize(method, path))
    }
}

impl Policy {
    /// Return `true` if this identity may send the request.
    ///
    /// A rule matches when the method is the same (exact, case-sensitive) and
    /// the path matches. A rule path is one of:
    /// - an exact path, for example `/payments`;
    /// - a prefix that ends with `/*`, for example `/reports/*`. It matches
    ///   every path with at least one more segment after the prefix, for
    ///   example `/reports/1` and `/reports/2024/q1`. It does not match
    ///   `/reports`, `/reports/` or `/reports-old/1`.
    ///
    /// The query is not part of the path. A path that `is_valid_path` rejects
    /// never matches.
    pub fn authorize(&self, method: &str, path: &str) -> bool {
        let path = without_query(path);
        is_valid_path(path)
            && self
                .allow
                .iter()
                .any(|rule| rule.method == method && path_matches(&rule.path, path))
    }
}

fn without_query(path: &str) -> &str {
    path.split_once('?').map_or(path, |(path, _)| path)
}

fn path_matches(pattern: &str, path: &str) -> bool {
    match pattern.strip_suffix('*') {
        // Keep the `/` at the end of the prefix, so `/reports-old/1` does not
        // match `/reports/*`.
        Some(prefix) if prefix.ends_with('/') => path
            .strip_prefix(prefix)
            .is_some_and(|rest| !rest.is_empty() && !rest.starts_with('/')),
        _ => pattern == path,
    }
}

/// Return `true` if `path` is safe to match against the policy. The path (the
/// part before `?`) must start with `/`, and must not have:
/// - an empty segment (`//`), except one at the end (`/reports/`);
/// - a segment that is `.` or `..`;
/// - a NUL character, or an encoded NUL (`%00`);
/// - an encoded `/`, `.` or `\` (`%2f`, `%2e`, `%5c`, in any case).
///
/// We never decode `%` sequences, so a client cannot hide a dot segment or a
/// slash in one.
pub fn is_valid_path(path: &str) -> bool {
    let path = without_query(path);
    let Some(rest) = path.strip_prefix('/') else {
        return false;
    };
    if path.contains('\0') {
        return false;
    }
    let lower = path.to_ascii_lowercase();
    if ["%2f", "%2e", "%5c", "%00"]
        .iter()
        .any(|code| lower.contains(code))
    {
        return false;
    }
    let mut segments = rest.split('/').peekable();
    while let Some(segment) = segments.next() {
        let last = segments.peek().is_none();
        if segment == "." || segment == ".." || (segment.is_empty() && !last) {
            return false;
        }
    }
    true
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

    fn policy(rules: &[(&str, &str)]) -> Policy {
        Policy {
            identity: "spiffe://acme/prod/agent".to_owned(),
            allow: rules
                .iter()
                .map(|(method, path)| Rule {
                    method: (*method).to_owned(),
                    path: (*path).to_owned(),
                })
                .collect(),
        }
    }

    #[test]
    fn allows_an_exact_method_and_path() {
        let policy = policy(&[("POST", "/payments")]);

        assert!(policy.authorize("POST", "/payments"));
    }

    #[test]
    fn denies_another_method() {
        let policy = policy(&[("POST", "/payments")]);

        assert!(!policy.authorize("GET", "/payments"));
        assert!(!policy.authorize("post", "/payments"));
    }

    #[test]
    fn denies_another_path() {
        let policy = policy(&[("POST", "/payments")]);

        assert!(!policy.authorize("POST", "/payments/1"));
        assert!(!policy.authorize("POST", "/payment"));
        assert!(!policy.authorize("POST", "/payments/"));
        assert!(!policy.authorize("POST", "/Payments"));
    }

    #[test]
    fn denies_everything_without_rules() {
        assert!(!policy(&[]).authorize("GET", "/"));
    }

    #[test]
    fn allows_when_any_rule_matches() {
        let policy = policy(&[("GET", "/a"), ("POST", "/b")]);

        assert!(policy.authorize("GET", "/a"));
        assert!(policy.authorize("POST", "/b"));
        assert!(!policy.authorize("GET", "/b"));
    }

    #[test]
    fn a_prefix_rule_matches_whole_segments() {
        let policy = policy(&[("GET", "/reports/*")]);

        assert!(policy.authorize("GET", "/reports/1"));
        assert!(policy.authorize("GET", "/reports/2024/q1"));
        assert!(!policy.authorize("GET", "/reports"));
        assert!(!policy.authorize("GET", "/reports/"));
        assert!(!policy.authorize("GET", "/reports-old/1"));
        assert!(!policy.authorize("GET", "/other/reports/1"));
        assert!(!policy.authorize("POST", "/reports/1"));
    }

    #[test]
    fn a_root_prefix_rule_matches_every_path_but_the_root() {
        let policy = policy(&[("GET", "/*")]);

        assert!(policy.authorize("GET", "/a"));
        assert!(!policy.authorize("GET", "/"));
    }

    #[test]
    fn the_query_is_not_part_of_the_path() {
        let policy = policy(&[("GET", "/reports/*"), ("POST", "/payments")]);

        assert!(policy.authorize("POST", "/payments?x=1"));
        assert!(policy.authorize("GET", "/reports/1?x=/../y"));
        assert!(!policy.authorize("GET", "/reports?x=/1"));
    }

    #[test]
    fn a_path_that_is_not_valid_never_matches() {
        let policy = policy(&[("GET", "/reports/*")]);

        for path in [
            "/reports/../reports/1",
            "/reports/./1",
            "/reports//1",
            "/reports/%2e%2e/1",
            "/reports/%2E/1",
            "/reports/a%2fb",
            "/reports/a%5Cb",
            "/reports/a%00b",
            "/reports/a\0b",
            "reports/1",
            "",
        ] {
            assert!(!policy.authorize("GET", path), "{path:?}");
        }
    }

    #[test]
    fn accepts_valid_paths() {
        for path in [
            "/",
            "/a",
            "/a/b",
            "/a/",
            "/a.b/c-d_e",
            "/a%20b",
            "/a?x=%2f",
            "/..a/b..",
        ] {
            assert!(is_valid_path(path), "{path:?}");
        }
    }

    #[test]
    fn rejects_invalid_paths() {
        for path in [
            "",
            "a",
            "//",
            "/a//b",
            "//a",
            "/..",
            "/a/..",
            "/a/../b",
            "/.",
            "/a/./b",
            "/a%2fb",
            "/a%2Fb",
            "/%2e%2e/b",
            "/a%5cb",
            "/a%00b",
            "/a\0b",
        ] {
            assert!(!is_valid_path(path), "{path:?}");
        }
    }

    #[test]
    fn policies_allow_only_what_the_identity_may_send() {
        let policies = Policies {
            policies: vec![
                policy(&[("GET", "/a")]),
                Policy {
                    identity: "spiffe://acme/prod/other".to_owned(),
                    allow: vec![Rule {
                        method: "GET".to_owned(),
                        path: "/b".to_owned(),
                    }],
                },
            ],
        };
        let agent = "spiffe://acme/prod/agent";

        assert!(policies.authorize(agent, "GET", "/a"));
        assert!(!policies.authorize(agent, "GET", "/b"));
        assert!(policies.authorize("spiffe://acme/prod/other", "GET", "/b"));
        assert!(!policies.authorize("spiffe://acme/prod/unknown", "GET", "/a"));
    }

    #[test]
    fn policies_merge_the_entries_of_one_identity() {
        let policies = Policies {
            policies: vec![policy(&[("GET", "/a")]), policy(&[("POST", "/b")])],
        };
        let agent = "spiffe://acme/prod/agent";

        assert!(policies.authorize(agent, "GET", "/a"));
        assert!(policies.authorize(agent, "POST", "/b"));
    }
}
