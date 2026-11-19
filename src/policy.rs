//! The policy: which client identity may send which requests.
//! It has the same shape as an entry in the policy file (YAML).

use crate::identity::Identity;
use hyper::Method;
use serde::Deserialize;
use serde::Deserializer;
use serde::de::Error as _;
use thiserror::Error;
use tracing::instrument;
use yaml_schema::Engine;
use yaml_schema::loader;

/// The schema of the policy file.
const SCHEMA: &str = include_str!("../policy-schema.yaml");

/// The reason why we cannot load the policy file.
#[derive(Debug, Error)]
pub enum PolicyError {
    /// The file cannot be read.
    #[error("cannot read the policy file: {0}")]
    Read(#[from] std::io::Error),
    /// The file does not follow the schema. The text has the first problem.
    #[error("the policy file is not valid: {0}")]
    Schema(String),
    /// The file follows the schema, but a value is not allowed. The text has the
    /// first problem.
    #[error("the policy file is not valid: {0}")]
    Content(String),
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

/// Read the policy file (YAML) at `path`. The file must follow the schema.
/// The check stops at the first problem. A method in the file can have any
/// letter case.
pub fn load(path: &str) -> Result<Policies, PolicyError> {
    let text = std::fs::read_to_string(path)?;
    check_schema(&text)?;
    let policies: Policies = serde_saphyr::from_str(&text)?;
    check_content(&policies)?;
    Ok(policies)
}

/// Check the values that the schema cannot check. Return the first problem.
///
/// A rule that is wrong would never match, and the proxy would answer `403`
/// for every request that the author wanted to allow. We find the mistake at
/// start instead.
fn check_content(policies: &Policies) -> Result<(), PolicyError> {
    for policy in &policies.policies {
        let identity = &policy.identity;
        if identity.parse::<Identity>().is_err() {
            return Err(PolicyError::Content(format!(
                "`{identity}` is not a valid SPIFFE ID"
            )));
        }
        for rule in &policy.allow {
            check_rule_path(&rule.path).map_err(|reason| {
                PolicyError::Content(format!(
                    "identity `{identity}`, path `{}`: {reason}",
                    rule.path
                ))
            })?;
        }
    }
    Ok(())
}

/// A rule path is an exact path, or a prefix that ends with `/*`. The part
/// without the `*` must be a path that `is_valid_path` accepts. If not, no
/// request could match the rule.
fn check_rule_path(path: &str) -> Result<(), &'static str> {
    let literal = match path.strip_suffix('*') {
        Some(prefix) if prefix.ends_with('/') => prefix,
        Some(_) => return Err("`*` is only allowed as the last segment, as `/*`"),
        None => path,
    };
    if literal.contains('*') {
        return Err("`*` is only allowed as the last segment, as `/*`");
    }
    if path.contains('?') {
        return Err("a rule path has no query");
    }
    if !is_valid_path(literal) {
        return Err("the path is not valid (see ADR 001)");
    }
    Ok(())
}

/// Check `text` against the schema. Return the first problem.
fn check_schema(text: &str) -> Result<(), PolicyError> {
    let schema = loader::load_from_str(SCHEMA).expect("the policy schema is valid");
    let context = Engine::evaluate(&schema, text, true)
        .map_err(|error| PolicyError::Schema(error.to_string()))?;
    let errors = context.errors.borrow();
    match errors.first() {
        Some(error) => Err(PolicyError::Schema(error.to_string())),
        None => Ok(()),
    }
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

/// Read a method in any letter case.
fn method_from_any_case<'de, D: Deserializer<'de>>(deserializer: D) -> Result<Method, D::Error> {
    let text = String::deserialize(deserializer)?;
    Method::from_bytes(text.to_ascii_uppercase().as_bytes()).map_err(D::Error::custom)
}

/// One allowed request: a method and a path.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Rule {
    /// The HTTP method. In the file it can have any letter case, for example
    /// `GET` or `get`.
    #[serde(deserialize_with = "method_from_any_case")]
    pub method: Method,
    /// An exact path, or a prefix that ends with `/*`.
    pub path: String,
}

impl Policies {
    /// Return `true` if `identity` (a SPIFFE ID) may send the request.
    /// An identity with no entry may send nothing. If an identity has more than
    /// one entry, it may send what any of them allows.
    #[instrument(name = "policy_check", skip_all)]
    pub fn authorize(&self, identity: &str, method: &Method, path: &str) -> bool {
        self.policies
            .iter()
            .filter(|policy| policy.identity == identity)
            .any(|policy| policy.authorize(method, path))
    }
}

impl Policy {
    /// Return `true` if this identity may send the request.
    ///
    /// A rule matches when the method is the same and
    /// the path matches. A rule path is one of:
    /// - an exact path, for example `/payments`;
    /// - a prefix that ends with `/*`, for example `/reports/*`. It matches
    ///   every path with at least one more segment after the prefix, for
    ///   example `/reports/1` and `/reports/2024/q1`. It does not match
    ///   `/reports`, `/reports/` or `/reports-old/1`.
    ///
    /// The query is not part of the path. A path that `is_valid_path` rejects
    /// never matches.
    pub fn authorize(&self, method: &Method, path: &str) -> bool {
        let path = without_query(path);
        is_valid_path(path)
            && self
                .allow
                .iter()
                .any(|rule| rule.method == *method && path_matches(&rule.path, path))
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

    fn schema_error(text: &str) -> String {
        match check_schema(text) {
            Err(PolicyError::Schema(message)) => message,
            other => panic!("expected a schema error, got {other:?}"),
        }
    }

    fn content_message(identity: &str, path: &str) -> String {
        let policies = Policies {
            policies: vec![Policy {
                identity: identity.to_owned(),
                allow: vec![Rule {
                    method: Method::GET,
                    path: path.to_owned(),
                }],
            }],
        };
        match check_content(&policies) {
            Err(PolicyError::Content(message)) => message,
            other => panic!("expected a content error, got {other:?}"),
        }
    }

    #[test]
    fn the_content_check_accepts_valid_rules() {
        for path in ["/", "/payments", "/reports/", "/reports/*", "/*", "/a/b/*"] {
            let policies = Policies {
                policies: vec![policy(&[("GET", path)])],
            };
            assert!(check_content(&policies).is_ok(), "{path}");
        }
    }

    #[test]
    fn the_content_check_rejects_a_wildcard_that_is_not_a_trailing_slash_star() {
        for path in ["/reports*", "/a/*/b", "/*/b", "*", "/a/**", "/a/*/*"] {
            assert!(
                content_message("spiffe://acme/agent", path).contains("`*`"),
                "{path}"
            );
        }
    }

    #[test]
    fn the_content_check_rejects_a_path_that_can_never_match() {
        for path in [
            "/a/../b",
            "/a//b",
            "/a/./b",
            "/a%2fb",
            "/a/%2e%2e/b/*",
            "/a?x=1",
        ] {
            assert!(
                !content_message("spiffe://acme/agent", path).is_empty(),
                "{path}"
            );
        }
    }

    #[test]
    fn the_content_check_rejects_an_identity_that_is_not_a_spiffe_id() {
        for identity in [
            "spiffe://acme",
            "spiffe://acme/",
            "spiffe://acme:8080/a",
            "spiffe://acme/a/../b",
            "spiffe://acme/a?x=1",
        ] {
            assert!(
                content_message(identity, "/a").contains("SPIFFE"),
                "{identity}"
            );
        }
    }

    const VALID: &str =
        "policies:\n- identity: spiffe://acme/agent\n  allow:\n  - method: GET\n    path: /a\n";

    #[test]
    fn the_schema_accepts_a_valid_file() {
        assert!(check_schema(VALID).is_ok());
    }

    #[test]
    fn the_schema_accepts_a_method_in_any_case() {
        assert!(check_schema(&VALID.replace("GET", "get")).is_ok());
        assert!(check_schema(&VALID.replace("GET", "Patch")).is_ok());
    }

    #[test]
    fn the_schema_rejects_a_bad_file() {
        for text in [
            VALID.replace("GET", "FETCH"),
            VALID.replace("spiffe://acme/agent", "https://acme/agent"),
            VALID.replace("spiffe://acme/agent", "spiffe://bad host"),
            VALID.replace("/a\n", "a\n"),
            VALID.replace("    path: /a\n", ""),
            VALID.replace("  allow:\n  - method: GET\n    path: /a\n", "  allow: []\n"),
            format!("{VALID}  extra: 1\n"),
            "other: 1\n".to_owned(),
        ] {
            assert!(!schema_error(&text).is_empty(), "accepted: {text}");
        }
    }

    #[test]
    fn load_changes_the_methods_to_upper_case() {
        let path = std::env::temp_dir().join(format!("policy-case-{}.yaml", std::process::id()));
        std::fs::write(&path, VALID.replace("GET", "get")).unwrap();

        let policies = load(path.to_str().unwrap());
        std::fs::remove_file(&path).unwrap();

        let policies = policies.unwrap();
        assert_eq!(policies.policies[0].allow[0].method, Method::GET);
        assert!(policies.authorize("spiffe://acme/agent", &Method::GET, "/a"));
    }

    fn policy(rules: &[(&str, &str)]) -> Policy {
        Policy {
            identity: "spiffe://acme/prod/agent".to_owned(),
            allow: rules
                .iter()
                .map(|(method, path)| Rule {
                    method: Method::from_bytes(method.as_bytes()).unwrap(),
                    path: (*path).to_owned(),
                })
                .collect(),
        }
    }

    #[test]
    fn allows_an_exact_method_and_path() {
        let policy = policy(&[("POST", "/payments")]);

        assert!(policy.authorize(&Method::POST, "/payments"));
    }

    #[test]
    fn denies_another_method() {
        let policy = policy(&[("POST", "/payments")]);

        assert!(!policy.authorize(&Method::GET, "/payments"));
        assert!(!policy.authorize(&Method::from_bytes(b"post").unwrap(), "/payments"));
    }

    #[test]
    fn denies_another_path() {
        let policy = policy(&[("POST", "/payments")]);

        assert!(!policy.authorize(&Method::POST, "/payments/1"));
        assert!(!policy.authorize(&Method::POST, "/payment"));
        assert!(!policy.authorize(&Method::POST, "/payments/"));
        assert!(!policy.authorize(&Method::POST, "/Payments"));
    }

    #[test]
    fn denies_everything_without_rules() {
        assert!(!policy(&[]).authorize(&Method::GET, "/"));
    }

    #[test]
    fn allows_when_any_rule_matches() {
        let policy = policy(&[("GET", "/a"), ("POST", "/b")]);

        assert!(policy.authorize(&Method::GET, "/a"));
        assert!(policy.authorize(&Method::POST, "/b"));
        assert!(!policy.authorize(&Method::GET, "/b"));
    }

    #[test]
    fn a_prefix_rule_matches_whole_segments() {
        let policy = policy(&[("GET", "/reports/*")]);

        assert!(policy.authorize(&Method::GET, "/reports/1"));
        assert!(policy.authorize(&Method::GET, "/reports/2024/q1"));
        assert!(!policy.authorize(&Method::GET, "/reports"));
        assert!(!policy.authorize(&Method::GET, "/reports/"));
        assert!(!policy.authorize(&Method::GET, "/reports-old/1"));
        assert!(!policy.authorize(&Method::GET, "/other/reports/1"));
        assert!(!policy.authorize(&Method::POST, "/reports/1"));
    }

    #[test]
    fn a_root_prefix_rule_matches_every_path_but_the_root() {
        let policy = policy(&[("GET", "/*")]);

        assert!(policy.authorize(&Method::GET, "/a"));
        assert!(!policy.authorize(&Method::GET, "/"));
    }

    #[test]
    fn the_query_is_not_part_of_the_path() {
        let policy = policy(&[("GET", "/reports/*"), ("POST", "/payments")]);

        assert!(policy.authorize(&Method::POST, "/payments?x=1"));
        assert!(policy.authorize(&Method::GET, "/reports/1?x=/../y"));
        assert!(!policy.authorize(&Method::GET, "/reports?x=/1"));
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
            assert!(!policy.authorize(&Method::GET, path), "{path:?}");
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
                        method: Method::GET,
                        path: "/b".to_owned(),
                    }],
                },
            ],
        };
        let agent = "spiffe://acme/prod/agent";

        assert!(policies.authorize(agent, &Method::GET, "/a"));
        assert!(!policies.authorize(agent, &Method::GET, "/b"));
        assert!(policies.authorize("spiffe://acme/prod/other", &Method::GET, "/b"));
        assert!(!policies.authorize("spiffe://acme/prod/unknown", &Method::GET, "/a"));
    }

    #[test]
    fn policies_merge_the_entries_of_one_identity() {
        let policies = Policies {
            policies: vec![policy(&[("GET", "/a")]), policy(&[("POST", "/b")])],
        };
        let agent = "spiffe://acme/prod/agent";

        assert!(policies.authorize(agent, &Method::GET, "/a"));
        assert!(policies.authorize(agent, &Method::POST, "/b"));
    }
}
