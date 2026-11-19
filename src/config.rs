//! The configuration of the program. All environment variables are read here.

use crate::state::Limits;
use crate::state::Timeouts;
use std::env::VarError;
use std::time::Duration;

/// An error in the configuration.
#[derive(Debug, thiserror::Error)]
pub enum ConfigError {
    /// The environment variable is not set.
    #[error("environment variable {0} is not set")]
    NotSet(&'static str),
    /// The environment variable is set, but its value is not valid Unicode.
    #[error("environment variable {0} is not valid Unicode")]
    NotUnicode(&'static str),
    /// The environment variable is set, but its value is empty.
    #[error("environment variable {0} is empty")]
    Empty(&'static str),
    /// The environment variable must be a whole number of seconds, more than 0.
    #[error("environment variable {name} must be a number of seconds, more than 0 (got {value:?})")]
    NotSeconds { name: &'static str, value: String },
    /// The environment variable must be a whole number of bytes. 0 means no limit.
    #[error("environment variable {name} must be a whole number of bytes (got {value:?})")]
    NotBytes { name: &'static str, value: String },
    /// `SERVER_ADDR` and `PROXY_ADDR` are the same address. The proxy would send
    /// every request to itself.
    #[error(
        "SERVER_ADDR and PROXY_ADDR are the same address ({0}): the proxy would send its requests to itself"
    )]
    UpstreamIsProxy(String),
}

/// The configuration of the program. Make it once, at start.
#[derive(Debug)]
pub struct Config {
    /// The address (`host:port`) of the `proxy` mode.
    proxy_addr: String,
    /// The address (`host:port`) of the `server` mode. The proxy sends its
    /// requests here.
    server_addr: String,
    /// The path of the certificate file (PEM). Only the `proxy` mode needs it.
    tls_cert: Option<String>,
    /// The path of the private key file (PEM). Only the `proxy` mode needs it.
    tls_key: Option<String>,
    /// The path of the CA bundle file (PEM) that signs the client certificates.
    /// Only the `proxy` mode needs it.
    client_ca: Option<String>,
    /// The path of the policy file (YAML). Only the `proxy` mode needs it.
    policy_file: Option<String>,
    /// How long the proxy waits for the client to send the request.
    client_timeout: Duration,
    /// How long the proxy waits for the response head from the upstream.
    upstream_timeout: Duration,
    /// The largest request body in bytes. 0 means no limit.
    max_request_body_bytes: u64,
    /// The largest response body in bytes. 0 means no limit.
    max_response_body_bytes: u64,
}

/// The address of the `proxy` mode when `PROXY_ADDR` is not set.
const DEFAULT_PROXY_ADDR: &str = "127.0.0.1:8080";

/// The address of the `server` mode when `SERVER_ADDR` is not set.
const DEFAULT_SERVER_ADDR: &str = "127.0.0.1:9000";

/// The time that the proxy waits for the client, and for the upstream, when
/// `PROXY_CLIENT_TIMEOUT_SECS` and `PROXY_UPSTREAM_TIMEOUT_SECS` are not set.
const DEFAULT_TIMEOUT_SECS: u64 = 10;

/// The size limit of a body when `PROXY_MAX_REQUEST_BODY_BYTES` and
/// `PROXY_MAX_RESPONSE_BODY_BYTES` are not set: 1 MiB.
const DEFAULT_MAX_BODY_BYTES: u64 = 1024 * 1024;

/// Read an environment variable that is a number of bytes.
///
/// Return `default` if the variable is not set. If the variable is set, it must
/// be a whole number. 0 is valid and means no limit.
fn try_read_bytes_from_env_with_default(
    name: &'static str,
    default: u64,
) -> Result<u64, ConfigError> {
    let Some(value) = try_read_optional_from_env(name)? else {
        return Ok(default);
    };
    value
        .parse::<u64>()
        .map_err(|_| ConfigError::NotBytes { name, value })
}

/// Read an environment variable that is a number of seconds.
///
/// Return `default_secs` if the variable is not set. If the variable is set, it
/// must be a whole number, more than 0.
fn try_read_secs_from_env_with_default(
    name: &'static str,
    default_secs: u64,
) -> Result<Duration, ConfigError> {
    let Some(value) = try_read_optional_from_env(name)? else {
        return Ok(Duration::from_secs(default_secs));
    };
    match value.parse::<u64>() {
        Ok(secs) if secs > 0 => Ok(Duration::from_secs(secs)),
        _ => Err(ConfigError::NotSeconds { name, value }),
    }
}

/// Read an environment variable that is required.
///
/// Return an error if the variable is not set, is not valid Unicode, or is empty.
fn try_read_from_env(name: &'static str) -> Result<String, ConfigError> {
    match std::env::var(name) {
        Ok(value) if value.is_empty() => Err(ConfigError::Empty(name)),
        Ok(value) => Ok(value),
        Err(VarError::NotPresent) => Err(ConfigError::NotSet(name)),
        Err(VarError::NotUnicode(_)) => Err(ConfigError::NotUnicode(name)),
    }
}

/// Read an environment variable that has a default.
///
/// Return `default` if the variable is not set. If the variable is set, it must
/// be valid Unicode and not empty. A mistake is never hidden by the default.
fn try_read_from_env_with_default(
    name: &'static str,
    default: &str,
) -> Result<String, ConfigError> {
    match try_read_from_env(name) {
        Err(ConfigError::NotSet(_)) => Ok(default.to_owned()),
        result => result,
    }
}

/// Read an environment variable that has no default and is not required.
///
/// Return `None` if the variable is not set. If the variable is set, it must
/// be valid Unicode and not empty. A mistake is never hidden.
fn try_read_optional_from_env(name: &'static str) -> Result<Option<String>, ConfigError> {
    match try_read_from_env(name) {
        Err(ConfigError::NotSet(_)) => Ok(None),
        result => result.map(Some),
    }
}

impl Config {
    /// Read the configuration from the environment variables.
    pub fn try_from_env() -> Result<Self, ConfigError> {
        Ok(Config {
            proxy_addr: try_read_from_env_with_default("PROXY_ADDR", DEFAULT_PROXY_ADDR)?,
            server_addr: try_read_from_env_with_default("SERVER_ADDR", DEFAULT_SERVER_ADDR)?,
            tls_cert: try_read_optional_from_env("PROXY_TLS_CERT")?,
            tls_key: try_read_optional_from_env("PROXY_TLS_KEY")?,
            client_ca: try_read_optional_from_env("PROXY_CLIENT_CA")?,
            policy_file: try_read_optional_from_env("PROXY_POLICY_FILE")?,
            client_timeout: try_read_secs_from_env_with_default(
                "PROXY_CLIENT_TIMEOUT_SECS",
                DEFAULT_TIMEOUT_SECS,
            )?,
            upstream_timeout: try_read_secs_from_env_with_default(
                "PROXY_UPSTREAM_TIMEOUT_SECS",
                DEFAULT_TIMEOUT_SECS,
            )?,
            max_request_body_bytes: try_read_bytes_from_env_with_default(
                "PROXY_MAX_REQUEST_BODY_BYTES",
                DEFAULT_MAX_BODY_BYTES,
            )?,
            max_response_body_bytes: try_read_bytes_from_env_with_default(
                "PROXY_MAX_RESPONSE_BODY_BYTES",
                DEFAULT_MAX_BODY_BYTES,
            )?,
        })
    }

    /// The address (`host:port`) of the `proxy` mode.
    pub fn proxy_addr(&self) -> &str {
        &self.proxy_addr
    }

    /// The address (`host:port`) of the `server` mode.
    pub fn server_addr(&self) -> &str {
        &self.server_addr
    }

    /// The timeouts of the proxy.
    pub fn timeouts(&self) -> Timeouts {
        Timeouts {
            client: self.client_timeout,
            upstream: self.upstream_timeout,
        }
    }

    /// The size limits of the bodies. A value of 0 in the environment gives
    /// `None`: no limit.
    pub fn limits(&self) -> Limits {
        Limits {
            request: (self.max_request_body_bytes > 0).then_some(self.max_request_body_bytes),
            response: (self.max_response_body_bytes > 0).then_some(self.max_response_body_bytes),
        }
    }

    /// Return an error if `SERVER_ADDR` is the same text as `PROXY_ADDR`.
    ///
    /// This is a check of the text only. It does not know that `localhost:8080`
    /// and `127.0.0.1:8080` are the same address. The `Via` header catches a
    /// loop that this check does not see.
    pub fn check_upstream_is_not_proxy(&self) -> Result<(), ConfigError> {
        if self.server_addr == self.proxy_addr {
            return Err(ConfigError::UpstreamIsProxy(self.proxy_addr.clone()));
        }
        Ok(())
    }

    /// The paths of the certificate file and the key file, in this order.
    /// Return an error that names the first variable that is not set.
    pub fn tls_paths(&self) -> Result<(&str, &str), ConfigError> {
        let cert = self
            .tls_cert
            .as_deref()
            .ok_or(ConfigError::NotSet("PROXY_TLS_CERT"))?;
        let key = self
            .tls_key
            .as_deref()
            .ok_or(ConfigError::NotSet("PROXY_TLS_KEY"))?;
        Ok((cert, key))
    }

    /// The path of the CA bundle file for the client certificates.
    /// Return an error if `PROXY_CLIENT_CA` is not set.
    pub fn client_ca(&self) -> Result<&str, ConfigError> {
        self.client_ca
            .as_deref()
            .ok_or(ConfigError::NotSet("PROXY_CLIENT_CA"))
    }

    /// The path of the policy file.
    /// Return an error if `PROXY_POLICY_FILE` is not set.
    pub fn policy_file(&self) -> Result<&str, ConfigError> {
        self.policy_file
            .as_deref()
            .ok_or(ConfigError::NotSet("PROXY_POLICY_FILE"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // These tests change the environment of the process. All tests of the
    // process share it, and they run in parallel. Each test uses its own
    // variable name, and no other code reads these names.
    //
    // SAFETY (for every `set_var` call below): no other thread reads or
    // writes these variables while the test runs.
    fn set(name: &str, value: &str) {
        unsafe { std::env::set_var(name, value) };
    }

    fn config(tls_cert: Option<&str>, tls_key: Option<&str>) -> Config {
        Config {
            proxy_addr: DEFAULT_PROXY_ADDR.into(),
            server_addr: DEFAULT_SERVER_ADDR.into(),
            tls_cert: tls_cert.map(Into::into),
            tls_key: tls_key.map(Into::into),
            client_ca: None,
            policy_file: None,
            client_timeout: Duration::from_secs(DEFAULT_TIMEOUT_SECS),
            upstream_timeout: Duration::from_secs(DEFAULT_TIMEOUT_SECS),
            max_request_body_bytes: DEFAULT_MAX_BODY_BYTES,
            max_response_body_bytes: DEFAULT_MAX_BODY_BYTES,
        }
    }

    #[test]
    fn limits_are_1_mib_by_default() {
        let limits = config(None, None).limits();

        assert_eq!(limits.request, Some(1_048_576));
        assert_eq!(limits.response, Some(1_048_576));
    }

    #[test]
    fn a_limit_of_0_means_no_limit() {
        let mut config = config(None, None);
        config.max_request_body_bytes = 0;
        config.max_response_body_bytes = 0;

        let limits = config.limits();

        assert_eq!(limits.request, None);
        assert_eq!(limits.response, None);
    }

    #[test]
    fn bytes_returns_the_default_when_not_set() {
        let value = try_read_bytes_from_env_with_default("CONFIG_TEST_BYTES_NOT_SET", 7).unwrap();

        assert_eq!(value, 7);
    }

    #[test]
    fn bytes_returns_the_value_and_accepts_0() {
        set("CONFIG_TEST_BYTES_SET", "1024");
        set("CONFIG_TEST_BYTES_ZERO", "0");

        assert_eq!(
            try_read_bytes_from_env_with_default("CONFIG_TEST_BYTES_SET", 7).unwrap(),
            1024
        );
        assert_eq!(
            try_read_bytes_from_env_with_default("CONFIG_TEST_BYTES_ZERO", 7).unwrap(),
            0
        );
    }

    #[test]
    fn bytes_fails_for_text_and_for_numbers_that_are_not_whole() {
        for (name, value) in [
            ("CONFIG_TEST_BYTES_TEXT", "big"),
            ("CONFIG_TEST_BYTES_NEGATIVE", "-1"),
            ("CONFIG_TEST_BYTES_FRACTION", "1.5"),
            ("CONFIG_TEST_BYTES_UNIT", "1MiB"),
        ] {
            set(name, value);

            let err = try_read_bytes_from_env_with_default(name, 7).unwrap_err();

            assert!(
                matches!(&err, ConfigError::NotBytes { value: got, .. } if got == value),
                "got: {err}"
            );
        }
    }

    #[test]
    fn bytes_fails_when_empty() {
        set("CONFIG_TEST_BYTES_EMPTY", "");

        let err = try_read_bytes_from_env_with_default("CONFIG_TEST_BYTES_EMPTY", 7).unwrap_err();

        assert!(matches!(err, ConfigError::Empty(_)), "got: {err}");
    }

    #[test]
    fn timeouts_are_10_seconds_by_default() {
        let timeouts = config(None, None).timeouts();

        assert_eq!(timeouts.client, Duration::from_secs(10));
        assert_eq!(timeouts.upstream, Duration::from_secs(10));
    }

    #[test]
    fn secs_returns_the_default_when_not_set() {
        let value = try_read_secs_from_env_with_default("CONFIG_TEST_SECS_NOT_SET", 7).unwrap();

        assert_eq!(value, Duration::from_secs(7));
    }

    #[test]
    fn secs_returns_the_value_when_set() {
        set("CONFIG_TEST_SECS_SET", "12");

        let value = try_read_secs_from_env_with_default("CONFIG_TEST_SECS_SET", 7).unwrap();

        assert_eq!(value, Duration::from_secs(12));
    }

    #[test]
    fn secs_fails_for_zero_and_for_text() {
        for (name, value) in [
            ("CONFIG_TEST_SECS_ZERO", "0"),
            ("CONFIG_TEST_SECS_TEXT", "soon"),
            ("CONFIG_TEST_SECS_NEGATIVE", "-1"),
            ("CONFIG_TEST_SECS_FRACTION", "1.5"),
        ] {
            set(name, value);

            let err = try_read_secs_from_env_with_default(name, 7).unwrap_err();

            assert!(
                matches!(&err, ConfigError::NotSeconds { value: got, .. } if got == value),
                "got: {err}"
            );
        }
    }

    #[test]
    fn secs_fails_when_empty() {
        set("CONFIG_TEST_SECS_EMPTY", "");

        let err = try_read_secs_from_env_with_default("CONFIG_TEST_SECS_EMPTY", 7).unwrap_err();

        assert!(matches!(err, ConfigError::Empty(_)), "got: {err}");
    }

    #[test]
    fn read_returns_the_value() {
        set("CONFIG_TEST_READ_VALUE", "value");

        assert_eq!(
            try_read_from_env("CONFIG_TEST_READ_VALUE").unwrap(),
            "value"
        );
    }

    #[test]
    fn read_fails_when_not_set() {
        let result = try_read_from_env("CONFIG_TEST_READ_NOT_SET");

        assert!(matches!(
            result,
            Err(ConfigError::NotSet("CONFIG_TEST_READ_NOT_SET"))
        ));
    }

    #[test]
    fn read_fails_when_empty() {
        set("CONFIG_TEST_READ_EMPTY", "");

        let result = try_read_from_env("CONFIG_TEST_READ_EMPTY");

        assert!(matches!(
            result,
            Err(ConfigError::Empty("CONFIG_TEST_READ_EMPTY"))
        ));
    }

    #[cfg(unix)]
    #[test]
    fn read_fails_when_not_unicode() {
        use std::os::unix::ffi::OsStrExt;
        let value = std::ffi::OsStr::from_bytes(&[0xff, 0xfe]);
        unsafe { std::env::set_var("CONFIG_TEST_READ_NOT_UNICODE", value) };

        let result = try_read_from_env("CONFIG_TEST_READ_NOT_UNICODE");

        assert!(matches!(
            result,
            Err(ConfigError::NotUnicode("CONFIG_TEST_READ_NOT_UNICODE"))
        ));
    }

    #[test]
    fn with_default_returns_the_value_when_set() {
        set("CONFIG_TEST_DEFAULT_VALUE", "value");

        let result = try_read_from_env_with_default("CONFIG_TEST_DEFAULT_VALUE", "default");

        assert_eq!(result.unwrap(), "value");
    }

    #[test]
    fn with_default_returns_the_default_when_not_set() {
        let result = try_read_from_env_with_default("CONFIG_TEST_DEFAULT_NOT_SET", "default");

        assert_eq!(result.unwrap(), "default");
    }

    #[test]
    fn with_default_fails_when_empty() {
        set("CONFIG_TEST_DEFAULT_EMPTY", "");

        let result = try_read_from_env_with_default("CONFIG_TEST_DEFAULT_EMPTY", "default");

        assert!(matches!(
            result,
            Err(ConfigError::Empty("CONFIG_TEST_DEFAULT_EMPTY"))
        ));
    }

    #[cfg(unix)]
    #[test]
    fn with_default_fails_when_not_unicode() {
        use std::os::unix::ffi::OsStrExt;
        let value = std::ffi::OsStr::from_bytes(&[0xff, 0xfe]);
        unsafe { std::env::set_var("CONFIG_TEST_DEFAULT_NOT_UNICODE", value) };

        let result = try_read_from_env_with_default("CONFIG_TEST_DEFAULT_NOT_UNICODE", "default");

        assert!(matches!(
            result,
            Err(ConfigError::NotUnicode("CONFIG_TEST_DEFAULT_NOT_UNICODE"))
        ));
    }

    #[test]
    fn optional_read_returns_the_value_when_set() {
        set("CONFIG_TEST_OPTIONAL_VALUE", "value");

        let result = try_read_optional_from_env("CONFIG_TEST_OPTIONAL_VALUE");

        assert_eq!(result.unwrap().as_deref(), Some("value"));
    }

    #[test]
    fn optional_read_returns_none_when_not_set() {
        let result = try_read_optional_from_env("CONFIG_TEST_OPTIONAL_NOT_SET");

        assert_eq!(result.unwrap(), None);
    }

    #[test]
    fn optional_read_fails_when_empty() {
        set("CONFIG_TEST_OPTIONAL_EMPTY", "");

        let result = try_read_optional_from_env("CONFIG_TEST_OPTIONAL_EMPTY");

        assert!(matches!(
            result,
            Err(ConfigError::Empty("CONFIG_TEST_OPTIONAL_EMPTY"))
        ));
    }

    #[test]
    fn tls_paths_returns_both_paths() {
        let config = config(Some("cert.pem"), Some("key.pem"));

        assert_eq!(config.tls_paths().unwrap(), ("cert.pem", "key.pem"));
    }

    #[test]
    fn tls_paths_names_the_certificate_when_it_is_not_set() {
        let config = config(None, Some("key.pem"));

        assert!(matches!(
            config.tls_paths(),
            Err(ConfigError::NotSet("PROXY_TLS_CERT"))
        ));
    }

    #[test]
    fn tls_paths_names_the_key_when_it_is_not_set() {
        let config = config(Some("cert.pem"), None);

        assert!(matches!(
            config.tls_paths(),
            Err(ConfigError::NotSet("PROXY_TLS_KEY"))
        ));
    }

    #[test]
    fn client_ca_returns_the_path() {
        let mut config = config(None, None);
        config.client_ca = Some("ca.pem".into());

        assert_eq!(config.client_ca().unwrap(), "ca.pem");
    }

    #[test]
    fn client_ca_names_the_variable_when_it_is_not_set() {
        let config = config(None, None);

        assert!(matches!(
            config.client_ca(),
            Err(ConfigError::NotSet("PROXY_CLIENT_CA"))
        ));
    }

    #[test]
    fn check_upstream_is_not_proxy_accepts_different_addresses() {
        let config = config(None, None);

        assert!(config.check_upstream_is_not_proxy().is_ok());
    }

    #[test]
    fn check_upstream_is_not_proxy_fails_for_the_same_address() {
        let mut config = config(None, None);
        config.server_addr = config.proxy_addr.clone();

        assert!(matches!(
            config.check_upstream_is_not_proxy(),
            Err(ConfigError::UpstreamIsProxy(_))
        ));
    }

    #[test]
    fn policy_file_returns_the_path() {
        let mut config = config(None, None);
        config.policy_file = Some("policies.yaml".into());

        assert_eq!(config.policy_file().unwrap(), "policies.yaml");
    }

    #[test]
    fn policy_file_names_the_variable_when_it_is_not_set() {
        let config = config(None, None);

        assert!(matches!(
            config.policy_file(),
            Err(ConfigError::NotSet("PROXY_POLICY_FILE"))
        ));
    }
}
