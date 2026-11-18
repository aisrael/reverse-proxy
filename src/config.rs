//! The configuration of the program. All environment variables are read here.

use std::env::VarError;

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
}

/// The address of the `proxy` mode when `PROXY_ADDR` is not set.
const DEFAULT_PROXY_ADDR: &str = "127.0.0.1:8080";

/// The address of the `server` mode when `SERVER_ADDR` is not set.
const DEFAULT_SERVER_ADDR: &str = "127.0.0.1:9000";

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
        }
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
}
