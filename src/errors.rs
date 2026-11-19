//! The error type of the crate.

use crate::config::ConfigError;
use crate::policy::PolicyError;
use thiserror::Error;

/// An error that stops the program.
#[derive(Debug, Error)]
pub enum Error {
    /// An input or output operation failed, for example `bind`.
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),
    /// The configuration is not valid, for example a required variable is not set.
    #[error("configuration error: {0}")]
    Config(#[from] ConfigError),
    /// The TLS configuration is not valid, for example the key does not match
    /// the certificate.
    #[error("TLS configuration error: {0}")]
    Tls(#[from] rustls::Error),
    /// The verifier for client certificates cannot be made, for example the CA
    /// bundle is empty.
    #[error("client certificate verifier error: {0}")]
    ClientVerifier(#[from] rustls::server::VerifierBuilderError),
    /// A PEM file cannot be read, or it has no item of the type that we need.
    #[error("cannot read {path}: {source}")]
    Pem {
        path: String,
        source: rustls_pki_types::pem::Error,
    },
    /// The watcher for the CA bundle file cannot start.
    #[error("cannot watch the client CA file: {0}")]
    Watch(#[from] notify::Error),
    /// The telemetry cannot be set up, for example the OTLP endpoint is not valid.
    #[error("telemetry error: {0}")]
    Telemetry(String),
    /// The policy file cannot be read or is not valid.
    #[error("policy error: {0}")]
    Policy(#[from] PolicyError),
}
