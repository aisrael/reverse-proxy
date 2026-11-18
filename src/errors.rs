//! The error type of the crate.

use thiserror::Error;

/// An error that stops the program.
#[derive(Debug, Error)]
pub enum Error {
    /// An input or output operation failed, for example `bind`.
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),
    /// A required environment variable is not set, or its value is not valid text.
    #[error("environment variable {0} is not set")]
    MissingEnv(&'static str),
    /// A PEM file cannot be read, or it has no item of the type that we need.
    #[error("cannot read {path}: {source}")]
    Pem {
        path: String,
        source: rustls_pki_types::pem::Error,
    },
}
