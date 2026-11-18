//! The error type of the crate.

use thiserror::Error;

/// An error that stops the program.
#[derive(Debug, Error)]
pub enum Error {
    /// An input or output operation failed, for example `bind`.
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),
}
