//! The `proxy` mode: send each request to one upstream and return its response.

use std::io;

/// Run the proxy. Not implemented yet.
pub async fn run() -> io::Result<()> {
    Err(io::Error::other("proxy mode is not implemented yet"))
}
