//! The state that the proxy shares between all requests.

use hyper::body::Incoming;
use hyper_util::client::legacy::Client;
use hyper_util::client::legacy::connect::HttpConnector;
use hyper_util::rt::TokioExecutor;

/// The client that sends requests to the upstream.
pub type UpstreamClient = Client<HttpConnector, Incoming>;

/// The state that all requests share. Share it as `Arc<AppState>`.
pub struct AppState {
    /// The client for the upstream. It keeps connections to the upstream open.
    pub client: UpstreamClient,
    /// The address (`host:port`) of the upstream. The connection uses plain HTTP.
    pub upstream: String,
}

impl AppState {
    /// Make the state for an upstream at `upstream` (a `host:port` address).
    pub fn new(upstream: &str) -> Self {
        Self {
            client: Client::builder(TokioExecutor::new()).build_http(),
            upstream: upstream.to_string(),
        }
    }
}
