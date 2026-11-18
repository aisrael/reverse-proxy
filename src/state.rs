//! The state that the proxy shares between all requests.

use hyper::body::Body;
use hyper::body::Incoming;
use hyper_util::client::legacy::Client;
use hyper_util::client::legacy::connect::HttpConnector;
use hyper_util::rt::TokioExecutor;

/// The client that sends requests to the upstream. `B` is the type of the
/// request body.
pub type UpstreamClient<B> = Client<HttpConnector, B>;

/// The state that all requests share. Share it as `Arc<AppState>`.
///
/// `B` is the type of the request body. The server uses `Incoming`. A test can
/// use another type.
pub struct AppState<B = Incoming> {
    /// The client for the upstream. It keeps connections to the upstream open.
    pub client: UpstreamClient<B>,
    /// The address (`host:port`) of the upstream. The connection uses plain HTTP.
    pub upstream: String,
}

impl<B> AppState<B>
where
    B: Body + Send,
    B::Data: Send,
{
    /// Make the state for an upstream at `upstream` (a `host:port` address).
    pub fn new(upstream: &str) -> Self {
        Self {
            client: Client::builder(TokioExecutor::new()).build_http(),
            upstream: upstream.to_string(),
        }
    }
}
