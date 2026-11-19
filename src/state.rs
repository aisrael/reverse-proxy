//! The state that the proxy shares between all requests.

use crate::deadline::DeadlineBody;
use crate::headers;
use crate::limit::LimitBody;
use crate::policy::Policies;
use crate::telemetry::Telemetry;
use hyper::body::Body;
use hyper::body::Incoming;
use hyper_util::client::legacy::Client;
use hyper_util::client::legacy::connect::HttpConnector;
use hyper_util::rt::TokioExecutor;
use std::error::Error;
use std::sync::Arc;
use std::time::Duration;

/// How long the proxy waits.
#[derive(Clone, Copy, Debug)]
pub struct Timeouts {
    /// How long the client has to send the request head, and then the request
    /// body. Each has this time.
    pub client: Duration,
    /// How long to wait for the response head from the upstream. This includes
    /// the connection, and the time to send the request.
    pub upstream: Duration,
}

/// The largest body that the proxy accepts, in bytes. `None` means no limit.
#[derive(Clone, Copy, Debug)]
pub struct Limits {
    /// The largest request body from the client.
    pub request: Option<u64>,
    /// The largest response body from the upstream.
    pub response: Option<u64>,
}

/// The client that sends requests to the upstream. `B` is the type of the
/// request body that the proxy got from the client.
pub type UpstreamClient<B> = Client<HttpConnector, DeadlineBody<LimitBody<B>>>;

/// The state that all requests share. Share it as `Arc<AppState>`.
///
/// `B` is the type of the request body. The server uses `Incoming`. A test can
/// use another type.
pub struct AppState<B = Incoming> {
    /// The client for the upstream. It keeps connections to the upstream open.
    pub client: UpstreamClient<B>,
    /// The address (`host:port`) of the upstream. The connection uses plain HTTP.
    pub upstream: String,
    /// Which identity may send which requests.
    pub policies: Policies,
    /// The name of this proxy in the `Via` header. It is different for each
    /// start. A request with this name in its `Via` header is a loop.
    pub via_name: String,
    /// How long to wait for the client and for the upstream.
    pub timeouts: Timeouts,
    /// The largest request body and response body.
    pub limits: Limits,
    /// The spans and the counter of timeouts.
    pub telemetry: Arc<Telemetry>,
}

impl<B> AppState<B>
where
    B: Body + Send + Unpin + 'static,
    B::Data: Send,
    B::Error: Into<Box<dyn Error + Send + Sync>>,
{
    /// Make the state for an upstream at `upstream` (a `host:port` address).
    pub fn new(
        upstream: &str,
        policies: Policies,
        timeouts: Timeouts,
        limits: Limits,
        telemetry: Arc<Telemetry>,
    ) -> Self {
        Self {
            client: Client::builder(TokioExecutor::new()).build_http(),
            upstream: upstream.to_string(),
            policies,
            via_name: headers::new_via_name(),
            timeouts,
            limits,
            telemetry,
        }
    }
}
