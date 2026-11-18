//! The audit event: one record for each request that the proxy decides on.
//!
//! The event goes to STDOUT as one line of JSON. The other logs go to STDERR
//! (see `logging`). The event never has a header, a cookie, a body or a query.

use hyper::Method;
use tracing::info;

/// What the proxy decided for a request.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Decision {
    /// The policy allows the request. The proxy sent it to the upstream.
    Allow,
    /// The proxy did not send the request to the upstream.
    Deny(Reason),
}

/// Why the proxy denied a request.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Reason {
    /// The client certificate has no valid identity (`401`).
    NoIdentity,
    /// The path is not valid (`400`).
    InvalidPath,
    /// The policy does not allow this identity to send this request (`403`).
    Policy,
}

impl Decision {
    /// The value of the `decision` field.
    fn as_str(self) -> &'static str {
        match self {
            Decision::Allow => "ALLOW",
            Decision::Deny(_) => "DENY",
        }
    }

    /// The value of the `reason` field. An allowed request has none.
    fn reason(self) -> Option<&'static str> {
        match self {
            Decision::Allow => None,
            Decision::Deny(Reason::NoIdentity) => Some("no_identity"),
            Decision::Deny(Reason::InvalidPath) => Some("invalid_path"),
            Decision::Deny(Reason::Policy) => Some("policy"),
        }
    }
}

/// The facts about one request. `record` writes them as one audit event.
pub struct Event<'a> {
    pub request_id: &'a str,
    /// The SPIFFE ID of the client. `None` if the certificate has no valid one.
    pub identity: Option<&'a str>,
    pub method: &'a Method,
    /// The path of the request, without the query.
    pub path: &'a str,
    /// The host that the client asked for, as the client sent it.
    pub host: Option<&'a str>,
    pub decision: Decision,
    /// The status that the client got.
    pub status: u16,
    /// The status from the upstream. `None` if the proxy got no response from it.
    pub upstream_status: Option<u16>,
    pub latency_ms: u64,
}

/// Write `event` as an audit event. A field that is `None` is not in the output.
pub fn record(event: &Event) {
    info!(
        target: "audit",
        request_id = event.request_id,
        identity = event.identity,
        method = %event.method,
        path = event.path,
        host = event.host,
        decision = event.decision.as_str(),
        reason = event.decision.reason(),
        status = event.status,
        upstream_status = event.upstream_status,
        latency_ms = event.latency_ms,
    );
}
