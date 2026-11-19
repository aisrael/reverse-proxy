//! The audit event: one record for each request that the proxy decides on.
//!
//! The event goes to STDOUT as one line of JSON. The other logs go to STDERR
//! (see `logging`). The event never has a header, a cookie, a body or a query.

use crate::identity::CertificateInfo;
use hyper::Method;
use tracing::info;
use tracing::instrument;

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
    /// The request came back to this proxy (`508`).
    Loop,
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
            Decision::Deny(Reason::Loop) => Some("loop"),
        }
    }
}

/// The facts about one request. `record` writes them as one audit event.
pub struct Event<'a> {
    pub request_id: &'a str,
    /// The SPIFFE ID of the client. `None` if the certificate has no valid one.
    pub identity: Option<&'a str>,
    /// The other fields of the client certificate. `None` if the client has no
    /// certificate that the proxy can read.
    pub certificate: Option<&'a CertificateInfo>,
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
    /// The trace ID (32 hexadecimal digits). `None` if the request has no trace.
    pub trace_id: Option<&'a str>,
    pub latency_ms: u64,
}

/// Write `event` as an audit event. A field that is `None` is not in the output.
#[instrument(name = "audit_write", skip_all)]
pub fn record(event: &Event) {
    let certificate = event.certificate;
    let uri_sans = certificate.and_then(|info| join(&info.uri_sans));
    let dns_sans = certificate.and_then(|info| join(&info.dns_sans));
    info!(
        target: "audit",
        request_id = event.request_id,
        identity = event.identity,
        cert_subject = certificate.map(|info| info.subject.as_str()),
        cert_issuer = certificate.map(|info| info.issuer.as_str()),
        cert_serial = certificate.map(|info| info.serial.as_str()),
        cert_not_before = certificate.map(|info| info.not_before.as_str()),
        cert_not_after = certificate.map(|info| info.not_after.as_str()),
        cert_uri_sans = uri_sans.as_deref(),
        cert_dns_sans = dns_sans.as_deref(),
        method = %event.method,
        path = event.path,
        host = event.host,
        decision = event.decision.as_str(),
        reason = event.decision.reason(),
        status = event.status,
        upstream_status = event.upstream_status,
        trace_id = event.trace_id,
        latency_ms = event.latency_ms,
    );
}

/// Join the values with a comma. Return `None` if there is no value, so the
/// field is not in the event.
fn join(values: &[String]) -> Option<String> {
    (!values.is_empty()).then(|| values.join(","))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn joins_values_with_a_comma() {
        let values = ["a.example".to_owned(), "b.example".to_owned()];

        assert_eq!(join(&values).as_deref(), Some("a.example,b.example"));
    }

    #[test]
    fn has_no_field_for_an_empty_list() {
        assert_eq!(join(&[]), None);
    }
}
