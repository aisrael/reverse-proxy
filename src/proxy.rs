//! The `proxy` mode: send each request to one upstream and return its response.
//!
//! This mode has its own accept loop. It does not share code with the `server` mode.

use crate::audit;
use crate::audit::Decision;
use crate::audit::Event;
use crate::audit::Reason;
use crate::deadline::DeadlineBody;
use crate::headers;
use crate::identity::CertificateInfo;
use crate::identity::Identity;
use crate::limit::BodyTooLarge;
use crate::limit::LimitBody;
use crate::policy;
use crate::policy::Policies;
use crate::state::AppState;
use crate::state::Limits;
use crate::state::Timeouts;
use crate::telemetry::SpanOutcome;
use crate::telemetry::Telemetry;
use crate::telemetry::TimeoutKind;
use bytes::Bytes;
use http_body_util::BodyExt;
use http_body_util::Empty;
use http_body_util::Full;
use http_body_util::combinators::UnsyncBoxBody;
use hyper::Request;
use hyper::Response;
use hyper::StatusCode;
use hyper::Uri;
use hyper::Version;
use hyper::body::Body as RequestBody;
use hyper::header::HOST;
use hyper::header::HeaderValue;
use hyper::http::uri::InvalidUri;
use hyper::service::service_fn;
use hyper_util::rt::TokioExecutor;
use hyper_util::rt::TokioIo;
use hyper_util::rt::TokioTimer;
use hyper_util::server::conn::auto::Builder;
use hyper_util::server::graceful::GracefulShutdown;
use opentelemetry::Context;
use opentelemetry::trace::TraceContextExt;
use rustls::ServerConnection;
use std::convert::Infallible;
use std::error::Error;
use std::net::IpAddr;
use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::atomic::Ordering;
use std::time::Duration;
use std::time::Instant;
use tokio::net::TcpListener;
use tokio::net::TcpStream;
use tokio::time::timeout;
use tokio_rustls::TlsAcceptor;
use tokio_util::sync::CancellationToken;
use tracing::Instrument;
use tracing::Span;
use tracing::debug;
use tracing::info;
use tracing::info_span;
use tracing::instrument;
use tracing::warn;
use tracing_opentelemetry::OpenTelemetrySpanExt;

/// Maximum time to wait for open connections to finish after a shutdown request.
const SHUTDOWN_TIMEOUT: Duration = Duration::from_secs(10);

/// Maximum time for the TLS handshake of one connection.
const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(10);

/// The type of every response body. The answer from the upstream and our own
/// error answer have different body types, so both are boxed.
type Body = UnsyncBoxBody<Bytes, Box<dyn Error + Send + Sync>>;

/// Accept connections on `listener` until `shutdown` is cancelled.
/// Every connection uses TLS: `acceptor` does the handshake.
/// The requests go to the upstream at `upstream` (a `host:port` address).
/// `policies` say which client identity may send which requests.
/// `timeouts` say how long to wait for the client and for the upstream.
/// `limits` say how large a request body and a response body can be.
/// `telemetry` has the spans and the counter of timeouts.
///
/// After that, stop accepting and wait for open connections to finish.
/// Stop waiting after `SHUTDOWN_TIMEOUT`.
#[allow(clippy::too_many_arguments)]
pub async fn serve(
    listener: TcpListener,
    shutdown: CancellationToken,
    acceptor: TlsAcceptor,
    upstream: &str,
    policies: Policies,
    timeouts: Timeouts,
    limits: Limits,
    telemetry: Arc<Telemetry>,
) {
    let state = Arc::new(AppState::new(
        upstream, policies, timeouts, limits, telemetry,
    ));
    info!(upstream = %state.upstream, "sending requests to the upstream");
    let mut builder = Builder::new(TokioExecutor::new());
    // HTTP/1: close a connection that does not send the request head in time.
    // HTTP/2 has no such setting.
    builder
        .http1()
        .timer(TokioTimer::new())
        .header_read_timeout(timeouts.client);
    let graceful = GracefulShutdown::new();

    loop {
        let (stream, peer) = tokio::select! {
            _ = shutdown.cancelled() => break,
            accepted = listener.accept() => match accepted {
                Ok(accepted) => accepted,
                Err(err) => {
                    warn!(%err, "failed to accept a connection");
                    continue;
                }
            },
        };
        debug!(%peer, "connection accepted");
        spawn_connection(&builder, &graceful, &acceptor, stream, peer, state.clone());
    }

    // Stop accepting. Close the listening socket before the wait.
    drop(listener);
    info!("waiting for open connections to finish");
    if timeout(SHUTDOWN_TIMEOUT, graceful.shutdown())
        .await
        .is_err()
    {
        warn!(
            timeout_secs = SHUTDOWN_TIMEOUT.as_secs(),
            "timeout: some connections are still open"
        );
    }
}

/// Serve one connection in its own task. HTTP/1 and HTTP/2 are both supported.
///
/// The task does the TLS handshake first. A handshake that fails or takes more
/// than `HANDSHAKE_TIMEOUT` closes this connection only. The accept loop does
/// not wait for it.
fn spawn_connection(
    builder: &Builder<TokioExecutor>,
    graceful: &GracefulShutdown,
    acceptor: &TlsAcceptor,
    stream: TcpStream,
    peer: SocketAddr,
    state: Arc<AppState>,
) {
    let builder = builder.clone();
    let acceptor = acceptor.clone();
    let watcher = graceful.watcher();
    let telemetry = state.telemetry.clone();
    tokio::spawn(async move {
        let handshake = timeout(HANDSHAKE_TIMEOUT, acceptor.accept(stream))
            .instrument(info_span!("tls_handshake"));
        let stream = match handshake.await {
            Ok(Ok(stream)) => stream,
            Ok(Err(err)) => {
                debug!(%peer, %err, "TLS handshake failed");
                return;
            }
            Err(_) => {
                debug!(%peer, "TLS handshake timed out");
                state.telemetry.record_timeout(TimeoutKind::Handshake);
                return;
            }
        };
        let client_ip = peer.ip();
        // Read the identity once. All requests of this connection share it.
        let (identity, certificate) = info_span!("identity_extraction").in_scope(|| {
            (
                client_identity(stream.get_ref().1, peer),
                client_certificate(stream.get_ref().1, peer).map(Arc::new),
            )
        });
        let service = service_fn(move |request| {
            handle(
                state.clone(),
                client_ip,
                identity.clone(),
                certificate.clone(),
                request,
            )
        });
        // The connection borrows `builder`, so create it inside the task.
        let connection = builder.serve_connection(TokioIo::new(stream), service);
        // `watch` tells the connection to finish its work when the shutdown starts.
        if let Err(err) = watcher.watch(connection).await {
            if err
                .downcast_ref::<hyper::Error>()
                .is_some_and(hyper::Error::is_timeout)
            {
                telemetry.record_timeout(TimeoutKind::ClientHeader);
            }
            debug!(%peer, %err, "connection error");
        }
        debug!(%peer, "connection closed");
    });
}

/// Read the identity of the client from the certificate that it sent in the
/// handshake. The TLS layer already checked the certificate.
/// Return `None` if the certificate has no valid identity.
fn client_identity(connection: &ServerConnection, peer: SocketAddr) -> Option<Identity> {
    let certificate = connection.peer_certificates()?.first()?;
    match Identity::from_certificate(certificate) {
        Ok(identity) => Some(identity),
        Err(err) => {
            // Never log the certificate.
            debug!(%peer, %err, "client certificate has no valid identity");
            None
        }
    }
}

/// Read the fields of the client certificate, for the audit event. The proxy
/// does not use them for a decision. Return `None` if the client sent no
/// certificate, or the certificate cannot be read.
fn client_certificate(connection: &ServerConnection, peer: SocketAddr) -> Option<CertificateInfo> {
    let certificate = connection.peer_certificates()?.first()?;
    match CertificateInfo::from_certificate(certificate) {
        Ok(info) => Some(info),
        Err(err) => {
            // Never log the certificate.
            debug!(%peer, %err, "client certificate cannot be read");
            None
        }
    }
}

/// Send `request` to the upstream of `state` and return the response.
/// `client_ip` is the IP address of the client. `identity` is the identity of
/// the client, if its certificate has a valid one. `certificate` has the other
/// fields of the certificate. They go to the audit event only.
///
/// Check the request, then forward it. The proxy answers with an empty body
/// and does not connect to the upstream if:
///
/// - the client has no valid identity: `401`;
/// - the request has the name of this proxy in its `Via` header, so it came
///   back to this proxy (a loop): `508`;
/// - the path is not valid (see `policy::is_valid_path`): `400`;
/// - the policy does not allow the identity to send this method and path: `403`.
///
/// Otherwise, prepare the request and forward it.
///
/// Every request has a request ID. The upstream gets it in the request, and the
/// client gets it in the response. Use the `X-Request-Id` of the client if it
/// is valid. Otherwise make a new one.
///
/// Never return an error: a failure becomes a `502 Bad Gateway` response, a
/// `504 Gateway Timeout` response if the upstream does not answer in time, or a
/// `408 Request Timeout` response if the client sends the request body too
/// slowly.
///
/// The span `request` is the root of the spans of one request. If the client
/// sent a valid `traceparent`, it is a child of the span of the client.
#[instrument(
    name = "request",
    skip_all,
    fields(
        http.request.method = %request.method(),
        http.response.status_code = tracing::field::Empty,
    )
)]
async fn handle<B>(
    state: Arc<AppState<B>>,
    client_ip: IpAddr,
    identity: Option<Identity>,
    certificate: Option<Arc<CertificateInfo>>,
    mut request: Request<B>,
) -> Result<Response<Body>, Infallible>
where
    B: RequestBody + Send + Unpin + 'static,
    B::Data: Send,
    B::Error: Into<Box<dyn Error + Send + Sync>>,
{
    let started = Instant::now();
    // Keep these for the audit event. Never keep the query.
    let method = request.method().clone();
    let path = request.uri().path().to_string();
    let identity = identity.map(|identity| identity.to_string());
    // Read the host before `prepare_request`, which sets `Host` to the upstream.
    let host = request
        .headers()
        .get(HOST)
        .and_then(|host| host.to_str().ok())
        .map(str::to_string);
    // Check this before `prepare_request`, which adds the name of this proxy.
    let is_loop = headers::via_has(request.headers(), &state.via_name);
    // Read the trace context of the client before `prepare_request` removes it.
    let parent = state.telemetry.extract(request.headers());
    let mut trace_id = Telemetry::trace_id(&parent);
    // Put the span of this request in the trace of the client. This does
    // nothing if the spans are not exported.
    let span = Span::current();
    let _ = span.set_parent(parent.clone());
    // The span of the upstream request is a child of this span, if the spans
    // are exported. If not, it is a child of the span of the client.
    let upstream_parent = {
        let context = span.context();
        if context.span().span_context().is_valid() {
            context
        } else {
            parent
        }
    };
    let prepared = prepare_request(&mut request, &state.upstream, client_ip, &state.via_name);
    // Do this after `prepare_request`. A `Connection` header from the client
    // can name `X-Request-Id`, and then `prepare_request` removes it.
    let request_id = headers::ensure_request_id(request.headers_mut());
    let mut upstream_status = None;
    let (mut response, decision) = match &identity {
        None => (
            empty(StatusCode::UNAUTHORIZED),
            Decision::Deny(Reason::NoIdentity),
        ),
        Some(_) if is_loop => (
            empty(StatusCode::LOOP_DETECTED),
            Decision::Deny(Reason::Loop),
        ),
        Some(_) if !policy::is_valid_path(&path) => (
            empty(StatusCode::BAD_REQUEST),
            Decision::Deny(Reason::InvalidPath),
        ),
        Some(identity) if !state.policies.authorize(identity, &method, &path) => {
            (empty(StatusCode::FORBIDDEN), Decision::Deny(Reason::Policy))
        }
        Some(_) => {
            let response = match prepared {
                Ok(()) => {
                    let upstream_span = state.telemetry.start_upstream_span(
                        &upstream_parent,
                        method.as_str(),
                        &state.upstream,
                    );
                    trace_id = Telemetry::trace_id(&upstream_span);
                    match forward(&state, request, started, upstream_span).await {
                        Ok(response) => {
                            upstream_status = Some(response.status().as_u16());
                            response
                        }
                        Err(UpstreamFailure::Error) => bad_gateway(),
                        Err(UpstreamFailure::Timeout) => gateway_timeout(),
                        Err(UpstreamFailure::ClientTimeout) => empty(StatusCode::REQUEST_TIMEOUT),
                        Err(UpstreamFailure::RequestTooLarge) => {
                            empty(StatusCode::PAYLOAD_TOO_LARGE)
                        }
                        Err(UpstreamFailure::ResponseTooLarge {
                            upstream_status: status,
                        }) => {
                            upstream_status = Some(status);
                            bad_gateway()
                        }
                    }
                }
                Err(err) => {
                    warn!(%err, "cannot make the upstream URI");
                    bad_gateway()
                }
            };
            (response, Decision::Allow)
        }
    };
    audit::record(&Event {
        request_id: request_id.to_str().unwrap_or_default(),
        identity: identity.as_deref(),
        certificate: certificate.as_deref(),
        method: &method,
        path: &path,
        host: host.as_deref(),
        decision,
        status: response.status().as_u16(),
        upstream_status,
        trace_id: trace_id.as_deref(),
        latency_ms: started.elapsed().as_millis() as u64,
    });
    span.record("http.response.status_code", response.status().as_u16());
    response
        .headers_mut()
        .insert(headers::REQUEST_ID, request_id);
    Ok(response)
}

/// Change `request` so that it is ready for the upstream at `upstream`
/// (a `host:port` address). `client_ip` is the IP address of the client.
///
/// Keep the method, the path, the query and the body. Change the rest as a
/// proxy must:
///
/// - Send the request to the upstream, as HTTP/1.
/// - Remove the hop-by-hop headers.
/// - Remove each request header that is not on the list of allowed headers.
/// - Replace the forwarding headers (`X-Forwarded-*`), and add `via_name` to `Via`.
/// - Set `Host` to the address of the upstream.
///
/// Keep the headers on the list of allowed headers.
/// Return an error if the URI for the upstream is not valid.
#[instrument(name = "header_filtering", skip_all)]
fn prepare_request<B>(
    request: &mut Request<B>,
    upstream: &str,
    client_ip: IpAddr,
    via_name: &str,
) -> Result<(), InvalidUri> {
    // The host that the client asked for. An HTTP/2 request has no `Host`
    // header, but its URI has the authority.
    let original_host = request.headers().get(HOST).cloned().or_else(|| {
        request
            .uri()
            .authority()
            .and_then(|authority| HeaderValue::from_str(authority.as_str()).ok())
    });
    let client_version = request.version();

    let path_and_query = request
        .uri()
        .path_and_query()
        .map_or("/", |path_and_query| path_and_query.as_str());
    let uri = format!("http://{upstream}{path_and_query}").parse::<Uri>()?;
    *request.uri_mut() = uri;
    // The connection to the upstream is HTTP/1, also when the client uses HTTP/2.
    *request.version_mut() = Version::HTTP_11;
    let request_headers = request.headers_mut();
    headers::remove_hop_by_hop(request_headers);
    headers::retain_allowed_request(request_headers);
    headers::set_forwarding(
        request_headers,
        client_ip,
        original_host.as_ref(),
        // Every client connection uses TLS.
        "https",
        client_version,
        via_name,
    );
    headers::set_host(request_headers, upstream);
    Ok(())
}

/// Why the proxy has no response from the upstream.
enum UpstreamFailure {
    /// The connection or the request failed.
    Error,
    /// The upstream did not send a response head within `timeouts.upstream`.
    Timeout,
    /// The client did not send the request body within `timeouts.client`.
    ClientTimeout,
    /// The request body is larger than `limits.request`.
    RequestTooLarge,
    /// The response body is larger than `limits.response`. The proxy knew this
    /// from the head, so it sent nothing to the client.
    ResponseTooLarge { upstream_status: u16 },
}

/// Send the prepared `request` to the upstream and return the response, with
/// the hop-by-hop headers removed. Stream the body of the response.
///
/// `span` is the context that has the span of this request. Set `traceparent`
/// and `tracestate` from it, and end it when the response head arrives or the
/// request fails. `started` is the time that the proxy began to handle the
/// request.
///
/// Wait at most `timeouts.upstream` for the response head. The time includes
/// the connection and the sending of the request. It does not include the body
/// of the response. The client must also send the request body before
/// `started + timeouts.client`. If something fails, log it, count a timeout,
/// and return the reason.
async fn forward<B>(
    state: &AppState<B>,
    request: Request<B>,
    started: Instant,
    span: Context,
) -> Result<Response<Body>, UpstreamFailure>
where
    B: RequestBody + Send + Unpin + 'static,
    B::Data: Send,
    B::Error: Into<Box<dyn Error + Send + Sync>>,
{
    let telemetry = &state.telemetry;
    let (mut parts, body) = request.into_parts();
    // A body with a length that is too large: do not connect to the upstream.
    if let Some(limit) = state.limits.request
        && body.size_hint().lower() > limit
    {
        warn!(limit, "the request body is larger than the limit");
        telemetry.end_span(&span, SpanOutcome::BodyTooLarge);
        return Err(UpstreamFailure::RequestTooLarge);
    }
    telemetry.inject(&span, &mut parts.headers);
    let body = LimitBody::new(body, state.limits.request);
    let request_too_large = body.exceeded_flag();
    let body = DeadlineBody::new(
        body,
        tokio::time::Instant::from_std(started + state.timeouts.client),
    );
    let client_expired = body.expired_flag();
    let request = Request::from_parts(parts, body);

    let result = timeout(state.timeouts.upstream, state.client.request(request)).await;
    // The client is slow: the failure is not the fault of the upstream.
    if client_expired.load(Ordering::SeqCst) {
        warn!(
            timeout_secs = state.timeouts.client.as_secs(),
            "the client did not send the request body in time"
        );
        telemetry.record_timeout(TimeoutKind::ClientBody);
        telemetry.end_span(&span, SpanOutcome::ClientTimeout);
        return Err(UpstreamFailure::ClientTimeout);
    }
    // The body was too large: the request to the upstream stopped, and the
    // client gets `413`.
    if request_too_large.load(Ordering::SeqCst) {
        warn!(
            limit = state.limits.request,
            "the request body is larger than the limit"
        );
        telemetry.end_span(&span, SpanOutcome::BodyTooLarge);
        return Err(UpstreamFailure::RequestTooLarge);
    }
    match result {
        Ok(Ok(response)) => {
            let status = response.status().as_u16();
            let (mut parts, body) = response.into_parts();
            // A body with a length that is too large: send nothing of it. The
            // proxy drops the response, and this closes the upstream connection.
            if let Some(limit) = state.limits.response
                && body.size_hint().lower() > limit
            {
                warn!(limit, "the response body is larger than the limit");
                telemetry.end_span(&span, SpanOutcome::BodyTooLarge);
                return Err(UpstreamFailure::ResponseTooLarge {
                    upstream_status: status,
                });
            }
            telemetry.end_span(&span, SpanOutcome::Response(status));
            headers::remove_hop_by_hop(&mut parts.headers);
            // The proxy already has the head, so a body that grows too large
            // can only stop the stream. hyper then closes the connection to
            // the upstream, and the client sees an incomplete response.
            let body = LimitBody::new(body, state.limits.response)
                .map_err(|err| {
                    if let Some(too_large) = err.downcast_ref::<BodyTooLarge>() {
                        warn!(
                            limit = too_large.limit,
                            "the response body is larger than the limit"
                        );
                    }
                    err
                })
                .boxed_unsync();
            Ok(Response::from_parts(parts, body))
        }
        Ok(Err(err)) => {
            warn!(%err, "request to the upstream failed");
            telemetry.end_span(&span, SpanOutcome::Failed);
            Err(UpstreamFailure::Error)
        }
        Err(_) => {
            warn!(
                timeout_secs = state.timeouts.upstream.as_secs(),
                "the upstream did not answer in time"
            );
            telemetry.record_timeout(TimeoutKind::Upstream);
            telemetry.end_span(&span, SpanOutcome::UpstreamTimeout);
            Err(UpstreamFailure::Timeout)
        }
    }
}

/// The answer for a request that the proxy does not forward. The response has
/// the given `status` and an empty body.
fn empty(status: StatusCode) -> Response<Body> {
    let body = Empty::<Bytes>::new()
        .map_err(|never| match never {})
        .boxed_unsync();
    let mut response = Response::new(body);
    *response.status_mut() = status;
    response
}

/// The answer when the upstream does not send a response in time.
/// The body has no detail. The detail is in the log.
fn gateway_timeout() -> Response<Body> {
    let body = Full::new(Bytes::from_static(b"Gateway Timeout"))
        .map_err(|never| match never {})
        .boxed_unsync();
    let mut response = Response::new(body);
    *response.status_mut() = StatusCode::GATEWAY_TIMEOUT;
    response
}

/// The answer for a failure between the proxy and the upstream.
/// The body has no detail. The detail is in the log.
fn bad_gateway() -> Response<Body> {
    let body = Full::new(Bytes::from_static(b"Bad Gateway"))
        .map_err(|never| match never {})
        .boxed_unsync();
    let mut response = Response::new(body);
    *response.status_mut() = StatusCode::BAD_GATEWAY;
    response
}

#[cfg(test)]
mod tests {
    use super::*;

    /// An upstream address that is not valid, so `prepare_request` fails.
    /// `handle` then returns at once. It makes no connection and opens no socket.
    const BAD_UPSTREAM: &str = "not a valid address";

    const PAYMENT_AGENT: &str = "spiffe://acme/prod/payment-agent";

    fn timeouts(client: Duration, upstream: Duration) -> Timeouts {
        Timeouts { client, upstream }
    }

    fn no_limits() -> Limits {
        Limits {
            request: None,
            response: None,
        }
    }

    /// The policy for the tests: `payment-agent` may `GET` and `POST` `/path`.
    fn policies() -> Policies {
        let yaml = format!(
            "policies:\n- identity: \"{PAYMENT_AGENT}\"\n  allow:\n  - method: GET\n    path: \"/path\"\n  - method: POST\n    path: \"/path\"\n"
        );
        serde_saphyr::from_str(&yaml).unwrap()
    }

    /// Call `handle` as an allowed client (`payment-agent`, `GET /path?x=1`).
    async fn call(headers: &[(&str, &str)]) -> Response<Body> {
        call_as(Some(PAYMENT_AGENT), "/path?x=1", headers).await
    }

    /// Call `handle` with the given identity (a SPIFFE ID), URI and headers.
    async fn call_as(
        identity: Option<&str>,
        uri: &str,
        headers: &[(&str, &str)],
    ) -> Response<Body> {
        let identity = identity.map(|id| id.parse::<Identity>().unwrap());
        let state = Arc::new(AppState::<Full<Bytes>>::new(
            BAD_UPSTREAM,
            policies(),
            timeouts(Duration::from_secs(5), Duration::from_secs(5)),
            no_limits(),
            Arc::new(Telemetry::without_export()),
        ));
        let mut request = Request::builder().uri(uri);
        for (name, value) in headers {
            request = request.header(*name, *value);
        }
        let request = request.body(Full::new(Bytes::new())).unwrap();

        match handle(state, "192.0.2.7".parse().unwrap(), identity, None, request).await {
            Ok(response) => response,
            Err(never) => match never {},
        }
    }

    /// Check that the response has `status`, a request ID and an empty body.
    async fn assert_rejection(response: Response<Body>, status: StatusCode) {
        assert_eq!(response.status(), status);
        assert_eq!(response.headers()["x-request-id"].len(), 36);
        let body = response.into_body().collect().await.unwrap().to_bytes();
        assert!(body.is_empty());
    }

    #[tokio::test]
    async fn handle_returns_502_when_the_upstream_uri_is_not_valid() {
        let response = call(&[]).await;

        assert_eq!(response.status(), StatusCode::BAD_GATEWAY);
        let body = response.into_body().collect().await.unwrap().to_bytes();
        assert_eq!(&body[..], b"Bad Gateway");
    }

    #[tokio::test]
    async fn handle_returns_401_without_a_valid_identity() {
        let response = call_as(None, "/path", &[]).await;

        assert_rejection(response, StatusCode::UNAUTHORIZED).await;
    }

    #[tokio::test]
    async fn handle_returns_403_for_a_path_that_the_policy_does_not_allow() {
        let response = call_as(Some(PAYMENT_AGENT), "/other", &[]).await;

        assert_rejection(response, StatusCode::FORBIDDEN).await;
    }

    #[tokio::test]
    async fn handle_returns_403_for_an_identity_without_a_policy() {
        let response = call_as(Some("spiffe://acme/prod/other-agent"), "/path", &[]).await;

        assert_rejection(response, StatusCode::FORBIDDEN).await;
    }

    #[tokio::test]
    async fn handle_returns_508_for_a_request_that_has_the_name_of_the_proxy_in_via() {
        let state = Arc::new(AppState::<Full<Bytes>>::new(
            BAD_UPSTREAM,
            policies(),
            timeouts(Duration::from_secs(5), Duration::from_secs(5)),
            no_limits(),
            Arc::new(Telemetry::without_export()),
        ));
        let via = format!("1.1 other, 1.1 {}", state.via_name);
        let request = Request::builder()
            .uri("/path")
            .header("via", via)
            .body(Full::new(Bytes::new()))
            .unwrap();
        let identity = Some(PAYMENT_AGENT.parse::<Identity>().unwrap());

        let response =
            match handle(state, "192.0.2.7".parse().unwrap(), identity, None, request).await {
                Ok(response) => response,
                Err(never) => match never {},
            };

        assert_rejection(response, StatusCode::LOOP_DETECTED).await;
    }

    #[tokio::test]
    async fn handle_does_not_stop_a_request_that_has_the_name_of_another_proxy_in_via() {
        let response = call(&[("via", "1.1 reverse-proxy-00000000")]).await;

        // The upstream address is not valid in this test, so the answer is 502.
        assert_eq!(response.status(), StatusCode::BAD_GATEWAY);
    }

    #[tokio::test]
    async fn handle_returns_400_for_a_path_that_is_not_valid() {
        let response = call_as(Some(PAYMENT_AGENT), "/path/%2e%2e/other", &[]).await;

        assert_rejection(response, StatusCode::BAD_REQUEST).await;
    }

    #[tokio::test]
    async fn handle_keeps_a_valid_request_id_in_the_response() {
        let response = call(&[("x-request-id", "client-id-1")]).await;

        assert_eq!(response.headers()["x-request-id"], "client-id-1");
    }

    #[tokio::test]
    async fn handle_makes_a_request_id_when_there_is_none() {
        let response = call(&[]).await;

        assert_eq!(response.headers()["x-request-id"].len(), 36);
    }

    // --- Spans, trace context and timeouts ---

    use opentelemetry::trace::Status;
    use opentelemetry_sdk::metrics::InMemoryMetricExporter;
    use opentelemetry_sdk::metrics::SdkMeterProvider;
    use opentelemetry_sdk::metrics::data::AggregatedMetrics;
    use opentelemetry_sdk::metrics::data::MetricData;
    use opentelemetry_sdk::trace::InMemorySpanExporter;
    use opentelemetry_sdk::trace::SdkTracerProvider;
    use std::future::Future;
    use tokio::io::AsyncReadExt;
    use tokio::io::AsyncWriteExt;
    use tokio::net::TcpListener;

    const TRACE_ID: &str = "0af7651916cd43dd8448eb211c80319c";
    const PARENT_SPAN_ID: &str = "b7ad6b7169203331";

    /// Telemetry that keeps spans and metrics in memory.
    struct Observed {
        telemetry: Arc<Telemetry>,
        spans: InMemorySpanExporter,
        metrics: InMemoryMetricExporter,
        meter_provider: SdkMeterProvider,
    }

    fn observed() -> Observed {
        let spans = InMemorySpanExporter::default();
        let metrics = InMemoryMetricExporter::default();
        let tracer_provider = SdkTracerProvider::builder()
            .with_simple_exporter(spans.clone())
            .build();
        let meter_provider = SdkMeterProvider::builder()
            .with_periodic_exporter(metrics.clone())
            .build();
        Observed {
            telemetry: Arc::new(Telemetry::with_providers(
                tracer_provider,
                meter_provider.clone(),
            )),
            spans,
            metrics,
            meter_provider,
        }
    }

    impl Observed {
        /// How many timeouts of `kind` the counter has.
        fn timeouts(&self, kind: &str) -> u64 {
            self.meter_provider.force_flush().unwrap();
            let mut total = 0;
            for resource in self.metrics.get_finished_metrics().unwrap() {
                for scope in resource.scope_metrics() {
                    for metric in scope.metrics() {
                        if metric.name() != "reverse_proxy.timeouts" {
                            continue;
                        }
                        let AggregatedMetrics::U64(MetricData::Sum(sum)) = metric.data() else {
                            panic!("the counter is not a sum of u64");
                        };
                        for point in sum.data_points() {
                            let has_kind = point.attributes().any(|attribute| {
                                attribute.key.as_str() == "timeout.kind"
                                    && attribute.value.as_str() == kind
                            });
                            if has_kind {
                                // The exporter keeps each export. Use the last one.
                                total = point.value();
                            }
                        }
                    }
                }
            }
            total
        }
    }

    /// A web server that answers `200` to one request. It sends the request
    /// head that it got to the returned channel.
    async fn answering_upstream() -> (String, tokio::sync::oneshot::Receiver<String>) {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap().to_string();
        let (sender, receiver) = tokio::sync::oneshot::channel();
        tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            let mut head = Vec::new();
            let mut buffer = [0u8; 1024];
            while !head.windows(4).any(|window| window == b"\r\n\r\n") {
                let read = stream.read(&mut buffer).await.unwrap();
                if read == 0 {
                    break;
                }
                head.extend_from_slice(&buffer[..read]);
            }
            let _ = sender.send(String::from_utf8_lossy(&head).into_owned());
            let _ = stream
                .write_all(b"HTTP/1.1 200 OK\r\ncontent-length: 0\r\nconnection: close\r\n\r\n")
                .await;
        });
        (address, receiver)
    }

    /// A listener that the kernel accepts connections on, and that never answers.
    async fn silent_upstream() -> (String, TcpListener) {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        (listener.local_addr().unwrap().to_string(), listener)
    }

    async fn call_handle<B>(state: Arc<AppState<B>>, request: Request<B>) -> Response<Body>
    where
        B: RequestBody + Send + Unpin + 'static,
        B::Data: Send,
        B::Error: Into<Box<dyn Error + Send + Sync>>,
    {
        let identity = Some(PAYMENT_AGENT.parse::<Identity>().unwrap());
        match handle(state, "192.0.2.7".parse().unwrap(), identity, None, request).await {
            Ok(response) => response,
            Err(never) => match never {},
        }
    }

    fn state_for<B>(upstream: &str, observed: &Observed, timeouts: Timeouts) -> Arc<AppState<B>>
    where
        B: RequestBody + Send + Unpin + 'static,
        B::Data: Send,
        B::Error: Into<Box<dyn Error + Send + Sync>>,
    {
        state_with_limits(upstream, observed, timeouts, no_limits())
    }

    fn state_with_limits<B>(
        upstream: &str,
        observed: &Observed,
        timeouts: Timeouts,
        limits: Limits,
    ) -> Arc<AppState<B>>
    where
        B: RequestBody + Send + Unpin + 'static,
        B::Data: Send,
        B::Error: Into<Box<dyn Error + Send + Sync>>,
    {
        Arc::new(AppState::new(
            upstream,
            policies(),
            timeouts,
            limits,
            observed.telemetry.clone(),
        ))
    }

    fn get_with(headers: &[(&str, &str)]) -> Request<Full<Bytes>> {
        let mut request = Request::builder().uri("/path?secret=1");
        for (name, value) in headers {
            request = request.header(*name, *value);
        }
        request.body(Full::new(Bytes::new())).unwrap()
    }

    /// The value of the `traceparent` header in a request head, if any.
    fn traceparent_of(head: &str) -> Option<String> {
        head.lines()
            .find_map(|line| line.strip_prefix("traceparent: "))
            .map(str::to_string)
    }

    #[tokio::test]
    async fn handle_keeps_the_trace_id_of_the_client_and_makes_a_span() {
        let observed = observed();
        let (upstream, head) = answering_upstream().await;
        let state = state_for(
            &upstream,
            &observed,
            timeouts(Duration::from_secs(5), Duration::from_secs(5)),
        );
        let traceparent = format!("00-{TRACE_ID}-{PARENT_SPAN_ID}-01");
        let request = get_with(&[("traceparent", &traceparent), ("tracestate", "a=b")]);

        let response = call_handle(state, request).await;

        assert_eq!(response.status(), StatusCode::OK);
        let sent = traceparent_of(&head.await.unwrap()).expect("no traceparent for the upstream");
        // Same trace, new span: the upstream sees the span of the proxy.
        assert!(sent.starts_with(&format!("00-{TRACE_ID}-")), "got: {sent}");
        assert!(!sent.contains(PARENT_SPAN_ID), "got: {sent}");
        let spans = observed.spans.get_finished_spans().unwrap();
        assert_eq!(spans.len(), 1);
        let span = &spans[0];
        assert_eq!(span.name, "upstream request");
        assert_eq!(span.span_context.trace_id().to_string(), TRACE_ID);
        assert_eq!(span.parent_span_id.to_string(), PARENT_SPAN_ID);
        assert!(sent.contains(&span.span_context.span_id().to_string()));
        let attribute = |name: &str| {
            span.attributes
                .iter()
                .find(|attribute| attribute.key.as_str() == name)
                .map(|attribute| attribute.value.to_string())
        };
        assert_eq!(attribute("http.request.method").as_deref(), Some("GET"));
        assert_eq!(
            attribute("http.response.status_code").as_deref(),
            Some("200")
        );
        // The span never has the query or a header.
        for attribute in &span.attributes {
            assert!(!attribute.value.to_string().contains("secret"));
        }
    }

    #[tokio::test]
    async fn handle_starts_a_new_trace_when_the_client_sends_none_or_a_bad_one() {
        for traceparent in [
            None,
            Some("not-a-traceparent"),
            Some("00-00000000000000000000000000000000-0000000000000000-01"),
        ] {
            let observed = observed();
            let (upstream, head) = answering_upstream().await;
            let state = state_for(
                &upstream,
                &observed,
                timeouts(Duration::from_secs(5), Duration::from_secs(5)),
            );
            let headers: Vec<(&str, &str)> = traceparent
                .map(|value| vec![("traceparent", value)])
                .unwrap_or_default();

            call_handle(state, get_with(&headers)).await;

            let sent = traceparent_of(&head.await.unwrap()).expect("no traceparent");
            let spans = observed.spans.get_finished_spans().unwrap();
            let trace_id = spans[0].span_context.trace_id().to_string();
            assert_eq!(trace_id.len(), 32);
            assert_ne!(trace_id, "0".repeat(32));
            assert!(sent.starts_with(&format!("00-{trace_id}-")), "got: {sent}");
            assert!(
                !spans[0]
                    .parent_span_id
                    .to_string()
                    .chars()
                    .any(|c| c != '0')
            );
        }
    }

    #[tokio::test]
    async fn handle_returns_504_and_counts_a_timeout_when_the_upstream_is_silent() {
        let observed = observed();
        let (upstream, _listener) = silent_upstream().await;
        let state = state_for(
            &upstream,
            &observed,
            timeouts(Duration::from_secs(5), Duration::from_millis(100)),
        );

        let response = call_handle(state, get_with(&[])).await;

        assert_eq!(response.status(), StatusCode::GATEWAY_TIMEOUT);
        assert_eq!(observed.timeouts("upstream"), 1);
        assert_eq!(observed.timeouts("client_body"), 0);
        let spans = observed.spans.get_finished_spans().unwrap();
        assert_eq!(spans.len(), 1);
        assert!(matches!(spans[0].status, Status::Error { .. }));
        assert!(
            spans[0]
                .attributes
                .iter()
                .any(|a| a.key.as_str() == "error.type" && a.value.to_string() == "timeout")
        );
    }

    /// A request body that never sends a frame.
    struct StalledBody;

    impl hyper::body::Body for StalledBody {
        type Data = Bytes;
        type Error = std::convert::Infallible;

        fn poll_frame(
            self: std::pin::Pin<&mut Self>,
            _cx: &mut std::task::Context<'_>,
        ) -> std::task::Poll<Option<Result<hyper::body::Frame<Bytes>, Self::Error>>> {
            std::task::Poll::Pending
        }
    }

    #[tokio::test]
    async fn handle_returns_408_and_counts_a_timeout_when_the_client_body_is_too_slow() {
        let observed = observed();
        let (upstream, _listener) = silent_upstream().await;
        let state = state_for::<StalledBody>(
            &upstream,
            &observed,
            timeouts(Duration::from_millis(100), Duration::from_secs(5)),
        );
        // `hyper` does not send the body of a `GET` request, so use `POST`.
        let request = Request::builder()
            .method("POST")
            .uri("/path")
            .body(StalledBody)
            .unwrap();

        let response = call_handle(state, request).await;

        assert_eq!(response.status(), StatusCode::REQUEST_TIMEOUT);
        assert_eq!(observed.timeouts("client_body"), 1);
        assert_eq!(observed.timeouts("upstream"), 0);
    }

    /// The limit in bytes for the body tests.
    const LIMIT: u64 = 1024;

    fn limits(request: Option<u64>, response: Option<u64>) -> Limits {
        Limits { request, response }
    }

    /// A request body of two frames. It has no length, as a chunked body.
    struct TwoFrames {
        frames: usize,
        size: usize,
    }

    impl hyper::body::Body for TwoFrames {
        type Data = Bytes;
        type Error = std::convert::Infallible;

        fn poll_frame(
            mut self: std::pin::Pin<&mut Self>,
            _cx: &mut std::task::Context<'_>,
        ) -> std::task::Poll<Option<Result<hyper::body::Frame<Bytes>, Self::Error>>> {
            if self.frames == 0 {
                return std::task::Poll::Ready(None);
            }
            self.frames -= 1;
            let data = Bytes::from(vec![b'x'; self.size]);
            std::task::Poll::Ready(Some(Ok(hyper::body::Frame::data(data))))
        }
    }

    /// A web server that reads one connection until the client closes it. It
    /// sends the number of bytes that it read to the returned channel.
    async fn draining_upstream() -> (String, tokio::sync::oneshot::Receiver<usize>) {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap().to_string();
        let (sender, receiver) = tokio::sync::oneshot::channel();
        tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            let mut total = 0;
            let mut buffer = [0u8; 1024];
            loop {
                match stream.read(&mut buffer).await {
                    Ok(0) | Err(_) => break,
                    Ok(read) => total += read,
                }
            }
            let _ = sender.send(total);
        });
        (address, receiver)
    }

    /// A web server that reads the request head, writes `response`, and closes
    /// the connection.
    async fn scripted_upstream(response: Vec<u8>) -> String {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap().to_string();
        tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            let mut head = Vec::new();
            let mut buffer = [0u8; 1024];
            while !head.windows(4).any(|window| window == b"\r\n\r\n") {
                let read = stream.read(&mut buffer).await.unwrap();
                if read == 0 {
                    break;
                }
                head.extend_from_slice(&buffer[..read]);
            }
            let _ = stream.write_all(&response).await;
        });
        address
    }

    fn post_with<B>(body: B) -> Request<B> {
        Request::builder()
            .method("POST")
            .uri("/path")
            .body(body)
            .unwrap()
    }

    #[tokio::test]
    async fn handle_returns_413_for_a_request_with_a_length_above_the_limit() {
        let observed = observed();
        let (upstream, listener) = silent_upstream().await;
        let state = state_with_limits::<Full<Bytes>>(
            &upstream,
            &observed,
            timeouts(Duration::from_secs(5), Duration::from_secs(5)),
            limits(Some(LIMIT), None),
        );
        let request = post_with(Full::new(Bytes::from(vec![b'x'; LIMIT as usize + 1])));

        let response = call_handle(state, request).await;

        assert_eq!(response.status(), StatusCode::PAYLOAD_TOO_LARGE);
        // The proxy knew the length, so it never connected to the upstream.
        let accepted = timeout(Duration::from_millis(200), listener.accept()).await;
        assert!(accepted.is_err(), "the proxy connected to the upstream");
    }

    #[tokio::test]
    async fn handle_forwards_a_request_of_exactly_the_limit() {
        let observed = observed();
        let (upstream, _head) = answering_upstream().await;
        let state = state_with_limits::<Full<Bytes>>(
            &upstream,
            &observed,
            timeouts(Duration::from_secs(5), Duration::from_secs(5)),
            limits(Some(LIMIT), None),
        );
        let request = post_with(Full::new(Bytes::from(vec![b'x'; LIMIT as usize])));

        let response = call_handle(state, request).await;

        assert_eq!(response.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn handle_returns_413_and_closes_the_upstream_when_a_streamed_request_grows_too_large() {
        let observed = observed();
        let (upstream, drained) = draining_upstream().await;
        let state = state_with_limits::<TwoFrames>(
            &upstream,
            &observed,
            timeouts(Duration::from_secs(5), Duration::from_secs(5)),
            limits(Some(LIMIT), None),
        );
        // 2 frames of 600 bytes: 1200 bytes, and no length.
        let request = post_with(TwoFrames {
            frames: 2,
            size: 600,
        });

        let response = call_handle(state, request).await;

        assert_eq!(response.status(), StatusCode::PAYLOAD_TOO_LARGE);
        // The upstream connection closes. The upstream did not get the whole body.
        let total = timeout(Duration::from_secs(2), drained)
            .await
            .expect("the upstream connection stayed open")
            .unwrap();
        assert!(total < 1200, "the upstream got {total} bytes");
    }

    #[tokio::test]
    async fn handle_forwards_a_large_request_when_the_limit_is_off() {
        let observed = observed();
        let (upstream, _head) = answering_upstream().await;
        let state = state_with_limits::<Full<Bytes>>(
            &upstream,
            &observed,
            timeouts(Duration::from_secs(5), Duration::from_secs(5)),
            limits(None, None),
        );
        let request = post_with(Full::new(Bytes::from(vec![b'x'; 4 * LIMIT as usize])));

        let response = call_handle(state, request).await;

        assert_eq!(response.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn handle_returns_502_for_a_response_with_a_length_above_the_limit() {
        let observed = observed();
        let upstream = scripted_upstream(
            format!(
                "HTTP/1.1 200 OK\r\ncontent-length: {}\r\nconnection: close\r\n\r\n",
                LIMIT + 1
            )
            .into_bytes(),
        )
        .await;
        let state = state_with_limits::<Full<Bytes>>(
            &upstream,
            &observed,
            timeouts(Duration::from_secs(5), Duration::from_secs(5)),
            limits(None, Some(LIMIT)),
        );

        let response = call_handle(state, get_with(&[])).await;

        assert_eq!(response.status(), StatusCode::BAD_GATEWAY);
    }

    #[tokio::test]
    async fn handle_stops_a_streamed_response_that_grows_too_large() {
        let observed = observed();
        // A chunked response of 2 chunks of 600 bytes (0x258): 1200 bytes.
        let chunk = "x".repeat(600);
        let upstream = scripted_upstream(
            format!(
                "HTTP/1.1 200 OK\r\ntransfer-encoding: chunked\r\nconnection: close\r\n\r\n258\r\n{chunk}\r\n258\r\n{chunk}\r\n0\r\n\r\n"
            )
            .into_bytes(),
        )
        .await;
        let state = state_with_limits::<Full<Bytes>>(
            &upstream,
            &observed,
            timeouts(Duration::from_secs(5), Duration::from_secs(5)),
            limits(None, Some(LIMIT)),
        );

        let response = call_handle(state, get_with(&[])).await;

        // The head is already sent, so the status stays `200`. The body fails.
        assert_eq!(response.status(), StatusCode::OK);
        let err = response.into_body().collect().await.unwrap_err();
        assert!(err.downcast_ref::<BodyTooLarge>().is_some(), "got: {err}");
    }

    #[tokio::test]
    async fn handle_forwards_a_response_of_exactly_the_limit() {
        let observed = observed();
        let body = "x".repeat(LIMIT as usize);
        let upstream = scripted_upstream(
            format!(
                "HTTP/1.1 200 OK\r\ncontent-length: {LIMIT}\r\nconnection: close\r\n\r\n{body}"
            )
            .into_bytes(),
        )
        .await;
        let state = state_with_limits::<Full<Bytes>>(
            &upstream,
            &observed,
            timeouts(Duration::from_secs(5), Duration::from_secs(5)),
            limits(None, Some(LIMIT)),
        );

        let response = call_handle(state, get_with(&[])).await;

        assert_eq!(response.status(), StatusCode::OK);
        let bytes = response.into_body().collect().await.unwrap().to_bytes();
        assert_eq!(bytes.len(), LIMIT as usize);
    }

    /// A request body that sends one frame and then waits for `gate`. It has
    /// no length.
    struct GatedBody {
        sent_first: bool,
        gate: tokio::sync::oneshot::Receiver<()>,
    }

    impl hyper::body::Body for GatedBody {
        type Data = Bytes;
        type Error = std::convert::Infallible;

        fn poll_frame(
            mut self: std::pin::Pin<&mut Self>,
            cx: &mut std::task::Context<'_>,
        ) -> std::task::Poll<Option<Result<hyper::body::Frame<Bytes>, Self::Error>>> {
            if !self.sent_first {
                self.sent_first = true;
                let data = Bytes::from_static(b"FIRSTCHUNK");
                return std::task::Poll::Ready(Some(Ok(hyper::body::Frame::data(data))));
            }
            match std::pin::Pin::new(&mut self.gate).poll(cx) {
                std::task::Poll::Ready(_) => std::task::Poll::Ready(None),
                std::task::Poll::Pending => std::task::Poll::Pending,
            }
        }
    }

    #[tokio::test]
    async fn handle_sends_the_request_body_to_the_upstream_while_the_client_still_sends() {
        let observed = observed();
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let upstream = listener.local_addr().unwrap().to_string();
        let (seen_sender, seen_receiver) = tokio::sync::oneshot::channel();
        tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            let mut received = Vec::new();
            let mut buffer = [0u8; 1024];
            while !String::from_utf8_lossy(&received).contains("FIRSTCHUNK") {
                let read = stream.read(&mut buffer).await.unwrap();
                if read == 0 {
                    break;
                }
                received.extend_from_slice(&buffer[..read]);
            }
            let _ = seen_sender.send(());
            let _ = stream
                .write_all(b"HTTP/1.1 200 OK\r\ncontent-length: 0\r\nconnection: close\r\n\r\n")
                .await;
        });
        let state = state_for::<GatedBody>(
            &upstream,
            &observed,
            timeouts(Duration::from_secs(5), Duration::from_secs(5)),
        );
        // The gate stays closed: the client never finishes the body.
        let (_gate_sender, gate) = tokio::sync::oneshot::channel();
        let request = post_with(GatedBody {
            sent_first: false,
            gate,
        });

        let call = tokio::spawn(call_handle(state, request));

        timeout(Duration::from_secs(2), seen_receiver)
            .await
            .expect("the upstream did not get the first chunk while the body was open")
            .unwrap();
        call.abort();
    }

    #[tokio::test]
    async fn a_slow_request_head_gives_a_hyper_timeout_error() {
        // The same builder settings as `serve`. `spawn_connection` counts the
        // error only if it is a `hyper::Error` with `is_timeout`.
        let mut builder = Builder::new(TokioExecutor::new());
        builder
            .http1()
            .timer(TokioTimer::new())
            .header_read_timeout(Duration::from_millis(100));
        let (mut client, server) = tokio::io::duplex(1024);
        let service = service_fn(|_request: Request<hyper::body::Incoming>| async {
            Ok::<_, Infallible>(Response::new(Full::new(Bytes::new())))
        });
        client
            .write_all(b"GET / HTTP/1.1\r\nHost: x\r\n")
            .await
            .unwrap();

        let result = builder
            .serve_connection(TokioIo::new(server), service)
            .await;

        let err = result.expect_err("the connection must fail");
        assert!(
            err.downcast_ref::<hyper::Error>()
                .is_some_and(hyper::Error::is_timeout),
            "got: {err:?}"
        );
    }
}
