//! The `proxy` mode: send each request to one upstream and return its response.
//!
//! This mode has its own accept loop. It does not share code with the `server` mode.

use crate::SERVER_ADDR;
use crate::headers;
use crate::state::AppState;
use bytes::Bytes;
use http_body_util::BodyExt;
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
use hyper_util::server::conn::auto::Builder;
use hyper_util::server::graceful::GracefulShutdown;
use std::convert::Infallible;
use std::error::Error;
use std::net::IpAddr;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;
use std::time::Instant;
use tokio::net::TcpListener;
use tokio::net::TcpStream;
use tokio::time::timeout;
use tokio_rustls::TlsAcceptor;
use tokio_util::sync::CancellationToken;
use tracing::debug;
use tracing::info;
use tracing::warn;

/// Maximum time to wait for open connections to finish after a shutdown request.
const SHUTDOWN_TIMEOUT: Duration = Duration::from_secs(10);

/// Maximum time for the TLS handshake of one connection.
const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(10);

/// The type of every response body. The answer from the upstream and our own
/// error answer have different body types, so both are boxed.
type Body = UnsyncBoxBody<Bytes, hyper::Error>;

/// Accept connections on `listener` until `shutdown` is cancelled.
/// Every connection uses TLS: `acceptor` does the handshake.
///
/// After that, stop accepting and wait for open connections to finish.
/// Stop waiting after `SHUTDOWN_TIMEOUT`.
pub async fn serve(listener: TcpListener, shutdown: CancellationToken, acceptor: TlsAcceptor) {
    // The upstream is the `server` mode.
    let state = Arc::new(AppState::new(SERVER_ADDR.as_str()));
    info!(upstream = %state.upstream, "sending requests to the upstream");
    let builder = Builder::new(TokioExecutor::new());
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
    tokio::spawn(async move {
        let stream = match timeout(HANDSHAKE_TIMEOUT, acceptor.accept(stream)).await {
            Ok(Ok(stream)) => stream,
            Ok(Err(err)) => {
                debug!(%peer, %err, "TLS handshake failed");
                return;
            }
            Err(_) => {
                debug!(%peer, "TLS handshake timed out");
                return;
            }
        };
        let client_ip = peer.ip();
        let service = service_fn(move |request| handle(state.clone(), client_ip, request));
        // The connection borrows `builder`, so create it inside the task.
        let connection = builder.serve_connection(TokioIo::new(stream), service);
        // `watch` tells the connection to finish its work when the shutdown starts.
        if let Err(err) = watcher.watch(connection).await {
            debug!(%peer, %err, "connection error");
        }
        debug!(%peer, "connection closed");
    });
}

/// Send `request` to the upstream of `state` and return the response.
/// `client_ip` is the IP address of the client.
///
/// Prepare the request, then forward it.
///
/// Every request has a request ID. The upstream gets it in the request, and the
/// client gets it in the response. Use the `X-Request-Id` of the client if it
/// is valid. Otherwise make a new one.
///
/// Never return an error: a failure becomes a `502 Bad Gateway` response.
async fn handle<B>(
    state: Arc<AppState<B>>,
    client_ip: IpAddr,
    mut request: Request<B>,
) -> Result<Response<Body>, Infallible>
where
    B: RequestBody + Send + Unpin + 'static,
    B::Data: Send,
    B::Error: Into<Box<dyn Error + Send + Sync>>,
{
    let started = Instant::now();
    // Keep the method and the path for the log line. Never log the query.
    let method = request.method().clone();
    let path = request.uri().path().to_string();
    let prepared = prepare_request(&mut request, &state.upstream, client_ip);
    // Do this after `prepare_request`. A `Connection` header from the client
    // can name `X-Request-Id`, and then `prepare_request` removes it.
    let request_id = headers::ensure_request_id(request.headers_mut());
    let mut response = match prepared {
        Ok(()) => forward(&state, request).await,
        Err(err) => {
            warn!(%err, "cannot make the upstream URI");
            bad_gateway()
        }
    };
    debug!(
        %method,
        %path,
        status = response.status().as_u16(),
        latency_ms = started.elapsed().as_millis() as u64,
        request_id = request_id.to_str().unwrap_or_default(),
        "request done"
    );
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
/// - Replace the forwarding headers (`X-Forwarded-*`, `Via`).
/// - Set `Host` to the address of the upstream.
///
/// Keep the other headers.
/// Return an error if the URI for the upstream is not valid.
fn prepare_request<B>(
    request: &mut Request<B>,
    upstream: &str,
    client_ip: IpAddr,
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
    headers::set_forwarding(
        request_headers,
        client_ip,
        original_host.as_ref(),
        // Every client connection uses TLS.
        "https",
        client_version,
    );
    headers::set_host(request_headers, upstream);
    Ok(())
}

/// Send the prepared `request` to the upstream and return the response, with
/// the hop-by-hop headers removed. Stream the body of the response.
/// If the upstream fails, return `502 Bad Gateway`.
async fn forward<B>(state: &AppState<B>, request: Request<B>) -> Response<Body>
where
    B: RequestBody + Send + Unpin + 'static,
    B::Data: Send,
    B::Error: Into<Box<dyn Error + Send + Sync>>,
{
    match state.client.request(request).await {
        Ok(response) => {
            let (mut parts, body) = response.into_parts();
            headers::remove_hop_by_hop(&mut parts.headers);
            Response::from_parts(parts, body.boxed_unsync())
        }
        Err(err) => {
            warn!(%err, "request to the upstream failed");
            bad_gateway()
        }
    }
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

    async fn call(headers: &[(&str, &str)]) -> Response<Body> {
        let state = Arc::new(AppState::<Full<Bytes>>::new(BAD_UPSTREAM));
        let mut request = Request::builder().uri("/path?x=1");
        for (name, value) in headers {
            request = request.header(*name, *value);
        }
        let request = request.body(Full::new(Bytes::new())).unwrap();

        match handle(state, "192.0.2.7".parse().unwrap(), request).await {
            Ok(response) => response,
            Err(never) => match never {},
        }
    }

    #[tokio::test]
    async fn handle_returns_502_when_the_upstream_uri_is_not_valid() {
        let response = call(&[]).await;

        assert_eq!(response.status(), StatusCode::BAD_GATEWAY);
        let body = response.into_body().collect().await.unwrap().to_bytes();
        assert_eq!(&body[..], b"Bad Gateway");
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
}
