//! The `proxy` mode: send each request to one upstream and return its response.
//!
//! This mode has its own accept loop. It does not share code with the `server` mode.

use crate::SERVER_ADDR;
use bytes::Bytes;
use http_body_util::BodyExt;
use http_body_util::Full;
use http_body_util::combinators::UnsyncBoxBody;
use hyper::Request;
use hyper::Response;
use hyper::StatusCode;
use hyper::Uri;
use hyper::Version;
use hyper::body::Incoming;
use hyper::service::service_fn;
use hyper_util::client::legacy::Client;
use hyper_util::client::legacy::connect::HttpConnector;
use hyper_util::rt::TokioExecutor;
use hyper_util::rt::TokioIo;
use hyper_util::server::conn::auto::Builder;
use hyper_util::server::graceful::GracefulShutdown;
use std::convert::Infallible;
use std::net::SocketAddr;
use std::time::Duration;
use tokio::net::TcpListener;
use tokio::net::TcpStream;
use tokio::time::timeout;
use tokio_util::sync::CancellationToken;
use tracing::debug;
use tracing::info;
use tracing::warn;

/// Address of the upstream (the `server` mode). The connection uses plain HTTP.
/// It is fixed for now.
const UPSTREAM_ADDR: &str = SERVER_ADDR;

/// Maximum time to wait for open connections to finish after a shutdown request.
const SHUTDOWN_TIMEOUT: Duration = Duration::from_secs(10);

/// The client that sends requests to the upstream.
type UpstreamClient = Client<HttpConnector, Incoming>;

/// The type of every response body. The answer from the upstream and our own
/// error answer have different body types, so both are boxed.
type Body = UnsyncBoxBody<Bytes, hyper::Error>;

/// Accept connections on `listener` until `shutdown` is cancelled.
///
/// After that, stop accepting and wait for open connections to finish.
/// Stop waiting after `SHUTDOWN_TIMEOUT`.
pub async fn serve(listener: TcpListener, shutdown: CancellationToken) {
    // One client for all requests. It keeps connections to the upstream open.
    let client: UpstreamClient = Client::builder(TokioExecutor::new()).build_http();
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
        spawn_connection(&builder, &graceful, stream, peer, client.clone());
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
fn spawn_connection(
    builder: &Builder<TokioExecutor>,
    graceful: &GracefulShutdown,
    stream: TcpStream,
    peer: SocketAddr,
    client: UpstreamClient,
) {
    let builder = builder.clone();
    let watcher = graceful.watcher();
    tokio::spawn(async move {
        let service = service_fn(move |request| handle(client.clone(), request));
        // The connection borrows `builder`, so create it inside the task.
        let connection = builder.serve_connection(TokioIo::new(stream), service);
        // `watch` tells the connection to finish its work when the shutdown starts.
        if let Err(err) = watcher.watch(connection).await {
            debug!(%peer, %err, "connection error");
        }
        debug!(%peer, "connection closed");
    });
}

/// Send `request` to the upstream and return the response.
///
/// Keep the method, the headers, the path and the query. Stream both bodies.
/// Never return an error: a failure becomes a `502 Bad Gateway` response.
async fn handle(
    client: UpstreamClient,
    mut request: Request<Incoming>,
) -> Result<Response<Body>, Infallible> {
    let path_and_query = request
        .uri()
        .path_and_query()
        .map_or("/", |path_and_query| path_and_query.as_str());
    let uri = match format!("http://{UPSTREAM_ADDR}{path_and_query}").parse::<Uri>() {
        Ok(uri) => uri,
        Err(err) => {
            warn!(%err, "cannot make the upstream URI");
            return Ok(bad_gateway());
        }
    };
    *request.uri_mut() = uri;
    // The connection to the upstream is HTTP/1, also when the client uses HTTP/2.
    *request.version_mut() = Version::HTTP_11;

    match client.request(request).await {
        Ok(response) => Ok(response.map(|body| body.boxed_unsync())),
        Err(err) => {
            warn!(%err, "request to the upstream failed");
            Ok(bad_gateway())
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
