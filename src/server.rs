use bytes::Bytes;
use http_body_util::BodyExt;
use http_body_util::Full;
use hyper::Request;
use hyper::Response;
use hyper::StatusCode;
use hyper::body::Incoming;
use hyper::service::service_fn;
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

/// Maximum time to wait for open connections to finish after a shutdown request.
const SHUTDOWN_TIMEOUT: Duration = Duration::from_secs(10);

/// Accept connections on `listener` until `shutdown` is cancelled.
///
/// After that, stop accepting and wait for open connections to finish.
/// Stop waiting after `SHUTDOWN_TIMEOUT`.
pub async fn serve(listener: TcpListener, shutdown: CancellationToken) {
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
        spawn_connection(&builder, &graceful, stream, peer);
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
) {
    let builder = builder.clone();
    let watcher = graceful.watcher();
    tokio::spawn(async move {
        // The connection borrows `builder`, so create it inside the task.
        let connection = builder.serve_connection(TokioIo::new(stream), service_fn(handle));
        // `watch` tells the connection to finish its work when the shutdown starts.
        if let Err(err) = watcher.watch(connection).await {
            debug!(%peer, %err, "connection error");
        }
        debug!(%peer, "connection closed");
    });
}

/// Answer a request.
///
/// - `/echo`: send back the request headers and the request body.
/// - Any other path: `200 OK` with the body `ok`.
async fn handle(request: Request<Incoming>) -> Result<Response<Full<Bytes>>, Infallible> {
    if request.uri().path() == "/echo" {
        return Ok(echo(request).await);
    }
    Ok(Response::new(Full::new(Bytes::from_static(b"ok\n"))))
}

/// Return `200 OK` with the same headers and the same body as the request.
/// A request without a body (for example `GET`) gets an empty body.
async fn echo(request: Request<Incoming>) -> Response<Full<Bytes>> {
    let (parts, body) = request.into_parts();
    let body = match body.collect().await {
        Ok(collected) => collected.to_bytes(),
        Err(err) => {
            warn!(%err, "failed to read the request body");
            let mut response = Response::new(Full::new(Bytes::new()));
            *response.status_mut() = StatusCode::BAD_REQUEST;
            return response;
        }
    };
    let mut response = Response::new(Full::new(body));
    *response.headers_mut() = parts.headers;
    response
}
