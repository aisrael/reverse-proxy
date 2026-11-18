use bytes::Bytes;
use http_body_util::Full;
use hyper::Request;
use hyper::Response;
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
use tokio::signal;
use tokio::time::timeout;
use tokio_util::sync::CancellationToken;
use tracing::debug;
use tracing::info;
use tracing::warn;
use tracing_subscriber::EnvFilter;

/// Address of the server. It is fixed for now.
const LISTEN_ADDR: &str = "127.0.0.1:8080";

/// Maximum time to wait for open connections to finish after a shutdown request.
const SHUTDOWN_TIMEOUT: Duration = Duration::from_secs(10);

#[tokio::main]
async fn main() -> std::io::Result<()> {
    // Log level comes from `RUST_LOG` (for example `RUST_LOG=debug`). Default is `info`.
    // Never log secrets.
    tracing_subscriber::fmt()
        .with_env_filter(
            EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info")),
        )
        .init();

    let listener = TcpListener::bind(LISTEN_ADDR).await?;
    info!(addr = %listener.local_addr()?, "listening");

    // Cancel the token when Ctrl+C arrives. This starts the graceful shutdown.
    let token = CancellationToken::new();
    tokio::spawn({
        let token = token.clone();
        async move {
            match signal::ctrl_c().await {
                Ok(()) => info!("Ctrl+C received, starting graceful shutdown"),
                Err(err) => warn!(%err, "failed to listen for Ctrl+C"),
            }
            token.cancel();
        }
    });

    serve(listener, token).await;

    info!("shut down cleanly");
    Ok(())
}

/// Accept connections on `listener` until `shutdown` is cancelled.
///
/// After that, stop accepting and wait for open connections to finish.
/// Stop waiting after `SHUTDOWN_TIMEOUT`.
async fn serve(listener: TcpListener, shutdown: CancellationToken) {
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
    stream: tokio::net::TcpStream,
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

/// Return `200 OK` with a fixed body for every request.
async fn handle(_request: Request<Incoming>) -> Result<Response<Full<Bytes>>, Infallible> {
    Ok(Response::new(Full::new(Bytes::from_static(b"ok\n"))))
}

#[cfg(test)]
mod tests {
    use super::*;
    use http_body_util::BodyExt;
    use http_body_util::Empty;
    use hyper::StatusCode;
    use hyper_util::client::legacy::Client;
    use tokio::task::JoinHandle;

    /// Start the server on a free port. Return its address, the token and the task.
    async fn start() -> (SocketAddr, CancellationToken, JoinHandle<()>) {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let token = CancellationToken::new();
        let task = tokio::spawn(serve(listener, token.clone()));
        (addr, token, task)
    }

    #[tokio::test]
    async fn returns_ok_with_fixed_body() {
        let (addr, token, task) = start().await;
        let client = Client::builder(TokioExecutor::new()).build_http::<Empty<Bytes>>();

        let response = client
            .get(format!("http://{addr}/any/path?x=1").parse().unwrap())
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let body = response.into_body().collect().await.unwrap().to_bytes();
        assert_eq!(&body[..], b"ok\n");

        drop(client);
        token.cancel();
        task.await.unwrap();
    }

    #[tokio::test]
    async fn shutdown_ends_serve() {
        let (_addr, token, task) = start().await;

        token.cancel();

        timeout(Duration::from_secs(5), task)
            .await
            .expect("serve did not end after shutdown")
            .unwrap();
    }

    #[tokio::test]
    async fn shutdown_stops_new_connections() {
        let (addr, token, task) = start().await;

        token.cancel();
        task.await.unwrap();

        assert!(tokio::net::TcpStream::connect(addr).await.is_err());
    }
}
