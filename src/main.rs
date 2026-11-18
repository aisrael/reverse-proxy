use bytes::Bytes;
use clap::Parser;
use clap::Subcommand;
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
use std::io;
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

/// Address of the `server` mode. It is fixed for now.
const LISTEN_ADDR: &str = "127.0.0.1:9000";

/// Maximum time to wait for open connections to finish after a shutdown request.
const SHUTDOWN_TIMEOUT: Duration = Duration::from_secs(10);

/// A reverse proxy, and a small web server to test it with.
#[derive(Parser)]
#[command(version, about)]
struct Cli {
    /// The mode to run. The default is `proxy`.
    #[command(subcommand)]
    command: Option<Command>,
}

#[derive(Subcommand)]
enum Command {
    /// Run the reverse proxy (default). Not implemented yet.
    Proxy,
    /// Run a web server that answers every request with `200 OK`.
    Server,
}

#[tokio::main]
async fn main() -> io::Result<()> {
    let cli = Cli::parse();

    // Log level comes from `RUST_LOG` (for example `RUST_LOG=debug`). Default is `info`.
    // Never log secrets.
    tracing_subscriber::fmt()
        .with_env_filter(
            EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info")),
        )
        .init();

    match cli.command.unwrap_or(Command::Proxy) {
        Command::Proxy => Err(io::Error::other("proxy mode is not implemented yet")),
        Command::Server => run_server().await,
    }
}

/// Run the web server until Ctrl+C arrives, then shut down gracefully.
async fn run_server() -> io::Result<()> {
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
