mod errors;
mod proxy;
mod server;

use bytes::Bytes;
use clap::Parser;
use clap::Subcommand;
use errors::Error;
use http_body_util::BodyExt;
use http_body_util::Full;
use hyper::Request;
use hyper::Response;
use hyper::StatusCode;
use hyper::body::Incoming;
use std::convert::Infallible;
use tokio::net::TcpListener;
use tokio::signal;
use tokio_util::sync::CancellationToken;
use tracing::info;
use tracing::warn;
use tracing_subscriber::EnvFilter;

/// Address of the `proxy` mode. It is fixed for now.
const PROXY_ADDR: &str = "127.0.0.1:8080";

/// Address of the `server` mode. The proxy sends its requests here. It is fixed for now.
const SERVER_ADDR: &str = "127.0.0.1:9000";

/// A reverse proxy, and a small web server to test it with.
#[derive(Parser)]
#[command(version, about)]
struct Cli {
    /// The mode to run. The default is `proxy`.
    #[command(subcommand)]
    command: Option<Command>,
}

#[derive(Clone, Copy, Subcommand)]
enum Command {
    /// Run the reverse proxy (default). It sends every request to the `server` mode.
    Proxy,
    /// Run a test web server. It is the upstream of the proxy.
    Server,
}

#[tokio::main]
async fn main() -> Result<(), Error> {
    let cli = Cli::parse();

    // Log level comes from `RUST_LOG` (for example `RUST_LOG=debug`). Default is `info`.
    // Never log secrets.
    tracing_subscriber::fmt()
        .with_env_filter(
            EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info")),
        )
        .init();

    let mode = cli.command.unwrap_or(Command::Proxy);
    let addr = match mode {
        Command::Proxy => PROXY_ADDR,
        Command::Server => SERVER_ADDR,
    };
    let listener = TcpListener::bind(addr).await?;
    info!(addr = %listener.local_addr()?, "listening");

    let shutdown = shutdown_on_ctrl_c();
    match mode {
        Command::Proxy => proxy::serve(listener, shutdown).await,
        Command::Server => server::serve(listener, shutdown).await,
    }

    info!("shut down cleanly");
    Ok(())
}

/// Return a token that is cancelled when Ctrl+C arrives.
/// The cancellation starts the graceful shutdown.
fn shutdown_on_ctrl_c() -> CancellationToken {
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
    token
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
