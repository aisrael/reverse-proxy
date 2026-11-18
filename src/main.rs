mod proxy;
mod server;

use bytes::Bytes;
use clap::Parser;
use clap::Subcommand;
use http_body_util::BodyExt;
use http_body_util::Full;
use hyper::Request;
use hyper::Response;
use hyper::StatusCode;
use hyper::body::Incoming;
use server::serve;
use std::convert::Infallible;
use std::io;
use tokio::net::TcpListener;
use tokio::signal;
use tokio_util::sync::CancellationToken;
use tracing::info;
use tracing::warn;
use tracing_subscriber::EnvFilter;

/// Address of the `server` mode. It is fixed for now.
const LISTEN_ADDR: &str = "127.0.0.1:9000";

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
        Command::Proxy => proxy::run().await,
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
