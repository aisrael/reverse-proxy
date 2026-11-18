mod errors;
mod headers;
mod proxy;
mod server;
mod state;
mod tls;

use clap::Parser;
use clap::Subcommand;
use errors::Error;
use std::sync::LazyLock;
use std::sync::OnceLock;
use tokio::net::TcpListener;
use tokio::signal;
use tokio_util::sync::CancellationToken;
use tracing::info;
use tracing::warn;
use tracing_subscriber::EnvFilter;

/// Address of the `proxy` mode when the environment variable `PROXY_ADDR` is not set.
const DEFAULT_PROXY_ADDR: &str = "127.0.0.1:8080";

/// Address of the `server` mode when the environment variable `SERVER_ADDR` is not set.
const DEFAULT_SERVER_ADDR: &str = "127.0.0.1:9000";

/// The address (`host:port`) of the `proxy` mode: `PROXY_ADDR`, or the default.
static PROXY_ADDR: LazyLock<String> = LazyLock::new(|| {
    std::env::var("PROXY_ADDR").unwrap_or_else(|_| DEFAULT_PROXY_ADDR.to_string())
});

/// The address (`host:port`) of the `server` mode: `SERVER_ADDR`, or the default.
/// The proxy sends its requests here.
static SERVER_ADDR: LazyLock<String> = LazyLock::new(|| {
    std::env::var("SERVER_ADDR").unwrap_or_else(|_| DEFAULT_SERVER_ADDR.to_string())
});

/// The path of the certificate file. It is set on the first call of `tls_cert_path`.
static TLS_CERT: OnceLock<String> = OnceLock::new();

/// The path of the private key file. It is set on the first call of `tls_key_path`.
static TLS_KEY: OnceLock<String> = OnceLock::new();

/// The path of the certificate file from `PROXY_TLS_CERT`.
/// Return an error if the variable is not set.
#[expect(dead_code, reason = "the TLS listener will use it")]
fn tls_cert_path() -> Result<&'static str, Error> {
    env_path(&TLS_CERT, "PROXY_TLS_CERT")
}

/// The path of the private key file from `PROXY_TLS_KEY`.
/// Return an error if the variable is not set.
#[expect(dead_code, reason = "the TLS listener will use it")]
fn tls_key_path() -> Result<&'static str, Error> {
    env_path(&TLS_KEY, "PROXY_TLS_KEY")
}

/// Read the variable `name` once and keep its value in `cell`.
/// The next calls return the kept value.
fn env_path(cell: &'static OnceLock<String>, name: &'static str) -> Result<&'static str, Error> {
    if let Some(path) = cell.get() {
        return Ok(path);
    }
    let path = std::env::var(name).map_err(|_| Error::MissingEnv(name))?;
    Ok(cell.get_or_init(|| path))
}

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
        Command::Proxy => PROXY_ADDR.as_str(),
        Command::Server => SERVER_ADDR.as_str(),
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
