mod config;
mod errors;
mod headers;
mod proxy;
mod server;
mod state;
mod tls;

use clap::Parser;
use clap::Subcommand;
use config::Config;
use errors::Error;
use std::sync::Arc;
use tokio::net::TcpListener;
use tokio::signal;
use tokio_rustls::TlsAcceptor;
use tokio_util::sync::CancellationToken;
use tracing::info;
use tracing::warn;
use tracing_subscriber::EnvFilter;

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

    let config = Config::try_from_env()?;
    let shutdown = shutdown_on_ctrl_c();
    match cli.command.unwrap_or(Command::Proxy) {
        Command::Proxy => {
            // Check the TLS setup before the bind. A wrong setup stops the proxy at once.
            let (cert_path, key_path) = config.tls_paths()?;
            let tls_config = tls::server_config(cert_path, key_path)?;
            let acceptor = TlsAcceptor::from(Arc::new(tls_config));
            let listener = bind(config.proxy_addr()).await?;
            proxy::serve(listener, shutdown, acceptor, config.server_addr()).await
        }
        Command::Server => {
            let listener = bind(config.server_addr()).await?;
            server::serve(listener, shutdown).await
        }
    }

    info!("shut down cleanly");
    Ok(())
}

/// Listen on `addr` (`host:port`).
async fn bind(addr: &str) -> Result<TcpListener, Error> {
    let listener = TcpListener::bind(addr).await?;
    info!(addr = %listener.local_addr()?, "listening");
    Ok(listener)
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
