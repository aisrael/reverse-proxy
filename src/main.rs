mod audit;
mod config;
mod deadline;
mod errors;
mod headers;
mod identity;
mod limit;
mod logging;
mod policy;
mod proxy;
mod reload;
mod server;
mod state;
mod telemetry;
mod tls;

use clap::Parser;
use clap::Subcommand;
use config::Config;
use errors::Error;
use std::sync::Arc;
use telemetry::Telemetry;
use tokio::net::TcpListener;
use tokio::signal;
use tokio_rustls::TlsAcceptor;
use tokio_util::sync::CancellationToken;
use tracing::info;
use tracing::warn;

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

    // The logs need the tracer of the telemetry, so start the telemetry first.
    let telemetry = Arc::new(Telemetry::init()?);
    logging::init(telemetry.span_tracer());

    let config = Config::try_from_env()?;
    let shutdown = shutdown_on_signal();
    match cli.command.unwrap_or(Command::Proxy) {
        Command::Proxy => {
            // Check the TLS setup and the policy before the bind. A wrong setup stops the proxy at once.
            config.check_upstream_is_not_proxy()?;
            let (cert_path, key_path) = config.tls_paths()?;
            let client_ca_path = config.client_ca()?;
            let (tls_config, client_verifier) =
                tls::server_config(cert_path, key_path, client_ca_path)?;
            let policies = policy::load(config.policy_file()?)?;
            info!(identities = policies.policies.len(), "policy loaded");
            reload::watch_client_ca(client_ca_path, client_verifier, shutdown.clone())?;
            let acceptor = TlsAcceptor::from(Arc::new(tls_config));
            let listener = bind(config.proxy_addr()).await?;
            proxy::serve(
                listener,
                shutdown,
                acceptor,
                config.server_addr(),
                policies,
                config.timeouts(),
                config.limits(),
                telemetry.clone(),
            )
            .await
        }
        Command::Server => {
            let listener = bind(config.server_addr()).await?;
            server::serve(listener, shutdown).await
        }
    }

    telemetry.shutdown();
    info!("shut down cleanly");
    Ok(())
}

/// Listen on `addr` (`host:port`).
async fn bind(addr: &str) -> Result<TcpListener, Error> {
    let listener = TcpListener::bind(addr).await?;
    info!(addr = %listener.local_addr()?, "listening");
    Ok(listener)
}

/// Return a token that is cancelled when Ctrl+C (SIGINT) or SIGTERM arrives.
/// The cancellation starts the graceful shutdown. Container platforms send
/// SIGTERM to stop a container.
fn shutdown_on_signal() -> CancellationToken {
    let token = CancellationToken::new();
    tokio::spawn({
        let token = token.clone();
        async move {
            wait_for_stop_signal().await;
            token.cancel();
        }
    });
    token
}

/// Wait until Ctrl+C or SIGTERM arrives, and log which one it was.
#[cfg(unix)]
async fn wait_for_stop_signal() {
    use tokio::signal::unix::SignalKind;
    use tokio::signal::unix::signal;

    let mut terminate = match signal(SignalKind::terminate()) {
        Ok(terminate) => terminate,
        Err(err) => {
            warn!(%err, "failed to listen for SIGTERM");
            wait_for_ctrl_c().await;
            return;
        }
    };
    tokio::select! {
        () = wait_for_ctrl_c() => {}
        _ = terminate.recv() => info!("SIGTERM received, starting graceful shutdown"),
    }
}

/// Wait until Ctrl+C arrives. There is no SIGTERM on this platform.
#[cfg(not(unix))]
async fn wait_for_stop_signal() {
    wait_for_ctrl_c().await;
}

/// Wait until Ctrl+C arrives. If the program cannot listen for it, wait for ever.
async fn wait_for_ctrl_c() {
    match signal::ctrl_c().await {
        Ok(()) => info!("Ctrl+C received, starting graceful shutdown"),
        Err(err) => {
            warn!(%err, "failed to listen for Ctrl+C");
            std::future::pending::<()>().await;
        }
    }
}
