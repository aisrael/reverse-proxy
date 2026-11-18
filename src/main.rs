use std::time::Duration;
use tokio::signal;
use tokio::task::JoinSet;
use tokio::time::sleep;
use tokio_util::sync::CancellationToken;
use tracing::debug;
use tracing::info;
use tracing::trace;
use tracing::warn;
use tracing_subscriber::EnvFilter;

#[tokio::main]
async fn main() {
    // Log level comes from `RUST_LOG` (for example `RUST_LOG=debug`). Default is `info`.
    // Never log secrets.
    tracing_subscriber::fmt()
        .with_env_filter(
            EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info")),
        )
        .init();

    let token = CancellationToken::new();
    let mut workers = JoinSet::new();

    // 1. Spawn background workers
    for id in 0..3 {
        let worker_token = token.clone();
        workers.spawn(worker(id, worker_token));
    }
    info!(workers = workers.len(), "started");

    // 2. Wait for Ctrl+C
    match signal::ctrl_c().await {
        Ok(()) => info!("Ctrl+C received, starting graceful shutdown"),
        Err(err) => warn!(%err, "failed to listen for Ctrl+C"),
    }

    // 3. Notify all tasks to stop and wait for them to finish
    token.cancel();
    while let Some(result) = workers.join_next().await {
        if let Err(err) = result {
            warn!(%err, "a worker failed");
        }
    }

    info!("all tasks shut down cleanly");
}

async fn worker(id: usize, token: CancellationToken) {
    debug!(worker = id, "started");
    loop {
        tokio::select! {
            // Listen for the cancellation signal
            _ = token.cancelled() => {
                info!(worker = id, "cleaning up");
                sleep(Duration::from_millis(200)).await; // Simulate cleanup
                break;
            }
            // Normal work loop
            _ = sleep(Duration::from_secs(1)) => {
                trace!(worker = id, "doing work");
            }
        }
    }
}
