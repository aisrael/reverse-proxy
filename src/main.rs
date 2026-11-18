use std::time::Duration;
use tokio::signal;
use tokio::task::JoinSet;
use tokio::time::sleep;
use tokio_util::sync::CancellationToken;

#[tokio::main]
async fn main() {
    let token = CancellationToken::new();
    let mut workers = JoinSet::new();

    // 1. Spawn background workers
    for id in 0..3 {
        let worker_token = token.clone();
        workers.spawn(worker(id, worker_token));
    }

    // 2. Wait for Ctrl+C
    match signal::ctrl_c().await {
        Ok(()) => println!("\nCtrl+C received, starting graceful shutdown..."),
        Err(err) => eprintln!("Failed to listen for Ctrl+C: {}", err),
    }

    // 3. Notify all tasks to stop and wait for them to finish
    token.cancel();
    while let Some(result) = workers.join_next().await {
        if let Err(err) = result {
            eprintln!("A worker failed: {}", err);
        }
    }

    println!("All tasks shut down cleanly.");
}

async fn worker(id: usize, token: CancellationToken) {
    loop {
        tokio::select! {
            // Listen for the cancellation signal
            _ = token.cancelled() => {
                println!("Worker {} cleaning up...", id);
                sleep(Duration::from_millis(200)).await; // Simulate cleanup
                break;
            }
            // Normal work loop
            _ = sleep(Duration::from_secs(1)) => {
                println!("Worker {} doing work...", id);
            }
        }
    }
}
