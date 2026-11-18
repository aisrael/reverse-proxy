//! Reload the CA bundle for the client certificates when its file changes.

use crate::errors::Error;
use crate::tls::ReloadableClientVerifier;
use crate::tls::build_client_verifier_from_pem;
use crate::tls::read_pem_file;
use notify::EventKind;
use notify::RecursiveMode;
use notify::Watcher;
use std::path::Path;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::mpsc;
use tokio::time::sleep;
use tokio_util::sync::CancellationToken;
use tracing::info;
use tracing::warn;

/// Wait this long after the last change before the reload. One update of a
/// file can make many events, and the file can be half written.
const DEBOUNCE: Duration = Duration::from_millis(500);

/// Watch the CA bundle file at `path`. When it changes, build a verifier from
/// the new content and give it to `verifier`. New TLS handshakes use it.
/// Connections that are open do not change.
///
/// If the new file is not valid, log a warning and keep the old CAs.
/// Stop when `shutdown` is cancelled.
///
/// The watch is on the directory of the file, not on the file. A tool can
/// replace a file (a rename) or change a symbolic link (a Kubernetes volume
/// does this). A watch on the file would not see the new file.
///
/// Return an error if the watch cannot start, for example if the directory does
/// not exist.
pub fn watch_client_ca(
    path: &str,
    verifier: Arc<ReloadableClientVerifier>,
    shutdown: CancellationToken,
) -> Result<(), Error> {
    let (sender, mut receiver) = mpsc::unbounded_channel();
    // The callback runs on a thread of the `notify` crate, so it only sends a message.
    let mut watcher =
        notify::recommended_watcher(move |event: notify::Result<notify::Event>| match event {
            Ok(event) if matches!(event.kind, EventKind::Access(_)) => {}
            Ok(_) => {
                let _ = sender.send(());
            }
            Err(err) => warn!(%err, "error from the file watcher"),
        })?;
    let directory = match Path::new(path).parent() {
        Some(directory) if !directory.as_os_str().is_empty() => directory,
        _ => Path::new("."),
    };
    watcher.watch(directory, RecursiveMode::NonRecursive)?;
    info!(path, "watching the client CA file for changes");

    let path = path.to_string();
    let mut loaded = read_pem_file(&path).ok();
    tokio::spawn(async move {
        // The watcher stops when it is dropped.
        let _watcher = watcher;
        loop {
            tokio::select! {
                _ = shutdown.cancelled() => return,
                event = receiver.recv() => if event.is_none() { return },
            }
            // Wait until no event arrives for `DEBOUNCE`.
            loop {
                tokio::select! {
                    _ = shutdown.cancelled() => return,
                    _ = sleep(DEBOUNCE) => break,
                    event = receiver.recv() => if event.is_none() { return },
                }
            }
            reload(&path, &verifier, &mut loaded);
        }
    });
    Ok(())
}

/// Read the file again. If the content is not the same as `loaded`, and it is
/// valid, give the new verifier to `verifier` and set `loaded`.
/// A file that is not valid does not change `verifier` or `loaded`.
fn reload(path: &str, verifier: &ReloadableClientVerifier, loaded: &mut Option<Vec<u8>>) {
    let pem = match read_pem_file(path) {
        Ok(pem) => pem,
        Err(err) => {
            warn!(%err, "cannot reload the client CA file, keeping the old CAs");
            return;
        }
    };
    if loaded.as_deref() == Some(pem.as_slice()) {
        return;
    }
    match build_client_verifier_from_pem(path, &pem) {
        Ok((new_verifier, count)) => {
            verifier.replace(new_verifier);
            *loaded = Some(pem);
            info!(path, cas = count, "client CA file reloaded");
        }
        Err(err) => {
            // Never log the content of the file.
            warn!(%err, "client CA file is not valid, keeping the old CAs");
        }
    }
}
