//! File watcher for vault auto-reload.
//!
//! Watches the vault file and triggers a reload when another process
//! (GUI or MCP server) writes changes.

use crate::Vault;
use notify::{Event, EventKind, RecommendedWatcher, RecursiveMode, Watcher};
use std::path::PathBuf;
use tokio::sync::mpsc;

/// Spawn a background task that watches the vault file and calls `vault.reload()`
/// whenever it detects a modification. Returns a handle to stop the watcher.
pub fn watch_vault(vault: Vault, vault_path: PathBuf) -> WatchHandle {
    let (stop_tx, mut stop_rx) = mpsc::channel::<()>(1);

    tokio::spawn(async move {
        let (tx, mut rx) = mpsc::channel(16);

        let mut watcher = match RecommendedWatcher::new(
            move |res: Result<Event, notify::Error>| {
                if let Ok(event) = res {
                    match event.kind {
                        EventKind::Modify(_) | EventKind::Create(_) => {
                            let _ = tx.blocking_send(());
                        }
                        _ => {}
                    }
                }
            },
            notify::Config::default(),
        ) {
            Ok(w) => w,
            Err(e) => {
                tracing::error!("Failed to create file watcher: {e}");
                return;
            }
        };

        // Watch the parent directory (some editors write to a temp file then rename)
        let watch_dir = vault_path.parent().unwrap_or(&vault_path);
        if let Err(e) = watcher.watch(watch_dir, RecursiveMode::NonRecursive) {
            tracing::error!("Failed to watch vault directory: {e}");
            return;
        }

        tracing::info!("Watching vault file for changes: {}", vault_path.display());

        loop {
            tokio::select! {
                Some(()) = rx.recv() => {
                    // Debounce: drain any queued events
                    while rx.try_recv().is_ok() {}

                    // Small delay to let the writing process finish
                    tokio::time::sleep(tokio::time::Duration::from_millis(100)).await;

                    match vault.reload().await {
                        Ok(()) => tracing::info!("Vault reloaded from disk"),
                        Err(e) => tracing::warn!("Vault reload failed: {e}"),
                    }
                }
                _ = stop_rx.recv() => {
                    tracing::info!("Vault watcher stopped");
                    break;
                }
            }
        }
    });

    WatchHandle { stop_tx }
}

/// Handle to stop the vault file watcher.
pub struct WatchHandle {
    stop_tx: mpsc::Sender<()>,
}

impl WatchHandle {
    /// Stop the watcher.
    pub async fn stop(self) {
        let _ = self.stop_tx.send(()).await;
    }
}
