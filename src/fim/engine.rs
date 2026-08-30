use notify::{Config, Event, EventKind, RecommendedWatcher, RecursiveMode, Watcher};
use std::path::{Path, PathBuf};
use std::sync::mpsc as std_mpsc;
use std::time::Duration;
use tokio::sync::mpsc as tokio_mpsc;
use tracing::{error, info, warn};
use walkdir::WalkDir;

use crate::config::FimConfig;
use crate::fim::hasher::HashAlgorithm;
use crate::fim::state::FileFingerprint;

#[derive(Debug, Clone)]
pub enum FimEvent {
    Modified {
        path: PathBuf,
        new_fingerprint: FileFingerprint,
    },
    Created {
        path: PathBuf,
        fingerprint: FileFingerprint,
    },
    Deleted {
        path: PathBuf,
    },
}

pub struct FimEngine {
    config: FimConfig,
    hash_algo: HashAlgorithm,
}

impl FimEngine {
    pub fn new(config: FimConfig) -> Self {
        let hash_algo = HashAlgorithm::parse(&config.hash_algorithm);
        Self { config, hash_algo }
    }

    /// Performs full recursive baseline scanning of configured paths.
    pub fn scan_baseline(&self) -> Vec<FileFingerprint> {
        let mut fingerprints = Vec::new();

        for include_path in &self.config.include_paths {
            if !include_path.exists() {
                warn!(
                    "Configured FIM path does not exist: {}",
                    include_path.display()
                );
                continue;
            }

            for entry in WalkDir::new(include_path)
                .into_iter()
                .filter_map(|e| e.ok())
            {
                let path = entry.path();
                if path.is_file() {
                    if self.is_excluded(path) {
                        continue;
                    }

                    match FileFingerprint::generate(path, self.hash_algo) {
                        Ok(fp) => fingerprints.push(fp),
                        Err(e) => {
                            warn!(
                                "Failed to generate fingerprint for {}: {}",
                                path.display(),
                                e
                            );
                        }
                    }
                }
            }
        }

        info!(
            "Baseline scan completed. Total indexed files: {}",
            fingerprints.len()
        );
        fingerprints
    }

    /// Starts real-time filesystem watcher emitting FIM events
    pub fn start_watcher(
        &self,
        event_tx: tokio_mpsc::Sender<FimEvent>,
    ) -> Result<RecommendedWatcher, Box<dyn std::error::Error + Send + Sync>> {
        let (std_tx, std_rx) = std_mpsc::channel();
        let mut watcher = RecommendedWatcher::new(
            std_tx,
            Config::default().with_poll_interval(Duration::from_millis(500)),
        )?;

        for include_path in &self.config.include_paths {
            if include_path.exists() {
                info!(
                    "Registering real-time FIM watch on: {}",
                    include_path.display()
                );
                if let Err(e) = watcher.watch(include_path, RecursiveMode::Recursive) {
                    error!("Failed to watch {}: {}", include_path.display(), e);
                }
            }
        }

        let config_clone = self.config.clone();
        let hash_algo = self.hash_algo;

        std::thread::spawn(move || {
            while let Ok(res) = std_rx.recv() {
                match res {
                    Ok(event) => {
                        Self::handle_fs_event(event, &config_clone, hash_algo, &event_tx);
                    }
                    Err(e) => {
                        warn!("Filesystem watcher error: {:?}", e);
                    }
                }
            }
        });

        Ok(watcher)
    }

    fn handle_fs_event(
        event: Event,
        config: &FimConfig,
        hash_algo: HashAlgorithm,
        event_tx: &tokio_mpsc::Sender<FimEvent>,
    ) {
        match event.kind {
            EventKind::Modify(_) | EventKind::Create(_) => {
                for path in event.paths {
                    if path.is_file() && !Self::check_excluded(&path, &config.exclude_paths) {
                        if let Ok(fp) = FileFingerprint::generate(&path, hash_algo) {
                            let fim_ev = FimEvent::Modified {
                                path: path.clone(),
                                new_fingerprint: fp,
                            };
                            let _ = event_tx.blocking_send(fim_ev);
                        }
                    }
                }
            }
            EventKind::Remove(_) => {
                for path in event.paths {
                    if !Self::check_excluded(&path, &config.exclude_paths) {
                        let fim_ev = FimEvent::Deleted { path };
                        let _ = event_tx.blocking_send(fim_ev);
                    }
                }
            }
            _ => {}
        }
    }

    pub fn is_excluded(&self, path: &Path) -> bool {
        Self::check_excluded(path, &self.config.exclude_paths)
    }

    fn check_excluded(path: &Path, exclude_patterns: &[String]) -> bool {
        let path_str = path.to_string_lossy();

        // 1. Always ignore SQLite internal journal, WAL and shared memory files to avoid self-trigger feedback loops
        if path_str.ends_with("-wal")
            || path_str.ends_with("-shm")
            || path_str.ends_with("-journal")
            || path_str.contains("/sauron.db")
        {
            return true;
        }

        // 2. Custom user exclusions
        for pattern in exclude_patterns {
            if pattern.starts_with('*') {
                let ext = &pattern[1..];
                if path_str.ends_with(ext) {
                    return true;
                }
            } else if path_str.contains(pattern) {
                return true;
            }
        }
        false
    }
}
