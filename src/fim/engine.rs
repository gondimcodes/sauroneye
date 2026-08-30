use std::path::{Path, PathBuf};
use tracing::{info, warn};
use walkdir::WalkDir;

use crate::config::FimConfig;
use crate::fim::hasher::HashAlgorithm;
use crate::fim::state::FileFingerprint;

#[derive(Debug, Clone)]
pub enum FimEvent {
    Modified {
        path: PathBuf,
        old_fingerprint: Option<FileFingerprint>,
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

    pub fn is_excluded(&self, path: &Path) -> bool {
        let path_str = path.to_string_lossy();
        for pattern in &self.config.exclude_paths {
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
