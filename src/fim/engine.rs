use notify::{Config, Event, EventKind, RecommendedWatcher, RecursiveMode, Watcher};
use std::path::{Path, PathBuf};
use std::sync::mpsc as std_mpsc;
use std::time::Duration;
use tokio::sync::mpsc as tokio_mpsc;
use tracing::{error, info, warn};
use walkdir::WalkDir;

use crate::config::{DistroExclusionsConfig, FimConfig};
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
    DirectoryCreated {
        path: PathBuf,
        permissions: u32,
        uid: u32,
        gid: u32,
    },
    DirectoryDeleted {
        path: PathBuf,
    },
    DirectoryRenamed {
        from: PathBuf,
        to: PathBuf,
    },
    PermissionsChanged {
        path: PathBuf,
        permissions: u32,
        is_dir: bool,
    },
    OwnershipChanged {
        path: PathBuf,
        uid: u32,
        gid: u32,
        user_name: Option<String>,
        group_name: Option<String>,
        is_dir: bool,
    },
}

pub struct FimEngine {
    config: FimConfig,
    distro_exclusions: DistroExclusionsConfig,
    active_exclusions: Vec<String>,
    hash_algo: HashAlgorithm,
}

impl FimEngine {
    pub fn new(config: FimConfig, distro_exclusions: DistroExclusionsConfig) -> Self {
        let hash_algo = HashAlgorithm::parse(&config.hash_algorithm);
        let active_exclusions = Self::compute_active_exclusions(&config, &distro_exclusions);
        Self {
            config,
            distro_exclusions,
            active_exclusions,
            hash_algo,
        }
    }

    fn compute_active_exclusions(
        config: &FimConfig,
        distro_cfg: &DistroExclusionsConfig,
    ) -> Vec<String> {
        let mut exclusions = config.exclude_paths.clone();

        let profile = config.distro_profile.to_lowercase();
        let is_auto = profile == "auto";

        // Detect or apply Debian/Ubuntu exclusions
        if profile == "debian"
            || profile == "ubuntu"
            || (is_auto && Path::new("/etc/debian_version").exists())
        {
            exclusions.extend(distro_cfg.debian.clone());
        }

        // Detect or apply RedHat/Rocky/Alma/CentOS/Fedora exclusions
        if profile == "redhat"
            || profile == "rhel"
            || profile == "fedora"
            || (is_auto && Path::new("/etc/redhat-release").exists())
        {
            exclusions.extend(distro_cfg.redhat.clone());
        }

        // Detect or apply Alpine exclusions
        if profile == "alpine" || (is_auto && Path::new("/etc/alpine-release").exists()) {
            exclusions.extend(distro_cfg.alpine.clone());
        }

        // Detect or apply Arch Linux exclusions
        if profile == "arch" || (is_auto && Path::new("/etc/arch-release").exists()) {
            exclusions.extend(distro_cfg.arch.clone());
        }

        exclusions
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

        let active_exclusions = self.active_exclusions.clone();
        let hash_algo = self.hash_algo;

        std::thread::spawn(move || {
            while let Ok(res) = std_rx.recv() {
                match res {
                    Ok(event) => {
                        Self::handle_fs_event(event, &active_exclusions, hash_algo, &event_tx);
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
        active_exclusions: &[String],
        hash_algo: HashAlgorithm,
        event_tx: &tokio_mpsc::Sender<FimEvent>,
    ) {
        use std::os::unix::fs::MetadataExt;

        match event.kind {
            EventKind::Create(_) => {
                for path in event.paths {
                    if !Self::check_excluded(&path, active_exclusions) {
                        if path.is_dir() {
                            if let Ok(meta) = std::fs::metadata(&path) {
                                let fim_ev = FimEvent::DirectoryCreated {
                                    path: path.clone(),
                                    permissions: meta.mode(),
                                    uid: meta.uid(),
                                    gid: meta.gid(),
                                };
                                let _ = event_tx.blocking_send(fim_ev);
                            }
                        } else if path.is_file() {
                            if let Ok(fp) = FileFingerprint::generate(&path, hash_algo) {
                                let fim_ev = FimEvent::Created {
                                    path: path.clone(),
                                    fingerprint: fp,
                                };
                                let _ = event_tx.blocking_send(fim_ev);
                            }
                        }
                    }
                }
            }
            EventKind::Modify(notify::event::ModifyKind::Metadata(meta_kind)) => {
                use notify::event::MetadataKind;
                match meta_kind {
                    MetadataKind::Permissions => {
                        for path in event.paths {
                            if !Self::check_excluded(&path, active_exclusions) {
                                if let Ok(meta) = std::fs::metadata(&path) {
                                    let fim_ev = FimEvent::PermissionsChanged {
                                        is_dir: path.is_dir(),
                                        path: path.clone(),
                                        permissions: meta.mode(),
                                    };
                                    let _ = event_tx.blocking_send(fim_ev);
                                }
                            }
                        }
                    }
                    MetadataKind::Ownership => {
                        for path in event.paths {
                            if !Self::check_excluded(&path, active_exclusions) {
                                if let Ok(meta) = std::fs::metadata(&path) {
                                    let uid = meta.uid();
                                    let gid = meta.gid();
                                    let user_name = nix::unistd::User::from_uid(
                                        nix::unistd::Uid::from_raw(uid),
                                    )
                                    .ok()
                                    .flatten()
                                    .map(|u| u.name);
                                    let group_name = nix::unistd::Group::from_gid(
                                        nix::unistd::Gid::from_raw(gid),
                                    )
                                    .ok()
                                    .flatten()
                                    .map(|g| g.name);

                                    let fim_ev = FimEvent::OwnershipChanged {
                                        is_dir: path.is_dir(),
                                        path: path.clone(),
                                        uid,
                                        gid,
                                        user_name,
                                        group_name,
                                    };
                                    let _ = event_tx.blocking_send(fim_ev);
                                }
                            }
                        }
                    }
                    MetadataKind::AccessTime | MetadataKind::WriteTime => {
                        // Ignora atime e mtime puros
                    }
                    _ => {
                        // MetadataKind::Any / Other / Extended
                        // Inspeciona os caminhos modificados
                        for path in event.paths {
                            if !Self::check_excluded(&path, active_exclusions) {
                                if let Ok(meta) = std::fs::metadata(&path) {
                                    let is_dir = path.is_dir();
                                    let fim_perm = FimEvent::PermissionsChanged {
                                        is_dir,
                                        path: path.clone(),
                                        permissions: meta.mode(),
                                    };
                                    let _ = event_tx.blocking_send(fim_perm);
                                }
                            }
                        }
                    }
                }
            }
            EventKind::Modify(notify::event::ModifyKind::Name(_)) => {
                if event.paths.len() >= 2 {
                    let from = &event.paths[0];
                    let to = &event.paths[1];
                    if !Self::check_excluded(from, active_exclusions)
                        || !Self::check_excluded(to, active_exclusions)
                    {
                        if to.is_dir() {
                            let fim_ev = FimEvent::DirectoryRenamed {
                                from: from.clone(),
                                to: to.clone(),
                            };
                            let _ = event_tx.blocking_send(fim_ev);
                        } else if to.is_file() {
                            if let Ok(fp) = FileFingerprint::generate(to, hash_algo) {
                                let _ = event_tx
                                    .blocking_send(FimEvent::Deleted { path: from.clone() });
                                let _ = event_tx.blocking_send(FimEvent::Created {
                                    path: to.clone(),
                                    fingerprint: fp,
                                });
                            }
                        }
                    }
                }
            }
            EventKind::Modify(_) | EventKind::Any => {
                for path in event.paths {
                    if !Self::check_excluded(&path, active_exclusions) {
                        if path.is_file() {
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
            }
            EventKind::Remove(_) => {
                for path in event.paths {
                    if !Self::check_excluded(&path, active_exclusions) {
                        // In remove event, path no longer exists on disk; send delete event
                        let fim_ev = FimEvent::Deleted { path };
                        let _ = event_tx.blocking_send(fim_ev);
                    }
                }
            }
            _ => {}
        }
    }

    pub fn is_excluded(&self, path: &Path) -> bool {
        Self::check_excluded(path, &self.active_exclusions)
    }

    fn check_excluded(path: &Path, exclude_patterns: &[String]) -> bool {
        let path_str = path.to_string_lossy();

        // 1. Always ignore SQLite internal files and generated reports to avoid self-trigger feedback loops
        if path_str.ends_with("-wal")
            || path_str.ends_with("-shm")
            || path_str.ends_with("-journal")
            || path_str.contains("/sauron.db")
            || path_str.contains("sauroneye_report")
        {
            return true;
        }

        // 2. Custom user and distro exclusions
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
