#![allow(dead_code)]

mod analyzer;
mod auth;
mod cli;
mod config;
mod db;
mod fim;
mod notifier;
mod rce_detect;

use clap::{Parser, Subcommand};
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;
use tokio::time::sleep;
use tracing::{info, warn};

use crate::analyzer::Analyzer;
use crate::auth::pam_watcher::PamWatcher;
use crate::cli::auth_prompt::AuthPrompt;
use crate::cli::banner::print_banner;
use crate::config::Config;
use crate::db::user::AdminAuth;
use crate::db::Database;
use crate::fim::FimEngine;
use crate::notifier::{
    AlertDispatcher, AlertMessage, AlertSeverity, TelegramNotifier, WhatsappNotifier,
};
use crate::rce_detect::RceDetector;

#[derive(Parser)]
#[command(name = "sauroneye")]
#[command(about = "SauronEye — Real-time File Integrity Monitoring, Auth Auditing & Intrusion Sentinel", long_about = None)]
struct Cli {
    #[arg(short, long, default_value = "config.toml")]
    config: PathBuf,

    #[command(subcommand)]
    command: Option<Commands>,
}

#[derive(Subcommand)]
enum Commands {
    /// Initializes database for the first time and registers admin credentials (One-Time Init)
    Init,
    /// Updates system baseline recalculating fingerprints (requires admin authentication)
    Update,
    /// Runs daemon in foreground for real-time monitoring
    Run,
    /// Displays current configuration and database status
    Status,
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    print_banner(env!("CARGO_PKG_VERSION"));

    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env().unwrap_or_else(|_| "info".into()),
        )
        .init();

    let cli = Cli::parse();
    let config = Config::load_from_file(&cli.config)?;

    // Initialize notification dispatcher
    let mut dispatcher = AlertDispatcher::new();
    if let Some(ref tg) = config.notifications.telegram {
        if tg.enabled {
            dispatcher.add_notifier(Arc::new(TelegramNotifier::new(tg.clone())));
        }
    }
    if let Some(ref wa) = config.notifications.whatsapp {
        if wa.enabled {
            dispatcher.add_notifier(Arc::new(WhatsappNotifier::new(wa.clone())));
        }
    }
    let dispatcher = Arc::new(dispatcher);

    let db = Database::open(&config.database.path, config.database.enable_wal)?;

    match cli.command.unwrap_or(Commands::Run) {
        Commands::Init => {
            handle_init(&config, &db, &dispatcher).await?;
        }
        Commands::Update => {
            handle_update(&config, &db, &dispatcher).await?;
        }
        Commands::Status => {
            handle_status(&config, &db)?;
        }
        Commands::Run => {
            handle_run(config, db, dispatcher).await?;
        }
    }

    Ok(())
}

async fn handle_init(
    config: &Config,
    db: &Database,
    dispatcher: &Arc<AlertDispatcher>,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    if db.is_initialized()? {
        let alert = AlertMessage::new(
            &config.general.hostname,
            "UNAUTHORIZED RE-INITIALIZATION ATTEMPT (--init)",
            AlertSeverity::Critical,
            "The --init command was executed on an already initialized system! Blocked by One-Time Init guard.",
        );
        dispatcher.dispatch(alert).await;
        eprintln!("❌ CRITICAL ERROR: SauronEye has already been initialized!");
        eprintln!("For security reasons, use 'sauroneye --update' with your admin credentials to recalculate the baseline.");
        std::process::exit(1);
    }

    println!("👁️  === SauronEye Initial Setup (One-Time Init) ===");
    let password = AuthPrompt::prompt_new_password()?;
    let password_hash = AdminAuth::hash_password(&password)?;

    db.create_admin_user(&password_hash)?;
    db.record_audit_log("INIT", "admin", "Database initialized successfully")?;
    println!("✅ Admin user created and credentials hashed with Argon2id.");

    println!("🔍 Performing initial recursive baseline scan of configured paths...");
    let fim_engine = FimEngine::new(config.fim.clone(), config.distro_exclusions.clone());
    let fingerprints = fim_engine.scan_baseline();

    db.save_fingerprints_batch(&fingerprints)?;
    println!(
        "✅ Initial baseline saved successfully! Total files indexed: {}",
        fingerprints.len()
    );

    let alert = AlertMessage::new(
        &config.general.hostname,
        "SauronEye Successfully Initialized",
        AlertSeverity::Info,
        &format!(
            "Initial baseline recorded with {} monitored files.",
            fingerprints.len()
        ),
    );
    dispatcher.dispatch(alert).await;

    Ok(())
}

async fn handle_update(
    config: &Config,
    db: &Database,
    dispatcher: &Arc<AlertDispatcher>,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    if !db.is_initialized()? {
        eprintln!("❌ System is not initialized yet. Run 'sauroneye --init' first.");
        std::process::exit(1);
    }

    println!("👁️  === Authenticated Baseline Update (sauroneye --update) ===");
    let password = AuthPrompt::prompt_password("Enter admin password: ")?;

    if !db.verify_admin_login(&password)? {
        let alert = AlertMessage::new(
            &config.general.hostname,
            "AUTHENTICATION FAILURE ON --update COMMAND",
            AlertSeverity::Critical,
            "Unauthorized baseline update attempt with incorrect admin credentials!",
        );
        dispatcher.dispatch(alert).await;
        eprintln!("❌ Incorrect admin password! Unauthorized attempt logged.");
        std::process::exit(1);
    }

    println!("🔓 Admin authentication verified.");
    println!("🔍 Rescanning directories and recalculating fingerprints...");
    let fim_engine = FimEngine::new(config.fim.clone(), config.distro_exclusions.clone());
    let fingerprints = fim_engine.scan_baseline();

    db.save_fingerprints_batch(&fingerprints)?;
    db.record_audit_log(
        "UPDATE_BASELINE",
        "admin",
        &format!("Baseline updated: {} files", fingerprints.len()),
    )?;

    let alert = AlertMessage::new(
        &config.general.hostname,
        "Baseline Updated Successfully",
        AlertSeverity::Info,
        &format!(
            "Baseline recalculation executed by admin. Total files: {}",
            fingerprints.len()
        ),
    );
    dispatcher.dispatch(alert).await;
    println!("✅ Baseline successfully updated in SQLite database!");

    Ok(())
}

fn handle_status(
    config: &Config,
    db: &Database,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    println!("👁️  === SauronEye Sentinel Status ===");
    println!("Host: {}", config.general.hostname);
    println!("Database Path: {}", config.database.path.display());
    println!(
        "Initialized: {}",
        if db.is_initialized()? {
            "Yes ✅"
        } else {
            "No ❌"
        }
    );
    println!("Monitored Directories: {:?}", config.fim.include_paths);
    println!("Hash Algorithm: {}", config.fim.hash_algorithm);
    Ok(())
}

async fn handle_run(
    config: Config,
    db: Database,
    dispatcher: Arc<AlertDispatcher>,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    if !db.is_initialized()? {
        warn!("SauronEye is not initialized. Run 'sauroneye --init' to set up credentials and baseline.");
    }

    info!(
        "Starting SauronEye sentinel daemon on host: {}",
        config.general.hostname
    );

    let fim_engine = FimEngine::new(config.fim.clone(), config.distro_exclusions.clone());
    let analyzer = Analyzer::new(config.package_manager.check_package_db);
    let rce_detector = RceDetector::new(config.rce_detector.clone());
    let mut pam_watcher = PamWatcher::new();

    // Dispara alerta informativo de inicialização / reinicialização do daemon
    let startup_alert = AlertMessage::new(
        &config.general.hostname,
        "SauronEye Daemon Started / Resumed",
        AlertSeverity::Info,
        &format!(
            "Sentinel daemon is now active and monitoring in real time.\nMonitored Paths: {:?}\nRCE Protection: {}\nAuth Auditing: {}",
            config.fim.include_paths,
            if config.rce_detector.enabled { "Active" } else { "Disabled" },
            if config.auth_monitor.enabled { "Active" } else { "Disabled" }
        ),
    );
    dispatcher.dispatch(startup_alert).await;

    // Inicia o watcher em tempo real de eventos do sistema de arquivos
    let (fim_tx, mut fim_rx) = tokio::sync::mpsc::channel::<crate::fim::engine::FimEvent>(512);
    let _watcher = fim_engine.start_watcher(fim_tx)?;

    // Captura de sinais do sistema operacional (SIGINT / SIGTERM)
    let mut sigterm = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())?;
    let mut sigint = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::interrupt())?;
    let poll_interval = Duration::from_millis(config.general.poll_interval_ms);

    loop {
        tokio::select! {
            _ = sigterm.recv() => {
                warn!("SIGTERM received. Shutting down SauronEye sentinel...");
                let alert = AlertMessage::new(
                    &config.general.hostname,
                    "SAURONEYE DAEMON STOPPED / TERMINATED (SIGTERM)",
                    AlertSeverity::Critical,
                    "The sentinel daemon received a SIGTERM signal and is shutting down! Service was stopped or system is restarting.",
                );
                let _ = tokio::time::timeout(Duration::from_secs(2), dispatcher.dispatch(alert)).await;
                std::process::exit(0);
            }
            _ = sigint.recv() => {
                warn!("SIGINT (Ctrl+C) received. Shutting down SauronEye sentinel...");
                let alert = AlertMessage::new(
                    &config.general.hostname,
                    "SAURONEYE DAEMON INTERRUPTED (SIGINT)",
                    AlertSeverity::Critical,
                    "The sentinel daemon was manually interrupted (SIGINT / Ctrl+C) and is shutting down!",
                );
                let _ = tokio::time::timeout(Duration::from_secs(2), dispatcher.dispatch(alert)).await;
                std::process::exit(0);
            }
            _ = sleep(poll_interval) => {
                // 1. Process Real-Time FIM Events
                while let Ok(fim_event) = fim_rx.try_recv() {
                    match fim_event {
                        crate::fim::engine::FimEvent::Modified { path, new_fingerprint } => {
                            let old_fp = db.get_fingerprint(&path).ok().flatten();
                            let is_different = if let Some(ref old) = old_fp {
                                old.hash_value != new_fingerprint.hash_value
                            } else {
                                true
                            };

                            if is_different {
                                let analysis = analyzer.analyze_modification(&path, None, old_fp.as_ref(), &new_fingerprint);
                                let alert = AlertMessage::new(
                                    &config.general.hostname,
                                    &analysis.title,
                                    analysis.severity,
                                    &analysis.details,
                                );
                                dispatcher.dispatch(alert).await;
                                let _ = db.save_fingerprints_batch(&[new_fingerprint]);
                            }
                        }
                        crate::fim::engine::FimEvent::Created { path, fingerprint } => {
                            if !analyzer.is_package_manager_active() {
                                let alert = AlertMessage::new(
                                    &config.general.hostname,
                                    "NEW FILE CREATED IN PROTECTED PATH",
                                    AlertSeverity::Warning,
                                    &format!("New file detected: {}\nHash: {}", path.display(), fingerprint.hash_value),
                                );
                                dispatcher.dispatch(alert).await;
                            }
                            let _ = db.save_fingerprints_batch(&[fingerprint]);
                        }
                        crate::fim::engine::FimEvent::Deleted { path } => {
                            if !analyzer.is_package_manager_active() {
                                let alert = AlertMessage::new(
                                    &config.general.hostname,
                                    "PROTECTED FILE DELETED",
                                    AlertSeverity::Critical,
                                    &format!("File was removed: {}", path.display()),
                                );
                                dispatcher.dispatch(alert).await;
                            }
                        }
                    }
                }

                // 2. RCE & Process Anomaly Scan
                if config.rce_detector.enabled {
                    let rce_alerts = rce_detector.scan_anomalies();
                    for rce in rce_alerts {
                        let alert = AlertMessage::new(
                            &config.general.hostname,
                            "RCE / ANOMALOUS SHELL SPAWN DETECTED",
                            AlertSeverity::Critical,
                            &format!(
                                "Protected Service: {} (PID: {})\nSpawned Child Command: {} (PID: {})",
                                rce.parent_service, rce.parent_pid, rce.child_cmd, rce.child_pid
                            ),
                        );
                        dispatcher.dispatch(alert).await;
                    }
                }

                // 3. Auth & Login Monitor
                if config.auth_monitor.enabled {
                    if let Ok(auth_events) = pam_watcher.poll_new_events() {
                        for ev in auth_events {
                            if config.auth_monitor.ignore_cron_sessions && ev.service == "cron" {
                                continue;
                            }

                            if ev.success && config.auth_monitor.monitor_successful_logins {
                                let alert = AlertMessage::new(
                                    &config.general.hostname,
                                    "Successful User Login",
                                    AlertSeverity::Info,
                                    &format!(
                                        "User: {}\nService: {}\nOrigin: {}\nRaw Log: {}",
                                        ev.user,
                                        ev.service,
                                        ev.rhost.unwrap_or_else(|| "local".to_string()),
                                        ev.raw_message
                                    ),
                                );
                                dispatcher.dispatch(alert).await;
                            } else if !ev.success && config.auth_monitor.monitor_failed_attempts {
                                let alert = AlertMessage::new(
                                    &config.general.hostname,
                                    "Authentication Failure Attempt",
                                    AlertSeverity::Warning,
                                    &format!(
                                        "User: {}\nService: {}\nOrigin: {}\nRaw Log: {}",
                                        ev.user,
                                        ev.service,
                                        ev.rhost.unwrap_or_else(|| "local".to_string()),
                                        ev.raw_message
                                    ),
                                );
                                dispatcher.dispatch(alert).await;
                            }
                        }
                    }
                }
            }
        }
    }
}
