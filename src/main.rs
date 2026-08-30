#![allow(dead_code)]

mod analyzer;
mod auth;
mod cli;
mod config;
mod db;
mod fim;
mod notifier;
mod rce_detect;
mod report;

use chrono::{DateTime, TimeZone, Utc};
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
use crate::cli::time_parser::parse_time_argument;
use crate::config::Config;
use crate::db::user::AdminAuth;
use crate::db::Database;
use crate::fim::FimEngine;
use crate::notifier::{
    AlertDispatcher, AlertMessage, AlertSeverity, SmtpNotifier, TelegramNotifier, WhatsappNotifier,
};
use crate::rce_detect::RceDetector;
use crate::report::generate_pdf_report;

#[derive(Parser)]
#[command(name = "sauroneye")]
#[command(
    about = "SauronEye — Real-time File Integrity Monitoring, Auth Auditing & Intrusion Sentinel",
    long_about = None
)]
struct Cli {
    #[arg(short, long, default_value = "/etc/sauroneye/config.toml")]
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
    /// Queries or purges forensic audit logs within a date/time range (requires admin authentication)
    Logs {
        #[arg(long, default_value = "1970-01-01 00:00:00")]
        from: String,
        #[arg(long, default_value = "now")]
        to: String,
        #[arg(long)]
        purge: bool,
    },
    /// Generates executive PDF forensic audit report and optionally sends via SMTP email (requires admin authentication)
    Report {
        #[arg(short, long, default_value = "sauroneye_report.pdf")]
        output: PathBuf,
        #[arg(long, default_value = "1970-01-01 00:00:00")]
        from: String,
        #[arg(long, default_value = "now")]
        to: String,
        #[arg(long)]
        email: Option<String>,
    },
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

    // Initialize notification dispatcher (Telegram & WhatsApp for real-time alerts)
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
        Commands::Logs { from, to, purge } => {
            handle_logs(&config, &db, &from, &to, purge)?;
        }
        Commands::Report {
            output,
            from,
            to,
            email,
        } => {
            handle_report(&config, &db, &output, &from, &to, email.as_deref()).await?;
        }
    }

    Ok(())
}

fn authenticate_admin(db: &Database) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    if !db.is_initialized()? {
        eprintln!("❌ System is not initialized yet. Run 'sauroneye --init' first.");
        std::process::exit(1);
    }

    let password = AuthPrompt::prompt_password("Enter admin password: ")?;
    if !db.verify_admin_login(&password)? {
        eprintln!("❌ Authentication failed: Invalid admin credentials.");
        std::process::exit(1);
    }
    println!("🔓 Admin authentication verified.");
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
    authenticate_admin(db)?;

    println!("👁️  === Authenticated Baseline Update (sauroneye --update) ===");
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
    authenticate_admin(db)?;

    println!("\n👁️  === SauronEye Sentinel Status ===");
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
    println!(
        "Monitored Directories (FIM): {:?}",
        config.fim.include_paths
    );
    println!("Hash Algorithm: {}", config.fim.hash_algorithm);
    println!(
        "Package Manager Auto-Detect: {}",
        config.package_manager.auto_detect
    );
    println!("RCE Anomaly Sentinel: {}\n", config.rce_detector.enabled);
    Ok(())
}

fn handle_logs(
    _config: &Config,
    db: &Database,
    from: &str,
    to: &str,
    purge: bool,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    authenticate_admin(db)?;

    let start_ts =
        parse_time_argument(from).map_err(|e| format!("Error in --from parameter: {}", e))?;
    let end_ts = parse_time_argument(to).map_err(|e| format!("Error in --to parameter: {}", e))?;

    if purge {
        let count = db.purge_audit_logs(start_ts, end_ts)?;
        println!(
            "🗑️  Purge complete: {} audit log entries permanently removed from database.",
            count
        );
        db.record_audit_log(
            "PURGE_LOGS",
            "admin",
            &format!("Purged {} log records", count),
        )?;
        return Ok(());
    }

    let logs = db.query_audit_logs(start_ts, end_ts)?;
    println!(
        "\n📜 === SauronEye Forensic Audit Logs (Total: {}) ===",
        logs.len()
    );
    println!("{:-<120}", "");
    println!(
        "{:<20} | {:<25} | {:<20} | {}",
        "Timestamp (UTC)", "Action", "Actor / IP", "Details"
    );
    println!("{:-<120}", "");

    for log in logs {
        let ts_str = Utc
            .timestamp_opt(log.timestamp, 0)
            .single()
            .map(|d: DateTime<Utc>| d.format("%Y-%m-%d %H:%M:%S").to_string())
            .unwrap_or_default();
        let details_first_line = log.details.lines().next().unwrap_or("").trim();

        // Format Actor / IP cleanly (e.g. root:::1 -> root [::1], 192.168.1.10 -> [192.168.1.10])
        let actor_formatted = if log.actor.contains(" [") && log.actor.ends_with(']') {
            log.actor.clone()
        } else if let Some((user, ip)) = log.actor.split_once(":::") {
            format!("{} [::{}]", user, ip)
        } else if let Some((user, ip)) = log.actor.split_once(':') {
            format!("{} [{}]", user, ip)
        } else if log.actor.contains('.') || log.actor.contains(':') {
            format!("[{}]", log.actor)
        } else {
            log.actor.clone()
        };

        println!(
            "{:<20} | {:<25} | {:<20} | {}",
            ts_str, log.action, actor_formatted, details_first_line
        );
    }
    println!("{:-<120}\n", "");
    Ok(())
}

async fn handle_report(
    config: &Config,
    db: &Database,
    output: &PathBuf,
    from: &str,
    to: &str,
    email_dest: Option<&str>,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    authenticate_admin(db)?;

    let start_ts =
        parse_time_argument(from).map_err(|e| format!("Error in --from parameter: {}", e))?;
    let end_ts = parse_time_argument(to).map_err(|e| format!("Error in --to parameter: {}", e))?;

    println!("👁️  Generating Forensic Security Audit PDF Report...");
    let logs = db.query_audit_logs(start_ts, end_ts)?;

    generate_pdf_report(&config.general.hostname, start_ts, end_ts, &logs, output)?;
    println!("✅ PDF Report generated successfully: {}", output.display());

    db.record_audit_log(
        "GENERATE_REPORT",
        "admin",
        &format!(
            "PDF report generated: {} ({} records)",
            output.display(),
            logs.len()
        ),
    )?;

    if let Some(to_email) = email_dest {
        println!("📧 Dispatching PDF Report via SMTP to {}...", to_email);
        let smtp_cfg = match &config.notifications.smtp {
            Some(s) if s.enabled => s.clone(),
            _ => {
                eprintln!("❌ SMTP is not configured or disabled in config.toml!");
                return Err("SMTP disabled".into());
            }
        };

        let mailer = SmtpNotifier::new(smtp_cfg);
        let subject = format!(
            "[SAURONEYE - REPORT] Security Audit Report - {}",
            config.general.hostname
        );
        let body = format!(
            "Hello,\n\nPlease find attached the official SauronEye Forensic Security Audit PDF Report for host {}.\n\nTimeframe: {} to {}\nTotal Recorded Incidents: {}\n\nGenerated automatically by SauronEye Sentinel.",
            config.general.hostname, from, to, logs.len()
        );

        mailer
            .send_pdf_report(to_email, &subject, &body, output)
            .await?;
        println!("✅ Email dispatched successfully with attached PDF report!");
    }

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
    let _ = db.record_audit_log("DAEMON_START", "system", "SauronEye Sentinel started");

    // Pré-carrega o baseline de permissões e ownership de todos os caminhos monitorados
    // ANTES de iniciar o watcher para evitar race condition.
    // Arquivos/dirs que aparecerem DEPOIS do watcher iniciar são genuinamente novos.
    let mut known_permissions: std::collections::HashMap<std::path::PathBuf, u32> =
        std::collections::HashMap::new();
    let mut known_ownership: std::collections::HashMap<std::path::PathBuf, (u32, u32)> =
        std::collections::HashMap::new();
    let mut recent_alert_debounce: std::collections::HashMap<String, std::time::Instant> =
        std::collections::HashMap::new();

    {
        use std::os::unix::fs::MetadataExt;
        for root in &config.fim.include_paths {
            for entry in walkdir::WalkDir::new(root)
                .into_iter()
                .filter_map(|e| e.ok())
            {
                let path = entry.path().to_path_buf();
                if let Ok(meta) = std::fs::metadata(&path) {
                    known_permissions.insert(path.clone(), meta.mode() & 0o777);
                    known_ownership.insert(path, (meta.uid(), meta.gid()));
                }
            }
        }
    }

    // Inicia o watcher em tempo real APÓS baseline capturado
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
                let _ = db.record_audit_log("DAEMON_STOP", "system", "SauronEye stopped by SIGTERM");
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
                let _ = db.record_audit_log("DAEMON_STOP", "system", "SauronEye interrupted by SIGINT");
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

                                // Send alert only if it is tampering OR if user explicitly enabled notifications for legitimate package updates
                                if !analysis.is_legitimate_update || config.package_manager.notify_legitimate_updates {
                                    let alert = AlertMessage::new(
                                        &config.general.hostname,
                                        &analysis.title,
                                        analysis.severity,
                                        &analysis.details,
                                    );
                                    dispatcher.dispatch(alert).await;
                                }
                                let _ = db.record_audit_log(
                                    if analysis.is_legitimate_update { "PACKAGE_UPDATE" } else { "FILE_TAMPERING" },
                                    "process",
                                    &format!("File: {}\nHash: {}", path.display(), new_fingerprint.hash_value),
                                );
                                let _ = db.save_fingerprints_batch(&[new_fingerprint]);
                            }
                        }
                        crate::fim::engine::FimEvent::Created { path, fingerprint } => {
                            if !analyzer.is_package_manager_active() {
                                let key = format!("created:{}", path.display());
                                let now = std::time::Instant::now();
                                if let Some(last_time) = recent_alert_debounce.get(&key) {
                                    if now.duration_since(*last_time) < std::time::Duration::from_secs(2) {
                                        let _ = db.save_fingerprints_batch(&[fingerprint]);
                                        continue;
                                    }
                                }
                                recent_alert_debounce.insert(key, now);

                                let active_sessions = crate::analyzer::process_context::ProcessInspector::get_active_logged_in_ips();
                                let ip_origin_str = if !active_sessions.is_empty() {
                                    active_sessions
                                        .iter()
                                        .map(|s| s.ip_origin.clone())
                                        .collect::<Vec<String>>()
                                        .join(", ")
                                } else {
                                    "local console / service".to_string()
                                };

                                let alert = AlertMessage::new(
                                    &config.general.hostname,
                                    "NEW FILE CREATED IN PROTECTED DIRECTORY",
                                    AlertSeverity::Warning,
                                    &format!(
                                        "A new unindexed file was created in a monitored path:\n\nFile: {}\nActive User Origin IP(s): {}\nSize: {} bytes\nHash ({}): {}",
                                        path.display(),
                                        ip_origin_str,
                                        fingerprint.size,
                                        fingerprint.hash_algorithm,
                                        fingerprint.hash_value
                                    ),
                                );
                                dispatcher.dispatch(alert).await;
                                let _ = db.record_audit_log(
                                    "FILE_CREATED",
                                    &ip_origin_str,
                                    &format!("File: {}\nHash: {}", path.display(), fingerprint.hash_value),
                                );
                            }
                            let _ = db.save_fingerprints_batch(&[fingerprint]);
                            // Registra o novo arquivo nos state maps para que
                            // eventos subsequentes de chmod/chown sejam comparados corretamente
                            use std::os::unix::fs::MetadataExt;
                            if let Ok(meta) = std::fs::metadata(&path) {
                                known_permissions.insert(path.clone(), meta.mode() & 0o777);
                                known_ownership.insert(path.clone(), (meta.uid(), meta.gid()));
                            }
                        }
                        crate::fim::engine::FimEvent::DirectoryCreated { path, permissions, uid, gid } => {
                            if !analyzer.is_package_manager_active() {
                                let active_sessions = crate::analyzer::process_context::ProcessInspector::get_active_logged_in_ips();
                                let ip_origin_str = if !active_sessions.is_empty() {
                                    active_sessions
                                        .iter()
                                        .map(|s| s.ip_origin.clone())
                                        .collect::<Vec<String>>()
                                        .join(", ")
                                } else {
                                    "local console / service".to_string()
                                };

                                let alert = AlertMessage::new(
                                    &config.general.hostname,
                                    "NEW DIRECTORY CREATED IN PROTECTED PATH",
                                    AlertSeverity::Warning,
                                    &format!(
                                        "A new directory was created in a monitored path:\n\nDirectory: {}\nActive User Origin IP(s): {}\nPermissions: {:o}\nOwner UID/GID: {}/{}",
                                        path.display(),
                                        ip_origin_str,
                                        permissions & 0o777,
                                        uid,
                                        gid
                                    ),
                                );
                                dispatcher.dispatch(alert).await;
                                let _ = db.record_audit_log(
                                    "DIR_CREATED",
                                    &ip_origin_str,
                                    &format!("Directory: {} (mode: {:o}, uid: {}, gid: {})", path.display(), permissions & 0o777, uid, gid),
                                );
                            }
                            // Registra o novo dir nos state maps para que
                            // eventos subsequentes de chmod/chown sejam comparados corretamente
                            known_permissions.insert(path.clone(), permissions & 0o777);
                            known_ownership.insert(path.clone(), (uid, gid));
                        }
                        crate::fim::engine::FimEvent::DirectoryDeleted { path } => {
                            if !analyzer.is_package_manager_active() {
                                let active_sessions = crate::analyzer::process_context::ProcessInspector::get_active_logged_in_ips();
                                let ip_origin_str = if !active_sessions.is_empty() {
                                    active_sessions
                                        .iter()
                                        .map(|s| s.ip_origin.clone())
                                        .collect::<Vec<String>>()
                                        .join(", ")
                                } else {
                                    "local console / service".to_string()
                                };

                                let alert = AlertMessage::new(
                                    &config.general.hostname,
                                    "PROTECTED DIRECTORY DELETED / REMOVED",
                                    AlertSeverity::Critical,
                                    &format!(
                                        "A monitored directory was permanently removed from disk:\n\nDirectory: {}\nActive User Origin IP(s): {}",
                                        path.display(),
                                        ip_origin_str
                                    ),
                                );
                                dispatcher.dispatch(alert).await;
                                let _ = db.record_audit_log(
                                    "DIR_DELETED",
                                    &ip_origin_str,
                                    &format!("Directory removed: {}", path.display()),
                                );
                            }
                        }
                        crate::fim::engine::FimEvent::DirectoryRenamed { from, to } => {
                            if !analyzer.is_package_manager_active() {
                                let active_sessions = crate::analyzer::process_context::ProcessInspector::get_active_logged_in_ips();
                                let ip_origin_str = if !active_sessions.is_empty() {
                                    active_sessions
                                        .iter()
                                        .map(|s| s.ip_origin.clone())
                                        .collect::<Vec<String>>()
                                        .join(", ")
                                } else {
                                    "local console / service".to_string()
                                };

                                let alert = AlertMessage::new(
                                    &config.general.hostname,
                                    "PROTECTED DIRECTORY RENAMED / MOVED",
                                    AlertSeverity::Warning,
                                    &format!(
                                        "A monitored directory was renamed or moved:\n\nFrom: {}\nTo: {}\nActive User Origin IP(s): {}",
                                        from.display(),
                                        to.display(),
                                        ip_origin_str
                                    ),
                                );
                                dispatcher.dispatch(alert).await;
                                let _ = db.record_audit_log(
                                    "DIR_RENAMED",
                                    &ip_origin_str,
                                    &format!("Directory renamed from {} to {}", from.display(), to.display()),
                                );
                            }
                        }
                        crate::fim::engine::FimEvent::PermissionsChanged { path, permissions, is_dir } => {
                            if !analyzer.is_package_manager_active() {
                                let norm_perm = permissions & 0o777;

                                // Baseline foi pré-carregado antes do watcher:
                                // None = arquivo novo criado após daemon iniciar (alerta já vem via Created)
                                // Some(old) == norm_perm = duplicata de kernel = descarta
                                // Some(old) != norm_perm = mudança REAL de permissão = alerta
                                let perm_changed = match known_permissions.get(&path) {
                                    None => false,  // Novo path: alerta já vem via FimEvent::Created
                                    Some(&old) => old != norm_perm,
                                };
                                if !perm_changed {
                                    continue;
                                }
                                known_permissions.insert(path.clone(), norm_perm);

                                // Debounce temporal para evitar duplicatas dentro da janela de 2s
                                let key = format!("chmod:{}:{:o}", path.display(), norm_perm);
                                let now = std::time::Instant::now();
                                if let Some(last_time) = recent_alert_debounce.get(&key) {
                                    if now.duration_since(*last_time) < std::time::Duration::from_secs(2) {
                                        continue;
                                    }
                                }
                                recent_alert_debounce.insert(key, now);

                                let active_sessions = crate::analyzer::process_context::ProcessInspector::get_active_logged_in_ips();
                                let ip_origin_str = if !active_sessions.is_empty() {
                                    active_sessions
                                        .iter()
                                        .map(|s| s.ip_origin.clone())
                                        .collect::<Vec<String>>()
                                        .join(", ")
                                } else {
                                    "local console / service".to_string()
                                };

                                let target_type = if is_dir { "Directory" } else { "File" };
                                let alert = AlertMessage::new(
                                    &config.general.hostname,
                                    &format!("PROTECTED {} PERMISSIONS MODIFIED (CHMOD)", target_type.to_uppercase()),
                                    AlertSeverity::Warning,
                                    &format!(
                                        "Permissions changed on protected {}:\n\nPath: {}\nActive User Origin IP(s): {}\nNew Permissions: {:o}",
                                        target_type.to_lowercase(),
                                        path.display(),
                                        ip_origin_str,
                                        norm_perm
                                    ),
                                );
                                dispatcher.dispatch(alert).await;
                                let _ = db.record_audit_log(
                                    "PERMISSIONS_CHANGED",
                                    &ip_origin_str,
                                    &format!("{}: {} (mode: {:o})", target_type, path.display(), norm_perm),
                                );
                            }
                        }
                        crate::fim::engine::FimEvent::OwnershipChanged { path, uid, gid, user_name, group_name, is_dir } => {
                            if !analyzer.is_package_manager_active() {
                                // None = arquivo novo = alerta já vem via FimEvent::Created
                                // Some((old_uid, old_gid)) == (uid, gid) = duplicata = descarta
                                // Some((old_uid, old_gid)) != (uid, gid) = mudança REAL = alerta
                                let owner_changed = match known_ownership.get(&path) {
                                    None => false,  // Novo path: alerta já vem via FimEvent::Created
                                    Some(&(old_uid, old_gid)) => old_uid != uid || old_gid != gid,
                                };
                                if !owner_changed {
                                    continue;
                                }
                                known_ownership.insert(path.clone(), (uid, gid));

                                // Debounce temporal para evitar duplicatas dentro da janela de 2s
                                let key = format!("chown:{}:{}:{}", path.display(), uid, gid);
                                let now = std::time::Instant::now();
                                if let Some(last_time) = recent_alert_debounce.get(&key) {
                                    if now.duration_since(*last_time) < std::time::Duration::from_secs(2) {
                                        continue;
                                    }
                                }
                                recent_alert_debounce.insert(key, now);

                                let active_sessions = crate::analyzer::process_context::ProcessInspector::get_active_logged_in_ips();
                                let ip_origin_str = if !active_sessions.is_empty() {
                                    active_sessions
                                        .iter()
                                        .map(|s| s.ip_origin.clone())
                                        .collect::<Vec<String>>()
                                        .join(", ")
                                } else {
                                    "local console / service".to_string()
                                };

                                let target_type = if is_dir { "Directory" } else { "File" };
                                let user_display = user_name.unwrap_or_else(|| uid.to_string());
                                let group_display = group_name.unwrap_or_else(|| gid.to_string());

                                let alert = AlertMessage::new(
                                    &config.general.hostname,
                                    &format!("PROTECTED {} OWNERSHIP MODIFIED (CHOWN)", target_type.to_uppercase()),
                                    AlertSeverity::Warning,
                                    &format!(
                                        "Ownership changed on protected {}:\n\nPath: {}\nActive User Origin IP(s): {}\nNew Owner: {}:{} (UID/GID: {}/{})",
                                        target_type.to_lowercase(),
                                        path.display(),
                                        ip_origin_str,
                                        user_display,
                                        group_display,
                                        uid,
                                        gid
                                    ),
                                );
                                dispatcher.dispatch(alert).await;
                                let _ = db.record_audit_log(
                                    "OWNERSHIP_CHANGED",
                                    &ip_origin_str,
                                    &format!("{}: {} (owner: {}:{}, uid: {}, gid: {})", target_type, path.display(), user_display, group_display, uid, gid),
                                );
                            }
                        }
                        crate::fim::engine::FimEvent::Deleted { path } => {
                            if !analyzer.is_package_manager_active() {
                                let key = format!("deleted:{}", path.display());
                                let now = std::time::Instant::now();
                                if let Some(last_time) = recent_alert_debounce.get(&key) {
                                    if now.duration_since(*last_time) < std::time::Duration::from_secs(2) {
                                        let _ = db.delete_fingerprint(&path);
                                        continue;
                                    }
                                }
                                recent_alert_debounce.insert(key, now);

                                let active_sessions = crate::analyzer::process_context::ProcessInspector::get_active_logged_in_ips();
                                let ip_origin_str = if !active_sessions.is_empty() {
                                    active_sessions
                                        .iter()
                                        .map(|s| s.ip_origin.clone())
                                        .collect::<Vec<String>>()
                                        .join(", ")
                                } else {
                                    "local console / service".to_string()
                                };

                                let alert = AlertMessage::new(
                                    &config.general.hostname,
                                    "PROTECTED FILE DELETED / REMOVED",
                                    AlertSeverity::Critical,
                                    &format!(
                                        "A monitored file was permanently removed from disk:\n\nFile: {}\nActive User Origin IP(s): {}",
                                        path.display(),
                                        ip_origin_str
                                    ),
                                );
                                dispatcher.dispatch(alert).await;
                                let _ = db.record_audit_log(
                                    "FILE_DELETED",
                                    &ip_origin_str,
                                    &format!("File removed: {}", path.display()),
                                );
                            }
                            let _ = db.delete_fingerprint(&path);
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
                        let _ = db.record_audit_log(
                            "RCE_ANOMALY",
                            &rce.parent_service,
                            &format!("Spawned: {} (PID: {})", rce.child_cmd, rce.child_pid),
                        );
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
                                        ev.rhost.as_deref().unwrap_or("local"),
                                        ev.raw_message
                                    ),
                                );
                                dispatcher.dispatch(alert).await;
                                let _ = db.record_audit_log(
                                    "AUTH_LOGIN_SUCCESS",
                                    &format!("{} [{}]", ev.user, ev.rhost.as_deref().unwrap_or("local")),
                                    &format!("Service: {}\nLog: {}", ev.service, ev.raw_message),
                                );
                            } else if !ev.success && config.auth_monitor.monitor_failed_attempts {
                                let alert = AlertMessage::new(
                                    &config.general.hostname,
                                    "Authentication Failure Attempt",
                                    AlertSeverity::Warning,
                                    &format!(
                                        "User: {}\nService: {}\nOrigin: {}\nRaw Log: {}",
                                        ev.user,
                                        ev.service,
                                        ev.rhost.as_deref().unwrap_or("local"),
                                        ev.raw_message
                                    ),
                                );
                                dispatcher.dispatch(alert).await;
                                let _ = db.record_audit_log(
                                    "AUTH_LOGIN_FAILURE",
                                    &format!("{} [{}]", ev.user, ev.rhost.as_deref().unwrap_or("local")),
                                    &format!("Service: {}\nLog: {}", ev.service, ev.raw_message),
                                );
                            }
                        }
                    }
                }
            }
        }
    }
}
