//! RDP Monitor - Windows service that detects Remote Desktop connections
//! through Windows Event Log subscriptions and sends email notifications.

mod app;
mod auth;
mod cli;
mod correlate;
mod db;
mod delivery;
mod events;
mod evt;
mod handler;
mod ipc_server;
mod logging;
mod mail;
mod monitor;
mod notify;
mod service;
mod store;
mod update;
mod winhttp;
mod winsec;

use std::path::PathBuf;
use std::sync::{Arc, OnceLock};

/// Common start-up for service and console mode.
pub fn startup(data_dir: Option<PathBuf>, is_service: bool) -> Result<Arc<app::Shared>, String> {
    let dir = data_dir.unwrap_or_else(rdpmon_core::paths::data_dir);
    std::fs::create_dir_all(&dir).map_err(|e| format!("cannot create {}: {e}", dir.display()))?;
    // Not fatal: monitoring matters more than the ACL. Without it, updates
    // (which write and execute files as SYSTEM) are refused.
    let acl = if is_service { winsec::secure_directory(&dir).map_err(|e| e.to_string()) } else { Err("console mode".into()) };
    logging::init(dir.join("logs").join("service.log"), !is_service);
    let (cfg, warning) = app::load_config(&dir);
    let has_password = !cfg.security.admin_password_hash.is_empty();
    let shared = app::Shared::new(dir, cfg).map_err(|e| e.to_string())?;
    let db = shared.open_db()?;
    let _ = db.audit("service", "service started", &format!("version {}", rdpmon_core::VERSION));
    match acl {
        Ok(()) => shared.dir_secured.store(true, std::sync::atomic::Ordering::SeqCst),
        Err(e) if is_service => {
            let m = format!("cannot secure the data directory ({e}); in-app updates are disabled");
            logging::error(&m);
            let _ = db.audit("service", "data directory not secured", &m);
        }
        Err(_) => {}
    }
    if has_password {
        shared.mark_initialized();
    }
    if let Some(w) = warning {
        logging::warn(&w);
        let _ = db.audit("service", "configuration warning", &w);
        shared.set_error(Some(w));
    }
    Ok(shared)
}

static CONSOLE: OnceLock<Arc<app::Shared>> = OnceLock::new();

unsafe extern "system" fn ctrl_handler(_: u32) -> i32 {
    if let Some(s) = CONSOLE.get() {
        s.request_stop();
    }
    1
}

fn console(args: &[String]) -> i32 {
    let dir = args.iter().position(|a| a == "--data-dir").and_then(|i| args.get(i + 1)).map(PathBuf::from);
    match startup(dir, false) {
        Ok(shared) => {
            let _ = CONSOLE.set(shared.clone());
            unsafe { windows_sys::Win32::System::Console::SetConsoleCtrlHandler(Some(ctrl_handler), 1) };
            logging::info(&format!("RDP Monitor {} running in console mode (Ctrl+C to stop)", rdpmon_core::VERSION));
            app::run(shared);
            0
        }
        Err(e) => {
            eprintln!("{e}");
            6
        }
    }
}

fn main() {
    let args: Vec<String> = std::env::args().collect();
    let rest = if args.len() > 2 { &args[2..] } else { &[][..] };
    let code = match args.get(1).map(String::as_str) {
        Some("service") => service::dispatch(),
        Some("console") => console(rest),
        Some("status") => cli::status(),
        Some("import") => cli::import(rest),
        Some("provision") => cli::provision(rest),
        Some("uninstall-check") => cli::uninstall_check(),
        Some("authorize-uninstall") => cli::authorize_uninstall(),
        Some("uninstall") => cli::uninstall(),
        Some("reset") => cli::reset(),
        Some("version" | "--version") => {
            println!("rdpmon-svc {}", rdpmon_core::VERSION);
            0
        }
        Some("help" | "--help" | "/?") => {
            println!("{}", cli::USAGE);
            0
        }
        _ => {
            eprintln!("{}", cli::USAGE);
            2
        }
    };
    std::process::exit(code);
}
