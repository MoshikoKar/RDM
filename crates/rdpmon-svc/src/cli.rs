//! Command-line operations for installers and deployment tools.
//!
//! Exit codes (stable, documented in docs/DEPLOYMENT.md):
//!   0 success                         4 package rejected (signature, replay)
//!   1 not authorized / blocked        5 configuration in package invalid
//!   2 invalid arguments               6 service unreachable or I/O error
//!   3 no trusted configuration key

use crate::store::{ConfigStore, Loaded};
use crate::{logging, service, winsec};
use rdpmon_core::config::Config;
use rdpmon_core::ipc::{self, Request, Response};
use rdpmon_core::package;

pub const USAGE: &str = "RDP Monitor service and administration tool

Usage:
  rdpmon-svc service                 (used by the Service Control Manager)
  rdpmon-svc status                  show service and monitoring status
  rdpmon-svc import <file.rdpcfg>    apply a signed configuration package to the running service
  rdpmon-svc provision [--trusted-key <base64>] [--package <file.rdpcfg>]
                                     installer use only (runs as SYSTEM while the service is stopped)
  rdpmon-svc uninstall-check         installer use only
  rdpmon-svc authorize-uninstall     prompt for the administration password and open the
                                     10-minute removal window (does not remove the product)
  rdpmon-svc uninstall               prompt for the administration password, stop the service
                                     and remove RDP Monitor (msiexec)
  rdpmon-svc reset                   SYSTEM only: return an agent whose protected configuration
                                     was lost to first-run setup (audited)
  rdpmon-svc console [--data-dir <dir>]  run in the foreground for troubleshooting
  rdpmon-svc version

Exit codes: 0 ok, 1 not authorized, 2 bad arguments, 3 no trusted key,
            4 package rejected, 5 invalid configuration, 6 service/I-O error";

fn arg_value(args: &[String], name: &str) -> Result<Option<String>, i32> {
    match args.iter().position(|a| a == name) {
        None => Ok(None),
        Some(i) => match args.get(i + 1) {
            Some(v) if v.trim().is_empty() => Ok(None),
            Some(v) => Ok(Some(v.trim().to_string())),
            None => {
                eprintln!("missing value for {name}");
                Err(2)
            }
        },
    }
}

fn read_package(path: &str) -> Result<String, i32> {
    if std::fs::metadata(path).map(|m| m.len() > 256 * 1024).unwrap_or(false) {
        eprintln!("{path} is too large to be a configuration package");
        return Err(4);
    }
    std::fs::read_to_string(path).map_err(|e| {
        eprintln!("cannot read {path}: {e}");
        6
    })
}

/// Recovery after the protected configuration was lost on an initialized
/// agent: returns it to first-run setup. Only works as SYSTEM (the database
/// is read-only for Administrators); always audited.
pub fn reset() -> i32 {
    let dir = rdpmon_core::paths::data_dir();
    let db = match crate::db::Db::open(&dir.join("history.db")) {
        Ok(d) => d,
        Err(e) => {
            eprintln!("cannot open the database ({e}); this command must run as SYSTEM");
            return 6;
        }
    };
    match db.delete_kv(crate::db::KV_INITIALIZED).and_then(|_| db.audit("admin", "agent reset to first-run setup", "rdpmon-svc reset")) {
        Ok(()) => {
            println!("Reset done. If the configuration was lost, open the configuration utility to set the agent up again.");
            0
        }
        Err(e) => {
            eprintln!("reset failed ({e}); this command must run as SYSTEM");
            6
        }
    }
}

pub fn status() -> i32 {
    match ipc::call(&Request::Status) {
        Ok(Response::Status(s)) => {
            println!("RDP Monitor {} on {}", s.version, s.hostname);
            println!("Administration password set: {}", if s.password_set { "yes" } else { "no" });
            println!("Email configured: {}", if s.smtp_configured { "yes" } else { "no" });
            for c in &s.monitoring {
                println!("  {:<75} {} {}", c.name, c.state, c.detail);
            }
            println!("Pending notifications: {}   Failed: {}", s.pending_notifications, s.failed_notifications);
            if let Some(t) = s.last_connection {
                println!("Last RDP connection: {t}");
            }
            if let Some(e) = s.last_error {
                println!("Last error: {e}");
            }
            0
        }
        Ok(other) => {
            eprintln!("unexpected response: {other:?}");
            6
        }
        Err(e) => {
            eprintln!("{e}");
            6
        }
    }
}

pub fn import(args: &[String]) -> i32 {
    let Some(path) = args.first() else {
        eprintln!("usage: rdpmon-svc import <file.rdpcfg>");
        return 2;
    };
    let data = match read_package(path) {
        Ok(d) => d,
        Err(c) => return c,
    };
    match ipc::call(&Request::ImportPackage { data }) {
        Ok(Response::Ok { message }) => {
            println!("{message}");
            0
        }
        Ok(Response::Error { message }) => {
            eprintln!("{message}");
            if message.contains("No trusted") { 3 } else if message.contains("invalid:") { 5 } else { 4 }
        }
        Ok(other) => {
            eprintln!("unexpected response: {other:?}");
            6
        }
        Err(e) => {
            eprintln!("{e}");
            6
        }
    }
}

pub fn uninstall_check() -> i32 {
    match ipc::call(&Request::CheckUninstall) {
        Ok(Response::Uninstall { authorized: true }) => 0,
        Ok(_) => {
            eprintln!("Removal of RDP Monitor is not authorized. Open the RDP Monitor configuration utility, sign in, and choose Security > Authorize uninstall.");
            1
        }
        Err(e) => {
            eprintln!("Cannot verify removal authorization: {e}. Start the RDP Monitor service and authorize the removal in the configuration utility.");
            1
        }
    }
}

/// Installer-time provisioning (MSI deferred custom action, LocalSystem).
pub fn provision(args: &[String]) -> i32 {
    let key = match arg_value(args, "--trusted-key") {
        Ok(v) => v,
        Err(c) => return c,
    };
    let pkg_path = match arg_value(args, "--package") {
        Ok(v) => v,
        Err(c) => return c,
    };
    let dir = rdpmon_core::paths::data_dir();
    if let Err(e) = std::fs::create_dir_all(&dir) {
        eprintln!("cannot create {}: {e}", dir.display());
        return 6;
    }
    if let Err(e) = winsec::secure_directory(&dir) {
        eprintln!("cannot secure {}: {e} (provisioning must run as SYSTEM)", dir.display());
        return 6;
    }
    logging::init(dir.join("logs").join("service.log"), false);
    if key.is_none() && pkg_path.is_none() {
        return 0;
    }
    if service::is_running() {
        // Never write the file under a running service: hand the package over.
        if key.is_some() {
            logging::info("provision: service is running; --trusted-key ignored (it can only bootstrap a new installation)");
        }
        return match pkg_path {
            Some(p) => import(&[p]),
            None => 0,
        };
    }

    let store = ConfigStore::new(&dir);
    let mut cfg = match store.load() {
        Ok(Loaded::Ok(c)) | Ok(Loaded::FromBackup(c, _)) => c,
        Ok(Loaded::Missing) => Config::default(),
        Err(e) => {
            eprintln!("existing configuration cannot be read: {e}");
            return 6;
        }
    };
    let initialized = crate::db::Db::open(&dir.join("history.db")).map(|d| d.initialized()).unwrap_or(true);
    if let Some(k) = key {
        if let Err(e) = rdpmon_core::crypto::decode_public_key(&k) {
            eprintln!("--trusted-key: {e}");
            return 2;
        }
        // The key may only bootstrap a never-initialized agent; otherwise an
        // administrator could run an MSI repair with their own key and reset
        // the administration password through a package.
        if cfg.security.trusted_config_key.is_empty() && (!cfg.security.admin_password_hash.is_empty() || initialized) {
            logging::warn("provision: --trusted-key ignored: the agent is already set up; install a key with the configuration utility");
        } else if cfg.security.trusted_config_key.is_empty() {
            cfg.security.trusted_config_key = k;
            logging::info("provision: trusted configuration key installed");
        } else if cfg.security.trusted_config_key != k {
            // Rotation must be authorized by the current key (signed package).
            logging::warn("provision: a different trusted key is already installed; --trusted-key ignored");
        }
    }
    let mut detail = String::from("trusted key checked");
    if let Some(p) = pkg_path {
        let data = match read_package(&p) {
            Ok(d) => d,
            Err(c) => return c,
        };
        if cfg.security.trusted_config_key.is_empty() {
            eprintln!("No trusted configuration key is installed; pass TRUSTED_CONFIG_KEY on first installation.");
            return 3;
        }
        let pkg = match package::verify(data.as_bytes(), &cfg.security.trusted_config_key) {
            Ok(p) => p,
            Err(e) => {
                eprintln!("{e}");
                logging::error(&format!("provision: package rejected: {e}"));
                return 4;
            }
        };
        if pkg.serial == cfg.security.last_package_serial {
            println!("Configuration package {} is already applied.", pkg.serial);
            return if store.save(&cfg).is_ok() { 0 } else { 6 };
        }
        cfg = match pkg.apply_to(&cfg) {
            Ok(c) => c,
            Err(e) => {
                eprintln!("{e}");
                logging::error(&format!("provision: package not applied: {e}"));
                return if e.contains("not newer") { 4 } else { 5 };
            }
        };
        detail = format!("package serial {} '{}' applied", pkg.serial, pkg.description);
    }
    if let Err(e) = store.save(&cfg) {
        eprintln!("{e}");
        return 6;
    }
    if let Ok(db) = crate::db::Db::open(&dir.join("history.db")) {
        let _ = db.audit("admin", "provisioned by installer", &detail);
    }
    logging::info(&format!("provision: {detail}"));
    println!("{detail}");
    0
}


fn read_secret(prompt: &str) -> String {
    use windows_sys::Win32::System::Console::{GetConsoleMode, GetStdHandle, SetConsoleMode, ENABLE_ECHO_INPUT, STD_INPUT_HANDLE};
    use std::io::{BufRead, Write};
    eprint!("{prompt}");
    let _ = std::io::stderr().flush();
    let h = unsafe { GetStdHandle(STD_INPUT_HANDLE) };
    let mut mode = 0u32;
    let have_console = unsafe { GetConsoleMode(h, &mut mode) } != 0;
    if have_console {
        unsafe { SetConsoleMode(h, mode & !ENABLE_ECHO_INPUT) };
    }
    let mut s = String::new();
    let _ = std::io::stdin().lock().read_line(&mut s);
    if have_console {
        unsafe { SetConsoleMode(h, mode) };
        eprintln!();
    }
    s.trim_end_matches(['\r', '\n']).to_string()
}

/// Verifies the administration password and opens the MSI removal window.
pub fn authorize_uninstall() -> i32 {
    let password = read_secret("Administration password: ");
    if password.is_empty() {
        eprintln!("Password is required.");
        return 2;
    }
    match ipc::call(&Request::AuthorizeUninstallWithPassword { password }) {
        Ok(Response::Ok { message }) => {
            println!("{message}");
            0
        }
        Ok(Response::Error { message }) => {
            eprintln!("{message}");
            1
        }
        Ok(other) => {
            eprintln!("unexpected response: {other:?}");
            6
        }
        Err(e) => {
            eprintln!("{e}");
            6
        }
    }
}

fn product_code() -> Result<String, String> {
    use std::process::Command;
    let script = r#"
$paths = @(
  'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*',
  'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*'
)
$app = Get-ItemProperty $paths -ErrorAction SilentlyContinue |
  Where-Object { $_.DisplayName -eq 'RDP Monitor' } |
  Select-Object -First 1
if (-not $app) { exit 2 }
Write-Output $app.PSChildName
"#;
    let out = Command::new("powershell.exe")
        .args(["-NoProfile", "-ExecutionPolicy", "Bypass", "-Command", script])
        .output()
        .map_err(|e| format!("cannot look up the installed product: {e}"))?;
    if !out.status.success() {
        return Err("RDP Monitor is not installed.".into());
    }
    let code = String::from_utf8_lossy(&out.stdout).trim().to_string();
    if code.is_empty() || !code.starts_with('{') {
        return Err("RDP Monitor is not installed.".into());
    }
    Ok(code)
}

/// Interactive removal: password -> authorize -> msiexec (stops the service).
pub fn uninstall() -> i32 {
    let auth = authorize_uninstall();
    if auth != 0 {
        return auth;
    }
    let code = match product_code() {
        Ok(c) => c,
        Err(e) => {
            eprintln!("{e}");
            return 6;
        }
    };
    let log = std::env::temp_dir().join("RDPMonitor-uninstall.log");
    println!("Stopping RDP Monitor and removing the product ({code})...");
    let status = std::process::Command::new(r"C:\Windows\System32\msiexec.exe")
        .args([
            "/x",
            &code,
            "/qb",
            "/norestart",
            "/l*v",
            &log.to_string_lossy(),
        ])
        .status();
    match status {
        Ok(s) => {
            let code = s.code().unwrap_or(1);
            if code == 0 {
                println!("RDP Monitor was removed. Log: {}", log.display());
            } else {
                eprintln!("msiexec exit code {code}. Log: {}", log.display());
            }
            code
        }
        Err(e) => {
            eprintln!("cannot start msiexec: {e}");
            6
        }
    }
}