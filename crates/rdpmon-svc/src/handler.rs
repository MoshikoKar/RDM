//! Authorization and execution of administration requests.

use crate::app::Shared;
use crate::db::Db;
use crate::{logging, mail, notify, update};
use rdpmon_core::config::{Config, SmtpConfig};
use rdpmon_core::ipc::{Request, Response, StatusInfo};
use rdpmon_core::{package, password};
use std::sync::atomic::Ordering;
use std::time::{Duration, Instant};

pub struct Client {
    pub pid: u32,
    pub user: String,
}

const NOT_SIGNED_IN: &str = "Not signed in, or the session expired. Please sign in again.";
const CONFIG_LOST: &str = "The protected configuration of this agent could not be loaded, so its administration password is unavailable. \
For safety, setup cannot be repeated from here. Run 'rdpmon-svc reset' as SYSTEM (for example from a GPO startup script \
or Vicarius), then complete the setup again or apply a signed configuration package (see docs/SECURITY.md).";

pub fn handle(sh: &Shared, db: &Db, req: Request, cl: &Client) -> Response {
    let who = format!("{} (pid {})", cl.user, cl.pid);
    let first_run = sh.first_run(db);
    let authorized = |token: &str| -> bool {
        let ok = sh.auth.lock().unwrap_or_else(|e| e.into_inner()).check(token, cl.pid, Instant::now());
        if !ok {
            let _ = db.audit("auth", "request rejected", &format!("invalid or expired session from {who}"));
        }
        ok
    };
    macro_rules! require {
        ($token:expr) => {
            if !authorized(&$token) {
                return Response::err(NOT_SIGNED_IN);
            }
        };
    }

    match req {
        Request::Status => Response::Status(status(sh, db)),
        Request::Login { password } => login(sh, db, &password, cl, &who),
        Request::Logout { token } => {
            sh.auth.lock().unwrap_or_else(|e| e.into_inner()).end(&token);
            Response::ok("Signed out.")
        }
        Request::InitialSetup { password, config } => {
            if !first_run {
                return Response::err(if sh.cfg().security.admin_password_hash.is_empty() {
                    CONFIG_LOST
                } else {
                    "Initial setup has already been completed. Sign in to change settings."
                });
            }
            initial_setup(sh, db, &password, config, cl, &who)
        }
        Request::GetConfig { token } => {
            if !first_run {
                require!(token);
            }
            let c = sh.cfg();
            Response::Config {
                has_smtp_password: !c.smtp.password.is_empty(),
                has_update_token: !c.updates.token.is_empty(),
                config: c.redacted(),
            }
        }
        Request::SaveConfig { token, config, smtp_password, update_token } => {
            require!(token);
            save_config(sh, db, config, smtp_password, update_token, &who)
        }
        Request::TestEmail { token, smtp, use_stored_password } => {
            match token {
                Some(t) => require!(t),
                None if first_run => {}
                None => return Response::err(NOT_SIGNED_IN),
            }
            test_email(sh, db, smtp, use_stored_password, &who)
        }
        Request::ChangePassword { token, current_password, new_password } => {
            require!(token);
            change_password(sh, db, &current_password, &new_password, cl, &who)
        }
        Request::GetAudit { token, limit } => {
            require!(token);
            match db.recent_audit(limit.clamp(1, 2000)) {
                Ok(entries) => Response::Audit { entries },
                Err(e) => Response::err(format!("Cannot read audit log: {e}")),
            }
        }
        Request::GetHistory { token, limit } => {
            require!(token);
            match db.recent_history(limit.clamp(1, 5000)) {
                Ok(entries) => Response::History { entries },
                Err(e) => Response::err(format!("Cannot read history: {e}")),
            }
        }
        Request::CheckUpdates { token } => {
            require!(token);
            let r = update::check(&sh.cfg());
            let _ = db.audit("update", "update check", &match &r {
                Ok(i) => format!("by {who}: latest {}", i.latest_version.clone().unwrap_or_else(|| "none".into())),
                Err(e) => format!("by {who}: failed: {e}"),
            });
            match r {
                Ok(info) => Response::Update(info),
                Err(e) => Response::err(e),
            }
        }
        Request::InstallUpdate { token, version } => {
            require!(token);
            let _ = db.audit("update", "update requested", &format!("version {version} by {who}"));
            match update::install(sh, db, &version) {
                Ok(m) => Response::ok(m),
                Err(e) => {
                    let _ = db.audit("update", "update rejected", &e);
                    Response::err(e)
                }
            }
        }
        Request::RestartMonitoring { token } => {
            require!(token);
            sh.resubscribe.store(true, Ordering::SeqCst);
            sh.config_changed.set();
            let _ = db.audit("admin", "monitoring restarted", &format!("by {who}"));
            Response::ok("Event subscriptions are being re-created.")
        }
        Request::AuthorizeUninstall { token } => {
            require!(token);
            authorize_uninstall(sh, db, &who)
        }
        Request::AuthorizeUninstallWithPassword { password } => {
            authorize_uninstall_with_password(sh, db, &password, &who)
        }
        Request::CheckUninstall => {
            let ok = sh.uninstall_authorized_until.lock().unwrap_or_else(|e| e.into_inner()).is_some_and(|t| t > Instant::now());
            let _ = db.audit("admin", if ok { "uninstall allowed" } else { "uninstall blocked" }, &format!("requested by {who}"));
            Response::Uninstall { authorized: ok }
        }
        Request::ImportPackage { data } => import_package(sh, db, data.as_bytes(), &who),
    }
}


fn authorize_uninstall(sh: &Shared, db: &Db, who: &str) -> Response {
    *sh.uninstall_authorized_until.lock().unwrap_or_else(|e| e.into_inner()) = Some(Instant::now() + Duration::from_secs(600));
    let _ = db.audit("admin", "uninstall authorized", &format!("for 10 minutes by {who}"));
    Response::ok("Uninstallation is authorized for the next 10 minutes. The service will be stopped when removal starts.")
}

fn authorize_uninstall_with_password(sh: &Shared, db: &Db, pw: &str, who: &str) -> Response {
    let now = Instant::now();
    let mut auth = sh.auth.lock().unwrap_or_else(|e| e.into_inner());
    if let Some(d) = auth.locked_for(now) {
        let _ = db.audit("auth", "uninstall blocked", &format!("locked out, attempt by {who}"));
        return Response::err(format!("Too many failed attempts. Try again in {} seconds.", d.as_secs() + 1));
    }
    let hash = sh.cfg().security.admin_password_hash;
    if hash.is_empty() {
        return Response::err(if db.initialized() { CONFIG_LOST } else { "No administration password is set yet. Complete the initial setup first." });
    }
    if !password::verify(pw, &hash) {
        auth.record_failure(now);
        let n = auth.failures();
        drop(auth);
        let _ = db.audit("auth", "uninstall password failed", &format!("wrong password from {who} (consecutive failures: {n})"));
        logging::warn(&format!("failed uninstall authorization from {who}"));
        return Response::err("Incorrect password.");
    }
    // No session is created: this request only opens the removal window.
    auth.clear_failures();
    drop(auth);
    authorize_uninstall(sh, db, who)
}
fn status(sh: &Shared, db: &Db) -> StatusInfo {
    let cfg = sh.cfg();
    let (pending, failed) = db.outbox_counts().unwrap_or((0, 0));
    StatusInfo {
        version: rdpmon_core::VERSION.into(),
        hostname: sh.host.clone(),
        // A lost configuration on an initialized agent must not show setup.
        password_set: !cfg.security.admin_password_hash.is_empty() || db.initialized(),
        smtp_configured: cfg.smtp.is_configured(),
        monitoring: sh.channels.lock().unwrap_or_else(|e| e.into_inner()).clone(),
        pending_notifications: pending,
        failed_notifications: failed,
        last_connection: db.last_connection_time().ok().flatten().and_then(|s| crate::db::parse_ts(&s)).map(notify::local),
        last_error: sh.last_error.lock().unwrap_or_else(|e| e.into_inner()).clone(),
        locked_out_seconds: sh.auth.lock().unwrap_or_else(|e| e.into_inner()).locked_for(Instant::now()).map_or(0, |d| d.as_secs() + 1),
    }
}

fn login(sh: &Shared, db: &Db, pw: &str, cl: &Client, who: &str) -> Response {
    let now = Instant::now();
    let mut auth = sh.auth.lock().unwrap_or_else(|e| e.into_inner());
    if let Some(d) = auth.locked_for(now) {
        let _ = db.audit("auth", "sign-in blocked", &format!("locked out, attempt by {who}"));
        return Response::err(format!("Too many failed attempts. Try again in {} seconds.", d.as_secs() + 1));
    }
    let hash = sh.cfg().security.admin_password_hash;
    if hash.is_empty() {
        return Response::err(if db.initialized() { CONFIG_LOST } else { "No administration password is set yet. Complete the initial setup first." });
    }
    if password::verify(pw, &hash) {
        let token = auth.new_session(cl.pid, now);
        let _ = db.audit("auth", "signed in", who);
        Response::Token { token }
    } else {
        auth.record_failure(now);
        let n = auth.failures();
        let _ = db.audit("auth", "sign-in failed", &format!("wrong password from {who} (consecutive failures: {n})"));
        logging::warn(&format!("failed administration sign-in from {who}"));
        Response::err("Incorrect password.")
    }
}

fn initial_setup(sh: &Shared, db: &Db, pw: &str, mut new: Config, cl: &Client, who: &str) -> Response {
    let cur = sh.cfg();
    if !cur.security.admin_password_hash.is_empty() {
        return Response::err("Initial setup has already been completed. Sign in to change settings.");
    }
    if let Err(e) = password::check_strength(pw) {
        return Response::err(e);
    }
    new.security.admin_password_hash = match password::hash(pw) {
        Ok(h) => h,
        Err(e) => return Response::err(e),
    };
    new.security.last_package_serial = cur.security.last_package_serial;
    if !cur.security.trusted_config_key.is_empty() {
        new.security.trusted_config_key = cur.security.trusted_config_key.clone();
    }
    if new.smtp.username.trim().is_empty() {
        new.smtp.password.clear();
    }
    if let Err(errs) = new.validate() {
        return Response::err(errs.join("\n"));
    }
    if let Err(e) = sh.apply_config(new) {
        return Response::err(format!("Could not save the configuration: {e}"));
    }
    let _ = db.audit("admin", "initial setup completed", &format!("administration password set by {who}"));
    let token = sh.auth.lock().unwrap_or_else(|e| e.into_inner()).new_session(cl.pid, Instant::now());
    Response::Token { token }
}

fn changed_sections(a: &Config, b: &Config) -> String {
    let mut v = Vec::new();
    if a.smtp != b.smtp {
        v.push("email");
    }
    if a.notifications != b.notifications {
        v.push("notifications");
    }
    if a.monitoring != b.monitoring {
        v.push("monitoring");
    }
    if a.failed_logons != b.failed_logons {
        v.push("failed logons");
    }
    if a.smb != b.smb {
        v.push("file share monitoring");
    }
    if a.report != b.report {
        v.push("weekly report");
    }
    if a.heartbeat != b.heartbeat {
        v.push("heartbeat");
    }
    if a.retention != b.retention {
        v.push("retention");
    }
    if a.security.trusted_config_key != b.security.trusted_config_key {
        v.push("trusted configuration key");
    }
    if a.security.harden_service != b.security.harden_service {
        v.push("service hardening");
    }
    if a.security.admin_password_hash != b.security.admin_password_hash {
        v.push("administration password");
    }
    if a.updates != b.updates {
        v.push("updates");
    }
    v.join(", ")
}

fn save_config(sh: &Shared, db: &Db, mut new: Config, smtp_pw: Option<String>, upd_token: Option<String>, who: &str) -> Response {
    let cur = sh.cfg();
    new.security.admin_password_hash = cur.security.admin_password_hash.clone();
    new.security.last_package_serial = cur.security.last_package_serial;
    // A stored secret is never re-used for a different destination: that
    // would let anyone holding a session send it to a server they control.
    new.smtp.password = match smtp_pw {
        Some(p) => p,
        None => {
            if !cur.smtp.password.is_empty()
                && (!new.smtp.host.trim().eq_ignore_ascii_case(cur.smtp.host.trim()) || new.smtp.username.trim() != cur.smtp.username.trim())
            {
                return Response::err("Re-enter the SMTP password when changing the SMTP server or user name.");
            }
            cur.smtp.password.clone()
        }
    };
    if new.smtp.username.trim().is_empty() {
        new.smtp.password.clear();
    }
    new.updates.token = match upd_token {
        Some(t) => t.trim().to_string(),
        None => {
            let host = |u: &str| rdpmon_core::config::repo_host_and_path(u).map(|x| x.0);
            if !cur.updates.token.is_empty() && host(&new.updates.repository_url) != host(&cur.updates.repository_url) {
                return Response::err("Re-enter the access token when changing the update repository server.");
            }
            cur.updates.token.clone()
        }
    };
    if let Err(errs) = new.validate() {
        return Response::err(errs.join("\n"));
    }
    if new == cur {
        return Response::ok("No changes to save.");
    }
    let what = changed_sections(&cur, &new);
    if let Err(e) = sh.apply_config(new) {
        return Response::err(format!("Could not save the configuration: {e}"));
    }
    let _ = db.audit("admin", "configuration changed", &format!("{what} - by {who}"));
    logging::info(&format!("configuration changed ({what}) by {who}"));
    Response::ok("Settings saved and applied.")
}

fn test_email(sh: &Shared, db: &Db, mut smtp: SmtpConfig, use_stored: bool, who: &str) -> Response {
    let cur = sh.cfg();
    if use_stored {
        if !smtp.host.trim().eq_ignore_ascii_case(cur.smtp.host.trim()) || smtp.username.trim() != cur.smtp.username.trim() {
            return Response::err("Enter the SMTP password to test a different server or user name.");
        }
        smtp.password = cur.smtp.password.clone();
    }
    let probe = Config { smtp: smtp.clone(), ..Default::default() };
    if let Err(errs) = probe.validate() {
        return Response::err(errs.join("\n"));
    }
    if !smtp.is_configured() {
        return Response::err("Enter the SMTP server, sender and at least one recipient first.");
    }
    let host = &sh.host;
    let m = crate::db::Message {
        subject: format!("RDP Monitor test email from {host}"),
        text: format!("This is a test message from RDP Monitor on {host}.\r\nIf you received it, email notifications are configured correctly.\r\n"),
        html: format!(
            "<!DOCTYPE html><html><body style=\"font-family:Segoe UI,Arial,sans-serif;font-size:13px\"><h2 style=\"font-size:17px\">RDP Monitor test email</h2><p>This is a test message from RDP Monitor on <b>{}</b>.</p><p>If you received it, email notifications are configured correctly.</p></body></html>",
            notify::html_escape(host)
        ),
    };
    let r = mail::send(&smtp, None, &m);
    let _ = db.audit("admin", "test email", &match &r {
        Ok(()) => format!("sent via {}:{} by {who}", smtp.host, smtp.port),
        Err(e) => format!("failed via {}:{} by {who}: {e}", smtp.host, smtp.port),
    });
    match r {
        Ok(()) => Response::ok(format!("Test email sent to {}. Check the inbox (and the spam folder).", smtp.to.join(", "))),
        Err(e) => Response::err(e),
    }
}

fn change_password(sh: &Shared, db: &Db, current: &str, new_pw: &str, cl: &Client, who: &str) -> Response {
    let now = Instant::now();
    let mut cfg = sh.cfg();
    {
        let mut auth = sh.auth.lock().unwrap_or_else(|e| e.into_inner());
        if let Some(d) = auth.locked_for(now) {
            return Response::err(format!("Too many failed attempts. Try again in {} seconds.", d.as_secs() + 1));
        }
        if !password::verify(current, &cfg.security.admin_password_hash) {
            auth.record_failure(now);
            let _ = db.audit("auth", "password change failed", &format!("wrong current password from {who}"));
            return Response::err("The current password is incorrect.");
        }
    }
    if let Err(e) = password::check_strength(new_pw) {
        return Response::err(e);
    }
    cfg.security.admin_password_hash = match password::hash(new_pw) {
        Ok(h) => h,
        Err(e) => return Response::err(e),
    };
    if let Err(e) = sh.apply_config(cfg) {
        return Response::err(format!("Could not save the new password: {e}"));
    }
    let mut auth = sh.auth.lock().unwrap_or_else(|e| e.into_inner());
    auth.end_all();
    let token = auth.new_session(cl.pid, now);
    let _ = db.audit("admin", "administration password changed", &format!("by {who}; other sessions signed out"));
    Response::Token { token }
}

fn import_package(sh: &Shared, db: &Db, data: &[u8], who: &str) -> Response {
    let cur = sh.cfg();
    // Re-running the same (verified) package, e.g. from a GPO startup script
    // on every boot, is a successful no-op.
    if let Ok(p) = package::verify(data, &cur.security.trusted_config_key) {
        if p.serial == cur.security.last_package_serial {
            return Response::ok(format!("Configuration package {} is already applied.", p.serial));
        }
    }
    let result = package::verify(data, &cur.security.trusted_config_key).and_then(|p| p.apply_to(&cur).map(|c| (p, c)));
    match result {
        Ok((pkg, new)) => {
            let what = changed_sections(&cur, &new);
            let pw_changed = new.security.admin_password_hash != cur.security.admin_password_hash;
            if let Err(e) = sh.apply_config(new) {
                return Response::err(format!("Could not save the configuration: {e}"));
            }
            if pw_changed {
                sh.auth.lock().unwrap_or_else(|e| e.into_inner()).end_all();
            }
            let detail = format!("serial {} '{}': {} - by {who}", pkg.serial, pkg.description, if what.is_empty() { "no changes" } else { &what });
            let _ = db.audit("admin", "configuration package applied", &detail);
            logging::info(&format!("configuration package applied: {detail}"));
            if pkg.authorize_uninstall {
                *sh.uninstall_authorized_until.lock().unwrap_or_else(|e| e.into_inner()) = Some(Instant::now() + Duration::from_secs(600));
                let _ = db.audit("admin", "uninstall authorized", &format!("for 10 minutes by signed package {}", pkg.serial));
                return Response::ok(format!("Configuration package {} applied. Removal is authorized for 10 minutes.", pkg.serial));
            }
            Response::ok(format!("Configuration package {} applied.", pkg.serial))
        }
        Err(e) => {
            let _ = db.audit("admin", "configuration package rejected", &format!("{e} - from {who}"));
            logging::warn(&format!("configuration package rejected: {e}"));
            Response::err(e)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rdpmon_core::crypto::{b64, generate_signing_key};
    use rdpmon_core::ipc::Request as R;
    use std::sync::Arc;

    fn setup() -> (Arc<Shared>, Db, std::path::PathBuf) {
        let dir = std::env::temp_dir().join(format!("rdpmon-h-{}", rdpmon_core::crypto::random_hex(6)));
        std::fs::create_dir_all(&dir).unwrap();
        let sh = Shared::new(dir.clone(), Config::default()).unwrap();
        let db = sh.open_db().unwrap();
        (sh, db, dir)
    }

    fn cl() -> Client {
        Client { pid: 100, user: "CORP\\admin".into() }
    }

    fn valid_cfg() -> Config {
        let mut c = Config::default();
        c.smtp.host = "mail.example.com".into();
        c.smtp.from = "rdp@example.com".into();
        c.smtp.to = vec!["it@example.com".into()];
        c
    }

    fn token(r: Response) -> String {
        match r {
            Response::Token { token } => token,
            other => panic!("expected token, got {other:?}"),
        }
    }

    #[test]
    fn first_run_setup_then_locked_down() {
        let (sh, db, dir) = setup();
        let weak = handle(&sh, &db, R::InitialSetup { password: "short".into(), config: valid_cfg() }, &cl());
        assert!(matches!(weak, Response::Error { .. }));
        let t = token(handle(&sh, &db, R::InitialSetup { password: "Good-Passw0rd".into(), config: valid_cfg() }, &cl()));
        assert!(!t.is_empty());
        // Setup cannot be repeated to take over the password.
        let again = handle(&sh, &db, R::InitialSetup { password: "Other-Passw0rd".into(), config: valid_cfg() }, &cl());
        assert!(matches!(again, Response::Error { .. }));
        // Config persisted encrypted and reloadable.
        let (loaded, warn) = crate::app::load_config(&dir);
        assert!(warn.is_none());
        assert_eq!(loaded.smtp.host, "mail.example.com");
        assert!(password::verify("Good-Passw0rd", &loaded.security.admin_password_hash));
        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn lost_configuration_does_not_reopen_first_run_setup() {
        let (sh, db, dir) = setup();
        token(handle(&sh, &db, R::InitialSetup { password: "Good-Passw0rd".into(), config: valid_cfg() }, &cl()));
        // Simulate config.dat + backup being unreadable at the next start.
        *sh.config.write().unwrap() = Config::default();
        assert!(!sh.first_run(&db));
        for r in [
            R::InitialSetup { password: "Attacker-Pass1".into(), config: valid_cfg() },
            R::GetConfig { token: String::new() },
            R::TestEmail { token: None, smtp: valid_cfg().smtp, use_stored_password: false },
        ] {
            assert!(matches!(handle(&sh, &db, r, &cl()), Response::Error { .. }));
        }
        assert!(matches!(handle(&sh, &db, R::Status, &cl()), Response::Status(s) if s.password_set));
        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn unauthorized_changes_are_rejected_and_audited() {
        let (sh, db, dir) = setup();
        token(handle(&sh, &db, R::InitialSetup { password: "Good-Passw0rd".into(), config: valid_cfg() }, &cl()));
        let mut evil = valid_cfg();
        evil.smtp.to = vec!["attacker@example.net".into()];
        for r in [
            R::SaveConfig { token: "forged".into(), config: evil.clone(), smtp_password: None, update_token: None },
            R::GetConfig { token: "forged".into() },
            R::TestEmail { token: None, smtp: evil.smtp.clone(), use_stored_password: true },
            R::AuthorizeUninstall { token: String::new() },
        ] {
            assert!(matches!(handle(&sh, &db, r, &cl()), Response::Error { .. }));
        }
        assert_eq!(sh.cfg().smtp.to, vec!["it@example.com".to_string()]);
        assert!(db.recent_audit(50).unwrap().iter().any(|a| a.action == "request rejected"));
        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn login_rate_limit_and_session_binding() {
        let (sh, db, dir) = setup();
        token(handle(&sh, &db, R::InitialSetup { password: "Good-Passw0rd".into(), config: valid_cfg() }, &cl()));
        for _ in 0..5 {
            assert!(matches!(handle(&sh, &db, R::Login { password: "wrong".into() }, &cl()), Response::Error { .. }));
        }
        // Locked: even the right password is refused now.
        match handle(&sh, &db, R::Login { password: "Good-Passw0rd".into() }, &cl()) {
            Response::Error { message } => assert!(message.contains("Too many")),
            other => panic!("{other:?}"),
        }
        assert_eq!(db.recent_audit(100).unwrap().iter().filter(|a| a.action == "sign-in failed").count(), 5);
        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn save_config_rules() {
        let (sh, db, dir) = setup();
        let mut c = valid_cfg();
        c.smtp.encryption = rdpmon_core::config::Encryption::Starttls;
        c.smtp.username = "svc".into();
        c.smtp.password = "smtp-pass".into();
        let t = token(handle(&sh, &db, R::InitialSetup { password: "Good-Passw0rd".into(), config: c.clone() }, &cl()));
        // Changing recipients keeps the stored SMTP password.
        let mut n = c.redacted();
        n.smtp.to.push("soc@example.com".into());
        assert!(matches!(handle(&sh, &db, R::SaveConfig { token: t.clone(), config: n.clone(), smtp_password: None, update_token: None }, &cl()), Response::Ok { .. }));
        assert_eq!(sh.cfg().smtp.password, "smtp-pass");
        assert_eq!(sh.cfg().smtp.to.len(), 2);
        // Redirecting the stored password to another server is refused.
        n.smtp.host = "evil.example.net".into();
        assert!(matches!(handle(&sh, &db, R::SaveConfig { token: t.clone(), config: n.clone(), smtp_password: None, update_token: None }, &cl()), Response::Error { .. }));
        // Invalid settings are refused with readable errors.
        let mut bad = c.redacted();
        bad.smtp.from = "nope".into();
        match handle(&sh, &db, R::SaveConfig { token: t.clone(), config: bad, smtp_password: None, update_token: None }, &cl()) {
            Response::Error { message } => assert!(message.contains("Sender")),
            other => panic!("{other:?}"),
        }
        // The password hash cannot be replaced through SaveConfig.
        let mut sneaky = c.redacted();
        sneaky.security.admin_password_hash = password::hash("Attacker-Pass1").unwrap();
        handle(&sh, &db, R::SaveConfig { token: t, config: sneaky, smtp_password: None, update_token: None }, &cl());
        assert!(password::verify("Good-Passw0rd", &sh.cfg().security.admin_password_hash));
        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn signed_package_import() {
        let (sh, db, dir) = setup();
        let k = generate_signing_key();
        let mut c = valid_cfg();
        c.security.trusted_config_key = b64(k.verifying_key().as_bytes());
        sh.apply_config(c).unwrap();
        let payload = "[package]\nserial = 7\n[smtp]\nto = [\"new@example.com\"]\n";
        let pkg = package::sign(payload, &k).unwrap();
        assert!(matches!(handle(&sh, &db, R::ImportPackage { data: pkg.clone() }, &cl()), Response::Ok { .. }));
        assert_eq!(sh.cfg().smtp.to, vec!["new@example.com".to_string()]);
        // Re-importing the same package is a no-op success (GPO startup scripts).
        assert!(matches!(handle(&sh, &db, R::ImportPackage { data: pkg }, &cl()), Response::Ok { .. }));
        // An older package (lower serial) is refused: no rollback by replay.
        let old = package::sign("[package]\nserial = 6\n[smtp]\nto = [\"old@example.com\"]\n", &k).unwrap();
        assert!(matches!(handle(&sh, &db, R::ImportPackage { data: old }, &cl()), Response::Error { .. }));
        // Package signed by an untrusted key is refused.
        let other = package::sign("[package]\nserial = 8\n[smtp]\nto = [\"x@example.com\"]\n", &generate_signing_key()).unwrap();
        assert!(matches!(handle(&sh, &db, R::ImportPackage { data: other }, &cl()), Response::Error { .. }));
        assert_eq!(sh.cfg().smtp.to, vec!["new@example.com".to_string()]);
        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn uninstall_requires_authorization() {
        let (sh, db, dir) = setup();
        assert!(matches!(handle(&sh, &db, R::CheckUninstall, &cl()), Response::Uninstall { authorized: false }));
        let t = token(handle(&sh, &db, R::InitialSetup { password: "Good-Passw0rd".into(), config: valid_cfg() }, &cl()));
        handle(&sh, &db, R::AuthorizeUninstall { token: t }, &cl());
        assert!(matches!(handle(&sh, &db, R::CheckUninstall, &cl()), Response::Uninstall { authorized: true }));
        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn uninstall_with_password_authorizes_removal() {
        let (sh, db, dir) = setup();
        handle(&sh, &db, R::InitialSetup { password: "Good-Passw0rd".into(), config: valid_cfg() }, &cl());
        *sh.uninstall_authorized_until.lock().unwrap() = None;
        assert!(matches!(
            handle(&sh, &db, R::AuthorizeUninstallWithPassword { password: "wrong".into() }, &cl()),
            Response::Error { .. }
        ));
        assert!(matches!(handle(&sh, &db, R::CheckUninstall, &cl()), Response::Uninstall { authorized: false }));
        assert!(matches!(
            handle(&sh, &db, R::AuthorizeUninstallWithPassword { password: "Good-Passw0rd".into() }, &cl()),
            Response::Ok { .. }
        ));
        assert!(matches!(handle(&sh, &db, R::CheckUninstall, &cl()), Response::Uninstall { authorized: true }));
        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn signed_package_can_authorize_silent_uninstall_once() {
        let (sh, db, dir) = setup();
        let k = generate_signing_key();
        let mut c = valid_cfg();
        c.security.trusted_config_key = b64(k.verifying_key().as_bytes());
        sh.apply_config(c).unwrap();
        let pkg = package::sign("[package]\nserial = 3\nauthorize_uninstall = true\n", &k).unwrap();
        assert!(matches!(handle(&sh, &db, R::ImportPackage { data: pkg.clone() }, &cl()), Response::Ok { .. }));
        assert!(matches!(handle(&sh, &db, R::CheckUninstall, &cl()), Response::Uninstall { authorized: true }));
        // Replaying the same package later must not re-open the window.
        *sh.uninstall_authorized_until.lock().unwrap() = None;
        handle(&sh, &db, R::ImportPackage { data: pkg }, &cl());
        assert!(matches!(handle(&sh, &db, R::CheckUninstall, &cl()), Response::Uninstall { authorized: false }));
        let _ = std::fs::remove_dir_all(dir);
    }
}
