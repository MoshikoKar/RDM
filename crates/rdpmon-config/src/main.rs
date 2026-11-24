//! RDP Monitor configuration utility. Runs only when opened; talks to the
//! service exclusively through the local administration pipe.

#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

slint::include_modules!();

use rdpmon_core::config::{split_addresses, Config, Encryption, UpdateProvider};
use rdpmon_core::ipc::{self, Request, Response, StatusInfo};
use std::sync::Mutex;

const DAYS: [&str; 7] = ["monday", "tuesday", "wednesday", "thursday", "friday", "saturday", "sunday"];

struct State {
    token: Option<String>,
    base: Option<Config>,
    has_smtp_password: bool,
    has_update_token: bool,
}

static STATE: Mutex<State> = Mutex::new(State { token: None, base: None, has_smtp_password: false, has_update_token: false });

fn state() -> std::sync::MutexGuard<'static, State> {
    STATE.lock().unwrap_or_else(|e| e.into_inner())
}

fn token() -> String {
    state().token.clone().unwrap_or_default()
}

fn call(req: Request) -> Result<Response, String> {
    ipc::call(&req).map_err(|e| e.to_string())
}

/// Runs `work` on a background thread and `done` on the UI thread.
fn bg<T: Send + 'static>(ui: &AppWindow, work: impl FnOnce() -> T + Send + 'static, done: impl FnOnce(&AppWindow, T) + Send + 'static) {
    ui.set_busy(true);
    let weak = ui.as_weak();
    std::thread::spawn(move || {
        let r = work();
        let _ = weak.upgrade_in_event_loop(move |ui| {
            ui.set_busy(false);
            done(&ui, r);
        });
    });
}

fn show(ui: &AppWindow, text: impl Into<String>, error: bool) {
    ui.set_message(text.into().into());
    ui.set_message_error(error);
}

/// Handles the common error cases; returns true if the caller should stop.
fn handle_error(ui: &AppWindow, r: &Result<Response, String>) -> bool {
    match r {
        Err(e) => {
            show(ui, e.clone(), true);
            true
        }
        Ok(Response::Error { message }) => {
            if message.starts_with("Not signed in") {
                state().token = None;
                ui.set_screen(1);
            }
            show(ui, message.clone(), true);
            true
        }
        _ => false,
    }
}

fn local_time(s: &str) -> String {
    chrono::DateTime::parse_from_rfc3339(s)
        .map(|t| t.with_timezone(&chrono::Local).format("%Y-%m-%d %H:%M:%S").to_string())
        .unwrap_or_else(|_| s.to_string())
}

fn channel_label(name: &str) -> &str {
    if name == "Security" {
        "Security log"
    } else if name.contains("LocalSessionManager") {
        "Session Manager log"
    } else if name.contains("RemoteConnectionManager") {
        "Remote Connection Manager log"
    } else {
        name
    }
}

fn fill_status(ui: &AppWindow, s: &StatusInfo) {
    ui.set_version(s.version.clone().into());
    ui.set_hostname(s.hostname.clone().into());
    ui.set_service_state("Running".into());
    let mon: Vec<String> = s.monitoring.iter().map(|c| format!("{}: {} ({})", channel_label(&c.name), c.state, c.detail)).collect();
    ui.set_monitoring_text(if mon.is_empty() { "Starting...".into() } else { mon.join("\n").into() });
    ui.set_queue_text(format!("{} waiting, {} failed{}", s.pending_notifications, s.failed_notifications, if s.smtp_configured { "" } else { " (email not configured)" }).into());
    ui.set_last_connection(s.last_connection.clone().unwrap_or_else(|| "none recorded".into()).into());
    ui.set_last_error(s.last_error.clone().unwrap_or_default().into());
}

fn fill_config(ui: &AppWindow, c: &Config, has_pw: bool, has_tok: bool) {
    {
        let mut st = state();
        st.base = Some(c.clone());
        st.has_smtp_password = has_pw;
        st.has_update_token = has_tok;
    }
    let s = &c.smtp;
    ui.set_smtp_host(s.host.clone().into());
    ui.set_smtp_port(s.port.to_string().into());
    ui.set_smtp_encryption(match s.encryption {
        Encryption::None => 0,
        Encryption::Starttls => 1,
        Encryption::Tls => 2,
    });
    ui.set_smtp_user(s.username.clone().into());
    ui.set_smtp_password("".into());
    ui.set_has_smtp_password(has_pw);
    ui.set_mail_from(s.from.clone().into());
    ui.set_mail_to(s.to.join("\n").into());
    ui.set_mail_cc(s.cc.join(", ").into());
    ui.set_mail_bcc(s.bcc.join(", ").into());
    let n = &c.notifications;
    ui.set_subject_format(n.subject_format.clone().into());
    ui.set_notify_new(n.notify_new_logons);
    ui.set_notify_reconnect(n.notify_reconnects);
    ui.set_cooldown(n.cooldown_minutes.to_string().into());
    let m = &c.monitoring;
    ui.set_security_log(m.security_log);
    ui.set_lsm_log(m.session_manager_log);
    ui.set_auth_log(m.auth_log);
    ui.set_ignore_loopback(m.ignore_loopback);
    ui.set_recovery_hours(m.recovery_max_hours.to_string().into());
    ui.set_history_days(c.retention.history_days.to_string().into());
    let r = &c.report;
    ui.set_report_enabled(r.enabled);
    ui.set_report_day(DAYS.iter().position(|d| r.day.eq_ignore_ascii_case(d) || r.day.to_lowercase().starts_with(&d[..3])).unwrap_or(0) as i32);
    ui.set_report_time(r.time.clone().into());
    ui.set_report_recipients(r.recipients.join(", ").into());
    ui.set_trusted_key(c.security.trusted_config_key.clone().into());
    ui.set_harden(c.security.harden_service);
    let u = &c.updates;
    ui.set_update_provider(match u.provider {
        UpdateProvider::None => 0,
        UpdateProvider::Github => 1,
        UpdateProvider::Gitlab => 2,
    });
    ui.set_repo_url(u.repository_url.clone().into());
    ui.set_update_token("".into());
    ui.set_has_update_token(has_tok);
    ui.set_signing_key(u.signing_public_key.clone().into());

    let onoff = |b: bool| if b { "on" } else { "off" };
    let cooldown = if n.cooldown_minutes == 0 { "every connection is emailed".to_string() } else { format!("{} minutes", n.cooldown_minutes) };
    let report = if r.enabled { format!("{} at {}", r.day, r.time) } else { "off".into() };
    let to = if s.to.is_empty() { "none (email not configured)".to_string() } else { s.to.join(", ") };
    ui.set_notification_summary(
        format!("New logins: {}    Reconnections: {}    Quiet period: {cooldown}\nRecipients: {to}\nWeekly report: {report}", onoff(n.notify_new_logons), onoff(n.notify_reconnects))
            .into(),
    );
}

fn parse_num<T: std::str::FromStr>(v: &str, what: &str) -> Result<T, String> {
    v.trim().parse::<T>().map_err(|_| format!("{what} must be a whole number."))
}

/// Builds the configuration from the form. Secrets: None = keep the stored value.
fn read_config(ui: &AppWindow) -> Result<(Config, Option<String>, Option<String>), String> {
    let (mut c, has_pw, has_tok) = {
        let st = state();
        (st.base.clone().unwrap_or_default(), st.has_smtp_password, st.has_update_token)
    };
    c.smtp.host = ui.get_smtp_host().trim().to_string();
    c.smtp.port = parse_num(&ui.get_smtp_port(), "SMTP port")?;
    c.smtp.encryption = match ui.get_smtp_encryption() {
        1 => Encryption::Starttls,
        2 => Encryption::Tls,
        _ => Encryption::None,
    };
    c.smtp.username = ui.get_smtp_user().trim().to_string();
    c.smtp.from = ui.get_mail_from().trim().to_string();
    c.smtp.to = split_addresses(&ui.get_mail_to());
    c.smtp.cc = split_addresses(&ui.get_mail_cc());
    c.smtp.bcc = split_addresses(&ui.get_mail_bcc());
    c.notifications.subject_format = ui.get_subject_format().trim().to_string();
    c.notifications.notify_new_logons = ui.get_notify_new();
    c.notifications.notify_reconnects = ui.get_notify_reconnect();
    c.notifications.cooldown_minutes = parse_num(&ui.get_cooldown(), "Quiet period")?;
    c.monitoring.security_log = ui.get_security_log();
    c.monitoring.session_manager_log = ui.get_lsm_log();
    c.monitoring.auth_log = ui.get_auth_log();
    c.monitoring.ignore_loopback = ui.get_ignore_loopback();
    c.monitoring.recovery_max_hours = parse_num(&ui.get_recovery_hours(), "Recovery period")?;
    c.retention.history_days = parse_num(&ui.get_history_days(), "History retention")?;
    c.report.enabled = ui.get_report_enabled();
    c.report.day = DAYS[(ui.get_report_day().clamp(0, 6)) as usize].to_string();
    c.report.time = ui.get_report_time().trim().to_string();
    c.report.recipients = split_addresses(&ui.get_report_recipients());
    c.security.trusted_config_key = ui.get_trusted_key().trim().to_string();
    c.security.harden_service = ui.get_harden();
    c.updates.provider = match ui.get_update_provider() {
        1 => UpdateProvider::Github,
        2 => UpdateProvider::Gitlab,
        _ => UpdateProvider::None,
    };
    c.updates.repository_url = ui.get_repo_url().trim().to_string();
    c.updates.signing_public_key = ui.get_signing_key().trim().to_string();
    let pw = ui.get_smtp_password().to_string();
    let smtp_pw = if pw.is_empty() && has_pw && !c.smtp.username.is_empty() { None } else { Some(pw) };
    let tok = ui.get_update_token().trim().to_string();
    let update_token = if tok.is_empty() && has_tok { None } else { Some(tok) };
    c.smtp.password = smtp_pw.clone().unwrap_or_default();
    Ok((c, smtp_pw, update_token))
}

enum Loaded {
    Failed(String),
    Setup(StatusInfo, Config, bool, bool),
    SignIn(StatusInfo),
    Main(StatusInfo, Config, bool, bool, Vec<rdpmon_core::ipc::HistoryEntry>),
}

fn load() -> Loaded {
    let status = match call(Request::Status) {
        Ok(Response::Status(s)) => s,
        Ok(Response::Error { message }) => return Loaded::Failed(message),
        Ok(_) => return Loaded::Failed("Unexpected response from the service.".into()),
        Err(e) => return Loaded::Failed(e),
    };
    let tok = token();
    if status.password_set && tok.is_empty() {
        return Loaded::SignIn(status);
    }
    match call(Request::GetConfig { token: tok.clone() }) {
        Ok(Response::Config { config, has_smtp_password, has_update_token }) => {
            if !status.password_set {
                return Loaded::Setup(status, config, has_smtp_password, has_update_token);
            }
            let history = match call(Request::GetHistory { token: tok, limit: 100 }) {
                Ok(Response::History { entries }) => entries,
                _ => Vec::new(),
            };
            Loaded::Main(status, config, has_smtp_password, has_update_token, history)
        }
        Ok(Response::Error { .. }) => {
            state().token = None;
            Loaded::SignIn(status)
        }
        Ok(_) => Loaded::Failed("Unexpected response from the service.".into()),
        Err(e) => Loaded::Failed(e),
    }
}

fn refresh(ui: &AppWindow) {
    bg(ui, load, |ui, r| match r {
        Loaded::Failed(e) => {
            ui.set_screen(0);
            show(ui, e, true);
        }
        Loaded::SignIn(s) => {
            fill_status(ui, &s);
            ui.set_screen(1);
            if s.locked_out_seconds > 0 {
                show(ui, format!("Sign-in is temporarily locked after failed attempts. Try again in {} seconds.", s.locked_out_seconds), true);
            }
        }
        Loaded::Setup(s, c, p, t) => {
            fill_status(ui, &s);
            fill_config(ui, &c, p, t);
            ui.set_setup_step(0);
            ui.set_screen(3);
            show(ui, "", false);
        }
        Loaded::Main(s, c, p, t, history) => {
            fill_status(ui, &s);
            fill_config(ui, &c, p, t);
            let lines: Vec<String> = history
                .iter()
                .map(|h| {
                    let user = if h.domain.is_empty() { h.user.clone() } else { format!("{}\\{}", h.domain, h.user) };
                    format!("{}  {:<10}  {:<28}  {:<16}  {}", local_time(&h.time), h.kind, user, h.source_ip, h.notification)
                })
                .collect();
            ui.set_history_text(if lines.is_empty() { "No RDP connections recorded yet.".into() } else { lines.join("\n").into() });
            ui.set_screen(2);
        }
    });
}

fn main() -> Result<(), slint::PlatformError> {
    let ui = AppWindow::new()?;

    ui.on_refresh({
        let w = ui.as_weak();
        move || {
            if let Some(ui) = w.upgrade() {
                show(&ui, "", false);
                refresh(&ui);
            }
        }
    });

    ui.on_login({
        let w = ui.as_weak();
        move || {
            let Some(ui) = w.upgrade() else { return };
            let password = ui.get_login_password().to_string();
            ui.set_login_password("".into());
            bg(&ui, move || call(Request::Login { password }), |ui, r| {
                if let Ok(Response::Token { token }) = &r {
                    state().token = Some(token.clone());
                    show(ui, "", false);
                    refresh(ui);
                } else if !handle_error(ui, &r) {
                    show(ui, "Unexpected response.", true);
                }
            });
        }
    });

    ui.on_logout({
        let w = ui.as_weak();
        move || {
            let Some(ui) = w.upgrade() else { return };
            let t = token();
            state().token = None;
            let _ = std::thread::spawn(move || call(Request::Logout { token: t }));
            ui.set_screen(1);
            show(&ui, "Signed out.", false);
        }
    });

    ui.on_save({
        let w = ui.as_weak();
        move || {
            let Some(ui) = w.upgrade() else { return };
            let (config, smtp_password, update_token) = match read_config(&ui) {
                Ok(x) => x,
                Err(e) => return show(&ui, e, true),
            };
            let token = token();
            bg(&ui, move || call(Request::SaveConfig { token, config, smtp_password, update_token }), |ui, r| {
                if handle_error(ui, &r) {
                    return;
                }
                if let Ok(Response::Ok { message }) = r {
                    show(ui, message, false);
                    refresh(ui);
                }
            });
        }
    });

    ui.on_test_email({
        let w = ui.as_weak();
        move || {
            let Some(ui) = w.upgrade() else { return };
            let (config, smtp_pw, _) = match read_config(&ui) {
                Ok(x) => x,
                Err(e) => return show(&ui, e, true),
            };
            let tok = state().token.clone();
            show(&ui, "Sending test email...", false);
            bg(&ui, move || call(Request::TestEmail { token: tok, smtp: config.smtp, use_stored_password: smtp_pw.is_none() }), |ui, r| {
                if handle_error(ui, &r) {
                    return;
                }
                if let Ok(Response::Ok { message }) = r {
                    show(ui, message, false);
                }
            });
        }
    });

    ui.on_setup_finish({
        let w = ui.as_weak();
        move || {
            let Some(ui) = w.upgrade() else { return };
            let password = ui.get_new_password().to_string();
            if password != ui.get_confirm_password().as_str() {
                ui.set_setup_step(3);
                return show(&ui, "The two passwords do not match.", true);
            }
            if let Err(e) = rdpmon_core::password::check_strength(&password) {
                ui.set_setup_step(3);
                return show(&ui, e, true);
            }
            let (config, _, _) = match read_config(&ui) {
                Ok(x) => x,
                Err(e) => return show(&ui, e, true),
            };
            bg(&ui, move || call(Request::InitialSetup { password, config }), |ui, r| {
                if handle_error(ui, &r) {
                    return;
                }
                if let Ok(Response::Token { token }) = r {
                    state().token = Some(token);
                    ui.set_new_password("".into());
                    ui.set_confirm_password("".into());
                    ui.set_page(0);
                    show(ui, "Setup complete. RDP Monitor is protected by your administration password.", false);
                    refresh(ui);
                }
            });
        }
    });

    ui.on_change_password({
        let w = ui.as_weak();
        move || {
            let Some(ui) = w.upgrade() else { return };
            let (cur, new) = (ui.get_current_password().to_string(), ui.get_new_password().to_string());
            if new != ui.get_confirm_password().as_str() {
                return show(&ui, "The new passwords do not match.", true);
            }
            if let Err(e) = rdpmon_core::password::check_strength(&new) {
                return show(&ui, e, true);
            }
            let token = token();
            bg(&ui, move || call(Request::ChangePassword { token, current_password: cur, new_password: new }), |ui, r| {
                ui.set_current_password("".into());
                if handle_error(ui, &r) {
                    return;
                }
                if let Ok(Response::Token { token }) = r {
                    state().token = Some(token);
                    ui.set_new_password("".into());
                    ui.set_confirm_password("".into());
                    show(ui, "Administration password changed.", false);
                }
            });
        }
    });

    let simple = |ui: &AppWindow, req: fn(String) -> Request| {
        let token = token();
        bg(ui, move || call(req(token)), |ui, r| {
            if handle_error(ui, &r) {
                return;
            }
            if let Ok(Response::Ok { message }) = r {
                show(ui, message, false);
            }
        });
    };

    ui.on_restart_monitoring({
        let w = ui.as_weak();
        move || {
            if let Some(ui) = w.upgrade() {
                simple(&ui, |token| Request::RestartMonitoring { token });
            }
        }
    });

    ui.on_authorize_uninstall({
        let w = ui.as_weak();
        move || {
            if let Some(ui) = w.upgrade() {
                simple(&ui, |token| Request::AuthorizeUninstall { token });
            }
        }
    });

    ui.on_load_audit({
        let w = ui.as_weak();
        move || {
            let Some(ui) = w.upgrade() else { return };
            let token = token();
            bg(&ui, move || call(Request::GetAudit { token, limit: 300 }), |ui, r| {
                if handle_error(ui, &r) {
                    return;
                }
                if let Ok(Response::Audit { entries }) = r {
                    let lines: Vec<String> = entries.iter().map(|a| format!("{}  [{}] {} - {}", local_time(&a.time), a.category, a.action, a.detail)).collect();
                    ui.set_audit_text(lines.join("\n").into());
                }
            });
        }
    });

    ui.on_check_updates({
        let w = ui.as_weak();
        move || {
            let Some(ui) = w.upgrade() else { return };
            let token = token();
            ui.set_update_message("Checking...".into());
            bg(&ui, move || call(Request::CheckUpdates { token }), |ui, r| {
                ui.set_update_message("".into());
                if handle_error(ui, &r) {
                    return;
                }
                if let Ok(Response::Update(i)) = r {
                    let latest = i.latest_version.clone().unwrap_or_default();
                    ui.set_update_latest(latest.clone().into());
                    ui.set_update_available(i.update_available);
                    let mut m = format!("Installed: {}   Latest available: {}", i.current_version, if latest.is_empty() { "-" } else { &latest });
                    if !i.published_at.is_empty() {
                        m.push_str(&format!("   Published: {}", local_time(&i.published_at)));
                    }
                    m.push_str(&format!("\n{}", i.message));
                    ui.set_update_message(m.into());
                    ui.set_update_notes(if i.release_notes.is_empty() { "".into() } else { format!("{}\n\n{}", i.release_name, i.release_notes).into() });
                }
            });
        }
    });

    ui.on_install_update({
        let w = ui.as_weak();
        move || {
            let Some(ui) = w.upgrade() else { return };
            let token = token();
            let version = ui.get_update_latest().to_string();
            ui.set_update_message(format!("Downloading and verifying {version}...").into());
            bg(&ui, move || call(Request::InstallUpdate { token, version }), |ui, r| {
                if handle_error(ui, &r) {
                    ui.set_update_message("".into());
                    return;
                }
                if let Ok(Response::Ok { message }) = r {
                    ui.set_update_available(false);
                    ui.set_update_message(message.into());
                }
            });
        }
    });

    #[cfg(debug_assertions)]
    if let Some(i) = std::env::args().position(|a| a == "--layout-preview") {
        // Development aid only (compiled out of release builds): render a
        // screen with default values to check the layout without a service.
        let n: i32 = std::env::args().nth(i + 1).and_then(|v| v.parse().ok()).unwrap_or(0);
        let mut c = Config::default();
        c.smtp.to = vec!["it@example.com".into()];
        fill_config(&ui, &c, false, false);
        ui.set_hostname("PREVIEW-PC".into());
        ui.set_version(rdpmon_core::VERSION.into());
        if n >= 10 {
            ui.set_screen(3);
            ui.set_setup_step(n - 10);
        } else {
            ui.set_screen(2);
            ui.set_page(n);
        }
        return ui.run();
    }

    refresh(&ui);
    ui.run()
}
