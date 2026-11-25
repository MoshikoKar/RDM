//! Agent configuration. Serialized as TOML; stored on disk only in
//! DPAPI-protected form (see `rdpmon-svc::store`).

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "lowercase")]
pub enum Encryption {
    /// Plain SMTP (only acceptable for internal relays).
    #[default]
    None,
    /// Plain connection upgraded with STARTTLS (required, not opportunistic).
    Starttls,
    /// Implicit TLS (SMTPS, usually port 465).
    Tls,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "lowercase")]
pub enum UpdateProvider {
    #[default]
    None,
    Github,
    Gitlab,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct SmtpConfig {
    pub host: String,
    pub port: u16,
    pub encryption: Encryption,
    /// Empty = no authentication.
    pub username: String,
    /// Secret. Never returned to the configuration utility.
    pub password: String,
    pub from: String,
    pub to: Vec<String>,
    pub cc: Vec<String>,
    pub bcc: Vec<String>,
    pub timeout_seconds: u32,
}

impl Default for SmtpConfig {
    fn default() -> Self {
        Self {
            host: String::new(),
            port: 25,
            encryption: Encryption::None,
            username: String::new(),
            password: String::new(),
            from: String::new(),
            to: Vec::new(),
            cc: Vec::new(),
            bcc: Vec::new(),
            timeout_seconds: 30,
        }
    }
}

impl SmtpConfig {
    pub fn is_configured(&self) -> bool {
        !self.host.trim().is_empty() && !self.from.trim().is_empty() && !self.to.is_empty()
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct NotificationConfig {
    /// Placeholders: {user} {domain} {ip} {host} {type} {time}
    pub subject_format: String,
    pub notify_new_logons: bool,
    pub notify_reconnects: bool,
    /// Email when a session is disconnected (4779 / LSM 24). Off by default.
    pub notify_disconnects: bool,
    /// Email when a user logs off (LSM 23, subscribed only when on).
    pub notify_logoffs: bool,
    /// 0 = notify on every distinct connection.
    pub cooldown_minutes: u32,
    /// Maximum number of undelivered notifications kept in the queue.
    pub max_queue: u32,
    /// Give up retrying a notification after this many hours.
    pub retry_hours: u32,
    /// Extra address ranges (CIDR, e.g. a VPN pool) shown as "Internal" in
    /// alerts. Private, CGNAT, link-local and ULA ranges always are.
    pub internal_networks: Vec<String>,
    /// "HH:MM-HH:MM" local time. Empty = no off-hours row in alerts.
    pub business_hours: String,
    pub business_days: Vec<String>,
}

impl Default for NotificationConfig {
    fn default() -> Self {
        Self {
            subject_format: "RDP ALERT: {user} from {ip} to {host}".into(),
            notify_new_logons: true,
            notify_reconnects: true,
            notify_disconnects: false,
            notify_logoffs: false,
            cooldown_minutes: 15,
            max_queue: 500,
            retry_hours: 72,
            internal_networks: Vec::new(),
            business_hours: String::new(),
            business_days: ["sunday", "monday", "tuesday", "wednesday", "thursday"].map(String::from).to_vec(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct MonitoringConfig {
    /// Security log: 4624 (LogonType 10), 4778, 4779.
    pub security_log: bool,
    /// TerminalServices-LocalSessionManager/Operational: 21, 24, 25.
    pub session_manager_log: bool,
    /// TerminalServices-RemoteConnectionManager/Operational: 1149 (supporting evidence only).
    pub auth_log: bool,
    /// Ignore connections from 127.0.0.1 / ::1. Off by default: RDP through
    /// a local tunnel (SSH, chisel, ...) arrives from loopback.
    pub ignore_loopback: bool,
    /// After a restart, recover missed events up to this age (hours).
    pub recovery_max_hours: u32,
    /// Events for the same user + source IP within this window are one connection.
    pub correlation_window_seconds: u32,
}

impl Default for MonitoringConfig {
    fn default() -> Self {
        Self {
            security_log: true,
            session_manager_log: true,
            auth_log: true,
            ignore_loopback: false,
            recovery_max_hours: 168,
            correlation_window_seconds: 30,
        }
    }
}

/// Alerts on repeated failed logons (4625, LogonType 3 or 10) from one IP.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct FailedLogonConfig {
    /// Off by default; the 4625 subscription exists only when enabled.
    pub enabled: bool,
    /// Failures from one IP within the window that trigger an alert.
    pub threshold: u32,
    pub window_minutes: u32,
}

impl Default for FailedLogonConfig {
    fn default() -> Self {
        Self { enabled: false, threshold: 5, window_minutes: 5 }
    }
}

/// Access to this computer's shared folders (Security 5140 / 5145 / 4625).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct SmbConfig {
    /// Off by default; no share events are subscribed unless enabled.
    pub enabled: bool,
    /// Email on successful share access (5140).
    pub notify_success: bool,
    /// Email on denied share access (5145 / 5140 failure) and enable the
    /// failed-logon alert (4625) for network logons.
    pub notify_failed: bool,
    /// Share names (e.g. "IPC$", "print$") never emailed; still recorded.
    pub exclude_shares: Vec<String>,
    /// Email only for shares whose name ends with '$' (C$, ADMIN$, ...).
    pub admin_shares_only: bool,
}

impl Default for SmbConfig {
    fn default() -> Self {
        Self { enabled: false, notify_success: true, notify_failed: true, exclude_shares: Vec::new(), admin_shares_only: false }
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct ReportConfig {
    pub enabled: bool,
    /// monday … sunday
    pub day: String,
    /// Local time, HH:MM (24h).
    pub time: String,
    pub period_days: u32,
    /// Empty = use the notification recipients.
    pub recipients: Vec<String>,
}

impl Default for ReportConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            day: "monday".into(),
            time: "08:00".into(),
            period_days: 7,
            recipients: Vec::new(),
        }
    }
}

/// Daily sign-of-life email and email-delivery recovery summary.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct HeartbeatConfig {
    pub enabled: bool,
    /// Local time, HH:MM (24h).
    pub time: String,
    /// Empty = use the notification recipients.
    pub recipients: Vec<String>,
    /// After an email outage, send one summary of delayed / dropped alerts.
    pub recovery_summary: bool,
}

impl Default for HeartbeatConfig {
    fn default() -> Self {
        Self { enabled: false, time: "08:00".into(), recipients: Vec::new(), recovery_summary: false }
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct RetentionConfig {
    pub history_days: u32,
    pub audit_days: u32,
    /// Sent / failed notifications are kept this long for troubleshooting.
    pub outbox_days: u32,
}

impl Default for RetentionConfig {
    fn default() -> Self {
        Self { history_days: 365, audit_days: 365, outbox_days: 30 }
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct SecurityConfig {
    /// Argon2id PHC string. Never returned to the configuration utility.
    pub admin_password_hash: String,
    /// Base64 Ed25519 public key that signs configuration packages.
    pub trusted_config_key: String,
    /// Restrict the Windows service DACL so Administrators cannot stop,
    /// reconfigure or delete the service through the SCM.
    pub harden_service: bool,
    /// Serial of the last applied configuration package (replay protection).
    pub last_package_serial: u64,
}

impl Default for SecurityConfig {
    fn default() -> Self {
        Self {
            admin_password_hash: String::new(),
            trusted_config_key: String::new(),
            harden_service: true,
            last_package_serial: 0,
        }
    }
}

/// Official release repository, used when no other source is configured.
pub const DEFAULT_UPDATE_REPOSITORY: &str = "https://github.com/MoshikoKar/RDM";
/// Public half of the key the official release workflow signs packages with.
pub const BUILTIN_UPDATE_SIGNING_KEY: &str = "SS5E0F0F1ouuO/5Ww0R5IDU06YpYjPbCEb66Jued9dg=";

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct UpdateConfig {
    pub provider: UpdateProvider,
    /// e.g. https://github.com/org/rdp-monitor or https://gitlab.example.com/it/rdp-monitor
    pub repository_url: String,
    /// Secret. Personal/project access token for private repositories.
    pub token: String,
    /// Base64 Ed25519 public key that signs release packages. Empty = the
    /// built-in key of the official releases.
    pub signing_public_key: String,
    pub allow_prerelease: bool,
    /// Check once a day and install a newer signed release automatically.
    pub auto_install: bool,
    /// Local time (HH:MM) of the daily check.
    pub check_time: String,
}

impl Default for UpdateConfig {
    fn default() -> Self {
        Self {
            provider: UpdateProvider::Github,
            repository_url: DEFAULT_UPDATE_REPOSITORY.into(),
            token: String::new(),
            signing_public_key: String::new(),
            allow_prerelease: false,
            auto_install: true,
            check_time: "03:00".into(),
        }
    }
}

impl UpdateConfig {
    /// The key release signatures are verified with.
    pub fn effective_signing_key(&self) -> &str {
        if self.signing_public_key.is_empty() { BUILTIN_UPDATE_SIGNING_KEY } else { &self.signing_public_key }
    }

    /// Versions before 0.2.1 defaulted to no update source and saved that
    /// explicitly; a source that was never set up gets the official one.
    fn migrate_unconfigured(&mut self) {
        if self.provider == UpdateProvider::None && self.repository_url.is_empty() && self.signing_public_key.is_empty() && self.token.is_empty() {
            let keep = (self.allow_prerelease, self.auto_install, self.check_time.clone());
            *self = Self::default();
            (self.allow_prerelease, self.auto_install, self.check_time) = keep;
        }
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, Default)]
#[serde(default, deny_unknown_fields)]
pub struct Config {
    pub smtp: SmtpConfig,
    pub notifications: NotificationConfig,
    pub monitoring: MonitoringConfig,
    pub failed_logons: FailedLogonConfig,
    pub smb: SmbConfig,
    pub report: ReportConfig,
    pub heartbeat: HeartbeatConfig,
    pub retention: RetentionConfig,
    pub security: SecurityConfig,
    pub updates: UpdateConfig,
}

impl Config {
    pub fn from_toml(text: &str) -> Result<Self, String> {
        let mut c: Self = toml::from_str(text).map_err(|e| format!("Invalid configuration: {e}"))?;
        c.updates.migrate_unconfigured();
        Ok(c)
    }

    /// Failed logons (4625) are watched for the failed-logon alert itself or
    /// for failed access to shared folders.
    pub fn failed_logons_active(&self) -> bool {
        self.failed_logons.enabled || (self.smb.enabled && self.smb.notify_failed)
    }

    pub fn to_toml(&self) -> String {
        toml::to_string_pretty(self).expect("configuration is always serializable")
    }

    /// Copy without secrets, for display in the configuration utility.
    pub fn redacted(&self) -> Self {
        let mut c = self.clone();
        c.smtp.password.clear();
        c.updates.token.clear();
        c.security.admin_password_hash.clear();
        c
    }

    /// Validates all settings. Returns every problem found, in plain language.
    pub fn validate(&self) -> Result<(), Vec<String>> {
        let mut errs = Vec::new();
        let s = &self.smtp;
        let smtp_used = !s.host.trim().is_empty() || !s.to.is_empty() || !s.from.trim().is_empty();
        if smtp_used {
            if s.host.trim().is_empty() {
                errs.push("SMTP server is required.".into());
            } else if !is_valid_host(s.host.trim()) {
                errs.push(format!("SMTP server '{}' is not a valid host name or IP address.", s.host));
            }
            if s.port == 0 {
                errs.push("SMTP port must be between 1 and 65535.".into());
            }
            if !is_valid_email(&s.from) {
                errs.push(format!("Sender address '{}' is not a valid email address.", s.from));
            }
            if s.to.is_empty() {
                errs.push("At least one recipient is required.".into());
            }
            for (label, list) in [("Recipient", &s.to), ("CC", &s.cc), ("BCC", &s.bcc)] {
                for a in list {
                    if !is_valid_email(a) {
                        errs.push(format!("{label} '{a}' is not a valid email address."));
                    }
                }
            }
            if !s.password.is_empty() && s.username.trim().is_empty() {
                errs.push("An SMTP password was given without a user name.".into());
            }
            if !s.username.trim().is_empty() && s.encryption == Encryption::None {
                errs.push("SMTP authentication requires STARTTLS or TLS so the password is not sent in clear text.".into());
            }
            if has_control(&s.username) {
                errs.push("SMTP user name contains invalid characters.".into());
            }
            if !(5..=300).contains(&s.timeout_seconds) {
                errs.push("SMTP timeout must be between 5 and 300 seconds.".into());
            }
        }
        let n = &self.notifications;
        if n.subject_format.trim().is_empty() || n.subject_format.len() > 200 || has_control(&n.subject_format) {
            errs.push("Email subject must be 1-200 characters on a single line.".into());
        }
        if n.cooldown_minutes > 10_080 {
            errs.push("Cooldown cannot exceed 10080 minutes (7 days).".into());
        }
        if !(10..=100_000).contains(&n.max_queue) {
            errs.push("Queue limit must be between 10 and 100000.".into());
        }
        if !(1..=720).contains(&n.retry_hours) {
            errs.push("Retry period must be between 1 and 720 hours.".into());
        }
        for c in &n.internal_networks {
            if parse_cidr(c).is_none() {
                errs.push(format!("Internal network '{c}' must be an address range such as 10.20.0.0/16."));
            }
        }
        if !n.business_hours.trim().is_empty() && parse_hours_range(&n.business_hours).is_none() {
            errs.push(format!("Business hours '{}' must look like 08:00-19:00 (start before end).", n.business_hours));
        }
        for d in &n.business_days {
            if parse_weekday(d).is_none() {
                errs.push(format!("Business day '{d}' is not a weekday name."));
            }
        }
        let m = &self.monitoring;
        if !m.security_log && !m.session_manager_log {
            errs.push("Enable at least one of the Security log or the Session Manager log.".into());
        }
        if self.notifications.notify_logoffs && !m.session_manager_log {
            errs.push("Logoff notifications need the Session Manager log.".into());
        }
        if m.recovery_max_hours > 24 * 31 {
            errs.push("Event recovery period cannot exceed 744 hours (31 days).".into());
        }
        if !(5..=300).contains(&m.correlation_window_seconds) {
            errs.push("Correlation window must be between 5 and 300 seconds.".into());
        }
        let f = &self.failed_logons;
        if !(1..=1000).contains(&f.threshold) {
            errs.push("Failed logon threshold must be between 1 and 1000.".into());
        }
        if !(1..=1440).contains(&f.window_minutes) {
            errs.push("Failed logon window must be between 1 and 1440 minutes.".into());
        }
        for s in &self.smb.exclude_shares {
            if s.trim().is_empty() || s.len() > 80 || has_control(s) || s.contains('\\') {
                errs.push(format!("Excluded share '{s}' must be a share name such as IPC$ (1-80 characters, no backslash)."));
            }
        }
        let r = &self.report;
        if parse_weekday(&r.day).is_none() {
            errs.push(format!("Report day '{}' is not a weekday name.", r.day));
        }
        if parse_hhmm(&r.time).is_none() {
            errs.push(format!("Report time '{}' must be HH:MM (24-hour).", r.time));
        }
        if !(1..=31).contains(&r.period_days) {
            errs.push("Report period must be between 1 and 31 days.".into());
        }
        for a in &r.recipients {
            if !is_valid_email(a) {
                errs.push(format!("Report recipient '{a}' is not a valid email address."));
            }
        }
        if r.enabled && smtp_used && r.recipients.is_empty() && s.to.is_empty() {
            errs.push("Weekly report needs recipients.".into());
        }
        let h = &self.heartbeat;
        if parse_hhmm(&h.time).is_none() {
            errs.push(format!("Heartbeat time '{}' must be HH:MM (24-hour).", h.time));
        }
        for a in &h.recipients {
            if !is_valid_email(a) {
                errs.push(format!("Heartbeat recipient '{a}' is not a valid email address."));
            }
        }
        let t = &self.retention;
        for (label, v) in [("History", t.history_days), ("Audit", t.audit_days), ("Notification queue", t.outbox_days)] {
            if !(1..=3650).contains(&v) {
                errs.push(format!("{label} retention must be between 1 and 3650 days."));
            }
        }
        let sec = &self.security;
        if !sec.trusted_config_key.is_empty() && crate::crypto::decode_public_key(&sec.trusted_config_key).is_err() {
            errs.push("Trusted configuration key is not a valid Ed25519 public key.".into());
        }
        if !sec.admin_password_hash.is_empty() && !crate::password::is_valid_hash(&sec.admin_password_hash) {
            errs.push("Administration password hash is not a valid Argon2id hash.".into());
        }
        let u = &self.updates;
        if u.provider != UpdateProvider::None {
            if !u.repository_url.starts_with("https://") {
                errs.push("Update repository URL must start with https://".into());
            } else if repo_host_and_path(&u.repository_url).is_none() {
                errs.push("Update repository URL must look like https://host/owner/project".into());
            }
        }
        if parse_hhmm(&u.check_time).is_none() {
            errs.push("Update check time must be HH:MM (24-hour).".into());
        }
        if !u.signing_public_key.is_empty() && crate::crypto::decode_public_key(&u.signing_public_key).is_err() {
            errs.push("Update signing key is not a valid Ed25519 public key.".into());
        }
        if has_control(&u.token) {
            errs.push("Update token contains invalid characters.".into());
        }
        if errs.is_empty() { Ok(()) } else { Err(errs) }
    }
}

fn has_control(s: &str) -> bool {
    s.chars().any(|c| c.is_control())
}

/// Conservative email syntax check (the mailer performs full RFC parsing).
pub fn is_valid_email(s: &str) -> bool {
    let s = s.trim();
    if s.is_empty() || s.len() > 254 || s.chars().any(|c| c.is_control() || c.is_whitespace() || ",;<>\"()[]\\".contains(c)) {
        return false;
    }
    let mut parts = s.split('@');
    let (Some(local), Some(domain), None) = (parts.next(), parts.next(), parts.next()) else {
        return false;
    };
    !local.is_empty() && local.len() <= 64 && is_valid_host(domain)
}

pub fn is_valid_host(h: &str) -> bool {
    if h.parse::<std::net::IpAddr>().is_ok() {
        return true;
    }
    !h.is_empty()
        && h.len() <= 253
        && h.split('.').all(|l| {
            !l.is_empty() && l.len() <= 63 && !l.starts_with('-') && !l.ends_with('-')
                && l.chars().all(|c| c.is_ascii_alphanumeric() || c == '-')
        })
}

pub fn parse_weekday(s: &str) -> Option<chrono::Weekday> {
    s.trim().parse::<chrono::Weekday>().ok()
}

pub fn parse_hhmm(s: &str) -> Option<(u32, u32)> {
    let (h, m) = s.trim().split_once(':')?;
    if h.is_empty() || h.len() > 2 || m.len() != 2 {
        return None;
    }
    let (h, m) = (h.parse::<u32>().ok()?, m.parse::<u32>().ok()?);
    (h < 24 && m < 60).then_some((h, m))
}

/// "08:00-19:00" -> ((8, 0), (19, 0)); the start must be before the end.
pub fn parse_hours_range(s: &str) -> Option<((u32, u32), (u32, u32))> {
    let (a, b) = s.trim().split_once('-')?;
    let (a, b) = (parse_hhmm(a)?, parse_hhmm(b)?);
    (a < b).then_some((a, b))
}

/// "10.0.0.0/8", "fd00::/8" or a single address -> (network, prefix length).
pub fn parse_cidr(s: &str) -> Option<(std::net::IpAddr, u8)> {
    let s = s.trim();
    let (a, p) = s.split_once('/').unwrap_or((s, ""));
    let ip: std::net::IpAddr = a.trim().parse().ok()?;
    let max = if ip.is_ipv4() { 32 } else { 128 };
    let p: u8 = if p.is_empty() { max } else { p.trim().parse().ok()? };
    (p <= max).then_some((ip, p))
}

pub fn cidr_contains(net: (std::net::IpAddr, u8), ip: std::net::IpAddr) -> bool {
    use std::net::IpAddr::{V4, V6};
    let p = net.1 as u32;
    match (net.0, ip) {
        (V4(n), V4(a)) => {
            let m = if p == 0 { 0 } else { u32::MAX << (32 - p) };
            u32::from(n) & m == u32::from(a) & m
        }
        (V6(n), V6(a)) => {
            let m = if p == 0 { 0 } else { u128::MAX << (128 - p) };
            u128::from(n) & m == u128::from(a) & m
        }
        _ => false,
    }
}

/// Splits `https://host[:port]/a/b/c` into (host[:port], "a/b/c").
pub fn repo_host_and_path(url: &str) -> Option<(String, String)> {
    let rest = url.strip_prefix("https://")?;
    let (host, path) = rest.split_once('/')?;
    let path = path.trim_end_matches('/').trim_end_matches(".git").trim_end_matches('/');
    if host.is_empty() || host.contains('@') || path.split('/').filter(|p| !p.is_empty()).count() < 2 {
        return None;
    }
    if path.contains("..") || path.contains('?') || path.contains('#') {
        return None;
    }
    Some((host.to_ascii_lowercase(), path.to_string()))
}

/// Splits free text (commas, semicolons, whitespace, new lines) into addresses.
pub fn split_addresses(s: &str) -> Vec<String> {
    s.split(|c: char| c == ',' || c == ';' || c.is_whitespace())
        .map(str::trim)
        .filter(|x| !x.is_empty())
        .map(String::from)
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn valid() -> Config {
        let mut c = Config::default();
        c.smtp.host = "mail.example.com".into();
        c.smtp.from = "rdp-monitor@example.com".into();
        c.smtp.to = vec!["it@example.com".into()];
        c
    }

    #[test]
    fn default_config_is_valid() {
        assert!(Config::default().validate().is_ok());
        assert!(valid().validate().is_ok());
    }

    #[test]
    fn toml_roundtrip() {
        let c = valid();
        assert_eq!(Config::from_toml(&c.to_toml()).unwrap(), c);
    }

    #[test]
    fn example_files_match_the_schema() {
        let c = Config::from_toml(include_str!("../../../examples/config.example.toml")).unwrap();
        c.validate().unwrap();
        assert_eq!(c, {
            let mut d = Config::default();
            d.smtp = c.smtp.clone();
            d
        }, "example documents the defaults");
        for p in [include_str!("../../../examples/package-site-a.toml"), include_str!("../../../examples/package-smtp-auth.toml")] {
            let mut t: toml::Table = toml::from_str(p).unwrap();
            t.remove("package");
            let merged: Config = toml::Value::Table(t).try_into().expect("package keys are valid settings");
            assert!(!merged.smtp.host.is_empty());
        }
    }

    #[test]
    fn unknown_keys_are_rejected() {
        assert!(Config::from_toml("[smtp]\nhots = \"x\"\n").is_err());
    }

    #[test]
    fn invalid_settings_are_reported() {
        let mut c = valid();
        c.smtp.from = "not an address".into();
        c.smtp.to.push("bad@".into());
        c.smtp.port = 0;
        c.report.time = "25:00".into();
        c.report.day = "funday".into();
        c.notifications.subject_format = "line1\r\nBcc: evil@example.com".into();
        c.updates.provider = UpdateProvider::Github;
        c.updates.repository_url = "http://github.com/a/b".into();
        c.failed_logons.threshold = 0;
        c.failed_logons.window_minutes = 0;
        c.smb.exclude_shares = vec![r"\\host\C$".into()];
        let errs = c.validate().unwrap_err();
        assert!(errs.len() >= 10, "{errs:?}");
    }

    #[test]
    fn updates_default_to_official_source() {
        let c = Config::default();
        assert_eq!(c.updates.provider, UpdateProvider::Github);
        assert_eq!(c.updates.repository_url, DEFAULT_UPDATE_REPOSITORY);
        assert!(c.updates.auto_install);
        assert!(crate::crypto::decode_public_key(c.updates.effective_signing_key()).is_ok());
        assert!(c.validate().is_ok());
        // Saved by an older version that had no update source set up.
        let old = Config::from_toml("[updates]
provider = \"none\"
repository_url = \"\"
signing_public_key = \"\"
").unwrap();
        assert_eq!(old.updates.provider, UpdateProvider::Github);
        // A deliberately configured source is kept.
        let own = Config::from_toml("[updates]
provider = \"gitlab\"
repository_url = \"https://gl.example.com/it/rdp\"
").unwrap();
        assert_eq!(own.updates.repository_url, "https://gl.example.com/it/rdp");
        let mut bad = Config::default();
        bad.updates.check_time = "3am".into();
        assert!(bad.validate().is_err());
    }

    #[test]
    fn failed_logons_follow_smb() {
        let mut c = Config::default();
        assert!(!c.failed_logons_active());
        c.smb.enabled = true;
        assert!(c.failed_logons_active());
        c.smb.notify_failed = false;
        assert!(!c.failed_logons_active());
    }

    #[test]
    fn smtp_requires_recipients() {
        let mut c = valid();
        c.smtp.to.clear();
        assert!(c.validate().is_err());
    }

    #[test]
    fn email_syntax() {
        assert!(is_valid_email("a.b@example.co.il"));
        assert!(is_valid_email("x@10.0.0.1"));
        assert!(!is_valid_email("a@b@c"));
        assert!(!is_valid_email("a b@c.com"));
        assert!(!is_valid_email("a@c.com\r\nBcc: x@y"));
        assert!(!is_valid_email("@c.com"));
    }

    #[test]
    fn helpers() {
        assert_eq!(parse_hhmm("08:05"), Some((8, 5)));
        assert_eq!(parse_hhmm("8:5"), None);
        assert_eq!(parse_weekday("Monday"), Some(chrono::Weekday::Mon));
        assert_eq!(
            repo_host_and_path("https://gitlab.example.com/it/tools/rdp-monitor.git"),
            Some(("gitlab.example.com".into(), "it/tools/rdp-monitor".into()))
        );
        assert_eq!(repo_host_and_path("https://github.com/only-owner"), None);
        assert_eq!(split_addresses("a@x.com; b@y.com,\nc@z.com"), vec!["a@x.com", "b@y.com", "c@z.com"]);
    }

    #[test]
    fn ranges_and_hours() {
        let net = parse_cidr("10.20.0.0/16").unwrap();
        assert!(cidr_contains(net, "10.20.3.4".parse().unwrap()));
        assert!(!cidr_contains(net, "10.21.0.1".parse().unwrap()));
        assert!(cidr_contains(parse_cidr("fd00::/8").unwrap(), "fd12::1".parse().unwrap()));
        assert!(cidr_contains(parse_cidr("0.0.0.0/0").unwrap(), "8.8.8.8".parse().unwrap()));
        assert!(!cidr_contains(net, "::1".parse().unwrap()));
        assert_eq!(parse_cidr("1.2.3.4"), Some(("1.2.3.4".parse().unwrap(), 32)));
        assert_eq!(parse_cidr("1.2.3.4/33"), None);
        assert_eq!(parse_cidr("vpn"), None);
        assert_eq!(parse_hours_range("08:00-19:00"), Some(((8, 0), (19, 0))));
        assert_eq!(parse_hours_range("19:00-08:00"), None);
        let mut c = Config::default();
        c.notifications.internal_networks = vec!["10.0.0.0/33".into()];
        c.notifications.business_hours = "8-19".into();
        c.notifications.business_days = vec!["sabbath".into()];
        assert_eq!(c.validate().unwrap_err().len(), 3);
    }

    #[test]
    fn redaction_removes_secrets() {
        let mut c = valid();
        c.smtp.password = "pw".into();
        c.updates.token = "tok".into();
        c.security.admin_password_hash = "h".into();
        let r = c.redacted();
        assert!(r.smtp.password.is_empty() && r.updates.token.is_empty() && r.security.admin_password_hash.is_empty());
    }
}
