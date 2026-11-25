//! Notification policy and alert / weekly-report message rendering.

use crate::correlate::Connection;
use crate::db::{ConnRow, Message, ShareRow};
use crate::events::Signal;
use chrono::{DateTime, Datelike, Duration, Local, LocalResult, NaiveDate, TimeZone, Utc};
use rdpmon_core::config::{Config, ReportConfig};
use std::collections::BTreeMap;

pub const ST_QUEUED: &str = "queued";
pub const ST_COOLDOWN: &str = "suppressed: cooldown";
pub const ST_DISABLED: &str = "suppressed: notification type disabled";
pub const ST_NO_SMTP: &str = "not sent: email not configured";
pub const ST_NA: &str = "history only";
pub const ST_BELOW: &str = "history only: below alert threshold";
pub const ST_EXCLUDED: &str = "history only: share excluded";

/// Decides whether a finalized connection triggers a notification. History
/// is always recorded regardless of the outcome.
pub fn decide(c: &Connection, cfg: &Config, last_notified: Option<DateTime<Utc>>) -> &'static str {
    let n = &cfg.notifications;
    let enabled = match c.kind {
        Signal::NewLogon => n.notify_new_logons,
        Signal::Reconnect => n.notify_reconnects,
        _ => return ST_NA,
    };
    if !enabled {
        return ST_DISABLED;
    }
    if !cfg.smtp.is_configured() {
        return ST_NO_SMTP;
    }
    if n.cooldown_minutes > 0 {
        if let Some(last) = last_notified {
            if (c.time - last).abs() < Duration::minutes(n.cooldown_minutes as i64) {
                return ST_COOLDOWN;
            }
        }
    }
    ST_QUEUED
}

/// Failed logons: one email per source IP per cooldown, and never more often
/// than once per counting window (also when the cooldown is 0).
pub fn failed_cooldown_minutes(cfg: &Config) -> u32 {
    cfg.notifications.cooldown_minutes.max(cfg.failed_logons.window_minutes)
}

/// Like `decide`, for a failed-logon burst that reached the threshold.
pub fn decide_failed(cfg: &Config, time: DateTime<Utc>, last_notified: Option<DateTime<Utc>>) -> &'static str {
    if !cfg.failed_logons_active() {
        return ST_DISABLED;
    }
    if !cfg.smtp.is_configured() {
        return ST_NO_SMTP;
    }
    if let Some(last) = last_notified {
        if (time - last).abs() < Duration::minutes(failed_cooldown_minutes(cfg) as i64) {
            return ST_COOLDOWN;
        }
    }
    ST_QUEUED
}

/// Share name without the `\\*\` prefix the events use.
pub fn share_name(share: &str) -> &str {
    share.rsplit('\\').find(|s| !s.is_empty()).unwrap_or(share)
}

/// True when a share event is never emailed (still recorded).
pub fn share_excluded(cfg: &Config, share: &str) -> bool {
    let name = share_name(share);
    cfg.smb.exclude_shares.iter().any(|x| x.trim().eq_ignore_ascii_case(name)) || (cfg.smb.admin_shares_only && !name.ends_with('$'))
}

/// Like `decide`, for share access / denied events.
pub fn decide_share(c: &Connection, cfg: &Config, last_notified: Option<DateTime<Utc>>) -> &'static str {
    let s = &cfg.smb;
    let enabled = s.enabled
        && match c.kind {
            Signal::ShareAccess => s.notify_success,
            Signal::ShareDenied => s.notify_failed,
            _ => false,
        };
    if !enabled {
        return ST_DISABLED;
    }
    if share_excluded(cfg, &c.share) {
        return ST_EXCLUDED;
    }
    if !cfg.smtp.is_configured() {
        return ST_NO_SMTP;
    }
    let n = &cfg.notifications;
    if let (true, Some(last)) = (n.cooldown_minutes > 0, last_notified) {
        if (c.time - last).abs() < Duration::minutes(n.cooldown_minutes as i64) {
            return ST_COOLDOWN;
        }
    }
    ST_QUEUED
}

pub fn local(t: DateTime<Utc>) -> String {
    t.with_timezone(&Local).format("%Y-%m-%d %H:%M:%S (UTC%:z)").to_string()
}

pub fn html_escape(s: &str) -> String {
    let mut o = String::with_capacity(s.len());
    for ch in s.chars() {
        match ch {
            '&' => o.push_str("&amp;"),
            '<' => o.push_str("&lt;"),
            '>' => o.push_str("&gt;"),
            '"' => o.push_str("&quot;"),
            '\'' => o.push_str("&#39;"),
            c => o.push(c),
        }
    }
    o
}

fn one_line(s: &str, max: usize) -> String {
    s.chars().map(|c| if c.is_control() { ' ' } else { c }).take(max).collect()
}

pub fn type_label(k: Signal) -> &'static str {
    match k {
        Signal::NewLogon => "New login",
        Signal::Reconnect => "Reconnection",
        Signal::Disconnect => "Disconnection",
        Signal::Auth => "Authentication",
        Signal::Failed => "Failed logon",
        Signal::ShareAccess => "Share access",
        Signal::ShareDenied => "Share access denied",
    }
}

const STYLE: &str = "body{font-family:Segoe UI,Arial,sans-serif;font-size:13px;color:#1f2328;margin:0;padding:16px}\
h2{font-size:17px;margin:0 0 12px}table{border-collapse:collapse}\
th,td{border:1px solid #d0d7de;padding:5px 9px;text-align:left;vertical-align:top}\
th{background:#f3f4f6;font-weight:600}.muted{color:#656d76;font-size:12px}";

/// `source_host` is the reverse-resolved name of the source IP, if any.
pub fn alert_message(c: &Connection, host: &str, source_host: Option<&str>, cfg: &Config, recovered: bool) -> Message {
    let user_full = if c.domain.is_empty() { c.user.clone() } else { format!("{}\\{}", c.domain, c.user) };
    let when = local(c.time);
    let kind = type_label(c.kind);
    let subject = one_line(
        &cfg.notifications
            .subject_format
            .replace("{user}", &c.user)
            .replace("{domain}", &c.domain)
            .replace("{ip}", &c.ip)
            .replace("{host}", host)
            .replace("{type}", kind)
            .replace("{time}", &when),
        200,
    );
    let session = c.session_id.map(|s| s.to_string()).unwrap_or_else(|| "not available".into());
    let ids = c.event_ids.iter().map(|i| i.to_string()).collect::<Vec<_>>().join(", ");
    let note = if recovered {
        "This connection was recovered from the Windows event log after the monitoring service was restarted."
    } else {
        ""
    };
    let cooldown = match cfg.notifications.cooldown_minutes {
        0 => "Every distinct connection is reported.".to_string(),
        m => format!("Further connections by this user from this IP are not reported for {m} minutes."),
    };
    let mut rows = vec![
        ("Computer", host.to_string()),
        ("User", user_full),
        ("Source IP", c.ip.clone()),
        ("Source hostname", source_host.unwrap_or("could not be resolved").to_string()),
        (
            "Client workstation (reported)",
            if c.client_name.is_empty() { "not reported".to_string() } else { one_line(&c.client_name, 64) },
        ),
    ];
    if !c.other_ips.is_empty() {
        rows.push(("Other addresses seen", c.other_ips.join(", ")));
    }
    rows.extend([
        ("Connection type", kind.to_string()),
        ("Date and time", when),
        ("Session ID", session),
        ("Windows event IDs", ids),
    ]);
    let mut text = String::from("Remote Desktop connection detected\r\n----------------------------------------\r\n");
    for (k, v) in &rows {
        text.push_str(&format!("{:<18} {}\r\n", format!("{k}:"), v));
    }
    text.push_str("----------------------------------------\r\n");
    if recovered {
        text.push_str(note);
        text.push_str("\r\n");
    }
    text.push_str(&cooldown);
    text.push_str("\r\n");

    let mut html = format!("<!DOCTYPE html><html><head><meta charset=\"utf-8\"><style>{STYLE}</style></head><body><h2>Remote Desktop connection detected</h2><table>");
    for (k, v) in &rows {
        html.push_str(&format!("<tr><th>{}</th><td>{}</td></tr>", k, html_escape(v)));
    }
    html.push_str("</table>");
    if recovered {
        html.push_str(&format!("<p>{}</p>", html_escape(note)));
    }
    html.push_str(&format!("<p class=\"muted\">{} Sent by RDP Monitor {}.</p></body></html>", html_escape(&cooldown), rdpmon_core::VERSION));
    Message { subject, text, html }
}

fn render(title: &str, rows: &[(&str, String)], notes: &[String], footer: &str) -> (String, String) {
    let mut text = format!("{title}\r\n----------------------------------------\r\n");
    for (k, v) in rows {
        text.push_str(&format!("{:<18} {}\r\n", format!("{k}:"), v));
    }
    text.push_str("----------------------------------------\r\n");
    let mut html = format!("<!DOCTYPE html><html><head><meta charset=\"utf-8\"><style>{STYLE}</style></head><body><h2>{}</h2><table>", html_escape(title));
    for (k, v) in rows {
        html.push_str(&format!("<tr><th>{}</th><td>{}</td></tr>", html_escape(k), html_escape(v)));
    }
    html.push_str("</table>");
    for n in notes {
        text.push_str(n);
        text.push_str("\r\n");
        html.push_str(&format!("<p>{}</p>", html_escape(n)));
    }
    text.push_str(footer);
    text.push_str("\r\n");
    html.push_str(&format!("<p class=\"muted\">{} Sent by RDP Monitor {}.</p></body></html>", html_escape(footer), rdpmon_core::VERSION));
    (text, html)
}

/// Counts distinct values, most frequent first: "a (3), b (1)" capped at `max`.
fn tally<'a>(values: impl Iterator<Item = &'a str>, max: usize, label: impl Fn(&str) -> String) -> String {
    let mut counts: BTreeMap<&str, u32> = BTreeMap::new();
    for v in values {
        *counts.entry(v).or_default() += 1;
    }
    let mut v: Vec<(&str, u32)> = counts.into_iter().collect();
    v.sort_by(|a, b| b.1.cmp(&a.1).then(a.0.cmp(b.0)));
    let more = v.len().saturating_sub(max);
    let mut s = v.iter().take(max).map(|(k, n)| format!("{} ({n})", label(k))).collect::<Vec<_>>().join(", ");
    if more > 0 {
        s.push_str(&format!(" and {more} more"));
    }
    s
}

/// Alert for a burst of failed logons from one source IP.
pub fn failed_message(b: &crate::failed::Burst, host: &str, source_host: Option<&str>, cfg: &Config, recovered: bool) -> Message {
    let n = b.attempts.len();
    let first = b.attempts.iter().map(|a| a.time).min().unwrap_or_default();
    let last = b.attempts.iter().map(|a| a.time).max().unwrap_or_default();
    let subject = one_line(&format!("FAILED LOGONS: {n} attempts from {} to {host}", b.ip), 200);
    let rows = vec![
        ("Computer", host.to_string()),
        ("Source IP", b.ip.clone()),
        ("Source hostname", source_host.unwrap_or("could not be resolved").to_string()),
        ("Connection type", type_label(Signal::Failed).to_string()),
        ("Failed attempts", format!("{n} within {} minutes", b.window_minutes)),
        ("Accounts tried", tally(b.attempts.iter().map(|a| a.user.as_str()), 10, |u| if u.is_empty() { "(none)".into() } else { u.to_string() })),
        ("Reasons", tally(b.attempts.iter().map(|a| a.status.as_str()), 10, crate::failed::reason)),
        ("Logon types", tally(b.attempts.iter().map(|a| a.logon_type.as_str()), 5, crate::failed::logon_type_label)),
        ("First attempt", local(first)),
        ("Last attempt", local(last)),
        ("Windows event IDs", "4625".into()),
    ];
    let mut notes = Vec::new();
    if recovered {
        notes.push("These attempts were recovered from the Windows event log after the monitoring service was restarted.".to_string());
    }
    let footer = format!(
        "Further failed logons from this IP are recorded in history but not emailed for {} minutes.",
        failed_cooldown_minutes(cfg)
    );
    let (text, html) = render("Repeated failed logons detected", &rows, &notes, &footer);
    Message { subject, text, html }
}

/// Alert for access (or denied access) to a shared folder.
pub fn share_message(c: &Connection, host: &str, source_host: Option<&str>, cfg: &Config, recovered: bool) -> Message {
    let user_full = if c.domain.is_empty() { c.user.clone() } else { format!("{}\\{}", c.domain, c.user) };
    let kind = type_label(c.kind);
    let subject = if c.kind == Signal::ShareDenied {
        format!("SHARE DENIED: {user_full} from {} to {} on {host}", c.ip, share_name(&c.share))
    } else {
        format!("SHARE ALERT: {user_full} from {} accessed {} on {host}", c.ip, share_name(&c.share))
    };
    let subject = one_line(&subject, 200);
    let mut rows = vec![
        ("Computer", host.to_string()),
        ("User", user_full),
        ("Source IP", c.ip.clone()),
        ("Source hostname", source_host.unwrap_or("could not be resolved").to_string()),
        ("Connection type", kind.to_string()),
        ("Share", c.share.clone()),
    ];
    if !c.path.is_empty() {
        rows.push(("Path", c.path.clone()));
    }
    rows.push(("Date and time", local(c.time)));
    rows.push(("Windows event IDs", c.event_ids.iter().map(|i| i.to_string()).collect::<Vec<_>>().join(", ")));
    let mut notes = Vec::new();
    if recovered {
        notes.push("This access was recovered from the Windows event log after the monitoring service was restarted.".to_string());
    }
    let footer = match cfg.notifications.cooldown_minutes {
        0 => "Every share access event is reported.".to_string(),
        m => format!("Further access to this share by this user from this IP is not reported for {m} minutes."),
    };
    let title = if c.kind == Signal::ShareDenied { "Shared folder access denied" } else { "Shared folder accessed" };
    let (text, html) = render(title, &rows, &notes, &footer);
    Message { subject, text, html }
}

// ---------------- weekly report ----------------

/// The most recent scheduled report time at or before `now`.
pub fn last_report_slot(r: &ReportConfig, now: DateTime<Local>) -> Option<DateTime<Local>> {
    let wd = rdpmon_core::config::parse_weekday(&r.day)?;
    let (h, m) = rdpmon_core::config::parse_hhmm(&r.time)?;
    let today = now.date_naive();
    let back = (7 + today.weekday().num_days_from_monday() as i64 - wd.num_days_from_monday() as i64) % 7;
    for extra in [0i64, 7] {
        let d: NaiveDate = today - Duration::days(back + extra);
        let slot = match Local.from_local_datetime(&d.and_hms_opt(h, m, 0)?) {
            LocalResult::Single(t) => t,
            LocalResult::Ambiguous(t, _) => t,
            LocalResult::None => Local.from_local_datetime(&d.and_hms_opt(h, m, 0)?.checked_add_signed(Duration::hours(1))?).earliest()?,
        };
        if slot <= now {
            return Some(slot);
        }
    }
    None
}

pub fn next_report_slot(r: &ReportConfig, now: DateTime<Local>) -> Option<DateTime<Local>> {
    let last = last_report_slot(r, now)?;
    last_report_slot(r, last + Duration::days(7) + Duration::hours(2)).filter(|t| *t > now)
}

/// Report content beyond the RDP connection rows.
#[derive(Debug, Default)]
pub struct ReportExtra {
    /// (failed logon attempts, distinct source IPs)
    pub failed: (u64, u64),
    pub shares: Vec<ShareRow>,
}

pub fn report_message(rows: &[ConnRow], extra: &ReportExtra, host: &str, start: DateTime<Utc>, end: DateTime<Utc>) -> Message {
    struct Agg {
        user: String,
        ip: String,
        logons: u32,
        reconnects: u32,
        first: DateTime<Utc>,
        last: DateTime<Utc>,
    }
    let mut groups: BTreeMap<(String, String), Agg> = BTreeMap::new();
    let (mut logons, mut reconnects) = (0u32, 0u32);
    let mut users = std::collections::BTreeSet::new();
    let mut ips = std::collections::BTreeSet::new();
    for r in rows {
        let full = if r.domain.is_empty() { r.user.clone() } else { format!("{}\\{}", r.domain, r.user) };
        users.insert(full.to_lowercase());
        ips.insert(r.ip.clone());
        let g = groups.entry((r.user.to_lowercase(), r.ip.clone())).or_insert(Agg {
            user: full,
            ip: r.ip.clone(),
            logons: 0,
            reconnects: 0,
            first: r.time,
            last: r.time,
        });
        if r.kind == "reconnect" {
            g.reconnects += 1;
            reconnects += 1;
        } else {
            g.logons += 1;
            logons += 1;
        }
        g.first = g.first.min(r.time);
        g.last = g.last.max(r.time);
    }
    let mut groups: Vec<Agg> = groups.into_values().collect();
    groups.sort_by(|a, b| (b.logons + b.reconnects).cmp(&(a.logons + a.reconnects)).then(a.user.cmp(&b.user)));

    let period = format!("{} - {}", local(start), local(end));
    let subject = one_line(&format!("Weekly RDP Connection Report - {host}"), 200);
    let total = rows.len();

    let mut text = format!(
        "Weekly RDP Connection Report - {host}\r\nPeriod: {period}\r\n\r\nTotal connections: {total}\r\nNew logins: {logons}\r\nReconnections: {reconnects}\r\nDistinct users: {}\r\nDistinct source IPs: {}\r\n\r\n",
        users.len(),
        ips.len()
    );
    let mut html = format!(
        "<!DOCTYPE html><html><head><meta charset=\"utf-8\"><style>{STYLE}</style></head><body>\
         <h2>Weekly RDP Connection Report - {}</h2><p>Period: {}</p>\
         <table><tr><th>Total connections</th><td>{total}</td></tr><tr><th>New logins</th><td>{logons}</td></tr>\
         <tr><th>Reconnections</th><td>{reconnects}</td></tr><tr><th>Distinct users</th><td>{}</td></tr>\
         <tr><th>Distinct source IPs</th><td>{}</td></tr></table>",
        html_escape(host),
        html_escape(&period),
        users.len(),
        ips.len()
    );
    if extra.failed.0 > 0 {
        let f = format!("Failed logons: {} from {} source IP(s)", extra.failed.0, extra.failed.1);
        text.push_str(&format!("{f}\r\n\r\n"));
        html.push_str(&format!("<p>{}</p>", html_escape(&f)));
    }
    if total == 0 {
        text.push_str("No RDP connections were recorded in this period.\r\n");
        html.push_str("<p>No RDP connections were recorded in this period.</p>");
    } else {
        html.push_str("<h2 style=\"margin-top:18px\">By user and source IP</h2><table><tr><th>User</th><th>Source IP</th><th>Logins</th><th>Reconnections</th><th>First seen</th><th>Last seen</th></tr>");
        text.push_str("By user and source IP:\r\n");
        for g in &groups {
            text.push_str(&format!(
                "  {} from {}: {} login(s), {} reconnection(s), first {}, last {}\r\n",
                g.user, g.ip, g.logons, g.reconnects, local(g.first), local(g.last)
            ));
            html.push_str(&format!(
                "<tr><td>{}</td><td>{}</td><td>{}</td><td>{}</td><td>{}</td><td>{}</td></tr>",
                html_escape(&g.user), html_escape(&g.ip), g.logons, g.reconnects, html_escape(&local(g.first)), html_escape(&local(g.last))
            ));
        }
        html.push_str("</table>");
        const MAX_ROWS: usize = 500;
        html.push_str("<h2 style=\"margin-top:18px\">All connections</h2><table><tr><th>Time</th><th>Type</th><th>User</th><th>Source IP</th></tr>");
        text.push_str("\r\nAll connections:\r\n");
        for r in rows.iter().rev().take(MAX_ROWS) {
            let kind = if r.kind == "reconnect" { "Reconnection" } else { "New login" };
            let user = if r.domain.is_empty() { r.user.clone() } else { format!("{}\\{}", r.domain, r.user) };
            text.push_str(&format!("  {}  {:<12}  {}  {}\r\n", local(r.time), kind, user, r.ip));
            html.push_str(&format!(
                "<tr><td>{}</td><td>{kind}</td><td>{}</td><td>{}</td></tr>",
                html_escape(&local(r.time)), html_escape(&user), html_escape(&r.ip)
            ));
        }
        html.push_str("</table>");
        if rows.len() > MAX_ROWS {
            let more = format!("{} older connections are not listed individually.", rows.len() - MAX_ROWS);
            text.push_str(&format!("  ... {more}\r\n"));
            html.push_str(&format!("<p class=\"muted\">{more}</p>"));
        }
    }
    if !extra.shares.is_empty() {
        html.push_str("<h2 style=\"margin-top:18px\">File share access</h2><table><tr><th>Type</th><th>User</th><th>Source IP</th><th>Share</th><th>Count</th></tr>");
        text.push_str("\r\nFile share access:\r\n");
        for s in &extra.shares {
            let kind = if s.kind == "share_denied" { "Denied" } else { "Access" };
            let user = if s.domain.is_empty() { s.user.clone() } else { format!("{}\\{}", s.domain, s.user) };
            text.push_str(&format!("  {kind:<7} {user} from {} to {}: {}\r\n", s.ip, s.share, s.count));
            html.push_str(&format!(
                "<tr><td>{kind}</td><td>{}</td><td>{}</td><td>{}</td><td>{}</td></tr>",
                html_escape(&user), html_escape(&s.ip), html_escape(&s.share), s.count
            ));
        }
        html.push_str("</table>");
    }
    html.push_str(&format!("<p class=\"muted\">Generated by RDP Monitor {}.</p></body></html>", rdpmon_core::VERSION));
    Message { subject, text, html }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::correlate::EventRef;

    fn cfg() -> Config {
        let mut c = Config::default();
        c.smtp.host = "mail.example.com".into();
        c.smtp.from = "a@example.com".into();
        c.smtp.to = vec!["b@example.com".into()];
        c
    }

    fn conn(kind: Signal, t: DateTime<Utc>) -> Connection {
        Connection {
            kind,
            time: t,
            user: "jdoe".into(),
            domain: "CORP".into(),
            ip: "203.0.113.10".into(),
            session_id: None,
            event_ids: vec![4624],
            refs: vec![EventRef { channel: "Security".into(), record_id: 1, time: t }],
            ..Default::default()
        }
    }

    #[test]
    fn cooldown_policy() {
        let c = cfg();
        let t = Utc::now();
        assert_eq!(decide(&conn(Signal::NewLogon, t), &c, None), ST_QUEUED);
        assert_eq!(decide(&conn(Signal::NewLogon, t), &c, Some(t - Duration::minutes(5))), ST_COOLDOWN);
        assert_eq!(decide(&conn(Signal::NewLogon, t), &c, Some(t - Duration::minutes(16))), ST_QUEUED);
        let mut every = c.clone();
        every.notifications.cooldown_minutes = 0;
        assert_eq!(decide(&conn(Signal::NewLogon, t), &every, Some(t)), ST_QUEUED);
    }

    #[test]
    fn notification_types_and_smtp() {
        let mut c = cfg();
        c.notifications.notify_reconnects = false;
        let t = Utc::now();
        assert_eq!(decide(&conn(Signal::Reconnect, t), &c, None), ST_DISABLED);
        assert_eq!(decide(&conn(Signal::Disconnect, t), &c, None), ST_NA);
        assert_eq!(decide(&conn(Signal::NewLogon, t), &Config::default(), None), ST_NO_SMTP);
    }

    #[test]
    fn alert_rendering_escapes_and_sanitizes() {
        let mut c = cfg();
        c.notifications.subject_format = "{type}: {user} from {ip} on {host}".into();
        let mut x = conn(Signal::Reconnect, Utc::now());
        x.user = "<script>\r\nBcc: evil".into();
        let m = alert_message(&x, "PC01", Some("ITMOSHE.corp.example"), &c, true);
        assert!(!m.subject.contains('\n') && !m.subject.contains('\r'));
        assert!(m.subject.starts_with("Reconnection: "));
        assert!(m.html.contains("&lt;script&gt;") && !m.html.contains("<script>"));
        assert!(m.text.contains("Source IP:") && m.text.contains("recovered"));
        assert!(m.text.contains("Source hostname:   ITMOSHE.corp.example"));
        let unresolved = alert_message(&x, "PC01", None, &c, false);
        assert!(unresolved.html.contains("<th>Source hostname</th><td>could not be resolved</td>"));
        assert!(!unresolved.text.contains("Other addresses seen"));
        assert!(unresolved.text.contains("Client workstation (reported): not reported"));
        x.client_name = "<b>x</b>".into();
        let named = alert_message(&x, "PC01", None, &c, false);
        assert!(named.html.contains("<th>Client workstation (reported)</th><td>&lt;b&gt;x&lt;/b&gt;</td>"));
        assert!(named.text.contains("Client workstation (reported): <b>x</b>"));
        let order = |m: &str| ["Source IP", "Source hostname", "Client workstation (reported)"].map(|k| m.find(k).unwrap());
        let o = order(&named.text);
        assert!(o[0] < o[1] && o[1] < o[2], "row order");
        x.other_ips = vec!["10.0.0.1".into()];
        assert!(alert_message(&x, "PC01", None, &c, false).html.contains("<th>Other addresses seen</th><td>10.0.0.1</td>"));
    }

    #[test]
    fn failed_logon_policy_and_rendering() {
        use crate::failed::{Attempt, Burst};
        let mut c = cfg();
        let t = Utc::now();
        assert_eq!(decide_failed(&c, t, None), ST_DISABLED, "opt-in");
        c.failed_logons.enabled = true;
        assert_eq!(decide_failed(&c, t, None), ST_QUEUED);
        assert_eq!(decide_failed(&c, t, Some(t - Duration::minutes(10))), ST_COOLDOWN);
        c.notifications.cooldown_minutes = 0;
        assert_eq!(decide_failed(&c, t, Some(t - Duration::minutes(2))), ST_COOLDOWN, "never more than once per window");
        let at = |u: &str, s: &str| Attempt { time: t, user: u.into(), logon_type: "3".into(), status: s.into() };
        let b = Burst {
            ip: "198.51.100.7".into(),
            window_minutes: 5,
            attempts: vec![at(r"CORP\<script>", "0xc000006a"), at(r"CORP\<script>", "0xc000006a"), at("root", "0xc0000064"), at("", "0xc0000064"), at("admin", "0xc000006a")],
        };
        let m = failed_message(&b, "PC01", Some("kali.example"), &c, false);
        assert!(m.subject.contains("5 attempts from 198.51.100.7"));
        assert!(m.text.contains("5 within 5 minutes"));
        assert!(m.text.contains("wrong password (3)") && m.text.contains("unknown user name (2)"));
        assert!(m.text.contains(r"CORP\<script> (2)") && m.text.contains("(none) (1)"));
        assert!(m.html.contains("&lt;script&gt;") && !m.html.contains("<script>"));
        assert!(m.text.contains("kali.example"));
    }

    #[test]
    fn share_policy_filters_and_rendering() {
        let mut c = cfg();
        let t = Utc::now();
        let mut x = conn(Signal::ShareAccess, t);
        x.share = r"\\*\C$".into();
        x.event_ids = vec![5140];
        assert_eq!(decide_share(&x, &c, None), ST_DISABLED, "opt-in");
        c.smb.enabled = true;
        assert_eq!(decide_share(&x, &c, None), ST_QUEUED);
        assert_eq!(decide_share(&x, &c, Some(t - Duration::minutes(5))), ST_COOLDOWN);
        c.smb.exclude_shares = vec!["c$".into()];
        assert_eq!(decide_share(&x, &c, None), ST_EXCLUDED, "exclude list is case-insensitive");
        c.smb.exclude_shares.clear();
        c.smb.admin_shares_only = true;
        let mut regular = x.clone();
        regular.share = r"\\*\Finance".into();
        assert_eq!(decide_share(&regular, &c, None), ST_EXCLUDED);
        assert_eq!(decide_share(&x, &c, None), ST_QUEUED);
        c.smb.notify_success = false;
        assert_eq!(decide_share(&x, &c, None), ST_DISABLED);
        let mut d = regular.clone();
        d.kind = Signal::ShareDenied;
        d.path = "<b>salaries</b>.xlsx".into();
        d.event_ids = vec![5145];
        c.smb.admin_shares_only = false;
        assert_eq!(decide_share(&d, &c, None), ST_QUEUED);
        let m = share_message(&d, "PC01", Some("itmoshe.corp.local"), &c, false);
        assert!(m.subject.starts_with("SHARE DENIED: ") && m.subject.contains(" to Finance on PC01"), "{}", m.subject);
        assert!(m.html.contains(r"<th>Share</th><td>\\*\Finance</td>"));
        assert!(m.html.contains("<th>Path</th><td>&lt;b&gt;salaries&lt;/b&gt;.xlsx</td>"));
        assert!(m.text.contains("Share access denied") && m.text.contains("itmoshe.corp.local"));
        assert!(!share_message(&x, "PC01", None, &c, false).text.contains("Path:"));
        assert_eq!(share_name(r"\\*\ADMIN$"), "ADMIN$");
    }

    #[test]
    fn report_aggregates() {
        let t = Utc::now();
        let row = |u: &str, ip: &str, k: &str, mins: i64| ConnRow { time: t - Duration::minutes(mins), kind: k.into(), user: u.into(), domain: "CORP".into(), ip: ip.into() };
        let rows = vec![row("jdoe", "1.1.1.1", "logon", 50), row("jdoe", "1.1.1.1", "reconnect", 40), row("asmith", "2.2.2.2", "logon", 30)];
        let m = report_message(&rows, &ReportExtra::default(), "PC01", t - Duration::days(7), t);
        assert!(m.text.contains("Total connections: 3"));
        assert!(m.text.contains("New logins: 2") && m.text.contains("Reconnections: 1"));
        assert!(m.text.contains("Distinct users: 2"));
        assert!(m.html.contains("CORP\\jdoe"));
        let empty = report_message(&[], &ReportExtra::default(), "PC01", t - Duration::days(7), t);
        assert!(empty.text.contains("No RDP connections"));
        assert!(!empty.text.contains("Failed logons"));
        let failed = report_message(&[], &ReportExtra { failed: (12, 2), ..Default::default() }, "PC01", t - Duration::days(7), t);
        assert!(failed.text.contains("Failed logons: 12 from 2 source IP(s)"));
        assert!(!failed.text.contains("File share access"));
        let share = ShareRow { kind: "share".into(), user: "<b>x</b>".into(), domain: "CORP".into(), ip: "10.0.0.5".into(), share: r"\\*\C$".into(), count: 3 };
        let shares = report_message(&[], &ReportExtra { shares: vec![share], ..Default::default() }, "PC01", t - Duration::days(7), t);
        assert!(shares.text.contains(r"Access  CORP\<b>x</b> from 10.0.0.5 to \\*\C$: 3"));
        assert!(shares.html.contains("&lt;b&gt;x&lt;/b&gt;"));
    }

    #[test]
    fn report_schedule() {
        let r = ReportConfig { day: "monday".into(), time: "08:00".into(), ..Default::default() };
        // Wednesday 2026-11-25 10:00 local -> last slot Monday 2026-11-23 08:00
        let now = Local.with_ymd_and_hms(2026, 11, 25, 10, 0, 0).unwrap();
        let last = last_report_slot(&r, now).unwrap();
        assert_eq!(last.format("%Y-%m-%d %H:%M").to_string(), "2026-11-23 08:00");
        let next = next_report_slot(&r, now).unwrap();
        assert_eq!(next.format("%Y-%m-%d %H:%M").to_string(), "2026-11-30 08:00");
        // Monday 07:00 -> previous Monday
        let mon_early = Local.with_ymd_and_hms(2026, 11, 23, 7, 0, 0).unwrap();
        assert_eq!(last_report_slot(&r, mon_early).unwrap().format("%Y-%m-%d").to_string(), "2026-11-16");
        assert_eq!(next_report_slot(&r, mon_early).unwrap().format("%Y-%m-%d %H:%M").to_string(), "2026-11-23 08:00");
    }
}
