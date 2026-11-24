//! Notification policy and alert / weekly-report message rendering.

use crate::correlate::Connection;
use crate::db::{ConnRow, Message};
use crate::events::Signal;
use chrono::{DateTime, Datelike, Duration, Local, LocalResult, NaiveDate, TimeZone, Utc};
use rdpmon_core::config::{Config, ReportConfig};
use std::collections::BTreeMap;

pub const ST_QUEUED: &str = "queued";
pub const ST_COOLDOWN: &str = "suppressed: cooldown";
pub const ST_DISABLED: &str = "suppressed: notification type disabled";
pub const ST_NO_SMTP: &str = "not sent: email not configured";
pub const ST_NA: &str = "history only";

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
    }
}

const STYLE: &str = "body{font-family:Segoe UI,Arial,sans-serif;font-size:13px;color:#1f2328;margin:0;padding:16px}\
h2{font-size:17px;margin:0 0 12px}table{border-collapse:collapse}\
th,td{border:1px solid #d0d7de;padding:5px 9px;text-align:left;vertical-align:top}\
th{background:#f3f4f6;font-weight:600}.muted{color:#656d76;font-size:12px}";

pub fn alert_message(c: &Connection, host: &str, cfg: &Config, recovered: bool) -> Message {
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
    let rows = [
        ("Computer", host.to_string()),
        ("User", user_full),
        ("Source IP", c.ip.clone()),
        ("Connection type", kind.to_string()),
        ("Date and time", when),
        ("Session ID", session),
        ("Windows event IDs", ids),
    ];
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

pub fn report_message(rows: &[ConnRow], host: &str, start: DateTime<Utc>, end: DateTime<Utc>) -> Message {
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
        let m = alert_message(&x, "PC01", &c, true);
        assert!(!m.subject.contains('\n') && !m.subject.contains('\r'));
        assert!(m.subject.starts_with("Reconnection: "));
        assert!(m.html.contains("&lt;script&gt;") && !m.html.contains("<script>"));
        assert!(m.text.contains("Source IP:") && m.text.contains("recovered"));
    }

    #[test]
    fn report_aggregates() {
        let t = Utc::now();
        let row = |u: &str, ip: &str, k: &str, mins: i64| ConnRow { time: t - Duration::minutes(mins), kind: k.into(), user: u.into(), domain: "CORP".into(), ip: ip.into() };
        let rows = vec![row("jdoe", "1.1.1.1", "logon", 50), row("jdoe", "1.1.1.1", "reconnect", 40), row("asmith", "2.2.2.2", "logon", 30)];
        let m = report_message(&rows, "PC01", t - Duration::days(7), t);
        assert!(m.text.contains("Total connections: 3"));
        assert!(m.text.contains("New logins: 2") && m.text.contains("Reconnections: 1"));
        assert!(m.text.contains("Distinct users: 2"));
        assert!(m.html.contains("CORP\\jdoe"));
        let empty = report_message(&[], "PC01", t - Duration::days(7), t);
        assert!(empty.text.contains("No RDP connections"));
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
