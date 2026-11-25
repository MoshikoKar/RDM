//! Parsing of rendered Windows event XML into normalized observations.

use chrono::{DateTime, Utc};

pub const CH_SECURITY: &str = "Security";
pub const CH_LSM: &str = "Microsoft-Windows-TerminalServices-LocalSessionManager/Operational";
pub const CH_RCM: &str = "Microsoft-Windows-TerminalServices-RemoteConnectionManager/Operational";

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum Signal {
    /// 1149: network-level authentication succeeded. Not proof of a session.
    Auth,
    /// 4624 LogonType 10, LSM 21.
    #[default]
    NewLogon,
    /// 4778, LSM 25.
    Reconnect,
    /// 4779, LSM 24 (history only).
    Disconnect,
    /// 4625 LogonType 3 or 10: failed logon. Never correlated into a session.
    Failed,
    /// 5140 (success): a shared folder was opened.
    ShareAccess,
    /// 5145 / 5140 with the Audit Failure keyword: share access denied.
    ShareDenied,
}

impl Signal {
    /// Events handled outside the RDP session correlation.
    pub fn is_standalone(self) -> bool {
        matches!(self, Signal::Failed | Signal::ShareAccess | Signal::ShareDenied)
    }
}

/// Audit Failure bit of the event Keywords.
const KEYWORD_AUDIT_FAILURE: u64 = 0x0010_0000_0000_0000;

#[derive(Debug, Clone, PartialEq)]
pub struct Observation {
    pub channel: String,
    pub record_id: u64,
    pub event_id: u32,
    pub time: DateTime<Utc>,
    pub signal: Signal,
    pub user: String,
    pub domain: String,
    pub ip: String,
    pub session_id: Option<u32>,
    /// Windows logon ID (4624 TargetLogonId, 4778/4779 LogonID), lower case.
    pub logon_id: Option<String>,
    /// 4625 only: LogonType.
    pub logon_type: String,
    /// 4625 only: SubStatus, or Status when SubStatus is 0x0 (lower case).
    pub status: String,
    /// 5140 / 5145: share as logged (e.g. `\\*\C$`).
    pub share: String,
    /// 5145: file or folder inside the share.
    pub path: String,
    /// Name the client reports for itself (4624 WorkstationName, 4778/4779
    /// ClientName). Chosen by the client: display only, never for filtering.
    pub client_name: String,
}

/// Canonical form of an account domain so the forms used by different events
/// compare equal: upper case, first label of an FQDN (`corp.local` -> `CORP`),
/// and `.` (local machine) mapped to the local computer name. Empty stays
/// empty (the event did not report a domain).
pub fn normalize_domain(domain: &str, host: &str) -> String {
    let d = domain.trim();
    if d.is_empty() {
        return String::new();
    }
    let d = if d == "." { host } else { d };
    d.split('.').next().unwrap_or("").to_ascii_uppercase()
}

/// Two normalized domains may belong to the same account unless both are
/// known and differ.
pub fn domains_compatible(a: &str, b: &str) -> bool {
    a.is_empty() || b.is_empty() || a == b
}

/// Why an event was not turned into an observation.
#[derive(Debug, PartialEq, Eq)]
pub enum Skip {
    Irrelevant,
    Malformed(String),
}

/// Parses a rendered event. `ignore_loopback` drops 127.0.0.1 / ::1.
pub fn parse(xml: &str, ignore_loopback: bool) -> Result<Observation, Skip> {
    let doc = roxmltree::Document::parse(xml).map_err(|e| Skip::Malformed(e.to_string()))?;
    let root = doc.root_element();
    let system = child(root, "System").ok_or_else(|| Skip::Malformed("no System element".into()))?;
    let event_id: u32 = text(child(system, "EventID")).parse().map_err(|_| Skip::Malformed("bad EventID".into()))?;
    let record_id: u64 = text(child(system, "EventRecordID")).parse().map_err(|_| Skip::Malformed("bad EventRecordID".into()))?;
    let channel = text(child(system, "Channel")).to_string();
    let time = child(system, "TimeCreated")
        .and_then(|n| n.attribute("SystemTime"))
        .and_then(|t| DateTime::parse_from_rfc3339(t).ok())
        .map(|t| t.with_timezone(&Utc))
        .ok_or_else(|| Skip::Malformed("bad TimeCreated".into()))?;

    let data = |name: &str| -> String {
        child(root, "EventData")
            .into_iter()
            .flat_map(|ed| ed.children())
            .find(|n| n.is_element() && n.attribute("Name") == Some(name))
            .map(|n| n.text().unwrap_or("").trim().to_string())
            .unwrap_or_default()
    };
    let user_data = |name: &str| -> String {
        child(root, "UserData")
            .and_then(|ud| ud.children().find(|n| n.is_element()))
            .and_then(|ex| child(ex, name))
            .map(|n| n.text().unwrap_or("").trim().to_string())
            .unwrap_or_default()
    };

    let mut logon_id = None;
    let (mut logon_type, mut status) = (String::new(), String::new());
    let (mut share, mut path) = (String::new(), String::new());
    let mut client_name = String::new();
    let (signal, user, domain, ip, session_id) = match (channel.as_str(), event_id) {
        (CH_SECURITY, 5140 | 5145) => {
            let kw = text(child(system, "Keywords"));
            let kw = u64::from_str_radix(kw.trim_start_matches("0x").trim_start_matches("0X"), 16).unwrap_or(0);
            let failure = kw & KEYWORD_AUDIT_FAILURE != 0;
            if event_id == 5145 && !failure {
                return Err(Skip::Irrelevant); // per-file success auditing: far too noisy
            }
            share = one_line(&data("ShareName"), 260);
            if event_id == 5145 {
                path = one_line(&data("RelativeTargetName"), 260);
            }
            let sig = if failure { Signal::ShareDenied } else { Signal::ShareAccess };
            (sig, data("SubjectUserName"), data("SubjectDomainName"), data("IpAddress"), None)
        }
        (CH_SECURITY, 4625) => {
            logon_type = data("LogonType");
            if logon_type != "3" && logon_type != "10" {
                return Err(Skip::Irrelevant);
            }
            let sub_status = data("SubStatus").to_ascii_lowercase();
            status = if sub_status.is_empty() || sub_status == "0x0" { data("Status").to_ascii_lowercase() } else { sub_status };
            (Signal::Failed, data("TargetUserName"), data("TargetDomainName"), data("IpAddress"), None)
        }
        (CH_SECURITY, 4624) => {
            if data("LogonType") != "10" {
                return Err(Skip::Irrelevant);
            }
            logon_id = normalize_logon_id(&data("TargetLogonId"));
            client_name = normalize_client_name(&data("WorkstationName"));
            (Signal::NewLogon, data("TargetUserName"), data("TargetDomainName"), data("IpAddress"), None)
        }
        (CH_SECURITY, 4778 | 4779) => {
            logon_id = normalize_logon_id(&data("LogonID"));
            client_name = normalize_client_name(&data("ClientName"));
            let sig = if event_id == 4778 { Signal::Reconnect } else { Signal::Disconnect };
            (sig, data("AccountName"), data("AccountDomain"), data("ClientAddress"), None)
        }
        (CH_RCM, 1149) => (Signal::Auth, user_data("Param1"), user_data("Param2"), user_data("Param3"), None),
        (CH_LSM, 21 | 24 | 25) => {
            let sig = match event_id {
                21 => Signal::NewLogon,
                24 => Signal::Disconnect,
                _ => Signal::Reconnect,
            };
            let (domain, user) = split_domain_user(&user_data("User"));
            (sig, user, domain, user_data("Address"), user_data("SessionID").parse().ok())
        }
        _ => return Err(Skip::Irrelevant),
    };

    let ip = normalize_ip(&ip);
    // A failed logon may name no (or a nonsense) account; only built-in
    // identities are excluded.
    let relevant = if signal == Signal::Failed { !is_builtin_domain(&domain) } else { is_relevant_user(&user, &domain) };
    if !relevant || ip.is_empty() || (ignore_loopback && is_loopback(&ip)) {
        return Err(Skip::Irrelevant);
    }
    let (user, domain) = (one_line(&user, 256), one_line(&domain, 256));
    Ok(Observation { channel, record_id, event_id, time, signal, user, domain, ip, session_id, logon_id, logon_type, status, share, path, client_name })
}

fn one_line(s: &str, max: usize) -> String {
    s.chars().filter(|c| !c.is_control()).take(max).collect()
}

/// "-" and empty mean not reported; single line, at most 64 characters.
fn normalize_client_name(s: &str) -> String {
    let s = one_line(s.trim(), 64);
    let s = s.trim();
    if s == "-" { String::new() } else { s.to_string() }
}

fn normalize_logon_id(s: &str) -> Option<String> {
    let s = s.trim().to_ascii_lowercase();
    (!s.is_empty() && s != "-" && s != "0x0").then_some(s)
}

/// Excludes built-in service identities (identified by their domain, which a
/// user cannot choose). Deliberately no user-name patterns: an attacker could
/// otherwise hide an RDP session behind an account named `x$` or `DWM-9`.
/// Machine-account activity never produces the RDP-specific events selected
/// (LogonType 10, session reconnects, remote session-manager logons).
pub fn is_relevant_user(user: &str, domain: &str) -> bool {
    let u = user.trim();
    !(u.is_empty() || u == "-" || is_builtin_domain(domain))
}

fn is_builtin_domain(domain: &str) -> bool {
    matches!(domain.trim().to_ascii_lowercase().as_str(), "nt authority" | "window manager" | "font driver host")
}

/// Returns "" for values that are not a remote address at all ("-",
/// console "LOCAL"). Unparseable values are kept (sanitized) rather than
/// silently dropping the connection.
pub fn normalize_ip(ip: &str) -> String {
    let ip = ip.trim();
    let ip = ip.strip_prefix("::ffff:").unwrap_or(ip);
    if ip.is_empty() || ip == "-" || ip.eq_ignore_ascii_case("LOCAL") {
        return String::new();
    }
    ip.chars().filter(|c| !c.is_control()).take(64).collect::<String>().to_ascii_lowercase()
}

fn child<'a, 'i>(n: roxmltree::Node<'a, 'i>, name: &str) -> Option<roxmltree::Node<'a, 'i>> {
    n.children().find(|c| c.is_element() && c.tag_name().name() == name)
}

fn text<'a>(n: Option<roxmltree::Node<'a, '_>>) -> &'a str {
    n.and_then(|n| n.text()).unwrap_or("").trim()
}

fn split_domain_user(s: &str) -> (String, String) {
    match s.split_once('\\') {
        Some((d, u)) => (d.to_string(), u.to_string()),
        None => (String::new(), s.to_string()),
    }
}


pub fn is_loopback(ip: &str) -> bool {
    ip.parse::<std::net::IpAddr>().map(|a| a.is_loopback()).unwrap_or(false)
}

#[cfg(test)]
pub mod samples {
    pub fn security(id: u32, rec: u64, time: &str, data: &[(&str, &str)]) -> String {
        let d: String = data.iter().map(|(k, v)| format!("<Data Name='{k}'>{v}</Data>")).collect();
        format!(
            "<Event xmlns='http://schemas.microsoft.com/win/2004/08/events/event'><System>\
             <Provider Name='Microsoft-Windows-Security-Auditing'/><EventID>{id}</EventID>\
             <TimeCreated SystemTime='{time}'/><EventRecordID>{rec}</EventRecordID>\
             <Channel>Security</Channel><Computer>PC01.corp.local</Computer></System>\
             <EventData>{d}</EventData></Event>"
        )
    }

    pub fn logon4624(rec: u64, time: &str, user: &str, ip: &str, logon_type: &str) -> String {
        security(4624, rec, time, &[
            ("SubjectUserSid", "S-1-5-18"), ("TargetUserName", user), ("TargetDomainName", "CORP"),
            ("TargetLogonId", "0x3e7a1"), ("LogonType", logon_type), ("WorkstationName", "LAPTOP7"),
            ("IpAddress", ip), ("IpPort", "0"),
        ])
    }

    pub fn failed4625(rec: u64, time: &str, user: &str, ip: &str, logon_type: &str, sub_status: &str) -> String {
        security(4625, rec, time, &[
            ("SubjectUserSid", "S-1-0-0"), ("TargetUserName", user), ("TargetDomainName", "CORP"),
            ("Status", "0xc000006d"), ("FailureReason", "%%2313"), ("SubStatus", sub_status),
            ("LogonType", logon_type), ("WorkstationName", "KALI"), ("IpAddress", ip), ("IpPort", "0"),
        ])
    }

    /// 5140 / 5145 with the success or failure audit keyword.
    pub fn share_event(id: u32, rec: u64, time: &str, user: &str, ip: &str, share: &str, path: &str, failure: bool) -> String {
        let kw = if failure { "0x8010000000000000" } else { "0x8020000000000000" };
        format!(
            "<Event xmlns='http://schemas.microsoft.com/win/2004/08/events/event'><System>\
             <Provider Name='Microsoft-Windows-Security-Auditing'/><EventID>{id}</EventID><Keywords>{kw}</Keywords>\
             <TimeCreated SystemTime='{time}'/><EventRecordID>{rec}</EventRecordID>\
             <Channel>Security</Channel><Computer>PC01.corp.local</Computer></System><EventData>\
             <Data Name='SubjectUserSid'>S-1-5-21-1</Data><Data Name='SubjectUserName'>{user}</Data>\
             <Data Name='SubjectDomainName'>CORP</Data><Data Name='SubjectLogonId'>0x5a1b2</Data>\
             <Data Name='ObjectType'>File</Data><Data Name='IpAddress'>{ip}</Data><Data Name='IpPort'>50112</Data>\
             <Data Name='ShareName'>{share}</Data><Data Name='ShareLocalPath'>\\??\\C:\\</Data>\
             <Data Name='RelativeTargetName'>{path}</Data><Data Name='AccessMask'>0x1</Data></EventData></Event>"
        )
    }

    pub fn session4778(id: u32, rec: u64, time: &str, user: &str, ip: &str) -> String {
        security(id, rec, time, &[
            ("AccountName", user), ("AccountDomain", "CORP"), ("LogonID", "0x3e7a1"),
            ("SessionName", "RDP-Tcp#3"), ("ClientName", "LAPTOP7"), ("ClientAddress", ip),
        ])
    }

    pub fn user_data(channel: &str, id: u32, rec: u64, time: &str, inner: &str) -> String {
        format!(
            "<Event xmlns='http://schemas.microsoft.com/win/2004/08/events/event'><System>\
             <EventID>{id}</EventID><TimeCreated SystemTime='{time}'/><EventRecordID>{rec}</EventRecordID>\
             <Channel>{channel}</Channel></System><UserData><EventXML xmlns='Event_NS'>{inner}</EventXML></UserData></Event>"
        )
    }

    pub fn lsm(id: u32, rec: u64, time: &str, user: &str, ip: &str, session: u32) -> String {
        user_data(super::CH_LSM, id, rec, time, &format!("<User>{user}</User><SessionID>{session}</SessionID><Address>{ip}</Address>"))
    }

    pub fn rcm1149(rec: u64, time: &str, user: &str, ip: &str) -> String {
        user_data(super::CH_RCM, 1149, rec, time, &format!("<Param1>{user}</Param1><Param2>CORP</Param2><Param3>{ip}</Param3>"))
    }
}

#[cfg(test)]
mod tests {
    use super::samples::*;
    use super::*;

    const T: &str = "2026-11-24T09:37:12.1234567Z";

    #[test]
    fn parses_4624_type_10() {
        let o = parse(&logon4624(100, T, "jdoe", "203.0.113.10", "10"), true).unwrap();
        assert_eq!((o.signal, o.user.as_str(), o.domain.as_str(), o.ip.as_str(), o.record_id), (Signal::NewLogon, "jdoe", "CORP", "203.0.113.10", 100));
        assert_eq!(o.time.to_rfc3339(), "2026-11-24T09:37:12.123456700+00:00");
    }

    #[test]
    fn ignores_non_rdp_and_system_logons() {
        assert_eq!(parse(&logon4624(1, T, "jdoe", "203.0.113.10", "3"), true), Err(Skip::Irrelevant));
        // Account names cannot be used to hide an RDP session.
        assert!(parse(&logon4624(1, T, "svc$", "203.0.113.10", "10"), true).is_ok());
        assert!(parse(&logon4624(1, T, "DWM-3", "203.0.113.10", "10"), true).is_ok());
        let dwm = security(4624, 1, T, &[("TargetUserName", "DWM-3"), ("TargetDomainName", "Window Manager"), ("LogonType", "10"), ("IpAddress", "203.0.113.10")]);
        assert_eq!(parse(&dwm, true), Err(Skip::Irrelevant));
        assert_eq!(parse(&logon4624(1, T, "jdoe", "weird-addr", "10"), true).unwrap().ip, "weird-addr");
        assert_eq!(parse(&logon4624(1, T, "jdoe", "-", "10"), true), Err(Skip::Irrelevant));
        assert_eq!(parse(&logon4624(1, T, "jdoe", "127.0.0.1", "10"), true), Err(Skip::Irrelevant));
        assert!(parse(&logon4624(1, T, "jdoe", "127.0.0.1", "10"), false).is_ok());
        assert_eq!(parse(&lsm(21, 5, T, r"CORP\jdoe", "LOCAL", 1), true), Err(Skip::Irrelevant));
        assert!(matches!(parse("<not-xml", true), Err(Skip::Malformed(_))));
    }

    #[test]
    fn parses_4625_network_and_rdp() {
        let f = parse(&failed4625(5, T, "administrator", "198.51.100.7", "3", "0xC000006A"), true).unwrap();
        assert_eq!((f.signal, f.user.as_str(), f.ip.as_str()), (Signal::Failed, "administrator", "198.51.100.7"));
        assert_eq!((f.logon_type.as_str(), f.status.as_str()), ("3", "0xc000006a"));
        let r = parse(&failed4625(6, T, "jdoe", "198.51.100.7", "10", "0x0"), true).unwrap();
        assert_eq!(r.status, "0xc000006d", "Status used when SubStatus is 0x0");
        assert_eq!(parse(&failed4625(7, T, "jdoe", "198.51.100.7", "2", "0xc000006a"), true), Err(Skip::Irrelevant), "interactive ignored");
        assert_eq!(parse(&failed4625(8, T, "jdoe", "-", "3", "0xc000006a"), true), Err(Skip::Irrelevant), "no address");
        assert_eq!(parse(&failed4625(9, T, "jdoe", "::1", "3", "0xc000006a"), true), Err(Skip::Irrelevant));
        assert!(parse(&failed4625(9, T, "jdoe", "::1", "3", "0xc000006a"), false).is_ok());
        assert!(parse(&failed4625(10, T, "", "198.51.100.7", "3", "0xc0000064"), true).is_ok(), "empty user name still counts");
    }

    #[test]
    fn parses_share_events() {
        let a = parse(&share_event(5140, 11, T, "jdoe", "10.10.1.222", r"\\*\C$", "", false), true).unwrap();
        assert_eq!((a.signal, a.share.as_str(), a.ip.as_str(), a.user.as_str()), (Signal::ShareAccess, r"\\*\C$", "10.10.1.222", "jdoe"));
        let d = parse(&share_event(5145, 12, T, "jdoe", "10.10.1.222", r"\\*\Finance", r"2026\budget.xlsx", true), true).unwrap();
        assert_eq!((d.signal, d.path.as_str()), (Signal::ShareDenied, r"2026\budget.xlsx"));
        assert_eq!(parse(&share_event(5145, 13, T, "jdoe", "10.10.1.222", r"\\*\Finance", "x", false), true), Err(Skip::Irrelevant), "5145 success is never used");
        assert_eq!(parse(&share_event(5140, 14, T, "jdoe", "10.10.1.222", r"\\*\C$", "", true), true).unwrap().signal, Signal::ShareDenied);
        assert!(parse(&share_event(5140, 15, T, "PC02$", "10.10.1.5", r"\\*\IPC$", "", false), true).is_ok(), "machine-like names still count");
        assert_eq!(parse(&share_event(5140, 16, T, "jdoe", "::1", r"\\*\C$", "", false), true), Err(Skip::Irrelevant));
    }

    #[test]
    fn parses_client_reported_name() {
        assert_eq!(parse(&logon4624(1, T, "jdoe", "198.51.100.25", "10"), true).unwrap().client_name, "LAPTOP7");
        assert_eq!(parse(&session4778(4778, 2, T, "jdoe", "198.51.100.25"), true).unwrap().client_name, "LAPTOP7");
        assert_eq!(parse(&lsm(21, 3, T, r"CORP\jdoe", "198.51.100.25", 2), true).unwrap().client_name, "");
        let named = |w: &str| {
            security(4624, 4, T, &[("TargetUserName", "jdoe"), ("TargetDomainName", "CORP"), ("LogonType", "10"), ("WorkstationName", w), ("IpAddress", "198.51.100.25")])
        };
        assert_eq!(parse(&named("-"), true).unwrap().client_name, "");
        assert_eq!(parse(&named("EVIL&#13;&#10;Bcc: x"), true).unwrap().client_name, "EVILBcc: x", "control characters stripped");
        assert_eq!(parse(&named(&"A".repeat(100)), true).unwrap().client_name.len(), 64);
    }

    #[test]
    fn domain_normalization() {
        assert_eq!(normalize_domain("corp.local", "PC01"), "CORP");
        assert_eq!(normalize_domain("Corp", "PC01"), "CORP");
        assert_eq!(normalize_domain(".", "pc01.corp.local"), "PC01");
        assert_eq!(normalize_domain("PC01", "PC01"), "PC01");
        assert_eq!(normalize_domain(" ", "PC01"), "");
        assert!(domains_compatible("CORP", ""));
        assert!(domains_compatible("CORP", "CORP"));
        assert!(!domains_compatible("CORP", "PC01"));
    }

    #[test]
    fn parses_reconnect_disconnect_and_lsm() {
        let r = parse(&session4778(4778, 7, T, "jdoe", "::ffff:198.51.100.25"), true).unwrap();
        assert_eq!((r.signal, r.ip.as_str()), (Signal::Reconnect, "198.51.100.25"));
        assert_eq!(r.logon_id.as_deref(), Some("0x3e7a1"));
        assert_eq!(parse(&logon4624(1, T, "jdoe", "198.51.100.25", "10"), true).unwrap().logon_id.as_deref(), Some("0x3e7a1"));
        assert_eq!(parse(&session4778(4779, 8, T, "jdoe", "198.51.100.25"), true).unwrap().signal, Signal::Disconnect);
        let l = parse(&lsm(25, 9, T, r"CORP\jdoe", "198.51.100.25", 4), true).unwrap();
        assert_eq!((l.signal, l.user.as_str(), l.domain.as_str(), l.session_id), (Signal::Reconnect, "jdoe", "CORP", Some(4)));
        assert_eq!(parse(&lsm(21, 9, T, r"CORP\jdoe", "198.51.100.25", 4), true).unwrap().signal, Signal::NewLogon);
        let a = parse(&rcm1149(3, T, "jdoe", "198.51.100.25"), true).unwrap();
        assert_eq!((a.signal, a.channel.as_str()), (Signal::Auth, CH_RCM));
    }
}
