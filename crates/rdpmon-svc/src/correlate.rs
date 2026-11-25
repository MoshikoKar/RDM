//! Groups the several Windows events produced by one RDP connection into a
//! single connection record.
//!
//! A new RDP logon typically produces 1149 (auth) + 4624/10 + LSM 21; a
//! reconnection produces 1149 + 4778 + LSM 25 (+ sometimes 4624/10). These
//! arrive on different channels, in no guaranteed order. Observations with the
//! same user + source IP and a compatible domain (see
//! `events::domains_compatible`), within the correlation window, of the same
//! class (establish / disconnect) and not repeating an event type already in
//! the group are merged. A group is finalized once no new related event has
//! arrived for `settle`, or after `max_hold` at the latest.
//!
//! 1149 alone never produces a connection: authentication is not proof that a
//! session was established. It is only attached as supporting evidence.

use crate::events::{domains_compatible, normalize_domain, Observation, Signal};
use chrono::{DateTime, Utc};
use std::time::{Duration, Instant};

#[derive(Debug, Clone, PartialEq)]
pub struct EventRef {
    pub channel: String,
    pub record_id: u64,
    pub time: DateTime<Utc>,
}

#[derive(Debug, Clone, PartialEq)]
pub struct Connection {
    /// NewLogon, Reconnect or Disconnect.
    pub kind: Signal,
    pub time: DateTime<Utc>,
    pub user: String,
    pub domain: String,
    pub ip: String,
    pub session_id: Option<u32>,
    pub event_ids: Vec<u32>,
    pub refs: Vec<EventRef>,
}

impl Connection {
    /// Cooldown key: normalized domain + user + source IP, so two different
    /// accounts with the same user name never suppress each other.
    pub fn key(&self, host: &str) -> String {
        format!("{}|{}|{}", normalize_domain(&self.domain, host), self.user.to_lowercase(), self.ip)
    }
}

struct Group {
    disconnect: bool,
    key: String,
    /// Normalized domain of the group ("" until an event reports one).
    domain: String,
    obs: Vec<Observation>,
    first_arrival: Instant,
    last_arrival: Instant,
}

pub struct Correlator {
    /// Local computer name, for domain normalization.
    host: String,
    window: chrono::Duration,
    settle: Duration,
    max_hold: Duration,
    groups: Vec<Group>,
    auths: Vec<(Observation, Instant)>,
}

impl Correlator {
    pub fn new(window_secs: u32, host: &str) -> Self {
        Self {
            host: host.to_string(),
            window: chrono::Duration::seconds(window_secs as i64),
            settle: Duration::from_secs(4),
            max_hold: Duration::from_secs(20),
            groups: Vec::new(),
            auths: Vec::new(),
        }
    }

    pub fn set_window(&mut self, window_secs: u32) {
        self.window = chrono::Duration::seconds(window_secs as i64);
    }

    pub fn is_idle(&self) -> bool {
        self.groups.is_empty()
    }

    pub fn push(&mut self, o: Observation, now: Instant) {
        let same = |x: &Observation| x.channel == o.channel && x.record_id == o.record_id && x.time == o.time;
        if self.groups.iter().any(|g| g.obs.iter().any(same)) || self.auths.iter().any(|(a, _)| same(a)) {
            return; // the same record read twice (re-subscription)
        }
        if o.signal == Signal::Auth {
            self.auths.push((o, now));
            return;
        }
        let disconnect = o.signal == Signal::Disconnect;
        let key = o.key();
        let domain = normalize_domain(&o.domain, &self.host);
        let window = self.window;
        let found = self.groups.iter_mut().find(|g| {
            g.disconnect == disconnect
                && g.key == key
                && domains_compatible(&g.domain, &domain)
                && !g.obs.iter().any(|x| x.channel == o.channel && x.event_id == o.event_id)
                && g.obs.iter().any(|x| (x.time - o.time).abs() <= window)
        });
        match found {
            Some(g) => {
                if g.domain.is_empty() {
                    g.domain = domain;
                }
                g.obs.push(o);
                g.last_arrival = now;
            }
            None => self.groups.push(Group { disconnect, key, domain, obs: vec![o], first_arrival: now, last_arrival: now }),
        }
    }

    /// When the next group becomes due (for the monitor's wait timeout).
    pub fn next_deadline(&self) -> Option<Instant> {
        self.groups.iter().map(|g| (g.last_arrival + self.settle).min(g.first_arrival + self.max_hold)).min()
    }

    pub fn flush_due(&mut self, now: Instant) -> Vec<Connection> {
        let (settle, max_hold) = (self.settle, self.max_hold);
        self.flush_where(|g| now >= g.last_arrival + settle || now >= g.first_arrival + max_hold, now)
    }

    /// Finalizes everything (end of backlog recovery, shutdown).
    pub fn flush_all(&mut self, now: Instant) -> Vec<Connection> {
        self.flush_where(|_| true, now)
    }

    fn flush_where(&mut self, due: impl Fn(&Group) -> bool, now: Instant) -> Vec<Connection> {
        let mut out = Vec::new();
        let mut i = 0;
        while i < self.groups.len() {
            if due(&self.groups[i]) {
                let g = self.groups.swap_remove(i);
                out.push(self.finalize(g));
            } else {
                i += 1;
            }
        }
        // Authentication events with no session after a generous delay are dropped.
        let keep = self.max_hold * 3;
        self.auths.retain(|(_, at)| now.saturating_duration_since(*at) < keep);
        out.sort_by_key(|c| c.time);
        out
    }

    fn finalize(&mut self, g: Group) -> Connection {
        let mut obs = g.obs;
        if !g.disconnect {
            let window = self.window;
            let first = obs.iter().map(|o| o.time).min().expect("group is never empty");
            let mut i = 0;
            while i < self.auths.len() {
                let a = &self.auths[i].0;
                if a.key() == g.key
                    && domains_compatible(&g.domain, &normalize_domain(&a.domain, &self.host))
                    && (a.time - first).abs() <= window
                {
                    obs.push(self.auths.swap_remove(i).0);
                } else {
                    i += 1;
                }
            }
        }
        let kind = if g.disconnect {
            Signal::Disconnect
        } else if obs.iter().any(|o| o.signal == Signal::Reconnect) {
            Signal::Reconnect
        } else {
            Signal::NewLogon
        };
        // Primary event: earliest session event (not the 1149 auth).
        let primary = obs
            .iter()
            .filter(|o| o.signal != Signal::Auth)
            .min_by_key(|o| o.time)
            .expect("group has a session event")
            .clone();
        let domain = obs.iter().map(|o| o.domain.clone()).find(|d| !d.is_empty()).unwrap_or_default();
        let session_id = obs.iter().find_map(|o| o.session_id);
        let mut event_ids: Vec<u32> = obs.iter().map(|o| o.event_id).collect();
        event_ids.sort_unstable();
        event_ids.dedup();
        let refs = obs.iter().map(|o| EventRef { channel: o.channel.clone(), record_id: o.record_id, time: o.time }).collect();
        Connection { kind, time: primary.time, user: primary.user, domain, ip: primary.ip, session_id, event_ids, refs }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::events::{parse, samples::*};

    fn obs(xml: String) -> Observation {
        parse(&xml, true).unwrap()
    }

    const T0: &str = "2026-11-24T09:00:00Z";
    const T1: &str = "2026-11-24T09:00:01Z";
    const T2: &str = "2026-11-24T09:00:02Z";

    #[test]
    fn new_logon_events_merge_into_one_connection() {
        let mut c = Correlator::new(30, "PC01");
        let now = Instant::now();
        c.push(obs(rcm1149(1, T0, "jdoe", "203.0.113.10")), now);
        c.push(obs(logon4624(2, T1, "jdoe", "203.0.113.10", "10")), now);
        c.push(obs(lsm(21, 3, T2, r"CORP\jdoe", "203.0.113.10", 3)), now);
        assert!(c.flush_due(now + Duration::from_secs(1)).is_empty(), "still settling");
        let out = c.flush_due(now + Duration::from_secs(5));
        assert_eq!(out.len(), 1);
        let x = &out[0];
        assert_eq!(x.kind, Signal::NewLogon);
        assert_eq!(x.event_ids, vec![21, 1149, 4624]);
        assert_eq!(x.session_id, Some(3));
        assert_eq!(x.domain, "CORP");
        assert_eq!(x.refs.len(), 3);
        assert!(c.is_idle());
    }

    #[test]
    fn reconnect_wins_over_logon_in_same_group() {
        let mut c = Correlator::new(30, "PC01");
        let now = Instant::now();
        c.push(obs(lsm(25, 9, T0, r"CORP\jdoe", "198.51.100.25", 4)), now);
        c.push(obs(logon4624(2, T1, "jdoe", "198.51.100.25", "10")), now);
        c.push(obs(session4778(4778, 3, T1, "jdoe", "198.51.100.25")), now);
        let out = c.flush_all(now);
        assert_eq!(out.len(), 1);
        assert_eq!(out[0].kind, Signal::Reconnect);
    }

    #[test]
    fn authentication_alone_is_not_a_connection() {
        let mut c = Correlator::new(30, "PC01");
        let now = Instant::now();
        c.push(obs(rcm1149(1, T0, "jdoe", "203.0.113.10")), now);
        assert!(c.flush_all(now + Duration::from_secs(120)).is_empty());
    }

    #[test]
    fn different_users_or_ips_are_separate() {
        let mut c = Correlator::new(30, "PC01");
        let now = Instant::now();
        c.push(obs(logon4624(1, T0, "jdoe", "203.0.113.10", "10")), now);
        c.push(obs(logon4624(2, T0, "asmith", "203.0.113.10", "10")), now);
        c.push(obs(logon4624(3, T0, "jdoe", "198.51.100.1", "10")), now);
        assert_eq!(c.flush_all(now).len(), 3);
    }

    #[test]
    fn same_user_name_in_different_domains_is_separate() {
        let mut c = Correlator::new(30, "PC01");
        let now = Instant::now();
        c.push(obs(lsm(21, 1, T0, r"CORP\admin", "203.0.113.10", 2)), now);
        c.push(obs(lsm(21, 2, T1, r"PC01\admin", "203.0.113.10", 3)), now);
        let out = c.flush_all(now);
        assert_eq!(out.len(), 2);
        assert_ne!(out[0].key("PC01"), out[1].key("PC01"), "separate cooldown keys");
    }

    #[test]
    fn fqdn_and_netbios_domain_merge() {
        let mut c = Correlator::new(30, "PC01");
        let now = Instant::now();
        let mut fqdn = obs(logon4624(1, T0, "jdoe", "203.0.113.10", "10"));
        fqdn.domain = "corp.local".into();
        c.push(fqdn, now);
        c.push(obs(lsm(21, 2, T1, r"CORP\jdoe", "203.0.113.10", 3)), now);
        assert_eq!(c.flush_all(now).len(), 1);
    }

    #[test]
    fn empty_domain_merges_with_the_session() {
        let mut c = Correlator::new(30, "PC01");
        let now = Instant::now();
        let mut nodomain = obs(logon4624(1, T0, "jdoe", "203.0.113.10", "10"));
        nodomain.domain.clear();
        c.push(nodomain, now);
        c.push(obs(lsm(21, 2, T1, r"CORP\jdoe", "203.0.113.10", 3)), now);
        let out = c.flush_all(now);
        assert_eq!(out.len(), 1);
        assert_eq!(out[0].domain, "CORP");
    }

    #[test]
    fn local_dot_domain_matches_computer_name() {
        let mut c = Correlator::new(30, "PC01");
        let now = Instant::now();
        let mut dot = obs(logon4624(1, T0, "admin", "203.0.113.10", "10"));
        dot.domain = ".".into();
        c.push(dot, now);
        c.push(obs(lsm(21, 2, T1, r"PC01\admin", "203.0.113.10", 3)), now);
        assert_eq!(c.flush_all(now).len(), 1);
    }

    #[test]
    fn repeated_event_type_starts_a_new_connection() {
        let mut c = Correlator::new(30, "PC01");
        let now = Instant::now();
        c.push(obs(session4778(4778, 1, T0, "jdoe", "203.0.113.10")), now);
        c.push(obs(session4778(4778, 2, T2, "jdoe", "203.0.113.10")), now);
        assert_eq!(c.flush_all(now).len(), 2);
    }

    #[test]
    fn same_record_read_twice_is_ignored() {
        let mut c = Correlator::new(30, "PC01");
        let now = Instant::now();
        c.push(obs(logon4624(1, T0, "jdoe", "203.0.113.10", "10")), now);
        c.push(obs(logon4624(1, T0, "jdoe", "203.0.113.10", "10")), now);
        let out = c.flush_all(now);
        assert_eq!(out.len(), 1);
        assert_eq!(out[0].refs.len(), 1);
    }

    #[test]
    fn events_outside_window_are_separate() {
        let mut c = Correlator::new(30, "PC01");
        let now = Instant::now();
        c.push(obs(logon4624(1, T0, "jdoe", "203.0.113.10", "10")), now);
        c.push(obs(lsm(21, 2, "2026-11-24T09:05:00Z", r"CORP\jdoe", "203.0.113.10", 3)), now);
        assert_eq!(c.flush_all(now).len(), 2);
    }

    #[test]
    fn disconnects_are_grouped_separately() {
        let mut c = Correlator::new(30, "PC01");
        let now = Instant::now();
        c.push(obs(session4778(4779, 1, T0, "jdoe", "203.0.113.10")), now);
        c.push(obs(lsm(24, 2, T1, r"CORP\jdoe", "203.0.113.10", 3)), now);
        c.push(obs(lsm(25, 3, T2, r"CORP\jdoe", "203.0.113.10", 3)), now);
        let out = c.flush_all(now);
        assert_eq!(out.iter().filter(|x| x.kind == Signal::Disconnect).count(), 1);
        assert_eq!(out.iter().filter(|x| x.kind == Signal::Reconnect).count(), 1);
    }

    #[test]
    fn max_hold_bounds_latency() {
        let mut c = Correlator::new(30, "PC01");
        let start = Instant::now();
        c.push(obs(logon4624(1, T0, "jdoe", "203.0.113.10", "10")), start);
        assert!(c.next_deadline().unwrap() <= start + Duration::from_secs(4));
        // Keep feeding unrelated-key events: the jdoe group must still flush.
        for i in 0..30u64 {
            let t = start + Duration::from_secs(i);
            c.push(obs(logon4624(100 + i, T0, &format!("u{i}"), "203.0.113.10", "10")), t);
        }
        assert!(c.flush_due(start + Duration::from_secs(21)).iter().any(|x| x.user == "jdoe"));
    }
}
