//! Failed logons (4625): per source IP sliding-window counting. Failed
//! logons do not go through the session correlator; every attempt is recorded
//! in history and an alert is raised once one IP reaches the threshold.

use chrono::{DateTime, Duration, Utc};
use std::collections::{HashMap, VecDeque};

/// Bounds memory under a large spray from many addresses.
const MAX_PER_IP: usize = 10_000;
const MAX_IPS: usize = 10_000;

#[derive(Debug, Clone, PartialEq)]
pub struct Attempt {
    pub time: DateTime<Utc>,
    /// DOMAIN\user as reported (may be empty).
    pub user: String,
    pub logon_type: String,
    /// NTSTATUS (SubStatus, or Status when SubStatus is 0x0), lower case.
    pub status: String,
}

/// The attempts from one IP inside the window, oldest first.
#[derive(Debug, Clone, PartialEq)]
pub struct Burst {
    pub ip: String,
    pub window_minutes: u32,
    pub attempts: Vec<Attempt>,
}

#[derive(Default)]
pub struct FailedTracker {
    by_ip: HashMap<String, VecDeque<Attempt>>,
}

impl FailedTracker {
    /// Adds an attempt. Returns the burst when the IP has at least
    /// `threshold` attempts within `window_minutes` (by event time).
    pub fn push(&mut self, ip: &str, a: Attempt, window_minutes: u32, threshold: u32) -> Option<Burst> {
        let window = Duration::minutes(window_minutes as i64);
        let cutoff = a.time - window;
        if self.by_ip.len() >= MAX_IPS && !self.by_ip.contains_key(ip) {
            self.by_ip.retain(|_, q| q.back().is_some_and(|x| x.time >= cutoff));
        }
        let q = self.by_ip.entry(ip.to_string()).or_default();
        q.push_back(a);
        q.make_contiguous().sort_by_key(|x| x.time);
        let newest = q.back().map(|x| x.time).unwrap_or(cutoff);
        while q.front().is_some_and(|x| x.time < newest - window) || q.len() > MAX_PER_IP {
            q.pop_front();
        }
        (q.len() as u32 >= threshold.max(1)).then(|| Burst { ip: ip.to_string(), window_minutes, attempts: q.iter().cloned().collect() })
    }
}

/// Short readable reason for a 4625 status code.
pub fn reason(status: &str) -> String {
    let r = match status.to_ascii_lowercase().as_str() {
        "0xc000006a" => "wrong password",
        "0xc0000064" => "unknown user name",
        "0xc000006d" => "bad user name or password",
        "0xc0000234" => "account locked out",
        "0xc0000072" => "account disabled",
        "0xc0000193" => "account expired",
        "0xc0000071" => "password expired",
        "0xc0000224" => "password must be changed",
        "0xc000006f" => "outside allowed logon hours",
        "0xc0000070" => "workstation not allowed",
        "0xc000015b" => "logon type not granted",
        "0xc0000133" => "clock out of sync with domain controller",
        "0xc000005e" => "no logon server available",
        "" => "unknown",
        other => return format!("status {other}"),
    };
    r.to_string()
}

pub fn logon_type_label(t: &str) -> String {
    match t {
        "3" => "3 (network: NLA, file shares and other network logons)".into(),
        "10" => "10 (remote desktop)".into(),
        other => other.to_string(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn at(t: DateTime<Utc>, user: &str) -> Attempt {
        Attempt { time: t, user: user.into(), logon_type: "3".into(), status: "0xc000006a".into() }
    }

    #[test]
    fn threshold_window_and_per_ip() {
        let mut f = FailedTracker::default();
        let t = Utc::now();
        for i in 0..4 {
            assert!(f.push("198.51.100.7", at(t + Duration::seconds(i), "admin"), 5, 5).is_none(), "4 failures: no alert");
        }
        assert!(f.push("203.0.113.9", at(t, "admin"), 5, 5).is_none(), "other IP counted separately");
        let b = f.push("198.51.100.7", at(t + Duration::seconds(10), "root"), 5, 5).expect("5th failure alerts");
        assert_eq!(b.attempts.len(), 5);
        assert_eq!(b.ip, "198.51.100.7");
        // Six minutes later the old attempts have left the window.
        assert!(f.push("198.51.100.7", at(t + Duration::minutes(6), "admin"), 5, 5).is_none());
    }

    #[test]
    fn reasons() {
        assert_eq!(reason("0xC000006A"), "wrong password");
        assert_eq!(reason("0xc0000064"), "unknown user name");
        assert_eq!(reason("0xc0000234"), "account locked out");
        assert_eq!(reason("0xc0000999"), "status 0xc0000999");
    }
}
