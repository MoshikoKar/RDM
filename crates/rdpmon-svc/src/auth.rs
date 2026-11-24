//! Administration sessions and login rate limiting (in memory).

use std::collections::HashMap;
use std::time::{Duration, Instant};

pub const SESSION_IDLE: Duration = Duration::from_secs(15 * 60);
const FREE_ATTEMPTS: u32 = 5;
const MAX_LOCKOUT: Duration = Duration::from_secs(15 * 60);

struct Session {
    pid: u32,
    last_used: Instant,
}

#[derive(Default)]
pub struct Auth {
    sessions: HashMap<String, Session>,
    failures: u32,
    locked_until: Option<Instant>,
}

impl Auth {
    /// Remaining lockout, if any.
    pub fn locked_for(&self, now: Instant) -> Option<Duration> {
        self.locked_until.filter(|t| *t > now).map(|t| t - now)
    }

    /// Records a failed password attempt; after 5 consecutive failures each
    /// further failure locks authentication for 30 s, 60 s, … up to 15 min.
    pub fn record_failure(&mut self, now: Instant) {
        self.failures += 1;
        if self.failures >= FREE_ATTEMPTS {
            let exp = (self.failures - FREE_ATTEMPTS).min(10);
            let d = (Duration::from_secs(30) * (1u32 << exp)).min(MAX_LOCKOUT);
            self.locked_until = Some(now + d);
        }
    }

    pub fn failures(&self) -> u32 {
        self.failures
    }

    pub fn new_session(&mut self, pid: u32, now: Instant) -> String {
        self.failures = 0;
        self.locked_until = None;
        self.sessions.retain(|_, s| now.duration_since(s.last_used) < SESSION_IDLE);
        let token = rdpmon_core::crypto::random_hex(32);
        self.sessions.insert(token.clone(), Session { pid, last_used: now });
        token
    }

    /// Valid only from the same client process and while not idle too long.
    pub fn check(&mut self, token: &str, pid: u32, now: Instant) -> bool {
        let found = self
            .sessions
            .iter_mut()
            .find(|(t, _)| rdpmon_core::crypto::ct_eq(t.as_bytes(), token.as_bytes()));
        match found {
            Some((_, s)) if s.pid == pid && now.duration_since(s.last_used) < SESSION_IDLE => {
                s.last_used = now;
                true
            }
            _ => false,
        }
    }

    pub fn end(&mut self, token: &str) {
        self.sessions.remove(token);
    }

    pub fn end_all(&mut self) {
        self.sessions.clear();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn lockout_escalates() {
        let mut a = Auth::default();
        let t = Instant::now();
        for _ in 0..4 {
            a.record_failure(t);
        }
        assert!(a.locked_for(t).is_none());
        a.record_failure(t);
        assert_eq!(a.locked_for(t), Some(Duration::from_secs(30)));
        a.record_failure(t);
        assert_eq!(a.locked_for(t), Some(Duration::from_secs(60)));
        for _ in 0..20 {
            a.record_failure(t);
        }
        assert_eq!(a.locked_for(t), Some(MAX_LOCKOUT));
        a.new_session(1, t);
        assert!(a.locked_for(t).is_none());
    }

    #[test]
    fn sessions_bound_to_pid_and_expire() {
        let mut a = Auth::default();
        let t = Instant::now();
        let tok = a.new_session(42, t);
        assert!(a.check(&tok, 42, t));
        assert!(!a.check(&tok, 43, t), "other process");
        assert!(!a.check("bogus", 42, t));
        assert!(!a.check(&tok, 42, t + SESSION_IDLE + Duration::from_secs(1)), "idle expiry");
    }
}
