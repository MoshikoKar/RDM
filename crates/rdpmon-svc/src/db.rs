//! SQLite persistence: connection history, processed-event de-duplication,
//! cooldown state, notification outbox, audit log, event-log bookmarks.

use crate::correlate::Connection;
use crate::events::Signal;
use chrono::{DateTime, Duration, Utc};
use rdpmon_core::config::RetentionConfig;
use rdpmon_core::ipc::{AuditEntry, HistoryEntry};
use rusqlite::{params, Connection as Sql, OptionalExtension};
use std::path::Path;

pub type Result<T> = rusqlite::Result<T>;

const SCHEMA_VERSION: i32 = 3;
pub const KV_INITIALIZED: &str = "initialized";

pub fn ts(t: DateTime<Utc>) -> String {
    t.format("%Y-%m-%dT%H:%M:%S%.3fZ").to_string()
}

pub fn parse_ts(s: &str) -> Option<DateTime<Utc>> {
    DateTime::parse_from_rfc3339(s).ok().map(|t| t.with_timezone(&Utc))
}

pub fn kind_name(k: Signal) -> &'static str {
    match k {
        Signal::NewLogon => "logon",
        Signal::Reconnect => "reconnect",
        Signal::Disconnect => "disconnect",
        Signal::Auth => "auth",
        Signal::Failed => "failed",
        Signal::Logoff => "logoff",
        Signal::ShareAccess => "share",
        Signal::ShareDenied => "share_denied",
    }
}

pub struct Db {
    pub conn: Sql,
}

pub struct OutboxItem {
    pub id: i64,
    pub kind: String,
    pub connection_id: Option<i64>,
    pub subject: String,
    pub body_text: String,
    pub body_html: String,
    pub created_at: DateTime<Utc>,
    pub attempts: u32,
}

pub struct Message {
    pub subject: String,
    pub text: String,
    pub html: String,
}

/// How familiar a user / source IP pair is, from RDP history.
#[derive(Debug, Clone, PartialEq)]
pub enum FirstSeen {
    NewUser,
    NewIp,
    NewPair,
    Seen(DateTime<Utc>),
}

/// Share access in a period, grouped by type, account, IP and share.
#[derive(Debug, Clone, PartialEq)]
pub struct ShareRow {
    pub kind: String,
    pub user: String,
    pub domain: String,
    pub ip: String,
    pub share: String,
    pub count: u64,
}

#[derive(Debug, Clone)]
pub struct ConnRow {
    pub time: DateTime<Utc>,
    pub kind: String,
    pub user: String,
    pub domain: String,
    pub ip: String,
}

impl Db {
    pub fn open(path: &Path) -> Result<Self> {
        let conn = Sql::open(path)?;
        conn.busy_timeout(std::time::Duration::from_secs(10))?;
        conn.pragma_update(None, "journal_mode", "WAL")?;
        conn.pragma_update(None, "synchronous", "NORMAL")?;
        let db = Db { conn };
        db.migrate(path)?;
        Ok(db)
    }

    #[cfg(test)]
    pub fn memory() -> Self {
        let db = Db { conn: Sql::open_in_memory().unwrap() };
        db.migrate(Path::new(":memory:")).unwrap();
        db
    }

    fn migrate(&self, path: &Path) -> Result<()> {
        let v: i32 = self.conn.pragma_query_value(None, "user_version", |r| r.get(0))?;
        if v > SCHEMA_VERSION {
            return Err(rusqlite::Error::InvalidParameterName(format!(
                "database schema {v} is newer than this program supports ({SCHEMA_VERSION}); refusing to modify it"
            )));
        }
        if v == SCHEMA_VERSION {
            return Ok(());
        }
        if v > 0 && path.exists() {
            // Keep a copy before any future irreversible migration.
            let _ = std::fs::copy(path, path.with_extension(format!("db.bak-v{v}")));
        }
        if v < 1 {
            self.conn.execute_batch(
                "BEGIN;
                 CREATE TABLE IF NOT EXISTS connections (
                    id INTEGER PRIMARY KEY, kind TEXT NOT NULL, event_time TEXT NOT NULL,
                    hostname TEXT NOT NULL, username TEXT NOT NULL, domain TEXT NOT NULL,
                    source_ip TEXT NOT NULL, session_id INTEGER, event_ids TEXT NOT NULL,
                    recovered INTEGER NOT NULL DEFAULT 0, notify_status TEXT NOT NULL);
                 CREATE INDEX IF NOT EXISTS ix_connections_time ON connections(event_time);
                 CREATE TABLE IF NOT EXISTS processed_events (
                    channel TEXT NOT NULL, record_id INTEGER NOT NULL, event_time TEXT NOT NULL,
                    processed_at TEXT NOT NULL, PRIMARY KEY (channel, record_id, event_time)) WITHOUT ROWID;
                 CREATE TABLE IF NOT EXISTS cooldown (key TEXT PRIMARY KEY, last_time TEXT NOT NULL);
                 CREATE TABLE IF NOT EXISTS outbox (
                    id INTEGER PRIMARY KEY, kind TEXT NOT NULL, dedupe_key TEXT NOT NULL UNIQUE,
                    connection_id INTEGER, subject TEXT NOT NULL, body_text TEXT NOT NULL, body_html TEXT NOT NULL,
                    created_at TEXT NOT NULL, status TEXT NOT NULL, attempts INTEGER NOT NULL DEFAULT 0,
                    next_attempt_at TEXT NOT NULL, last_error TEXT, sent_at TEXT);
                 CREATE INDEX IF NOT EXISTS ix_outbox_due ON outbox(status, next_attempt_at);
                 CREATE TABLE IF NOT EXISTS audit (
                    id INTEGER PRIMARY KEY, time TEXT NOT NULL, category TEXT NOT NULL,
                    action TEXT NOT NULL, detail TEXT NOT NULL);
                 CREATE INDEX IF NOT EXISTS ix_audit_time ON audit(time);
                 CREATE TABLE IF NOT EXISTS bookmarks (channel TEXT PRIMARY KEY, xml TEXT NOT NULL, updated_at TEXT NOT NULL);
                 CREATE TABLE IF NOT EXISTS kv (key TEXT PRIMARY KEY, value TEXT NOT NULL);
                 PRAGMA user_version = 1;
                 COMMIT;",
            )?;
        }
        if v < 2 {
            self.conn.execute_batch(
                "BEGIN;
                 ALTER TABLE connections ADD COLUMN share TEXT NOT NULL DEFAULT '';
                 ALTER TABLE connections ADD COLUMN path TEXT NOT NULL DEFAULT '';
                 PRAGMA user_version = 2;
                 COMMIT;",
            )?;
        }
        if v < 3 {
            self.conn.execute_batch(
                "BEGIN;
                 CREATE INDEX IF NOT EXISTS ix_connections_user_ip ON connections(username COLLATE NOCASE, source_ip);
                 PRAGMA user_version = 3;
                 COMMIT;",
            )?;
        }
        Ok(())
    }

    // ---------- events / connections ----------

    pub fn is_processed(&self, channel: &str, record_id: u64, time: DateTime<Utc>) -> Result<bool> {
        self.conn
            .query_row(
                "SELECT 1 FROM processed_events WHERE channel=?1 AND record_id=?2 AND event_time=?3",
                params![channel, record_id as i64, ts(time)],
                |_| Ok(()),
            )
            .optional()
            .map(|r| r.is_some())
    }

    pub fn cooldown_last(&self, key: &str) -> Result<Option<DateTime<Utc>>> {
        Ok(self
            .conn
            .query_row("SELECT last_time FROM cooldown WHERE key=?1", [key], |r| r.get::<_, String>(0))
            .optional()?
            .and_then(|s| parse_ts(&s)))
    }

    /// Records a finalized connection atomically: history row, processed
    /// event ids, cooldown state (under `cooldown_key`) and (optionally) a
    /// queued notification. Returns the connection id and whether an older
    /// queued item was dropped.
    #[allow(clippy::too_many_arguments)]
    pub fn record_connection(
        &mut self,
        c: &Connection,
        hostname: &str,
        cooldown_key: &str,
        recovered: bool,
        status: &str,
        message: Option<Message>,
        max_queue: u32,
    ) -> Result<(i64, bool)> {
        let now = ts(Utc::now());
        let tx = self.conn.transaction()?;
        let ids = c.event_ids.iter().map(|i| i.to_string()).collect::<Vec<_>>().join(",");
        tx.execute(
            "INSERT INTO connections (kind, event_time, hostname, username, domain, source_ip, session_id, event_ids, recovered, notify_status, share, path)
             VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11,?12)",
            params![kind_name(c.kind), ts(c.time), hostname, c.user, c.domain, c.ip, c.session_id, ids, recovered, status, c.share, c.path],
        )?;
        let conn_id = tx.last_insert_rowid();
        for r in &c.refs {
            tx.execute(
                "INSERT OR IGNORE INTO processed_events (channel, record_id, event_time, processed_at) VALUES (?1,?2,?3,?4)",
                params![r.channel, r.record_id as i64, ts(r.time), now],
            )?;
        }
        let mut dropped = false;
        if let Some(m) = message {
            tx.execute(
                "INSERT INTO cooldown (key, last_time) VALUES (?1, ?2) ON CONFLICT(key) DO UPDATE SET last_time=excluded.last_time",
                params![cooldown_key, ts(c.time)],
            )?;
            dropped = enqueue_tx(&tx, "alert", &format!("conn:{conn_id}"), Some(conn_id), &m, max_queue)?;
        }
        tx.commit()?;
        Ok((conn_id, dropped))
    }

    pub fn connections_between(&self, start: DateTime<Utc>, end: DateTime<Utc>) -> Result<Vec<ConnRow>> {
        let mut st = self.conn.prepare(
            "SELECT event_time, kind, username, domain, source_ip FROM connections
             WHERE event_time >= ?1 AND event_time < ?2 AND kind IN ('logon','reconnect') ORDER BY event_time",
        )?;
        let rows = st.query_map(params![ts(start), ts(end)], |r| {
            Ok(ConnRow {
                time: parse_ts(&r.get::<_, String>(0)?).unwrap_or_default(),
                kind: r.get(1)?,
                user: r.get(2)?,
                domain: r.get(3)?,
                ip: r.get(4)?,
            })
        })?;
        rows.collect()
    }

    /// Compares a new RDP connection with earlier logons / reconnections.
    /// Call before the connection itself is recorded.
    pub fn first_seen(&self, user: &str, ip: &str) -> Result<FirstSeen> {
        const RDP: &str = "kind IN ('logon','reconnect')";
        let user_last: Option<String> = self.conn.query_row(
            &format!("SELECT max(event_time) FROM connections WHERE username = ?1 COLLATE NOCASE AND {RDP}"),
            [user],
            |r| r.get(0),
        )?;
        if user_last.is_none() {
            return Ok(FirstSeen::NewUser);
        }
        let ip_seen = self
            .conn
            .query_row(&format!("SELECT 1 FROM connections WHERE source_ip = ?1 AND {RDP} LIMIT 1"), [ip], |_| Ok(()))
            .optional()?
            .is_some();
        if !ip_seen {
            return Ok(FirstSeen::NewIp);
        }
        let pair_last: Option<String> = self.conn.query_row(
            &format!("SELECT max(event_time) FROM connections WHERE username = ?1 COLLATE NOCASE AND source_ip = ?2 AND {RDP}"),
            [user, ip],
            |r| r.get(0),
        )?;
        Ok(match pair_last.and_then(|s| parse_ts(&s)) {
            Some(t) => FirstSeen::Seen(t),
            None => FirstSeen::NewPair,
        })
    }

    /// Start (and source IP) of the session that a disconnect / logoff at
    /// `before` ends: the latest logon or reconnection of the user with the
    /// same session ID, else (when `ip` is known) from the same IP.
    pub fn session_start(&self, user: &str, session_id: Option<u32>, ip: &str, before: DateTime<Utc>) -> Result<Option<(DateTime<Utc>, String)>> {
        const Q: &str = "SELECT event_time, source_ip FROM connections
             WHERE username = ?1 COLLATE NOCASE AND kind IN ('logon','reconnect') AND event_time <= ?2";
        let row = |r: &rusqlite::Row| Ok((r.get::<_, String>(0)?, r.get::<_, String>(1)?));
        let mut found = None;
        if let Some(s) = session_id {
            found = self
                .conn
                .query_row(&format!("{Q} AND session_id = ?3 ORDER BY event_time DESC LIMIT 1"), params![user, ts(before), s], row)
                .optional()?;
        }
        if found.is_none() && !ip.is_empty() {
            found = self
                .conn
                .query_row(&format!("{Q} AND source_ip = ?3 ORDER BY event_time DESC LIMIT 1"), params![user, ts(before), ip], row)
                .optional()?;
        }
        Ok(found.and_then(|(t, ip)| parse_ts(&t).map(|t| (t, ip))))
    }

    /// Failed logons in the period: (attempts, distinct source IPs).
    pub fn failed_between(&self, start: DateTime<Utc>, end: DateTime<Utc>) -> Result<(u64, u64)> {
        self.conn.query_row(
            "SELECT count(*), count(DISTINCT source_ip) FROM connections WHERE event_time >= ?1 AND event_time < ?2 AND kind='failed'",
            params![ts(start), ts(end)],
            |r| Ok((r.get::<_, i64>(0)? as u64, r.get::<_, i64>(1)? as u64)),
        )
    }

    pub fn shares_between(&self, start: DateTime<Utc>, end: DateTime<Utc>) -> Result<Vec<ShareRow>> {
        let mut st = self.conn.prepare(
            "SELECT kind, username, domain, source_ip, share, count(*) FROM connections
             WHERE event_time >= ?1 AND event_time < ?2 AND kind IN ('share','share_denied')
             GROUP BY kind, lower(domain), lower(username), source_ip, lower(share)
             ORDER BY count(*) DESC, username LIMIT 200",
        )?;
        let rows = st.query_map(params![ts(start), ts(end)], |r| {
            Ok(ShareRow {
                kind: r.get(0)?,
                user: r.get(1)?,
                domain: r.get(2)?,
                ip: r.get(3)?,
                share: r.get(4)?,
                count: r.get::<_, i64>(5)? as u64,
            })
        })?;
        rows.collect()
    }

    pub fn recent_history(&self, limit: u32) -> Result<Vec<HistoryEntry>> {
        let mut st = self.conn.prepare(
            "SELECT event_time, kind, username, domain, source_ip, session_id, event_ids, notify_status
             FROM connections ORDER BY event_time DESC LIMIT ?1",
        )?;
        let rows = st.query_map([limit], |r| {
            Ok(HistoryEntry {
                time: r.get(0)?,
                kind: r.get(1)?,
                user: r.get(2)?,
                domain: r.get(3)?,
                source_ip: r.get(4)?,
                session_id: r.get(5)?,
                event_ids: r.get(6)?,
                notification: r.get(7)?,
            })
        })?;
        rows.collect()
    }

    pub fn last_connection_time(&self) -> Result<Option<String>> {
        self.conn
            .query_row("SELECT max(event_time) FROM connections WHERE kind IN ('logon','reconnect')", [], |r| r.get(0))
    }

    // ---------- bookmarks / kv ----------

    pub fn bookmark(&self, channel: &str) -> Result<Option<String>> {
        self.conn.query_row("SELECT xml FROM bookmarks WHERE channel=?1", [channel], |r| r.get(0)).optional()
    }

    pub fn set_bookmark(&self, channel: &str, xml: &str) -> Result<()> {
        self.conn.execute(
            "INSERT INTO bookmarks (channel, xml, updated_at) VALUES (?1,?2,?3)
             ON CONFLICT(channel) DO UPDATE SET xml=excluded.xml, updated_at=excluded.updated_at",
            params![channel, xml, ts(Utc::now())],
        )?;
        Ok(())
    }

    pub fn kv(&self, key: &str) -> Result<Option<String>> {
        self.conn.query_row("SELECT value FROM kv WHERE key=?1", [key], |r| r.get(0)).optional()
    }

    pub fn set_kv(&self, key: &str, value: &str) -> Result<()> {
        self.conn.execute(
            "INSERT INTO kv (key, value) VALUES (?1,?2) ON CONFLICT(key) DO UPDATE SET value=excluded.value",
            params![key, value],
        )?;
        Ok(())
    }

    /// Set once an administration password exists. Survives loss of the
    /// configuration file, so losing config.dat never re-opens first-run setup.
    pub fn initialized(&self) -> bool {
        matches!(self.kv(KV_INITIALIZED), Ok(Some(_)))
    }

    pub fn delete_kv(&self, key: &str) -> Result<()> {
        self.conn.execute("DELETE FROM kv WHERE key=?1", [key])?;
        Ok(())
    }

    // ---------- outbox ----------

    /// Returns true if an older pending item had to be dropped (queue full).
    /// Returns Ok(false) without inserting if the dedupe key already exists.
    pub fn enqueue(&mut self, kind: &str, dedupe_key: &str, m: &Message, max_queue: u32) -> Result<bool> {
        let tx = self.conn.transaction()?;
        let d = enqueue_tx(&tx, kind, dedupe_key, None, m, max_queue)?;
        tx.commit()?;
        Ok(d)
    }

    pub fn due_items(&self, now: DateTime<Utc>, limit: u32) -> Result<Vec<OutboxItem>> {
        let mut st = self.conn.prepare(
            "SELECT id, kind, connection_id, subject, body_text, body_html, created_at, attempts FROM outbox
             WHERE status='pending' AND next_attempt_at <= ?1 ORDER BY id LIMIT ?2",
        )?;
        let rows = st.query_map(params![ts(now), limit], |r| {
            Ok(OutboxItem {
                id: r.get(0)?,
                kind: r.get(1)?,
                connection_id: r.get(2)?,
                subject: r.get(3)?,
                body_text: r.get(4)?,
                body_html: r.get(5)?,
                created_at: parse_ts(&r.get::<_, String>(6)?).unwrap_or_else(Utc::now),
                attempts: r.get(7)?,
            })
        })?;
        rows.collect()
    }

    pub fn next_due(&self) -> Result<Option<DateTime<Utc>>> {
        Ok(self
            .conn
            .query_row("SELECT min(next_attempt_at) FROM outbox WHERE status='pending'", [], |r| r.get::<_, Option<String>>(0))?
            .and_then(|s| parse_ts(&s)))
    }

    pub fn mark_sent(&self, item: &OutboxItem) -> Result<()> {
        self.conn.execute(
            "UPDATE outbox SET status='sent', sent_at=?2, attempts=attempts+1, last_error=NULL WHERE id=?1",
            params![item.id, ts(Utc::now())],
        )?;
        if let Some(c) = item.connection_id {
            self.conn.execute("UPDATE connections SET notify_status='sent' WHERE id=?1", [c])?;
        }
        Ok(())
    }

    pub fn mark_retry(&self, item: &OutboxItem, next: DateTime<Utc>, err: &str) -> Result<()> {
        self.conn.execute(
            "UPDATE outbox SET attempts=attempts+1, next_attempt_at=?2, last_error=?3 WHERE id=?1",
            params![item.id, ts(next), err],
        )?;
        Ok(())
    }

    pub fn mark_failed(&self, item: &OutboxItem, err: &str) -> Result<()> {
        self.conn.execute(
            "UPDATE outbox SET status='failed', attempts=attempts+1, last_error=?2 WHERE id=?1",
            params![item.id, err],
        )?;
        if let Some(c) = item.connection_id {
            self.conn.execute("UPDATE connections SET notify_status='failed' WHERE id=?1", [c])?;
        }
        Ok(())
    }

    /// SMTP server unreachable: no pending item is attempted before `t`.
    pub fn defer_pending_until(&self, t: DateTime<Utc>) -> Result<usize> {
        self.conn.execute(
            "UPDATE outbox SET next_attempt_at=?1 WHERE status='pending' AND next_attempt_at < ?1",
            [ts(t)],
        )
    }

    /// After an SMTP configuration change, retry everything immediately.
    pub fn retry_pending_now(&self) -> Result<usize> {
        self.conn.execute("UPDATE outbox SET next_attempt_at=?1 WHERE status='pending'", [ts(Utc::now())])
    }

    pub fn outbox_counts(&self) -> Result<(u64, u64)> {
        self.conn.query_row(
            "SELECT coalesce(sum(status='pending'),0), coalesce(sum(status='failed'),0) FROM outbox",
            [],
            |r| Ok((r.get::<_, i64>(0)? as u64, r.get::<_, i64>(1)? as u64)),
        )
    }

    // ---------- audit ----------

    pub fn audit(&self, category: &str, action: &str, detail: &str) -> Result<()> {
        self.conn.execute(
            "INSERT INTO audit (time, category, action, detail) VALUES (?1,?2,?3,?4)",
            params![ts(Utc::now()), category, action, detail],
        )?;
        Ok(())
    }

    pub fn recent_audit(&self, limit: u32) -> Result<Vec<AuditEntry>> {
        let mut st = self.conn.prepare("SELECT time, category, action, detail FROM audit ORDER BY id DESC LIMIT ?1")?;
        let rows = st.query_map([limit], |r| {
            Ok(AuditEntry { time: r.get(0)?, category: r.get(1)?, action: r.get(2)?, detail: r.get(3)? })
        })?;
        rows.collect()
    }

    // ---------- retention ----------

    pub fn cleanup(&self, r: &RetentionConfig, now: DateTime<Utc>) -> Result<()> {
        let days = |d: u32| ts(now - Duration::days(d as i64));
        self.conn.execute("DELETE FROM connections WHERE event_time < ?1", [days(r.history_days)])?;
        self.conn.execute("DELETE FROM audit WHERE time < ?1", [days(r.audit_days)])?;
        // Hard cap so repeated requests cannot grow the database without bound.
        self.conn.execute("DELETE FROM audit WHERE id <= (SELECT max(id) - 100000 FROM audit)", [])?;
        self.conn.execute("DELETE FROM outbox WHERE status <> 'pending' AND created_at < ?1", [days(r.outbox_days)])?;
        // Processed ids only matter while the events can still be re-read.
        self.conn.execute("DELETE FROM processed_events WHERE processed_at < ?1", [days(35)])?;
        self.conn.execute("DELETE FROM cooldown WHERE last_time < ?1", [days(8)])?;
        Ok(())
    }
}

fn enqueue_tx(tx: &rusqlite::Transaction, kind: &str, dedupe: &str, conn_id: Option<i64>, m: &Message, max_queue: u32) -> Result<bool> {
    let now = ts(Utc::now());
    let inserted = tx.execute(
        "INSERT OR IGNORE INTO outbox (kind, dedupe_key, connection_id, subject, body_text, body_html, created_at, status, next_attempt_at)
         VALUES (?1,?2,?3,?4,?5,?6,?7,'pending',?7)",
        params![kind, dedupe, conn_id, m.subject, m.text, m.html, now],
    )?;
    if inserted == 0 {
        return Ok(false);
    }
    let pending: i64 = tx.query_row("SELECT count(*) FROM outbox WHERE status='pending'", [], |r| r.get(0))?;
    let excess = pending - max_queue as i64;
    if excess > 0 {
        tx.execute(
            "UPDATE connections SET notify_status='dropped' WHERE id IN
               (SELECT connection_id FROM outbox WHERE status='pending' AND connection_id IS NOT NULL ORDER BY id LIMIT ?1)",
            [excess],
        )?;
        tx.execute(
            "UPDATE outbox SET status='dropped', last_error='queue limit reached' WHERE id IN
               (SELECT id FROM outbox WHERE status='pending' ORDER BY id LIMIT ?1)",
            [excess],
        )?;
        return Ok(true);
    }
    Ok(false)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::correlate::EventRef;

    pub fn conn(user: &str, t: DateTime<Utc>) -> Connection {
        Connection {
            kind: Signal::NewLogon,
            time: t,
            user: user.into(),
            domain: "CORP".into(),
            ip: "203.0.113.10".into(),
            session_id: Some(2),
            event_ids: vec![21, 4624],
            refs: vec![EventRef { channel: "Security".into(), record_id: 77, time: t }],
            ..Default::default()
        }
    }

    fn msg() -> Message {
        Message { subject: "s".into(), text: "t".into(), html: "h".into() }
    }

    #[test]
    fn records_history_dedupe_and_cooldown() {
        let mut db = Db::memory();
        let t = Utc::now();
        let c = conn("jdoe", t);
        assert!(!db.is_processed("Security", 77, t).unwrap());
        db.record_connection(&c, "PC01", &c.key("PC01"), false, "queued", Some(msg()), 100).unwrap();
        assert!(db.is_processed("Security", 77, t).unwrap());
        assert!(!db.is_processed("Security", 77, t + Duration::seconds(1)).unwrap(), "cleared log reusing ids is not a duplicate");
        assert_eq!(db.cooldown_last(&c.key("PC01")).unwrap().map(ts), Some(ts(t)));
        assert_eq!(db.outbox_counts().unwrap(), (1, 0));
        db.record_connection(&conn("asmith", t), "PC01", "k", false, "cooldown", None, 100).unwrap();
        assert_eq!(db.outbox_counts().unwrap(), (1, 0));
        assert_eq!(db.recent_history(10).unwrap().len(), 2);
        assert_eq!(db.connections_between(t - Duration::hours(1), t + Duration::hours(1)).unwrap().len(), 2);
    }

    #[test]
    fn cooldown_is_keyed_per_domain() {
        let mut db = Db::memory();
        let t = Utc::now();
        let corp = conn("admin", t);
        let mut local = conn("admin", t);
        local.domain = "PC01".into();
        db.record_connection(&corp, "PC01", &corp.key("PC01"), false, "queued", Some(msg()), 100).unwrap();
        assert!(db.cooldown_last(&corp.key("PC01")).unwrap().is_some());
        assert!(db.cooldown_last(&local.key("PC01")).unwrap().is_none(), "local account is not in cooldown");
        let mut fqdn = conn("Admin", t);
        fqdn.domain = "corp.local".into();
        assert!(db.cooldown_last(&fqdn.key("PC01")).unwrap().is_some(), "same account, other domain form");
    }

    #[test]
    fn failed_logons_are_counted_but_not_listed_as_connections() {
        let mut db = Db::memory();
        let t = Utc::now();
        for (i, ip) in ["198.51.100.7", "198.51.100.7", "203.0.113.9"].iter().enumerate() {
            let mut f = conn("admin", t);
            f.kind = Signal::Failed;
            f.ip = ip.to_string();
            f.refs[0].record_id = 100 + i as u64;
            db.record_connection(&f, "PC01", &format!("failed|{ip}"), false, "n/a", None, 10).unwrap();
        }
        let range = (t - Duration::hours(1), t + Duration::hours(1));
        assert_eq!(db.failed_between(range.0, range.1).unwrap(), (3, 2));
        assert!(db.connections_between(range.0, range.1).unwrap().is_empty());
    }

    #[test]
    fn share_history_and_schema_upgrade() {
        let mut db = Db::memory();
        let t = Utc::now();
        for (i, (kind, share)) in [(Signal::ShareAccess, r"\\*\C$"), (Signal::ShareAccess, r"\\*\c$"), (Signal::ShareDenied, r"\\*\Finance")].iter().enumerate() {
            let mut s = conn("jdoe", t);
            s.kind = *kind;
            s.share = share.to_string();
            s.refs[0].record_id = 200 + i as u64;
            db.record_connection(&s, "PC01", "k", false, "n/a", None, 10).unwrap();
        }
        let rows = db.shares_between(t - Duration::hours(1), t + Duration::hours(1)).unwrap();
        assert_eq!(rows.len(), 2);
        assert_eq!((rows[0].kind.as_str(), rows[0].count), ("share", 2));
        // A version 1 database gains the new columns.
        let dir = std::env::temp_dir().join(format!("rdpmon-test-{}", rdpmon_core::crypto::random_hex(6)));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("history.db");
        {
            // Turn a current database back into the version 1 layout.
            let old = Db::open(&path).unwrap();
            old.conn
                .execute_batch(
                    "DROP INDEX IF EXISTS ix_connections_user_ip;
                     ALTER TABLE connections DROP COLUMN share;
                     ALTER TABLE connections DROP COLUMN path;
                     PRAGMA user_version = 1;",
                )
                .unwrap();
        }
        let mut db = Db::open(&path).unwrap();
        db.record_connection(&conn("jdoe", t), "PC01", "k", false, "n/a", None, 10).unwrap();
        drop(db);
        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn first_seen_lookup() {
        let mut db = Db::memory();
        let t = Utc::now() - Duration::days(3);
        assert_eq!(db.first_seen("jdoe", "203.0.113.10").unwrap(), FirstSeen::NewUser, "fresh database");
        db.record_connection(&conn("jdoe", t), "PC01", "k", false, "n/a", None, 10).unwrap();
        let mut other = conn("asmith", t);
        other.ip = "198.51.100.1".into();
        other.refs[0].record_id = 78;
        db.record_connection(&other, "PC01", "k", false, "n/a", None, 10).unwrap();
        let mut failed = conn("mallory", t);
        failed.kind = Signal::Failed;
        failed.refs[0].record_id = 79;
        db.record_connection(&failed, "PC01", "k", false, "n/a", None, 10).unwrap();
        assert_eq!(db.first_seen("JDOE", "203.0.113.10").unwrap().clone(), FirstSeen::Seen(parse_ts(&ts(t)).unwrap()));
        assert_eq!(db.first_seen("jdoe", "192.0.2.1").unwrap(), FirstSeen::NewIp);
        assert_eq!(db.first_seen("jdoe", "198.51.100.1").unwrap(), FirstSeen::NewPair);
        assert_eq!(db.first_seen("mallory", "203.0.113.10").unwrap(), FirstSeen::NewUser, "failed logons do not count");
    }

    #[test]
    fn session_start_lookup() {
        let mut db = Db::memory();
        let t = Utc::now() - Duration::hours(2);
        db.record_connection(&conn("jdoe", t), "PC01", "k", false, "n/a", None, 10).unwrap(); // session 2
        let mut later = conn("jdoe", t + Duration::minutes(30));
        later.session_id = Some(5);
        later.ip = "198.51.100.1".into();
        later.refs[0].record_id = 78;
        db.record_connection(&later, "PC01", "k", false, "n/a", None, 10).unwrap();
        let end = t + Duration::minutes(72);
        let by_session = db.session_start("JDOE", Some(2), "", end).unwrap().unwrap();
        assert_eq!((by_session.0, by_session.1.as_str()), (parse_ts(&ts(t)).unwrap(), "203.0.113.10"));
        let by_ip = db.session_start("jdoe", None, "198.51.100.1", end).unwrap().unwrap();
        assert_eq!(by_ip.0, parse_ts(&ts(t + Duration::minutes(30))).unwrap());
        assert_eq!(db.session_start("jdoe", Some(9), "", end).unwrap(), None, "no matching start");
        assert_eq!(db.session_start("jdoe", Some(2), "", t - Duration::minutes(1)).unwrap(), None, "start must be before the end");
    }

    #[test]
    fn outbox_retry_send_fail_and_limits() {
        let mut db = Db::memory();
        let now = Utc::now();
        assert!(!db.enqueue("report", "r1", &msg(), 3).unwrap());
        assert!(!db.enqueue("report", "r1", &msg(), 3).unwrap(), "duplicate dedupe key ignored");
        assert_eq!(db.outbox_counts().unwrap().0, 1);
        let items = db.due_items(now + Duration::seconds(1), 10).unwrap();
        assert_eq!(items.len(), 1);
        db.mark_retry(&items[0], now + Duration::minutes(5), "connection refused").unwrap();
        assert!(db.due_items(now + Duration::seconds(1), 10).unwrap().is_empty());
        assert!(db.next_due().unwrap().unwrap() > now);
        db.retry_pending_now().unwrap();
        let items = db.due_items(Utc::now() + Duration::seconds(1), 10).unwrap();
        assert_eq!(items[0].attempts, 1);
        db.mark_failed(&items[0], "gave up").unwrap();
        assert_eq!(db.outbox_counts().unwrap(), (0, 1));
        for i in 0..3 {
            db.enqueue("report", &format!("x{i}"), &msg(), 3).unwrap();
        }
        assert!(db.enqueue("report", "x3", &msg(), 3).unwrap(), "oldest dropped when full");
        assert_eq!(db.outbox_counts().unwrap().0, 3);
    }

    #[test]
    fn queue_survives_reopen() {
        let dir = std::env::temp_dir().join(format!("rdpmon-test-{}", rdpmon_core::crypto::random_hex(6)));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("history.db");
        {
            let mut db = Db::open(&path).unwrap();
            db.enqueue("alert", "k", &msg(), 10).unwrap();
            db.set_bookmark("Security", "<BookmarkList/>").unwrap();
        }
        let db = Db::open(&path).unwrap();
        assert_eq!(db.outbox_counts().unwrap().0, 1);
        assert_eq!(db.bookmark("Security").unwrap().as_deref(), Some("<BookmarkList/>"));
        drop(db);
        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn retention_cleanup() {
        let mut db = Db::memory();
        let old = Utc::now() - Duration::days(400);
        db.record_connection(&conn("old", old), "PC", "k1", false, "n/a", None, 10).unwrap();
        db.record_connection(&conn("new", Utc::now()), "PC", "k2", false, "n/a", None, 10).unwrap();
        db.audit("admin", "x", "y").unwrap();
        db.cleanup(&RetentionConfig::default(), Utc::now()).unwrap();
        let h = db.recent_history(10).unwrap();
        assert_eq!(h.len(), 1);
        assert_eq!(h[0].user, "new");
        assert_eq!(db.recent_audit(10).unwrap().len(), 1);
    }
}
