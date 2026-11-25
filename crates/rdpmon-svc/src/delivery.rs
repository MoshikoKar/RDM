//! The single notification delivery worker. Also runs the weekly report
//! schedule and daily retention clean-up. Sleeps on a condition variable until
//! the next due item, the next report slot, a configuration change or stop.

use crate::app::Shared;
use crate::db::{Db, OutboxItem};
use crate::{logging, mail, notify};
use chrono::{DateTime, Duration, Local, Utc};
use rdpmon_core::config::Config;
use std::sync::Arc;

const KV_REPORT_SLOT: &str = "report_last_slot";
const KV_HEARTBEAT_SLOT: &str = "heartbeat_last_slot";
pub const KV_UPDATE_PENDING: &str = "update_pending_version";

/// Exponential backoff: 1, 2, 4 … minutes, capped at one hour.
pub fn backoff(attempts: u32) -> Duration {
    Duration::minutes(1i64 << attempts.min(6)).min(Duration::hours(1))
}

/// An email delivery outage in progress.
pub struct Outage {
    since: DateTime<Utc>,
    /// Notifications that were attempted and failed during the outage.
    delayed: std::collections::BTreeSet<i64>,
    dropped_at_start: u64,
    failed_at_start: u64,
}

pub fn run(shared: Arc<Shared>) {
    let mut db = match shared.open_db() {
        Ok(d) => d,
        Err(e) => {
            logging::error(&e);
            std::process::exit(2);
        }
    };
    report_update_result(&db);
    let mut next_cleanup = Utc::now() + Duration::minutes(2);
    let mut outage: Option<Outage> = None;

    while !shared.stopping() {
        let cfg = shared.cfg();
        let now = Utc::now();

        run_weekly_report(&shared, &mut db, &cfg);
        run_heartbeat(&shared, &mut db, &cfg);

        if now >= next_cleanup {
            if let Err(e) = db.cleanup(&cfg.retention, now) {
                logging::warn(&format!("retention clean-up failed: {e}"));
            }
            next_cleanup = now + Duration::hours(24);
        }

        if cfg.smtp.is_configured() && !deliver_due(&shared, &mut db, &cfg, &mut outage) {
            // The queue state could not be recorded: wait instead of
            // resending (duplicate emails) or hammering the SMTP server.
            shared.set_error(Some("Database error while updating the notification queue; retrying in 60 s.".into()));
            shared.wait_delivery(std::time::Duration::from_secs(60));
            continue;
        }

        // Sleep until the next thing to do (or until woken).
        let mut next = next_cleanup;
        if cfg.smtp.is_configured() {
            if let Ok(Some(t)) = db.next_due() {
                next = next.min(t);
            }
        }
        if cfg.report.enabled {
            if let Some(t) = notify::next_report_slot(&cfg.report, Local::now()) {
                next = next.min(t.with_timezone(&Utc));
            }
        }
        if cfg.heartbeat.enabled {
            if let Some(t) = notify::next_daily_slot(&cfg.heartbeat.time, Local::now()) {
                next = next.min(t.with_timezone(&Utc));
            }
        }
        let wait = (next - Utc::now()).to_std().unwrap_or_default().max(std::time::Duration::from_millis(500));
        shared.wait_delivery(wait.min(std::time::Duration::from_secs(6 * 3600)));
    }
    logging::info("delivery worker stopped");
}

/// Returns false if the queue state could not be written to the database.
fn deliver_due(shared: &Shared, db: &mut Db, cfg: &Config, outage: &mut Option<Outage>) -> bool {
    let items = match db.due_items(Utc::now(), 25) {
        Ok(i) => i,
        Err(e) => {
            logging::error(&format!("cannot read notification queue: {e}"));
            return false;
        }
    };
    for item in items {
        if shared.stopping() {
            return true;
        }
        let to = match item.kind.as_str() {
            "report" => Some(cfg.report.recipients.as_slice()),
            "heartbeat" => Some(cfg.heartbeat.recipients.as_slice()),
            _ => None,
        };
        let msg = crate::db::Message { subject: item.subject.clone(), text: item.body_text.clone(), html: item.body_html.clone() };
        match mail::send_classified(&cfg.smtp, to, &msg) {
            Ok(()) => {
                if let Err(e) = db.mark_sent(&item) {
                    logging::error(&format!("notification #{} was sent but cannot be marked as sent: {e}", item.id));
                    return false;
                }
                logging::info(&format!("{} notification #{} delivered", item.kind, item.id));
                if let Some(o) = outage.take() {
                    shared.set_error(None);
                    let _ = db.audit("delivery", "email delivery restored", &format!("SMTP server {} is accepting messages again", cfg.smtp.host));
                    if cfg.heartbeat.recovery_summary {
                        queue_recovery_summary(shared, db, cfg, o, item.id);
                    }
                }
            }
            Err(e) if e.message_rejected => {
                // Retrying cannot help, and it must not delay other alerts.
                if db.mark_failed(&item, &e.message).is_err() {
                    return false;
                }
                logging::error(&format!("{} notification #{} rejected by the server: {}", item.kind, item.id, e.message));
                let _ = db.audit("delivery", "notification rejected", &format!("#{}: {}", item.id, e.message));
            }
            Err(e) => {
                // The server is most likely unavailable: postpone the rest too
                // rather than hammering it.
                return handle_failure(shared, db, cfg, &item, &e.message, outage)
                    && db.defer_pending_until(Utc::now() + backoff(item.attempts)).is_ok();
            }
        }
    }
    true
}

fn handle_failure(shared: &Shared, db: &Db, cfg: &Config, item: &OutboxItem, err: &str, outage: &mut Option<Outage>) -> bool {
    let give_up_at = item.created_at + Duration::hours(cfg.notifications.retry_hours as i64);
    let recorded = if Utc::now() >= give_up_at {
        logging::error(&format!("{} notification #{} failed permanently: {err}", item.kind, item.id));
        let _ = db.audit("delivery", "notification failed", &format!("#{} gave up after {} attempts: {err}", item.id, item.attempts + 1));
        db.mark_failed(item, err).is_ok()
    } else {
        let next = Utc::now() + backoff(item.attempts);
        logging::warn(&format!("{} notification #{} not delivered (attempt {}): {err}; retry at {}", item.kind, item.id, item.attempts + 1, notify::local(next)));
        db.mark_retry(item, next, err).is_ok()
    };
    shared.set_error(Some(format!("Email delivery failing: {err}")));
    let o = outage.get_or_insert_with(|| {
        let _ = db.audit("delivery", "email delivery failing", err);
        Outage {
            since: Utc::now(),
            delayed: Default::default(),
            dropped_at_start: db.status_count("dropped").unwrap_or(0),
            failed_at_start: db.status_count("failed").unwrap_or(0),
        }
    });
    o.delayed.insert(item.id);
    recorded
}

/// Everything still waiting when delivery recovers was delayed too (other
/// items are deferred without an attempt while the server is down).
fn queue_recovery_summary(shared: &Shared, db: &mut Db, cfg: &Config, mut o: Outage, sent_id: i64) {
    o.delayed.insert(sent_id);
    o.delayed.extend(db.pending_ids().unwrap_or_default());
    let dropped = db.status_count("dropped").unwrap_or(0).saturating_sub(o.dropped_at_start);
    let failed = db.status_count("failed").unwrap_or(0).saturating_sub(o.failed_at_start);
    let m = notify::recovery_message(&shared.host, o.since, Utc::now(), o.delayed.len(), dropped, failed);
    match db.enqueue("notice", &format!("recovery:{}", crate::db::ts(o.since)), &m, cfg.notifications.max_queue) {
        Ok(_) => logging::info("email delivery recovery summary queued"),
        Err(e) => logging::error(&format!("cannot queue delivery recovery summary: {e}")),
    }
}

/// Daily heartbeat, with the same "not right after installation" rule as
/// the weekly report.
fn run_heartbeat(shared: &Shared, db: &mut Db, cfg: &Config) {
    let now = Local::now();
    let Some(slot) = notify::last_daily_slot(&cfg.heartbeat.time, now) else { return };
    let slot_s = slot.to_rfc3339();
    let last: Option<DateTime<chrono::FixedOffset>> = db.kv(KV_HEARTBEAT_SLOT).ok().flatten().and_then(|s| DateTime::parse_from_rfc3339(&s).ok());
    match last {
        None => {
            let _ = db.set_kv(KV_HEARTBEAT_SLOT, &slot_s);
        }
        Some(l) if slot.fixed_offset() > l => {
            let _ = db.set_kv(KV_HEARTBEAT_SLOT, &slot_s);
            if !cfg.heartbeat.enabled || !cfg.smtp.is_configured() {
                return;
            }
            let now = Utc::now();
            let info = notify::HeartbeatInfo {
                host: shared.host.clone(),
                uptime: now - shared.started,
                channels: shared.channels.lock().unwrap_or_else(|e| e.into_inner()).clone(),
                connections_24h: db.connections_between(now - Duration::hours(24), now).map(|r| r.len()).unwrap_or(0),
                pending: db.outbox_counts().map(|c| c.0).unwrap_or(0),
                oldest_pending: db.oldest_pending().ok().flatten(),
                last_error: shared.last_error.lock().unwrap_or_else(|e| e.into_inner()).clone(),
                now,
            };
            let m = notify::heartbeat_message(&info);
            match db.enqueue("heartbeat", &format!("heartbeat:{slot_s}"), &m, cfg.notifications.max_queue) {
                Ok(_) => logging::info("heartbeat queued"),
                Err(e) => logging::error(&format!("cannot queue heartbeat: {e}")),
            }
        }
        _ => {}
    }
}

fn run_weekly_report(shared: &Shared, db: &mut Db, cfg: &Config) {
    let now = Local::now();
    let Some(slot) = notify::last_report_slot(&cfg.report, now) else { return };
    let slot_s = slot.to_rfc3339();
    let last: Option<DateTime<chrono::FixedOffset>> = db.kv(KV_REPORT_SLOT).ok().flatten().and_then(|s| DateTime::parse_from_rfc3339(&s).ok());
    match last {
        // First start: do not send a report immediately after installation.
        None => {
            let _ = db.set_kv(KV_REPORT_SLOT, &slot_s);
        }
        Some(l) if slot.fixed_offset() > l => {
            let _ = db.set_kv(KV_REPORT_SLOT, &slot_s);
            if !cfg.report.enabled || !cfg.smtp.is_configured() {
                return;
            }
            let end = slot.with_timezone(&Utc);
            let start = end - Duration::days(cfg.report.period_days as i64);
            match db.connections_between(start, end) {
                Ok(rows) => {
                    let extra = notify::ReportExtra {
                        failed: db.failed_between(start, end).unwrap_or_default(),
                        shares: db.shares_between(start, end).unwrap_or_default(),
                    };
                    let m = notify::report_message(&rows, &extra, &shared.host, start, end);
                    match db.enqueue("report", &format!("report:{slot_s}"), &m, cfg.notifications.max_queue) {
                        Ok(_) => logging::info(&format!("weekly report queued ({} connections)", rows.len())),
                        Err(e) => logging::error(&format!("cannot queue weekly report: {e}")),
                    }
                }
                Err(e) => logging::error(&format!("cannot build weekly report: {e}")),
            }
        }
        _ => {}
    }
}

/// After an application update the new service records whether it worked.
fn report_update_result(db: &Db) {
    if let Ok(Some(v)) = db.kv(KV_UPDATE_PENDING) {
        if v == rdpmon_core::VERSION {
            let _ = db.audit("update", "update installed", &format!("now running version {v}"));
        } else {
            let _ = db.audit(
                "update",
                "update not installed",
                &format!("expected {v}, still running {}; see updates\\install-{v}.log", rdpmon_core::VERSION),
            );
        }
        let _ = db.delete_kv(KV_UPDATE_PENDING);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn recovery_summary_after_smtp_outage() {
        let dir = std::env::temp_dir().join(format!("rdpmon-test-{}", rdpmon_core::crypto::random_hex(6)));
        std::fs::create_dir_all(&dir).unwrap();
        let mut cfg = Config::default();
        cfg.smtp.host = "127.0.0.1".into();
        cfg.smtp.from = "rdp@example.com".into();
        cfg.smtp.to = vec!["it@example.com".into()];
        cfg.smtp.timeout_seconds = 5;
        cfg.heartbeat.recovery_summary = true;
        let closed = std::net::TcpListener::bind("127.0.0.1:0").unwrap().local_addr().unwrap().port();
        cfg.smtp.port = closed;
        let shared = Shared::new(dir.clone(), cfg.clone()).unwrap();
        let mut db = Db::memory();
        let msg = |s: &str| crate::db::Message { subject: s.into(), text: "t".into(), html: "h".into() };
        db.enqueue("alert", "a1", &msg("first alert"), 100).unwrap();
        db.enqueue("alert", "a2", &msg("second alert"), 100).unwrap();
        let mut outage = None;
        assert!(deliver_due(&shared, &mut db, &cfg, &mut outage));
        assert!(outage.is_some(), "outage detected");
        assert_eq!(db.outbox_counts().unwrap().0, 2, "both still pending");

        // The server is back.
        db.retry_pending_now().unwrap();
        let f1 = crate::mail::fake::start("235 ok\r\n", "250 ok\r\n");
        cfg.smtp.port = f1.port;
        let items = db.due_items(Utc::now() + Duration::seconds(1), 1).unwrap();
        assert_eq!(items.len(), 1);
        // Deliver exactly one item so the single-connection fake suffices.
        assert!(deliver_one(&shared, &mut db, &cfg, &mut outage));
        assert!(f1.transcript.recv().unwrap().contains("Subject: first alert"));
        assert!(outage.is_none(), "outage over");
        let pending = db.due_items(Utc::now() + Duration::seconds(1), 10).unwrap();
        let summary = pending.iter().find(|i| i.kind == "notice").expect("summary queued");
        assert!(summary.body_text.contains("Delayed notifications: 2"), "{}", summary.body_text);

        // Without the option no summary is queued.
        let mut off = cfg.clone();
        off.heartbeat.recovery_summary = false;
        let mut o = Some(Outage { since: Utc::now(), delayed: Default::default(), dropped_at_start: 0, failed_at_start: 0 });
        let f2 = crate::mail::fake::start("235 ok\r\n", "250 ok\r\n");
        off.smtp.port = f2.port;
        let before = db.outbox_counts().unwrap().0;
        assert!(deliver_one(&shared, &mut db, &off, &mut o));
        let _ = f2.transcript.recv();
        assert_eq!(db.outbox_counts().unwrap().0, before - 1, "one sent, nothing new queued");
        drop(shared);
        let _ = std::fs::remove_dir_all(dir);
    }

    /// deliver_due limited to the single oldest due item.
    fn deliver_one(shared: &Shared, db: &mut Db, cfg: &Config, outage: &mut Option<Outage>) -> bool {
        let keep: Vec<i64> = db.due_items(Utc::now() + Duration::seconds(1), 100).unwrap().iter().skip(1).map(|i| i.id).collect();
        for id in &keep {
            db.conn.execute("UPDATE outbox SET next_attempt_at='9999-01-01T00:00:00.000Z' WHERE id=?1", [id]).unwrap();
        }
        let ok = deliver_due(shared, db, cfg, outage);
        for id in &keep {
            db.conn.execute("UPDATE outbox SET next_attempt_at=?2 WHERE id=?1 AND status='pending'", rusqlite::params![id, crate::db::ts(Utc::now())]).unwrap();
        }
        ok
    }

    #[test]
    fn backoff_is_exponential_and_capped() {
        assert_eq!(backoff(0), Duration::minutes(1));
        assert_eq!(backoff(1), Duration::minutes(2));
        assert_eq!(backoff(3), Duration::minutes(8));
        assert_eq!(backoff(10), Duration::hours(1));
    }
}
