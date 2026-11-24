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
pub const KV_UPDATE_PENDING: &str = "update_pending_version";

/// Exponential backoff: 1, 2, 4 … minutes, capped at one hour.
pub fn backoff(attempts: u32) -> Duration {
    Duration::minutes(1i64 << attempts.min(6)).min(Duration::hours(1))
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
    let mut failing = false;

    while !shared.stopping() {
        let cfg = shared.cfg();
        let now = Utc::now();

        run_weekly_report(&shared, &mut db, &cfg);

        if now >= next_cleanup {
            if let Err(e) = db.cleanup(&cfg.retention, now) {
                logging::warn(&format!("retention clean-up failed: {e}"));
            }
            next_cleanup = now + Duration::hours(24);
        }

        if cfg.smtp.is_configured() && !deliver_due(&shared, &db, &cfg, &mut failing) {
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
        let wait = (next - Utc::now()).to_std().unwrap_or_default().max(std::time::Duration::from_millis(500));
        shared.wait_delivery(wait.min(std::time::Duration::from_secs(6 * 3600)));
    }
    logging::info("delivery worker stopped");
}

/// Returns false if the queue state could not be written to the database.
fn deliver_due(shared: &Shared, db: &Db, cfg: &Config, failing: &mut bool) -> bool {
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
        let to = (item.kind == "report").then_some(cfg.report.recipients.as_slice());
        let msg = crate::db::Message { subject: item.subject.clone(), text: item.body_text.clone(), html: item.body_html.clone() };
        match mail::send_classified(&cfg.smtp, to, &msg) {
            Ok(()) => {
                if let Err(e) = db.mark_sent(&item) {
                    logging::error(&format!("notification #{} was sent but cannot be marked as sent: {e}", item.id));
                    return false;
                }
                logging::info(&format!("{} notification #{} delivered", item.kind, item.id));
                if *failing {
                    *failing = false;
                    shared.set_error(None);
                    let _ = db.audit("delivery", "email delivery restored", &format!("SMTP server {} is accepting messages again", cfg.smtp.host));
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
                return handle_failure(shared, db, cfg, &item, &e.message, failing)
                    && db.defer_pending_until(Utc::now() + backoff(item.attempts)).is_ok();
            }
        }
    }
    true
}

fn handle_failure(shared: &Shared, db: &Db, cfg: &Config, item: &OutboxItem, err: &str, failing: &mut bool) -> bool {
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
    if !*failing {
        *failing = true;
        let _ = db.audit("delivery", "email delivery failing", err);
    }
    recorded
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
                    let m = notify::report_message(&rows, &shared.host, start, end);
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
    fn backoff_is_exponential_and_capped() {
        assert_eq!(backoff(0), Duration::minutes(1));
        assert_eq!(backoff(1), Duration::minutes(2));
        assert_eq!(backoff(3), Duration::minutes(8));
        assert_eq!(backoff(10), Duration::hours(1));
    }
}
