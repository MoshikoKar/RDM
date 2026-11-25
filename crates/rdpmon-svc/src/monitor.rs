//! Event monitor thread: event-log subscriptions → correlation → history,
//! cooldown and notification queue. Blocks in WaitForMultipleObjects; wakes
//! only for new events, configuration changes, correlation deadlines,
//! re-subscription retries and a 5-minute subscription health check.

use crate::app::Shared;
use crate::correlate::{Connection, Correlator};
use crate::db::Db;
use crate::events::{self, Skip, CH_LSM, CH_RCM, CH_SECURITY};
use crate::evt::{query_xml, Subscription};
use crate::notify;
use crate::winsec::{wait_any, Event};
use crate::logging;
use rdpmon_core::config::MonitoringConfig;
use rdpmon_core::ipc::ChannelStatus;
use std::sync::atomic::Ordering;
use std::sync::Arc;
use std::time::{Duration, Instant};

const HEALTH_INTERVAL: Duration = Duration::from_secs(300);
const RETRY_INTERVAL: Duration = Duration::from_secs(60);

// Field order matters: the subscription is closed before its signal event.
struct Channel {
    name: &'static str,
    sub: Option<Subscription>,
    signal: Event,
    mon: MonitoringConfig,
    retry_at: Option<Instant>,
    status: ChannelStatus,
}

fn max_age_ms(m: &MonitoringConfig) -> u64 {
    (m.recovery_max_hours.max(1) as u64) * 3_600_000
}

/// XPath selections per channel. The LogonType filter runs inside the event
/// log service, so the agent never renders the (very frequent) non-RDP logons.
pub fn channel_queries(m: &MonitoringConfig) -> Vec<(&'static str, Vec<String>)> {
    channel_queries_aged(m, max_age_ms(m))
}

fn channel_queries_aged(m: &MonitoringConfig, age_ms: u64) -> Vec<(&'static str, Vec<String>)> {
    let age = format!("TimeCreated[timediff(@SystemTime) &lt;= {age_ms}]");
    let mut v = Vec::new();
    if m.security_log {
        v.push((CH_SECURITY, vec![
            format!("*[System[(EventID=4624) and {age}]] and *[EventData[Data[@Name='LogonType']='10']]"),
            format!("*[System[(EventID=4778 or EventID=4779) and {age}]]"),
        ]));
    }
    if m.session_manager_log {
        v.push((CH_LSM, vec![format!("*[System[(EventID=21 or EventID=24 or EventID=25) and {age}]]")]));
    }
    if m.auth_log {
        v.push((CH_RCM, vec![format!("*[System[(EventID=1149) and {age}]]")]));
    }
    v
}

fn build_channels(m: &MonitoringConfig) -> Vec<Channel> {
    channel_queries(m)
        .into_iter()
        .map(|(name, _)| Channel {
            name,
            mon: m.clone(),
            signal: Event::new(true).expect("create event"),
            sub: None,
            retry_at: Some(Instant::now()),
            status: ChannelStatus { name: name.into(), state: "starting".into(), detail: String::new() },
        })
        .collect()
}

pub fn run(shared: Arc<Shared>) {
    let mut db = match shared.open_db() {
        Ok(d) => d,
        Err(e) => {
            logging::error(&e);
            shared.set_error(Some(e));
            // Without a database nothing can be recorded; let SCM recovery restart us.
            std::process::exit(2);
        }
    };
    let mut cfg = shared.cfg();
    let mut corr = Correlator::new(cfg.monitoring.correlation_window_seconds, &shared.host);
    let mut channels = build_channels(&cfg.monitoring);
    let mut next_health = Instant::now() + HEALTH_INTERVAL;

    loop {
        // (Re)open subscriptions that are due, draining any recovered backlog.
        let now = Instant::now();
        let mut opened_any = false;
        for ch in channels.iter_mut().filter(|c| c.sub.is_none() && c.retry_at.is_some_and(|t| t <= now)) {
            open_channel(ch, &db);
            opened_any |= ch.sub.is_some();
        }
        if opened_any {
            // Backlog from every channel has been read: correlate it completely.
            drain_all(&shared, &mut db, &mut corr, &mut channels);
            for c in corr.flush_all(Instant::now()) {
                handle_connection(&shared, &mut db, &cfg, &c);
            }
        }
        publish_status(&shared, &channels);

        // Finalize settled connections; persist bookmarks only when nothing
        // is pending so a restart can never skip an unprocessed event.
        for c in corr.flush_due(Instant::now()) {
            handle_connection(&shared, &mut db, &cfg, &c);
        }
        if corr.is_idle() {
            for ch in channels.iter_mut() {
                if let Some(bm) = ch.sub.as_mut().and_then(|s| s.take_bookmark()) {
                    if let Err(e) = db.set_bookmark(ch.name, &bm) {
                        logging::warn(&format!("could not save bookmark for {}: {e}", ch.name));
                    }
                }
            }
        }

        // Wait.
        let mut deadline = next_health;
        if let Some(d) = corr.next_deadline() {
            deadline = deadline.min(d);
        }
        for t in channels.iter().filter(|c| c.sub.is_none()).filter_map(|c| c.retry_at) {
            deadline = deadline.min(t);
        }
        let timeout = deadline.saturating_duration_since(Instant::now()).as_millis().min(u32::MAX as u128 - 1) as u32;
        let mut handles = vec![shared.stop.0, shared.config_changed.0];
        handles.extend(channels.iter().map(|c| c.signal.0));
        let which = wait_any(&handles, timeout);

        match which {
            Some(0) => {
                for c in corr.flush_all(Instant::now()) {
                    handle_connection(&shared, &mut db, &cfg, &c);
                }
                for ch in channels.iter_mut() {
                    if let Some(bm) = ch.sub.as_mut().and_then(|s| s.take_bookmark()) {
                        let _ = db.set_bookmark(ch.name, &bm);
                    }
                }
                logging::info("monitor stopped");
                return;
            }
            Some(1) => {
                let new = shared.cfg();
                corr.set_window(new.monitoring.correlation_window_seconds);
                if shared.resubscribe.swap(false, Ordering::SeqCst) {
                    // Drain and settle what we have, then re-create subscriptions.
                    drain_all(&shared, &mut db, &mut corr, &mut channels);
                    for c in corr.flush_all(Instant::now()) {
                        handle_connection(&shared, &mut db, &new, &c);
                    }
                    for ch in channels.iter_mut() {
                        if let Some(bm) = ch.sub.as_mut().and_then(|s| s.take_bookmark()) {
                            let _ = db.set_bookmark(ch.name, &bm);
                        }
                    }
                    channels = build_channels(&new.monitoring);
                    logging::info("event subscriptions re-created after configuration change");
                }
                cfg = new;
            }
            Some(i) => {
                let ch = &mut channels[i - 2];
                ch.signal.reset();
                drain_channel(&shared, &mut db, &mut corr, ch);
            }
            None => {
                if Instant::now() >= next_health {
                    // Health check: EvtNext on a broken subscription returns an
                    // error (e.g. Event Log service restarted) → re-subscribe.
                    drain_all(&shared, &mut db, &mut corr, &mut channels);
                    next_health = Instant::now() + HEALTH_INTERVAL;
                }
            }
        }
    }
}

fn open_channel(ch: &mut Channel, db: &Db) {
    let bookmark = db.bookmark(ch.name).ok().flatten();
    // A bookmark only exists after the first matching event. Until then,
    // recover from the time the channel was first monitored, so events during
    // a restart or upgrade are not lost (duplicates are filtered later).
    let since_key = format!("monitored_since:{}", ch.name);
    let since = db.kv(&since_key).ok().flatten().and_then(|s| crate::db::parse_ts(&s));
    let mut age = max_age_ms(&ch.mon);
    let from_oldest = bookmark.is_none() && since.is_some();
    if let (true, Some(t)) = (from_oldest, since) {
        age = age.min((chrono::Utc::now() - t).num_milliseconds().max(0) as u64 + 600_000);
    }
    let selects = channel_queries_aged(&ch.mon, age).into_iter().find(|(n, _)| *n == ch.name).map(|x| x.1).unwrap_or_default();
    let q = query_xml(ch.name, &selects);
    match Subscription::open_with(&q, bookmark.as_deref(), from_oldest, ch.signal.0) {
        Ok(s) => {
            ch.sub = Some(s);
            ch.retry_at = None;
            ch.status.state = "active".into();
            ch.status.detail = if bookmark.is_some() {
                "resumed from bookmark".into()
            } else if from_oldest {
                "recovering since last start".into()
            } else {
                let _ = db.set_kv(&since_key, &crate::db::ts(chrono::Utc::now()));
                "started (new events only)".into()
            };
            ch.signal.set(); // drain immediately
            logging::info(&format!("subscribed to {} ({})", ch.name, ch.status.detail));
        }
        Err(e) => {
            ch.retry_at = Some(Instant::now() + RETRY_INTERVAL);
            ch.status.state = "error".into();
            ch.status.detail = describe_open_error(&e);
            logging::warn(&format!("cannot subscribe to {}: {} - retrying in 60 s", ch.name, ch.status.detail));
        }
    }
}

fn describe_open_error(e: &std::io::Error) -> String {
    match e.raw_os_error() {
        Some(5) => "access denied (the service must run as LocalSystem)".into(),
        Some(15007) => "event log channel not found on this system".into(),
        Some(15025) | Some(15021) => "event log channel is disabled".into(),
        _ => e.to_string(),
    }
}

fn drain_all(shared: &Shared, db: &mut Db, corr: &mut Correlator, channels: &mut [Channel]) {
    for ch in channels.iter_mut() {
        drain_channel(shared, db, corr, ch);
    }
}

fn drain_channel(shared: &Shared, db: &mut Db, corr: &mut Correlator, ch: &mut Channel) {
    let ignore_loopback = shared.cfg().monitoring.ignore_loopback;
    loop {
        let Some(sub) = ch.sub.as_mut() else { return };
        match sub.drain(256) {
            Ok(batch) => {
                let n = batch.len();
                for xml in batch {
                    match events::parse(&xml, ignore_loopback) {
                        Ok(o) => {
                            if db.is_processed(&o.channel, o.record_id, o.time).unwrap_or(false) {
                                continue;
                            }
                            corr.push(o, Instant::now());
                        }
                        Err(Skip::Irrelevant) => {}
                        Err(Skip::Malformed(e)) => logging::warn(&format!("unparseable event on {}: {e}", ch.name)),
                    }
                }
                if n < 256 {
                    return;
                }
            }
            Err(e) => {
                // Reopen from the last persisted bookmark; records read again
                // are de-duplicated by the correlator and processed_events.
                ch.sub = None;
                ch.retry_at = Some(Instant::now() + Duration::from_secs(5));
                ch.status.state = "reconnecting".into();
                ch.status.detail = format!("subscription interrupted: {e}");
                logging::warn(&format!("subscription to {} failed ({e}); re-subscribing", ch.name));
                let _ = db.audit("service", "event subscription interrupted", &format!("{}: {e}", ch.name));
                return;
            }
        }
    }
}

fn publish_status(shared: &Shared, channels: &[Channel]) {
    *shared.channels.lock().unwrap_or_else(|e| e.into_inner()) = channels.iter().map(|c| c.status.clone()).collect();
}

fn handle_connection(shared: &Shared, db: &mut Db, cfg: &rdpmon_core::config::Config, c: &Connection) {
    // Connections that happened while the service was not running.
    let recovered = c.time < shared.started - chrono::Duration::seconds(5);
    let last = db.cooldown_last(&c.key(&shared.host)).ok().flatten();
    let status = notify::decide(c, cfg, last);
    let msg = (status == notify::ST_QUEUED).then(|| {
        let source_host = crate::resolve::hostname(&c.ip, crate::resolve::TIMEOUT);
        notify::alert_message(c, &shared.host, source_host.as_deref(), cfg, recovered)
    });
    match db.record_connection(c, &shared.host, recovered, status, msg, cfg.notifications.max_queue) {
        Ok((_, dropped)) => {
            logging::info(&format!(
                "{} {}\\{} from {} (events {:?}){} - {status}",
                crate::db::kind_name(c.kind),
                c.domain,
                c.user,
                c.ip,
                c.event_ids,
                if recovered { " [recovered]" } else { "" }
            ));
            if dropped {
                let _ = db.audit("delivery", "notification dropped", "queue limit reached; oldest pending notification discarded");
            }
            if status == notify::ST_QUEUED {
                shared.wake_delivery();
            }
        }
        Err(e) => {
            // Never advance the bookmark past an unrecorded connection: exit
            // so the SCM restarts the service, which re-reads the events from
            // the last persisted bookmark.
            logging::error(&format!("failed to record connection ({e}); restarting to retry"));
            std::process::exit(3);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The production XPath queries are syntax-checked by the real event log
    /// service (using the Application channel, which needs no elevation).
    #[test]
    fn production_queries_are_accepted_by_windows() {
        for (_, selects) in channel_queries(&MonitoringConfig::default()) {
            let sig = Event::new(true).unwrap();
            Subscription::open(&query_xml("Application", &selects), None, sig.0).expect("query rejected");
        }
    }
}
