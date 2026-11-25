//! Event monitor thread: event-log subscriptions → correlation → history,
//! cooldown and notification queue. Blocks in WaitForMultipleObjects; wakes
//! only for new events, configuration changes, correlation deadlines,
//! re-subscription retries and a 5-minute subscription health check.

use crate::app::Shared;
use crate::correlate::{Connection, Correlator, EventRef};
use crate::db::Db;
use crate::events::{self, Observation, Signal, Skip, CH_LSM, CH_RCM, CH_SECURITY};
use crate::failed::{self, FailedTracker};
use crate::evt::{query_xml, Subscription};
use crate::notify;
use crate::winsec::{wait_any, Event};
use crate::logging;
use rdpmon_core::config::{Config, MonitoringConfig};
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
    cfg: Config,
    retry_at: Option<Instant>,
    status: ChannelStatus,
}

fn max_age_ms(m: &MonitoringConfig) -> u64 {
    (m.recovery_max_hours.max(1) as u64) * 3_600_000
}

/// XPath selections per channel. The LogonType filter runs inside the event
/// log service, so the agent never renders the (very frequent) non-RDP logons.
pub fn channel_queries(c: &Config) -> Vec<(&'static str, Vec<String>)> {
    channel_queries_aged(c, max_age_ms(&c.monitoring))
}

fn channel_queries_aged(c: &Config, age_ms: u64) -> Vec<(&'static str, Vec<String>)> {
    let m = &c.monitoring;
    let age = format!("TimeCreated[timediff(@SystemTime) &lt;= {age_ms}]");
    let mut v = Vec::new();
    let mut security = Vec::new();
    if m.security_log {
        security.push(format!("*[System[(EventID=4624) and {age}]] and *[EventData[Data[@Name='LogonType']='10']]"));
        security.push(format!("*[System[(EventID=4778 or EventID=4779) and {age}]]"));
    }
    if c.failed_logons_active() {
        // With NLA a failed RDP password is LogonType 3, not 10.
        security.push(format!(
            "*[System[(EventID=4625) and {age}]] and *[EventData[Data[@Name='LogonType']='3' or Data[@Name='LogonType']='10']]"
        ));
    }
    if c.smb.enabled {
        // Audit Failure keyword (0x10000000000000): the event log service
        // drops 5145 successes (one per file opened) before they reach us.
        let failure = "band(Keywords,4503599627370496)";
        if c.smb.notify_success {
            security.push(format!("*[System[(EventID=5140) and {age}]]"));
        } else {
            security.push(format!("*[System[(EventID=5140) and {failure} and {age}]]"));
        }
        if c.smb.notify_failed {
            security.push(format!("*[System[(EventID=5145) and {failure} and {age}]]"));
        }
    }
    if !security.is_empty() {
        v.push((CH_SECURITY, security));
    }
    if m.session_manager_log {
        v.push((CH_LSM, vec![format!("*[System[(EventID=21 or EventID=24 or EventID=25) and {age}]]")]));
    }
    if m.auth_log {
        v.push((CH_RCM, vec![format!("*[System[(EventID=1149) and {age}]]")]));
    }
    v
}

fn build_channels(c: &Config) -> Vec<Channel> {
    channel_queries(c)
        .into_iter()
        .map(|(name, _)| Channel {
            name,
            cfg: c.clone(),
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
    let mut failed = FailedTracker::default();
    let mut channels = build_channels(&cfg);
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
            drain_all(&shared, &mut db, &mut corr, &mut failed, &mut channels);
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
                    drain_all(&shared, &mut db, &mut corr, &mut failed, &mut channels);
                    for c in corr.flush_all(Instant::now()) {
                        handle_connection(&shared, &mut db, &new, &c);
                    }
                    for ch in channels.iter_mut() {
                        if let Some(bm) = ch.sub.as_mut().and_then(|s| s.take_bookmark()) {
                            let _ = db.set_bookmark(ch.name, &bm);
                        }
                    }
                    channels = build_channels(&new);
                    logging::info("event subscriptions re-created after configuration change");
                }
                cfg = new;
            }
            Some(i) => {
                let ch = &mut channels[i - 2];
                ch.signal.reset();
                drain_channel(&shared, &mut db, &mut corr, &mut failed, ch);
            }
            None => {
                if Instant::now() >= next_health {
                    // Health check: EvtNext on a broken subscription returns an
                    // error (e.g. Event Log service restarted) → re-subscribe.
                    drain_all(&shared, &mut db, &mut corr, &mut failed, &mut channels);
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
    let mut age = max_age_ms(&ch.cfg.monitoring);
    let from_oldest = bookmark.is_none() && since.is_some();
    if let (true, Some(t)) = (from_oldest, since) {
        age = age.min((chrono::Utc::now() - t).num_milliseconds().max(0) as u64 + 600_000);
    }
    let selects = channel_queries_aged(&ch.cfg, age).into_iter().find(|(n, _)| *n == ch.name).map(|x| x.1).unwrap_or_default();
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
            if ch.name == CH_SECURITY {
                let w = crate::auditpol::warnings(&ch.cfg);
                if !w.is_empty() {
                    let w = w.join("; ");
                    logging::warn(&format!("audit policy: {w}"));
                    ch.status.detail.push_str(&format!("; WARNING: {w}"));
                }
            }
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

fn drain_all(shared: &Shared, db: &mut Db, corr: &mut Correlator, failed: &mut FailedTracker, channels: &mut [Channel]) {
    for ch in channels.iter_mut() {
        drain_channel(shared, db, corr, failed, ch);
    }
}

fn drain_channel(shared: &Shared, db: &mut Db, corr: &mut Correlator, failed: &mut FailedTracker, ch: &mut Channel) {
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
                            if o.signal == Signal::Failed {
                                handle_failed(shared, db, failed, o);
                            } else if o.signal.is_standalone() {
                                handle_share(shared, db, o);
                            } else {
                                corr.push(o, Instant::now());
                            }
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

fn handle_connection(shared: &Shared, db: &mut Db, cfg: &Config, c: &Connection) {
    // Connections that happened while the service was not running.
    let recovered = c.time < shared.started - chrono::Duration::seconds(5);
    let last = db.cooldown_last(&c.key(&shared.host)).ok().flatten();
    let status = notify::decide(c, cfg, last);
    let msg = (status == notify::ST_QUEUED).then(|| {
        let ctx = notify::AlertContext {
            source_host: crate::resolve::hostname(&c.ip, crate::resolve::TIMEOUT),
            // Before this connection is recorded.
            first_seen: db.first_seen(&c.user, &c.ip).ok().map(|f| notify::first_seen_text(&f)),
        };
        notify::alert_message(c, &shared.host, &ctx, cfg, recovered)
    });
    record(shared, db, cfg, c, &c.key(&shared.host), recovered, status, msg);
}

/// One failed logon: counted per source IP, always recorded in history,
/// emailed once the IP reaches the threshold (outside its cooldown).
fn handle_failed(shared: &Shared, db: &mut Db, tracker: &mut FailedTracker, o: Observation) {
    let cfg = shared.cfg();
    let f = &cfg.failed_logons;
    let recovered = o.time < shared.started - chrono::Duration::seconds(5);
    let user = if o.domain.is_empty() { o.user.clone() } else { format!("{}\\{}", o.domain, o.user) };
    let attempt = failed::Attempt { time: o.time, user, logon_type: o.logon_type.clone(), status: o.status.clone() };
    let key = format!("failed|{}", o.ip);
    let burst = tracker.push(&o.ip, attempt, f.window_minutes, f.threshold);
    let status = match &burst {
        None => notify::ST_BELOW,
        Some(_) => notify::decide_failed(&cfg, o.time, db.cooldown_last(&key).ok().flatten()),
    };
    let msg = burst.filter(|_| status == notify::ST_QUEUED).map(|b| {
        let source_host = crate::resolve::hostname(&b.ip, crate::resolve::TIMEOUT);
        notify::failed_message(&b, &shared.host, source_host.as_deref(), &cfg, recovered)
    });
    let c = Connection {
        kind: Signal::Failed,
        time: o.time,
        refs: vec![EventRef { channel: o.channel, record_id: o.record_id, time: o.time }],
        event_ids: vec![o.event_id],
        user: o.user,
        domain: o.domain,
        ip: o.ip,
        ..Default::default()
    };
    record(shared, db, &cfg, &c, &key, recovered, status, msg);
}

/// One share access / denied event: no correlation, one row per event,
/// emailed per account + IP + share outside the cooldown.
fn handle_share(shared: &Shared, db: &mut Db, o: Observation) {
    let cfg = shared.cfg();
    let recovered = o.time < shared.started - chrono::Duration::seconds(5);
    let c = Connection {
        kind: o.signal,
        time: o.time,
        refs: vec![EventRef { channel: o.channel, record_id: o.record_id, time: o.time }],
        event_ids: vec![o.event_id],
        user: o.user,
        domain: o.domain,
        ip: o.ip,
        share: o.share,
        path: o.path,
        ..Default::default()
    };
    let key = format!(
        "smb|{}|{}|{}|{}",
        events::normalize_domain(&c.domain, &shared.host),
        c.user.to_lowercase(),
        c.ip,
        notify::share_name(&c.share).to_lowercase()
    );
    let status = notify::decide_share(&c, &cfg, db.cooldown_last(&key).ok().flatten());
    let msg = (status == notify::ST_QUEUED).then(|| {
        let source_host = crate::resolve::hostname(&c.ip, crate::resolve::TIMEOUT);
        notify::share_message(&c, &shared.host, source_host.as_deref(), &cfg, recovered)
    });
    record(shared, db, &cfg, &c, &key, recovered, status, msg);
}

#[allow(clippy::too_many_arguments)]
fn record(shared: &Shared, db: &mut Db, cfg: &Config, c: &Connection, key: &str, recovered: bool, status: &str, msg: Option<crate::db::Message>) {
    match db.record_connection(c, &shared.host, key, recovered, status, msg, cfg.notifications.max_queue) {
        Ok((_, dropped)) => {
            // Individual failed logons below the threshold are not logged:
            // a password spray would flood the service log.
            if status != notify::ST_BELOW {
                logging::info(&format!(
                    "{} {}\\{} from {} (events {:?}){} - {status}",
                    crate::db::kind_name(c.kind),
                    c.domain,
                    c.user,
                    c.ip,
                    c.event_ids,
                    if recovered { " [recovered]" } else { "" }
                ));
            }
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
        let mut all = Config::default();
        all.failed_logons.enabled = true;
        all.smb.enabled = true;
        let mut failed_only = all.clone();
        failed_only.smb.notify_success = false;
        let selects: Vec<_> = channel_queries(&all).into_iter().chain(channel_queries(&failed_only)).collect();
        for (_, selects) in selects {
            let sig = Event::new(true).unwrap();
            Subscription::open(&query_xml("Application", &selects), None, sig.0).expect("query rejected");
        }
    }
}
