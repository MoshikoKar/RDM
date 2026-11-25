//! Service runtime: shared state and the three worker threads
//! (event monitor, notification delivery, local administration pipe).

use crate::db::Db;
use crate::store::{ConfigStore, Loaded};
use crate::winsec::Event;
use crate::{logging, winsec};
use rdpmon_core::config::Config;
use rdpmon_core::ipc::ChannelStatus;
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Condvar, Mutex, RwLock};
use std::time::Instant;

pub struct Shared {
    pub data_dir: PathBuf,
    pub host: String,
    pub config: RwLock<Config>,
    pub store: ConfigStore,
    /// Manual-reset: set once when the service is stopping.
    pub stop: Event,
    /// Auto-reset: configuration changed / resubscribe requested.
    pub config_changed: Event,
    pub resubscribe: AtomicBool,
    delivery_wake: (Mutex<bool>, Condvar),
    pub channels: Mutex<Vec<ChannelStatus>>,
    pub last_error: Mutex<Option<String>>,
    pub uninstall_authorized_until: Mutex<Option<Instant>>,
    pub auth: Mutex<crate::auth::Auth>,
    pub started: chrono::DateTime<chrono::Utc>,
    /// The protected DACL was applied to the data directory.
    pub dir_secured: AtomicBool,
}

impl Shared {
    pub fn new(data_dir: PathBuf, config: Config) -> std::io::Result<Arc<Self>> {
        Ok(Arc::new(Self {
            store: ConfigStore::new(&data_dir),
            data_dir,
            host: winsec::hostname(),
            config: RwLock::new(config),
            stop: Event::new(true)?,
            config_changed: Event::new(false)?,
            resubscribe: AtomicBool::new(false),
            delivery_wake: (Mutex::new(false), Condvar::new()),
            channels: Mutex::new(Vec::new()),
            last_error: Mutex::new(None),
            uninstall_authorized_until: Mutex::new(None),
            auth: Mutex::new(crate::auth::Auth::default()),
            started: chrono::Utc::now(),
            dir_secured: AtomicBool::new(false),
        }))
    }

    pub fn db_path(&self) -> PathBuf {
        self.data_dir.join("history.db")
    }

    pub fn open_db(&self) -> Result<Db, String> {
        Db::open(&self.db_path()).map_err(|e| format!("cannot open database: {e}"))
    }

    pub fn cfg(&self) -> Config {
        self.config.read().unwrap_or_else(|e| e.into_inner()).clone()
    }

    pub fn stopping(&self) -> bool {
        self.stop.is_set()
    }

    pub fn request_stop(&self) {
        self.stop.set();
        self.wake_delivery();
    }

    pub fn wake_delivery(&self) {
        let (m, c) = &self.delivery_wake;
        *m.lock().unwrap_or_else(|e| e.into_inner()) = true;
        c.notify_all();
    }

    /// Sleeps until woken or the timeout expires.
    pub fn wait_delivery(&self, timeout: std::time::Duration) {
        let (m, c) = &self.delivery_wake;
        let mut woken = m.lock().unwrap_or_else(|e| e.into_inner());
        if !*woken {
            woken = c.wait_timeout(woken, timeout).unwrap_or_else(|e| e.into_inner()).0;
        }
        *woken = false;
    }

    pub fn mark_initialized(&self) {
        match self.open_db().and_then(|db| db.set_kv(crate::db::KV_INITIALIZED, "1").map_err(|e| e.to_string())) {
            Ok(()) => {}
            Err(e) => logging::error(&format!("cannot record initialization marker: {e}")),
        }
    }

    /// First-run setup is possible only on a never-initialized agent.
    pub fn first_run(&self, db: &Db) -> bool {
        self.cfg().security.admin_password_hash.is_empty() && !db.initialized()
    }

    pub fn set_error(&self, e: Option<String>) {
        *self.last_error.lock().unwrap_or_else(|x| x.into_inner()) = e;
    }

    /// Persists, then activates a new configuration (caller validated it).
    pub fn apply_config(&self, new: Config) -> Result<(), String> {
        let old = self.cfg();
        self.store.save(&new)?;
        if !new.security.admin_password_hash.is_empty() {
            self.mark_initialized();
        }
        *self.config.write().unwrap_or_else(|e| e.into_inner()) = new.clone();
        if old.monitoring != new.monitoring || crate::monitor::channel_queries(&old) != crate::monitor::channel_queries(&new) {
            self.resubscribe.store(true, Ordering::SeqCst);
        }
        self.config_changed.set();
        if old.smtp != new.smtp {
            if let Ok(db) = self.open_db() {
                let _ = db.retry_pending_now();
            }
        }
        if old.security.harden_service != new.security.harden_service {
            apply_service_hardening(new.security.harden_service);
        }
        self.wake_delivery();
        Ok(())
    }
}

pub fn apply_service_hardening(hardened: bool) {
    match winsec::set_service_dacl(hardened) {
        Ok(()) => logging::info(&format!("service DACL set ({})", if hardened { "hardened" } else { "Windows default" })),
        Err(e) => logging::warn(&format!("could not set service DACL: {e}")),
    }
}

/// Loads the configuration at service start. A missing configuration is not
/// an error: monitoring and history work without email settings.
pub fn load_config(data_dir: &std::path::Path) -> (Config, Option<String>) {
    let store = ConfigStore::new(data_dir);
    match store.load() {
        Ok(Loaded::Ok(c)) => (c, None),
        Ok(Loaded::Missing) => (Config::default(), Some("No configuration found - running with defaults (no email) until the agent is configured.".into())),
        Ok(Loaded::FromBackup(c, why)) => (c, Some(format!("Configuration file unreadable ({why}); restored the previous version."))),
        Err(e) => (
            Config::default(),
            Some(format!("Configuration could not be loaded ({e}). Running with defaults; the agent must be reconfigured.")),
        ),
    }
}

/// Runs the service until `shared.stop` is signalled.
pub fn run(shared: Arc<Shared>) {
    let threads = [
        ("monitor", spawn(&shared, crate::monitor::run)),
        ("delivery", spawn(&shared, crate::delivery::run)),
        ("admin-pipe", spawn(&shared, crate::ipc_server::run)),
    ];
    winsec::wait_any(&[shared.stop.0], u32::MAX);
    for (name, t) in threads {
        if t.join().is_err() {
            logging::error(&format!("{name} thread panicked"));
        }
    }
}

fn spawn(shared: &Arc<Shared>, f: fn(Arc<Shared>)) -> std::thread::JoinHandle<()> {
    let s = shared.clone();
    std::thread::Builder::new().stack_size(1024 * 1024).spawn(move || f(s)).expect("spawn worker thread")
}
