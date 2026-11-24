//! Minimal size-capped text log (`logs\service.log`, 1 MiB, one rollover).
//! Never pass secrets to these functions.

use std::io::Write;
use std::path::PathBuf;
use std::sync::Mutex;

const MAX_BYTES: u64 = 1024 * 1024;

struct State {
    path: Option<PathBuf>,
    echo: bool,
}

static STATE: Mutex<State> = Mutex::new(State { path: None, echo: false });

pub fn init(path: PathBuf, echo_to_stderr: bool) {
    if let Some(dir) = path.parent() {
        let _ = std::fs::create_dir_all(dir);
    }
    let mut s = STATE.lock().unwrap_or_else(|e| e.into_inner());
    s.path = Some(path);
    s.echo = echo_to_stderr;
}

fn write(level: &str, msg: &str) {
    let line = format!("{} {level:<5} {msg}\r\n", chrono::Local::now().format("%Y-%m-%d %H:%M:%S%.3f"));
    let s = STATE.lock().unwrap_or_else(|e| e.into_inner());
    if s.echo {
        eprint!("{line}");
    }
    let Some(path) = &s.path else { return };
    if std::fs::metadata(path).map(|m| m.len() > MAX_BYTES).unwrap_or(false) {
        let _ = std::fs::rename(path, path.with_extension("log.1"));
    }
    if let Ok(mut f) = std::fs::OpenOptions::new().create(true).append(true).open(path) {
        let _ = f.write_all(line.as_bytes());
    }
}

pub fn info(msg: &str) {
    write("INFO", msg);
}
pub fn warn(msg: &str) {
    write("WARN", msg);
}
pub fn error(msg: &str) {
    write("ERROR", msg);
}
