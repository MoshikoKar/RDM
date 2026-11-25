//! Application updates from GitHub / GitLab Releases: checked once a day (and
//! installed when `auto_install` is on) or when an administrator clicks
//! Check / Install.
//!
//! Trust comes from an Ed25519 signature (`.msi.sig`) verified with the
//! update signing key (the built-in key of the official releases unless
//! another is configured) - not from the hosting provider, TLS or a checksum
//! published next to the file.

use crate::app::Shared;
use chrono::Local;
use std::sync::Arc;
use crate::db::Db;
use crate::delivery::KV_UPDATE_PENDING;
use crate::{logging, winhttp};
use rdpmon_core::config::{repo_host_and_path, Config, UpdateConfig, UpdateProvider};
use rdpmon_core::ipc::UpdateInfo;
use rdpmon_core::release::{self, SigFile};
use semver::Version;
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::io::Write;

const MAX_MSI_BYTES: u64 = 512 * 1024 * 1024;
const MAX_API_BYTES: u64 = 8 * 1024 * 1024;

#[derive(Debug, Clone)]
pub struct Asset {
    pub name: String,
    pub url: String,
}

#[derive(Debug, Clone)]
pub struct Release {
    pub version: Version,
    pub name: String,
    pub notes: String,
    pub published: String,
    pub prerelease: bool,
    pub draft: bool,
    pub assets: Vec<Asset>,
}

pub fn msi_name(v: &Version) -> String {
    format!("RDPMonitor-{v}-x64.msi")
}

impl Release {
    fn asset(&self, name: &str) -> Option<&Asset> {
        self.assets.iter().find(|a| a.name == name)
    }
    fn installable(&self) -> bool {
        let m = msi_name(&self.version);
        self.asset(&m).is_some() && self.asset(&format!("{m}.sig")).is_some()
    }
}

struct Source {
    list_url: String,
    /// Host that may receive the access token; never forwarded elsewhere.
    auth_host: String,
    auth: Option<(&'static str, String)>,
    accept_list: &'static str,
    accept_asset: &'static str,
    gitlab_host: Option<String>,
}

fn source(u: &UpdateConfig) -> Result<Source, String> {
    if u.provider == UpdateProvider::None {
        return Err("No update source is configured. Set it in the Updates section.".into());
    }
    let (host, path) = repo_host_and_path(&u.repository_url).ok_or("The update repository URL is not valid.")?;
    let token = u.token.trim();
    match u.provider {
        UpdateProvider::None => unreachable!(),
        UpdateProvider::Github => {
            let mut parts = path.split('/');
            let (Some(owner), Some(repo), None) = (parts.next(), parts.next(), parts.next()) else {
                return Err("GitHub repository URL must be https://github.com/<owner>/<repository>.".into());
            };
            let api = if host == "github.com" { "api.github.com".to_string() } else { host.clone() };
            let base = if host == "github.com" { format!("https://{api}") } else { format!("https://{api}/api/v3") };
            Ok(Source {
                list_url: format!("{base}/repos/{owner}/{repo}/releases?per_page=30"),
                auth_host: with_port(&api),
                auth: (!token.is_empty()).then(|| ("Authorization", format!("Bearer {token}"))),
                accept_list: "application/vnd.github+json",
                accept_asset: "application/octet-stream",
                gitlab_host: None,
            })
        }
        UpdateProvider::Gitlab => {
            let enc: String = path.bytes().map(|b| if b.is_ascii_alphanumeric() || b"-_.".contains(&b) { (b as char).to_string() } else { format!("%{b:02X}") }).collect();
            Ok(Source {
                list_url: format!("https://{host}/api/v4/projects/{enc}/releases?per_page=30&order_by=released_at&sort=desc"),
                auth_host: with_port(&host),
                auth: (!token.is_empty()).then(|| ("PRIVATE-TOKEN", token.to_string())),
                accept_list: "application/json",
                accept_asset: "application/octet-stream",
                gitlab_host: Some(host),
            })
        }
    }
}

/// GET with manual redirect handling: HTTPS only, at most 5 hops, and the
/// access token is sent only to the configured repository host.
fn fetch(src: &Source, url: &str, accept: &str, max: u64, mut sink: Option<&mut dyn Write>) -> Result<Vec<u8>, String> {
    let mut url = url.to_string();
    for _ in 0..6 {
        let (host, port, _) = winhttp::split_url(&url)?;
        let mut headers = vec![("Accept", accept.to_string())];
        if format!("{host}:{port}") == src.auth_host {
            if let Some((k, v)) = &src.auth {
                headers.push((k, v.clone()));
            }
            if src.gitlab_host.is_none() {
                headers.push(("X-GitHub-Api-Version", "2022-11-28".into()));
            }
        }
        let r = winhttp::get(&url, &headers, max, sink.as_mut().map(|s| &mut **s as &mut dyn Write))?;
        match r.status {
            200..=299 => return Ok(r.body),
            301 | 302 | 303 | 307 | 308 => {
                let loc = r.location.ok_or("redirect without a Location header")?;
                url = if loc.starts_with("https://") {
                    loc
                } else if loc.starts_with('/') {
                    format!("https://{host}{}{loc}", if port == 443 { String::new() } else { format!(":{port}") })
                } else {
                    return Err(format!("refusing insecure or unsupported redirect to '{loc}'"));
                };
            }
            401 | 403 => return Err(format!("Access denied by {host} (HTTP {}). Check the access token and its permissions.", r.status)),
            404 => return Err(format!("Not found on {host} (HTTP 404). Check the repository URL, or provide a token for a private repository.")),
            s => return Err(format!("{host} returned HTTP {s}.")),
        }
    }
    Err("too many redirects".into())
}

pub fn parse_github(json: &[u8]) -> Result<Vec<Release>, String> {
    let v: Value = serde_json::from_slice(json).map_err(|_| "Unexpected response from GitHub.".to_string())?;
    let arr = v.as_array().ok_or("Unexpected response from GitHub.")?;
    Ok(arr
        .iter()
        .filter_map(|r| {
            let tag = r["tag_name"].as_str()?;
            Some(Release {
                version: Version::parse(tag.trim_start_matches(['v', 'V'])).ok()?,
                name: r["name"].as_str().unwrap_or(tag).to_string(),
                notes: r["body"].as_str().unwrap_or("").to_string(),
                published: r["published_at"].as_str().unwrap_or("").to_string(),
                prerelease: r["prerelease"].as_bool().unwrap_or(false),
                draft: r["draft"].as_bool().unwrap_or(false),
                assets: r["assets"]
                    .as_array()
                    .map(|a| {
                        a.iter()
                            .filter_map(|x| Some(Asset { name: x["name"].as_str()?.to_string(), url: x["url"].as_str()?.to_string() }))
                            .collect()
                    })
                    .unwrap_or_default(),
            })
        })
        .collect())
}

pub fn parse_gitlab(json: &[u8], host: &str) -> Result<Vec<Release>, String> {
    let v: Value = serde_json::from_slice(json).map_err(|_| "Unexpected response from GitLab.".to_string())?;
    let arr = v.as_array().ok_or("Unexpected response from GitLab.")?;
    Ok(arr
        .iter()
        .filter_map(|r| {
            let tag = r["tag_name"].as_str()?;
            Some(Release {
                version: Version::parse(tag.trim_start_matches(['v', 'V'])).ok()?,
                name: r["name"].as_str().unwrap_or(tag).to_string(),
                notes: r["description"].as_str().unwrap_or("").to_string(),
                published: r["released_at"].as_str().unwrap_or("").to_string(),
                prerelease: r["upcoming_release"].as_bool().unwrap_or(false),
                draft: false,
                assets: r["assets"]["links"]
                    .as_array()
                    .map(|a| {
                        a.iter()
                            .filter_map(|x| {
                                let url = x["direct_asset_url"].as_str().or(x["url"].as_str())?.to_string();
                                // Asset links must be served by the configured GitLab server.
                                let ok = winhttp::split_url(&url).map(|(h, _, _)| h == host.split(':').next().unwrap_or(host)).unwrap_or(false);
                                ok.then(|| Asset { name: x["name"].as_str().unwrap_or("").to_string(), url })
                            })
                            .collect()
                    })
                    .unwrap_or_default(),
            })
        })
        .collect())
}

/// Highest eligible installable release (drafts and prereleases excluded by default).
pub fn select(releases: Vec<Release>, allow_prerelease: bool) -> Option<Release> {
    releases
        .into_iter()
        .filter(|r| !r.draft && (allow_prerelease || (!r.prerelease && r.version.pre.is_empty())) && r.installable())
        .max_by(|a, b| a.version.cmp(&b.version))
}

fn list(src: &Source) -> Result<Vec<Release>, String> {
    let body = fetch(src, &src.list_url, src.accept_list, MAX_API_BYTES, None)?;
    match &src.gitlab_host {
        Some(h) => parse_gitlab(&body, h),
        None => parse_github(&body),
    }
}

fn current() -> Version {
    Version::parse(rdpmon_core::VERSION).expect("crate version is semver")
}

pub fn check(cfg: &Config) -> Result<UpdateInfo, String> {
    let src = source(&cfg.updates)?;
    let best = select(list(&src)?, cfg.updates.allow_prerelease);
    let cur = current();
    Ok(match best {
        Some(r) => {
            let newer = r.version > cur;
            UpdateInfo {
                current_version: cur.to_string(),
                latest_version: Some(r.version.to_string()),
                update_available: newer,
                release_name: r.name,
                release_notes: r.notes.chars().take(20_000).collect(),
                published_at: r.published,
                message: if newer { format!("Version {} is available.", r.version) } else { "RDP Monitor is up to date.".into() },
            }
        }
        None => UpdateInfo {
            current_version: cur.to_string(),
            message: "No eligible release found. Releases must contain RDPMonitor-<version>-x64.msi and its .msi.sig signature.".into(),
            ..Default::default()
        },
    })
}

/// "host" -> "host:443", "host:8443" unchanged (token host comparison).
fn with_port(authority: &str) -> String {
    let a = authority.to_ascii_lowercase();
    if a.rsplit_once(':').is_some_and(|(_, p)| p.parse::<u16>().is_ok()) { a } else { format!("{a}:443") }
}

fn is_reparse(m: &std::fs::Metadata) -> bool {
    use std::os::windows::fs::MetadataExt;
    const FILE_ATTRIBUTE_REPARSE_POINT: u32 = 0x400;
    m.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0
}

struct HashingFile {
    f: std::fs::File,
    h: Sha256,
}

impl Write for HashingFile {
    fn write(&mut self, b: &[u8]) -> std::io::Result<usize> {
        let n = self.f.write(b)?;
        self.h.update(&b[..n]);
        Ok(n)
    }
    fn flush(&mut self) -> std::io::Result<()> {
        self.f.flush()
    }
}

pub fn install(sh: &Shared, db: &Db, version: &str) -> Result<String, String> {
    let cfg = sh.cfg();
    let target = Version::parse(version.trim().trim_start_matches(['v', 'V'])).map_err(|_| format!("'{version}' is not a valid version."))?;
    let cur = current();
    if target <= cur {
        return Err(format!("Version {target} is not newer than the installed version {cur}; downgrades are not allowed."));
    }
    // One installation at a time (daily auto-update vs. an administrator).
    static INSTALLING: std::sync::Mutex<()> = std::sync::Mutex::new(());
    let _busy = INSTALLING.try_lock().map_err(|_| "An update is already being installed.".to_string())?;
    let src = source(&cfg.updates)?;
    let rel = list(&src)?
        .into_iter()
        .find(|r| r.version == target && !r.draft && (cfg.updates.allow_prerelease || (!r.prerelease && r.version.pre.is_empty())))
        .ok_or_else(|| format!("Release {target} was not found or is not eligible."))?;
    let name = msi_name(&target);
    let msi = rel.asset(&name).ok_or_else(|| format!("Release {target} has no {name}."))?.clone();
    let sig_asset = rel.asset(&format!("{name}.sig")).ok_or_else(|| format!("Release {target} has no {name}.sig - unsigned releases are rejected."))?.clone();

    if !sh.dir_secured.load(std::sync::atomic::Ordering::SeqCst) {
        return Err("In-app updates are disabled because the data directory could not be secured; install the new MSI with your deployment tool.".into());
    }
    let dir = sh.data_dir.join("updates");
    // A pre-created junction/symlink would redirect SYSTEM file operations.
    if std::fs::symlink_metadata(&dir).map(|m| m.file_type().is_symlink() || is_reparse(&m)).unwrap_or(false) {
        return Err(format!("{} is a link; refusing to use it.", dir.display()));
    }
    std::fs::create_dir_all(&dir).map_err(|e| format!("cannot create {}: {e}", dir.display()))?;
    if let Ok(rd) = std::fs::read_dir(&dir) {
        for e in rd.flatten() {
            let _ = std::fs::remove_file(e.path());
        }
    }

    let sig_bytes = fetch(&src, &sig_asset.url, src.accept_asset, 64 * 1024, None)?;
    let sig: SigFile = serde_json::from_slice(&sig_bytes).map_err(|_| "The release signature file is malformed.".to_string())?;

    let part = dir.join(format!("{name}.part"));
    let mut hf = HashingFile { f: std::fs::File::create(&part).map_err(|e| format!("cannot create download file: {e}"))?, h: Sha256::new() };
    logging::info(&format!("downloading update {target}"));
    let r = fetch(&src, &msi.url, src.accept_asset, MAX_MSI_BYTES, Some(&mut hf));
    hf.f.sync_all().ok();
    let sha = rdpmon_core::crypto::hex(&hf.h.finalize());
    drop(hf.f);
    if let Err(e) = r.and_then(|_| release::verify(&sig, &name, &target.to_string(), &sha, cfg.updates.effective_signing_key())) {
        let _ = std::fs::remove_file(&part);
        return Err(format!("Update rejected: {e}"));
    }
    let path = dir.join(&name);
    std::fs::rename(&part, &path).map_err(|e| format!("cannot finalize download: {e}"))?;
    let log = dir.join(format!("install-{target}.log"));

    db.set_kv(KV_UPDATE_PENDING, &target.to_string()).map_err(|e| e.to_string())?;
    let _ = db.audit("update", "update verified", &format!("{name} sha256 {sha}; starting installer"));
    let msiexec = std::path::PathBuf::from(std::env::var_os("SystemRoot").unwrap_or_else(|| "C:\\Windows".into())).join("System32\\msiexec.exe");
    use std::os::windows::process::CommandExt;
    const CREATE_NO_WINDOW: u32 = 0x0800_0000;
    std::process::Command::new(msiexec)
        .arg("/i")
        .arg(&path)
        .args(["/qn", "/norestart", "/l*v"])
        .arg(&log)
        .creation_flags(CREATE_NO_WINDOW)
        .spawn()
        .map_err(|e| format!("cannot start Windows Installer: {e}"))?;
    close_config_utility();
    logging::info(&format!("update {target} verified; msiexec started (log: {})", log.display()));
    Ok(format!(
        "Version {target} was downloaded and its signature verified. Installation has started; the service restarts automatically in a minute or two. Settings and history are preserved."
    ))
}

/// Ends running copies of the configuration utility so the installer can
/// replace it. Delayed so an administrator who started the update still
/// receives the reply; the installer itself needs longer than that to start.
fn close_config_utility() {
    std::thread::spawn(|| {
        std::thread::sleep(std::time::Duration::from_secs(3));
        let taskkill = std::path::PathBuf::from(std::env::var_os("SystemRoot").unwrap_or_else(|| "C:\\Windows".into())).join("System32\\taskkill.exe");
        use std::os::windows::process::CommandExt;
        let _ = std::process::Command::new(taskkill).args(["/F", "/IM", "rdpmon-config.exe"]).creation_flags(0x0800_0000).output();
    });
}

const KV_UPDATE_SLOT: &str = "update_last_slot";

/// Daily update worker: at `check_time` it looks for a newer signed release
/// and, with `auto_install`, installs it (the installer stops this service,
/// replaces the program and starts the new version).
pub fn run(shared: Arc<Shared>) {
    // Let the service settle (and a just-finished update report itself) first.
    if crate::winsec::wait_any(&[shared.stop.0], 5 * 60 * 1000).is_some() {
        return;
    }
    while !shared.stopping() {
        let cfg = shared.cfg();
        let u = &cfg.updates;
        if u.auto_install && u.provider != UpdateProvider::None {
            if let Some(slot) = crate::notify::last_daily_slot(&u.check_time, Local::now()) {
                let slot_s = slot.to_rfc3339();
                match shared.open_db() {
                    Ok(db) if db.kv(KV_UPDATE_SLOT).ok().flatten().as_deref() != Some(slot_s.as_str()) => {
                        let _ = db.set_kv(KV_UPDATE_SLOT, &slot_s);
                        auto_update(&shared, &db, &cfg);
                    }
                    Ok(_) => {}
                    Err(e) => logging::warn(&format!("update check skipped: {e}")),
                }
            }
        }
        // Re-read the settings at least hourly.
        let next = crate::notify::next_daily_slot(&u.check_time, Local::now())
            .map(|t| (t - Local::now()).to_std().unwrap_or_default())
            .unwrap_or(std::time::Duration::from_secs(3600))
            .min(std::time::Duration::from_secs(3600))
            .max(std::time::Duration::from_secs(1));
        if crate::winsec::wait_any(&[shared.stop.0], next.as_millis() as u32).is_some() {
            break;
        }
    }
    logging::info("update worker stopped");
}

fn auto_update(shared: &Shared, db: &Db, cfg: &Config) {
    let info = match check(cfg) {
        Ok(i) => i,
        Err(e) => {
            logging::warn(&format!("daily update check failed: {e}"));
            let _ = db.audit("update", "update check failed", &e);
            return;
        }
    };
    let Some(v) = info.latest_version.filter(|_| info.update_available) else {
        logging::info("daily update check: up to date");
        return;
    };
    let _ = db.audit("update", "automatic update", &format!("installing version {v}"));
    match install(shared, db, &v) {
        Ok(m) => logging::info(&m),
        Err(e) => {
            logging::warn(&format!("automatic update to {v} failed: {e}"));
            let _ = db.audit("update", "update rejected", &e);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const GH: &str = r#"[
      {"tag_name":"v1.3.0-beta.1","name":"beta","body":"","draft":false,"prerelease":true,"published_at":"2026-11-20T00:00:00Z",
       "assets":[{"name":"RDPMonitor-1.3.0-beta.1-x64.msi","url":"https://api.github.com/a/1"},{"name":"RDPMonitor-1.3.0-beta.1-x64.msi.sig","url":"https://api.github.com/a/2"}]},
      {"tag_name":"v1.2.0","name":"1.2.0","body":"Fixes","draft":false,"prerelease":false,"published_at":"2026-11-10T00:00:00Z",
       "assets":[{"name":"RDPMonitor-1.2.0-x64.msi","url":"https://api.github.com/a/3"},{"name":"RDPMonitor-1.2.0-x64.msi.sig","url":"https://api.github.com/a/4"}]},
      {"tag_name":"v9.0.0","name":"draft","body":"","draft":true,"prerelease":false,"assets":[{"name":"RDPMonitor-9.0.0-x64.msi","url":"x"},{"name":"RDPMonitor-9.0.0-x64.msi.sig","url":"y"}]},
      {"tag_name":"v1.5.0","name":"unsigned","body":"","draft":false,"prerelease":false,"assets":[{"name":"RDPMonitor-1.5.0-x64.msi","url":"z"}]},
      {"tag_name":"not-a-version","assets":[]}
    ]"#;

    #[test]
    fn github_selection_skips_drafts_prereleases_and_unsigned() {
        let r = select(parse_github(GH.as_bytes()).unwrap(), false).unwrap();
        assert_eq!(r.version, Version::new(1, 2, 0));
        assert_eq!(r.notes, "Fixes");
        let pre = select(parse_github(GH.as_bytes()).unwrap(), true).unwrap();
        assert_eq!(pre.version.to_string(), "1.3.0-beta.1");
    }

    #[test]
    fn gitlab_parsing_rejects_foreign_asset_hosts() {
        let j = r#"[{"tag_name":"1.4.0","name":"1.4.0","description":"notes","released_at":"2026-11-01T00:00:00Z","upcoming_release":false,
          "assets":{"links":[
            {"name":"RDPMonitor-1.4.0-x64.msi","url":"https://gitlab.example.com/api/v4/projects/1/packages/generic/rdpmon/1.4.0/RDPMonitor-1.4.0-x64.msi"},
            {"name":"RDPMonitor-1.4.0-x64.msi.sig","url":"https://evil.example.net/x.sig"}]}}]"#;
        let rs = parse_gitlab(j.as_bytes(), "gitlab.example.com").unwrap();
        assert_eq!(rs[0].assets.len(), 1, "foreign-host asset dropped");
        assert!(select(rs, false).is_none(), "without a trusted-host signature it is not installable");
    }

    #[test]
    fn sources() {
        let mut u = UpdateConfig { provider: UpdateProvider::Github, repository_url: "https://github.com/acme/rdp-monitor".into(), token: "t".into(), ..Default::default() };
        let s = source(&u).unwrap();
        assert_eq!(s.list_url, "https://api.github.com/repos/acme/rdp-monitor/releases?per_page=30");
        assert_eq!(s.auth_host, "api.github.com:443");
        u.provider = UpdateProvider::Gitlab;
        u.repository_url = "https://gitlab.example.com/it/tools/rdp-monitor".into();
        let s = source(&u).unwrap();
        assert_eq!(s.list_url, "https://gitlab.example.com/api/v4/projects/it%2Ftools%2Frdp-monitor/releases?per_page=30&order_by=released_at&sort=desc");
        assert_eq!(s.auth.unwrap().0, "PRIVATE-TOKEN");
        u.provider = UpdateProvider::None;
        assert!(source(&u).is_err());
    }

    /// Live, read-only call to the public GitHub API: exercises WinHTTP,
    /// TLS validation and JSON parsing. A repository without releases yields
    /// "no eligible release"; network failure is reported, not a panic.
    #[test]
    #[ignore = "requires internet access"]
    fn live_github_check() {
        let mut c = Config::default();
        c.updates = UpdateConfig {
            provider: UpdateProvider::Github,
            repository_url: "https://github.com/rust-lang/rustup".into(),
            signing_public_key: rdpmon_core::crypto::b64(rdpmon_core::crypto::generate_signing_key().verifying_key().as_bytes()),
            ..Default::default()
        };
        let info = check(&c).unwrap();
        assert!(info.latest_version.is_none(), "rustup releases do not carry RDP Monitor assets");
        c.updates.repository_url = "https://github.com/rust-lang/this-repo-does-not-exist-xyz".into();
        assert!(check(&c).unwrap_err().contains("404"));
    }
}
