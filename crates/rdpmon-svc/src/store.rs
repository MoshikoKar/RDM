//! Protected configuration file (`config.dat`): the TOML configuration
//! encrypted and integrity-protected with DPAPI under the service account
//! (LocalSystem). Written atomically; the previous version is kept as
//! `config.dat.bak` and used if the current file is unreadable.

use rdpmon_core::config::Config;
use rdpmon_core::crypto::{dpapi_protect, dpapi_unprotect};
use std::path::{Path, PathBuf};

const ENTROPY: &[u8] = b"RDPMonitor.config.v1";

pub struct ConfigStore {
    path: PathBuf,
}

pub enum Loaded {
    Missing,
    Ok(Config),
    /// Main file unreadable/tampered; backup used.
    FromBackup(Config, String),
}

impl ConfigStore {
    pub fn new(dir: &Path) -> Self {
        Self { path: dir.join("config.dat") }
    }

    fn bak(&self) -> PathBuf {
        self.path.with_extension("dat.bak")
    }

    fn read(path: &Path) -> Result<Config, String> {
        let blob = std::fs::read(path).map_err(|e| format!("cannot read {}: {e}", path.display()))?;
        let plain = dpapi_unprotect(&blob, ENTROPY)
            .map_err(|_| format!("{} could not be decrypted (modified, copied from another computer, or not running as the service account)", path.display()))?;
        let text = String::from_utf8(plain).map_err(|_| "configuration is not UTF-8".to_string())?;
        Config::from_toml(&text)
    }

    pub fn load(&self) -> Result<Loaded, String> {
        if !self.path.exists() {
            return Ok(if self.bak().exists() {
                match Self::read(&self.bak()) {
                    Ok(c) => Loaded::FromBackup(c, "config.dat is missing".into()),
                    Err(_) => Loaded::Missing,
                }
            } else {
                Loaded::Missing
            });
        }
        match Self::read(&self.path) {
            Ok(c) => Ok(Loaded::Ok(c)),
            Err(e) => match Self::read(&self.bak()) {
                Ok(c) => Ok(Loaded::FromBackup(c, e)),
                Err(_) => Err(e),
            },
        }
    }

    pub fn save(&self, cfg: &Config) -> Result<(), String> {
        let blob = dpapi_protect(cfg.to_toml().as_bytes(), ENTROPY).map_err(|e| format!("DPAPI protection failed: {e}"))?;
        use std::io::Write;
        let tmp = self.path.with_extension("dat.tmp");
        {
            let mut f = std::fs::File::create(&tmp).map_err(|e| format!("cannot write configuration: {e}"))?;
            f.write_all(&blob).map_err(|e| format!("cannot write configuration: {e}"))?;
            // Durable before it replaces the current file (power loss safety).
            f.sync_all().map_err(|e| format!("cannot flush configuration: {e}"))?;
        }
        // Only a readable current file may become the backup: never replace a
        // good backup with a corrupt file.
        if Self::read(&self.path).is_ok() {
            let _ = std::fs::copy(&self.path, self.bak());
        }
        std::fs::rename(&tmp, &self.path).map_err(|e| format!("cannot replace configuration: {e}"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn save_load_backup_and_tamper() {
        let dir = std::env::temp_dir().join(format!("rdpmon-store-{}", rdpmon_core::crypto::random_hex(6)));
        std::fs::create_dir_all(&dir).unwrap();
        let s = ConfigStore::new(&dir);
        assert!(matches!(s.load().unwrap(), Loaded::Missing));
        let mut c = Config::default();
        c.smtp.password = "s3cret-smtp".into();
        s.save(&c).unwrap();
        let raw = std::fs::read(dir.join("config.dat")).unwrap();
        assert!(!String::from_utf8_lossy(&raw).contains("s3cret-smtp"), "secret must not be stored in clear");
        assert!(matches!(s.load().unwrap(), Loaded::Ok(x) if x == c));
        c.smtp.port = 587;
        s.save(&c).unwrap();
        // Tamper with the current file: backup (previous version) is used.
        let mut raw = std::fs::read(dir.join("config.dat")).unwrap();
        let n = raw.len() - 5;
        raw[n] ^= 0x55;
        std::fs::write(dir.join("config.dat"), raw).unwrap();
        match s.load().unwrap() {
            Loaded::FromBackup(b, _) => assert_eq!(b.smtp.port, 25),
            _ => panic!("expected backup"),
        }
        // Saving over the corrupt file must keep the good backup intact.
        c.smtp.port = 465;
        s.save(&c).unwrap();
        assert_eq!(ConfigStore::read(&dir.join("config.dat.bak")).unwrap().smtp.port, 25);
        assert!(matches!(s.load().unwrap(), Loaded::Ok(x) if x.smtp.port == 465));
        let _ = std::fs::remove_dir_all(dir);
    }
}
