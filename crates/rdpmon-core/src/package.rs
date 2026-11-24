//! Signed configuration packages (`.rdpcfg`).
//!
//! A package is a JSON envelope containing a base64 TOML payload and an
//! Ed25519 signature over `DOMAIN || payload`. The payload contains a
//! `[package]` header and any subset of the normal configuration sections;
//! only the sections/keys present are changed (arrays are replaced whole).
//!
//! Packages are authenticated, not confidential: secrets inside them are
//! readable by anyone who can read the package file. See docs/SECURITY.md.

use crate::config::Config;
use crate::crypto::{b64, decode_public_key, unb64};
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier};
use serde::{Deserialize, Serialize};

pub const FORMAT: &str = "rdpmon-config-v1";
const DOMAIN: &[u8] = b"RDPMON-CONFIG-V1\0";
const MAX_PACKAGE_BYTES: usize = 256 * 1024;

#[derive(Serialize, Deserialize)]
struct Envelope {
    format: String,
    payload: String,
    signature: String,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct Header {
    serial: u64,
    #[serde(default)]
    description: String,
    #[serde(default)]
    new_trusted_config_key: Option<String>,
    #[serde(default)]
    authorize_uninstall: bool,
}

#[derive(Debug, Clone)]
pub struct VerifiedPackage {
    pub serial: u64,
    pub description: String,
    pub new_trusted_config_key: Option<String>,
    /// Opens the 10-minute removal window (silent enterprise uninstall).
    pub authorize_uninstall: bool,
    settings: toml::Table,
}

/// Signs a TOML payload (must contain a `[package]` table with `serial`).
pub fn sign(payload_toml: &str, key: &SigningKey) -> Result<String, String> {
    parse_payload(payload_toml)?; // refuse to sign something the agent would reject
    let sig = key.sign(&[DOMAIN, payload_toml.as_bytes()].concat());
    let env = Envelope { format: FORMAT.into(), payload: b64(payload_toml.as_bytes()), signature: b64(&sig.to_bytes()) };
    Ok(serde_json::to_string_pretty(&env).expect("serializable"))
}

/// Verifies the signature with the trusted public key and parses the payload.
pub fn verify(data: &[u8], trusted_key_b64: &str) -> Result<VerifiedPackage, String> {
    if trusted_key_b64.trim().is_empty() {
        return Err("No trusted configuration key is installed on this computer; packages cannot be accepted.".into());
    }
    if data.len() > MAX_PACKAGE_BYTES {
        return Err("Configuration package is too large.".into());
    }
    let env: Envelope = serde_json::from_slice(data).map_err(|_| "File is not an RDP Monitor configuration package.".to_string())?;
    if env.format != FORMAT {
        return Err(format!("Unsupported package format '{}'.", env.format));
    }
    let payload = unb64(&env.payload)?;
    let sig_bytes: [u8; 64] = unb64(&env.signature)?.try_into().map_err(|_| "Malformed package signature.".to_string())?;
    let key = decode_public_key(trusted_key_b64)?;
    key.verify(&[DOMAIN, &payload].concat(), &Signature::from_bytes(&sig_bytes))
        .map_err(|_| "Package signature is invalid or was not made with the trusted configuration key.".to_string())?;
    let text = String::from_utf8(payload).map_err(|_| "Package payload is not UTF-8.".to_string())?;
    parse_payload(&text)
}

fn parse_payload(text: &str) -> Result<VerifiedPackage, String> {
    let mut table: toml::Table = toml::from_str(text).map_err(|e| format!("Package payload is not valid TOML: {e}"))?;
    let header_val = table.remove("package").ok_or("Package payload has no [package] section.")?;
    let header: Header = header_val.try_into().map_err(|e| format!("Invalid [package] section: {e}"))?;
    if header.serial == 0 {
        return Err("Package serial must be greater than zero.".into());
    }
    if let Some(k) = &header.new_trusted_config_key {
        decode_public_key(k).map_err(|e| format!("new_trusted_config_key: {e}"))?;
    }
    if let Some(sec) = table.get("security").and_then(|v| v.as_table()) {
        for forbidden in ["trusted_config_key", "last_package_serial"] {
            if sec.contains_key(forbidden) {
                return Err(format!("security.{forbidden} cannot be set by a package (use [package] new_trusted_config_key)."));
            }
        }
    }
    Ok(VerifiedPackage {
        serial: header.serial,
        description: header.description,
        new_trusted_config_key: header.new_trusted_config_key,
        authorize_uninstall: header.authorize_uninstall,
        settings: table,
    })
}

impl VerifiedPackage {
    /// Produces the new configuration. Rejects replayed/older packages.
    pub fn apply_to(&self, current: &Config) -> Result<Config, String> {
        if self.serial <= current.security.last_package_serial {
            return Err(format!(
                "Package serial {} is not newer than the last applied package ({}); refusing to apply an old package.",
                self.serial, current.security.last_package_serial
            ));
        }
        let mut base = toml::Table::try_from(current).map_err(|e| e.to_string())?;
        merge(&mut base, &self.settings);
        let mut cfg: Config = toml::Value::Table(base).try_into().map_err(|e| format!("Invalid configuration in package: {e}"))?;
        // Same rule as the UI: a stored secret never follows a changed
        // destination unless the package supplies the secret itself.
        let has = |section: &str, key: &str| self.settings.get(section).and_then(|s| s.as_table()).is_some_and(|t| t.contains_key(key));
        if (!cfg.smtp.host.trim().eq_ignore_ascii_case(current.smtp.host.trim()) || cfg.smtp.username.trim() != current.smtp.username.trim())
            && !has("smtp", "password")
        {
            cfg.smtp.password.clear();
        }
        let repo_host = |u: &str| crate::config::repo_host_and_path(u).map(|x| x.0);
        if repo_host(&cfg.updates.repository_url) != repo_host(&current.updates.repository_url) && !has("updates", "token") {
            cfg.updates.token.clear();
        }
        if cfg.security.admin_password_hash.is_empty() && !current.security.admin_password_hash.is_empty() {
            return Err("A package cannot remove the administration password.".into());
        }
        cfg.security.last_package_serial = self.serial;
        if let Some(k) = &self.new_trusted_config_key {
            cfg.security.trusted_config_key = k.clone();
        }
        cfg.validate().map_err(|e| format!("Configuration in package is invalid: {}", e.join(" ")))?;
        Ok(cfg)
    }
}

fn merge(base: &mut toml::Table, patch: &toml::Table) {
    for (k, v) in patch {
        match (base.get_mut(k), v) {
            (Some(toml::Value::Table(b)), toml::Value::Table(p)) => merge(b, p),
            _ => {
                base.insert(k.clone(), v.clone());
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::generate_signing_key;

    fn key() -> (SigningKey, String) {
        let k = generate_signing_key();
        let p = b64(k.verifying_key().as_bytes());
        (k, p)
    }

    const PAYLOAD: &str = r#"
[package]
serial = 5
description = "site A"

[smtp]
host = "relay.example.com"
from = "rdp@example.com"
to = ["it@example.com", "soc@example.com"]

[notifications]
cooldown_minutes = 0
"#;

    #[test]
    fn sign_verify_apply_partial() {
        let (k, p) = key();
        let pkg = sign(PAYLOAD, &k).unwrap();
        let v = verify(pkg.as_bytes(), &p).unwrap();
        let mut cur = Config::default();
        cur.notifications.notify_reconnects = false;
        let new = v.apply_to(&cur).unwrap();
        assert_eq!(new.smtp.host, "relay.example.com");
        assert_eq!(new.smtp.to.len(), 2);
        assert_eq!(new.notifications.cooldown_minutes, 0);
        assert!(!new.notifications.notify_reconnects, "untouched keys keep their value");
        assert_eq!(new.security.last_package_serial, 5);
    }

    #[test]
    fn rejects_wrong_key_and_tampering() {
        let (k, _) = key();
        let (_, other) = key();
        let pkg = sign(PAYLOAD, &k).unwrap();
        assert!(verify(pkg.as_bytes(), &other).is_err());
        let mut env: serde_json::Value = serde_json::from_str(&pkg).unwrap();
        env["payload"] = b64(PAYLOAD.replace("relay", "evil").as_bytes()).into();
        let (_, p) = (0, b64(k.verifying_key().as_bytes()));
        assert!(verify(env.to_string().as_bytes(), &p).is_err());
        assert!(verify(pkg.as_bytes(), "").is_err(), "no trusted key = no packages");
    }

    #[test]
    fn rejects_replay() {
        let (k, p) = key();
        let v = verify(sign(PAYLOAD, &k).unwrap().as_bytes(), &p).unwrap();
        let mut cur = Config::default();
        cur.security.last_package_serial = 5;
        assert!(v.apply_to(&cur).is_err());
    }

    #[test]
    fn rejects_forbidden_and_invalid() {
        let (k, _) = key();
        assert!(sign("[package]\nserial=1\n[security]\ntrusted_config_key=\"x\"\n", &k).is_err());
        assert!(sign("[smtp]\nhost=\"x\"\n", &k).is_err());
        let (k, p) = key();
        let bad = sign("[package]\nserial=9\n[smtp]\nhost=\"relay.example.com\"\nfrom=\"bad\"\nto=[\"a@b.com\"]\n", &k).unwrap();
        assert!(verify(bad.as_bytes(), &p).unwrap().apply_to(&Config::default()).is_err());
    }

    #[test]
    fn secrets_do_not_follow_a_changed_destination() {
        let (k, p) = key();
        let mut cur = Config::default();
        cur.smtp.host = "mail.example.com".into();
        cur.smtp.encryption = crate::config::Encryption::Starttls;
        cur.smtp.username = "svc".into();
        cur.smtp.password = "secret".into();
        cur.smtp.from = "a@example.com".into();
        cur.smtp.to = vec!["b@example.com".into()];
        cur.security.admin_password_hash = crate::password::hash("Good-Passw0rd").unwrap();
        let apply = |payload: &str| verify(sign(payload, &k).unwrap().as_bytes(), &p).unwrap().apply_to(&cur);
        let moved = apply("[package]\nserial=1\n[smtp]\nhost=\"evil.example.net\"\n").unwrap();
        assert!(moved.smtp.password.is_empty(), "password must not be sent to a new host");
        let kept = apply("[package]\nserial=1\n[smtp]\nto=[\"c@example.com\"]\n").unwrap();
        assert_eq!(kept.smtp.password, "secret");
        let supplied = apply("[package]\nserial=1\n[smtp]\nhost=\"new.example.com\"\npassword=\"p2\"\n").unwrap();
        assert_eq!(supplied.smtp.password, "p2");
        assert!(apply("[package]\nserial=1\n[security]\nadmin_password_hash=\"\"\n").is_err(), "cannot reset to first run");
    }

    #[test]
    fn key_rotation() {
        let (k, p) = key();
        let (_, p2) = key();
        let v = verify(sign(&format!("[package]\nserial=2\nnew_trusted_config_key=\"{p2}\"\n"), &k).unwrap().as_bytes(), &p).unwrap();
        let mut cur = Config::default();
        cur.security.trusted_config_key = p;
        assert_eq!(v.apply_to(&cur).unwrap().security.trusted_config_key, p2);
    }
}
