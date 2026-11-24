//! Release package signatures (`<installer>.msi.sig`).
//!
//! The signature binds the file name, the version and the SHA-256 of the MSI,
//! and is made offline with a key the repository host never sees. A checksum
//! published next to the asset is therefore *not* what establishes trust.

use crate::crypto::{b64, decode_public_key, unb64};
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier};
use serde::{Deserialize, Serialize};

pub const FORMAT: &str = "rdpmon-release-v1";

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SigFile {
    pub format: String,
    pub file: String,
    pub version: String,
    pub sha256: String,
    pub signature: String,
}

fn message(file: &str, version: &str, sha256: &str) -> Vec<u8> {
    format!("RDPMON-RELEASE-V1\0{file}\0{version}\0{}", sha256.to_ascii_lowercase()).into_bytes()
}

pub fn sign(file: &str, version: &str, sha256_hex: &str, key: &SigningKey) -> SigFile {
    let sig = key.sign(&message(file, version, sha256_hex));
    SigFile {
        format: FORMAT.into(),
        file: file.into(),
        version: version.into(),
        sha256: sha256_hex.to_ascii_lowercase(),
        signature: b64(&sig.to_bytes()),
    }
}

/// Verifies that `sig` is a valid signature by `trusted_key` for exactly this
/// file name, version and content hash.
pub fn verify(sig: &SigFile, file: &str, version: &str, actual_sha256: &str, trusted_key: &str) -> Result<(), String> {
    if sig.format != FORMAT {
        return Err("Unsupported release signature format.".into());
    }
    if sig.file != file {
        return Err(format!("Signature is for '{}', not '{file}'.", sig.file));
    }
    if sig.version != version {
        return Err(format!("Signature is for version {}, not {version}.", sig.version));
    }
    if !sig.sha256.eq_ignore_ascii_case(actual_sha256) {
        return Err("Downloaded file does not match the signed hash (corrupted or modified).".into());
    }
    let key = decode_public_key(trusted_key).map_err(|e| format!("Trusted update key: {e}"))?;
    let bytes: [u8; 64] = unb64(&sig.signature)?.try_into().map_err(|_| "Malformed release signature.".to_string())?;
    key.verify(&message(file, version, actual_sha256), &Signature::from_bytes(&bytes))
        .map_err(|_| "Release signature is invalid or not made with the trusted update key.".to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::{generate_signing_key, sha256_hex};

    #[test]
    fn release_signature() {
        let k = generate_signing_key();
        let pubk = b64(k.verifying_key().as_bytes());
        let h = sha256_hex(b"msi bytes");
        let s = sign("RDPMonitor-1.2.0-x64.msi", "1.2.0", &h, &k);
        assert!(verify(&s, "RDPMonitor-1.2.0-x64.msi", "1.2.0", &h, &pubk).is_ok());
        assert!(verify(&s, "RDPMonitor-1.2.0-x64.msi", "1.2.0", &sha256_hex(b"other"), &pubk).is_err());
        assert!(verify(&s, "RDPMonitor-1.3.0-x64.msi", "1.2.0", &h, &pubk).is_err());
        assert!(verify(&s, "RDPMonitor-1.2.0-x64.msi", "1.3.0", &h, &pubk).is_err());
        let other = b64(generate_signing_key().verifying_key().as_bytes());
        assert!(verify(&s, "RDPMonitor-1.2.0-x64.msi", "1.2.0", &h, &other).is_err());
        let mut forged = s.clone();
        forged.version = "9.9.9".into();
        assert!(verify(&forged, "RDPMonitor-1.2.0-x64.msi", "9.9.9", &h, &pubk).is_err());
    }
}
