//! Random numbers, Windows DPAPI secret protection, Ed25519 key handling.

use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine;
use ed25519_dalek::{SigningKey, VerifyingKey};
use sha2::{Digest, Sha256};
use std::io;

pub fn random_bytes<const N: usize>() -> [u8; N] {
    let mut b = [0u8; N];
    getrandom::getrandom(&mut b).expect("operating system random number generator failed");
    b
}

pub fn random_hex(n: usize) -> String {
    let mut b = vec![0u8; n];
    getrandom::getrandom(&mut b).expect("operating system random number generator failed");
    hex(&b)
}

pub fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

pub fn sha256_hex(data: &[u8]) -> String {
    hex(&Sha256::digest(data))
}

pub fn b64(data: &[u8]) -> String {
    B64.encode(data)
}

pub fn unb64(s: &str) -> Result<Vec<u8>, String> {
    B64.decode(s.trim()).map_err(|_| "invalid base64 data".to_string())
}

pub fn decode_public_key(s: &str) -> Result<VerifyingKey, String> {
    let bytes: [u8; 32] = unb64(s)?.try_into().map_err(|_| "public key must be 32 bytes".to_string())?;
    VerifyingKey::from_bytes(&bytes).map_err(|_| "invalid Ed25519 public key".to_string())
}

pub fn decode_signing_key(s: &str) -> Result<SigningKey, String> {
    let bytes: [u8; 32] = unb64(s)?.try_into().map_err(|_| "private key must be 32 bytes".to_string())?;
    Ok(SigningKey::from_bytes(&bytes))
}

pub fn generate_signing_key() -> SigningKey {
    SigningKey::from_bytes(&random_bytes::<32>())
}

/// Constant-time comparison for secrets such as session tokens.
pub fn ct_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    a.iter().zip(b).fold(0u8, |acc, (x, y)| acc | (x ^ y)) == 0
}

/// Encrypts `data` with DPAPI for the *current user account*. The service runs
/// as LocalSystem, so only code running as SYSTEM can decrypt the result.
/// DPAPI blobs are integrity protected: any modification makes decryption fail.
pub fn dpapi_protect(data: &[u8], entropy: &[u8]) -> io::Result<Vec<u8>> {
    dpapi(data, entropy, true)
}

pub fn dpapi_unprotect(data: &[u8], entropy: &[u8]) -> io::Result<Vec<u8>> {
    dpapi(data, entropy, false)
}

#[cfg(windows)]
fn dpapi(data: &[u8], entropy: &[u8], protect: bool) -> io::Result<Vec<u8>> {
    use windows_sys::Win32::Foundation::LocalFree;
    use windows_sys::Win32::Security::Cryptography::{
        CryptProtectData, CryptUnprotectData, CRYPTPROTECT_UI_FORBIDDEN, CRYPT_INTEGER_BLOB,
    };
    let input = CRYPT_INTEGER_BLOB { cbData: data.len() as u32, pbData: data.as_ptr() as *mut u8 };
    let ent = CRYPT_INTEGER_BLOB { cbData: entropy.len() as u32, pbData: entropy.as_ptr() as *mut u8 };
    let mut out = CRYPT_INTEGER_BLOB { cbData: 0, pbData: std::ptr::null_mut() };
    // SAFETY: all pointers reference live buffers for the duration of the call;
    // the output buffer is allocated by the OS and released with LocalFree.
    unsafe {
        let ok = if protect {
            CryptProtectData(&input, std::ptr::null(), &ent, std::ptr::null(), std::ptr::null(), CRYPTPROTECT_UI_FORBIDDEN, &mut out)
        } else {
            CryptUnprotectData(&input, std::ptr::null_mut(), &ent, std::ptr::null(), std::ptr::null(), CRYPTPROTECT_UI_FORBIDDEN, &mut out)
        };
        if ok == 0 {
            return Err(io::Error::last_os_error());
        }
        let v = std::slice::from_raw_parts(out.pbData, out.cbData as usize).to_vec();
        LocalFree(out.pbData as _);
        Ok(v)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn dpapi_roundtrip_and_tamper_detection() {
        let blob = dpapi_protect(b"secret", b"ctx").unwrap();
        assert_ne!(&blob[..], b"secret");
        assert_eq!(dpapi_unprotect(&blob, b"ctx").unwrap(), b"secret");
        assert!(dpapi_unprotect(&blob, b"other").is_err(), "wrong entropy must fail");
        let mut bad = blob.clone();
        let last = bad.len() - 1;
        bad[last] ^= 0xff;
        assert!(dpapi_unprotect(&bad, b"ctx").is_err(), "tampered blob must fail");
    }

    #[test]
    fn key_encoding() {
        let k = generate_signing_key();
        let pubk = b64(k.verifying_key().as_bytes());
        assert_eq!(decode_public_key(&pubk).unwrap(), k.verifying_key());
        assert!(decode_public_key("AAAA").is_err());
        assert!(ct_eq(b"abc", b"abc") && !ct_eq(b"abc", b"abd") && !ct_eq(b"a", b"ab"));
    }
}
