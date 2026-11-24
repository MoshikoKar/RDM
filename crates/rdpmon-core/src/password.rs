//! Administration password verifier (Argon2id, PHC string format).

use argon2::password_hash::{PasswordHash, PasswordHasher, PasswordVerifier, SaltString};
use argon2::Argon2;

pub const MIN_LENGTH: usize = 10;

pub fn check_strength(pw: &str) -> Result<(), String> {
    if pw.chars().count() < MIN_LENGTH {
        return Err(format!("The password must be at least {MIN_LENGTH} characters long."));
    }
    if pw.chars().count() > 256 {
        return Err("The password is too long (maximum 256 characters).".into());
    }
    let classes = [
        pw.chars().any(|c| c.is_lowercase()),
        pw.chars().any(|c| c.is_uppercase()),
        pw.chars().any(|c| c.is_ascii_digit()),
        pw.chars().any(|c| !c.is_alphanumeric()),
    ];
    if classes.iter().filter(|x| **x).count() < 3 {
        return Err("Use at least three of: lowercase letters, uppercase letters, digits, symbols.".into());
    }
    Ok(())
}

/// Argon2id with the crate defaults (m=19 MiB, t=2, p=1 - OWASP recommendation).
pub fn hash(pw: &str) -> Result<String, String> {
    let salt = SaltString::encode_b64(&crate::crypto::random_bytes::<16>()).map_err(|e| e.to_string())?;
    Argon2::default()
        .hash_password(pw.as_bytes(), &salt)
        .map(|h| h.to_string())
        .map_err(|e| format!("password hashing failed: {e}"))
}

pub fn verify(pw: &str, phc: &str) -> bool {
    match PasswordHash::new(phc) {
        Ok(h) if acceptable(&h) => Argon2::default().verify_password(pw.as_bytes(), &h).is_ok(),
        _ => false,
    }
}

/// Argon2id with bounded cost parameters: a hash supplied by a package must
/// not be able to make verification allocate gigabytes or run for minutes.
fn acceptable(h: &PasswordHash) -> bool {
    let p = |k: &str| h.params.get_decimal(k);
    h.algorithm.as_str() == "argon2id"
        && matches!(p("m"), Some(m) if (8_192..=262_144).contains(&m))
        && matches!(p("t"), Some(t) if (1..=10).contains(&t))
        && matches!(p("p"), Some(par) if (1..=8).contains(&par))
}

pub fn is_valid_hash(phc: &str) -> bool {
    PasswordHash::new(phc).map(|h| acceptable(&h)).unwrap_or(false)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hash_and_verify() {
        let h = hash("Correct-Horse-9").unwrap();
        assert!(h.starts_with("$argon2id$"));
        assert!(is_valid_hash(&h));
        assert!(verify("Correct-Horse-9", &h));
        assert!(!verify("correct-horse-9", &h));
        assert!(!verify("Correct-Horse-9", "garbage"));
        assert!(!verify("", ""));
        // Excessive cost parameters are refused (memory-exhaustion guard).
        let huge = h.replace("m=19456", "m=4194304");
        assert!(!is_valid_hash(&huge) && !verify("Correct-Horse-9", &huge));
        assert_ne!(hash("Correct-Horse-9").unwrap(), h, "salts must differ");
    }

    #[test]
    fn strength() {
        assert!(check_strength("short1A!").is_err());
        assert!(check_strength("alllowercaseletters").is_err());
        assert!(check_strength("Abcdefghij1").is_ok());
    }
}
