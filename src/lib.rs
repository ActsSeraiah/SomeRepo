//! security_utils: small security-themed utilities for tutorials
//!
//! This crate provides simple helpers used in security tutorials:
//! - password hashing using Argon2
//! - password verification
//! - constant-time comparison
//! - random token generation

use argon2::{Argon2, password_hash::{PasswordHasher, PasswordVerifier, SaltString, PasswordHash}};
use rand_core::OsRng;
use subtle::ConstantTimeEq;
use rand::{thread_rng, distributions::Alphanumeric, Rng};

/// Hash a password with Argon2 and a random salt. Returns an encoded PHC string.
pub fn hash_password(password: &str) -> Result<String, String> {
    let salt = SaltString::generate(&mut OsRng);
    let argon2 = Argon2::default();
    argon2
        .hash_password(password.as_bytes(), &salt)
        .map(|ph| ph.to_string())
        .map_err(|e| e.to_string())
}

/// Verify a password against a PHC encoded Argon2 hash.
pub fn verify_password(hash: &str, password: &str) -> Result<bool, String> {
    let parsed = PasswordHash::new(hash).map_err(|e| e.to_string())?;
    Ok(Argon2::default().verify_password(password.as_bytes(), &parsed).is_ok())
}

/// Constant-time equality for two byte slices.
pub fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    a.ct_eq(b).unwrap_u8() == 1
}

/// Generate a compact random token consisting of ASCII alphanumeric characters.
pub fn generate_token(len: usize) -> String {
    thread_rng()
        .sample_iter(&Alphanumeric)
        .take(len)
        .map(char::from)
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_hash_and_verify() {
        let pwd = "correct horse battery staple";
        let hash = hash_password(pwd).expect("hash failed");
        assert!(verify_password(&hash, pwd).unwrap());
        assert!(!verify_password(&hash, "wrong").unwrap());
    }

    #[test]
    fn test_constant_time_eq() {
        let a = b"abcdef";
        let b_same = b"abcdef";
        let b_diff = b"abcdeg";
        assert!(constant_time_eq(a, b_same));
        assert!(!constant_time_eq(a, b_diff));
    }

    #[test]
    fn test_generate_token() {
        let t = generate_token(32);
        assert_eq!(t.len(), 32);
    }
}
