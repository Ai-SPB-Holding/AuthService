//! TOTP helpers built on `totp-rs` (RFC 6238, ±1 step skew).

use totp_rs::{Algorithm, Secret, TOTP};

use crate::services::errors::AppError;

pub const TOTP_DIGITS: usize = 6;
pub const TOTP_STEP: u64 = 30;
pub const TOTP_SKEW: u8 = 1;

/// Build a TOTP instance for validation using raw secret bytes (same encoding as Google Authenticator).
pub fn build_totp(
    secret_bytes: Vec<u8>,
    issuer: Option<String>,
    account_name: &str,
) -> Result<TOTP, AppError> {
    TOTP::new(
        Algorithm::SHA1,
        TOTP_DIGITS,
        TOTP_SKEW,
        TOTP_STEP,
        secret_bytes,
        issuer,
        account_name.to_string(),
    )
    .map_err(|e| AppError::Validation(e.to_string()))
}

/// Check a 6-digit user input against the secret at `time` (unix seconds).
pub fn check_totp(totp: &TOTP, user_code: &str, time: u64) -> Result<bool, AppError> {
    if user_code.len() != TOTP_DIGITS || !user_code.chars().all(|c| c.is_ascii_digit()) {
        return Err(AppError::Validation("totp must be 6 digits".to_string()));
    }
    Ok(totp.check(user_code, time))
}

/// Generate a new RFC-recommended 160-bit secret, return raw bytes and base32 (for display / otpauth).
pub fn generate_totp_secret() -> (Vec<u8>, String) {
    let s = Secret::generate_secret();
    let bytes = s.to_bytes().expect("generated secret");
    let b32 = match s.to_encoded() {
        Secret::Encoded(b) => b,
        Secret::Raw(_) => unreachable!(),
    };
    (bytes, b32)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn known_secret_generates_checkable() {
        let s = Secret::Raw(b"TestSecretSuperSecret".to_vec());
        let bytes = s.to_bytes().unwrap();
        let totp = build_totp(bytes, Some("Iss".to_string()), "user@test.com").unwrap();
        let t = 1_600_000_000u64;
        let code = totp.generate(t);
        let ok = check_totp(&totp, &code, t).unwrap();
        assert!(ok);
    }
}
