use argon2::password_hash::{SaltString, rand_core::OsRng};
use argon2::{Algorithm, Argon2, Params, PasswordHash, PasswordHasher, PasswordVerifier, Version};

/// Pinned Argon2id parameters (memory 19 MiB, 2 iterations, 1 lane) for passwords and client secrets.
fn argon2_engine() -> Argon2<'static> {
    let params = Params::new(19_456, 2, 1, None).expect("valid argon2 params");
    Argon2::new(Algorithm::Argon2id, Version::V0x13, params)
}

pub fn hash_password(password: &str) -> Result<String, String> {
    let salt = SaltString::generate(&mut OsRng);
    argon2_engine()
        .hash_password(password.as_bytes(), &salt)
        .map(|v| v.to_string())
        .map_err(|e| e.to_string())
}

pub fn verify_password(password: &str, hash: &str) -> bool {
    let parsed = match PasswordHash::new(hash) {
        Ok(v) => v,
        Err(_) => return false,
    };

    Argon2::default()
        .verify_password(password.as_bytes(), &parsed)
        .is_ok()
        || argon2_engine()
            .verify_password(password.as_bytes(), &parsed)
            .is_ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hash_and_verify_password() {
        let hash = hash_password("P@ssword123").expect("hash");
        assert!(verify_password("P@ssword123", &hash));
        assert!(!verify_password("wrong", &hash));
    }
}
