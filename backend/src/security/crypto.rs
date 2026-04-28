//! AES-256-GCM encryption for TOTP secrets at rest (nonce + ciphertext+tag concatenated).

use aes_gcm::aead::{Aead, KeyInit};
use aes_gcm::{Aes256Gcm, Nonce};
use rand::RngCore;
use rand::rngs::OsRng;

use crate::services::errors::AppError;

const NONCE_LEN: usize = 12;

/// Key material: 32 bytes (AES-256). Optional previous key for rotation (decrypt-only fallback).
pub struct TotpEncryption {
    primary: Aes256Gcm,
    previous: Option<Aes256Gcm>,
}

impl TotpEncryption {
    pub fn from_key(primary: &[u8; 32], previous: Option<&[u8; 32]>) -> Self {
        let primary = Aes256Gcm::new_from_slice(primary).expect("valid key length");
        let previous = previous.map(|k| Aes256Gcm::new_from_slice(k).expect("valid key length"));
        Self { primary, previous }
    }

    /// Returns `nonce || ciphertext` where ciphertext includes GCM tag.
    pub fn seal(&self, plaintext: &[u8]) -> Result<Vec<u8>, AppError> {
        let mut nonce = [0u8; NONCE_LEN];
        OsRng.fill_bytes(&mut nonce);
        let n = Nonce::from_slice(&nonce);
        let buf = plaintext.to_vec();
        let ct = self
            .primary
            .encrypt(n, buf.as_ref())
            .map_err(|_| AppError::Internal("totp encrypt failed".to_string()))?;
        let mut out = Vec::with_capacity(NONCE_LEN + ct.len());
        out.extend_from_slice(&nonce);
        out.extend_from_slice(&ct);
        Ok(out)
    }

    fn open_with_cipher(cipher: &Aes256Gcm, blob: &[u8]) -> Result<Vec<u8>, AppError> {
        if blob.len() <= NONCE_LEN {
            return Err(AppError::Unauthorized);
        }
        let (n, ct) = blob.split_at(NONCE_LEN);
        let nonce = Nonce::from_slice(n);
        cipher
            .decrypt(nonce, ct)
            .map_err(|_| AppError::Unauthorized)
    }

    pub fn open(&self, blob: &[u8]) -> Result<Vec<u8>, AppError> {
        match Self::open_with_cipher(&self.primary, blob) {
            Ok(p) => Ok(p),
            Err(_) => {
                if let Some(prev) = &self.previous {
                    Self::open_with_cipher(prev, blob)
                } else {
                    Err(AppError::Unauthorized)
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn seal_open_roundtrip() {
        let key: [u8; 32] = [7u8; 32];
        let enc = TotpEncryption::from_key(&key, None);
        let p = b"twenty-byte-totp!!";
        let blob = enc.seal(p).unwrap();
        assert_eq!(enc.open(&blob).unwrap(), p);
    }

    #[test]
    fn previous_key_decrypts() {
        let k1: [u8; 32] = [1u8; 32];
        let k2: [u8; 32] = [2u8; 32];
        let old = TotpEncryption::from_key(&k1, None);
        let blob = old.seal(b"secret").unwrap();
        let rotated = TotpEncryption::from_key(&k2, Some(&k1));
        assert_eq!(rotated.open(&blob).unwrap(), b"secret".as_slice());
    }
}
