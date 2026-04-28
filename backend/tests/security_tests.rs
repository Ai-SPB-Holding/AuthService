use auth_service::security::crypto::TotpEncryption;
use auth_service::security::password::{hash_password, verify_password};
use auth_service::security::totp_impl::{build_totp, check_totp, generate_totp_secret};

/// Must match `test/sql/security_escalation_seed.sql` (security-all harness).
#[test]
fn security_escalation_seed_password_verifies() {
    assert!(verify_password(
        "EscalationProbe2026!Secure",
        "$argon2id$v=19$m=19456,t=2,p=1$jOZW1+L0FdXdHy7VtVMoPQ$aWGXncHsDmXH8aaIkuEIyV+oYu9/JcXSZJ5SKddd54w"
    ));
}

#[test]
fn rejects_invalid_password_hash() {
    assert!(!verify_password("secret", "invalid"));
}

#[test]
fn verifies_hash_correctly() {
    let hash = hash_password("StrongPass!123").expect("hash should be generated");
    assert!(verify_password("StrongPass!123", &hash));
}

#[test]
fn totp_encrypt_roundtrip() {
    let key: [u8; 32] = *b"0123456789abcdef0123456789abcdef";
    let enc = TotpEncryption::from_key(&key, None);
    let (raw, _b32) = generate_totp_secret();
    let blob = enc.seal(&raw).expect("seal");
    let out = enc.open(&blob).expect("open");
    assert_eq!(out, raw);
}

#[test]
fn totp_verify_window() {
    let (raw, _b32) = generate_totp_secret();
    let totp = build_totp(raw, Some("ACME".to_string()), "u@x.y").expect("totp");
    let t = 1_700_000_000u64;
    let g = totp.generate(t);
    assert!(check_totp(&totp, &g, t).expect("ok"));
    assert!(!check_totp(&totp, "000000", t).expect("cmp"));
}
