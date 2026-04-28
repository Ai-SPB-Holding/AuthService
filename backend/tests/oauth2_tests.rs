//! OAuth2 / PKCE helpers (no DB — safe for CI without Postgres).

use auth_service::repositories::user_repository::PostgresUserRepository;
use auth_service::security::jwt::AccessClaims;
use auth_service::services::auth_service::AuthService;
use auth_service::services::client_oauth::{enforce_token_endpoint_auth_method, ClientCredentialsSource};
use auth_service::services::errors::AppError;

#[test]
fn pkce_s256_roundtrip() {
    let verifier = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";
    let challenge = "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM";
    assert!(AuthService::<PostgresUserRepository>::verify_pkce_s256(verifier, challenge));
}

#[test]
fn pkce_s256_rejects_wrong_verifier() {
    assert!(!AuthService::<PostgresUserRepository>::verify_pkce_s256(
        "wrong",
        "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM"
    ));
}

#[test]
fn access_claims_email_verified_defaults_false_when_omitted() {
    let j = r#"{"sub":"u","exp":9999999999,"iss":"i","aud":"a","roles":[],"permissions":[],"tenant_id":"t"}"#;
    let c: AccessClaims = serde_json::from_str(j).expect("deserialize");
    assert!(!c.email_verified);
}

#[test]
fn token_endpoint_auth_method_basic_requires_basic_header() {
    assert!(enforce_token_endpoint_auth_method(
        "client_secret_basic",
        true,
        ClientCredentialsSource::BasicHeader
    )
    .is_ok());
    let err = enforce_token_endpoint_auth_method(
        "client_secret_basic",
        true,
        ClientCredentialsSource::PostBody,
    )
    .expect_err("post should fail");
    assert!(matches!(err, AppError::Validation(_)));
}

#[test]
fn token_endpoint_auth_method_post_requires_post_body() {
    assert!(enforce_token_endpoint_auth_method(
        "client_secret_post",
        true,
        ClientCredentialsSource::PostBody
    )
    .is_ok());
    let err = enforce_token_endpoint_auth_method(
        "client_secret_post",
        true,
        ClientCredentialsSource::BasicHeader,
    )
    .expect_err("basic should fail");
    assert!(matches!(err, AppError::Validation(_)));
}

#[test]
fn token_endpoint_auth_rejects_unimplemented_methods() {
    let err = enforce_token_endpoint_auth_method(
        "private_key_jwt",
        true,
        ClientCredentialsSource::BasicHeader,
    )
    .expect_err("not implemented");
    assert!(matches!(err, AppError::Validation(_)));
}
