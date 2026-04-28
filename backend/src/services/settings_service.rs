//! Read/update `.env` for operator-controlled auth-service settings.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use base64::Engine;
use uuid::Uuid;

use crate::config::AppConfig;
use crate::http::handlers::admin_portal::insert_audit_log;
use crate::services::errors::AppError;
use sqlx::PgPool;

fn unescape_env_value(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    let mut it = s.chars().peekable();
    while let Some(c) = it.next() {
        if c == '\\' {
            match it.next() {
                Some('n') => out.push('\n'),
                Some('r') => out.push('\r'),
                Some('t') => out.push('\t'),
                Some('\\') => out.push('\\'),
                Some('"') => out.push('"'),
                Some(x) => {
                    out.push('\\');
                    out.push(x);
                }
                None => out.push('\\'),
            }
        } else {
            out.push(c);
        }
    }
    out
}

/// Format a single key=value line for `.env`.
pub fn format_env_line(key: &str, value: &str) -> String {
    let needs_quote = value.contains('\n')
        || value.contains(' ')
        || value.contains('"')
        || value.is_empty()
        || value.contains('\\');
    if needs_quote {
        let escaped = value
            .replace('\\', "\\\\")
            .replace('"', "\\\"")
            .replace('\n', "\\n")
            .replace('\r', "\\r");
        format!("{key}=\"{escaped}\"")
    } else {
        format!("{key}={value}")
    }
}

fn parse_env_lines(content: &str) -> BTreeMap<String, String> {
    let mut map = BTreeMap::new();
    for line in content.lines() {
        let t = line.trim();
        if t.is_empty() || t.starts_with('#') {
            continue;
        }
        let Some((raw_k, raw_v)) = t.split_once('=') else {
            continue;
        };
        let k = raw_k.trim().to_string();
        let v = raw_v.trim();
        let val = if v.len() >= 2 && v.starts_with('"') && v.ends_with('"') {
            unescape_env_value(&v[1..v.len() - 1])
        } else if v.len() >= 2 && v.starts_with('\'') && v.ends_with('\'') {
            v[1..v.len() - 1].to_string()
        } else {
            v.to_string()
        };
        map.insert(k, val);
    }
    map
}

fn upsert_env_line(content: &str, key: &str, value: &str) -> String {
    let new_line = format_env_line(key, value);
    let mut out_lines: Vec<String> = Vec::new();
    let mut seen = false;
    for line in content.lines() {
        let t = line.trim();
        if t.starts_with('#') || t.is_empty() {
            out_lines.push(line.to_string());
            continue;
        }
        if let Some((raw_k, _)) = t.split_once('=') {
            if raw_k.trim() == key {
                out_lines.push(new_line.clone());
                seen = true;
                continue;
            }
        }
        out_lines.push(line.to_string());
    }
    if !seen {
        if !out_lines.is_empty()
            && !out_lines
                .last()
                .map(|s| s.as_str())
                .unwrap_or("")
                .is_empty()
        {
            out_lines.push(String::new());
        }
        out_lines.push(new_line);
    }
    let mut s = out_lines.join("\n");
    if !s.ends_with('\n') {
        s.push('\n');
    }
    s
}

fn atomic_write(path: &Path, content: &str) -> Result<(), AppError> {
    let dir = path.parent().filter(|p| !p.as_os_str().is_empty());
    let tmp_path = if let Some(d) = dir {
        d.join(format!(".env.tmp.{}", std::process::id()))
    } else {
        PathBuf::from(format!(".env.tmp.{}", std::process::id()))
    };

    std::fs::write(&tmp_path, content).map_err(|e| {
        AppError::Internal(format!("write temp env file {}: {e}", tmp_path.display()))
    })?;
    std::fs::rename(&tmp_path, path).map_err(|e| {
        let _ = std::fs::remove_file(&tmp_path);
        AppError::Internal(format!("replace env file {}: {e}", path.display()))
    })?;
    Ok(())
}

fn validate_pem_private(s: &str) -> Result<(), AppError> {
    if !s.contains("BEGIN") || !s.contains("PRIVATE KEY") {
        return Err(AppError::Validation(
            "AUTH__JWT_PRIVATE_KEY_PEM must be a PEM private key".to_string(),
        ));
    }
    Ok(())
}

fn validate_pem_public(s: &str) -> Result<(), AppError> {
    if !s.contains("BEGIN") || !s.contains("PUBLIC KEY") {
        return Err(AppError::Validation(
            "AUTH__JWT_PUBLIC_KEY_PEM must be a PEM public key".to_string(),
        ));
    }
    Ok(())
}

fn validate_totp_key_b64(s: &str) -> Result<(), AppError> {
    let raw = base64::engine::general_purpose::STANDARD
        .decode(s.trim().as_bytes())
        .map_err(|e| AppError::Validation(format!("TOTP__ENCRYPTION_KEY_B64: {e}")))?;
    if raw.len() != 32 {
        return Err(AppError::Validation(
            "TOTP__ENCRYPTION_KEY_B64 must decode to exactly 32 bytes".to_string(),
        ));
    }
    Ok(())
}

fn validate_issuer(s: &str) -> Result<(), AppError> {
    let t = s.trim();
    if t.is_empty() {
        return Err(AppError::Validation(
            "SERVER__ISSUER cannot be empty".to_string(),
        ));
    }
    if !(t.starts_with("http://") || t.starts_with("https://")) {
        return Err(AppError::Validation(
            "SERVER__ISSUER must be an http(s) URL".to_string(),
        ));
    }
    Ok(())
}

#[derive(Clone, serde::Serialize)]
pub struct SettingsView {
    pub require_login_2fa: bool,
    pub client_mfa_enforce: bool,
    /// Public URL / issuer (`SERVER__ISSUER`).
    pub api_domain: String,
    pub jwt_private_key_pem_set: bool,
    pub jwt_public_key_pem_set: bool,
    pub cookie_secret_set: bool,
    pub totp_encryption_key_b64_set: bool,
    pub env_file_path: String,
    #[serde(default)]
    pub restart_required_note: Option<String>,
    /// Server default access JWT TTL (`AUTH__ACCESS_TTL_SECONDS`).
    pub default_access_ttl_seconds: u64,
    /// Server default refresh token TTL (`AUTH__REFRESH_TTL_SECONDS`).
    pub default_refresh_ttl_seconds: u64,
    /// Max allowed per-client access TTL (`AUTH__MAX_CLIENT_ACCESS_TTL_SECONDS`).
    pub max_client_access_ttl_seconds: u64,
    /// Max allowed per-client refresh TTL (`AUTH__MAX_CLIENT_REFRESH_TTL_SECONDS`).
    pub max_client_refresh_ttl_seconds: u64,
}

#[derive(Clone, serde::Deserialize)]
pub struct SettingsUpdate {
    pub require_login_2fa: Option<bool>,
    pub client_mfa_enforce: Option<bool>,
    pub api_domain: Option<String>,
    pub private_key_pem: Option<String>,
    pub public_key_pem: Option<String>,
    pub cookie_secret: Option<String>,
    pub totp_encryption_key_b64: Option<String>,
    /// Required when changing sensitive values and 2FA is required.
    pub totp_code: Option<String>,
}

pub fn load_settings_view(config: &AppConfig, env_path: &Path) -> Result<SettingsView, AppError> {
    let mut req_2fa = config.auth.require_login_2fa;
    let mut client_mfa = config.oidc.client_mfa_enforce;
    let mut issuer = config.server.issuer.clone();
    let mut pk_set = !config.auth.jwt_private_key_pem.trim().is_empty();
    let mut pub_set = !config.auth.jwt_public_key_pem.trim().is_empty();
    let mut cookie_set = config
        .auth
        .cookie_secret
        .as_ref()
        .map(|s| !s.trim().is_empty())
        .unwrap_or(false);
    let mut totp_set = !config.totp.encryption_key_b64.trim().is_empty();

    if let Ok(content) = std::fs::read_to_string(env_path) {
        let m = parse_env_lines(&content);
        if let Some(v) = m.get("AUTH__REQUIRE_LOGIN_2FA") {
            req_2fa = v == "1" || v.eq_ignore_ascii_case("true");
        }
        if let Some(v) = m.get("OIDC__CLIENT_MFA_ENFORCE") {
            client_mfa = v == "1" || v.eq_ignore_ascii_case("true");
        }
        if let Some(v) = m.get("SERVER__ISSUER") {
            issuer = v.clone();
        }
        if let Some(v) = m.get("AUTH__JWT_PRIVATE_KEY_PEM") {
            pk_set = !v.trim().is_empty();
        }
        if let Some(v) = m.get("AUTH__JWT_PUBLIC_KEY_PEM") {
            pub_set = !v.trim().is_empty();
        }
        if let Some(v) = m.get("AUTH__COOKIE_SECRET") {
            cookie_set = !v.trim().is_empty();
        }
        if let Some(v) = m.get("TOTP__ENCRYPTION_KEY_B64") {
            totp_set = !v.trim().is_empty();
        }
    }

    Ok(SettingsView {
        require_login_2fa: req_2fa,
        client_mfa_enforce: client_mfa,
        api_domain: issuer,
        jwt_private_key_pem_set: pk_set,
        jwt_public_key_pem_set: pub_set,
        cookie_secret_set: cookie_set,
        totp_encryption_key_b64_set: totp_set,
        env_file_path: env_path.display().to_string(),
        restart_required_note: None,
        default_access_ttl_seconds: config.auth.access_ttl_seconds,
        default_refresh_ttl_seconds: config.auth.refresh_ttl_seconds,
        max_client_access_ttl_seconds: config.auth.max_client_access_ttl_seconds,
        max_client_refresh_ttl_seconds: config.auth.max_client_refresh_ttl_seconds,
    })
}

/// Returns true if any sensitive env keys would change.
pub fn would_touch_sensitive(update: &SettingsUpdate) -> bool {
    if update
        .api_domain
        .as_ref()
        .is_some_and(|s| !s.trim().is_empty())
    {
        return true;
    }
    update
        .private_key_pem
        .as_ref()
        .is_some_and(|s| !s.trim().is_empty())
        || update
            .public_key_pem
            .as_ref()
            .is_some_and(|s| !s.trim().is_empty())
        || update
            .cookie_secret
            .as_ref()
            .is_some_and(|s| !s.trim().is_empty())
        || update
            .totp_encryption_key_b64
            .as_ref()
            .is_some_and(|s| !s.trim().is_empty())
}

pub async fn apply_settings_update(
    config: &AppConfig,
    pool: &PgPool,
    tenant_id: Uuid,
    actor_user_id: Uuid,
    update: SettingsUpdate,
) -> Result<(SettingsView, bool), AppError> {
    let env_path = PathBuf::from(config.auth.env_file_path.trim());
    let path = if env_path.is_absolute() {
        env_path
    } else {
        std::env::current_dir()
            .map_err(|e| AppError::Internal(e.to_string()))?
            .join(env_path)
    };

    let mut content = if path.exists() {
        std::fs::read_to_string(&path)
            .map_err(|e| AppError::Internal(format!("read {}: {e}", path.display())))?
    } else {
        String::new()
    };

    let mut changed_keys: Vec<&'static str> = Vec::new();

    if let Some(v) = update.require_login_2fa {
        let s = if v { "true" } else { "false" };
        content = upsert_env_line(&content, "AUTH__REQUIRE_LOGIN_2FA", s);
        changed_keys.push("AUTH__REQUIRE_LOGIN_2FA");
    }
    if let Some(v) = update.client_mfa_enforce {
        let s = if v { "true" } else { "false" };
        content = upsert_env_line(&content, "OIDC__CLIENT_MFA_ENFORCE", s);
        changed_keys.push("OIDC__CLIENT_MFA_ENFORCE");
    }
    if let Some(ref v) = update.api_domain {
        let s = v.trim();
        validate_issuer(s)?;
        content = upsert_env_line(&content, "SERVER__ISSUER", s);
        changed_keys.push("SERVER__ISSUER");
    }
    if let Some(ref v) = update.private_key_pem {
        if !v.trim().is_empty() {
            validate_pem_private(v.trim())?;
            content = upsert_env_line(&content, "AUTH__JWT_PRIVATE_KEY_PEM", v.trim());
            changed_keys.push("AUTH__JWT_PRIVATE_KEY_PEM");
        }
    }
    if let Some(ref v) = update.public_key_pem {
        if !v.trim().is_empty() {
            validate_pem_public(v.trim())?;
            content = upsert_env_line(&content, "AUTH__JWT_PUBLIC_KEY_PEM", v.trim());
            changed_keys.push("AUTH__JWT_PUBLIC_KEY_PEM");
        }
    }
    if let Some(ref v) = update.cookie_secret {
        if !v.trim().is_empty() {
            if v.trim().len() < 32 {
                return Err(AppError::Validation(
                    "AUTH__COOKIE_SECRET must be at least 32 characters (matches HS256 idp_session requirement)"
                        .to_string(),
                ));
            }
            content = upsert_env_line(&content, "AUTH__COOKIE_SECRET", v.trim());
            changed_keys.push("AUTH__COOKIE_SECRET");
        }
    }
    if let Some(ref v) = update.totp_encryption_key_b64 {
        if !v.trim().is_empty() {
            validate_totp_key_b64(v.trim())?;
            content = upsert_env_line(&content, "TOTP__ENCRYPTION_KEY_B64", v.trim());
            changed_keys.push("TOTP__ENCRYPTION_KEY_B64");
        }
    }

    if changed_keys.is_empty() {
        let view = load_settings_view(config, &path)?;
        return Ok((view, false));
    }

    atomic_write(&path, &content)?;

    let mut view = load_settings_view(config, &path)?;
    view.restart_required_note =
        Some("Process must be restarted to apply .env changes to the running service.".to_string());

    insert_audit_log(
        pool,
        tenant_id,
        Some(actor_user_id),
        "settings_env_update",
        Some(&path.display().to_string()),
        Some(serde_json::json!({ "keys": changed_keys })),
    )
    .await;

    Ok((view, true))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn format_env_line_escapes_newlines() {
        let pem = "-----BEGIN X-----\nABC\n-----END X-----";
        let line = format_env_line("AUTH__JWT_PRIVATE_KEY_PEM", pem);
        assert!(line.starts_with("AUTH__JWT_PRIVATE_KEY_PEM=\""));
        assert!(line.contains("\\n"));
    }

    #[test]
    fn upsert_replaces_existing_key() {
        let content = "FOO=bar\nAUTH__COOKIE_SECRET=old\nBAZ=qux\n";
        let next = upsert_env_line(content, "AUTH__COOKIE_SECRET", "newsecretvalue");
        assert!(
            next.contains("AUTH__COOKIE_SECRET=newsecretvalue")
                || next.contains("AUTH__COOKIE_SECRET=\"newsecretvalue\"")
        );
        assert!(!next.contains("AUTH__COOKIE_SECRET=old"));
    }
}
