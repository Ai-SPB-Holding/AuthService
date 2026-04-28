use std::time::Duration;

use config::{Config, Environment};
use serde::Deserialize;

#[derive(Clone, Deserialize)]
pub struct AppConfig {
    pub server: ServerConfig,
    pub database: DatabaseConfig,
    pub redis: RedisConfig,
    pub auth: AuthConfig,
    pub oidc: OidcConfig,
    #[serde(default)]
    pub cors: CorsConfig,
    #[serde(default)]
    pub metrics: MetricsConfig,
    #[serde(default)]
    pub email: EmailConfig,
    #[serde(default)]
    pub totp: TotpConfig,
}

#[derive(Clone, Debug, Deserialize)]
pub struct ServerConfig {
    #[serde(default = "default_host")]
    pub host: String,
    #[serde(default = "default_port")]
    pub port: u16,
    #[serde(default = "default_issuer")]
    pub issuer: String,
    /// `Cross-Origin-Resource-Policy` header value (e.g. `cross-origin`, `same-origin`). Empty = omit header.
    #[serde(default = "default_cross_origin_resource_policy")]
    pub cross_origin_resource_policy: String,
    /// When true, send `X-Frame-Options: DENY` on all responses (typical for JSON APIs).
    #[serde(default = "default_true")]
    pub x_frame_options_deny: bool,
}

#[derive(Clone, Debug, Deserialize)]
pub struct DatabaseConfig {
    pub url: String,
    #[serde(default = "default_db_pool")]
    pub pool_size: u32,
}

#[derive(Clone, Debug, Deserialize)]
pub struct RedisConfig {
    pub url: String,
    #[serde(default = "default_redis_prefix")]
    pub prefix: String,
}

impl RedisConfig {
    /// Prefix a raw redis key with `REDIS__PREFIX` (if set).
    ///
    /// Behavior:
    /// - empty prefix => returns `raw` unchanged
    /// - ensures prefix ends with `:`
    /// - strips leading `:` from `raw` to avoid `::`
    pub fn key(&self, raw: &str) -> String {
        let raw = raw.trim();
        let p = self.prefix.trim();
        if p.is_empty() {
            return raw.to_string();
        }
        let mut pref = p.to_string();
        if !pref.ends_with(':') {
            pref.push(':');
        }
        let raw = raw.trim_start_matches(':');
        format!("{pref}{raw}")
    }
}

#[derive(Clone, Debug, Deserialize)]
pub struct AuthConfig {
    pub jwt_private_key_pem: String,
    pub jwt_public_key_pem: String,
    /// Optional previous RSA public PEM (JWKS + verification) for key rotation.
    #[serde(default)]
    pub jwt_previous_public_key_pem: Option<String>,
    /// `kid` for the previous key in JWKS (default `rsa-key-0`).
    #[serde(default)]
    pub jwt_previous_kid: Option<String>,
    #[serde(default = "default_access_ttl")]
    pub access_ttl_seconds: u64,
    #[serde(default = "default_refresh_ttl")]
    pub refresh_ttl_seconds: u64,
    /// Upper bound for per-client `clients.access_ttl_seconds` (operator cap; DB allows up to 86400).
    #[serde(default = "default_max_client_access_ttl_cap")]
    pub max_client_access_ttl_seconds: u64,
    /// Upper bound for per-client `clients.refresh_ttl_seconds` (operator cap; DB allows up to 7776000).
    #[serde(default = "default_max_client_refresh_ttl_cap")]
    pub max_client_refresh_ttl_seconds: u64,
    pub cookie_secret: Option<String>,
    /// `aud` value required for admin API tokens (`/admin/*`).
    #[serde(default = "default_admin_api_audience")]
    pub admin_api_audience: String,
    /// When `true`, password login requires TOTP enrollment and verification for every user.
    #[serde(default)]
    pub require_login_2fa: bool,
    /// Path to `.env` updated by `PUT /admin/settings` (default `.env`).
    #[serde(default = "default_auth_env_file_path")]
    pub env_file_path: String,
    /// Comma-separated `users.id` (UUID) allowlist: these admins see **all tenants** in list/read
    /// and aggregate metrics (auth-service deployment operator), not only `tenant_id` from the JWT.
    #[serde(default)]
    pub global_admin_user_ids: String,
    /// One-time bootstrap token: allows creating the very first admin when there are zero users.
    /// Used by `POST /bootstrap/admin` (must be disabled/removed after bootstrap).
    #[serde(default)]
    pub bootstrap_admin_token: Option<String>,
    /// Second allowlist, same meaning as [AUTH__GLOBAL_ADMIN_USER_IDS] — `AUTH__AUTH_SERVICE_DEPLOYMENT_ADMINS`.
    #[serde(default)]
    pub auth_service_deployment_admins: String,
    /// Include `'self'` in `Content-Security-Policy: frame-ancestors` for `/embedded-login`.
    #[serde(default = "default_true")]
    pub embedded_csp_include_self: bool,
    /// Allow `/embedded-login` when `Referer`/`Origin` does not match parent origins (local dev only).
    #[serde(default)]
    pub embedded_relax_parent_origin_check: bool,
    /// Max `POST /api/login` attempts per IP per window (Redis; 0 = disable).
    #[serde(default = "default_embedded_ip_limit")]
    pub embedded_login_ip_max_attempts: u32,
    /// Window seconds for [`AuthConfig::embedded_login_ip_max_attempts`].
    #[serde(default = "default_embedded_ip_window_secs")]
    pub embedded_login_ip_window_seconds: u64,
    /// When `false` (default), embedded `/api/*` IP rate limits use the TCP client address only.
    /// Set `true` only behind a reverse proxy that **replaces** client `X-Forwarded-For` with the real hop
    /// (never forward untrusted XFF from browsers directly to this service).
    #[serde(default)]
    pub trust_x_forwarded_for: bool,
    /// When `true`, allows deprecated OAuth2 resource-owner password grant on `POST /token`.
    #[serde(default)]
    pub allow_resource_owner_password_grant: bool,
    /// Max `POST /token` attempts per client IP per window (0 = disable rate limit).
    #[serde(default = "default_oauth_token_ip_limit")]
    pub oauth_token_ip_max_attempts: u32,
    #[serde(default = "default_oauth_token_ip_window_secs")]
    pub oauth_token_ip_window_seconds: u64,
    /// Max `GET /authorize` requests per IP per window (0 = disable).
    #[serde(default = "default_oauth_authorize_ip_limit")]
    pub oauth_authorize_ip_max_attempts: u32,
    #[serde(default = "default_oauth_authorize_ip_window_secs")]
    pub oauth_authorize_ip_window_seconds: u64,
}

#[derive(Clone, Debug, Deserialize)]
pub struct OidcConfig {
    pub keycloak_client_id: String,
    pub keycloak_client_secret: String,
    /// Legacy default redirect (prefer per-client `allowed_redirect_uris`).
    pub redirect_url: String,
    pub server_metadata_url: Option<String>,
    /// If set, unauthenticated `GET /authorize` redirects here with `?return_to=...`
    #[serde(default)]
    pub login_url: Option<String>,
    /// Default authorization code lifetime (seconds).
    #[serde(default = "default_auth_code_ttl")]
    pub auth_code_ttl_seconds: u64,
    /// When `true` (default), enforces per-client `mfa_policy` on password login, `/token` password grant, and `GET /authorize`.
    #[serde(default = "default_true")]
    pub client_mfa_enforce: bool,
    /// When `OIDC__SERVER_METADATA_URL` is set but the upstream fetch fails, serve the built-in discovery document instead of 502.
    /// Use only if you accept masking misconfiguration; default false.
    #[serde(default)]
    pub metadata_proxy_fallback: bool,
}

/// CORS: comma-separated origins, e.g. `http://localhost:5173,https://app.example.com`. Empty = no browser CORS.
#[derive(Clone, Debug, Deserialize, Default)]
pub struct CorsConfig {
    #[serde(default)]
    pub allowed_origins: String,
}

/// Protect `/metrics` with `Authorization: Bearer <token>` when `bypass_token` is set.
#[derive(Clone, Debug, Deserialize, Default)]
pub struct MetricsConfig {
    #[serde(default)]
    pub bypass_token: Option<String>,
}

/// Email (Exmail API) + verification codes.
#[derive(Clone, Debug, Deserialize)]
pub struct EmailConfig {
    /// Secret for `X-API-Key` (maps from `EMAIL__API_KEY_SECRET`).
    #[serde(default)]
    pub api_key_secret: String,
    /// Optional explicit From header if API supports it; otherwise set on provider side.
    #[serde(default = "default_email_from")]
    pub from_address: String,
    #[serde(default = "default_code_ttl_mins")]
    pub code_ttl_minutes: u64,
    #[serde(default = "default_max_sends_per_hour")]
    pub max_sends_per_hour: u32,
    #[serde(default = "default_max_verify_attempts")]
    pub max_verify_attempts: u32,
    /// Appended to the code before Argon2 hashing.
    #[serde(default)]
    pub code_pepper: Option<String>,
}

impl Default for EmailConfig {
    fn default() -> Self {
        Self {
            api_key_secret: String::new(),
            from_address: default_email_from(),
            code_ttl_minutes: default_code_ttl_mins(),
            max_sends_per_hour: default_max_sends_per_hour(),
            max_verify_attempts: default_max_verify_attempts(),
            code_pepper: None,
        }
    }
}

#[derive(Clone, Debug, Deserialize)]
pub struct TotpConfig {
    /// Base64-encoded 32-byte key for AES-256-GCM (`TOTP__ENCRYPTION_KEY_B64`).
    #[serde(default)]
    pub encryption_key_b64: String,
    /// Optional previous key (same format) for decrypting existing secrets during rotation.
    #[serde(default)]
    pub encryption_key_previous_b64: Option<String>,
    /// Display name in Authenticator (issuer).
    #[serde(default = "default_totp_issuer")]
    pub issuer_name: String,
    #[serde(default = "default_mfa_step_up_ttl")]
    pub mfa_step_up_ttl_seconds: u64,
    #[serde(default = "default_email_jwt_ttl")]
    pub email_verification_jwt_ttl_seconds: u64,
}

impl Default for TotpConfig {
    fn default() -> Self {
        Self {
            encryption_key_b64: String::new(),
            encryption_key_previous_b64: None,
            issuer_name: default_totp_issuer(),
            mfa_step_up_ttl_seconds: default_mfa_step_up_ttl(),
            email_verification_jwt_ttl_seconds: default_email_jwt_ttl(),
        }
    }
}

impl std::fmt::Debug for AppConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AppConfig")
            .field("server", &self.server)
            .field("database", &"<redacted>")
            .field("redis", &"<redacted>")
            .field("auth", &"<redacted>")
            .field("oidc", &"<redacted>")
            .field("cors", &self.cors)
            .field("metrics", &self.metrics)
            .field("email", &"<redacted>")
            .field("totp", &"<redacted>")
            .finish()
    }
}

impl AppConfig {
    /// `AUTH__GLOBAL_ADMIN_USER_IDS` and/or `AUTH__AUTH_SERVICE_DEPLOYMENT_ADMINS` — if JWT `sub` is listed,
    /// admin API list/read/aggregate is not restricted to the token’s tenant (full deployment / «auth-service admin»).
    pub fn is_global_service_admin(&self, sub_user_id: &str) -> bool {
        let sub = sub_user_id.trim();
        if sub.is_empty() {
            return false;
        }
        for csv in [
            self.auth.global_admin_user_ids.as_str(),
            self.auth.auth_service_deployment_admins.as_str(),
        ] {
            if !csv.trim().is_empty() && csv.split(',').any(|p| p.trim() == sub) {
                return true;
            }
        }
        false
    }

    pub fn from_env() -> Result<Self, config::ConfigError> {
        dotenvy::dotenv().ok();

        let cfg = Config::builder()
            .add_source(Environment::default().separator("__"))
            .build()?;

        cfg.try_deserialize()
    }

    /// Parsed CORS allowlist.
    pub fn cors_origin_list(&self) -> Vec<String> {
        self.cors
            .allowed_origins
            .split(',')
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty())
            .collect()
    }

    pub fn access_ttl(&self) -> Duration {
        Duration::from_secs(self.auth.access_ttl_seconds)
    }

    pub fn refresh_ttl(&self) -> Duration {
        Duration::from_secs(self.auth.refresh_ttl_seconds)
    }

    /// `Secure` flag for embedded CSRF cookie when issuer is HTTPS.
    pub fn embedded_csrf_cookie_secure(&self) -> bool {
        self.server
            .issuer
            .trim_start()
            .to_ascii_lowercase()
            .starts_with("https://")
    }
}

fn default_host() -> String {
    "0.0.0.0".to_string()
}

fn default_port() -> u16 {
    8080
}

fn default_db_pool() -> u32 {
    20
}

fn default_redis_prefix() -> String {
    String::new()
}

fn default_access_ttl() -> u64 {
    900
}

fn default_refresh_ttl() -> u64 {
    60 * 60 * 24 * 14
}

fn default_max_client_access_ttl_cap() -> u64 {
    86400
}

fn default_max_client_refresh_ttl_cap() -> u64 {
    7776000
}

fn default_issuer() -> String {
    "https://auth.local".to_string()
}

fn default_cross_origin_resource_policy() -> String {
    "cross-origin".to_string()
}

fn default_email_from() -> String {
    "noreply@24ai-spbconsult.ru".to_string()
}

fn default_code_ttl_mins() -> u64 {
    5
}

fn default_max_sends_per_hour() -> u32 {
    5
}

fn default_max_verify_attempts() -> u32 {
    5
}

fn default_totp_issuer() -> String {
    "AuthService".to_string()
}

fn default_mfa_step_up_ttl() -> u64 {
    300
}

fn default_email_jwt_ttl() -> u64 {
    900
}

fn default_admin_api_audience() -> String {
    "auth-service".to_string()
}

fn default_auth_code_ttl() -> u64 {
    300
}

fn default_true() -> bool {
    true
}

fn default_auth_env_file_path() -> String {
    ".env".to_string()
}

fn default_embedded_ip_limit() -> u32 {
    60
}

fn default_embedded_ip_window_secs() -> u64 {
    300
}

fn default_oauth_token_ip_limit() -> u32 {
    120
}

fn default_oauth_token_ip_window_secs() -> u64 {
    60
}

fn default_oauth_authorize_ip_limit() -> u32 {
    240
}

fn default_oauth_authorize_ip_window_secs() -> u64 {
    60
}
