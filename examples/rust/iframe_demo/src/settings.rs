use std::env;

use authservice_sdk::config::{ClientConfig, Config, TokenEndpointAuthMethod};
use secrecy::SecretString;

use crate::error::DemoError;

#[derive(Clone)]
pub struct DemoSettings {
    pub client_label: &'static str,
    pub listen_port: u16,
    pub auth_public_origin: String,
    pub auth_api_base: String,
    pub oauth_client_id: String,
    pub oauth_client_secret: Option<String>,
    pub tenant_id: String,
    pub jwt_audience: String,
    pub sqlite_path: String,
    pub is_confidential: bool,
}

fn env_trim(name: &str, default: Option<&str>) -> Option<String> {
    env::var(name)
        .ok()
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        .or_else(|| default.map(String::from))
}

impl DemoSettings {
    pub fn load_confidential_9999() -> Result<Self, DemoError> {
        let public = env_trim("AUTH_PUBLIC_ORIGIN", Some("http://localhost:8080")).unwrap();
        let internal = env_trim("AUTH_API_BASE", Some("http://127.0.0.1:8080")).unwrap();
        let cid = env_trim("CLIENT_9999_ID", None).ok_or(DemoError::msg(
            "Set CLIENT_9999_ID, CLIENT_9999_SECRET, TENANT_ID (see .env.example)",
        ))?;
        let secret = env_trim("CLIENT_9999_SECRET", None).ok_or(DemoError::msg(
            "Set CLIENT_9999_SECRET for confidential demo",
        ))?;
        let tid = env_trim("TENANT_ID", None).ok_or(DemoError::msg("Set TENANT_ID"))?;
        let aud = env_trim("JWT_AUDIENCE_9999", None).unwrap_or_else(|| cid.clone());
        let port: u16 = env_trim("DEMO_PORT_9999", Some("9999"))
            .unwrap()
            .parse()
            .map_err(|_| DemoError::msg("DEMO_PORT_9999 must be a number"))?;
        Ok(Self {
            client_label: "confidential @ :9999",
            listen_port: port,
            auth_public_origin: public.trim_end_matches('/').to_string(),
            auth_api_base: internal.trim_end_matches('/').to_string(),
            oauth_client_id: cid,
            oauth_client_secret: Some(secret),
            tenant_id: tid,
            jwt_audience: aud,
            sqlite_path: env_trim("SQLITE_PATH", Some("iframe_demo_rust.sqlite3")).unwrap(),
            is_confidential: true,
        })
    }

    pub fn load_public_9898() -> Result<Self, DemoError> {
        let public = env_trim("AUTH_PUBLIC_ORIGIN", Some("http://localhost:8080")).unwrap();
        let internal = env_trim("AUTH_API_BASE", Some("http://127.0.0.1:8080")).unwrap();
        let cid = env_trim("CLIENT_9898_ID", None).ok_or(DemoError::msg(
            "Set CLIENT_9898_ID, TENANT_ID (see .env.example)",
        ))?;
        let tid = env_trim("TENANT_ID", None).ok_or(DemoError::msg("Set TENANT_ID"))?;
        let aud = env_trim("JWT_AUDIENCE_9898", None).unwrap_or_else(|| cid.clone());
        let port: u16 = env_trim("DEMO_PORT_9898", Some("9898"))
            .unwrap()
            .parse()
            .map_err(|_| DemoError::msg("DEMO_PORT_9898 must be a number"))?;
        Ok(Self {
            client_label: "public @ :9898",
            listen_port: port,
            auth_public_origin: public.trim_end_matches('/').to_string(),
            auth_api_base: internal.trim_end_matches('/').to_string(),
            oauth_client_id: cid,
            oauth_client_secret: None,
            tenant_id: tid,
            jwt_audience: aud,
            sqlite_path: env_trim("SQLITE_PATH", Some("iframe_demo_rust.sqlite3")).unwrap(),
            is_confidential: false,
        })
    }

    /// Builds [`Config`] for [`OAuth2Client`] (discovery + token endpoint).
    pub fn sdk_config(&self) -> Result<Config, DemoError> {
        let server_metadata_url = format!(
            "{}/.well-known/openid-configuration",
            self.auth_api_base.trim_end_matches('/')
        );
        let redirect_uri = env_trim(
            "REDIRECT_URL",
            Some(&format!(
                "http://127.0.0.1:{}/oauth/callback",
                self.listen_port
            )),
        )
        .unwrap();
        url::Url::parse(&redirect_uri).map_err(|e| DemoError::Msg(e.to_string()))?;
        let client_secret = self
            .oauth_client_secret
            .as_ref()
            .filter(|s| !s.is_empty())
            .map(|s| SecretString::new(s.clone().into()));
        let client = ClientConfig {
            client_id: self.oauth_client_id.clone(),
            redirect_uri,
            client_secret,
            token_endpoint_auth_method: TokenEndpointAuthMethod::Auto,
        };
        client
            .validate()
            .map_err(|e| DemoError::Msg(e.to_string()))?;
        Ok(Config {
            client,
            server_metadata_url,
            default_audience: Some(self.jwt_audience.clone()),
        })
    }
}
