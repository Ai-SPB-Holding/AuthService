use reqwest::Client;
use serde::{Deserialize, Serialize};

use crate::services::errors::AppError;

#[derive(Clone)]
pub struct OidcProxy {
    client: Client,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OidcMetadata {
    pub issuer: String,
    pub authorization_endpoint: String,
    pub token_endpoint: String,
    pub userinfo_endpoint: String,
    pub jwks_uri: String,
}

impl OidcProxy {
    pub fn new() -> Self {
        Self {
            client: Client::new(),
        }
    }

    pub async fn fetch_metadata(&self, metadata_url: &str) -> Result<OidcMetadata, AppError> {
        self.client
            .get(metadata_url)
            .send()
            .await
            .map_err(|e| AppError::Internal(format!("oidc metadata fetch failed: {e}")))?
            .json::<OidcMetadata>()
            .await
            .map_err(|e| AppError::Internal(format!("oidc metadata parse failed: {e}")))
    }
}
