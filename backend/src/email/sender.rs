use aexmail::{ExmailClient, SendMailRequest};

use crate::config::AppConfig;
use crate::services::errors::AppError;

/// Thin wrapper over `aexmail` for transactional messages.
#[derive(Clone)]
pub struct ExmailMailer {
    client: ExmailClient,
    api_key: String,
    /// From address in config; Exmail may bind sender to the API key account.
    #[allow(dead_code)]
    from_addr: String,
}

impl ExmailMailer {
    pub fn from_config(config: &AppConfig) -> Result<Self, AppError> {
        let client = ExmailClient::new().map_err(|e| AppError::Config(format!("exmail client: {e}")))?;
        Ok(Self {
            client,
            api_key: config.email.api_key_secret.clone(),
            from_addr: config.email.from_address.clone(),
        })
    }

    /// RU copy per product spec. `from` is taken from service account / API; `from_addr` is kept for future API extension.
    pub async fn send_email_confirmation(&self, to: &str, code: &str) -> Result<(), AppError> {
        if self.api_key.is_empty() {
            return Err(AppError::Config("EMAIL__API_KEY_SECRET is not set".to_string()));
        }
        let body = format!(
            "Ваш код подтверждения: {code}\nКод действует 5 минут."
        );
        let req = SendMailRequest {
            to: to.to_string(),
            subject: "Подтверждение email".to_string(),
            body,
        };
        self.client
            .send_mail(&self.api_key, req)
            .await
            .map_err(|e| AppError::Internal(format!("send mail: {e}")))?;
        Ok(())
    }
}
