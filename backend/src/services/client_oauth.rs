//! OAuth client resolution and confidential-client secret verification (multi-tenant safe).

use sqlx::{PgPool, Row};
use uuid::Uuid;

use crate::security::password;
use crate::services::errors::AppError;

/// How client credentials were supplied at the token endpoint.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ClientCredentialsSource {
    None,
    BasicHeader,
    PostBody,
}

/// Verify Argon2 `client_secret_argon2` only (plaintext column removed in migration 0017).
pub fn verify_confidential_client_secret(row: &sqlx::postgres::PgRow, provided: &str) -> bool {
    let h: Option<String> = row.try_get("client_secret_argon2").ok().flatten();
    h.as_ref()
        .is_some_and(|h| !h.is_empty() && password::verify_password(provided, h))
}

/// Enforce `token_endpoint_auth_method` vs how credentials were sent.
pub fn enforce_token_endpoint_auth_method(
    method: &str,
    confidential: bool,
    source: ClientCredentialsSource,
) -> Result<(), AppError> {
    if !confidential {
        if method != "none" {
            return Err(AppError::Validation(
                "public clients must use token_endpoint_auth_method=none".to_string(),
            ));
        }
        return Ok(());
    }
    match method {
        "client_secret_basic" => {
            if source != ClientCredentialsSource::BasicHeader {
                return Err(AppError::Validation(
                    "client credentials must be sent using HTTP Basic authentication for this client"
                        .to_string(),
                ));
            }
        }
        "client_secret_post" => {
            if source != ClientCredentialsSource::PostBody {
                return Err(AppError::Validation(
                    "client_id and client_secret must be sent in the POST body for this client"
                        .to_string(),
                ));
            }
        }
        "none" => {
            return Err(AppError::Validation(
                "confidential clients cannot use token_endpoint_auth_method=none".to_string(),
            ));
        }
        "private_key_jwt" | "tls_client_auth" => {
            return Err(AppError::Validation(format!(
                "token_endpoint_auth_method `{method}` is not implemented yet"
            )));
        }
        _ => {
            return Err(AppError::Validation(
                "unsupported token_endpoint_auth_method".to_string(),
            ));
        }
    }
    Ok(())
}

/// Rows with the same public `client_id` across tenants; authenticate with optional secret.
pub async fn clients_by_public_id(
    pool: &PgPool,
    client_id: &str,
) -> Result<Vec<sqlx::postgres::PgRow>, AppError> {
    let rows = sqlx::query(
        "SELECT id, tenant_id, client_id, client_type, token_endpoint_auth_method, client_secret_argon2,
                COALESCE(require_pkce, true) AS require_pkce, pkce_methods
         FROM clients WHERE client_id = $1",
    )
    .bind(client_id)
    .fetch_all(pool)
    .await?;
    Ok(rows)
}

/// Pick the tenant row whose confidential secret matches, or the single public row when no secret is sent.
pub fn pick_client_row_authenticated<'a>(
    rows: &'a [sqlx::postgres::PgRow],
    client_secret: Option<&str>,
) -> Result<&'a sqlx::postgres::PgRow, AppError> {
    let sec = client_secret.map(str::trim).filter(|s| !s.is_empty());
    let public_no_secret: Vec<&sqlx::postgres::PgRow> = rows
        .iter()
        .filter(|r| {
            r.try_get::<String, _>("client_type")
                .unwrap_or_else(|_| "public".to_string())
                == "public"
        })
        .collect();
    if sec.is_none() && public_no_secret.len() > 1 {
        return Err(AppError::Validation(
            "multiple OAuth clients share this client_id; use a unique client_id per tenant"
                .to_string(),
        ));
    }
    for row in rows {
        let ctype: String = row
            .try_get::<String, _>("client_type")
            .unwrap_or_else(|_| "public".to_string());
        if ctype == "confidential" {
            let Some(p) = sec else {
                continue;
            };
            if verify_confidential_client_secret(row, p) {
                return Ok(row);
            }
        } else if sec.is_none() {
            return Ok(row);
        }
    }
    Err(AppError::Unauthorized)
}

/// Introspection / revocation: authenticate client credentials.
pub async fn resolve_introspect_client(
    pool: &PgPool,
    client_id: &str,
    client_secret: Option<&str>,
    source: ClientCredentialsSource,
) -> Result<(), AppError> {
    let rows = clients_by_public_id(pool, client_id).await?;
    if rows.is_empty() {
        return Err(AppError::Unauthorized);
    }
    let row = pick_client_row_authenticated(&rows, client_secret)?;
    let ctype: String = row
        .try_get::<String, _>("client_type")
        .unwrap_or_else(|_| "public".to_string());
    let method: String = row
        .try_get::<String, _>("token_endpoint_auth_method")
        .unwrap_or_else(|_| "none".to_string());
    enforce_token_endpoint_auth_method(method.as_str(), ctype == "confidential", source)?;
    Ok(())
}

pub async fn assert_grant_allowed(
    pool: &PgPool,
    tenant_id: Uuid,
    client_public_id: &str,
    grant: &str,
) -> Result<(), AppError> {
    let ok: bool = sqlx::query_scalar(
        "SELECT EXISTS(SELECT 1 FROM clients WHERE tenant_id = $1 AND client_id = $2 AND $3 = ANY(grant_types))",
    )
    .bind(tenant_id)
    .bind(client_public_id)
    .bind(grant)
    .fetch_one(pool)
    .await
    .unwrap_or(false);
    if !ok {
        return Err(AppError::Validation(format!(
            "grant_type `{grant}` is not allowed for this client"
        )));
    }
    Ok(())
}

/// PKCE policy at `/authorize`: public clients always require PKCE S256.
pub fn authorize_pkce_ok(
    row: &sqlx::postgres::PgRow,
    code_challenge: Option<&str>,
    code_challenge_method: Option<&str>,
) -> Result<(), AppError> {
    let ctype: String = row
        .try_get::<String, _>("client_type")
        .unwrap_or_else(|_| "public".to_string());
    let require_pkce: bool = row.try_get("require_pkce").unwrap_or(true);
    let pkce_methods: Vec<String> = row
        .try_get::<Vec<String>, _>("pkce_methods")
        .unwrap_or_else(|_| vec!["S256".to_string()]);

    let need_pkce = ctype == "public" || require_pkce;
    if !need_pkce {
        return Ok(());
    }
    if code_challenge_method.as_deref() != Some("S256") {
        return Err(AppError::Validation(
            "pkce S256 is required for this client".to_string(),
        ));
    }
    let ch = code_challenge
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .ok_or_else(|| AppError::Validation("code_challenge required".to_string()))?;
    if !pkce_methods.iter().any(|m| m == "S256") {
        return Err(AppError::Validation(
            "S256 is not enabled in client pkce_methods".to_string(),
        ));
    }
    if ch.is_empty() {
        return Err(AppError::Validation("code_challenge required".to_string()));
    }
    Ok(())
}

pub fn pkce_challenge_for_storage(
    row: &sqlx::postgres::PgRow,
    code_challenge: Option<&str>,
) -> Result<(String, String), AppError> {
    let ctype: String = row
        .try_get::<String, _>("client_type")
        .unwrap_or_else(|_| "public".to_string());
    let require_pkce: bool = row.try_get("require_pkce").unwrap_or(true);
    let need_pkce = ctype == "public" || require_pkce;
    if need_pkce {
        let ch = code_challenge
            .map(str::trim)
            .filter(|s| !s.is_empty())
            .ok_or_else(|| AppError::Validation("code_challenge required".to_string()))?;
        return Ok((ch.to_string(), "S256".to_string()));
    }
    Ok((String::new(), "none".to_string()))
}
