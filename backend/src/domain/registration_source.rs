/// Default `registration_source` when `POST /auth/register` omits it (admin API only).
pub const DEFAULT_DIRECT: &str = "direct";
/// Default for `POST /admin/users` (dashboard form).
pub const DEFAULT_DASHBOARD: &str = "dashboard";

/// Trims, length cap, rejects control characters.
pub fn parse_registration_source(input: Option<&str>, default: &str) -> Result<String, String> {
    let s = input
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .unwrap_or(default);
    if s.is_empty() {
        return Ok(default.to_string());
    }
    if s.len() > 128 {
        return Err("registration_source must be at most 128 characters".to_string());
    }
    if s.chars().any(|c| c.is_control()) {
        return Err("registration_source must not contain control characters".to_string());
    }
    Ok(s.to_string())
}

#[cfg(test)]
mod tests {
    use super::parse_registration_source;

    #[test]
    fn default_when_none() {
        assert_eq!(parse_registration_source(None, "x").unwrap(), "x");
    }

    #[test]
    fn make_auth() {
        assert_eq!(
            parse_registration_source(Some("  make-auth-service  "), "direct").unwrap(),
            "make-auth-service"
        );
    }
}
