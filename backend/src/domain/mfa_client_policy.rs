/// OAuth client–level TOTP / Authenticator policy stored in `clients.mfa_policy`.
pub fn parse_mfa_policy(v: Option<&str>) -> Result<&'static str, String> {
    let s = v.unwrap_or("off").trim();
    if s.is_empty() {
        return Ok("off");
    }
    match s.to_ascii_lowercase().as_str() {
        "off" => Ok("off"),
        "optional" => Ok("optional"),
        "required" => Ok("required"),
        _ => Err("mfa_policy must be off, optional, or required".to_string()),
    }
}

#[cfg(test)]
mod tests {
    use super::parse_mfa_policy;

    #[test]
    fn default_off() {
        assert_eq!(parse_mfa_policy(None).unwrap(), "off");
        assert_eq!(parse_mfa_policy(Some("")).unwrap(), "off");
    }

    #[test]
    fn case_insensitive() {
        assert_eq!(parse_mfa_policy(Some("ReQuIrEd")).unwrap(), "required");
    }

    #[test]
    fn rejects_invalid() {
        assert!(parse_mfa_policy(Some("always")).is_err());
    }
}
