//! Whitelisted design tokens for `clients.embedded_ui_theme` and runtime `THEME_UPDATE`.

use serde_json::{Map, Value, json};

const MAX_STR: usize = 64;

/// Validates theme JSON, returns a normalized (compact) `Value` or an error string.
/// `None` / null is allowed (no custom theme).
pub fn validate_embedded_ui_theme(input: Option<&Value>) -> Result<Option<Value>, String> {
    let Some(v) = input else {
        return Ok(None);
    };
    if v.is_null() {
        return Ok(None);
    }
    let obj = v
        .as_object()
        .ok_or_else(|| "embedded_ui_theme must be a JSON object".to_string())?;
    let ver = obj
        .get("v")
        .and_then(|x| x.as_u64())
        .ok_or_else(|| "theme.v must be 1".to_string())?;
    if ver != 1 {
        return Err("theme.v must be 1".to_string());
    }

    let color_scheme = obj
        .get("colorScheme")
        .map(|x| {
            x.as_str()
                .ok_or_else(|| "colorScheme must be a string".to_string())
                .and_then(|s| match s {
                    "light" | "dark" | "system" => Ok(s.to_string()),
                    _ => Err("colorScheme must be light, dark, or system".to_string()),
                })
        })
        .transpose()?;

    let mut out = Map::new();
    out.insert("v".to_string(), json!(1));
    if let Some(cs) = color_scheme {
        out.insert("colorScheme".to_string(), json!(cs));
    }
    if let Some(c) = obj.get("colors") {
        out.insert("colors".to_string(), parse_colors(c)?);
    }
    if let Some(r) = obj.get("radius") {
        out.insert("radius".to_string(), parse_sp_radius(r, 24)?);
    }
    if let Some(s) = obj.get("spacing") {
        out.insert("spacing".to_string(), parse_sp_radius(s, 32)?);
    }
    if let Some(f) = obj.get("font") {
        out.insert("font".to_string(), parse_font(f)?);
    }
    for k in obj.keys() {
        if !["v", "colorScheme", "colors", "radius", "spacing", "font"].contains(&k.as_str()) {
            return Err(format!("unknown theme key: {k}"));
        }
    }
    Ok(Some(Value::Object(out)))
}

fn parse_colors(c: &Value) -> Result<Value, String> {
    let o = c
        .as_object()
        .ok_or_else(|| "colors must be an object".to_string())?;
    const KEYS: [&str; 5] = ["primary", "onPrimary", "background", "surface", "error"];
    let mut m = Map::new();
    for k in KEYS {
        if let Some(x) = o.get(k) {
            let s = x
                .as_str()
                .ok_or_else(|| format!("colors.{k} must be a string"))?;
            m.insert(k.to_string(), json!(validate_color_string(s)?));
        }
    }
    for k in o.keys() {
        if !KEYS.contains(&k.as_str()) {
            return Err(format!("unknown color key: {k}"));
        }
    }
    Ok(Value::Object(m))
}

fn parse_sp_radius(v: &Value, cap: u64) -> Result<Value, String> {
    let o = v
        .as_object()
        .ok_or_else(|| "must be an object".to_string())?;
    const KEYS: [&str; 3] = ["sm", "md", "lg"];
    let mut m = Map::new();
    for k in KEYS {
        if let Some(x) = o.get(k) {
            let n = x.as_u64().ok_or("radius/spacing values must be integers")?;
            if n > cap {
                return Err(format!("value {k} out of range (0..={cap})"));
            }
            m.insert(k.to_string(), json!(n));
        }
    }
    for k in o.keys() {
        if !KEYS.contains(&k.as_str()) {
            return Err(format!("unknown key: {k}"));
        }
    }
    Ok(Value::Object(m))
}

fn parse_font(v: &Value) -> Result<Value, String> {
    let o = v
        .as_object()
        .ok_or_else(|| "font must be an object".to_string())?;
    let mut m = Map::new();
    if let Some(f) = o.get("family") {
        let s = f
            .as_str()
            .ok_or_else(|| "font.family must be a string".to_string())?;
        if !["system", "serif", "mono"].contains(&s) {
            return Err("font.family must be system, serif, or mono".to_string());
        }
        m.insert("family".to_string(), json!(s));
    }
    if let Some(f) = o.get("size") {
        let s = f
            .as_str()
            .ok_or_else(|| "font.size must be a string".to_string())?;
        if !["sm", "md", "lg"].contains(&s) {
            return Err("font.size must be sm, md, or lg".to_string());
        }
        m.insert("size".to_string(), json!(s));
    }
    for k in o.keys() {
        if k != "family" && k != "size" {
            return Err(format!("unknown font key: {k}"));
        }
    }
    Ok(Value::Object(m))
}

fn validate_color_string(s: &str) -> Result<String, String> {
    let t = s.trim();
    if t.is_empty() || t.len() > MAX_STR {
        return Err("color string length invalid".to_string());
    }
    let lower = t.to_ascii_lowercase();
    if lower.contains("url(")
        || lower.contains("expression(")
        || lower.contains("javascript:")
        || lower.contains('<')
        || lower.contains("import")
    {
        return Err("forbidden in color value".to_string());
    }
    if let Some(h) = t.strip_prefix('#') {
        let ok = matches!(h.len(), 3 | 6 | 8) && h.chars().all(|c| c.is_ascii_hexdigit());
        if ok {
            return Ok(t.to_string());
        }
        return Err("invalid hex color".to_string());
    }
    let safe_css = |x: &str| {
        x.chars()
            .all(|c| c.is_ascii_alphanumeric() || " ,.%+-.()".contains(c))
    };
    if (lower.starts_with("rgb(") || lower.starts_with("rgba(")) && t.ends_with(')') {
        let inner = if let Some(i) = t.strip_prefix("rgba(") {
            i.strip_suffix(')').unwrap_or("")
        } else if let Some(i) = t.strip_prefix("rgb(") {
            i.strip_suffix(')').unwrap_or("")
        } else {
            ""
        };
        if safe_css(inner) {
            return Ok(t.to_string());
        }
    }
    if (lower.starts_with("hsl(") || lower.starts_with("hsla(")) && t.ends_with(')') {
        let inner = if let Some(i) = t.strip_prefix("hsla(") {
            i.strip_suffix(')').unwrap_or("")
        } else if let Some(i) = t.strip_prefix("hsl(") {
            i.strip_suffix(')').unwrap_or("")
        } else {
            ""
        };
        if safe_css(inner) {
            return Ok(t.to_string());
        }
    }
    Err("invalid color format (use #hex or rgb/hsl only)".to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn accepts_minimal() {
        let v = json!({ "v": 1, "colorScheme": "light" });
        let out = validate_embedded_ui_theme(Some(&v)).unwrap().unwrap();
        assert_eq!(out.get("v").and_then(|x| x.as_u64()), Some(1));
    }

    #[test]
    fn rejects_url_in_color() {
        let v = json!({ "v": 1, "colors": { "primary": "url(//evil)" } });
        assert!(validate_embedded_ui_theme(Some(&v)).is_err());
    }
}
