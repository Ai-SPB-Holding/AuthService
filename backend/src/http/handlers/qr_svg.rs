//! SVG QR (base64) for `otpauth://` URLs — shared by embedded and auth flows.
use base64::Engine;
use qrcode::render::svg;
use qrcode::{EcLevel, QrCode};

use crate::services::errors::AppError;

pub fn otpauth_url_qr_svg_base64(url: &str) -> Result<String, AppError> {
    let code = QrCode::with_error_correction_level(url.as_bytes(), EcLevel::M)
        .map_err(|e| AppError::Internal(format!("qr encode: {e}")))?;
    let svg: String = code
        .render()
        .min_dimensions(192, 192)
        .max_dimensions(256, 256)
        .dark_color(svg::Color("#000000"))
        .light_color(svg::Color("#ffffff"))
        .build();
    Ok(base64::engine::general_purpose::STANDARD.encode(svg.as_bytes()))
}
