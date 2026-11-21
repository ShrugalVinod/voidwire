//! Terminal QR codes for `voidwire://` URIs.

use qrcode::render::unicode::Dense1x2;
use qrcode::{EcLevel, QrCode};
use vw_core::{Result, VwError};

/// Render `data` as a QR code made of Unicode half blocks (2 rows per line).
pub fn render_terminal(data: &str) -> Result<String> {
    let code = QrCode::with_error_correction_level(data.as_bytes(), EcLevel::L)
        .map_err(|e| VwError::Config(format!("QR encode failed: {e}")))?;
    Ok(code
        .render::<Dense1x2>()
        .dark_color(Dense1x2::Light)
        .light_color(Dense1x2::Dark)
        .quiet_zone(true)
        .build())
}

#[cfg(test)]
mod tests {
    #[test]
    fn renders() {
        let s = super::render_terminal("voidwire://node/abc").unwrap();
        assert!(s.lines().count() > 10);
    }
}
