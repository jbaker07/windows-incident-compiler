//! Export Watermarking
//!
//! Embeds license/installation metadata into exported artifacts to deter
//! casual redistribution and enable attribution of leaked content.
//!
//! Watermarks are:
//! - Visible (in headers/footers)
//! - Machine-readable (in metadata)
//! - Non-removable without obvious tampering

use serde::{Deserialize, Serialize};

/// Watermark metadata to embed in exports.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Watermark {
    /// Customer name/ID (from license)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub customer: Option<String>,

    /// License ID
    pub license_id: String,

    /// Installation ID (truncated hash for privacy)
    pub install_hash: String,

    /// Build version
    pub build_version: String,

    /// Export timestamp (Unix millis)
    pub exported_at: i64,

    /// Export type (e.g., "diff_report", "bundle", "pdf")
    pub export_type: String,
}

impl Watermark {
    /// Create a new watermark from license info.
    pub fn new(
        customer: Option<String>,
        license_id: &str,
        install_id: &str,
        export_type: &str,
    ) -> Self {
        // Truncate install_id to first 8 chars for privacy
        let install_hash = if install_id.len() > 8 {
            install_id[..8].to_string()
        } else {
            install_id.to_string()
        };

        Self {
            customer,
            license_id: license_id.to_string(),
            install_hash,
            build_version: env!("CARGO_PKG_VERSION").to_string(),
            exported_at: chrono::Utc::now().timestamp_millis(),
            export_type: export_type.to_string(),
        }
    }

    /// Generate a human-readable watermark string for headers/footers.
    pub fn to_visible_string(&self) -> String {
        let customer_part = self
            .customer
            .as_ref()
            .map(|c| format!("Licensed to: {} | ", c))
            .unwrap_or_default();

        format!(
            "{}License: {} | Install: {} | v{}",
            customer_part, self.license_id, self.install_hash, self.build_version
        )
    }

    /// Generate a compact machine-readable watermark for embedding in metadata.
    pub fn to_metadata_string(&self) -> String {
        serde_json::to_string(self).unwrap_or_else(|_| {
            format!(
                "{{\"license_id\":\"{}\",\"install_hash\":\"{}\"}}",
                self.license_id, self.install_hash
            )
        })
    }

    /// Generate an HTML comment watermark.
    pub fn to_html_comment(&self) -> String {
        format!("<!-- EDR Watermark: {} -->", self.to_metadata_string())
    }

    /// Generate a PDF metadata string.
    pub fn to_pdf_metadata(&self) -> Vec<(String, String)> {
        let mut meta = vec![
            ("EDR-License".to_string(), self.license_id.clone()),
            ("EDR-Install".to_string(), self.install_hash.clone()),
            ("EDR-Version".to_string(), self.build_version.clone()),
        ];

        if let Some(ref customer) = self.customer {
            meta.push(("EDR-Customer".to_string(), customer.clone()));
        }

        meta
    }
}

/// Trait for types that can be watermarked.
pub trait Watermarkable {
    /// Apply watermark to this export.
    fn apply_watermark(&mut self, watermark: &Watermark);

    /// Extract watermark from this export (if present).
    fn extract_watermark(&self) -> Option<Watermark>;
}

/// Helper to create a watermark from the current license state.
pub fn create_watermark_from_license(export_type: &str) -> Option<Watermark> {
    use crate::license_manager::global_license_manager;
    use crate::LicenseStatus;

    let manager = global_license_manager();
    let status = manager.get_status();

    let install_id = manager.get_install_id().ok()?;

    match status {
        LicenseStatus::Valid {
            license_id,
            customer,
            ..
        } => Some(Watermark::new(
            customer,
            &license_id,
            &install_id,
            export_type,
        )),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_watermark_creation() {
        let wm = Watermark::new(
            Some("Test Corp".to_string()),
            "lic_abc123",
            "install-uuid-1234-5678",
            "diff_report",
        );

        assert_eq!(wm.license_id, "lic_abc123");
        assert_eq!(wm.install_hash, "install-"); // Truncated to 8 chars
        assert_eq!(wm.export_type, "diff_report");
        assert!(wm.customer.is_some());
    }

    #[test]
    fn test_visible_string() {
        let wm = Watermark::new(
            Some("Acme Inc".to_string()),
            "lic_xyz789",
            "abcd1234efgh5678",
            "bundle",
        );

        let visible = wm.to_visible_string();
        assert!(visible.contains("Licensed to: Acme Inc"));
        assert!(visible.contains("lic_xyz789"));
        assert!(visible.contains("abcd1234"));
    }

    #[test]
    fn test_metadata_string_is_json() {
        let wm = Watermark::new(None, "lic_test", "inst123", "pdf");

        let meta = wm.to_metadata_string();
        // Should be valid JSON
        let parsed: serde_json::Value = serde_json::from_str(&meta).expect("Should be valid JSON");
        assert_eq!(parsed["license_id"], "lic_test");
    }

    #[test]
    fn test_html_comment() {
        let wm = Watermark::new(None, "lic_html", "inst", "html");

        let comment = wm.to_html_comment();
        assert!(comment.starts_with("<!-- EDR Watermark:"));
        assert!(comment.ends_with("-->"));
    }
}
