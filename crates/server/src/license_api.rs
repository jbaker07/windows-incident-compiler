//! License API endpoints
//!
//! Provides HTTP API for license status and management.

use axum::{http::StatusCode, response::IntoResponse, Json};
use serde::{Deserialize, Serialize};

use edr_core::{entitlements, global_license_manager, LicenseStatus};

// ─────────────────────────────────────────────────────────────────────────────
// Response Types
// ─────────────────────────────────────────────────────────────────────────────

/// Response for /api/license/status
#[derive(Debug, Serialize)]
pub struct LicenseStatusResponse {
    pub success: bool,
    pub install_id: String,
    pub status: LicenseStatusInfo,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub license: Option<LicenseDetails>,
    /// Machine fingerprint status for binding display
    #[serde(skip_serializing_if = "Option::is_none")]
    pub fingerprint: Option<FingerprintInfo>,
}

/// Machine fingerprint information
#[derive(Debug, Serialize)]
pub struct FingerprintInfo {
    /// Whether a fingerprint is available on this machine
    pub available: bool,
    /// The fingerprint value (if available)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub value: Option<String>,
    /// Human-readable status
    pub status: FingerprintStatus,
}

/// Fingerprint status for UI display
#[derive(Debug, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum FingerprintStatus {
    /// Fingerprint available and matches license (or license has no binding)
    Bound,
    /// Fingerprint available but doesn't match license
    Mismatch,
    /// Unable to generate fingerprint (VM, restricted environment)
    Unavailable,
    /// No license installed, fingerprint not checked
    NotChecked,
}

/// License status information
#[derive(Debug, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum LicenseStatusInfo {
    Valid,
    NotInstalled,
    Invalid,
    Expired,
    WrongInstallation,
    WrongMachine,
    NotConfigured,
}

/// License details when valid
#[derive(Debug, Serialize)]
pub struct LicenseDetails {
    pub license_id: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub customer: Option<String>,
    pub edition: String,
    pub entitlements: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub expires_at: Option<i64>,
}

/// Error response for Pro-required features
#[derive(Debug, Serialize)]
pub struct ProRequiredResponse {
    pub error: &'static str,
    pub feature: String,
    pub install_id: String,
    pub upgrade: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
}

/// Request to install a license
#[derive(Debug, Deserialize)]
pub struct InstallLicenseRequest {
    /// The license JSON content (not a file path)
    pub license_content: String,
}

/// Response for license installation
#[derive(Debug, Serialize)]
pub struct InstallLicenseResponse {
    pub success: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub status: Option<LicenseStatusInfo>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

// ─────────────────────────────────────────────────────────────────────────────
// API Handlers
// ─────────────────────────────────────────────────────────────────────────────

/// GET /api/license/status - Get current license status
pub async fn license_status_handler() -> impl IntoResponse {
    let manager = global_license_manager();

    let install_id = manager
        .get_install_id()
        .unwrap_or_else(|_| "unknown".to_string());
    let status = manager.get_status();

    // Get fingerprint info
    let machine_fp = manager.get_machine_fingerprint();
    let fingerprint_info = match &status {
        LicenseStatus::Valid { .. } => Some(FingerprintInfo {
            available: machine_fp.is_some(),
            value: machine_fp.as_ref().map(|fp| fp.0.clone()),
            status: if machine_fp.is_some() {
                FingerprintStatus::Bound
            } else {
                FingerprintStatus::Unavailable
            },
        }),
        LicenseStatus::WrongMachine { .. } => Some(FingerprintInfo {
            available: machine_fp.is_some(),
            value: machine_fp.as_ref().map(|fp| fp.0.clone()),
            status: FingerprintStatus::Mismatch,
        }),
        LicenseStatus::NotInstalled | LicenseStatus::NotConfigured => Some(FingerprintInfo {
            available: machine_fp.is_some(),
            value: machine_fp.as_ref().map(|fp| fp.0.clone()),
            status: FingerprintStatus::NotChecked,
        }),
        _ => Some(FingerprintInfo {
            available: machine_fp.is_some(),
            value: machine_fp.as_ref().map(|fp| fp.0.clone()),
            status: if machine_fp.is_some() {
                FingerprintStatus::Bound
            } else {
                FingerprintStatus::Unavailable
            },
        }),
    };

    let (status_info, license_details) = match status {
        LicenseStatus::Valid {
            license_id,
            customer,
            edition,
            entitlements,
            expires_at,
        } => (
            LicenseStatusInfo::Valid,
            Some(LicenseDetails {
                license_id,
                customer,
                edition,
                entitlements,
                expires_at,
            }),
        ),
        LicenseStatus::NotInstalled => (LicenseStatusInfo::NotInstalled, None),
        LicenseStatus::Invalid { .. } => (LicenseStatusInfo::Invalid, None),
        LicenseStatus::Expired { .. } => (LicenseStatusInfo::Expired, None),
        LicenseStatus::WrongInstallation { .. } => (LicenseStatusInfo::WrongInstallation, None),
        LicenseStatus::WrongMachine { .. } => (LicenseStatusInfo::WrongMachine, None),
        LicenseStatus::NotConfigured => (LicenseStatusInfo::NotConfigured, None),
    };

    Json(LicenseStatusResponse {
        success: true,
        install_id,
        status: status_info,
        license: license_details,
        fingerprint: fingerprint_info,
    })
}

/// POST /api/license/install - Install a license from content
pub async fn install_license_handler(
    Json(request): Json<InstallLicenseRequest>,
) -> impl IntoResponse {
    let manager = global_license_manager();

    match manager.install_license_content(&request.license_content) {
        Ok(status) => {
            let status_info = match status {
                LicenseStatus::Valid { .. } => LicenseStatusInfo::Valid,
                LicenseStatus::NotInstalled => LicenseStatusInfo::NotInstalled,
                LicenseStatus::Invalid { .. } => LicenseStatusInfo::Invalid,
                LicenseStatus::Expired { .. } => LicenseStatusInfo::Expired,
                LicenseStatus::WrongInstallation { .. } => LicenseStatusInfo::WrongInstallation,
                LicenseStatus::WrongMachine { .. } => LicenseStatusInfo::WrongMachine,
                LicenseStatus::NotConfigured => LicenseStatusInfo::NotConfigured,
            };

            (
                StatusCode::OK,
                Json(InstallLicenseResponse {
                    success: true,
                    status: Some(status_info),
                    error: None,
                }),
            )
        }
        Err(e) => (
            StatusCode::BAD_REQUEST,
            Json(InstallLicenseResponse {
                success: false,
                status: None,
                error: Some(e),
            }),
        ),
    }
}

/// POST /api/license/reload - Force reload license from disk
pub async fn reload_license_handler() -> impl IntoResponse {
    let manager = global_license_manager();
    let status = manager.reload();

    let install_id = manager
        .get_install_id()
        .unwrap_or_else(|_| "unknown".to_string());

    let (status_info, license_details) = match status {
        LicenseStatus::Valid {
            license_id,
            customer,
            edition,
            entitlements,
            expires_at,
        } => (
            LicenseStatusInfo::Valid,
            Some(LicenseDetails {
                license_id,
                customer,
                edition,
                entitlements,
                expires_at,
            }),
        ),
        LicenseStatus::NotInstalled => (LicenseStatusInfo::NotInstalled, None),
        LicenseStatus::Invalid { .. } => (LicenseStatusInfo::Invalid, None),
        LicenseStatus::Expired { .. } => (LicenseStatusInfo::Expired, None),
        LicenseStatus::WrongInstallation { .. } => (LicenseStatusInfo::WrongInstallation, None),
        LicenseStatus::WrongMachine { .. } => (LicenseStatusInfo::WrongMachine, None),
        LicenseStatus::NotConfigured => (LicenseStatusInfo::NotConfigured, None),
    };

    Json(LicenseStatusResponse {
        success: true,
        install_id,
        status: status_info,
        license: license_details,
        fingerprint: None, // Reload handler doesn't compute fingerprint status
    })
}

// ─────────────────────────────────────────────────────────────────────────────
// Entitlement Checking Utilities
// ─────────────────────────────────────────────────────────────────────────────

/// Check if the diff_mode entitlement is granted.
/// Returns Ok(()) if granted, or an error response if not.
pub fn require_diff_mode_entitlement() -> Result<(), (StatusCode, Json<ProRequiredResponse>)> {
    let manager = global_license_manager();

    if manager.has_entitlement(entitlements::DIFF_MODE) {
        return Ok(());
    }

    let install_id = manager
        .get_install_id()
        .unwrap_or_else(|_| "unknown".to_string());
    let status = manager.get_status();

    let reason = match status {
        LicenseStatus::NotInstalled => Some("No license installed".to_string()),
        LicenseStatus::Invalid { reason } => Some(format!("Invalid license: {}", reason)),
        LicenseStatus::Expired { expired_at } => Some(format!("License expired at {}", expired_at)),
        LicenseStatus::WrongInstallation {
            expected,
            actual: _,
        } => Some(format!(
            "License bound to different installation: {}",
            expected
        )),
        LicenseStatus::WrongMachine {
            expected,
            actual: _,
        } => Some(format!("License bound to different machine: {}", expected)),
        LicenseStatus::NotConfigured => Some("License system not configured".to_string()),
        LicenseStatus::Valid { entitlements, .. } => {
            if !entitlements.contains(&entitlements::DIFF_MODE.to_string()) {
                Some("License does not include diff_mode entitlement".to_string())
            } else {
                None // Should not reach here
            }
        }
    };

    Err((
        StatusCode::PAYMENT_REQUIRED,
        Json(ProRequiredResponse {
            error: "pro_required",
            feature: "diff_mode".to_string(),
            install_id,
            upgrade: true,
            reason,
        }),
    ))
}

/// Generic entitlement check
#[allow(dead_code)] // May be used by future Pro features
pub fn require_entitlement(
    entitlement: &str,
) -> Result<(), (StatusCode, Json<ProRequiredResponse>)> {
    let manager = global_license_manager();

    if manager.has_entitlement(entitlement) {
        return Ok(());
    }

    let install_id = manager
        .get_install_id()
        .unwrap_or_else(|_| "unknown".to_string());

    Err((
        StatusCode::PAYMENT_REQUIRED,
        Json(ProRequiredResponse {
            error: "pro_required",
            feature: entitlement.to_string(),
            install_id,
            upgrade: true,
            reason: Some(format!(
                "License does not include {} entitlement",
                entitlement
            )),
        }),
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_pro_required_response_serialization() {
        let response = ProRequiredResponse {
            error: "pro_required",
            feature: "diff_mode".to_string(),
            install_id: "test-install-id".to_string(),
            upgrade: true,
            reason: Some("No license".to_string()),
        };

        let json = serde_json::to_string(&response).unwrap();
        assert!(json.contains("pro_required"));
        assert!(json.contains("diff_mode"));
        assert!(json.contains("test-install-id"));
    }

    #[test]
    fn test_license_status_info_serialization() {
        let status = LicenseStatusInfo::Valid;
        let json = serde_json::to_string(&status).unwrap();
        assert_eq!(json, "\"valid\"");

        let status = LicenseStatusInfo::NotInstalled;
        let json = serde_json::to_string(&status).unwrap();
        assert_eq!(json, "\"not_installed\"");
    }
}
