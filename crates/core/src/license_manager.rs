//! License Manager
//!
//! Manages license loading, validation, caching, and entitlement queries.
//! This is the main interface for checking license status throughout the application.

use std::fs;
use std::sync::RwLock;

use crate::install_id::{get_license_path, get_or_create_install_id, read_install_id};
use crate::license::{LicensePayload, LicenseVerifyResult, SignedLicense};
use crate::machine_fingerprint::MachineFingerprint;

// ─────────────────────────────────────────────────────────────────────────────
// License Status Types
// ─────────────────────────────────────────────────────────────────────────────

/// Current license status
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(tag = "status", rename_all = "snake_case")]
pub enum LicenseStatus {
    /// No license file found
    NotInstalled,
    /// License is valid and active
    Valid {
        license_id: String,
        customer: Option<String>,
        edition: String,
        entitlements: Vec<String>,
        expires_at: Option<i64>,
    },
    /// License signature is invalid (tampered or wrong key)
    Invalid { reason: String },
    /// License has expired
    Expired { expired_at: i64 },
    /// License is bound to a different installation
    WrongInstallation { expected: String, actual: String },
    /// License is bound to a different machine
    WrongMachine {
        expected: String,
        actual: Option<String>,
    },
    /// Public key not configured (development build)
    NotConfigured,
}

impl LicenseStatus {
    /// Check if the status indicates a valid, active license
    pub fn is_valid(&self) -> bool {
        matches!(self, LicenseStatus::Valid { .. })
    }

    /// Get the list of entitlements if license is valid
    pub fn entitlements(&self) -> &[String] {
        match self {
            LicenseStatus::Valid { entitlements, .. } => entitlements,
            _ => &[],
        }
    }

    /// Check if a specific entitlement is granted
    pub fn has_entitlement(&self, entitlement: &str) -> bool {
        self.entitlements().iter().any(|e| e == entitlement)
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// License Manager
// ─────────────────────────────────────────────────────────────────────────────

/// Thread-safe license manager with caching.
pub struct LicenseManager {
    /// Cached license status
    cached_status: RwLock<Option<LicenseStatus>>,
    /// Cached install ID
    cached_install_id: RwLock<Option<String>>,
    /// Cached machine fingerprint
    cached_fingerprint: RwLock<Option<Option<MachineFingerprint>>>,
}

impl Default for LicenseManager {
    fn default() -> Self {
        Self::new()
    }
}

impl LicenseManager {
    /// Create a new license manager
    pub fn new() -> Self {
        Self {
            cached_status: RwLock::new(None),
            cached_install_id: RwLock::new(None),
            cached_fingerprint: RwLock::new(None),
        }
    }

    /// Get the installation ID, creating one if needed.
    pub fn get_install_id(&self) -> Result<String, String> {
        // Check cache first
        {
            let cache = self.cached_install_id.read().unwrap();
            if let Some(ref id) = *cache {
                return Ok(id.clone());
            }
        }

        // Get or create install ID
        let id = get_or_create_install_id()?;

        // Cache it
        {
            let mut cache = self.cached_install_id.write().unwrap();
            *cache = Some(id.clone());
        }

        Ok(id)
    }

    /// Get the machine fingerprint (cached).
    pub fn get_machine_fingerprint(&self) -> Option<MachineFingerprint> {
        // Check cache first
        {
            let cache = self.cached_fingerprint.read().unwrap();
            if let Some(ref fp) = *cache {
                return fp.clone();
            }
        }

        // Generate fingerprint
        let fp = MachineFingerprint::generate();

        // Cache it (even if None, to avoid repeated attempts)
        {
            let mut cache = self.cached_fingerprint.write().unwrap();
            *cache = Some(fp.clone());
        }

        fp
    }

    /// Get the current license status, loading from disk if needed.
    pub fn get_status(&self) -> LicenseStatus {
        // Check cache first
        {
            let cache = self.cached_status.read().unwrap();
            if let Some(ref status) = *cache {
                return status.clone();
            }
        }

        // Load and validate
        let status = self.load_and_validate();

        // Cache the result
        {
            let mut cache = self.cached_status.write().unwrap();
            *cache = Some(status.clone());
        }

        status
    }

    /// Force reload the license from disk
    pub fn reload(&self) -> LicenseStatus {
        // Clear cache
        {
            let mut cache = self.cached_status.write().unwrap();
            *cache = None;
        }

        self.get_status()
    }

    /// Check if a specific entitlement is granted
    pub fn has_entitlement(&self, entitlement: &str) -> bool {
        self.get_status().has_entitlement(entitlement)
    }

    /// Install a license from a file path.
    /// Copies the file to the standard license location.
    pub fn install_license(&self, source_path: &std::path::Path) -> Result<LicenseStatus, String> {
        // Read the source file
        let content = fs::read_to_string(source_path)
            .map_err(|e| format!("Failed to read license file: {}", e))?;

        // Parse and validate before installing
        let license: SignedLicense =
            serde_json::from_str(&content).map_err(|e| format!("Invalid license format: {}", e))?;

        // Get install ID
        let install_id = self.get_install_id()?;

        // Verify the license
        let verify_result = license.verify(&install_id);

        // Convert to status (we still install even if invalid, for diagnostics)
        let status = self.verify_result_to_status(verify_result, &license.payload);

        // Only install if valid
        if !status.is_valid() {
            return Err(format!("License validation failed: {:?}", status));
        }

        // Copy to destination
        let dest_path = get_license_path();
        if let Some(parent) = dest_path.parent() {
            fs::create_dir_all(parent)
                .map_err(|e| format!("Failed to create license directory: {}", e))?;
        }

        fs::write(&dest_path, &content).map_err(|e| format!("Failed to write license: {}", e))?;

        // Clear cache and return new status
        {
            let mut cache = self.cached_status.write().unwrap();
            *cache = Some(status.clone());
        }

        Ok(status)
    }

    /// Install a license from JSON content directly.
    pub fn install_license_content(&self, content: &str) -> Result<LicenseStatus, String> {
        // Parse and validate
        let license: SignedLicense =
            serde_json::from_str(content).map_err(|e| format!("Invalid license format: {}", e))?;

        // Get install ID
        let install_id = self.get_install_id()?;

        // Verify the license
        let verify_result = license.verify(&install_id);
        let status = self.verify_result_to_status(verify_result, &license.payload);

        // Only install if valid
        if !status.is_valid() {
            return Err(format!("License validation failed: {:?}", status));
        }

        // Write to destination
        let dest_path = get_license_path();
        if let Some(parent) = dest_path.parent() {
            fs::create_dir_all(parent)
                .map_err(|e| format!("Failed to create license directory: {}", e))?;
        }

        fs::write(&dest_path, content).map_err(|e| format!("Failed to write license: {}", e))?;

        // Update cache
        {
            let mut cache = self.cached_status.write().unwrap();
            *cache = Some(status.clone());
        }

        Ok(status)
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Internal Methods
    // ─────────────────────────────────────────────────────────────────────────

    fn load_and_validate(&self) -> LicenseStatus {
        let license_path = get_license_path();

        // Check if license file exists
        if !license_path.exists() {
            return LicenseStatus::NotInstalled;
        }

        // Read and parse license
        let content = match fs::read_to_string(&license_path) {
            Ok(c) => c,
            Err(e) => {
                return LicenseStatus::Invalid {
                    reason: format!("Failed to read license: {}", e),
                }
            }
        };

        let license: SignedLicense = match serde_json::from_str(&content) {
            Ok(l) => l,
            Err(e) => {
                return LicenseStatus::Invalid {
                    reason: format!("Invalid license JSON: {}", e),
                }
            }
        };

        // Get install ID
        let install_id = match read_install_id() {
            Some(id) => id,
            None => match get_or_create_install_id() {
                Ok(id) => id,
                Err(e) => {
                    return LicenseStatus::Invalid {
                        reason: format!("Cannot determine install ID: {}", e),
                    }
                }
            },
        };

        // Get machine fingerprint (may be None on VMs/restricted environments)
        let machine_fp = self.get_machine_fingerprint();
        let fp_str = machine_fp.as_ref().map(|fp| fp.0.as_str());

        // Verify with fingerprint
        let verify_result = license.verify_with_fingerprint(&install_id, fp_str);
        self.verify_result_to_status(verify_result, &license.payload)
    }

    fn verify_result_to_status(
        &self,
        result: LicenseVerifyResult,
        payload: &LicensePayload,
    ) -> LicenseStatus {
        match result {
            LicenseVerifyResult::Valid => LicenseStatus::Valid {
                license_id: payload.license_id.clone(),
                customer: payload.customer.clone(),
                edition: payload.edition.clone(),
                entitlements: payload.entitlements.clone(),
                expires_at: payload.expires_at,
            },
            LicenseVerifyResult::InvalidSignature => LicenseStatus::Invalid {
                reason: "Signature verification failed".to_string(),
            },
            LicenseVerifyResult::Expired => LicenseStatus::Expired {
                expired_at: payload.expires_at.unwrap_or(0),
            },
            LicenseVerifyResult::InstallIdMismatch { expected, actual } => {
                LicenseStatus::WrongInstallation { expected, actual }
            }
            LicenseVerifyResult::MachineFingerPrintMismatch { expected, actual } => {
                LicenseStatus::WrongMachine { expected, actual }
            }
            LicenseVerifyResult::PublicKeyNotConfigured => LicenseStatus::NotConfigured,
            LicenseVerifyResult::InvalidPublicKey => LicenseStatus::Invalid {
                reason: "Invalid public key".to_string(),
            },
            LicenseVerifyResult::InvalidSignatureFormat => LicenseStatus::Invalid {
                reason: "Invalid signature format".to_string(),
            },
        }
    }
}

/// Global license manager instance for convenience.
/// Use this for simple entitlement checks throughout the application.
static GLOBAL_LICENSE_MANAGER: std::sync::OnceLock<LicenseManager> = std::sync::OnceLock::new();

/// Get the global license manager instance
pub fn global_license_manager() -> &'static LicenseManager {
    GLOBAL_LICENSE_MANAGER.get_or_init(LicenseManager::new)
}

/// Convenience function to check if an entitlement is granted.
/// Uses the global license manager.
pub fn has_entitlement(entitlement: &str) -> bool {
    global_license_manager().has_entitlement(entitlement)
}

/// Convenience function to check if diff_mode is enabled.
pub fn diff_mode_enabled() -> bool {
    has_entitlement(crate::license::entitlements::DIFF_MODE)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_license_status_is_valid() {
        let valid = LicenseStatus::Valid {
            license_id: "test".to_string(),
            customer: None,
            edition: "pro".to_string(),
            entitlements: vec!["diff_mode".to_string()],
            expires_at: None,
        };
        assert!(valid.is_valid());

        let invalid = LicenseStatus::NotInstalled;
        assert!(!invalid.is_valid());
    }

    #[test]
    fn test_license_status_has_entitlement() {
        let status = LicenseStatus::Valid {
            license_id: "test".to_string(),
            customer: None,
            edition: "pro".to_string(),
            entitlements: vec!["diff_mode".to_string(), "pro_reports".to_string()],
            expires_at: None,
        };

        assert!(status.has_entitlement("diff_mode"));
        assert!(status.has_entitlement("pro_reports"));
        assert!(!status.has_entitlement("team_features"));
    }

    #[test]
    fn test_license_status_not_installed_no_entitlements() {
        let status = LicenseStatus::NotInstalled;
        assert!(!status.has_entitlement("diff_mode"));
        assert!(status.entitlements().is_empty());
    }

    #[test]
    fn test_license_manager_creation() {
        let manager = LicenseManager::new();
        // Should not panic
        let _ = manager.get_status();
    }
}
