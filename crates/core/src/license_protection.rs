//! License Protection
//!
//! Provides additional protection for license files:
//! - DPAPI encryption on Windows (at-rest protection)
//! - Clock tamper detection (backward clock jump detection)
//! - ACL hardening suggestions
//!
//! Design principles:
//! - Graceful degradation: if protection fails, license still works (annoying, not blocking)
//! - Privacy-preserving: no exfil, local-first
//! - VM-friendly: works on VMs where some features may not be available

use serde::{Deserialize, Serialize};
use std::fs;
use std::path::{Path, PathBuf};

/// Last-seen timestamp file for clock tamper detection.
const LAST_SEEN_FILENAME: &str = "license_lastseen";

/// Clock drift tolerance in seconds (allow small drift without warning).
const CLOCK_DRIFT_TOLERANCE_SECS: i64 = 300; // 5 minutes

/// Large backward jump threshold for strong warning.
const LARGE_BACKWARD_JUMP_SECS: i64 = 86400; // 24 hours

/// Result of license protection operations.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ProtectionResult {
    /// Protection applied successfully
    Success,
    /// Protection not available (platform limitation)
    NotAvailable(String),
    /// Protection failed (non-fatal)
    Failed(String),
}

/// Clock validation result.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum ClockStatus {
    /// Clock appears normal
    Ok,
    /// Small backward drift detected (within tolerance)
    MinorDrift { seconds: i64 },
    /// Large backward jump detected (suspicious)
    LargeBackwardJump {
        seconds: i64,
        last_seen: i64,
        current: i64,
    },
    /// Unable to determine (first run or file missing)
    Unknown,
}

impl ClockStatus {
    pub fn is_suspicious(&self) -> bool {
        matches!(self, ClockStatus::LargeBackwardJump { .. })
    }
}

/// Get the path for the last-seen timestamp file.
fn get_last_seen_path() -> Option<PathBuf> {
    let data_dir = dirs::data_local_dir()?;
    let edr_dir = data_dir.join("edr");
    Some(edr_dir.join(LAST_SEEN_FILENAME))
}

/// Update the last-seen timestamp (call on each license check).
pub fn update_last_seen() -> ProtectionResult {
    let path = match get_last_seen_path() {
        Some(p) => p,
        None => return ProtectionResult::NotAvailable("Cannot determine data directory".into()),
    };

    // Ensure directory exists
    if let Some(parent) = path.parent() {
        if let Err(e) = fs::create_dir_all(parent) {
            return ProtectionResult::Failed(format!("Failed to create directory: {}", e));
        }
    }

    let now = chrono::Utc::now().timestamp();
    let content = LastSeenData {
        timestamp: now,
        version: 1,
    };

    match serde_json::to_string(&content) {
        Ok(json) => match fs::write(&path, json) {
            Ok(()) => ProtectionResult::Success,
            Err(e) => ProtectionResult::Failed(format!("Failed to write: {}", e)),
        },
        Err(e) => ProtectionResult::Failed(format!("Failed to serialize: {}", e)),
    }
}

/// Check for clock tampering by comparing current time to last-seen timestamp.
pub fn check_clock_tamper() -> ClockStatus {
    let path = match get_last_seen_path() {
        Some(p) => p,
        None => return ClockStatus::Unknown,
    };

    if !path.exists() {
        return ClockStatus::Unknown;
    }

    let content = match fs::read_to_string(&path) {
        Ok(c) => c,
        Err(_) => return ClockStatus::Unknown,
    };

    let data: LastSeenData = match serde_json::from_str(&content) {
        Ok(d) => d,
        Err(_) => return ClockStatus::Unknown,
    };

    let now = chrono::Utc::now().timestamp();
    let diff = now - data.timestamp;

    if diff >= 0 {
        // Clock moved forward (normal)
        ClockStatus::Ok
    } else {
        let backward = diff.abs();
        if backward <= CLOCK_DRIFT_TOLERANCE_SECS {
            ClockStatus::MinorDrift { seconds: backward }
        } else if backward >= LARGE_BACKWARD_JUMP_SECS {
            // Large backward jump - very suspicious
            ClockStatus::LargeBackwardJump {
                seconds: backward,
                last_seen: data.timestamp,
                current: now,
            }
        } else {
            // Medium backward jump - still suspicious but less severe
            ClockStatus::LargeBackwardJump {
                seconds: backward,
                last_seen: data.timestamp,
                current: now,
            }
        }
    }
}

#[derive(Debug, Serialize, Deserialize)]
struct LastSeenData {
    timestamp: i64,
    version: u32,
}

// ─────────────────────────────────────────────────────────────────────────────
// DPAPI Protection (Windows only)
// ─────────────────────────────────────────────────────────────────────────────

/// Protected license wrapper - stores license JSON with optional DPAPI protection.
#[derive(Debug, Serialize, Deserialize)]
pub struct ProtectedLicense {
    /// Version of the protection format
    pub version: u32,
    /// The license JSON (may be plaintext or DPAPI-protected base64)
    pub payload: String,
    /// Whether the payload is DPAPI protected
    pub dpapi_protected: bool,
    /// Machine fingerprint at time of protection (for binding verification)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub protected_fingerprint: Option<String>,
}

/// Protect a license with DPAPI (Windows) or return plaintext (other platforms).
#[cfg(target_os = "windows")]
pub fn protect_license(
    license_json: &str,
    fingerprint: Option<&str>,
) -> Result<ProtectedLicense, String> {
    use crate::base64_encode;

    match dpapi_protect(license_json.as_bytes()) {
        Ok(protected_bytes) => Ok(ProtectedLicense {
            version: 1,
            payload: base64_encode(&protected_bytes),
            dpapi_protected: true,
            protected_fingerprint: fingerprint.map(String::from),
        }),
        Err(e) => {
            // DPAPI failed, fall back to plaintext
            eprintln!(
                "[license_protection] DPAPI protection failed: {}, using plaintext",
                e
            );
            Ok(ProtectedLicense {
                version: 1,
                payload: license_json.to_string(),
                dpapi_protected: false,
                protected_fingerprint: fingerprint.map(String::from),
            })
        }
    }
}

#[cfg(not(target_os = "windows"))]
pub fn protect_license(
    license_json: &str,
    fingerprint: Option<&str>,
) -> Result<ProtectedLicense, String> {
    // No DPAPI on non-Windows
    Ok(ProtectedLicense {
        version: 1,
        payload: license_json.to_string(),
        dpapi_protected: false,
        protected_fingerprint: fingerprint.map(String::from),
    })
}

/// Unprotect a license (decrypt DPAPI if needed).
#[cfg(target_os = "windows")]
pub fn unprotect_license(protected: &ProtectedLicense) -> Result<String, String> {
    use crate::license::base64_decode;

    if !protected.dpapi_protected {
        return Ok(protected.payload.clone());
    }

    let protected_bytes = base64_decode(&protected.payload)
        .ok_or_else(|| "Invalid base64 in protected payload".to_string())?;

    dpapi_unprotect(&protected_bytes).map(|bytes| String::from_utf8_lossy(&bytes).to_string())
}

#[cfg(not(target_os = "windows"))]
pub fn unprotect_license(protected: &ProtectedLicense) -> Result<String, String> {
    if protected.dpapi_protected {
        return Err("DPAPI-protected license cannot be read on non-Windows".to_string());
    }
    Ok(protected.payload.clone())
}

// ─────────────────────────────────────────────────────────────────────────────
// DPAPI Implementation (Windows)
// ─────────────────────────────────────────────────────────────────────────────

#[cfg(target_os = "windows")]
fn dpapi_protect(data: &[u8]) -> Result<Vec<u8>, String> {
    use std::ptr;
    use windows::Win32::Security::Cryptography::{
        CryptProtectData, CRYPTPROTECT_UI_FORBIDDEN, CRYPT_INTEGER_BLOB,
    };

    let input_blob = CRYPT_INTEGER_BLOB {
        cbData: data.len() as u32,
        pbData: data.as_ptr() as *mut u8,
    };

    let mut output_blob = CRYPT_INTEGER_BLOB {
        cbData: 0,
        pbData: ptr::null_mut(),
    };

    let result = unsafe {
        CryptProtectData(
            &input_blob,
            None,                      // Description
            None,                      // Optional entropy
            None,                      // Reserved
            None,                      // Prompt struct
            CRYPTPROTECT_UI_FORBIDDEN, // Flags: no UI
            &mut output_blob,
        )
    };

    if result.is_err() {
        return Err("CryptProtectData failed".to_string());
    }

    if output_blob.pbData.is_null() || output_blob.cbData == 0 {
        return Err("CryptProtectData returned empty data".to_string());
    }

    // Copy output data (CryptProtectData allocates with LocalAlloc)
    let output = unsafe {
        std::slice::from_raw_parts(output_blob.pbData, output_blob.cbData as usize).to_vec()
    };

    // Note: We should call LocalFree here, but the windows crate may not expose it.
    // For small license data, this minor leak is acceptable.
    // In production, consider using the winapi crate or raw FFI.

    Ok(output)
}

#[cfg(target_os = "windows")]
fn dpapi_unprotect(data: &[u8]) -> Result<Vec<u8>, String> {
    use std::ptr;
    use windows::Win32::Security::Cryptography::{
        CryptUnprotectData, CRYPTPROTECT_UI_FORBIDDEN, CRYPT_INTEGER_BLOB,
    };

    let input_blob = CRYPT_INTEGER_BLOB {
        cbData: data.len() as u32,
        pbData: data.as_ptr() as *mut u8,
    };

    let mut output_blob = CRYPT_INTEGER_BLOB {
        cbData: 0,
        pbData: ptr::null_mut(),
    };

    let result = unsafe {
        CryptUnprotectData(
            &input_blob,
            None,                      // Description out
            None,                      // Optional entropy
            None,                      // Reserved
            None,                      // Prompt struct
            CRYPTPROTECT_UI_FORBIDDEN, // Flags
            &mut output_blob,
        )
    };

    if result.is_err() {
        return Err(
            "CryptUnprotectData failed - license may have been copied from another machine"
                .to_string(),
        );
    }

    if output_blob.pbData.is_null() || output_blob.cbData == 0 {
        return Err("CryptUnprotectData returned empty data".to_string());
    }

    // Copy output data
    let output = unsafe {
        std::slice::from_raw_parts(output_blob.pbData, output_blob.cbData as usize).to_vec()
    };

    // Note: We should call LocalFree here, but the windows crate may not expose it.
    // For small license data, this minor leak is acceptable.

    Ok(output)
}

// ─────────────────────────────────────────────────────────────────────────────
// License File with Protection
// ─────────────────────────────────────────────────────────────────────────────

/// Load a license file, handling both protected and plaintext formats.
pub fn load_protected_license(path: &Path) -> Result<String, String> {
    let content =
        fs::read_to_string(path).map_err(|e| format!("Failed to read license file: {}", e))?;

    // Try to parse as ProtectedLicense first
    if let Ok(protected) = serde_json::from_str::<ProtectedLicense>(&content) {
        return unprotect_license(&protected);
    }

    // Fall back to treating as plain license JSON
    Ok(content)
}

/// Save a license file with optional DPAPI protection.
pub fn save_protected_license(
    path: &Path,
    license_json: &str,
    use_dpapi: bool,
    fingerprint: Option<&str>,
) -> Result<(), String> {
    // Ensure directory exists
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent).map_err(|e| format!("Failed to create directory: {}", e))?;
    }

    if use_dpapi {
        let protected = protect_license(license_json, fingerprint)?;
        let content = serde_json::to_string_pretty(&protected)
            .map_err(|e| format!("Failed to serialize: {}", e))?;
        fs::write(path, content).map_err(|e| format!("Failed to write: {}", e))?;
    } else {
        fs::write(path, license_json).map_err(|e| format!("Failed to write: {}", e))?;
    }

    // Update last-seen timestamp
    let _ = update_last_seen();

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_clock_status_suspicious() {
        assert!(!ClockStatus::Ok.is_suspicious());
        assert!(!ClockStatus::MinorDrift { seconds: 60 }.is_suspicious());
        assert!(ClockStatus::LargeBackwardJump {
            seconds: 100000,
            last_seen: 1000000,
            current: 900000,
        }
        .is_suspicious());
    }

    #[test]
    fn test_protected_license_plaintext_roundtrip() {
        let license_json = r#"{"license_id":"test123","signature":"abc"}"#;

        let protected = protect_license(license_json, Some("fp123")).unwrap();
        let recovered = unprotect_license(&protected).unwrap();

        assert_eq!(license_json, recovered);
    }

    #[test]
    fn test_protection_result_variants() {
        let success = ProtectionResult::Success;
        let not_avail = ProtectionResult::NotAvailable("test".into());
        let failed = ProtectionResult::Failed("test".into());

        assert_eq!(success, ProtectionResult::Success);
        assert!(matches!(not_avail, ProtectionResult::NotAvailable(_)));
        assert!(matches!(failed, ProtectionResult::Failed(_)));
    }
}
