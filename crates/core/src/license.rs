//! License Schema and Cryptographic Verification
//!
//! Defines the license file format and implements Ed25519 signature verification.
//! Licenses are JSON files containing entitlements bound to a specific installation.

use serde::{Deserialize, Serialize};

// ─────────────────────────────────────────────────────────────────────────────
// Ed25519 Public Keys (embedded in application)
// ─────────────────────────────────────────────────────────────────────────────

/// The Ed25519 public key used to verify license signatures.
/// This is the only key that can validate licenses; the private key is held by the vendor.
///
/// To generate a new keypair, run: `cargo run --bin license_gen -- --generate-keypair`
///
/// IMPORTANT: Replace this placeholder with your actual public key before shipping!
pub const LICENSE_PUBLIC_KEY_B64: &str = "REPLACE_WITH_YOUR_PUBLIC_KEY_BASE64";

/// Additional public keys for key rotation support.
/// When rotating keys:
/// 1. Add the new key to this list
/// 2. Update LICENSE_PUBLIC_KEY_B64 to the new key
/// 3. Old licenses signed with rotated keys will still verify
///
/// Format: Array of base64-encoded Ed25519 public keys (32 bytes each)
pub const LICENSE_PUBLIC_KEYS_ROTATED: &[&str] = &[
    // Add rotated keys here, e.g.:
    // "OLD_KEY_1_BASE64",
    // "OLD_KEY_2_BASE64",
];

/// Get all valid public keys (current + rotated) for verification.
pub fn get_all_public_keys() -> Vec<&'static str> {
    let mut keys = vec![LICENSE_PUBLIC_KEY_B64];
    keys.extend(LICENSE_PUBLIC_KEYS_ROTATED.iter().copied());
    keys
}

// ─────────────────────────────────────────────────────────────────────────────
// License Schema Types
// ─────────────────────────────────────────────────────────────────────────────

/// The payload portion of a license (everything except the signature).
/// This is what gets signed and verified.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct LicensePayload {
    /// Unique identifier for this license
    pub license_id: String,

    /// Customer name (optional, for display purposes)
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub customer: Option<String>,

    /// Edition tier: "pro", "team", etc.
    pub edition: String,

    /// List of granted entitlements (e.g., ["diff_mode", "pro_reports"])
    pub entitlements: Vec<String>,

    /// Unix timestamp (milliseconds) when the license was issued
    pub issued_at: i64,

    /// Unix timestamp (milliseconds) when the license expires.
    /// None means perpetual license.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expires_at: Option<i64>,

    /// The installation ID this license is bound to
    pub bound_install_id: String,

    /// Optional machine fingerprint for enhanced binding.
    /// If present, the license only validates on machines with matching fingerprint.
    /// Set to "PORTABLE" for development/testing licenses that work on any machine.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub bound_machine_fingerprint: Option<String>,
}

/// A complete signed license containing payload and signature.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SignedLicense {
    /// The license payload (all fields except signature)
    #[serde(flatten)]
    pub payload: LicensePayload,

    /// Base64-encoded Ed25519 signature over the canonical payload
    pub signature: String,
}

/// Known entitlement identifiers
pub mod entitlements {
    /// Diff Mode - compare signal snapshots between runs
    pub const DIFF_MODE: &str = "diff_mode";

    /// Pro Reports - enhanced PDF report generation
    pub const PRO_REPORTS: &str = "pro_reports";

    /// Team Features - collaboration and sharing (future)
    pub const TEAM_FEATURES: &str = "team_features";
}

// ─────────────────────────────────────────────────────────────────────────────
// Canonical Serialization
// ─────────────────────────────────────────────────────────────────────────────

impl LicensePayload {
    /// Serialize the payload to canonical JSON bytes for signing/verification.
    ///
    /// Uses a deterministic field order to ensure consistent signatures:
    /// license_id, customer, edition, entitlements, issued_at, expires_at, bound_install_id, bound_machine_fingerprint
    pub fn to_canonical_bytes(&self) -> Vec<u8> {
        // Build canonical JSON manually to ensure field order
        let mut parts = Vec::new();

        parts.push(format!(
            r#""license_id":"{}""#,
            escape_json(&self.license_id)
        ));

        if let Some(ref customer) = self.customer {
            parts.push(format!(r#""customer":"{}""#, escape_json(customer)));
        }

        parts.push(format!(r#""edition":"{}""#, escape_json(&self.edition)));

        let ent_json: Vec<String> = self
            .entitlements
            .iter()
            .map(|e| format!(r#""{}""#, escape_json(e)))
            .collect();
        parts.push(format!(r#""entitlements":[{}]"#, ent_json.join(",")));

        parts.push(format!(r#""issued_at":{}"#, self.issued_at));

        if let Some(exp) = self.expires_at {
            parts.push(format!(r#""expires_at":{}"#, exp));
        }

        parts.push(format!(
            r#""bound_install_id":"{}""#,
            escape_json(&self.bound_install_id)
        ));

        if let Some(ref fp) = self.bound_machine_fingerprint {
            parts.push(format!(
                r#""bound_machine_fingerprint":"{}""#,
                escape_json(fp)
            ));
        }

        let canonical = format!("{{{}}}", parts.join(","));
        canonical.into_bytes()
    }
}

/// Escape special characters for JSON string values
fn escape_json(s: &str) -> String {
    s.replace('\\', "\\\\")
        .replace('"', "\\\"")
        .replace('\n', "\\n")
        .replace('\r', "\\r")
        .replace('\t', "\\t")
}

// ─────────────────────────────────────────────────────────────────────────────
// Signature Verification
// ─────────────────────────────────────────────────────────────────────────────

/// Result of license verification
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LicenseVerifyResult {
    /// License is valid
    Valid,
    /// Signature verification failed (tampered or wrong key)
    InvalidSignature,
    /// License has expired
    Expired,
    /// License is bound to a different installation
    InstallIdMismatch { expected: String, actual: String },
    /// License is bound to a different machine fingerprint
    MachineFingerPrintMismatch {
        expected: String,
        actual: Option<String>,
    },
    /// Public key is not configured (placeholder still in place)
    PublicKeyNotConfigured,
    /// Failed to decode the public key
    InvalidPublicKey,
    /// Failed to decode the signature
    InvalidSignatureFormat,
}

impl SignedLicense {
    /// Verify the license signature and binding.
    ///
    /// Checks:
    /// 1. Public key is properly configured
    /// 2. Signature is valid Ed25519 over canonical payload (tries all keys)
    /// 3. License has not expired
    /// 4. License is bound to the provided install_id
    /// 5. If machine fingerprint is set, verifies it matches
    pub fn verify(&self, install_id: &str) -> LicenseVerifyResult {
        self.verify_with_fingerprint(install_id, None)
    }

    /// Verify the license with optional machine fingerprint.
    ///
    /// If the license has a bound_machine_fingerprint that is not "PORTABLE",
    /// and machine_fingerprint is Some, they must match.
    pub fn verify_with_fingerprint(
        &self,
        install_id: &str,
        machine_fingerprint: Option<&str>,
    ) -> LicenseVerifyResult {
        // Check if public key is configured
        if LICENSE_PUBLIC_KEY_B64 == "REPLACE_WITH_YOUR_PUBLIC_KEY_BASE64" {
            return LicenseVerifyResult::PublicKeyNotConfigured;
        }

        // Decode signature
        let sig_bytes = match base64_decode(&self.signature) {
            Some(bytes) if bytes.len() == 64 => bytes,
            _ => return LicenseVerifyResult::InvalidSignatureFormat,
        };

        // Verify Ed25519 signature against all known public keys
        let canonical = self.payload.to_canonical_bytes();
        let mut signature_valid = false;

        for key_b64 in get_all_public_keys() {
            // Skip placeholder keys
            if key_b64 == "REPLACE_WITH_YOUR_PUBLIC_KEY_BASE64" || key_b64.is_empty() {
                continue;
            }

            if let Some(pub_key_bytes) = base64_decode(key_b64) {
                if pub_key_bytes.len() == 32
                    && ed25519_verify(&pub_key_bytes, &canonical, &sig_bytes)
                {
                    signature_valid = true;
                    break;
                }
            }
        }

        if !signature_valid {
            return LicenseVerifyResult::InvalidSignature;
        }

        // Check expiration
        if let Some(expires_at) = self.payload.expires_at {
            let now_ms = chrono::Utc::now().timestamp_millis();
            if now_ms > expires_at {
                return LicenseVerifyResult::Expired;
            }
        }

        // Check install_id binding
        if self.payload.bound_install_id != install_id {
            return LicenseVerifyResult::InstallIdMismatch {
                expected: self.payload.bound_install_id.clone(),
                actual: install_id.to_string(),
            };
        }

        // Check machine fingerprint binding (if specified in license)
        if let Some(ref bound_fp) = self.payload.bound_machine_fingerprint {
            // "PORTABLE" is a special value that matches any machine
            if bound_fp != "PORTABLE" {
                match machine_fingerprint {
                    Some(actual_fp) if actual_fp == bound_fp => {
                        // Match - continue
                    }
                    Some(actual_fp) => {
                        return LicenseVerifyResult::MachineFingerPrintMismatch {
                            expected: bound_fp.clone(),
                            actual: Some(actual_fp.to_string()),
                        };
                    }
                    None => {
                        // License requires fingerprint but we couldn't generate one
                        // This is a soft failure - log warning but allow
                        // (graceful degradation for VMs/restricted environments)
                    }
                }
            }
        }

        LicenseVerifyResult::Valid
    }

    /// Check if the license grants a specific entitlement.
    pub fn has_entitlement(&self, entitlement: &str) -> bool {
        self.payload.entitlements.iter().any(|e| e == entitlement)
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Ed25519 Implementation (minimal, no external crypto dependency)
// ─────────────────────────────────────────────────────────────────────────────

/// Decode base64 string to bytes
pub fn base64_decode(input: &str) -> Option<Vec<u8>> {
    // Standard base64 alphabet
    const ALPHABET: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

    let input = input.trim().replace(['\n', '\r', ' '], "");
    let input = input.trim_end_matches('=');

    if input.is_empty() {
        return Some(Vec::new());
    }

    let mut result = Vec::with_capacity(input.len() * 3 / 4);
    let mut buffer = 0u32;
    let mut bits = 0;

    for c in input.bytes() {
        let value = ALPHABET.iter().position(|&x| x == c)? as u32;
        buffer = (buffer << 6) | value;
        bits += 6;

        if bits >= 8 {
            bits -= 8;
            result.push((buffer >> bits) as u8);
            buffer &= (1 << bits) - 1;
        }
    }

    Some(result)
}

/// Encode bytes to base64 string
pub fn base64_encode(input: &[u8]) -> String {
    const ALPHABET: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

    let mut result = String::with_capacity(input.len().div_ceil(3) * 4);

    for chunk in input.chunks(3) {
        let b0 = chunk[0] as u32;
        let b1 = chunk.get(1).copied().unwrap_or(0) as u32;
        let b2 = chunk.get(2).copied().unwrap_or(0) as u32;

        let combined = (b0 << 16) | (b1 << 8) | b2;

        result.push(ALPHABET[(combined >> 18) as usize] as char);
        result.push(ALPHABET[((combined >> 12) & 0x3F) as usize] as char);

        if chunk.len() > 1 {
            result.push(ALPHABET[((combined >> 6) & 0x3F) as usize] as char);
        } else {
            result.push('=');
        }

        if chunk.len() > 2 {
            result.push(ALPHABET[(combined & 0x3F) as usize] as char);
        } else {
            result.push('=');
        }
    }

    result
}

/// Verify an Ed25519 signature.
/// This is a placeholder that will use the ed25519-dalek crate.
fn ed25519_verify(public_key: &[u8], message: &[u8], signature: &[u8]) -> bool {
    use ed25519_dalek::Verifier;
    use ed25519_dalek::{Signature, VerifyingKey};

    // Convert bytes to key types
    let Ok(pub_key_array): Result<[u8; 32], _> = public_key.try_into() else {
        return false;
    };
    let Ok(sig_array): Result<[u8; 64], _> = signature.try_into() else {
        return false;
    };

    let Ok(verifying_key) = VerifyingKey::from_bytes(&pub_key_array) else {
        return false;
    };
    let signature = Signature::from_bytes(&sig_array);

    verifying_key.verify(message, &signature).is_ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_canonical_bytes_deterministic() {
        let payload = LicensePayload {
            license_id: "lic_123".to_string(),
            customer: Some("Test Corp".to_string()),
            edition: "pro".to_string(),
            entitlements: vec!["diff_mode".to_string()],
            issued_at: 1700000000000,
            expires_at: Some(1800000000000),
            bound_install_id: "install-uuid".to_string(),
            bound_machine_fingerprint: None,
        };

        let bytes1 = payload.to_canonical_bytes();
        let bytes2 = payload.to_canonical_bytes();

        assert_eq!(
            bytes1, bytes2,
            "Canonical serialization must be deterministic"
        );
    }

    #[test]
    fn test_canonical_bytes_format() {
        let payload = LicensePayload {
            license_id: "lic_123".to_string(),
            customer: None,
            edition: "pro".to_string(),
            entitlements: vec!["diff_mode".to_string()],
            issued_at: 1700000000000,
            expires_at: None,
            bound_install_id: "install-uuid".to_string(),
            bound_machine_fingerprint: None,
        };

        let bytes = payload.to_canonical_bytes();
        let json_str = String::from_utf8(bytes).unwrap();

        // Should be valid JSON
        assert!(json_str.starts_with('{'));
        assert!(json_str.ends_with('}'));
        assert!(json_str.contains(r#""license_id":"lic_123""#));
        // Should NOT contain customer when None
        assert!(!json_str.contains("customer"));
    }

    #[test]
    fn test_base64_roundtrip() {
        let original = b"Hello, World!";
        let encoded = base64_encode(original);
        let decoded = base64_decode(&encoded).unwrap();
        assert_eq!(original.to_vec(), decoded);
    }

    #[test]
    fn test_base64_decode_standard() {
        // "Hello" in base64
        let decoded = base64_decode("SGVsbG8=").unwrap();
        assert_eq!(decoded, b"Hello");
    }

    #[test]
    fn test_has_entitlement() {
        let license = SignedLicense {
            payload: LicensePayload {
                license_id: "test".to_string(),
                customer: None,
                edition: "pro".to_string(),
                entitlements: vec!["diff_mode".to_string(), "pro_reports".to_string()],
                issued_at: 0,
                expires_at: None,
                bound_install_id: "test".to_string(),
                bound_machine_fingerprint: None,
            },
            signature: String::new(),
        };

        assert!(license.has_entitlement("diff_mode"));
        assert!(license.has_entitlement("pro_reports"));
        assert!(!license.has_entitlement("team_features"));
    }

    #[test]
    fn test_verify_public_key_not_configured() {
        let license = SignedLicense {
            payload: LicensePayload {
                license_id: "test".to_string(),
                customer: None,
                edition: "pro".to_string(),
                entitlements: vec![],
                issued_at: 0,
                expires_at: None,
                bound_install_id: "test".to_string(),
                bound_machine_fingerprint: None,
            },
            signature: String::new(),
        };

        // With the placeholder key, verification should return PublicKeyNotConfigured
        let result = license.verify("test");
        assert_eq!(result, LicenseVerifyResult::PublicKeyNotConfigured);
    }

    #[test]
    fn test_escape_json() {
        assert_eq!(escape_json("hello"), "hello");
        assert_eq!(escape_json(r#"say "hi""#), r#"say \"hi\""#);
        assert_eq!(escape_json("line1\nline2"), r#"line1\nline2"#);
    }
}
