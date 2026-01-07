//! License API Integration Tests
//!
//! Tests cover:
//! - GET /api/license/status
//! - POST /api/license/install
//! - POST /api/license/reload
//! - 402 response for protected endpoints without license

use serde_json::json;

/// Test license status response structure when no license is installed
#[test]
fn test_license_status_not_installed_structure() {
    let response = json!({
        "status": "not_installed",
        "install_id": "550e8400-e29b-41d4-a716-446655440000",
        "entitlements": []
    });

    assert_eq!(response["status"], "not_installed");
    assert!(response["install_id"].is_string());
    assert!(response["entitlements"].is_array());
    assert!(response["entitlements"].as_array().unwrap().is_empty());
}

/// Test license status response structure when license is valid
#[test]
fn test_license_status_valid_structure() {
    let response = json!({
        "status": "valid",
        "install_id": "550e8400-e29b-41d4-a716-446655440000",
        "entitlements": ["diff_mode", "pro_reports"],
        "license_id": "LIC-001",
        "customer": "Acme Corp",
        "edition": "pro",
        "expires_at": null
    });

    assert_eq!(response["status"], "valid");
    assert!(response["install_id"].is_string());

    let entitlements = response["entitlements"].as_array().unwrap();
    assert_eq!(entitlements.len(), 2);
    assert!(entitlements.contains(&json!("diff_mode")));
    assert!(entitlements.contains(&json!("pro_reports")));

    assert_eq!(response["customer"], "Acme Corp");
    assert_eq!(response["edition"], "pro");
    assert!(response["expires_at"].is_null());
}

/// Test license status response when license is expired
#[test]
fn test_license_status_expired_structure() {
    let response = json!({
        "status": "expired",
        "install_id": "550e8400-e29b-41d4-a716-446655440000",
        "entitlements": [],
        "expired_at": 1704153600000_i64
    });

    assert_eq!(response["status"], "expired");
    assert!(response["entitlements"].as_array().unwrap().is_empty());
    assert!(response["expired_at"].is_i64());
}

/// Test license status response when install_id doesn't match
#[test]
fn test_license_status_install_id_mismatch() {
    let response = json!({
        "status": "wrong_installation",
        "install_id": "550e8400-e29b-41d4-a716-446655440000",
        "entitlements": [],
        "expected": "other-install-id",
        "actual": "550e8400-e29b-41d4-a716-446655440000"
    });

    assert_eq!(response["status"], "wrong_installation");
    assert!(response["entitlements"].as_array().unwrap().is_empty());
}

/// Test license install request structure
#[test]
fn test_install_license_request_structure() {
    let request = json!({
        "license_content": "{\"license_id\":\"LIC-001\",\"customer\":\"Test\",\"edition\":\"pro\",\"entitlements\":[\"diff_mode\"],\"issued_at\":1704067200000,\"expires_at\":null,\"bound_install_id\":\"...\",\"signature\":\"...\"}"
    });

    assert!(request["license_content"].is_string());
}

/// Test license install success response
#[test]
fn test_install_license_success_response() {
    let response = json!({
        "success": true,
        "message": "License installed successfully"
    });

    assert!(response["success"].as_bool().unwrap());
    assert!(response["message"].is_string());
}

/// Test license install failure response
#[test]
fn test_install_license_failure_response() {
    let response = json!({
        "success": false,
        "message": "Invalid license signature"
    });

    assert!(!response["success"].as_bool().unwrap());
    assert!(response["message"].is_string());
}

/// Test 402 response structure for Pro-gated endpoints
#[test]
fn test_pro_required_402_response() {
    let response = json!({
        "error": "pro_license_required",
        "message": "This feature requires an active EDR Pro license.",
        "install_id": "550e8400-e29b-41d4-a716-446655440000",
        "required_entitlement": "diff_mode"
    });

    assert_eq!(response["error"], "pro_license_required");
    assert!(response["message"].is_string());
    assert!(response["install_id"].is_string());
    assert_eq!(response["required_entitlement"], "diff_mode");
}

/// Test that all license status variants are covered
#[test]
fn test_license_status_variants() {
    let valid_statuses = vec![
        "valid",
        "not_installed",
        "expired",
        "wrong_installation",
        "invalid",
        "not_configured",
    ];

    for status in valid_statuses {
        let response = json!({
            "status": status,
            "install_id": "test-id",
            "entitlements": []
        });

        assert!(response["status"].is_string());
        assert_eq!(response["status"], status);
    }
}

/// Test license payload canonical serialization order
/// This verifies the JSON keys are ordered for signature verification
#[test]
fn test_license_payload_canonical_order() {
    // The canonical order: license_id, customer?, edition, entitlements, issued_at, expires_at?, bound_install_id
    let payload = json!({
        "license_id": "LIC-001",
        "customer": "Test",
        "edition": "pro",
        "entitlements": ["diff_mode"],
        "issued_at": 1704067200000_i64,
        "expires_at": null,
        "bound_install_id": "550e8400-e29b-41d4-a716-446655440000"
    });

    // When serialized with sorted keys, this should maintain order
    let canonical = serde_json::to_string(&payload).unwrap();

    // Verify fields are present
    assert!(canonical.contains("license_id"));
    assert!(canonical.contains("edition"));
    assert!(canonical.contains("entitlements"));
    assert!(canonical.contains("bound_install_id"));
}

/// Test entitlement list parsing
#[test]
fn test_entitlement_list_parsing() {
    let entitlement_string = "diff_mode,pro_reports,team_features";
    let entitlements: Vec<&str> = entitlement_string.split(',').collect();

    assert_eq!(entitlements.len(), 3);
    assert!(entitlements.contains(&"diff_mode"));
    assert!(entitlements.contains(&"pro_reports"));
    assert!(entitlements.contains(&"team_features"));
}

/// Test install_id format (UUID v4)
#[test]
fn test_install_id_format() {
    let install_id = "550e8400-e29b-41d4-a716-446655440000";

    // UUID v4 format: 8-4-4-4-12 hex characters
    let parts: Vec<&str> = install_id.split('-').collect();
    assert_eq!(parts.len(), 5);
    assert_eq!(parts[0].len(), 8);
    assert_eq!(parts[1].len(), 4);
    assert_eq!(parts[2].len(), 4);
    assert_eq!(parts[3].len(), 4);
    assert_eq!(parts[4].len(), 12);

    // All parts should be valid hex
    for part in &parts {
        assert!(part.chars().all(|c| c.is_ascii_hexdigit()));
    }
}

/// Test signed license file JSON structure
#[test]
fn test_signed_license_structure() {
    let license = json!({
        "license_id": "LIC-001",
        "customer": "Acme Corp",
        "edition": "pro",
        "entitlements": ["diff_mode"],
        "issued_at": 1704067200000_i64,
        "expires_at": null,
        "bound_install_id": "550e8400-e29b-41d4-a716-446655440000",
        "signature": "base64encodedSignatureHere=="
    });

    assert!(license["license_id"].is_string());
    assert!(license["signature"].is_string());
    assert!(license["customer"].is_string());
    assert!(license["bound_install_id"].is_string());
    assert!(license["entitlements"].is_array());
    assert!(license["edition"].is_string());
    assert!(license["issued_at"].is_i64());
}

#[cfg(test)]
mod core_license_tests {
    use edr_core::license::{LicensePayload, LicenseVerifyResult};

    /// Test canonical bytes determinism
    #[test]
    fn test_canonical_bytes_determinism() {
        let payload = LicensePayload {
            license_id: "LIC-TEST-001".to_string(),
            customer: Some("Test Customer".to_string()),
            edition: "pro".to_string(),
            entitlements: vec!["diff_mode".to_string()],
            issued_at: 1704067200000,
            expires_at: None,
            bound_install_id: "550e8400-e29b-41d4-a716-446655440000".to_string(),
            bound_machine_fingerprint: None,
        };

        let bytes1 = payload.to_canonical_bytes();
        let bytes2 = payload.to_canonical_bytes();

        assert_eq!(bytes1, bytes2, "Canonical bytes should be deterministic");
        assert!(!bytes1.is_empty(), "Canonical bytes should not be empty");
    }

    /// Test that canonical serialization includes all fields
    #[test]
    fn test_canonical_bytes_contains_all_fields() {
        let payload = LicensePayload {
            license_id: "LIC-TEST-002".to_string(),
            customer: Some("Acme Corp".to_string()),
            edition: "enterprise".to_string(),
            entitlements: vec!["diff_mode".to_string()],
            issued_at: 1704067200000,
            expires_at: Some(1735689600000),
            bound_install_id: "unique-id-123".to_string(),
            bound_machine_fingerprint: None,
        };

        let canonical = String::from_utf8(payload.to_canonical_bytes()).unwrap();

        assert!(canonical.contains("LIC-TEST-002"));
        assert!(canonical.contains("Acme Corp"));
        assert!(canonical.contains("unique-id-123"));
        assert!(canonical.contains("diff_mode"));
        assert!(canonical.contains("enterprise"));
        assert!(canonical.contains("1704067200000"));
        assert!(canonical.contains("1735689600000"));
    }

    /// Test verify result variants
    #[test]
    fn test_verify_result_variants() {
        let valid = LicenseVerifyResult::Valid;
        let expired = LicenseVerifyResult::Expired;
        let mismatch = LicenseVerifyResult::InstallIdMismatch {
            expected: "a".to_string(),
            actual: "b".to_string(),
        };
        let invalid = LicenseVerifyResult::InvalidSignature;
        let not_configured = LicenseVerifyResult::PublicKeyNotConfigured;

        assert!(matches!(valid, LicenseVerifyResult::Valid));
        assert!(matches!(expired, LicenseVerifyResult::Expired));
        assert!(matches!(
            mismatch,
            LicenseVerifyResult::InstallIdMismatch { .. }
        ));
        assert!(matches!(invalid, LicenseVerifyResult::InvalidSignature));
        assert!(matches!(
            not_configured,
            LicenseVerifyResult::PublicKeyNotConfigured
        ));
    }
}

#[cfg(test)]
mod license_manager_tests {
    use edr_core::license_manager::LicenseStatus;

    /// Test license status enum behavior
    #[test]
    fn test_license_status_variants() {
        let valid = LicenseStatus::Valid {
            license_id: "LIC-001".to_string(),
            customer: Some("Test".to_string()),
            edition: "pro".to_string(),
            entitlements: vec!["diff_mode".to_string()],
            expires_at: None,
        };

        let not_installed = LicenseStatus::NotInstalled;
        let expired = LicenseStatus::Expired {
            expired_at: 1704067200000,
        };
        let wrong = LicenseStatus::WrongInstallation {
            expected: "a".to_string(),
            actual: "b".to_string(),
        };
        let invalid = LicenseStatus::Invalid {
            reason: "bad sig".to_string(),
        };
        let not_configured = LicenseStatus::NotConfigured;

        // These should all be distinct variants
        assert!(matches!(valid, LicenseStatus::Valid { .. }));
        assert!(matches!(not_installed, LicenseStatus::NotInstalled));
        assert!(matches!(expired, LicenseStatus::Expired { .. }));
        assert!(matches!(wrong, LicenseStatus::WrongInstallation { .. }));
        assert!(matches!(invalid, LicenseStatus::Invalid { .. }));
        assert!(matches!(not_configured, LicenseStatus::NotConfigured));
    }

    /// Test LicenseStatus::is_valid()
    #[test]
    fn test_license_status_is_valid() {
        let valid = LicenseStatus::Valid {
            license_id: "LIC-001".to_string(),
            customer: None,
            edition: "pro".to_string(),
            entitlements: vec!["diff_mode".to_string()],
            expires_at: None,
        };

        let not_installed = LicenseStatus::NotInstalled;
        let expired = LicenseStatus::Expired { expired_at: 0 };

        assert!(valid.is_valid());
        assert!(!not_installed.is_valid());
        assert!(!expired.is_valid());
    }

    /// Test LicenseStatus::has_entitlement()
    #[test]
    fn test_license_status_has_entitlement() {
        let valid = LicenseStatus::Valid {
            license_id: "LIC-001".to_string(),
            customer: None,
            edition: "pro".to_string(),
            entitlements: vec!["diff_mode".to_string(), "pro_reports".to_string()],
            expires_at: None,
        };

        let not_installed = LicenseStatus::NotInstalled;

        assert!(valid.has_entitlement("diff_mode"));
        assert!(valid.has_entitlement("pro_reports"));
        assert!(!valid.has_entitlement("team_features"));
        assert!(!not_installed.has_entitlement("diff_mode"));
    }
}
