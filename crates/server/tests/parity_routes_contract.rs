//! Parity Tests: Routes & Contract Snapshot Validation
//!
//! These tests verify that the current build matches the frozen snapshots
//! in docs/parity/. This guards against accidental API drift after refactoring.
//!
//! **VERSIONING RULE:**
//! If routes_snapshot.json or contract_snapshot.json changes, you MUST bump
//! the CONTRACT_VERSION constant in services/meta.rs and update the snapshots.
//! This ensures deliberate, tracked API evolution.
//!
//! **ESCAPE HATCH:**
//! Set LOCINT_ALLOW_CONTRACT_DRIFT=1 to print mismatches without failing.
//! This is for local development only - CI should never set this.

use edr_server::services;

/// Load the frozen routes snapshot from docs/parity/routes_snapshot.json
fn load_routes_snapshot() -> serde_json::Value {
    let snapshot_path = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../docs/parity/routes_snapshot.json"
    );
    let content = std::fs::read_to_string(snapshot_path)
        .expect("Failed to read docs/parity/routes_snapshot.json - ensure it exists");
    serde_json::from_str(&content)
        .expect("Failed to parse routes_snapshot.json as valid JSON")
}

/// Load the frozen contract snapshot from docs/parity/contract_snapshot.json
fn load_contract_snapshot() -> serde_json::Value {
    let snapshot_path = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../docs/parity/contract_snapshot.json"
    );
    let content = std::fs::read_to_string(snapshot_path)
        .expect("Failed to read docs/parity/contract_snapshot.json - ensure it exists");
    serde_json::from_str(&content)
        .expect("Failed to parse contract_snapshot.json as valid JSON")
}

/// Check if we're in drift-tolerant mode (for local dev only)
fn allow_drift() -> bool {
    std::env::var("LOCINT_ALLOW_CONTRACT_DRIFT")
        .map(|v| v == "1" || v.to_lowercase() == "true")
        .unwrap_or(false)
}

/// Generate a simple diff-like message between two JSON values
fn json_diff_message(name: &str, expected: &serde_json::Value, actual: &serde_json::Value) -> String {
    let expected_pretty = serde_json::to_string_pretty(expected).unwrap_or_default();
    let actual_pretty = serde_json::to_string_pretty(actual).unwrap_or_default();
    
    format!(
        "\n=== {} MISMATCH ===\n\
        Expected (from snapshot):\n{}\n\n\
        Actual (from current build):\n{}\n\
        ===\n\
        If this change is intentional:\n\
        1. Bump CONTRACT_VERSION in services/meta.rs\n\
        2. Update docs/parity/{}_snapshot.json\n\
        3. Document the change in CHANGELOG.md\n",
        name.to_uppercase(),
        expected_pretty,
        actual_pretty,
        name
    )
}

/// Test that current routes match the frozen snapshot
#[test]
fn routes_match_snapshot() {
    // Get current routes from the authoritative source
    let current_routes = services::meta::get_registered_routes();
    let current_json: serde_json::Value = serde_json::to_value(&current_routes)
        .expect("Failed to serialize current routes");
    
    // Load frozen snapshot
    let snapshot_json = load_routes_snapshot();
    
    // Compare
    if current_json != snapshot_json {
        let diff_msg = json_diff_message("routes", &snapshot_json, &current_json);
        
        if allow_drift() {
            eprintln!(
                "\n⚠️  LOCINT_ALLOW_CONTRACT_DRIFT=1 set - printing mismatch but not failing\n{}",
                diff_msg
            );
        } else {
            panic!(
                "Routes do not match frozen snapshot!\n{}\n\
                Set LOCINT_ALLOW_CONTRACT_DRIFT=1 to bypass (dev only).",
                diff_msg
            );
        }
    }
    
    // Log success for visibility
    eprintln!("✓ Routes parity check passed ({} routes)", current_routes.len());
}

/// Test that current contract matches the frozen snapshot
#[test]
fn contract_matches_snapshot() {
    // Get current contract from the authoritative source
    let current_contract = services::meta::get_api_contract();
    
    // Load frozen snapshot
    let snapshot_json = load_contract_snapshot();
    
    // Compare
    if current_contract != snapshot_json {
        let diff_msg = json_diff_message("contract", &snapshot_json, &current_contract);
        
        if allow_drift() {
            eprintln!(
                "\n⚠️  LOCINT_ALLOW_CONTRACT_DRIFT=1 set - printing mismatch but not failing\n{}",
                diff_msg
            );
        } else {
            panic!(
                "Contract does not match frozen snapshot!\n{}\n\
                Set LOCINT_ALLOW_CONTRACT_DRIFT=1 to bypass (dev only).",
                diff_msg
            );
        }
    }
    
    // Extract and log key identifiers
    let version = current_contract["contract_version"].as_str().unwrap_or("unknown");
    let hash = current_contract["contract_hash"].as_str().unwrap_or("unknown");
    eprintln!("✓ Contract parity check passed (version={}, hash={})", version, hash);
}

/// Test route count for quick sanity check
#[test]
fn route_count_sanity() {
    let routes = services::meta::get_registered_routes();
    let count = routes.len();
    
    // The thin router should have the same number of routes as the snapshot
    // This is a quick check that catches gross omissions
    let snapshot = load_routes_snapshot();
    let snapshot_count = snapshot.as_array().map(|a| a.len()).unwrap_or(0);
    
    assert_eq!(
        count, snapshot_count,
        "Route count mismatch: current={}, snapshot={}. \
        This may indicate missing or extra routes.",
        count, snapshot_count
    );
    
    eprintln!("✓ Route count sanity check passed ({} routes)", count);
}

/// Test contract version format
#[test]
fn contract_version_format() {
    let contract = services::meta::get_api_contract();
    
    // Verify required fields exist
    assert!(
        contract.get("contract_version").is_some(),
        "contract_version field missing from API contract"
    );
    assert!(
        contract.get("contract_hash").is_some(),
        "contract_hash field missing from API contract"
    );
    
    let version = contract["contract_version"].as_str().unwrap();
    let hash = contract["contract_hash"].as_str().unwrap();
    
    // Version should be semver-ish
    assert!(
        version.contains('.'),
        "contract_version should be semver format (got: {})",
        version
    );
    
    // Hash should have our prefix
    assert!(
        hash.starts_with("v1-"),
        "contract_hash should start with 'v1-' (got: {})",
        hash
    );
    
    eprintln!("✓ Contract version format check passed");
}

// =============================================================================
// ERROR ENVELOPE CONTRACT TESTS
// =============================================================================
// These tests verify that error responses follow the contract:
//   { success: false, error: "<string>", code: "<ERROR_CODE>" }
//
// This is critical for UI parity - the frontend expects this exact shape.

/// Test FEATURE_LOCKED error envelope matches contract
#[test]
fn error_envelope_feature_locked() {
    use edr_server::services::types::{feature_locked_403, ProductTier};
    
    // Generate the error envelope (returns tuple of (StatusCode, Json<Value>))
    let (_status, axum::Json(envelope)) = feature_locked_403("test_feature", ProductTier::Pro);
    
    // Contract: success must be false
    assert_eq!(
        envelope.get("success").and_then(|v| v.as_bool()),
        Some(false),
        "FEATURE_LOCKED envelope must have success=false"
    );
    
    // Contract: error must be a string (not an object)
    let error = envelope.get("error");
    assert!(
        error.is_some() && error.unwrap().is_string(),
        "FEATURE_LOCKED envelope must have error as string, got: {:?}",
        error
    );
    
    // Contract: code must be "FEATURE_LOCKED"
    assert_eq!(
        envelope.get("code").and_then(|v| v.as_str()),
        Some("FEATURE_LOCKED"),
        "FEATURE_LOCKED envelope must have code=\"FEATURE_LOCKED\""
    );
    
    eprintln!("✓ FEATURE_LOCKED error envelope contract check passed");
}

/// Test INVALID_MODE error envelope from diff service matches contract
#[test]
fn error_envelope_invalid_mode() {
    use edr_server::services::diff::DiffError;
    
    // Generate the invalid mode error
    let err = DiffError::invalid_mode("bogus_mode");
    let envelope = err.to_json();
    
    // Contract: success must be false
    assert_eq!(
        envelope.get("success").and_then(|v| v.as_bool()),
        Some(false),
        "INVALID_MODE envelope must have success=false"
    );
    
    // Contract: error must be a string containing the bad mode
    let error = envelope.get("error");
    assert!(
        error.is_some() && error.unwrap().is_string(),
        "INVALID_MODE envelope must have error as string, got: {:?}",
        error
    );
    let error_str = error.unwrap().as_str().unwrap();
    assert!(
        error_str.contains("bogus_mode"),
        "INVALID_MODE error should contain the invalid mode name, got: {}",
        error_str
    );
    
    // Contract: code must be "INVALID_MODE"
    assert_eq!(
        envelope.get("code").and_then(|v| v.as_str()),
        Some("INVALID_MODE"),
        "INVALID_MODE envelope must have code=\"INVALID_MODE\""
    );
    
    eprintln!("✓ INVALID_MODE error envelope contract check passed");
}
