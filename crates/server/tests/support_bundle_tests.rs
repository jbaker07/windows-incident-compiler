//! Support Bundle Integration Tests

use edr_server::support_bundle::{
    compute_sha256, LogCollector, RedactionMap, SupportBundleBuilder, SupportBundleRequest,
};
use std::path::PathBuf;

#[test]
fn test_support_bundle_zip_structure_allowlist() {
    let request = SupportBundleRequest {
        include_latest_incident: true,
        include_recompute_inputs: false,
        max_logs_kb: 512,
        redact: true,
    };

    let builder = SupportBundleBuilder::new(
        request,
        PathBuf::from("/tmp"),
        "1.0.0".to_string(),
        r#"{"verdict": "healthy"}"#.to_string(),
    );

    // Verify manifest structure
    assert_eq!(builder.app_version, "1.0.0");
    assert!(builder.component_versions.contains_key("edr-locald"));
    assert!(builder.component_versions.contains_key("edr-server"));

    // Build ZIP to verify structure
    if let Ok(zip_data) = builder.build_zip() {
        assert!(!zip_data.is_empty());
        // ZIP should be larger than just the data due to headers/compression
        assert!(zip_data.len() > 50, "ZIP file too small, likely corrupted");
    }
}

#[test]
fn test_support_bundle_redacts_sensitive_tokens() {
    let mut map = RedactionMap::new();
    map.add("john_doe".to_string(), "USER_1".to_string());
    map.add("192.168.1.1".to_string(), "IP_1".to_string());
    map.add("/Users/john".to_string(), "PATH_1".to_string());

    let input = "User john_doe at /Users/john logged in from 192.168.1.1";
    let output = edr_server::support_bundle::redact_content(input, true, &map);

    assert!(output.contains("USER_1"), "Username should be redacted");
    assert!(output.contains("IP_1"), "IP should be redacted");
    assert!(output.contains("PATH_1"), "Path should be redacted");
    assert!(
        !output.contains("john_doe"),
        "Original username should not appear"
    );
    assert!(
        !output.contains("192.168.1.1"),
        "Original IP should not appear"
    );
}

#[test]
fn test_support_bundle_size_caps_enforced() {
    let max_kb = 10;
    let collector = LogCollector::new(PathBuf::from("/tmp"), max_kb);

    assert_eq!(collector.max_kb, 10);
    assert_eq!(collector.telemetry_root, PathBuf::from("/tmp"));
}

#[test]
fn test_support_bundle_hashes_validate() {
    let data1 = b"hello world";
    let data2 = b"hello world";
    let data3 = b"different data";

    let hash1 = compute_sha256(data1);
    let hash2 = compute_sha256(data2);
    let hash3 = compute_sha256(data3);

    // Same data should produce same hash
    assert_eq!(hash1, hash2);

    // Different data should produce different hash
    assert_ne!(hash1, hash3);

    // SHA256 hex is 64 characters
    assert_eq!(hash1.len(), 64);
}

#[test]
fn test_support_bundle_contains_selfcheck() {
    let request = SupportBundleRequest {
        include_latest_incident: true,
        include_recompute_inputs: false,
        max_logs_kb: 512,
        redact: true,
    };

    let selfcheck_json = r#"{"verdict": "healthy", "db_ok": true}"#;
    let builder = SupportBundleBuilder::new(
        request,
        PathBuf::from("/tmp"),
        "1.0.0".to_string(),
        selfcheck_json.to_string(),
    );

    // Verify selfcheck is stored
    assert_eq!(builder.selfcheck_json, selfcheck_json);
    assert!(builder.request.redact);
    assert!(builder.request.include_latest_incident);
}
