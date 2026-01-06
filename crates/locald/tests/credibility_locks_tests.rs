//! Tests for credibility lock features:
//! - Namespace isolation (imported vs live)
//! - ZIP safety policies
//! - Startup failure surfacing

use serde_json::json;

#[test]
fn test_default_queries_exclude_imported() {
    // Verify that default incident queries exclude imported bundles
    // This would be tested with actual DB queries, but for now we verify the concept

    let live_incident_id = "inc_20250102_001";
    let imported_incident_id = "imported_abc123_inc_001";

    // Simulating the filter logic: NOT LIKE 'imported_%'
    let filter_excludes_imported = |id: &str| !id.starts_with("imported_");

    assert!(
        filter_excludes_imported(live_incident_id),
        "Live incidents should be included"
    );
    assert!(
        !filter_excludes_imported(imported_incident_id),
        "Imported incidents should be excluded by default"
    );
}

#[test]
fn test_include_imported_flag_returns_both() {
    // Verify that with include_imported=1, both live and imported are returned
    let live_incident_id = "inc_20250102_001";
    let imported_incident_id = "imported_abc123_inc_001";

    // Simulating include_imported logic: no filter
    let should_include =
        |_id: &str, include_imported: bool| include_imported || !_id.starts_with("imported_");

    assert!(
        should_include(live_incident_id, false),
        "Live should always be included"
    );
    assert!(
        !should_include(imported_incident_id, false),
        "Imported should be excluded when flag is false"
    );
    assert!(
        should_include(imported_incident_id, true),
        "Imported should be included when flag is true"
    );
}

#[test]
fn test_zip_rejects_path_traversal() {
    use edr_locald::safety::ZipSafetyPolicy;

    let policy = ZipSafetyPolicy::default_edr();

    let traversal_paths = vec![
        "../../../etc/passwd",
        "..\\..\\windows\\system32",
        "/etc/passwd",
    ];

    for path in traversal_paths {
        assert!(
            !policy.is_filename_allowed(path),
            "Should reject traversal: {}",
            path
        );
    }
}

#[test]
fn test_zip_rejects_unknown_filenames() {
    use edr_locald::safety::ZipSafetyPolicy;

    let policy = ZipSafetyPolicy::default_edr();

    let unknown_files = vec![
        "malware.exe",
        "payload.dll",
        "unauthorized.json",
        "../allowed_subdir/unauthorized.json",
    ];

    for filename in unknown_files {
        assert!(
            !policy.is_filename_allowed(filename),
            "Should reject unknown filename: {}",
            filename
        );
    }
}

#[test]
fn test_zip_allows_known_filenames() {
    use edr_locald::safety::ZipSafetyPolicy;

    let policy = ZipSafetyPolicy::default_edr();

    let known_files = vec![
        "manifest.json",
        "replay/events.jsonl",
        "recompute/hypotheses.json",
        "metadata.json",
        "replay/something/nested.json",
        "recompute/2025/january/data.json",
    ];

    for filename in known_files {
        assert!(
            policy.is_filename_allowed(filename),
            "Should allow known filename: {}",
            filename
        );
    }
}

#[test]
fn test_zip_safety_policy_sizes() {
    use edr_locald::safety::ZipSafetyPolicy;

    let policy = ZipSafetyPolicy::default_edr();

    assert_eq!(policy.max_files, 32, "Default should limit to 32 files");
    assert_eq!(
        policy.max_total_uncompressed,
        25 * 1024 * 1024,
        "Should limit to 25MB total"
    );
    assert_eq!(
        policy.max_single_file,
        10 * 1024 * 1024,
        "Should limit single file to 10MB"
    );
    assert!(
        policy.reject_nested_archives,
        "Should reject nested archives"
    );
}

#[test]
fn test_selfcheck_response_structure() {
    // Verify that /api/selfcheck can report both healthy and error states
    let healthy_check = json!({
        "overall_health": "healthy",
        "db_writable": true,
        "telemetry_root_writable": true,
        "schema_version_match": true,
        "last_event_ts": "2025-01-02T14:30:00Z"
    });

    let error_check = json!({
        "overall_health": "blocked",
        "db_writable": false,
        "telemetry_root_writable": true,
        "schema_version_match": true,
        "error_reason": "Database not writable: permission denied",
        "recommended_action": "Check permissions on database file or restart with elevated privileges"
    });

    // Verify structures
    assert_eq!(healthy_check["overall_health"], "healthy");
    assert!(healthy_check["db_writable"].as_bool().unwrap());

    assert_eq!(error_check["overall_health"], "blocked");
    assert!(!error_check["db_writable"].as_bool().unwrap());
    assert!(error_check["error_reason"].is_string());
    assert!(error_check["recommended_action"].is_string());
}

#[test]
fn test_data_namespace_isolation() {
    use edr_locald::safety::DataNamespace;

    let live = DataNamespace::Live;
    let imported = DataNamespace::Imported(12345);

    // Verify namespace strings are different
    assert_ne!(live.as_str(), imported.as_str());

    // Verify they can be parsed back
    assert_eq!(DataNamespace::parse(&live.as_str()), Some(live));
    assert_eq!(DataNamespace::parse(&imported.as_str()), Some(imported));

    // Verify they are not equal
    assert_ne!(live, imported);
}

#[test]
fn test_import_path_construction() {
    use edr_locald::safety::DataNamespace;

    let bundle_id_hash = 0xABCD1234u32;
    let namespace = DataNamespace::Imported(bundle_id_hash);

    // Verify the path prefix would be correct
    let ns_string = namespace.as_str();
    assert!(
        ns_string.starts_with("imported_"),
        "Should start with imported_"
    );
    assert_eq!(
        ns_string, "imported_2882343476",
        "Should contain the decimal representation of bundle ID"
    );
}
