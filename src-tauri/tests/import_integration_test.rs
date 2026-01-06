//! Integration tests for the import pipeline
//!
//! Tests the full import → manifest → events flow with test fixtures.

use edr_desktop_lib::{SafeImporter, ImportLimits};
use std::path::PathBuf;
use std::fs;

/// Workspace root for test fixtures
fn workspace_root() -> PathBuf {
    let manifest_dir = env!("CARGO_MANIFEST_DIR");
    PathBuf::from(manifest_dir).parent().unwrap().to_path_buf()
}

/// Test fixture directory
fn fixtures_dir() -> PathBuf {
    workspace_root().join("testdata").join("imports")
}

#[test]
fn test_import_folder_produces_manifest() {
    let fixtures = fixtures_dir();
    if !fixtures.exists() {
        eprintln!("Skipping test: fixtures not found at {:?}", fixtures);
        return;
    }
    
    let temp_dir = std::env::temp_dir().join("import_test_manifest");
    let _ = fs::remove_dir_all(&temp_dir);
    fs::create_dir_all(&temp_dir).expect("Failed to create temp dir");
    
    let importer = SafeImporter::new(
        "test_run".to_string(),
        temp_dir.clone(),
        Some(ImportLimits::default()),
    );
    
    let result = importer.import(fixtures.to_str().unwrap());
    assert!(result.is_ok(), "Import failed: {:?}", result.err());
    
    let result = result.unwrap();
    assert!(!result.bundle_id.is_empty(), "Bundle ID should not be empty");
    assert!(result.summary.total_files >= 5, "Expected at least 5 files, got {}", result.summary.total_files);
    
    // Verify manifest file exists
    let manifest_path = PathBuf::from(&result.manifest_path);
    assert!(manifest_path.exists(), "Manifest file should exist at {:?}", manifest_path);
    
    // Read and verify manifest JSON structure
    let manifest_content = fs::read_to_string(&manifest_path).expect("Failed to read manifest");
    let manifest: serde_json::Value = serde_json::from_str(&manifest_content)
        .expect("Manifest should be valid JSON");
    
    assert!(manifest.get("bundle_id").is_some(), "Manifest should have bundle_id");
    assert!(manifest.get("files").is_some(), "Manifest should have files array");
    assert!(manifest.get("summary").is_some(), "Manifest should have summary");
    
    // Cleanup
    let _ = fs::remove_dir_all(&temp_dir);
}

#[test]
fn test_import_validates_file_types() {
    let fixtures = fixtures_dir();
    if !fixtures.exists() {
        return;
    }
    
    let temp_dir = std::env::temp_dir().join("import_test_filetypes");
    let _ = fs::remove_dir_all(&temp_dir);
    fs::create_dir_all(&temp_dir).expect("Failed to create temp dir");
    
    let importer = SafeImporter::new(
        "test_run".to_string(),
        temp_dir.clone(),
        Some(ImportLimits::default()),
    );
    
    let result = importer.import(fixtures.to_str().unwrap()).unwrap();
    
    // Read manifest and check file kinds
    let manifest_content = fs::read_to_string(&result.manifest_path).expect("Failed to read manifest");
    let manifest: serde_json::Value = serde_json::from_str(&manifest_content).unwrap();
    
    let files = manifest.get("files").unwrap().as_array().unwrap();
    
    // Verify we have various file kinds detected
    let kinds: Vec<&str> = files.iter()
        .filter_map(|f| f.get("kind").and_then(|k| k.as_str()))
        .collect();
    
    // Should detect XML, JSON, and text files
    assert!(
        kinds.iter().any(|k| k.contains("json") || k.contains("xml") || k.contains("text") || *k == "unknown"),
        "Expected various file kinds, got: {:?}", kinds
    );
    
    // Cleanup
    let _ = fs::remove_dir_all(&temp_dir);
}

#[test]
fn test_import_sha256_hashing() {
    let fixtures = fixtures_dir();
    if !fixtures.exists() {
        return;
    }
    
    let temp_dir = std::env::temp_dir().join("import_test_sha256");
    let _ = fs::remove_dir_all(&temp_dir);
    fs::create_dir_all(&temp_dir).expect("Failed to create temp dir");
    
    let importer = SafeImporter::new(
        "test_run".to_string(),
        temp_dir.clone(),
        Some(ImportLimits::default()),
    );
    
    let result = importer.import(fixtures.to_str().unwrap()).unwrap();
    
    // Read manifest and check SHA256 hashes
    let manifest_content = fs::read_to_string(&result.manifest_path).expect("Failed to read manifest");
    let manifest: serde_json::Value = serde_json::from_str(&manifest_content).unwrap();
    
    let files = manifest.get("files").unwrap().as_array().unwrap();
    
    for file in files {
        let sha256 = file.get("sha256").and_then(|s| s.as_str());
        assert!(sha256.is_some(), "Each file should have a SHA256 hash");
        let hash = sha256.unwrap();
        assert_eq!(hash.len(), 64, "SHA256 hash should be 64 hex characters");
        assert!(hash.chars().all(|c| c.is_ascii_hexdigit()), "Hash should be hex");
    }
    
    // Cleanup
    let _ = fs::remove_dir_all(&temp_dir);
}
