//! E2E Integration Test: Playbook Fires from YAML
//!
//! This test proves that:
//! 1. PlaybookManager loads YAML playbooks from playbooks/windows/
//! 2. At least one playbook can fire when given appropriate facts
//! 3. Truthful accounting: shows total/loaded/skipped counts
//!
//! Run with: cargo test --package edr-locald e2e_yaml_playbook_fires -- --nocapture

use std::path::PathBuf;

/// Get the playbooks/windows path for tests
fn get_playbook_dir() -> PathBuf {
    let manifest_dir = std::env::var("CARGO_MANIFEST_DIR").unwrap_or_else(|_| ".".to_string());
    let project_root = PathBuf::from(manifest_dir)
        .parent() // crates/
        .and_then(|p| p.parent()) // project root
        .map(|p| p.to_path_buf())
        .unwrap_or_else(|| PathBuf::from("../.."));
    project_root.join("playbooks").join("windows")
}

#[cfg(test)]
mod e2e_tests {
    use super::*;
    use crate::hypothesis::{EvidencePtr, Fact, FactType, ScopeKey};
    use crate::hypothesis_controller::HypothesisController;
    use crate::playbook_manager::PlaybookManager;
    use chrono::Utc;

    /// Create a PowerShell execution fact that should trigger encoded_powershell playbook
    fn make_encoded_powershell_fact(host_id: &str, scope_key: &str) -> Fact {
        let ts = Utc::now();
        let ptr = EvidencePtr::new("e2e_test", "seg_001", 0).with_timestamp(ts);

        Fact::new(
            host_id,
            ScopeKey::Process {
                key: scope_key.to_string(),
            },
            FactType::Exec {
                exe_hash: Some("e2e_hash".to_string()),
                path: "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe".to_string(),
                signer: Some("Microsoft".to_string()),
                cmdline: Some("-EncodedCommand SQBuAHYAbwBrAGUALQBXAGUAYgBSAGUAcQB1AGUAcwB0AA==".to_string()),
            },
            vec![ptr],
        )
    }

    /// E2E TEST: Load YAML playbooks and verify at least one can fire
    #[test]
    fn e2e_yaml_playbook_fires() {
        let playbook_dir = get_playbook_dir();
        
        if !playbook_dir.exists() {
            eprintln!("SKIP: playbook dir not found at {:?}", playbook_dir);
            return;
        }

        // Step 1: Load playbooks with truthful accounting
        let mut mgr = PlaybookManager::new();
        let loaded = mgr.load_from_yaml_dir(&playbook_dir);
        
        // Log truthful accounting
        let result = mgr.load_result();
        eprintln!("=== TRUTHFUL PLAYBOOK ACCOUNTING ===");
        eprintln!("Total YAML files: {}", result.total_yaml_files);
        eprintln!("Loaded (runnable): {}", result.loaded_count);
        eprintln!("Skipped: {}", result.skipped_count);
        eprintln!("Skip reasons: {:?}", result.skipped_by_reason);
        if !result.skipped_examples.is_empty() {
            eprintln!("Skipped examples:");
            for s in &result.skipped_examples {
                eprintln!("  - {} ({})", s.playbook_id, s.reason);
            }
        }
        eprintln!("Categories: {:?}", result.categories);
        eprintln!("=====================================");
        
        assert!(loaded, "Should load at least one playbook");
        assert!(result.loaded_count > 0, "Loaded count should be > 0");

        // Step 2: Create HypothesisController and register playbooks
        let mut controller = HypothesisController::new("e2e_test_host");
        
        for pb in mgr.playbooks() {
            controller.register_playbook(pb.clone());
        }
        
        eprintln!("Registered {} playbooks with HypothesisController", mgr.loaded_count());

        // Step 3: Create a fact that should trigger encoded_powershell playbook
        let fact = make_encoded_powershell_fact("e2e_test_host", "proc_e2e_001");
        
        eprintln!("Ingesting Exec fact: powershell.exe -EncodedCommand ...");
        let affected = controller.ingest_fact(fact).unwrap();
        
        eprintln!("Affected hypothesis IDs: {:?}", affected);
        
        // Step 4: Verify at least one hypothesis was created/updated
        assert!(
            !affected.is_empty(),
            "FAIL: No playbook matched the encoded PowerShell fact! \
             This indicates playbooks are loaded but not matching."
        );
        
        eprintln!("SUCCESS: {} hypothesis(es) created/updated", affected.len());
        
        // Step 5: Check hypothesis details
        for hyp_id in &affected {
            if let Some(hyp) = controller.get_hypothesis(hyp_id) {
                eprintln!("Hypothesis: {}", hyp_id);
                eprintln!("  Template (playbook): {}", hyp.template_id);
                eprintln!("  Family: {}", hyp.family);
                eprintln!("  Status: {:?}", hyp.status);
                eprintln!("  Slots filled: {}", hyp.slot_fills.len());
                eprintln!("  Required satisfied: {}", hyp.all_required_satisfied());
            }
        }
        
        // Test passes if at least one hypothesis was created
        // (proving that a YAML playbook matched the fact)
    }

    /// Accounting test: Verify loaded_count matches actual runnable playbooks
    #[test]
    fn e2e_truthful_accounting_matches() {
        let playbook_dir = get_playbook_dir();
        
        if !playbook_dir.exists() {
            eprintln!("SKIP: playbook dir not found");
            return;
        }

        let mut mgr = PlaybookManager::new();
        mgr.load_from_yaml_dir(&playbook_dir);
        
        let result = mgr.load_result();
        let playbooks = mgr.playbooks();
        
        // Accounting invariant: playbooks.len() == loaded_count
        assert_eq!(
            playbooks.len() as u32,
            result.loaded_count,
            "playbooks.len() should match loaded_count"
        );
        
        // Accounting invariant: total = loaded + skipped + errors
        // (approximately, errors may overlap with skipped)
        eprintln!("Accounting check:");
        eprintln!("  total_yaml_files: {}", result.total_yaml_files);
        eprintln!("  loaded_count: {}", result.loaded_count);
        eprintln!("  skipped_count: {}", result.skipped_count);
        eprintln!("  errors: {}", result.errors.len());
        
        // skipped_count should be total - loaded
        assert_eq!(
            result.skipped_count,
            result.total_yaml_files - result.loaded_count,
            "skipped_count should be total - loaded"
        );
        
        // Every loaded playbook should have at least one slot
        for pb in playbooks {
            assert!(
                !pb.slots.is_empty(),
                "Loaded playbook {} has no slots - should have been skipped!",
                pb.playbook_id
            );
        }
        
        eprintln!("Accounting invariants verified!");
    }
}
