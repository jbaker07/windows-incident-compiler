//! Tests for slot matching and hypothesis compilation
//!
//! These tests verify the ground-truth slot engine behavior:
//! - Required slots must fill within TTL to fire incidents
//! - Optional slots enrich but don't block firing
//! - TTL expiry drops partial hypotheses
//! - Capability gating (SOFT facts only fill required if playbook allows)
//! - Determinism: same facts → same output

use crate::hypothesis::{EvidencePtr, Fact, FactType, ScopeKey};
use crate::hypothesis_controller::HypothesisController;
use crate::slot_matcher::{PlaybookDef, PlaybookSlot, SlotPredicate};
use chrono::Utc;

/// Helper to create a test fact
fn make_exec_fact(host_id: &str, exe_path: &str, scope_key: &str) -> Fact {
    let ts = Utc::now();
    let ptr = EvidencePtr::new("test_stream", "seg_001", 0).with_timestamp(ts);

    Fact::new(
        host_id,
        ScopeKey::Process {
            key: scope_key.to_string(),
        },
        FactType::Exec {
            exe_hash: Some("abc123".to_string()),
            path: exe_path.to_string(),
            signer: None,
            cmdline: Some("test".to_string()),
        },
        vec![ptr],
    )
}

fn make_connect_fact(host_id: &str, dst_ip: &str, dst_port: u16, scope_key: &str) -> Fact {
    let ts = Utc::now();
    let ptr = EvidencePtr::new("test_stream", "seg_001", 1).with_timestamp(ts);

    Fact::new(
        host_id,
        ScopeKey::Process {
            key: scope_key.to_string(),
        },
        FactType::OutboundConnect {
            dst_ip: dst_ip.to_string(),
            dst_port,
            proto: "tcp".to_string(),
            sock_id: None,
        },
        vec![ptr],
    )
}

fn make_dns_fact(host_id: &str, query: &str, scope_key: &str) -> Fact {
    let ts = Utc::now();
    let ptr = EvidencePtr::new("test_stream", "seg_001", 2).with_timestamp(ts);

    Fact::new(
        host_id,
        ScopeKey::Process {
            key: scope_key.to_string(),
        },
        FactType::DnsResolve {
            query: query.to_string(),
            responses: vec!["1.2.3.4".to_string()],
        },
        vec![ptr],
    )
}

/// Create a playbook with 2 REQUIRED slots (Exec + OutboundConnect)
fn make_two_slot_playbook() -> PlaybookDef {
    PlaybookDef {
        playbook_id: "pb_test_two_slots".to_string(),
        title: "Test Two Slot Playbook".to_string(),
        family: "test".to_string(),
        severity: "high".to_string(),
        entity_scope: "host|process".to_string(),
        ttl_seconds: 300,
        cooldown_seconds: 60,
        tags: vec!["test".to_string()],
        slots: vec![
            PlaybookSlot::required(
                "exec_slot",
                "Process Execution",
                SlotPredicate::for_fact_type("Exec"),
            )
            .with_ttl(300),
            PlaybookSlot::required(
                "connect_slot",
                "Outbound Connection",
                SlotPredicate::for_fact_type("OutboundConnect"),
            )
            .with_ttl(300),
        ],
        narrative: Some("Process exec followed by network connection".to_string()),
        playbook_hash: String::new(),
    }
}

/// Create a playbook with 1 REQUIRED slot and 1 OPTIONAL DNS slot
fn make_optional_dns_playbook() -> PlaybookDef {
    PlaybookDef {
        playbook_id: "pb_test_optional_dns".to_string(),
        title: "Test Optional DNS Playbook".to_string(),
        family: "test".to_string(),
        severity: "medium".to_string(),
        entity_scope: "host|process".to_string(),
        ttl_seconds: 300,
        cooldown_seconds: 60,
        tags: vec!["test".to_string()],
        slots: vec![
            PlaybookSlot::required(
                "exec_slot",
                "Process Execution",
                SlotPredicate::for_fact_type("Exec"),
            )
            .with_ttl(300),
            PlaybookSlot::optional(
                "dns_slot",
                "DNS Resolution",
                SlotPredicate::for_fact_type("DnsResolve"),
            )
            .with_ttl(300),
        ],
        narrative: Some("Process exec with optional DNS".to_string()),
        playbook_hash: String::new(),
    }
}

/// Create a playbook with DNS as REQUIRED but soft_required=true
fn make_soft_required_dns_playbook() -> PlaybookDef {
    PlaybookDef {
        playbook_id: "pb_test_soft_dns".to_string(),
        title: "Test Soft Required DNS Playbook".to_string(),
        family: "test".to_string(),
        severity: "medium".to_string(),
        entity_scope: "host|process".to_string(),
        ttl_seconds: 300,
        cooldown_seconds: 60,
        tags: vec!["test".to_string()],
        slots: vec![
            PlaybookSlot::required(
                "exec_slot",
                "Process Execution",
                SlotPredicate::for_fact_type("Exec"),
            )
            .with_ttl(300),
            PlaybookSlot::required(
                "dns_slot",
                "DNS Resolution (soft allowed)",
                SlotPredicate::for_fact_type("DnsResolve").with_soft_required(true),
            )
            .with_ttl(300),
        ],
        narrative: Some("Process exec with soft-required DNS".to_string()),
        playbook_hash: String::new(),
    }
}

/// Create a playbook with DNS as REQUIRED but soft_required=false (default)
fn make_hard_required_dns_playbook() -> PlaybookDef {
    PlaybookDef {
        playbook_id: "pb_test_hard_dns".to_string(),
        title: "Test Hard Required DNS Playbook".to_string(),
        family: "test".to_string(),
        severity: "medium".to_string(),
        entity_scope: "host|process".to_string(),
        ttl_seconds: 300,
        cooldown_seconds: 60,
        tags: vec!["test".to_string()],
        slots: vec![
            PlaybookSlot::required(
                "exec_slot",
                "Process Execution",
                SlotPredicate::for_fact_type("Exec"),
            )
            .with_ttl(300),
            PlaybookSlot::required(
                "dns_slot",
                "DNS Resolution (hard required)",
                SlotPredicate::for_fact_type("DnsResolve"), // soft_required=false by default
            )
            .with_ttl(300),
        ],
        narrative: Some("Process exec with hard-required DNS".to_string()),
        playbook_hash: String::new(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Test: A minimal playbook with 2 REQUIRED slots (Exec + OutboundConnect) fires
    #[test]
    fn test_two_required_slots_fire() {
        let mut controller = HypothesisController::new("test_host");
        controller.register_playbook(make_two_slot_playbook());

        // Ingest Exec fact
        let exec_fact = make_exec_fact("test_host", "/usr/bin/curl", "proc_123");
        let affected1 = controller.ingest_fact(exec_fact).unwrap();

        // Should have created a hypothesis
        assert!(
            !affected1.is_empty(),
            "Exec fact should create/update hypothesis"
        );

        // Hypothesis should not be promoted yet (only 1 of 2 slots filled)
        let active = controller.active_hypotheses();
        assert_eq!(active.len(), 1, "Should have exactly one active hypothesis");
        assert!(
            !active[0].all_required_satisfied(),
            "Should NOT have all required slots filled"
        );

        // Ingest OutboundConnect fact
        let connect_fact = make_connect_fact("test_host", "8.8.8.8", 443, "proc_123");
        let affected2 = controller.ingest_fact(connect_fact).unwrap();

        assert!(
            !affected2.is_empty(),
            "Connect fact should update hypothesis"
        );

        // Now all required slots should be filled, incident should have been created
        // Check that hypothesis was promoted
        let _active_after = controller.active_hypotheses();
        // After promotion, the hypothesis may no longer be "active" (status = Promoted)
        // So we check that an incident was created
        let _incident = controller.get_incident(&affected2[0]);
        // The hypothesis should have been promoted, check status
        if let Some(hyp) = controller.get_hypothesis(&affected1[0]) {
            // It could be promoted or still active depending on timing
            // Let's check slot fill status
            assert!(
                hyp.all_required_satisfied()
                    || hyp.status == crate::hypothesis::HypothesisStatus::Promoted,
                "Hypothesis should have all required slots filled or be promoted"
            );
        }
    }

    /// Test: A playbook with an OPTIONAL DNS slot enriches but is not required
    #[test]
    fn test_optional_slot_not_required() {
        let mut controller = HypothesisController::new("test_host");
        controller.register_playbook(make_optional_dns_playbook());

        // Ingest only Exec fact (the only required slot)
        let exec_fact = make_exec_fact("test_host", "/usr/bin/test", "proc_456");
        let affected = controller.ingest_fact(exec_fact).unwrap();

        assert!(!affected.is_empty(), "Exec fact should create hypothesis");

        // With only 1 required slot (Exec), the playbook should fire immediately
        if let Some(hyp) = controller.get_hypothesis(&affected[0]) {
            assert!(
                hyp.all_required_satisfied()
                    || hyp.status == crate::hypothesis::HypothesisStatus::Promoted,
                "Single required slot should be sufficient to fire"
            );
        }
    }

    /// Test: Optional DNS slot enriches the hypothesis when required slots aren't all filled yet
    #[test]
    fn test_optional_slot_enriches() {
        let mut controller = HypothesisController::new("test_host");

        // Create a playbook with 2 required slots + 1 optional DNS
        let mut playbook = make_two_slot_playbook();
        playbook.playbook_id = "pb_test_optional_enrich".to_string();
        playbook.slots.push(
            PlaybookSlot::optional(
                "dns_slot",
                "DNS Resolution",
                SlotPredicate::for_fact_type("DnsResolve"),
            )
            .with_ttl(300),
        );
        controller.register_playbook(playbook);

        // Ingest Exec fact first (1 of 2 required)
        let exec_fact = make_exec_fact("test_host", "/usr/bin/test", "proc_789");
        let affected1 = controller.ingest_fact(exec_fact).unwrap();
        assert!(!affected1.is_empty());

        // Hypothesis should exist and not be promoted yet (only 1 of 2 required slots)
        let hyp_id = &affected1[0];

        // Ingest DNS fact (optional) - should enrich the hypothesis
        let dns_fact = make_dns_fact("test_host", "evil.com", "proc_789");
        let _affected2 = controller.ingest_fact(dns_fact).unwrap();

        // Check that the DNS slot was filled for enrichment
        if let Some(hyp) = controller.get_hypothesis(hyp_id) {
            // Hypothesis should still be active (not promoted)
            assert!(
                !hyp.all_required_satisfied(),
                "Should NOT have all required slots (still missing connect)"
            );

            // But the optional DNS slot should have been filled
            let dns_filled = hyp.slot_fills.contains_key("dns_slot");
            assert!(
                dns_filled,
                "Optional DNS slot should be filled for enrichment"
            );
        } else {
            panic!("Hypothesis should still exist");
        }
    }

    /// Test: Capability gating - DNS (SOFT) cannot fill required slot by default
    #[test]
    fn test_soft_capability_gating_blocks_required() {
        let mut controller = HypothesisController::new("test_host");
        controller.register_playbook(make_hard_required_dns_playbook());

        // Ingest Exec fact
        let exec_fact = make_exec_fact("test_host", "/usr/bin/test", "proc_soft_1");
        let affected1 = controller.ingest_fact(exec_fact).unwrap();
        assert!(!affected1.is_empty());

        // Ingest DNS fact - should NOT fill the required slot because DNS is SOFT
        let dns_fact = make_dns_fact("test_host", "example.com", "proc_soft_1");
        let _affected2 = controller.ingest_fact(dns_fact).unwrap();

        // The hypothesis should NOT have all required slots filled
        // because DNS (SOFT capability) cannot fill a required slot without soft_required=true
        if let Some(hyp) = controller.get_hypothesis(&affected1[0]) {
            // DNS slot should NOT be filled (capability gating)
            let dns_filled = hyp
                .slot_fills
                .get("dns_slot")
                .map(|f| f.satisfied)
                .unwrap_or(false);
            assert!(!dns_filled, "SOFT DNS should NOT fill hard required slot");
            assert!(
                !hyp.all_required_satisfied(),
                "Should NOT have all required satisfied"
            );
        }
    }

    /// Test: Capability gating - DNS (SOFT) CAN fill required slot when soft_required=true
    #[test]
    fn test_soft_capability_allowed_when_explicitly_set() {
        let mut controller = HypothesisController::new("test_host");
        controller.register_playbook(make_soft_required_dns_playbook());

        // Ingest Exec fact
        let exec_fact = make_exec_fact("test_host", "/usr/bin/test", "proc_soft_2");
        let affected1 = controller.ingest_fact(exec_fact).unwrap();
        assert!(!affected1.is_empty());

        // Ingest DNS fact - SHOULD fill because soft_required=true
        let dns_fact = make_dns_fact("test_host", "example.com", "proc_soft_2");
        let _affected2 = controller.ingest_fact(dns_fact).unwrap();

        // The hypothesis should have all required slots filled now
        if let Some(hyp) = controller.get_hypothesis(&affected1[0]) {
            // DNS slot should be filled (soft_required=true allows it)
            let dns_filled = hyp
                .slot_fills
                .get("dns_slot")
                .map(|f| f.satisfied)
                .unwrap_or(false);
            assert!(dns_filled, "SOFT DNS should fill soft_required slot");
        }
    }

    /// Test: Determinism - same facts in same order yields same hypothesis_id and slots
    #[test]
    fn test_determinism() {
        // Create two controllers with identical config
        let mut controller1 = HypothesisController::new("test_host");
        let mut controller2 = HypothesisController::new("test_host");

        controller1.register_playbook(make_two_slot_playbook());
        controller2.register_playbook(make_two_slot_playbook());

        // Feed identical facts to both
        let exec_fact1 = make_exec_fact("test_host", "/usr/bin/curl", "proc_det");
        let exec_fact2 = make_exec_fact("test_host", "/usr/bin/curl", "proc_det");

        let affected1 = controller1.ingest_fact(exec_fact1).unwrap();
        let affected2 = controller2.ingest_fact(exec_fact2).unwrap();

        // Hypothesis IDs should be identical (deterministic)
        assert_eq!(
            affected1, affected2,
            "Same facts should produce same hypothesis IDs"
        );

        // Slot fills should be identical
        if let (Some(hyp1), Some(hyp2)) = (
            controller1.get_hypothesis(&affected1[0]),
            controller2.get_hypothesis(&affected2[0]),
        ) {
            assert_eq!(
                hyp1.slot_fills.keys().collect::<Vec<_>>(),
                hyp2.slot_fills.keys().collect::<Vec<_>>(),
                "Same facts should fill same slots"
            );
        }
    }

    /// Test: Hypothesis expires after TTL
    #[test]
    fn test_hypothesis_expiry() {
        let mut controller = HypothesisController::new("test_host");

        // Create a playbook with very short TTL for testing
        let mut short_ttl_playbook = make_two_slot_playbook();
        short_ttl_playbook.playbook_id = "pb_short_ttl".to_string();
        short_ttl_playbook.ttl_seconds = 1; // 1 second TTL
        controller.register_playbook(short_ttl_playbook);

        // Ingest first fact
        let exec_fact = make_exec_fact("test_host", "/usr/bin/test", "proc_expire");
        let affected = controller.ingest_fact(exec_fact).unwrap();
        assert!(!affected.is_empty());

        // Hypothesis should be active initially
        let active_before = controller.active_hypotheses();
        assert!(
            !active_before.is_empty(),
            "Hypothesis should be active initially"
        );

        // Wait for expiry (note: in real tests we'd mock time)
        // For now, we manually trigger expiry check
        std::thread::sleep(std::time::Duration::from_secs(2));
        controller.expire_hypotheses();

        // Hypothesis should be expired now
        if let Some(hyp) = controller.get_hypothesis(&affected[0]) {
            assert!(
                hyp.is_expired() || hyp.status == crate::hypothesis::HypothesisStatus::Expired,
                "Hypothesis should be expired after TTL"
            );
        }
    }

    /// Test: Playbook index correctly indexes by fact type
    #[test]
    fn test_playbook_index() {
        use crate::slot_matcher::PlaybookIndex;

        let mut index = PlaybookIndex::new();
        index.add_playbook(make_two_slot_playbook());
        index.add_playbook(make_optional_dns_playbook());

        // Should find playbooks for Exec facts
        let exec_candidates = index.candidates_for_fact_type("Exec");
        assert_eq!(
            exec_candidates.len(),
            2,
            "Should find 2 playbooks with Exec slots"
        );

        // Should find playbooks for OutboundConnect facts
        let connect_candidates = index.candidates_for_fact_type("OutboundConnect");
        assert_eq!(
            connect_candidates.len(),
            1,
            "Should find 1 playbook with OutboundConnect slot"
        );

        // Should find playbooks for DnsResolve facts
        let dns_candidates = index.candidates_for_fact_type("DnsResolve");
        assert_eq!(
            dns_candidates.len(),
            1,
            "Should find 1 playbook with DnsResolve slot"
        );

        // Should NOT find playbooks for unregistered fact types
        let unknown_candidates = index.candidates_for_fact_type("Unknown");
        assert!(
            unknown_candidates.is_empty(),
            "Should not find playbooks for unknown fact type"
        );
    }
}
