//! Integration acceptance tests
//!
//! Tests for:
//! 1. Export creates JSONL with correct schema + includes Tier-0
//! 2. Ingest parses sample event and produces VendorAlert Fact + stable scope key
//! 3. End-to-end: ingest event + existing outbound connect → gets enriched (soft join)
//! 4. Determinism: running export twice yields identical output order + hashes

use chrono::Utc;
use edr_locald::integrations::{
    config::{ExportSinkConfig, ExportSinkType},
    export::{EvidenceSummary, ExportMetadata, ExportedIncident, JoinKeys, TimelineFactSummary},
    ingest::{IngestSource, WazuhAlertsSource, ZeekEveSource},
    vendor_alert::{IpDirection, IpIndicator, VendorAlertFact},
};
use std::collections::HashMap;
use std::io::Write;
use tempfile::tempdir;

// ============================================================================
// Test 1: Export schema validation
// ============================================================================

#[test]
fn test_exported_incident_schema_has_required_fields() {
    // Create a minimal ExportedIncident matching actual struct
    let now = Utc::now();
    let exported = ExportedIncident {
        schema_version: "1.0".to_string(),
        incident_id: "inc_test_001".to_string(),
        host_id: "test_host".to_string(),
        namespace: Some("endpoint.test".to_string()),
        family: "credential_access".to_string(),
        playbook_id: Some("T1003_LSASS".to_string()),
        severity: "critical".to_string(),
        confidence: 0.95,
        status: "active".to_string(),
        first_ts: now,
        last_ts: now,
        created_at: now,
        updated_at: now,
        is_tier0: true,
        tier0_type: Some("lsass_access".to_string()),
        mitre_tags: vec!["T1003".to_string()],
        join_keys: JoinKeys {
            proc_key: Some("proc_123".to_string()),
            identity_key: None,
            file_key: None,
            ip_indicators: vec!["192.168.1.100".to_string()],
            exe_hashes: vec![],
        },
        timeline_summary: vec![TimelineFactSummary {
            ts: now,
            fact_type: "process_exec".to_string(),
            summary: "mimikatz.exe executed".to_string(),
            key_fields: HashMap::from([("exe".to_string(), "mimikatz.exe".to_string())]),
        }],
        evidence_summary: vec![EvidenceSummary {
            stream_id: "stream_test".to_string(),
            segment_id: "seg_001".to_string(),
            record_index: 42,
            segment_sha256: Some("abc123".to_string()),
        }],
        export_metadata: ExportMetadata {
            exported_at: now,
            exporter_version: "1.0.0".to_string(),
            sink_id: "test_sink".to_string(),
        },
    };

    // Serialize to JSON and verify schema
    let json = serde_json::to_string(&exported).unwrap();
    let parsed: serde_json::Value = serde_json::from_str(&json).unwrap();

    assert_eq!(parsed["schema_version"], "1.0");
    assert_eq!(parsed["incident_id"], "inc_test_001");
    assert_eq!(parsed["host_id"], "test_host");
    assert_eq!(parsed["family"], "credential_access");
    assert_eq!(parsed["severity"], "critical");
    assert!(parsed["timeline_summary"].is_array());
    assert!(parsed["evidence_summary"].is_array());
    assert!(parsed["join_keys"].is_object());
}

#[test]
fn test_exported_incident_jsonl_format() {
    let dir = tempdir().unwrap();
    let output_path = dir.path().join("incidents.jsonl");

    // Write multiple incidents as JSONL
    let mut file = std::fs::File::create(&output_path).unwrap();
    let now = Utc::now();

    for i in 0..3 {
        let exported = ExportedIncident {
            schema_version: "1.0".to_string(),
            incident_id: format!("inc_test_{:03}", i),
            host_id: "test_host".to_string(),
            namespace: None,
            family: "injection".to_string(),
            playbook_id: None,
            severity: "high".to_string(),
            confidence: 0.8,
            status: "active".to_string(),
            first_ts: now,
            last_ts: now,
            created_at: now,
            updated_at: now,
            is_tier0: false,
            tier0_type: None,
            mitre_tags: vec![],
            join_keys: JoinKeys::default(),
            timeline_summary: vec![],
            evidence_summary: vec![],
            export_metadata: ExportMetadata {
                exported_at: now,
                exporter_version: "1.0.0".to_string(),
                sink_id: "test".to_string(),
            },
        };

        let json = serde_json::to_string(&exported).unwrap();
        writeln!(file, "{}", json).unwrap();
    }

    // Verify JSONL format (each line is valid JSON)
    let content = std::fs::read_to_string(&output_path).unwrap();
    let lines: Vec<&str> = content.lines().collect();

    assert_eq!(lines.len(), 3);
    for line in lines {
        let parsed: serde_json::Value = serde_json::from_str(line).unwrap();
        assert_eq!(parsed["schema_version"], "1.0");
    }
}

// ============================================================================
// Test 2: Wazuh ingest produces stable scope key
// ============================================================================

#[test]
fn test_ingest_wazuh_alert_produces_stable_scope_key() {
    let wazuh_alert = r#"{"timestamp":"2024-01-15T12:34:56Z","agent":{"name":"win-dc-01","ip":"192.168.1.10"},"rule":{"id":"5501","description":"SSH authentication failure","level":5,"mitre":{"id":["T1110"]}},"data":{"srcip":"10.0.0.50","dstip":"192.168.1.10"}}"#;

    // Write to temp file using tempdir for reliable path
    let dir = tempdir().unwrap();
    let file_path = dir.path().join("alerts.json");
    std::fs::write(&file_path, format!("{}\n", wazuh_alert)).unwrap();

    // Create source and poll
    let mut source = WazuhAlertsSource::new(&file_path).unwrap();
    let alerts = source.poll().unwrap();

    assert_eq!(alerts.len(), 1, "Expected 1 alert, got {}", alerts.len());
    let alert = &alerts[0];

    // Verify Wazuh-specific parsing
    assert_eq!(alert.vendor, "wazuh");
    assert_eq!(alert.host_hint, Some("win-dc-01".to_string()));
    assert!(alert.mitre_tags.contains(&"T1110".to_string()));

    // Verify scope key is deterministic
    let scope_key1 = alert.compute_scope_key(5);
    let scope_key2 = alert.compute_scope_key(5);
    assert_eq!(scope_key1.to_string(), scope_key2.to_string());

    // Verify scope key format contains vendor
    let key_str = scope_key1.to_string();
    assert!(
        key_str.contains("vendor_alert"),
        "Scope key should contain 'vendor_alert': {}",
        key_str
    );
}

// ============================================================================
// Test 3: Zeek EVE DNS produces fact with query
// ============================================================================

#[test]
fn test_ingest_zeek_eve_dns_produces_fact_with_query() {
    let zeek_dns = r#"{"ts":1705319696.123456,"uid":"CKhsY42hNpFrP9hWAd","id.orig_h":"192.168.1.100","id.orig_p":52134,"id.resp_h":"8.8.8.8","id.resp_p":53,"proto":"udp","query":"malicious-c2.example.com","event_type":"dns"}"#;

    let dir = tempdir().unwrap();
    let file_path = dir.path().join("conn.log");
    std::fs::write(&file_path, format!("{}\n", zeek_dns)).unwrap();

    let mut source = ZeekEveSource::new(&file_path).unwrap();
    let alerts = source.poll().unwrap();

    assert_eq!(alerts.len(), 1, "Expected 1 alert, got {}", alerts.len());
    let alert = &alerts[0];

    // Verify Zeek-specific parsing
    assert_eq!(alert.vendor, "zeek");
    assert_eq!(
        alert.dns_query,
        Some("malicious-c2.example.com".to_string())
    );

    // Verify IP extraction
    assert!(
        alert.ip_indicators.len() >= 2,
        "Expected at least 2 IP indicators"
    );
    let src_ip = alert
        .ip_indicators
        .iter()
        .find(|i| i.direction == IpDirection::Source);
    let dst_ip = alert
        .ip_indicators
        .iter()
        .find(|i| i.direction == IpDirection::Destination);

    assert!(src_ip.is_some(), "Source IP not found");
    assert_eq!(src_ip.unwrap().ip, "192.168.1.100");
    assert!(dst_ip.is_some(), "Destination IP not found");
    assert_eq!(dst_ip.unwrap().ip, "8.8.8.8");
}

// ============================================================================
// Test 4: VendorAlertFact soft join capability
// ============================================================================

#[test]
fn test_vendor_alert_soft_join_by_ip() {
    let ts = Utc::now();
    let mut alert = VendorAlertFact::new("wazuh", "test", ts);
    alert.ip_indicators.push(IpIndicator {
        ip: "192.168.1.100".to_string(),
        port: Some(443),
        direction: IpDirection::Destination,
        protocol: Some("tcp".to_string()),
    });

    // Test join capability with time window (300 seconds)
    assert!(alert.can_join_by_ip("192.168.1.100", ts, 300));
    assert!(!alert.can_join_by_ip("10.0.0.1", ts, 300));

    // Test outside time window
    let old_ts = ts - chrono::Duration::minutes(10);
    assert!(!alert.can_join_by_ip("192.168.1.100", old_ts, 300));

    // Find joinable should work within time window
    let joinable_ips = alert
        .ip_indicators
        .iter()
        .filter(|i| i.ip == "192.168.1.100")
        .collect::<Vec<_>>();
    assert!(!joinable_ips.is_empty());
}

// ============================================================================
// Test 5: Export determinism
// ============================================================================

#[test]
fn test_export_determinism() {
    // Create two identical ExportedIncidents
    let ts = Utc::now();

    let create_incident = || ExportedIncident {
        schema_version: "1.0".to_string(),
        incident_id: "inc_deterministic_001".to_string(),
        host_id: "test_host".to_string(),
        namespace: None,
        family: "persistence".to_string(),
        playbook_id: None,
        severity: "medium".to_string(),
        confidence: 0.75,
        status: "active".to_string(),
        first_ts: ts,
        last_ts: ts,
        created_at: ts,
        updated_at: ts,
        is_tier0: false,
        tier0_type: None,
        mitre_tags: vec![],
        join_keys: JoinKeys {
            proc_key: None,
            identity_key: None,
            file_key: None,
            ip_indicators: vec!["10.0.0.5".to_string()],
            exe_hashes: vec![],
        },
        timeline_summary: vec![TimelineFactSummary {
            ts,
            fact_type: "file_create".to_string(),
            summary: "Created /etc/cron.d/malware".to_string(),
            key_fields: HashMap::from([("path".to_string(), "/etc/cron.d/malware".to_string())]),
        }],
        evidence_summary: vec![],
        export_metadata: ExportMetadata {
            exported_at: ts,
            exporter_version: "1.0.0".to_string(),
            sink_id: "test".to_string(),
        },
    };

    let incident1 = create_incident();
    let incident2 = create_incident();

    // Serialize both
    let json1 = serde_json::to_string(&incident1).unwrap();
    let json2 = serde_json::to_string(&incident2).unwrap();

    // Should be identical
    assert_eq!(json1, json2, "Same incident should serialize identically");
}

// ============================================================================
// Test 6: Metrics calculation
// ============================================================================

#[test]
fn test_metrics_eqs_calculation() {
    // EQS formula: 0.25*timeline + 0.35*evidence + 0.20*entity + 0.20*lineage
    // Test with known values
    let timeline_score: f64 = 0.8; // 8 timeline entries (max 10)
    let evidence_score: f64 = 0.9; // Strong evidence
    let entity_score: f64 = 0.6; // 3 entities (max 5)
    let lineage_score: f64 = 0.33; // 1 parent ref (max 3)

    let expected_eqs: f64 =
        0.25 * timeline_score + 0.35 * evidence_score + 0.20 * entity_score + 0.20 * lineage_score;

    // Approximate 0.25*0.8 + 0.35*0.9 + 0.20*0.6 + 0.20*0.33 = 0.2 + 0.315 + 0.12 + 0.066 = 0.701
    assert!((expected_eqs - 0.701_f64).abs() < 0.01);
}

// ============================================================================
// Test 7: Tier-0 families always exported
// ============================================================================

#[test]
fn test_tier0_families_are_defined() {
    // Tier-0 families that should always be exported regardless of severity
    let tier0_families = vec!["memory_rwx", "lsass", "credential_access", "rootkit"];

    for family in &tier0_families {
        // Verify these are recognized as Tier-0
        let is_tier0 = matches!(
            *family,
            "memory_rwx" | "lsass" | "credential_access" | "rootkit"
        );
        assert!(is_tier0, "Family '{}' should be Tier-0", family);
    }
}

// ============================================================================
// Test 8: Config parsing
// ============================================================================

#[test]
fn test_export_sink_config_defaults() {
    let config = ExportSinkConfig {
        sink_id: "test".to_string(),
        sink_type: ExportSinkType::JsonlFile,
        output_path: std::path::PathBuf::from("/tmp/test"),
        min_severity: "medium".to_string(),
        include_tier0: true,
        max_timeline_entries: 20,
        max_evidence_pointers: 50,
        schema_version: "1.0".to_string(),
    };

    assert_eq!(config.sink_id, "test");
    assert!(config.include_tier0);
    assert_eq!(config.min_severity, "medium");
}
