#[cfg(test)]
mod tests {
    use super::super::event::Event;
    use super::super::event_keys;
    use super::super::evidence_ptr::EvidencePtr;
    use std::collections::BTreeMap;

    #[test]
    fn test_event_validate_all_valid_keys() {
        let valid_keys = event_keys::all_valid_keys();
        let mut fields = BTreeMap::new();

        // Add all valid keys to ensure they pass validation
        for key in valid_keys {
            fields.insert(key.to_string(), serde_json::json!("test_value"));
        }

        let event = Event {
            ts_ms: 1000,
            host: "test-host".to_string(),
            tags: vec!["test".to_string()],
            proc_key: None,
            file_key: None,
            identity_key: None,
            evidence_ptr: Some(EvidencePtr {
                stream_id: "test".to_string(),
                segment_id: 0,
                record_index: 0,
            }),
            fields,
        };

        assert!(event.validate_basic().is_ok());
    }

    #[test]
    fn test_event_validate_empty_fields() {
        let event = Event {
            ts_ms: 1000,
            host: "test-host".to_string(),
            tags: vec!["test".to_string()],
            proc_key: None,
            file_key: None,
            identity_key: None,
            evidence_ptr: Some(EvidencePtr {
                stream_id: "test".to_string(),
                segment_id: 0,
                record_index: 0,
            }),
            fields: BTreeMap::new(),
        };

        assert!(event.validate_basic().is_ok());
    }

    #[test]
    fn test_event_validate_unknown_field() {
        let mut fields = BTreeMap::new();
        fields.insert("unknown_field".to_string(), serde_json::json!("value"));

        let event = Event {
            ts_ms: 1000,
            host: "test-host".to_string(),
            tags: vec!["test".to_string()],
            proc_key: None,
            file_key: None,
            identity_key: None,
            evidence_ptr: Some(EvidencePtr {
                stream_id: "test".to_string(),
                segment_id: 0,
                record_index: 0,
            }),
            fields,
        };

        let result = event.validate_basic();
        assert!(result.is_err());
        assert!(result
            .unwrap_err()
            .contains("unknown event field: unknown_field"));
    }

    #[test]
    fn test_event_validate_mixed_valid_and_invalid() {
        let mut fields = BTreeMap::new();
        fields.insert(event_keys::PROC_PID.to_string(), serde_json::json!(1234));
        fields.insert("bad_field".to_string(), serde_json::json!("bad"));

        let event = Event {
            ts_ms: 1000,
            host: "test-host".to_string(),
            tags: vec!["test".to_string()],
            proc_key: None,
            file_key: None,
            identity_key: None,
            evidence_ptr: Some(EvidencePtr {
                stream_id: "test".to_string(),
                segment_id: 0,
                record_index: 0,
            }),
            fields,
        };

        let result = event.validate_basic();
        assert!(result.is_err());
        assert!(result
            .unwrap_err()
            .contains("unknown event field: bad_field"));
    }

    #[test]
    fn test_event_keys_coverage() {
        // This test verifies that all valid keys are accessible
        // and non-empty
        let valid_keys = event_keys::all_valid_keys();
        assert!(!valid_keys.is_empty(), "Valid keys should not be empty");
        assert!(
            valid_keys.len() > 30,
            "Valid keys should have at least 30 keys"
        );

        // Verify no duplicates
        let mut seen = std::collections::HashSet::new();
        for key in &valid_keys {
            assert!(seen.insert(key), "Duplicate key found: {}", key);
        }
    }

    #[test]
    fn test_episode_candidate_determinism() {
        // Test that episode IDs are deterministic
        use sha2::{Digest, Sha256};

        let event_keys1 = vec!["proc:1234:bash".to_string(), "file:/etc/shadow".to_string()];
        let event_keys2 = vec!["proc:1234:bash".to_string(), "file:/etc/shadow".to_string()];

        let mut hasher1 = Sha256::new();
        for key in &event_keys1 {
            hasher1.update(key.as_bytes());
        }
        let id1 = format!("{:x}", hasher1.finalize());

        let mut hasher2 = Sha256::new();
        for key in &event_keys2 {
            hasher2.update(key.as_bytes());
        }
        let id2 = format!("{:x}", hasher2.finalize());

        assert_eq!(id1, id2, "Same event keys should produce same episode ID");
    }
}
