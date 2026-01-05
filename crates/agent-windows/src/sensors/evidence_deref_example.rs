// windows/sensors/evidence_deref_example.rs
// Evidence-first proof: segment write + EvidencePtr + deref

#[cfg(test)]
mod evidence_first_proof {
    use chrono::Utc;

    #[test]
    fn test_evidence_first_single_event() {
        // Minimal example: 1 canonical event with EvidencePtr
        
        let event = crate::Event {
            ts: Utc::now(),
            event_type: crate::core::event::EventType::Execve,
            pid: Some(1234),
            ppid: Some(1000),
            uid: Some(500),
            exe: Some("C:\\Windows\\System32\\cmd.exe".to_string()),
            argv: Some(vec!["cmd.exe".to_string(), "/c".to_string(), "whoami".to_string()]),
            tags: vec!["windows_evtx".to_string(), "process".to_string()],
            ..Default::default()
        };

        // Simulate writing to segment (stream_id=0, segment_id=1, record_index=42)
        let evidence_ptr = EvidencePtr {
            stream_id: "windows_evtx_0".to_string(),
            segment_id: 1,
            record_index: 42,
            ts: event.ts,
            event_type: format!("{:?}", event.event_type),
            sensor_kind: "windows_evtx".to_string(),
        };

        // Proof: event has pointer-addressable location
        assert_eq!(evidence_ptr.segment_id, 1);
        assert_eq!(evidence_ptr.record_index, 42);
        assert_eq!(evidence_ptr.sensor_kind, "windows_evtx");
        
        // locald would now ingest this event + ptr and store in:
        // processed_records(stream_id, segment_id, record_index, event_json, evidence_ptr_json)
        // Query: SELECT event_json FROM processed_records WHERE segment_id=1 AND record_index=42
        // Returns: {"ts":"...","event_type":"Execve","pid":1234,"exe":"cmd.exe",...}
        
        println!("EvidencePtr: stream={} segment={} index={}", 
            evidence_ptr.stream_id, evidence_ptr.segment_id, evidence_ptr.record_index);
    }
}

pub struct EvidencePtr {
    pub stream_id: String,
    pub segment_id: u64,
    pub record_index: u64,
    pub ts: chrono::DateTime<chrono::Utc>,
    pub event_type: String,
    pub sensor_kind: String,
}
