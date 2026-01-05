// locald/evidence_deref_example.rs
// Minimal evidence-first example: process exec → canonical Event with EvidencePtr → ingestion → deref

use chrono::Utc;
use serde_json::json;

/// Example: Windows process creation event (EVTX 4688) → canonical Event → ingest → deref

pub fn evidence_deref_example() -> String {
    // 1. Raw EVTX record (from Windows Event Log)
    let evtx_raw = json!({
        "log_name": "Security",
        "event_id": 4688,
        "ts": "2025-12-21T10:30:45Z",
        "computer": "WORKSTATION-01",
        "fields": {
            "NewProcessName": "C:\\Windows\\System32\\powershell.exe",
            "CommandLine": "powershell.exe -NoProfile -Command Get-Process",
            "NewProcessId": "4128",
            "ParentProcessId": "5432",
            "SubjectUserSid": "S-1-5-21-..."
        }
    });

    // 2. Normalized canonical Event (evtx_collector.rs → canonical core::Event)
    let canonical_event = json!({
        "ts": "2025-12-21T10:30:45Z",
        "event_type": "Execve",
        "pid": 4128,
        "ppid": 5432,
        "exe": "C:\\Windows\\System32\\powershell.exe",
        "argv": ["powershell.exe -NoProfile -Command Get-Process"],
        "evidence_ptr": {
            "stream_id": "windows_001",
            "segment_id": "segment_0001",
            "record_index": 42,
            "ts": "2025-12-21T10:30:45Z",
            "event_type": "Execve",
            "sensor_kind": "windows_evtx"
        },
        "tags": ["windows_evtx", "process", "execution"]
    });

    // 3. JSONL segment write (capture_windows_rotating.rs)
    let segment_entry = format!(
        "{}\n",
        serde_json::to_string(&canonical_event).unwrap()
    );

    // 4. Index entry for segment (hash + ptr metadata)
    let index_entry = json!({
        "segment_id": "segment_0001",
        "start_ts": "2025-12-21T10:30:00Z",
        "end_ts": "2025-12-21T10:31:00Z",
        "record_count": 1,
        "sha256": "abc1234567890def...",
        "records": [{
            "index": 42,
            "ts": "2025-12-21T10:30:45Z",
            "event_type": "Execve"
        }]
    });

    // 5. Evidence deref in locald: given EvidencePtr, fetch record
    let evidence_ptr = json!({
        "stream_id": "windows_001",
        "segment_id": "segment_0001",
        "record_index": 42
    });

    // 6. Deref result: canonical Event fully reconstructed
    let dereferenced = json!({
        "source": "segment_0001 @ record_index 42",
        "event": canonical_event,
        "verified": true
    });

    format!(
        "RAW EVTX:\n{}\n\nCANONICAL EVENT:\n{}\n\nEVIDENCE PTR:\n{}\n\nDEREFED:\n{}",
        serde_json::to_string_pretty(&evtx_raw).unwrap(),
        serde_json::to_string_pretty(&canonical_event).unwrap(),
        serde_json::to_string_pretty(&evidence_ptr).unwrap(),
        serde_json::to_string_pretty(&dereferenced).unwrap()
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_evidence_deref() {
        let result = evidence_deref_example();
        assert!(result.contains("Execve"));
        assert!(result.contains("record_index"));
        assert!(result.contains("windows_evtx"));
    }
}
