//! End to end test of the edr-locald binary with the YAML playbooks.
//!
//! Builds a small telemetry root (index.json plus one segment), runs
//! `edr-locald --once` against it, and reads the signals, explanations and the
//! playbooks_loaded.json status file it writes. This is the same path the
//! desktop app and the PowerShell scripts use, minus live capture.

use rusqlite::Connection;
use std::path::{Path, PathBuf};
use std::process::Command;

fn repo_playbooks() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../../playbooks/windows")
}

/// Segment records in the format the capture agent writes.
fn segment_lines() -> Vec<serde_json::Value> {
    let base = 1_700_000_000_000i64;
    let xml_4688 = "<Event><System><EventID>4688</EventID></System><EventData>\
        <Data Name='SubjectUserName'>alice</Data>\
        <Data Name='NewProcessName'>C:\\Windows\\System32\\wbem\\WMIC.exe</Data>\
        <Data Name='CommandLine'>wmic shadowcopy delete /nointeractive</Data>\
        </EventData></Event>";
    vec![
        // Security log cleared, with the event data only in the XML
        serde_json::json!({
            "ts_ms": base,
            "host": "WS01",
            "tags": ["windows", "event_log", "security"],
            "fields": {
                "windows.event_id": 1102,
                "windows.channel": "Security",
                "windows.provider": "Microsoft-Windows-Eventlog",
                "windows.xml": "<Event><UserData><LogFileCleared><SubjectUserName>alice</SubjectUserName></LogFileCleared></UserData></Event>"
            },
            "evidence_ptr": {"stream_id": "Security", "segment_id": 7, "record_index": 0}
        }),
        // Service installed from a temp folder, flat fields
        serde_json::json!({
            "ts_ms": base + 1000,
            "host": "WS01",
            "tags": ["windows", "event_log", "system"],
            "fields": {
                "windows.event_id": 7045,
                "windows.channel": "System",
                "ServiceName": "TestPersistenceService",
                "ImagePath": "C:\\Windows\\Temp\\persistence.exe"
            },
            "evidence_ptr": {"stream_id": "System", "segment_id": 7, "record_index": 1}
        }),
        // Shadow copy deletion, event data only in the XML
        serde_json::json!({
            "ts_ms": base + 2000,
            "host": "WS01",
            "tags": ["windows", "event_log", "security"],
            "fields": {
                "windows.event_id": 4688,
                "windows.channel": "Security",
                "windows.xml": xml_4688
            },
            "evidence_ptr": {"stream_id": "Security", "segment_id": 7, "record_index": 2}
        }),
        // Benign process, must not produce a signal
        serde_json::json!({
            "ts_ms": base + 3000,
            "host": "WS01",
            "tags": ["windows", "event_log", "security"],
            "fields": {
                "windows.event_id": 4688,
                "windows.channel": "Security",
                "NewProcessName": "C:\\Windows\\System32\\notepad.exe",
                "CommandLine": "notepad.exe C:\\notes.txt",
                "SubjectUserName": "alice"
            },
            "evidence_ptr": {"stream_id": "Security", "segment_id": 7, "record_index": 3}
        }),
    ]
}

fn make_root() -> tempfile::TempDir {
    let root = tempfile::tempdir().expect("tempdir");
    let segments = root.path().join("segments");
    std::fs::create_dir_all(&segments).unwrap();
    let body: String = segment_lines().iter().map(|v| format!("{}\n", v)).collect();
    // Named the way capture names segments, so evidence lookups use the
    // evtx_NNNNNN fallback.
    std::fs::write(segments.join("evtx_000007.jsonl"), body).unwrap();
    std::fs::write(
        root.path().join("index.json"),
        r#"{"schema_version": 1, "segments": [{"rel_path": "segments/evtx_000007.jsonl", "stream_id": "Security"}]}"#,
    )
    .unwrap();
    root
}

fn run_locald(root: &Path, envs: &[(&str, String)]) {
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_edr-locald"));
    cmd.arg("--once")
        .env("EDR_TELEMETRY_ROOT", root)
        .env_remove("EDR_PLAYBOOKS_DIR")
        .env_remove("EDR_PLAYBOOK_DIR")
        .env_remove("EDR_SELECTED_PLAYBOOKS")
        .env_remove("EDR_WORKFLOW_SEED");
    for (k, v) in envs {
        cmd.env(k, v);
    }
    let out = cmd.output().expect("run edr-locald");
    assert!(
        out.status.success(),
        "edr-locald failed: {}",
        String::from_utf8_lossy(&out.stderr)
    );
}

fn signal_types(root: &Path) -> Vec<(String, String, serde_json::Value)> {
    let db = Connection::open(root.join("workbench.db")).unwrap();
    let mut stmt = db
        .prepare("SELECT signal_id, signal_type, metadata FROM signals ORDER BY signal_type")
        .unwrap();
    let rows = stmt
        .query_map([], |r| {
            Ok((
                r.get::<_, String>(0)?,
                r.get::<_, String>(1)?,
                r.get::<_, String>(2)?,
            ))
        })
        .unwrap()
        .map(|r| r.unwrap())
        .map(|(id, t, m)| (id, t, serde_json::from_str(&m).unwrap()))
        .collect();
    rows
}

fn status(root: &Path) -> serde_json::Value {
    let text = std::fs::read_to_string(root.join("playbooks_loaded.json")).unwrap();
    serde_json::from_str(&text).unwrap()
}

#[test]
fn locald_runs_all_yaml_playbooks_and_writes_signals() {
    let root = make_root();
    run_locald(
        root.path(),
        &[("EDR_PLAYBOOKS_DIR", repo_playbooks().display().to_string())],
    );

    let st = status(root.path());
    assert_eq!(st["count"], 30);
    assert_eq!(st["dir_source"], "EDR_PLAYBOOKS_DIR");
    assert_eq!(st["errors"].as_array().unwrap().len(), 0);

    let signals = signal_types(root.path());
    let types: Vec<&str> = signals.iter().map(|(_, t, _)| t.as_str()).collect();
    for expected in [
        "playbook:signal_defense_evasion",
        "playbook:signal_log_tamper_detection",
        "playbook:signal_service_persistence",
        "playbook:signal_wmic_abuse",
    ] {
        assert!(
            types.contains(&expected),
            "missing {} in {:?}",
            expected,
            types
        );
    }
    assert_eq!(signals.len(), 4, "unexpected signals: {:?}", types);

    let wmic = signals
        .iter()
        .find(|(_, t, _)| t == "playbook:signal_wmic_abuse")
        .unwrap();
    assert_eq!(wmic.2["rule"], "WMIC Shadow Copy Delete");
    assert_eq!(wmic.2["mitre_techniques"], serde_json::json!(["T1490"]));
    assert_eq!(wmic.2["attack_version"], "20.1");
    assert!(wmic.2["mitre_tactics"]
        .as_array()
        .unwrap()
        .contains(&serde_json::json!("impact")));

    // Every signal has an explanation whose evidence points at the right record
    let db = Connection::open(root.path().join("workbench.db")).unwrap();
    for (id, t, _) in &signals {
        let json: String = db
            .query_row(
                "SELECT explanation_json FROM signal_explanations WHERE signal_id = ?1",
                [id],
                |r| r.get(0),
            )
            .unwrap_or_else(|_| panic!("no explanation for {}", t));
        let exp: serde_json::Value = serde_json::from_str(&json).unwrap();
        assert_eq!(
            format!("playbook:{}", exp["playbook_id"].as_str().unwrap()),
            *t
        );
        assert!(!exp["slots"].as_array().unwrap().is_empty());
        let evidence = exp["evidence"].as_array().unwrap();
        assert!(!evidence.is_empty(), "{} has no evidence", t);
        assert!(
            evidence.iter().all(|e| e["excerpt"].is_string()),
            "{} evidence did not dereference: {:?}",
            t,
            evidence
        );
    }
}

#[test]
fn locald_honors_the_desktop_selection() {
    let root = make_root();
    run_locald(
        root.path(),
        &[
            ("EDR_PLAYBOOKS_DIR", repo_playbooks().display().to_string()),
            ("EDR_SELECTED_PLAYBOOKS", "signal_wmic_abuse".to_string()),
        ],
    );

    let st = status(root.path());
    assert_eq!(st["count"], 1);
    assert_eq!(st["loaded"], serde_json::json!(["signal_wmic_abuse"]));
    assert_eq!(st["selected"], serde_json::json!(["signal_wmic_abuse"]));

    let signals = signal_types(root.path());
    let types: Vec<&str> = signals.iter().map(|(_, t, _)| t.as_str()).collect();
    assert_eq!(types, vec!["playbook:signal_wmic_abuse"]);
}

#[test]
fn locald_accepts_the_old_playbook_dir_variable() {
    let root = make_root();
    run_locald(
        root.path(),
        &[("EDR_PLAYBOOK_DIR", repo_playbooks().display().to_string())],
    );
    let st = status(root.path());
    assert_eq!(st["count"], 30);
    assert_eq!(st["dir_source"], "EDR_PLAYBOOK_DIR");
}

#[test]
fn locald_reports_a_missing_playbook_dir() {
    let root = make_root();
    run_locald(
        root.path(),
        &[(
            "EDR_PLAYBOOKS_DIR",
            root.path().join("no-such-dir").display().to_string(),
        )],
    );
    let st = status(root.path());
    assert_eq!(st["count"], 0);
    assert_eq!(st["errors"].as_array().unwrap().len(), 1);
    assert!(signal_types(root.path()).is_empty());
}
