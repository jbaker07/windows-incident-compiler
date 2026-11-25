//! Fixture tests for every YAML playbook in playbooks/windows.
//!
//! Each playbook has a fixture file in testdata/playbooks/windows/<id>.json with
//! two lists:
//!
//! * `fires`: event sequences that must make a named rule fire
//! * `near_miss`: event sequences that look similar but must not fire any rule
//!
//! The events go through the same path as edr-locald: flatten_event_xml, then
//! extract_facts, then the playbook engine. Each playbook gets its own named
//! test below, so a failure names the playbook.

use edr_core::{Event, EvidencePtr};
use edr_locald::os::windows::{extract_facts, flatten_event_xml};
use edr_locald::playbook::{
    load_dir, parse_playbook, Playbook, PlaybookEngine, PlaybookMatch, ATTACK_TACTICS,
    ATTACK_VERSION, RETIRED_TECHNIQUES,
};
use serde::Deserialize;
use std::collections::{BTreeMap, HashSet};
use std::path::{Path, PathBuf};

const EXPECTED_PLAYBOOKS: usize = 30;

/// ATT&CK v20.1 Enterprise techniques used by the shipped playbooks, as read
/// from attack.mitre.org: (ID, name, tactics).
const ATTACK_V20_1: &[(&str, &str, &[&str])] = &[
    (
        "T1003.001",
        "OS Credential Dumping: LSASS Memory",
        &["credential_access"],
    ),
    (
        "T1003.002",
        "OS Credential Dumping: Security Account Manager",
        &["credential_access"],
    ),
    (
        "T1003.003",
        "OS Credential Dumping: NTDS",
        &["credential_access"],
    ),
    (
        "T1016",
        "System Network Configuration Discovery",
        &["discovery"],
    ),
    (
        "T1021.001",
        "Remote Services: Remote Desktop Protocol",
        &["lateral_movement"],
    ),
    (
        "T1021.002",
        "Remote Services: SMB/Windows Admin Shares",
        &["lateral_movement"],
    ),
    (
        "T1021.006",
        "Remote Services: Windows Remote Management",
        &["lateral_movement"],
    ),
    (
        "T1027.010",
        "Obfuscated Files or Information: Command Obfuscation",
        &["stealth"],
    ),
    (
        "T1027.013",
        "Obfuscated Files or Information: Encrypted/Encoded File",
        &["stealth"],
    ),
    ("T1033", "System Owner/User Discovery", &["discovery"]),
    (
        "T1047",
        "Windows Management Instrumentation",
        &["execution"],
    ),
    (
        "T1049",
        "System Network Connections Discovery",
        &["discovery"],
    ),
    (
        "T1053.005",
        "Scheduled Task/Job: Scheduled Task",
        &["execution", "persistence", "privilege_escalation"],
    ),
    (
        "T1055",
        "Process Injection",
        &["stealth", "privilege_escalation"],
    ),
    (
        "T1055.001",
        "Process Injection: Dynamic-link Library Injection",
        &["stealth", "privilege_escalation"],
    ),
    (
        "T1055.012",
        "Process Injection: Process Hollowing",
        &["stealth", "privilege_escalation"],
    ),
    ("T1057", "Process Discovery", &["discovery"]),
    (
        "T1059.001",
        "Command and Scripting Interpreter: PowerShell",
        &["execution"],
    ),
    (
        "T1059.005",
        "Command and Scripting Interpreter: Visual Basic",
        &["execution"],
    ),
    (
        "T1059.007",
        "Command and Scripting Interpreter: JavaScript",
        &["execution"],
    ),
    ("T1069", "Permission Groups Discovery", &["discovery"]),
    (
        "T1069.002",
        "Permission Groups Discovery: Domain Groups",
        &["discovery"],
    ),
    (
        "T1070.004",
        "Indicator Removal: File Deletion",
        &["stealth"],
    ),
    (
        "T1070.005",
        "Indicator Removal: Network Share Connection Removal",
        &["stealth"],
    ),
    (
        "T1074.001",
        "Data Staged: Local Data Staging",
        &["collection"],
    ),
    (
        "T1078",
        "Valid Accounts",
        &[
            "stealth",
            "persistence",
            "privilege_escalation",
            "initial_access",
        ],
    ),
    ("T1082", "System Information Discovery", &["discovery"]),
    ("T1087", "Account Discovery", &["discovery"]),
    (
        "T1087.002",
        "Account Discovery: Domain Account",
        &["discovery"],
    ),
    (
        "T1098",
        "Account Manipulation",
        &["persistence", "privilege_escalation"],
    ),
    (
        "T1098.007",
        "Account Manipulation: Additional Local or Domain Groups",
        &["persistence", "privilege_escalation"],
    ),
    ("T1105", "Ingress Tool Transfer", &["command_and_control"]),
    (
        "T1110.001",
        "Brute Force: Password Guessing",
        &["credential_access"],
    ),
    (
        "T1110.003",
        "Brute Force: Password Spraying",
        &["credential_access"],
    ),
    (
        "T1112",
        "Modify Registry",
        &["defense_impairment", "persistence"],
    ),
    (
        "T1133",
        "External Remote Services",
        &["persistence", "initial_access"],
    ),
    ("T1135", "Network Share Discovery", &["discovery"]),
    ("T1136", "Create Account", &["persistence"]),
    (
        "T1136.001",
        "Create Account: Local Account",
        &["persistence"],
    ),
    (
        "T1140",
        "Deobfuscate/Decode Files or Information",
        &["stealth"],
    ),
    (
        "T1197",
        "BITS Jobs",
        &["stealth", "persistence", "execution"],
    ),
    (
        "T1204.002",
        "User Execution: Malicious File",
        &["execution"],
    ),
    ("T1218", "System Binary Proxy Execution", &["stealth"]),
    (
        "T1218.005",
        "System Binary Proxy Execution: Mshta",
        &["stealth"],
    ),
    (
        "T1218.010",
        "System Binary Proxy Execution: Regsvr32",
        &["stealth"],
    ),
    (
        "T1218.011",
        "System Binary Proxy Execution: Rundll32",
        &["stealth"],
    ),
    ("T1220", "XSL Script Processing", &["stealth"]),
    ("T1482", "Domain Trust Discovery", &["discovery"]),
    ("T1490", "Inhibit System Recovery", &["impact"]),
    (
        "T1543.003",
        "Create or Modify System Process: Windows Service",
        &["persistence", "privilege_escalation"],
    ),
    (
        "T1546.003",
        "Event Triggered Execution: Windows Management Instrumentation Event Subscription",
        &["privilege_escalation", "persistence"],
    ),
    (
        "T1546.012",
        "Event Triggered Execution: Image File Execution Options Injection",
        &["privilege_escalation", "persistence"],
    ),
    (
        "T1547.001",
        "Boot or Logon Autostart Execution: Registry Run Keys / Startup Folder",
        &["persistence", "privilege_escalation"],
    ),
    (
        "T1547.004",
        "Boot or Logon Autostart Execution: Winlogon Helper DLL",
        &["persistence", "privilege_escalation"],
    ),
    (
        "T1555.004",
        "Credentials from Password Stores: Windows Credential Manager",
        &["credential_access"],
    ),
    (
        "T1558.003",
        "Steal or Forge Kerberos Tickets: Kerberoasting",
        &["credential_access"],
    ),
    (
        "T1560.001",
        "Archive Collected Data: Archive via Utility",
        &["collection"],
    ),
    ("T1564.003", "Hide Artifacts: Hidden Window", &["stealth"]),
    (
        "T1564.012",
        "Hide Artifacts: File/Path Exclusions",
        &["stealth"],
    ),
    (
        "T1566.001",
        "Phishing: Spearphishing Attachment",
        &["initial_access"],
    ),
    (
        "T1569.002",
        "System Services: Service Execution",
        &["execution"],
    ),
    (
        "T1574.001",
        "Hijack Execution Flow: DLL",
        &["stealth", "execution"],
    ),
    ("T1615", "Group Policy Discovery", &["discovery"]),
    ("T1620", "Reflective Code Loading", &["stealth"]),
    ("T1685", "Disable or Modify Tools", &["defense_impairment"]),
    (
        "T1685.001",
        "Disable or Modify Tools: Disable or Modify Windows Event Log",
        &["defense_impairment"],
    ),
    (
        "T1685.005",
        "Disable or Modify Tools: Clear Windows Event Logs",
        &["defense_impairment"],
    ),
    (
        "T1686.003",
        "Disable or Modify System Firewall: Windows Host Firewall",
        &["defense_impairment"],
    ),
];

fn repo_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../..")
}

fn playbook_dir() -> PathBuf {
    repo_root().join("playbooks/windows")
}

fn fixture_dir() -> PathBuf {
    repo_root().join("testdata/playbooks/windows")
}

#[derive(Debug, Deserialize)]
struct Fixture {
    playbook: String,
    fires: Vec<FireCase>,
    near_miss: Vec<NearMissCase>,
}

#[derive(Debug, Deserialize)]
struct FireCase {
    rule: String,
    events: Vec<FixtureEvent>,
}

#[derive(Debug, Deserialize)]
struct NearMissCase {
    name: String,
    events: Vec<FixtureEvent>,
}

#[derive(Debug, Deserialize)]
struct FixtureEvent {
    /// Seconds after the fixture start. Defaults to the event position.
    t: Option<i64>,
    host: Option<String>,
    #[serde(default)]
    tags: Vec<String>,
    identity_key: Option<String>,
    proc_key: Option<String>,
    fields: BTreeMap<String, serde_json::Value>,
}

fn load_playbook(id: &str) -> Playbook {
    let path = playbook_dir().join(format!("{}.yaml", id));
    let text =
        std::fs::read_to_string(&path).unwrap_or_else(|e| panic!("{}: {}", path.display(), e));
    parse_playbook(&text, Some(&path)).unwrap_or_else(|e| panic!("{}: {}", id, e))
}

fn load_fixture(id: &str) -> Fixture {
    let path = fixture_dir().join(format!("{}.json", id));
    let text =
        std::fs::read_to_string(&path).unwrap_or_else(|e| panic!("{}: {}", path.display(), e));
    let fixture: Fixture =
        serde_json::from_str(&text).unwrap_or_else(|e| panic!("{}: {}", path.display(), e));
    assert_eq!(
        fixture.playbook,
        id,
        "fixture {} names the wrong playbook",
        path.display()
    );
    fixture
}

fn to_event(e: &FixtureEvent, index: usize) -> Event {
    let t = e.t.unwrap_or(index as i64);
    let mut tags = vec!["windows".to_string(), "event_log".to_string()];
    tags.extend(e.tags.iter().cloned());
    let mut event = Event {
        ts_ms: 1_700_000_000_000 + t * 1000,
        host: e.host.clone().unwrap_or_else(|| "WS01".to_string()),
        tags,
        proc_key: e.proc_key.clone(),
        file_key: None,
        identity_key: e.identity_key.clone(),
        evidence_ptr: Some(EvidencePtr {
            stream_id: "fixture".to_string(),
            segment_id: 1,
            record_index: index as u32,
        }),
        fields: e.fields.clone(),
    };
    flatten_event_xml(&mut event);
    event
}

fn run(playbook: &Playbook, events: &[FixtureEvent]) -> Vec<PlaybookMatch> {
    let mut engine = PlaybookEngine::new(vec![playbook.clone()]);
    let mut out = Vec::new();
    for (i, e) in events.iter().enumerate() {
        let event = to_event(e, i);
        let facts = extract_facts(&event);
        out.extend(engine.process(&event, &facts));
    }
    out
}

/// Run every fixture case for one playbook.
fn check_playbook(id: &str) {
    let playbook = load_playbook(id);
    let fixture = load_fixture(id);

    let rule_names: HashSet<&str> = playbook.rules.iter().map(|r| r.name.as_str()).collect();
    let covered: HashSet<&str> = fixture.fires.iter().map(|c| c.rule.as_str()).collect();
    for name in &rule_names {
        assert!(
            covered.contains(name),
            "{}: rule '{}' has no positive fixture",
            id,
            name
        );
    }
    assert!(
        !fixture.near_miss.is_empty(),
        "{}: needs at least one near miss fixture",
        id
    );

    for (i, case) in fixture.fires.iter().enumerate() {
        assert!(
            rule_names.contains(case.rule.as_str()),
            "{}: fixture names unknown rule '{}'",
            id,
            case.rule
        );
        let matches = run(&playbook, &case.events);
        let fired: Vec<&str> = matches.iter().map(|m| m.rule_name.as_str()).collect();
        assert!(
            fired.contains(&case.rule.as_str()),
            "{}: positive case {} expected rule '{}' to fire, fired: {:?}",
            id,
            i,
            case.rule,
            fired
        );
        for m in &matches {
            assert_eq!(m.playbook_id, id);
            assert_eq!(m.attack_version, ATTACK_VERSION);
            assert!(!m.techniques.is_empty(), "{}: match without techniques", id);
            assert!(!m.facts.is_empty(), "{}: match without facts", id);
            assert!(
                m.facts.iter().all(|f| !f.fact.evidence_ptrs.is_empty()),
                "{}: fact without evidence",
                id
            );
        }
    }

    for case in &fixture.near_miss {
        let matches = run(&playbook, &case.events);
        let fired: Vec<&str> = matches.iter().map(|m| m.rule_name.as_str()).collect();
        assert!(
            matches.is_empty(),
            "{}: near miss '{}' fired {:?}",
            id,
            case.name,
            fired
        );
    }
}

macro_rules! playbook_case {
    ($id:ident) => {
        #[test]
        fn $id() {
            check_playbook(stringify!($id));
        }
    };
}

playbook_case!(signal_bitsadmin_abuse);
playbook_case!(signal_certutil_abuse);
playbook_case!(signal_credential_access);
playbook_case!(signal_defense_evasion);
playbook_case!(signal_discovery_burst);
playbook_case!(signal_dll_side_loading);
playbook_case!(signal_encoded_powershell);
playbook_case!(signal_file_staging);
playbook_case!(signal_group_membership_change);
playbook_case!(signal_lateral_movement_detection);
playbook_case!(signal_log_tamper_detection);
playbook_case!(signal_log_tampering);
playbook_case!(signal_logon_anomaly);
playbook_case!(signal_lolbin_abuse);
playbook_case!(signal_mshta_abuse);
playbook_case!(signal_net_command_abuse);
playbook_case!(signal_office_child_process);
playbook_case!(signal_persistence_windows);
playbook_case!(signal_powershell_download);
playbook_case!(signal_process_injection);
playbook_case!(signal_registry_persistence);
playbook_case!(signal_regsvr32_abuse);
playbook_case!(signal_rundll32_abuse);
playbook_case!(signal_sc_abuse);
playbook_case!(signal_schtasks_abuse);
playbook_case!(signal_security_tool_disable);
playbook_case!(signal_service_persistence);
playbook_case!(signal_task_persistence);
playbook_case!(signal_wmic_abuse);
playbook_case!(signal_wscript_cscript_abuse);

#[test]
fn all_playbooks_load_without_errors() {
    let report = load_dir(&playbook_dir(), None);
    assert!(report.errors.is_empty(), "load errors: {:?}", report.errors);
    assert_eq!(report.files_found, EXPECTED_PLAYBOOKS);
    assert_eq!(report.playbooks.len(), EXPECTED_PLAYBOOKS);
    assert!(report.disabled.is_empty());
}

#[test]
fn every_playbook_file_has_a_fixture_and_a_named_test() {
    let report = load_dir(&playbook_dir(), None);
    let named: HashSet<&str> = include_str!("yaml_playbooks.rs")
        .lines()
        .filter_map(|l| l.strip_prefix("playbook_case!(")?.strip_suffix(");"))
        .collect();
    for pb in &report.playbooks {
        assert!(
            fixture_dir().join(format!("{}.json", pb.id)).is_file(),
            "{} has no fixture file",
            pb.id
        );
        assert!(
            named.contains(pb.id.as_str()),
            "{} has no playbook_case! line",
            pb.id
        );
    }
}

#[test]
fn attack_mappings_follow_v20_1() {
    let report = load_dir(&playbook_dir(), None);
    let mut all_techniques = HashSet::new();
    for pb in &report.playbooks {
        assert_eq!(pb.attack_version, "20.1", "{}", pb.id);
        let mut justified = HashSet::new();
        for t in &pb.techniques {
            let (_, name, tactics) = ATTACK_V20_1
                .iter()
                .find(|(id, _, _)| *id == t.id)
                .unwrap_or_else(|| {
                    panic!(
                        "{}: {} is not in the v20.1 table, check attack.mitre.org",
                        pb.id, t.id
                    )
                });
            assert_eq!(
                &t.name, name,
                "{}: {} should be named '{}'",
                pb.id, t.id, name
            );
            assert!(
                tactics
                    .iter()
                    .any(|tac| pb.tactics.iter().any(|p| p == tac)),
                "{}: {} maps to {:?} but the playbook lists none of them",
                pb.id,
                t.id,
                tactics
            );
            justified.extend(tactics.iter().copied());
            assert!(!RETIRED_TECHNIQUES.iter().any(|(old, _)| *old == t.id));
            all_techniques.insert(t.id.clone());
        }
        for tac in &pb.tactics {
            assert!(
                ATTACK_TACTICS.iter().any(|(n, _, _)| n == tac),
                "{}: unknown tactic {}",
                pb.id,
                tac
            );
            assert!(
                justified.contains(tac.as_str()),
                "{}: tactic {} is not a tactic of any listed technique",
                pb.id,
                tac
            );
        }
        for rule in &pb.rules {
            assert!(
                !rule.techniques.is_empty(),
                "{}: rule {} maps to nothing",
                pb.id,
                rule.name
            );
        }
    }
    assert_eq!(
        all_techniques.len(),
        ATTACK_V20_1.len(),
        "table and playbooks list different techniques"
    );
}

#[test]
fn selection_loads_only_the_named_playbooks() {
    let selected = vec![
        "signal_bitsadmin_abuse".to_string(),
        "signal_wmic_abuse.yaml"
            .trim_end_matches(".yaml")
            .to_string(),
        "not_a_playbook".to_string(),
    ];
    let report = load_dir(&playbook_dir(), Some(&selected));
    assert_eq!(
        report.loaded_ids(),
        vec!["signal_bitsadmin_abuse", "signal_wmic_abuse"]
    );
    assert_eq!(report.not_selected.len(), EXPECTED_PLAYBOOKS - 2);
    assert_eq!(report.unknown_selected, vec!["not_a_playbook"]);
    assert!(report.errors.is_empty());
}

#[test]
fn every_playbook_fires_on_its_fixtures_when_all_are_loaded() {
    // Same fixtures, one engine with all 30 playbooks, as edr-locald runs them.
    // Every positive case must still fire its rule.
    let report = load_dir(&playbook_dir(), None);
    for pb in &report.playbooks {
        let fixture = load_fixture(&pb.id);
        for case in &fixture.fires {
            let mut engine = PlaybookEngine::new(report.playbooks.clone());
            let mut fired = Vec::new();
            for (i, e) in case.events.iter().enumerate() {
                let event = to_event(e, i);
                let facts = extract_facts(&event);
                fired.extend(engine.process(&event, &facts));
            }
            assert!(
                fired
                    .iter()
                    .any(|m| m.playbook_id == pb.id && m.rule_name == case.rule),
                "{} rule '{}' did not fire with all playbooks loaded",
                pb.id,
                case.rule
            );
        }
    }
}

#[test]
fn event_xml_drives_a_playbook_end_to_end() {
    // A 4688 event as the capture agent writes it: system fields plus XML.
    let xml = "<Event><System><EventID>4688</EventID></System><EventData>\
        <Data Name='SubjectUserName'>alice</Data>\
        <Data Name='NewProcessName'>C:\\Windows\\System32\\wbem\\WMIC.exe</Data>\
        <Data Name='CommandLine'>wmic shadowcopy delete /nointeractive</Data>\
        </EventData></Event>";
    let mut fields = BTreeMap::new();
    fields.insert("windows.event_id".to_string(), serde_json::json!(4688));
    fields.insert("windows.channel".to_string(), serde_json::json!("Security"));
    fields.insert("windows.xml".to_string(), serde_json::json!(xml));
    let e = FixtureEvent {
        t: Some(0),
        host: None,
        tags: vec![],
        identity_key: None,
        proc_key: None,
        fields,
    };
    let matches = run(&load_playbook("signal_wmic_abuse"), &[e]);
    assert_eq!(matches.len(), 1);
    assert_eq!(matches[0].rule_name, "WMIC Shadow Copy Delete");
    assert_eq!(matches[0].techniques, vec!["T1490".to_string()]);
}

#[test]
fn import_playbook_templates_are_valid_yaml() {
    // playbooks/import holds templates for the evidence importer. No code runs
    // them yet, but they must stay parseable so a future loader can read them.
    let dir = repo_root().join("playbooks/import");
    let mut count = 0;
    for entry in std::fs::read_dir(&dir).unwrap() {
        let path = entry.unwrap().path();
        if path.extension().and_then(|e| e.to_str()) != Some("yaml") {
            continue;
        }
        let text = std::fs::read_to_string(&path).unwrap();
        serde_yaml::from_str::<serde_yaml::Value>(&text)
            .unwrap_or_else(|e| panic!("{}: {}", path.display(), e));
        count += 1;
    }
    assert_eq!(count, 14);
}
