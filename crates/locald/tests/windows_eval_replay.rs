//! Replay of the events `scripts/eval_windows.ps1 -ScenarioSet full` makes a
//! Windows host write, in the record format the capture agent writes.
//!
//! The XML follows what EvtRender returns on Windows: the event namespace,
//! single quoted attributes, `<EventID Qualifiers='16384'>` for the Service
//! Control Manager, escaped task XML in 4698, and the command lines .NET builds
//! (quoted program name first). edr-locald runs over it with `--once` and the
//! test checks the playbooks the script expects, by id. The CI job on
//! windows-latest checks the same list against a live capture.

use rusqlite::Connection;
use std::collections::BTreeSet;
use std::path::{Path, PathBuf};
use std::process::Command;

const HOST: &str = "fv-az100-200";
const USER: &str = "runneradmin";
/// 2026-11-23T10:00:00Z
const BASE_MS: i64 = 1_795_428_000_000;

/// Playbooks eval_windows.ps1 expects from the full scenario set
const EXPECTED: [&str; 11] = [
    "signal_certutil_abuse",
    "signal_discovery_burst",
    "signal_encoded_powershell",
    "signal_group_membership_change",
    "signal_log_tamper_detection",
    "signal_logon_anomaly",
    "signal_net_command_abuse",
    "signal_sc_abuse",
    "signal_schtasks_abuse",
    "signal_service_persistence",
    "signal_task_persistence",
];

fn repo_playbooks() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../../playbooks/windows")
}

fn escape(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&apos;")
}

fn iso(offset_ms: i64) -> String {
    let ts = chrono::DateTime::from_timestamp_millis(BASE_MS + offset_ms).unwrap();
    // Windows writes seven fractional digits (100 ns units)
    let hundred_ns = (BASE_MS + offset_ms).rem_euclid(1000) * 10_000;
    format!("{}.{:07}Z", ts.format("%Y-%m-%dT%H:%M:%S"), hundred_ns)
}

struct Replay {
    lines: Vec<serde_json::Value>,
    record_id: u64,
}

impl Replay {
    fn new() -> Self {
        Self {
            lines: Vec::new(),
            record_id: 1000,
        }
    }

    fn push(&mut self, offset_ms: i64, channel: &str, provider: &str, event_id: &str, body: &str) {
        self.record_id += 1;
        // "4688", or a whole element such as "<EventID Qualifiers='16384'>7045</EventID>"
        let id: u32 = if event_id.starts_with('<') {
            event_id
                .split('>')
                .nth(1)
                .unwrap()
                .split('<')
                .next()
                .unwrap()
        } else {
            event_id
        }
        .parse()
        .unwrap();
        let event_id_xml = if event_id.starts_with('<') {
            event_id.to_string()
        } else {
            format!("<EventID>{}</EventID>", event_id)
        };
        let xml = format!(
            "<Event xmlns='http://schemas.microsoft.com/win/2004/08/events/event'><System>\
             <Provider Name='{provider}'/>{event_id_xml}<Version>0</Version><Level>0</Level>\
             <TimeCreated SystemTime='{ts}'/><EventRecordID>{rid}</EventRecordID><Correlation/>\
             <Execution ProcessID='4' ThreadID='88'/><Channel>{channel}</Channel>\
             <Computer>{HOST}</Computer><Security/></System>{body}</Event>",
            ts = iso(offset_ms),
            rid = self.record_id,
        );
        let index = self.lines.len() as u32;
        self.lines.push(serde_json::json!({
            "ts_ms": BASE_MS + offset_ms,
            "host": HOST,
            "tags": ["windows", "event_log", channel.to_lowercase()],
            "fields": {
                "windows.channel": channel,
                "windows.event_id": id,
                "windows.provider": provider,
                "windows.computer": HOST,
                "windows.source_record_id": self.record_id,
                "windows.xml": xml,
            },
            "evidence_ptr": {"stream_id": channel, "segment_id": 0, "record_index": index}
        }));
    }

    fn data(pairs: &[(&str, &str)]) -> String {
        let mut out = String::from("<EventData>");
        for (k, v) in pairs {
            out.push_str(&format!("<Data Name='{}'>{}</Data>", k, escape(v)));
        }
        out.push_str("</EventData>");
        out
    }

    fn security(&mut self, offset_ms: i64, event_id: u32, pairs: &[(&str, &str)]) {
        let body = Self::data(pairs);
        self.push(
            offset_ms,
            "Security",
            "Microsoft-Windows-Security-Auditing",
            &event_id.to_string(),
            &body,
        );
    }

    /// Security 4688 as written with command line logging on
    fn process(&mut self, offset_ms: i64, image: &str, cmdline: &str) {
        self.security(
            offset_ms,
            4688,
            &[
                ("SubjectUserSid", "S-1-5-21-1-2-3-500"),
                ("SubjectUserName", USER),
                ("SubjectDomainName", HOST),
                ("SubjectLogonId", "0x2a4f1"),
                ("NewProcessId", "0x1a2c"),
                ("NewProcessName", image),
                ("TokenElevationType", "%%1936"),
                ("ProcessId", "0x1234"),
                ("CommandLine", cmdline),
                ("TargetUserSid", "S-1-0-0"),
                ("TargetUserName", "-"),
                ("TargetDomainName", "-"),
                ("TargetLogonId", "0x0"),
                (
                    "ParentProcessName",
                    "C:\\Program Files\\PowerShell\\7\\pwsh.exe",
                ),
                ("MandatoryLabel", "S-1-16-12288"),
            ],
        );
    }

    fn log_cleared(&mut self, offset_ms: i64, channel: &str, event_id: &str) {
        let body = format!(
            "<UserData><LogFileCleared xmlns='http://manifests.microsoft.com/win/2004/08/windows/eventlog'>\
             <SubjectUserSid>S-1-5-21-1-2-3-500</SubjectUserSid><SubjectUserName>{USER}</SubjectUserName>\
             <SubjectDomainName>{HOST}</SubjectDomainName><SubjectLogonId>0x2a4f1</SubjectLogonId>\
             </LogFileCleared></UserData>"
        );
        self.push(
            offset_ms,
            channel,
            "Microsoft-Windows-Eventlog",
            event_id,
            &body,
        );
    }
}

fn sys32(exe: &str) -> String {
    format!("C:\\Windows\\System32\\{}", exe)
}

/// The full scenario, in the order the script runs it
fn scenario() -> Vec<serde_json::Value> {
    let mut r = Replay::new();
    let work = "C:\\ProgramData\\edr_eval\\work";

    r.log_cleared(0, "Security", "1102");
    r.process(800, &sys32("wevtutil.exe"), "\"wevtutil.exe\" cl System");
    r.log_cleared(900, "System", "104");

    r.process(5_000, &sys32("whoami.exe"), "\"whoami.exe\" /all");
    r.process(5_400, &sys32("HOSTNAME.EXE"), "\"hostname.exe\"");
    r.process(5_600, &sys32("ipconfig.exe"), "\"ipconfig.exe\" /all");
    r.process(5_900, &sys32("tasklist.exe"), "\"tasklist.exe\"");
    r.process(6_400, &sys32("net.exe"), "\"net.exe\" user");
    r.process(
        6_450,
        &sys32("net1.exe"),
        "C:\\Windows\\system32\\net1  user",
    );
    r.process(
        6_900,
        &sys32("net.exe"),
        "\"net.exe\" localgroup administrators",
    );

    let encoded = "VwByAGkAdABlAC0ATwB1AHQAcAB1AHQAIAAnAGUAZAByACAAZQB2AGEAbAAgAGUAbgBjAG8AZABlAGQAIABjAG8AbQBtAGEAbgBkACcA";
    r.process(
        7_500,
        "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
        &format!(
            "\"powershell.exe\" -NoProfile -NonInteractive -WindowStyle Hidden -EncodedCommand {}",
            encoded
        ),
    );
    r.process(
        9_000,
        &sys32("certutil.exe"),
        &format!(
            "\"certutil.exe\" -f -encode {w}\\edr_eval_plain.txt {w}\\edr_eval_b64.txt",
            w = work
        ),
    );
    r.process(
        9_500,
        &sys32("certutil.exe"),
        &format!(
            "\"certutil.exe\" -urlcache -split -f http://127.0.0.1:9/edr_eval.txt {}\\edr_eval_dl.txt",
            work
        ),
    );

    for i in 0..6 {
        r.security(
            12_000 + i * 150,
            4625,
            &[
                ("SubjectUserSid", "S-1-5-21-1-2-3-500"),
                ("SubjectUserName", USER),
                ("SubjectDomainName", HOST),
                ("SubjectLogonId", "0x2a4f1"),
                ("TargetUserSid", "S-1-0-0"),
                ("TargetUserName", "edr_eval_nouser"),
                ("TargetDomainName", "."),
                ("Status", "0xc000006d"),
                ("FailureReason", "%%2313"),
                ("SubStatus", "0xc0000064"),
                ("LogonType", "3"),
                ("LogonProcessName", "Advapi  "),
                ("AuthenticationPackageName", "Negotiate"),
                ("WorkstationName", HOST),
                ("ProcessName", "C:\\Program Files\\PowerShell\\7\\pwsh.exe"),
                ("IpAddress", "-"),
                ("IpPort", "-"),
            ],
        );
    }

    r.process(
        15_000,
        &sys32("schtasks.exe"),
        "\"schtasks.exe\" /Create /F /TN EdrEvalTask /SC ONLOGON /RU SYSTEM /TR \"powershell.exe -NoProfile -File C:\\Users\\Public\\edr_eval.ps1\"",
    );
    let task_xml = "<?xml version=\"1.0\" encoding=\"UTF-16\"?>\r\n\
        <Task version=\"1.2\" xmlns=\"http://schemas.microsoft.com/windows/2004/02/mit/task\">\r\n\
        <RegistrationInfo><URI>\\EdrEvalTask</URI></RegistrationInfo>\r\n\
        <Triggers><LogonTrigger><Enabled>true</Enabled></LogonTrigger></Triggers>\r\n\
        <Principals><Principal id=\"Author\"><UserId>S-1-5-18</UserId><RunLevel>LeastPrivilege</RunLevel></Principal></Principals>\r\n\
        <Settings><Hidden>false</Hidden></Settings>\r\n\
        <Actions Context=\"Author\"><Exec><Command>powershell.exe</Command>\
        <Arguments>-NoProfile -File C:\\Users\\Public\\edr_eval.ps1</Arguments></Exec></Actions>\r\n\
        </Task>";
    r.security(
        15_100,
        4698,
        &[
            ("SubjectUserSid", "S-1-5-21-1-2-3-500"),
            ("SubjectUserName", USER),
            ("SubjectDomainName", HOST),
            ("SubjectLogonId", "0x2a4f1"),
            ("TaskName", "\\EdrEvalTask"),
            ("TaskContent", task_xml),
        ],
    );

    r.process(
        16_000,
        &sys32("sc.exe"),
        "\"sc.exe\" create EdrEvalSvc binPath= C:\\Users\\Public\\edr_eval_svc.exe start= demand",
    );
    let svc = Replay::data(&[
        ("ServiceName", "EdrEvalSvc"),
        ("ImagePath", "C:\\Users\\Public\\edr_eval_svc.exe"),
        ("ServiceType", "user mode service"),
        ("StartType", "demand start"),
        ("AccountName", "LocalSystem"),
    ]);
    r.push(
        16_100,
        "System",
        "Service Control Manager",
        "<EventID Qualifiers='16384'>7045</EventID>",
        &svc,
    );

    r.process(
        18_000,
        &sys32("net.exe"),
        "\"net.exe\" user edr_eval_user Ev1!0a1b2c3d4e /add",
    );
    r.security(
        18_100,
        4720,
        &[
            ("TargetUserName", "edr_eval_user"),
            ("TargetDomainName", HOST),
            ("TargetSid", "S-1-5-21-1-2-3-1001"),
            ("SubjectUserSid", "S-1-5-21-1-2-3-500"),
            ("SubjectUserName", USER),
            ("SubjectDomainName", HOST),
            ("SubjectLogonId", "0x2a4f1"),
            ("SamAccountName", "edr_eval_user"),
        ],
    );
    r.process(
        19_000,
        &sys32("net.exe"),
        "\"net.exe\" localgroup administrators edr_eval_user /add",
    );
    r.security(
        19_100,
        4732,
        &[
            ("MemberName", "-"),
            ("MemberSid", "S-1-5-21-1-2-3-1001"),
            ("TargetUserName", "Administrators"),
            ("TargetDomainName", "Builtin"),
            ("TargetSid", "S-1-5-32-544"),
            ("SubjectUserSid", "S-1-5-21-1-2-3-500"),
            ("SubjectUserName", USER),
            ("SubjectDomainName", HOST),
            ("SubjectLogonId", "0x2a4f1"),
        ],
    );

    r.process(
        21_000,
        &sys32("cmd.exe"),
        "\"cmd.exe\" /c echo edr-eval-marker-20261123_100000",
    );
    r.lines
}

fn run_locald(root: &Path) {
    let out = Command::new(env!("CARGO_BIN_EXE_edr-locald"))
        .arg("--once")
        .env("EDR_TELEMETRY_ROOT", root)
        .env("EDR_PLAYBOOKS_DIR", repo_playbooks())
        .env_remove("EDR_PLAYBOOK_DIR")
        .env_remove("EDR_SELECTED_PLAYBOOKS")
        .env_remove("EDR_WORKFLOW_SEED")
        .output()
        .expect("run edr-locald");
    assert!(
        out.status.success(),
        "edr-locald failed: {}",
        String::from_utf8_lossy(&out.stderr)
    );
}

fn fired_playbooks(root: &Path) -> BTreeSet<String> {
    let db = Connection::open(root.join("workbench.db")).unwrap();
    let mut stmt = db.prepare("SELECT signal_type FROM signals").unwrap();
    let rows = stmt
        .query_map([], |r| r.get::<_, String>(0))
        .unwrap()
        .map(|r| r.unwrap().trim_start_matches("playbook:").to_string())
        .collect();
    rows
}

/// Telemetry root with the replay as one capture segment
fn write_root(dir: &Path) {
    let segments = dir.join("segments");
    std::fs::create_dir_all(&segments).unwrap();
    let body: String = scenario().iter().map(|v| format!("{}\n", v)).collect();
    std::fs::write(segments.join("evtx_000000.jsonl"), body).unwrap();
    std::fs::write(
        dir.join("index.json"),
        r#"{"schema_version": 1, "next_seq": 1, "segments": [{"seq": 0, "segment_id": "evtx_000000", "rel_path": "segments/evtx_000000.jsonl"}]}"#,
    )
    .unwrap();
}

#[test]
fn eval_full_scenario_fires_the_expected_playbooks() {
    // EDR_EVAL_REPLAY_DIR also writes the telemetry root there, to run
    // `eval_windows.ps1 -CheckOnly` against it on any OS.
    if let Ok(dir) = std::env::var("EDR_EVAL_REPLAY_DIR") {
        write_root(Path::new(&dir));
    }

    let root = tempfile::tempdir().unwrap();
    write_root(root.path());

    run_locald(root.path());

    let fired = fired_playbooks(root.path());
    let missing: Vec<&str> = EXPECTED
        .iter()
        .copied()
        .filter(|id| !fired.contains(*id))
        .collect();
    assert!(
        missing.is_empty(),
        "missing {:?}, fired {:?}",
        missing,
        fired
    );

    // Every signal has an explanation with slots and evidence, as the script checks
    let db = Connection::open(root.path().join("workbench.db")).unwrap();
    let mut stmt = db
        .prepare(
            "SELECT s.signal_type, e.explanation_json FROM signals s \
             LEFT JOIN signal_explanations e ON e.signal_id = s.signal_id",
        )
        .unwrap();
    let rows: Vec<(String, Option<String>)> = stmt
        .query_map([], |r| Ok((r.get(0)?, r.get(1)?)))
        .unwrap()
        .map(|r| r.unwrap())
        .collect();
    for (t, json) in rows {
        let exp: serde_json::Value =
            serde_json::from_str(&json.unwrap_or_else(|| panic!("{} has no explanation", t)))
                .unwrap();
        assert!(
            !exp["slots"].as_array().unwrap().is_empty(),
            "{} has no slots",
            t
        );
        assert!(
            !exp["evidence"].as_array().unwrap().is_empty(),
            "{} has no evidence",
            t
        );
    }
}
