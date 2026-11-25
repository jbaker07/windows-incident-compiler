//! One import of `testdata/import_formats/`, which holds a file per format the
//! README lists, written the way each tool writes it. The test checks that the
//! importer classifies each file, parses it with the right adapter, and writes
//! the expected events (types, key fields, timestamps) to events.json, and that
//! the manifest summary matches.

use edr_desktop_lib::{ImportLimits, SafeImporter};
use serde_json::Value;
use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::PathBuf;

fn fixtures_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .unwrap()
        .join("testdata")
        .join("import_formats")
}

struct Imported {
    manifest: Value,
    events: Vec<Value>,
}

impl Imported {
    fn file(&self, rel_path: &str) -> &Value {
        self.manifest["files"]
            .as_array()
            .unwrap()
            .iter()
            .find(|f| f["rel_path"] == rel_path)
            .unwrap_or_else(|| panic!("{} not in the manifest", rel_path))
    }

    fn events_of(&self, rel_path: &str) -> Vec<&Value> {
        self.events
            .iter()
            .filter(|e| e["source_file"] == rel_path)
            .collect()
    }

    /// Event type counts for one file
    fn types(&self, rel_path: &str) -> BTreeMap<String, usize> {
        let mut out = BTreeMap::new();
        for e in self.events_of(rel_path) {
            *out.entry(e["event_type"].as_str().unwrap().to_string())
                .or_insert(0) += 1;
        }
        out
    }

    /// The first event of a type in one file
    fn first(&self, rel_path: &str, event_type: &str) -> &Value {
        self.events_of(rel_path)
            .into_iter()
            .find(|e| e["event_type"] == event_type)
            .unwrap_or_else(|| panic!("no {} event from {}", event_type, rel_path))
    }
}

fn import_fixtures(name: &str) -> (Imported, PathBuf) {
    let out = std::env::temp_dir().join(format!("import_formats_{}_{}", name, std::process::id()));
    let _ = fs::remove_dir_all(&out);
    fs::create_dir_all(&out).unwrap();
    let importer = SafeImporter::new(
        "formats".to_string(),
        out.clone(),
        Some(ImportLimits::default()),
    );
    let result = importer
        .import(fixtures_dir().to_str().unwrap())
        .expect("import");
    let manifest_path = PathBuf::from(&result.manifest_path);
    let manifest: Value =
        serde_json::from_str(&fs::read_to_string(&manifest_path).unwrap()).unwrap();
    let events_path = manifest_path.parent().unwrap().join("events.json");
    let events: Vec<Value> =
        serde_json::from_str(&fs::read_to_string(events_path).unwrap()).unwrap();
    (Imported { manifest, events }, out)
}

fn types(pairs: &[(&str, usize)]) -> BTreeMap<String, usize> {
    pairs.iter().map(|(t, n)| (t.to_string(), *n)).collect()
}

/// File, kind, parser (None when stored only), event types and counts
type Expectation = (
    &'static str,
    &'static str,
    Option<&'static str>,
    BTreeMap<String, usize>,
);

/// What every fixture must produce
fn expected() -> Vec<Expectation> {
    vec![
        (
            "conn.log",
            "zeek_conn",
            Some("zeek"),
            types(&[("netflow", 2)]),
        ),
        (
            "dns.log",
            "zeek_dns",
            Some("zeek"),
            types(&[("dns_query", 1)]),
        ),
        (
            "http.log",
            "zeek_http",
            Some("zeek"),
            types(&[("http_txn", 1)]),
        ),
        (
            "ssl.log",
            "zeek_ssl",
            Some("zeek"),
            types(&[("tls_handshake", 1)]),
        ),
        (
            "eve.json",
            "suricata_eve",
            Some("suricata"),
            types(&[
                ("net_alert", 1),
                ("dns_query", 1),
                ("http_txn", 1),
                ("tls_handshake", 1),
                ("netflow", 1),
            ]),
        ),
        (
            "nmap_scan.xml",
            "nmap_xml",
            Some("nmap"),
            types(&[
                ("host_discovered", 1),
                ("port_discovered", 3),
                ("nmap_script", 2),
            ]),
        ),
        (
            "burp_export.har",
            "har",
            Some("har"),
            types(&[("http_request", 2)]),
        ),
        (
            "osquery_results.json",
            "osquery",
            Some("osquery"),
            types(&[
                ("process_info", 1),
                ("listening_port", 1),
                ("user_info", 1),
                ("file_event", 1),
            ]),
        ),
        (
            "velociraptor_Windows.System.Pslist.json",
            "velociraptor",
            Some("velociraptor"),
            types(&[("process_info", 2)]),
        ),
        (
            "security_evtx.json",
            "evtx_json",
            Some("evtx_json"),
            types(&[
                ("process_create", 1),
                ("logon_failure", 1),
                ("service_installed", 1),
            ]),
        ),
        (
            "zap_report.json",
            "zap_json",
            Some("zap"),
            types(&[("web_vulnerability", 2)]),
        ),
        (
            "yara_scan.txt",
            "yara_text",
            Some("yara"),
            types(&[("yara_match", 2)]),
        ),
        (
            "yara_results.json",
            "yara_json",
            Some("yara"),
            types(&[("yara_match", 1)]),
        ),
        (
            "Invoke-AtomicTest-ExecutionLog.csv",
            "atomic_output",
            Some("atomic"),
            types(&[("technique_executed", 2)]),
        ),
        (
            ".bash_history",
            "shell_history",
            Some("plaintext"),
            types(&[("shell_command", 5)]),
        ),
        (
            ".zsh_history",
            "shell_history",
            Some("plaintext"),
            types(&[("shell_command", 2)]),
        ),
        (
            "PowerShell_transcript.WS01.abc123.20240101000050.txt",
            "ps_transcript",
            Some("plaintext"),
            types(&[("powershell_command", 3)]),
        ),
        (
            "gobuster_dir.txt",
            "gobuster",
            Some("plaintext"),
            types(&[("directory_found", 3)]),
        ),
        (
            "ffuf_results.json",
            "ffuf",
            Some("plaintext"),
            types(&[("fuzz_result", 2)]),
        ),
        (
            "siem_export.jsonl",
            "jsonl",
            Some("jsonl"),
            types(&[("process_start", 1), ("network_connection", 1)]),
        ),
        (
            "burp_proxy_history.xml",
            "burp_xml",
            Some("burp"),
            types(&[("http_request", 2)]),
        ),
        (
            "burp_scan_issues.xml",
            "burp_xml",
            Some("burp"),
            types(&[("web_vulnerability", 2)]),
        ),
        (
            "alerts_export.yaml",
            "yaml",
            Some("yaml"),
            types(&[("login_failure", 1), ("login_success", 1), ("generic", 1)]),
        ),
        (
            "firewall_export.csv",
            "csv",
            Some("csv"),
            types(&[("network_connection", 2)]),
        ),
        ("capture.pcap", "pcap", None, types(&[])),
    ]
}

#[test]
fn every_claimed_format_is_classified_and_parsed() {
    let (imp, out) = import_fixtures("all");

    let listed: BTreeSet<String> = imp.manifest["files"]
        .as_array()
        .unwrap()
        .iter()
        .map(|f| f["rel_path"].as_str().unwrap().to_string())
        .collect();
    let covered: BTreeSet<String> = expected().iter().map(|(f, ..)| f.to_string()).collect();
    assert_eq!(listed, covered, "every fixture is checked");

    let mut total = 0;
    for (rel_path, kind, parser, want) in expected() {
        let f = imp.file(rel_path);
        assert_eq!(f["kind"], kind, "{} kind", rel_path);
        assert_eq!(f["parsed"], parser.is_some(), "{} parsed: {}", rel_path, f);
        assert_eq!(f["parser"].as_str(), parser, "{} parser", rel_path);
        assert_eq!(imp.types(rel_path), want, "{} event types", rel_path);
        let n: usize = want.values().sum();
        if parser.is_some() {
            assert_eq!(
                f["events_extracted"], n as u64,
                "{} count in manifest",
                rel_path
            );
            assert!(
                f["warnings"].as_array().unwrap().is_empty(),
                "{} warnings: {}",
                rel_path,
                f["warnings"]
            );
        }
        for e in imp.events_of(rel_path) {
            assert_eq!(e["evidence_ptr"]["rel_path"], rel_path);
            assert_eq!(e["evidence_ptr"]["bundle_id"], imp.manifest["bundle_id"]);
        }
        total += n;
    }

    let summary = &imp.manifest["summary"];
    assert_eq!(summary["total_files"], 25);
    assert_eq!(summary["parsed_files"], 24);
    assert_eq!(summary["events_extracted"], total as u64);
    assert_eq!(imp.events.len(), total);

    let _ = fs::remove_dir_all(out);
}

#[test]
fn network_formats_keep_endpoints_and_times() {
    let (imp, out) = import_fixtures("network");

    // Zeek and Suricata describe the same traffic with the same names
    let conn = imp.first("conn.log", "netflow");
    assert_eq!(conn["fields"]["src_ip"], "10.0.0.5");
    assert_eq!(conn["fields"]["dest_ip"], "93.184.216.34");
    assert_eq!(conn["fields"]["dest_port"], 443);
    // Zeek writes epoch seconds as a float, so compare to the millisecond
    assert!(conn["timestamp"]
        .as_str()
        .unwrap()
        .starts_with("2024-01-01T00:00:00.123"));
    assert_eq!(conn["timestamp_quality"], "precise");
    assert_eq!(
        imp.first("dns.log", "dns_query")["fields"]["query"],
        "evil-c2.example"
    );
    assert_eq!(
        imp.first("http.log", "http_txn")["fields"]["uri"],
        "/payload.ps1"
    );
    assert_eq!(
        imp.first("ssl.log", "tls_handshake")["fields"]["server_name"],
        "www.example.com"
    );

    let alert = imp.first("eve.json", "net_alert");
    assert_eq!(
        alert["fields"]["signature"],
        "ET POLICY PowerShell User-Agent Outbound"
    );
    assert_eq!(alert["fields"]["dest_ip"], "198.51.100.7");
    // "+0000" offsets parse, so the time is the event's and not the import's
    assert_eq!(alert["timestamp"], "2024-01-01T00:00:02.000123Z");
    assert_eq!(alert["timestamp_quality"], "precise");
    assert_eq!(
        imp.first("eve.json", "dns_query")["fields"]["query"],
        "evil-c2.example"
    );
    assert_eq!(
        imp.first("eve.json", "tls_handshake")["fields"]["sni"],
        "www.example.com"
    );

    let port = imp
        .events_of("nmap_scan.xml")
        .into_iter()
        .find(|e| e["event_type"] == "port_discovered" && e["fields"]["port"] == 22)
        .expect("port 22");
    assert_eq!(port["fields"]["service"], "ssh");
    let script = imp
        .events_of("nmap_scan.xml")
        .into_iter()
        .find(|e| e["fields"]["script_id"] == "ssh-hostkey")
        .expect("ssh-hostkey script");
    // &#xa; in the XML attribute is decoded to a newline
    assert_eq!(script["fields"]["output"], "\n  256 aa:bb:cc:dd (ECDSA)\n");

    let login = imp
        .events_of("burp_export.har")
        .into_iter()
        .find(|e| e["fields"]["method"] == "POST")
        .expect("POST entry");
    assert_eq!(login["fields"]["status"], 302);
    assert_eq!(login["fields"]["server_ip"], "203.0.113.10");
    assert_eq!(login["timestamp"], "2024-01-01T00:00:05Z");

    let _ = fs::remove_dir_all(out);
}

#[test]
fn endpoint_formats_name_processes_accounts_and_services() {
    let (imp, out) = import_fixtures("endpoint");

    // osquery daemon log: one JSON object per line, the row under "columns"
    let proc = imp.first("osquery_results.json", "process_info");
    assert_eq!(
        proc["fields"]["command_line"],
        "powershell.exe -nop -w hidden -enc SQBFAFgA"
    );
    assert_eq!(proc["fields"]["host"], "WS01");
    assert_eq!(proc["timestamp"], "2024-01-01T00:00:10Z");
    let port = imp.first("osquery_results.json", "listening_port");
    assert_eq!(port["fields"]["port"], "4444");
    assert_eq!(port["fields"]["protocol"], "tcp");
    assert_eq!(
        imp.first("osquery_results.json", "user_info")["fields"]["username"],
        "backdoor"
    );
    assert_eq!(
        imp.first("osquery_results.json", "file_event")["fields"]["file_path"],
        "C:\\Users\\Public\\payload.dll"
    );

    // Velociraptor collection named after its artifact
    let ps = imp.first("velociraptor_Windows.System.Pslist.json", "process_info");
    assert_eq!(ps["fields"]["artifact"], "Windows.System.Pslist");
    assert_eq!(ps["timestamp_quality"], "precise");

    // evtx_dump JSON: provider and time sit under "#attributes"
    let created = imp.first("security_evtx.json", "process_create");
    assert_eq!(
        created["fields"]["provider"],
        "Microsoft-Windows-Security-Auditing"
    );
    assert_eq!(
        created["fields"]["CommandLine"],
        "powershell.exe -nop -w hidden -enc SQBFAFgA"
    );
    assert_eq!(created["timestamp"], "2024-01-01T00:00:09.123456Z");
    assert_eq!(
        imp.first("security_evtx.json", "logon_failure")["fields"]["IpAddress"],
        "203.0.113.50"
    );
    let svc = imp.first("security_evtx.json", "service_installed");
    assert_eq!(svc["fields"]["ImagePath"], "C:\\Users\\Public\\evil.exe");
    assert_eq!(svc["fields"]["channel"], "System");

    // Generic JSON lines: nested fields flattened, entities named once
    let start = imp.first("siem_export.jsonl", "process_start");
    assert_eq!(
        start["fields"]["process.command_line"],
        "rundll32.exe C:\\Users\\Public\\payload.dll,Start"
    );
    assert_eq!(start["fields"]["process_name"], "rundll32.exe");
    assert_eq!(start["fields"]["user_name"], "alice");
    assert_eq!(
        imp.first("siem_export.jsonl", "network_connection")["fields"]["dest_ip"],
        "198.51.100.7"
    );

    let _ = fs::remove_dir_all(out);
}

#[test]
fn scanner_and_red_team_formats() {
    let (imp, out) = import_fixtures("scanners");

    let sqli = imp
        .events_of("zap_report.json")
        .into_iter()
        .find(|e| e["fields"]["alert_name"] == "SQL Injection")
        .expect("SQL injection alert");
    assert_eq!(sqli["fields"]["risk_level"], "High");
    assert_eq!(sqli["fields"]["cwe_id"], "CWE-89");
    // The report time, marked as an estimate
    assert_eq!(sqli["timestamp"], "2024-01-01T00:00:20Z");
    assert_eq!(sqli["timestamp_quality"], "estimated");

    // yara -s: the string lines belong to the match above them
    let mimikatz = imp
        .events_of("yara_scan.txt")
        .into_iter()
        .find(|e| e["fields"]["rule"] == "Mimikatz_Strings")
        .expect("Mimikatz match");
    assert_eq!(
        mimikatz["fields"]["matched_strings"]
            .as_array()
            .unwrap()
            .len(),
        2
    );
    assert_eq!(
        mimikatz["fields"]["target_file"],
        "C:\\Users\\Public\\payload.dll"
    );
    assert_eq!(
        imp.first("yara_results.json", "yara_match")["fields"]["rule"],
        "Mimikatz_Strings"
    );

    // Invoke-AtomicTest CSV log, techniques named as in ATT&CK v20.1
    let atomic = imp.events_of("Invoke-AtomicTest-ExecutionLog.csv");
    let lsass = atomic
        .iter()
        .find(|e| e["fields"]["technique_id"] == "T1003.001")
        .expect("T1003.001 run");
    assert_eq!(
        lsass["fields"]["technique_name"],
        "OS Credential Dumping: LSASS Memory"
    );
    assert_eq!(
        lsass["fields"]["tactics"],
        serde_json::json!(["Credential Access"])
    );
    assert_eq!(lsass["fields"]["success"], true);
    assert_eq!(lsass["timestamp"], "2024-01-01T00:00:40Z");

    let found = imp
        .events_of("gobuster_dir.txt")
        .into_iter()
        .find(|e| e["fields"]["path"] == "/admin")
        .expect("/admin");
    assert_eq!(found["fields"]["status_code"], 301);
    let fuzz = imp.first("ffuf_results.json", "fuzz_result");
    assert_eq!(fuzz["timestamp"], "2024-01-01T00:01:00Z");
    assert_eq!(fuzz["timestamp_quality"], "estimated");

    // Shell history: bash has no times, zsh extended history does
    let bash = imp.events_of(".bash_history");
    assert_eq!(bash[0]["fields"]["command"], "whoami");
    assert!(bash.iter().all(|e| e["timestamp_quality"] == "unknown"));
    let zsh = imp.first(".zsh_history", "shell_command");
    assert_eq!(zsh["fields"]["command"], "sudo -l");
    assert_eq!(zsh["timestamp"], "2024-01-01T00:00:50Z");

    let ps = imp.first(
        "PowerShell_transcript.WS01.abc123.20240101000050.txt",
        "powershell_command",
    );
    assert_eq!(ps["fields"]["command"], "whoami /priv");
    assert_eq!(ps["fields"]["hostname"], "WS01");
    assert_eq!(ps["fields"]["username"], "CORP\\alice");

    let _ = fs::remove_dir_all(out);
}

#[test]
fn burp_yaml_and_csv_exports() {
    let (imp, out) = import_fixtures("structured");

    // Burp "Save items": one request per item, bodies stay in the file
    let login = imp
        .events_of("burp_proxy_history.xml")
        .into_iter()
        .find(|e| e["fields"]["method"] == "POST")
        .expect("POST item");
    assert_eq!(login["fields"]["url"], "https://app.example.com/login");
    assert_eq!(login["fields"]["status"], 302);
    assert_eq!(login["fields"]["server_ip"], "203.0.113.10");
    assert_eq!(login["fields"]["comment"], "login bypass test");
    assert_eq!(login["timestamp"], "2024-01-01T00:00:05Z");
    assert_eq!(login["timestamp_quality"], "precise");
    assert_eq!(login["evidence_ptr"]["json_path"], "/items/item[1]");

    // Burp scanner issues, named like ZAP findings
    let sqli = imp
        .events_of("burp_scan_issues.xml")
        .into_iter()
        .find(|e| e["fields"]["alert_name"] == "SQL injection")
        .expect("SQL injection issue");
    assert_eq!(sqli["fields"]["risk_level"], "High");
    assert_eq!(sqli["fields"]["location"], "/login [pass parameter]");
    assert_eq!(sqli["fields"]["cwe_id"], "CWE-89");
    assert_eq!(
        sqli["fields"]["cwe_ids"],
        serde_json::json!(["CWE-89", "CWE-94"])
    );
    assert_eq!(sqli["timestamp"], "2024-01-01T00:01:00Z");
    assert_eq!(sqli["timestamp_quality"], "estimated");

    // YAML: list items and a second document, nested fields flattened
    let failure = imp.first("alerts_export.yaml", "login_failure");
    assert_eq!(failure["fields"]["user.name"], "admin");
    assert_eq!(failure["fields"]["src_ip"], "203.0.113.50");
    assert_eq!(failure["fields"]["hostname"], "vpn-gw-01");
    assert_eq!(failure["timestamp"], "2024-01-01T00:03:00Z");
    assert_eq!(failure["evidence_ptr"]["json_path"], "doc[0][0]");
    let pod = imp.first("alerts_export.yaml", "generic");
    assert_eq!(pod["fields"]["kind"], "Pod");
    assert_eq!(pod["fields"]["metadata.name"], "miner");
    assert_eq!(pod["evidence_ptr"]["json_path"], "doc[1]");

    // CSV: header names become fields, numbers stay numbers
    let deny = imp
        .events_of("firewall_export.csv")
        .into_iter()
        .find(|e| e["fields"]["Action"] == "deny")
        .expect("deny row");
    assert_eq!(deny["fields"]["dest_port"], 3389);
    assert_eq!(deny["fields"]["src_ip"], "203.0.113.50");
    assert_eq!(deny["timestamp"], "2024-01-01T00:04:00Z");
    assert_eq!(deny["source_line"], 2);

    let _ = fs::remove_dir_all(out);
}
