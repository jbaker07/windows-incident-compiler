// windows/sensors/primitives/auth_event.rs
// Detects authentication events on Windows
// Triggers on: Security Event IDs 4624, 4625, 4634, 4648, etc.

use edr_core::Event;
use edr_core::event_keys;
use std::collections::BTreeMap;
use serde_json::json;

/// Security Event IDs for authentication
const EVENT_LOGON_SUCCESS: &str = "4624";    // Successful logon
const EVENT_LOGON_FAILED: &str = "4625";     // Failed logon
const EVENT_LOGOFF: &str = "4634";           // Logoff
const EVENT_EXPLICIT_CREDS: &str = "4648";   // Logon with explicit credentials
const EVENT_KERBEROS_AUTH: &str = "4768";    // Kerberos TGT requested
const EVENT_KERBEROS_TICKET: &str = "4769";  // Kerberos service ticket requested
const EVENT_KERBEROS_FAIL: &str = "4771";    // Kerberos pre-auth failed
const EVENT_NTLM_AUTH: &str = "4776";        // NTLM credential validation
const EVENT_SPECIAL_LOGON: &str = "4672";    // Special privileges assigned
const EVENT_ACCOUNT_LOCKED: &str = "4740";   // Account locked out
const EVENT_RDP_CONNECT: &str = "4778";      // RDP session reconnected
const EVENT_RDP_DISCONNECT: &str = "4779";   // RDP session disconnected

/// Windows logon types
const LOGON_TYPE_INTERACTIVE: u32 = 2;
const LOGON_TYPE_NETWORK: u32 = 3;
const LOGON_TYPE_BATCH: u32 = 4;
const LOGON_TYPE_SERVICE: u32 = 5;
const LOGON_TYPE_UNLOCK: u32 = 7;
const LOGON_TYPE_NETWORK_CLEARTEXT: u32 = 8;
const LOGON_TYPE_NEW_CREDENTIALS: u32 = 9;
const LOGON_TYPE_REMOTE_INTERACTIVE: u32 = 10;  // RDP
const LOGON_TYPE_CACHED: u32 = 11;

/// Detect auth event from Windows Security Event Log
pub fn detect_auth_event(base_event: &Event) -> Option<Event> {
    // Get Event ID
    let event_id = base_event.fields
        .get("EventID")
        .or_else(|| base_event.fields.get("event_id"))
        .and_then(|v| v.as_str().map(|s| s.to_string()).or_else(|| v.as_u64().map(|n| n.to_string())))?;

    // Map Event ID to auth method and result
    let (auth_method, auth_result) = match event_id.as_str() {
        EVENT_LOGON_SUCCESS => (determine_auth_method(base_event), "success"),
        EVENT_LOGON_FAILED => (determine_auth_method(base_event), "failure"),
        EVENT_LOGOFF => ("logoff", "success"),
        EVENT_EXPLICIT_CREDS => ("explicit_credentials", "success"),
        EVENT_KERBEROS_AUTH => ("kerberos_tgt", "success"),
        EVENT_KERBEROS_TICKET => ("kerberos_service", "success"),
        EVENT_KERBEROS_FAIL => ("kerberos", "failure"),
        EVENT_NTLM_AUTH => {
            let status = base_event.fields.get("Status")
                .and_then(|v| v.as_str())
                .unwrap_or("0x0");
            let result = if status == "0x0" { "success" } else { "failure" };
            ("ntlm", result)
        }
        EVENT_SPECIAL_LOGON => ("special_privileges", "success"),
        EVENT_ACCOUNT_LOCKED => ("lockout", "failure"),
        EVENT_RDP_CONNECT => ("rdp", "success"),
        EVENT_RDP_DISCONNECT => ("rdp_disconnect", "success"),
        _ => return None,
    };

    // Extract user information
    let target_user = base_event.fields
        .get("TargetUserName")
        .or_else(|| base_event.fields.get("User"))
        .or_else(|| base_event.fields.get(event_keys::AUTH_USER))
        .and_then(|v| v.as_str())
        .unwrap_or("unknown");

    let target_domain = base_event.fields
        .get("TargetDomainName")
        .and_then(|v| v.as_str())
        .unwrap_or("");

    let full_user = if !target_domain.is_empty() {
        format!("{}\\{}", target_domain, target_user)
    } else {
        target_user.to_string()
    };

    // Extract source IP
    let src_ip = base_event.fields
        .get("IpAddress")
        .or_else(|| base_event.fields.get("SourceNetworkAddress"))
        .or_else(|| base_event.fields.get(event_keys::AUTH_SRC_IP))
        .and_then(|v| v.as_str())
        .filter(|s| !s.is_empty() && *s != "-" && *s != "::1" && *s != "127.0.0.1");

    // Extract source workstation
    let workstation = base_event.fields
        .get("WorkstationName")
        .or_else(|| base_event.fields.get("SourceWorkstation"))
        .and_then(|v| v.as_str());

    // Get logon type if available
    let logon_type = base_event.fields
        .get("LogonType")
        .and_then(|v| v.as_u64().or_else(|| v.as_str().and_then(|s| s.parse().ok())))
        .map(|v| v as u32);

    // Get process info if available
    let pid = base_event.fields
        .get(event_keys::PROC_PID)
        .or_else(|| base_event.fields.get("ProcessId"))
        .and_then(|v| v.as_u64())
        .map(|v| v as u32);

    let process_name = base_event.fields
        .get("ProcessName")
        .or_else(|| base_event.fields.get(event_keys::PROC_EXE))
        .and_then(|v| v.as_str());

    // Build fields
    let mut fields = BTreeMap::new();
    fields.insert(event_keys::AUTH_USER.to_string(), json!(full_user));
    fields.insert(event_keys::AUTH_METHOD.to_string(), json!(auth_method));
    fields.insert(event_keys::AUTH_RESULT.to_string(), json!(auth_result));

    if let Some(ip) = src_ip {
        fields.insert(event_keys::AUTH_SRC_IP.to_string(), json!(ip));
    }

    if let Some(ws) = workstation {
        fields.insert("workstation".to_string(), json!(ws));
    }

    if let Some(lt) = logon_type {
        fields.insert("logon_type".to_string(), json!(lt));
        fields.insert("logon_type_name".to_string(), json!(logon_type_name(lt)));
    }

    if let Some(p) = pid {
        fields.insert(event_keys::PROC_PID.to_string(), json!(p));
    }

    if let Some(pn) = process_name {
        fields.insert(event_keys::PROC_EXE.to_string(), json!(pn));
    }

    // For failed logons, include failure reason
    if auth_result == "failure" {
        if let Some(status) = base_event.fields.get("Status").and_then(|v| v.as_str()) {
            fields.insert("failure_status".to_string(), json!(status));
            fields.insert("failure_reason".to_string(), json!(failure_status_to_reason(status)));
        }
        if let Some(sub_status) = base_event.fields.get("SubStatus").and_then(|v| v.as_str()) {
            fields.insert("failure_sub_status".to_string(), json!(sub_status));
        }
    }

    Some(Event {
        ts_ms: base_event.ts_ms,
        host: base_event.host.clone(),
        tags: vec![
            "windows".to_string(),
            "auth_event".to_string(),
            "security".to_string(),
        ],
        proc_key: base_event.proc_key.clone(),
        file_key: None,
        identity_key: base_event.identity_key.clone(),
        evidence_ptr: None,
        fields,
    })
}

/// Detect auth event from explicit credential usage (runas, psexec, etc.)
pub fn detect_auth_event_from_exec(base_event: &Event) -> Option<Event> {
    let image = base_event.fields
        .get(event_keys::PROC_EXE)
        .or_else(|| base_event.fields.get("Image"))
        .and_then(|v| v.as_str())?;

    let image_lower = image.to_lowercase();
    let image_base = std::path::Path::new(&image_lower)
        .file_name()?
        .to_str()?;

    let cmd_line = base_event.fields
        .get(event_keys::PROC_ARGV)
        .or_else(|| base_event.fields.get("CommandLine"))
        .and_then(|v| v.as_str())
        .map(|s| s.to_lowercase())
        .unwrap_or_default();

    // Check for credential-related tools
    let (auth_method, target_user) = match image_base {
        "runas.exe" => {
            let target = extract_runas_user(&cmd_line);
            ("runas", target)
        }
        "psexec.exe" | "psexec64.exe" => {
            let target = extract_psexec_user(&cmd_line);
            ("psexec", target)
        }
        "net.exe" => {
            if cmd_line.contains("use") && cmd_line.contains("/user:") {
                let target = extract_net_use_user(&cmd_line);
                ("net_use", target)
            } else {
                return None;
            }
        }
        "cmdkey.exe" => {
            if cmd_line.contains("/add") {
                ("credential_manager", "system".to_string())
            } else {
                return None;
            }
        }
        "wmic.exe" => {
            if cmd_line.contains("/user:") {
                let target = extract_wmic_user(&cmd_line);
                ("wmic", target)
            } else {
                return None;
            }
        }
        _ => return None,
    };

    let pid = base_event.fields
        .get(event_keys::PROC_PID)
        .or_else(|| base_event.fields.get("ProcessId"))
        .and_then(|v| v.as_u64())
        .map(|v| v as u32)?;

    let uid = base_event.fields
        .get(event_keys::PROC_UID)
        .or_else(|| base_event.fields.get("User"))
        .and_then(|v| v.as_str())
        .unwrap_or("unknown")
        .to_string();

    let mut fields = BTreeMap::new();
    fields.insert(event_keys::PROC_PID.to_string(), json!(pid));
    fields.insert(event_keys::PROC_UID.to_string(), json!(uid.clone()));
    fields.insert(event_keys::PROC_EUID.to_string(), json!(uid));
    fields.insert(event_keys::PROC_EXE.to_string(), json!(image));
    fields.insert(event_keys::AUTH_USER.to_string(), json!(target_user));
    fields.insert(event_keys::AUTH_METHOD.to_string(), json!(auth_method));
    fields.insert(event_keys::AUTH_RESULT.to_string(), json!("unknown")); // Can't determine from exec alone
    fields.insert(event_keys::PROC_ARGV.to_string(), json!(cmd_line));

    Some(Event {
        ts_ms: base_event.ts_ms,
        host: base_event.host.clone(),
        tags: vec![
            "windows".to_string(),
            "auth_event".to_string(),
            "exec".to_string(),
        ],
        proc_key: base_event.proc_key.clone(),
        file_key: None,
        identity_key: base_event.identity_key.clone(),
        evidence_ptr: None,
        fields,
    })
}

/// Determine auth method from logon type
fn determine_auth_method(base_event: &Event) -> &'static str {
    let logon_type = base_event.fields
        .get("LogonType")
        .and_then(|v| v.as_u64().or_else(|| v.as_str().and_then(|s| s.parse().ok())))
        .map(|v| v as u32);

    match logon_type {
        Some(LOGON_TYPE_INTERACTIVE) => "interactive",
        Some(LOGON_TYPE_NETWORK) => "network",
        Some(LOGON_TYPE_BATCH) => "batch",
        Some(LOGON_TYPE_SERVICE) => "service",
        Some(LOGON_TYPE_UNLOCK) => "unlock",
        Some(LOGON_TYPE_NETWORK_CLEARTEXT) => "network_cleartext",
        Some(LOGON_TYPE_NEW_CREDENTIALS) => "new_credentials",
        Some(LOGON_TYPE_REMOTE_INTERACTIVE) => "rdp",
        Some(LOGON_TYPE_CACHED) => "cached",
        _ => "unknown",
    }
}

/// Convert logon type to human-readable name
fn logon_type_name(lt: u32) -> &'static str {
    match lt {
        LOGON_TYPE_INTERACTIVE => "Interactive",
        LOGON_TYPE_NETWORK => "Network",
        LOGON_TYPE_BATCH => "Batch",
        LOGON_TYPE_SERVICE => "Service",
        LOGON_TYPE_UNLOCK => "Unlock",
        LOGON_TYPE_NETWORK_CLEARTEXT => "NetworkCleartext",
        LOGON_TYPE_NEW_CREDENTIALS => "NewCredentials",
        LOGON_TYPE_REMOTE_INTERACTIVE => "RemoteInteractive (RDP)",
        LOGON_TYPE_CACHED => "CachedInteractive",
        _ => "Unknown",
    }
}

/// Convert failure status to reason
fn failure_status_to_reason(status: &str) -> &'static str {
    match status {
        "0xC000006D" => "bad_username_or_password",
        "0xC000006E" => "account_restriction",
        "0xC000006F" => "invalid_logon_hours",
        "0xC0000070" => "invalid_workstation",
        "0xC0000071" => "password_expired",
        "0xC0000072" => "account_disabled",
        "0xC00000DC" => "invalid_server_state",
        "0xC0000133" => "clocks_out_of_sync",
        "0xC0000224" => "password_must_change",
        "0xC0000234" => "account_locked",
        _ => "unknown",
    }
}

/// Extract user from runas command
fn extract_runas_user(cmd: &str) -> String {
    // runas /user:DOMAIN\user command
    if let Some(idx) = cmd.find("/user:") {
        let after = &cmd[idx + 6..];
        let user_end = after.find(' ').unwrap_or(after.len());
        return after[..user_end].to_string();
    }
    "unknown".to_string()
}

/// Extract user from psexec command
fn extract_psexec_user(cmd: &str) -> String {
    // psexec \\host -u user -p pass command
    if let Some(idx) = cmd.find("-u ") {
        let after = &cmd[idx + 3..];
        let user_end = after.find(' ').unwrap_or(after.len());
        return after[..user_end].to_string();
    }
    "unknown".to_string()
}

/// Extract user from net use command
fn extract_net_use_user(cmd: &str) -> String {
    // net use \\host /user:domain\user password
    if let Some(idx) = cmd.find("/user:") {
        let after = &cmd[idx + 6..];
        let user_end = after.find(' ').unwrap_or(after.len());
        return after[..user_end].to_string();
    }
    "unknown".to_string()
}

/// Extract user from wmic command
fn extract_wmic_user(cmd: &str) -> String {
    // wmic /node:host /user:user /password:pass process call create
    if let Some(idx) = cmd.find("/user:") {
        let after = &cmd[idx + 6..];
        let user_end = after.find(' ').unwrap_or(after.len());
        return after[..user_end].to_string();
    }
    "unknown".to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_base_event(tags: Vec<&str>, fields: Vec<(&str, serde_json::Value)>) -> Event {
        let mut f = BTreeMap::new();
        for (k, v) in fields {
            f.insert(k.to_string(), v);
        }
        Event {
            ts_ms: 1000000,
            host: "testhost".to_string(),
            tags: tags.into_iter().map(|s| s.to_string()).collect(),
            proc_key: Some("proc_test".to_string()),
            file_key: None,
            identity_key: Some("id_test".to_string()),
            evidence_ptr: None,
            fields: f,
        }
    }

    #[test]
    fn test_detect_logon_success() {
        let event = make_base_event(
            vec!["security"],
            vec![
                ("EventID", json!("4624")),
                ("TargetUserName", json!("admin")),
                ("TargetDomainName", json!("CORP")),
                ("IpAddress", json!("192.168.1.100")),
                ("LogonType", json!(10)),
            ],
        );

        let result = detect_auth_event(&event);
        assert!(result.is_some());
        let e = result.unwrap();
        assert!(e.tags.contains(&"auth_event".to_string()));
        assert_eq!(e.fields.get("auth_user").unwrap(), "CORP\\admin");
        assert_eq!(e.fields.get("auth_method").unwrap(), "rdp");
        assert_eq!(e.fields.get("auth_result").unwrap(), "success");
        assert_eq!(e.fields.get("auth_src_ip").unwrap(), "192.168.1.100");
    }

    #[test]
    fn test_detect_logon_failed() {
        let event = make_base_event(
            vec!["security"],
            vec![
                ("EventID", json!("4625")),
                ("TargetUserName", json!("user")),
                ("TargetDomainName", json!("CORP")),
                ("IpAddress", json!("10.0.0.50")),
                ("LogonType", json!(3)),
                ("Status", json!("0xC000006D")),
            ],
        );

        let result = detect_auth_event(&event);
        assert!(result.is_some());
        let e = result.unwrap();
        assert_eq!(e.fields.get("auth_result").unwrap(), "failure");
        assert_eq!(e.fields.get("failure_reason").unwrap(), "bad_username_or_password");
    }

    #[test]
    fn test_detect_runas() {
        let event = make_base_event(
            vec!["sysmon_process", "exec"],
            vec![
                (event_keys::PROC_PID, json!(1234)),
                (event_keys::PROC_EXE, json!("C:\\Windows\\System32\\runas.exe")),
                (event_keys::PROC_ARGV, json!("runas /user:admin cmd.exe")),
                (event_keys::PROC_UID, json!("user")),
            ],
        );

        let result = detect_auth_event_from_exec(&event);
        assert!(result.is_some());
        let e = result.unwrap();
        assert_eq!(e.fields.get("auth_method").unwrap(), "runas");
        assert_eq!(e.fields.get("auth_user").unwrap(), "admin");
    }

    #[test]
    fn test_detect_psexec() {
        let event = make_base_event(
            vec!["sysmon_process", "exec"],
            vec![
                (event_keys::PROC_PID, json!(1234)),
                (event_keys::PROC_EXE, json!("C:\\tools\\psexec.exe")),
                (event_keys::PROC_ARGV, json!("psexec \\\\server -u domain\\admin cmd")),
                (event_keys::PROC_UID, json!("user")),
            ],
        );

        let result = detect_auth_event_from_exec(&event);
        assert!(result.is_some());
        let e = result.unwrap();
        assert_eq!(e.fields.get("auth_method").unwrap(), "psexec");
    }

    #[test]
    fn test_logon_type_mapping() {
        assert_eq!(logon_type_name(2), "Interactive");
        assert_eq!(logon_type_name(3), "Network");
        assert_eq!(logon_type_name(10), "RemoteInteractive (RDP)");
    }

    #[test]
    fn test_no_detection_non_auth_event() {
        let event = make_base_event(
            vec!["security"],
            vec![
                ("EventID", json!("1234")), // Not an auth event
            ],
        );

        let result = detect_auth_event(&event);
        assert!(result.is_none());
    }
}
