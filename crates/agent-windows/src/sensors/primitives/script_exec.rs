// windows/sensors/primitives/script_exec.rs
// Detects script/interpreter execution on Windows
// PowerShell, cmd, wscript, cscript, mshta, etc.

use edr_core::Event;
use edr_core::event_keys;
use std::collections::BTreeMap;
use serde_json::json;

/// Script interpreters to detect
const SCRIPT_INTERPRETERS: &[(&str, &str)] = &[
    ("powershell.exe", "powershell"),
    ("powershell_ise.exe", "powershell"),
    ("pwsh.exe", "powershell"),
    ("cmd.exe", "cmd"),
    ("wscript.exe", "wscript"),
    ("cscript.exe", "cscript"),
    ("mshta.exe", "mshta"),
    ("msbuild.exe", "msbuild"),
    ("regsvr32.exe", "regsvr32"),
    ("rundll32.exe", "rundll32"),
    ("certutil.exe", "certutil"),
    ("bitsadmin.exe", "bitsadmin"),
    ("wmic.exe", "wmic"),
    ("python.exe", "python"),
    ("python3.exe", "python"),
    ("perl.exe", "perl"),
    ("ruby.exe", "ruby"),
    ("node.exe", "node"),
];

/// LOLBins (Living Off the Land Binaries) on Windows
const LOLBINS: &[&str] = &[
    "certutil.exe",
    "bitsadmin.exe",
    "mshta.exe",
    "msbuild.exe",
    "regsvr32.exe",
    "rundll32.exe",
    "installutil.exe",
    "regasm.exe",
    "regsvcs.exe",
    "msconfig.exe",
    "dnscmd.exe",
    "odbcconf.exe",
    "pcalua.exe",
    "syncappvpublishingserver.exe",
    "forfiles.exe",
    "presentationhost.exe",
    "ieexec.exe",
    "bash.exe",
    "wsl.exe",
];

/// Suspicious PowerShell indicators
const SUSPICIOUS_PS_PATTERNS: &[&str] = &[
    "-encodedcommand",
    "-enc ",
    "-e ",
    "-ec ",
    "bypass",
    "-noprofile",
    "-nop ",
    "-windowstyle hidden",
    "-w hidden",
    "iex(",
    "invoke-expression",
    "downloadstring",
    "downloadfile",
    "webclient",
    "bitstransfer",
    "reflection.assembly",
    "frombase64string",
    "[convert]::frombase64",
    "invoke-mimikatz",
    "invoke-shellcode",
    "invoke-obfuscation",
    "amsibypass",
    "disable-realtimemonitoring",
];

/// Detect script execution from exec events
pub fn detect_script_exec(base_event: &Event) -> Option<Event> {
    let image = base_event.fields
        .get(event_keys::PROC_EXE)
        .or_else(|| base_event.fields.get("Image"))
        .and_then(|v| v.as_str())?;

    let image_lower = image.to_lowercase();
    let image_base = std::path::Path::new(&image_lower)
        .file_name()
        .and_then(|n| n.to_str())
        .unwrap_or("");

    // Check if exe matches script interpreter
    let (_, interpreter) = SCRIPT_INTERPRETERS.iter()
        .find(|(tool, _)| image_base == *tool)?;

    let cmd_line = base_event.fields
        .get(event_keys::PROC_ARGV)
        .or_else(|| base_event.fields.get("CommandLine"))
        .and_then(|v| v.as_str())
        .unwrap_or("");

    let cmd_line_lower = cmd_line.to_lowercase();

    // Determine if inline script or script file
    let (is_inline, script_path) = detect_script_mode(&cmd_line_lower, *interpreter);

    // Extract process info
    let pid = base_event.fields
        .get(event_keys::PROC_PID)
        .or_else(|| base_event.fields.get("ProcessId"))
        .and_then(|v| v.as_u64().or_else(|| v.as_str().and_then(|s| s.parse().ok())))
        .map(|v| v as u32)?;

    let user = base_event.fields
        .get(event_keys::PROC_UID)
        .or_else(|| base_event.fields.get("User"))
        .and_then(|v| v.as_str())
        .unwrap_or("unknown")
        .to_string();

    let mut fields = BTreeMap::new();
    fields.insert(event_keys::PROC_PID.to_string(), json!(pid));
    fields.insert(event_keys::PROC_UID.to_string(), json!(user.clone()));
    fields.insert(event_keys::PROC_EUID.to_string(), json!(user));
    fields.insert(event_keys::PROC_EXE.to_string(), json!(image));
    fields.insert(event_keys::SCRIPT_INTERPRETER.to_string(), json!(interpreter));
    fields.insert(event_keys::SCRIPT_INLINE.to_string(), json!(is_inline));

    if let Some(path) = script_path {
        fields.insert(event_keys::SCRIPT_PATH.to_string(), json!(path));
    }

    if !cmd_line.is_empty() {
        // Truncate command line to 2KB
        let cmd_truncated = if cmd_line.len() > 2048 {
            &cmd_line[..2048]
        } else {
            cmd_line
        };
        fields.insert(event_keys::PROC_ARGV.to_string(), json!(cmd_truncated));
    }

    // Add suspicion indicators for PowerShell
    if *interpreter == "powershell" {
        let suspicious = SUSPICIOUS_PS_PATTERNS.iter()
            .any(|p| cmd_line_lower.contains(p));
        if suspicious {
            fields.insert("suspicious".to_string(), json!(true));
        }
    }

    Some(Event {
        ts_ms: base_event.ts_ms,
        host: base_event.host.clone(),
        tags: vec!["windows".to_string(), "script_exec".to_string(), "sysmon".to_string()],
        proc_key: base_event.proc_key.clone(),
        file_key: None,
        identity_key: base_event.identity_key.clone(),
        evidence_ptr: None,
        fields,
    })
}

/// Detect LOLBin execution with suspicious arguments
pub fn detect_lolbin_exec(base_event: &Event) -> Option<Event> {
    let image = base_event.fields
        .get(event_keys::PROC_EXE)
        .or_else(|| base_event.fields.get("Image"))
        .and_then(|v| v.as_str())?;

    let image_lower = image.to_lowercase();
    let image_base = std::path::Path::new(&image_lower)
        .file_name()
        .and_then(|n| n.to_str())
        .unwrap_or("");

    // Check if exe is a LOLBin
    if !LOLBINS.iter().any(|l| image_base == *l) {
        return None;
    }

    let cmd_line = base_event.fields
        .get(event_keys::PROC_ARGV)
        .or_else(|| base_event.fields.get("CommandLine"))
        .and_then(|v| v.as_str())
        .unwrap_or("");

    let cmd_line_lower = cmd_line.to_lowercase();

    // Only flag suspicious LOLBin usage
    if !is_suspicious_lolbin(image_base, &cmd_line_lower) {
        return None;
    }

    let pid = base_event.fields
        .get(event_keys::PROC_PID)
        .or_else(|| base_event.fields.get("ProcessId"))
        .and_then(|v| v.as_u64().or_else(|| v.as_str().and_then(|s| s.parse().ok())))
        .map(|v| v as u32)?;

    let user = base_event.fields
        .get(event_keys::PROC_UID)
        .or_else(|| base_event.fields.get("User"))
        .and_then(|v| v.as_str())
        .unwrap_or("unknown")
        .to_string();

    let mut fields = BTreeMap::new();
    fields.insert(event_keys::PROC_PID.to_string(), json!(pid));
    fields.insert(event_keys::PROC_UID.to_string(), json!(user.clone()));
    fields.insert(event_keys::PROC_EUID.to_string(), json!(user));
    fields.insert(event_keys::PROC_EXE.to_string(), json!(image));
    fields.insert(event_keys::SCRIPT_INTERPRETER.to_string(), json!(format!("lolbin:{}", image_base)));
    fields.insert(event_keys::SCRIPT_INLINE.to_string(), json!(true));

    if !cmd_line.is_empty() {
        let cmd_truncated = if cmd_line.len() > 2048 {
            &cmd_line[..2048]
        } else {
            cmd_line
        };
        fields.insert(event_keys::PROC_ARGV.to_string(), json!(cmd_truncated));
    }

    Some(Event {
        ts_ms: base_event.ts_ms,
        host: base_event.host.clone(),
        tags: vec!["windows".to_string(), "script_exec".to_string(), "lolbin".to_string()],
        proc_key: base_event.proc_key.clone(),
        file_key: None,
        identity_key: base_event.identity_key.clone(),
        evidence_ptr: None,
        fields,
    })
}

fn detect_script_mode(cmd_line: &str, interpreter: &str) -> (bool, Option<String>) {
    let is_inline = match interpreter {
        "powershell" => {
            cmd_line.contains("-c ") || cmd_line.contains("-command ") ||
            cmd_line.contains("-enc") || cmd_line.contains("-e ") ||
            cmd_line.contains("iex") || cmd_line.contains("invoke-expression")
        }
        "cmd" => {
            cmd_line.contains("/c ") || cmd_line.contains("/k ")
        }
        "wscript" | "cscript" => {
            cmd_line.contains("//e:") || cmd_line.contains("//b")
        }
        "mshta" => {
            cmd_line.contains("javascript:") || cmd_line.contains("vbscript:") ||
            cmd_line.contains("about:")
        }
        "python" => {
            cmd_line.contains("-c ") || cmd_line.contains("-c\"")
        }
        _ => false,
    };

    // Try to extract script path
    let script_path = extract_script_path(cmd_line);

    (is_inline, script_path)
}

fn extract_script_path(cmd_line: &str) -> Option<String> {
    // Look for common script extensions
    let extensions = [".ps1", ".bat", ".cmd", ".vbs", ".js", ".wsf", ".hta", ".py", ".pl", ".rb"];
    
    for ext in extensions {
        if let Some(start) = cmd_line.find(ext) {
            // Find start of path (space before or after quotes)
            let before = &cmd_line[..start + ext.len()];
            // Look backwards for space or quote
            if let Some(path_start) = before.rfind(|c: char| c == ' ' || c == '"' || c == '\'') {
                let path = before[path_start + 1..].trim_matches(|c| c == '"' || c == '\'');
                if !path.is_empty() {
                    return Some(path.to_string());
                }
            }
        }
    }
    None
}

fn is_suspicious_lolbin(exe: &str, cmd_line: &str) -> bool {
    match exe {
        "certutil.exe" => {
            // Download, decode, encode operations
            cmd_line.contains("-urlcache") || cmd_line.contains("-decode") ||
            cmd_line.contains("-encode") || cmd_line.contains("split") ||
            cmd_line.contains("-f ") && (cmd_line.contains("http") || cmd_line.contains("ftp"))
        }
        "bitsadmin.exe" => {
            // Download operations
            cmd_line.contains("/transfer") || cmd_line.contains("/create") ||
            cmd_line.contains("/addfile") || cmd_line.contains("/setnotifycmdline")
        }
        "mshta.exe" => {
            // Script execution, especially remote
            cmd_line.contains("javascript:") || cmd_line.contains("vbscript:") ||
            cmd_line.contains("http") || cmd_line.contains("about:")
        }
        "msbuild.exe" => {
            // Inline task execution
            cmd_line.contains("<task") || cmd_line.contains(".csproj") ||
            cmd_line.contains(".xml") || cmd_line.contains("/p:")
        }
        "regsvr32.exe" => {
            // Remote/scrobj execution (squiblydoo)
            cmd_line.contains("/s") && cmd_line.contains("/n") ||
            cmd_line.contains("/i:http") || cmd_line.contains("scrobj.dll")
        }
        "rundll32.exe" => {
            // Suspicious DLL execution
            cmd_line.contains("javascript:") || cmd_line.contains("shell32.dll,control_rundll") ||
            cmd_line.contains("http") || cmd_line.contains("url.dll,fileprotocolhandler")
        }
        "installutil.exe" | "regasm.exe" | "regsvcs.exe" => {
            // Any execution is suspicious (often used for bypass)
            !cmd_line.contains(".net") && !cmd_line.contains("gac")
        }
        "forfiles.exe" => {
            // Command execution
            cmd_line.contains("/c ") && (cmd_line.contains("cmd") || cmd_line.contains("powershell"))
        }
        "bash.exe" | "wsl.exe" => {
            // WSL execution with commands
            cmd_line.contains("-c ") || cmd_line.contains("bash -i") ||
            cmd_line.contains("/bin/") || cmd_line.contains("nc ")
        }
        _ => false,
    }
}
