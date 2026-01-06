// workbench/api.rs
// REST API endpoints for the workbench UI

use super::document::*;
use super::export::*;
use serde::{Deserialize, Serialize};

// ============================================================================
// API Request/Response Types
// ============================================================================

#[derive(Debug, Serialize, Deserialize)]
pub struct CreateDocumentRequest {
    pub title: String,
    pub author: Option<String>,
    pub tags: Option<Vec<String>>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct UpdateSectionRequest {
    pub section: String, // "summary", "impact", "technique", etc.
    pub content: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct UpdateTechniqueRequest {
    pub technique_id: Option<String>,
    pub technique_name: Option<String>,
    pub tactic: Option<String>,
    pub confidence: Option<String>,
    pub notes: Option<String>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct AddTimelineEntryRequest {
    pub timestamp: u64,
    pub title: String,
    pub description: Option<String>,
    pub event_type: String,
    pub evidence_ptr: Option<EvidencePointer>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct UpdateTimelineEntryRequest {
    pub title: Option<String>,
    pub description: Option<String>,
    pub included: Option<bool>,
    pub starred: Option<bool>,
    pub annotation: Option<String>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct SelectEventRequest {
    pub event_id: String,
    pub selected: bool,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct StarEventRequest {
    pub event_id: String,
    pub starred: bool,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct AnnotateEventRequest {
    pub event_id: String,
    pub annotation: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct AddCustomSectionRequest {
    pub heading: String,
    pub content: Option<String>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct SessionControlRequest {
    pub action: SessionAction,
    pub note: Option<String>,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub enum SessionAction {
    Start,
    Stop,
    Pause,
    Resume,
    MarkImportant,
    MarkPhaseStart,
    MarkPhaseEnd,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct ExportRequest {
    pub format: ExportFormat,
    pub options: Option<ExportOptions>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct ApiResponse<T> {
    pub success: bool,
    pub data: Option<T>,
    pub error: Option<String>,
}

impl<T> ApiResponse<T> {
    pub fn ok(data: T) -> Self {
        Self {
            success: true,
            data: Some(data),
            error: None,
        }
    }

    pub fn err(msg: &str) -> Self {
        Self {
            success: false,
            data: None,
            error: Some(msg.to_string()),
        }
    }
}

// ============================================================================
// MITRE ATT&CK Technique Database (subset for common detection engineering)
// ============================================================================

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MitreTechnique {
    pub id: &'static str,
    pub name: &'static str,
    pub tactic: &'static str,
    pub description: &'static str,
}

pub const MITRE_TECHNIQUES: &[MitreTechnique] = &[
    // Credential Access
    MitreTechnique { id: "T1003", name: "OS Credential Dumping", tactic: "Credential Access", description: "Adversaries may attempt to dump credentials to obtain account login information." },
    MitreTechnique { id: "T1003.001", name: "LSASS Memory", tactic: "Credential Access", description: "Adversaries may attempt to access credential material stored in LSASS process memory." },
    MitreTechnique { id: "T1003.002", name: "Security Account Manager", tactic: "Credential Access", description: "Adversaries may attempt to extract credential material from the SAM database." },
    MitreTechnique { id: "T1003.003", name: "NTDS", tactic: "Credential Access", description: "Adversaries may attempt to access or create a copy of the Active Directory domain database." },
    MitreTechnique { id: "T1558", name: "Steal or Forge Kerberos Tickets", tactic: "Credential Access", description: "Adversaries may attempt to subvert Kerberos authentication." },
    MitreTechnique { id: "T1558.003", name: "Kerberoasting", tactic: "Credential Access", description: "Adversaries may abuse Kerberos to collect service tickets for offline cracking." },

    // Execution
    MitreTechnique { id: "T1059", name: "Command and Scripting Interpreter", tactic: "Execution", description: "Adversaries may abuse command and script interpreters to execute commands." },
    MitreTechnique { id: "T1059.001", name: "PowerShell", tactic: "Execution", description: "Adversaries may abuse PowerShell for execution." },
    MitreTechnique { id: "T1059.003", name: "Windows Command Shell", tactic: "Execution", description: "Adversaries may abuse the Windows command shell for execution." },
    MitreTechnique { id: "T1059.004", name: "Unix Shell", tactic: "Execution", description: "Adversaries may abuse Unix shell commands for execution." },
    MitreTechnique { id: "T1204", name: "User Execution", tactic: "Execution", description: "Adversaries may rely on user interaction for execution." },

    // Persistence
    MitreTechnique { id: "T1547", name: "Boot or Logon Autostart Execution", tactic: "Persistence", description: "Adversaries may configure system settings to automatically execute a program." },
    MitreTechnique { id: "T1547.001", name: "Registry Run Keys / Startup Folder", tactic: "Persistence", description: "Adversaries may use Run keys or Startup folder for persistence." },
    MitreTechnique { id: "T1053", name: "Scheduled Task/Job", tactic: "Persistence", description: "Adversaries may abuse task scheduling for persistence." },
    MitreTechnique { id: "T1543", name: "Create or Modify System Process", tactic: "Persistence", description: "Adversaries may create or modify system processes for persistence." },
    MitreTechnique { id: "T1543.003", name: "Windows Service", tactic: "Persistence", description: "Adversaries may create or modify Windows services for persistence." },

    // Privilege Escalation
    MitreTechnique { id: "T1548", name: "Abuse Elevation Control Mechanism", tactic: "Privilege Escalation", description: "Adversaries may circumvent elevation controls." },
    MitreTechnique { id: "T1548.002", name: "Bypass User Account Control", tactic: "Privilege Escalation", description: "Adversaries may bypass UAC to elevate privileges." },
    MitreTechnique { id: "T1068", name: "Exploitation for Privilege Escalation", tactic: "Privilege Escalation", description: "Adversaries may exploit vulnerabilities to escalate privileges." },

    // Defense Evasion
    MitreTechnique { id: "T1070", name: "Indicator Removal", tactic: "Defense Evasion", description: "Adversaries may delete or modify artifacts generated on a host system." },
    MitreTechnique { id: "T1070.001", name: "Clear Windows Event Logs", tactic: "Defense Evasion", description: "Adversaries may clear Windows Event Logs to hide activity." },
    MitreTechnique { id: "T1562", name: "Impair Defenses", tactic: "Defense Evasion", description: "Adversaries may maliciously modify security tools." },
    MitreTechnique { id: "T1562.001", name: "Disable or Modify Tools", tactic: "Defense Evasion", description: "Adversaries may disable security tools." },
    MitreTechnique { id: "T1055", name: "Process Injection", tactic: "Defense Evasion", description: "Adversaries may inject code into processes to evade defenses." },

    // Discovery
    MitreTechnique { id: "T1087", name: "Account Discovery", tactic: "Discovery", description: "Adversaries may attempt to get a listing of accounts on a system." },
    MitreTechnique { id: "T1082", name: "System Information Discovery", tactic: "Discovery", description: "Adversaries may attempt to get detailed information about the OS." },
    MitreTechnique { id: "T1083", name: "File and Directory Discovery", tactic: "Discovery", description: "Adversaries may enumerate files and directories." },
    MitreTechnique { id: "T1057", name: "Process Discovery", tactic: "Discovery", description: "Adversaries may attempt to get information about running processes." },

    // Lateral Movement
    MitreTechnique { id: "T1021", name: "Remote Services", tactic: "Lateral Movement", description: "Adversaries may use remote services to move laterally." },
    MitreTechnique { id: "T1021.001", name: "Remote Desktop Protocol", tactic: "Lateral Movement", description: "Adversaries may use RDP to move laterally." },
    MitreTechnique { id: "T1021.002", name: "SMB/Windows Admin Shares", tactic: "Lateral Movement", description: "Adversaries may use SMB to move laterally." },
    MitreTechnique { id: "T1021.004", name: "SSH", tactic: "Lateral Movement", description: "Adversaries may use SSH to move laterally." },
    MitreTechnique { id: "T1570", name: "Lateral Tool Transfer", tactic: "Lateral Movement", description: "Adversaries may transfer tools between systems." },

    // Collection
    MitreTechnique { id: "T1005", name: "Data from Local System", tactic: "Collection", description: "Adversaries may search local system sources for data." },
    MitreTechnique { id: "T1039", name: "Data from Network Shared Drive", tactic: "Collection", description: "Adversaries may search network shares for data." },
    MitreTechnique { id: "T1560", name: "Archive Collected Data", tactic: "Collection", description: "Adversaries may compress or encrypt collected data." },

    // Exfiltration
    MitreTechnique { id: "T1041", name: "Exfiltration Over C2 Channel", tactic: "Exfiltration", description: "Adversaries may exfiltrate data over the C2 channel." },
    MitreTechnique { id: "T1048", name: "Exfiltration Over Alternative Protocol", tactic: "Exfiltration", description: "Adversaries may exfiltrate data over alternative protocols." },

    // Command and Control
    MitreTechnique { id: "T1071", name: "Application Layer Protocol", tactic: "Command and Control", description: "Adversaries may communicate using OSI application layer protocols." },
    MitreTechnique { id: "T1071.001", name: "Web Protocols", tactic: "Command and Control", description: "Adversaries may use HTTP/HTTPS for C2." },
    MitreTechnique { id: "T1105", name: "Ingress Tool Transfer", tactic: "Command and Control", description: "Adversaries may transfer tools into the environment." },

    // Impact
    MitreTechnique { id: "T1486", name: "Data Encrypted for Impact", tactic: "Impact", description: "Adversaries may encrypt data to interrupt availability." },
    MitreTechnique { id: "T1489", name: "Service Stop", tactic: "Impact", description: "Adversaries may stop services to render systems unusable." },
];

pub fn search_techniques(query: &str) -> Vec<&'static MitreTechnique> {
    let query_lower = query.to_lowercase();
    MITRE_TECHNIQUES
        .iter()
        .filter(|t| {
            t.id.to_lowercase().contains(&query_lower)
                || t.name.to_lowercase().contains(&query_lower)
                || t.tactic.to_lowercase().contains(&query_lower)
        })
        .collect()
}

pub fn get_technique(id: &str) -> Option<&'static MitreTechnique> {
    MITRE_TECHNIQUES.iter().find(|t| t.id == id)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_search_techniques() {
        let results = search_techniques("credential");
        assert!(!results.is_empty());
        assert!(results.iter().any(|t| t.id == "T1003"));
    }

    #[test]
    fn test_get_technique() {
        let tech = get_technique("T1003.001");
        assert!(tech.is_some());
        assert_eq!(tech.unwrap().name, "LSASS Memory");
    }
}
