use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

use super::EvidencePtr;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Event {
    pub ts_ms: i64,
    pub host: String,

    /// Normalized tags, e.g. ["windows", "registry", "persistence"]
    pub tags: Vec<String>,

    /// Deterministic entity keys (optional depending on event)
    pub proc_key: Option<String>,
    pub file_key: Option<String>,
    pub identity_key: Option<String>,

    /// Evidence pointer to the raw segment record that produced this Event
    /// None until assignment by capture writer (segment seq + record counter)
    pub evidence_ptr: Option<EvidencePtr>,

    /// Extra structured fields (avoid platform-specific structs)
    #[serde(default)]
    pub fields: BTreeMap<String, serde_json::Value>,
}

impl Event {
    pub fn tag_contains(&self, s: &str) -> bool {
        self.tags.iter().any(|t| t == s)
    }

    /// Validate event fields against canonical keys.
    /// Returns Ok(()) if all fields are recognized, Err with invalid key if not.
    pub fn validate_basic(&self) -> Result<(), String> {
        let valid_keys = super::event_keys::all_valid_keys();
        let valid_set: std::collections::HashSet<_> = valid_keys.into_iter().collect();

        for key in self.fields.keys() {
            if !valid_set.contains(key.as_str()) {
                return Err(format!("unknown event field: {}", key));
            }
        }

        Ok(())
    }

    /// Validate canonical primitive event structure
    /// Rules:
    /// 1. tags[1] must be one of: "credential_access", "discovery", "exfiltration", "network_connection"
    /// 2. If exfiltration: MUST have fields[primitive_subtype] = "archive_tool_exec" XOR "staging_write"
    /// 3. Required fields vary by type:
    ///    - credential_access: pid, uid, euid, exe, cred_tool
    ///    - discovery: pid, uid, euid, exe, discovery_tool
    ///    - exfiltration (archive): pid, uid, euid, exe, archive_tool, primitive_subtype, argv
    ///    - exfiltration (staging): pid, uid, euid, exe, path, op, primitive_subtype
    ///    - network_connection: pid, uid, euid, remote_ip, remote_port
    pub fn validate_canonical_primitive(&self) -> Result<(), String> {
        // Check that tags has at least 2 elements
        if self.tags.len() < 2 {
            return Err(format!(
                "Event must have at least 2 tags, found {}",
                self.tags.len()
            ));
        }

        let event_type = &self.tags[1];
        let canonical_types = [
            "credential_access",
            "discovery",
            "exfiltration",
            "network_connection",
            "persistence_change",
            "defense_evasion",
            "process_injection",
            "auth_event",
            "script_exec",
        ];

        if !canonical_types.contains(&event_type.as_str()) {
            return Err(format!(
                "Event type must be one of {:?}, found: {}",
                canonical_types, event_type
            ));
        }

        // Validate by type
        match event_type.as_str() {
            "credential_access" => {
                self.validate_required_fields(&[
                    super::event_keys::PROC_PID,
                    super::event_keys::PROC_UID,
                    super::event_keys::PROC_EUID,
                    super::event_keys::PROC_EXE,
                    super::event_keys::CRED_TOOL,
                ])?;
                Ok(())
            }
            "discovery" => {
                self.validate_required_fields(&[
                    super::event_keys::PROC_PID,
                    super::event_keys::PROC_UID,
                    super::event_keys::PROC_EUID,
                    super::event_keys::PROC_EXE,
                    super::event_keys::DISCOVERY_TOOL,
                ])?;
                Ok(())
            }
            "exfiltration" => {
                // MUST have primitive_subtype field
                let subtype = self
                    .fields
                    .get(super::event_keys::PRIMITIVE_SUBTYPE)
                    .and_then(|v| v.as_str())
                    .ok_or_else(|| {
                        format!(
                            "exfiltration event must have field '{}'",
                            super::event_keys::PRIMITIVE_SUBTYPE
                        )
                    })?;

                match subtype {
                    "archive_tool_exec" => {
                        self.validate_required_fields(&[
                            super::event_keys::PROC_PID,
                            super::event_keys::PROC_UID,
                            super::event_keys::PROC_EUID,
                            super::event_keys::PROC_EXE,
                            super::event_keys::ARCHIVE_TOOL,
                            super::event_keys::PRIMITIVE_SUBTYPE,
                        ])?;
                        Ok(())
                    }
                    "staging_write" => {
                        self.validate_required_fields(&[
                            super::event_keys::PROC_PID,
                            super::event_keys::PROC_UID,
                            super::event_keys::PROC_EUID,
                            super::event_keys::FILE_PATH,
                            super::event_keys::FILE_OP,
                            super::event_keys::PRIMITIVE_SUBTYPE,
                        ])?;
                        Ok(())
                    }
                    other => Err(format!(
                        "invalid primitive_subtype for exfiltration: {}",
                        other
                    )),
                }
            }
            "network_connection" => {
                self.validate_required_fields(&[
                    super::event_keys::PROC_PID,
                    super::event_keys::PROC_UID,
                    super::event_keys::PROC_EUID,
                    super::event_keys::NET_REMOTE_IP,
                    super::event_keys::NET_REMOTE_PORT,
                ])?;
                Ok(())
            }
            "persistence_change" => {
                self.validate_required_fields(&[
                    super::event_keys::PROC_PID,
                    super::event_keys::PROC_UID,
                    super::event_keys::PROC_EUID,
                    super::event_keys::PERSIST_LOCATION,
                    super::event_keys::PERSIST_TYPE,
                    super::event_keys::PERSIST_ACTION,
                ])?;
                Ok(())
            }
            "defense_evasion" => {
                self.validate_required_fields(&[
                    super::event_keys::PROC_PID,
                    super::event_keys::PROC_UID,
                    super::event_keys::PROC_EUID,
                    super::event_keys::PROC_EXE,
                    super::event_keys::EVASION_TARGET,
                    super::event_keys::EVASION_ACTION,
                ])?;
                Ok(())
            }
            "process_injection" => {
                self.validate_required_fields(&[
                    super::event_keys::PROC_PID,
                    super::event_keys::PROC_UID,
                    super::event_keys::PROC_EUID,
                    super::event_keys::PROC_EXE,
                    super::event_keys::INJECT_METHOD,
                    super::event_keys::INJECT_TARGET_PID,
                ])?;
                Ok(())
            }
            "auth_event" => {
                self.validate_required_fields(&[
                    super::event_keys::AUTH_USER,
                    super::event_keys::AUTH_METHOD,
                    super::event_keys::AUTH_RESULT,
                ])?;
                Ok(())
            }
            "script_exec" => {
                self.validate_required_fields(&[
                    super::event_keys::PROC_PID,
                    super::event_keys::PROC_UID,
                    super::event_keys::PROC_EUID,
                    super::event_keys::PROC_EXE,
                    super::event_keys::SCRIPT_INTERPRETER,
                ])?;
                Ok(())
            }
            _ => Err(format!("unhandled event type: {}", event_type)),
        }
    }

    /// Helper to check if all required fields are present
    fn validate_required_fields(&self, required: &[&str]) -> Result<(), String> {
        for field in required {
            if !self.fields.contains_key(*field) {
                return Err(format!("event missing required field: {}", field));
            }
        }
        Ok(())
    }
}
