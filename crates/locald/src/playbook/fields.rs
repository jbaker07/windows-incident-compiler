//! Field view: the names a playbook rule can read from a fact.
//!
//! A rule condition names a field. The view answers it in two passes:
//!
//! 1. Lowercase names in `VIEW_FIELDS` come from the typed fact (for example
//!    `path` and `cmdline` on an Exec fact) or from a fixed alias over the raw
//!    Windows event (for example `parent_image` reads ParentImage or
//!    ParentProcessName).
//! 2. Any other name is looked up as a raw event field by its Windows name, for
//!    example `TargetUserName`, `ShareName` or `TicketEncryptionType`.
//!
//! Empty strings count as missing. Windows writes "-" for empty values, and that
//! stays visible so rules can exclude it on purpose.

use crate::hypothesis::canonical_fact::{
    AuthType, InjectionType, PersistenceType, RegistryOp, TamperAction,
};
use crate::hypothesis::{Fact, FactType, ScopeKey};
use edr_core::Event;

/// Lowercase field names the view understands. The loader rejects any other
/// lowercase name so a typo in a playbook fails at load time instead of never
/// matching.
pub const VIEW_FIELDS: &[&str] = &[
    // Every fact
    "fact_type",
    "host",
    "user",
    "process",
    "event_id",
    "channel",
    "provider",
    // Process and file facts
    "path",
    "image",
    "cmdline",
    "exe_hash",
    "signer",
    "parent_path",
    "parent_image",
    "parent_cmdline",
    "process_path",
    "process_image",
    // Authentication facts
    "auth_type",
    "source_ip",
    "success",
    "logon_type",
    // Module loads
    "hash",
    "signed",
    "is_kernel",
    // Registry
    "key",
    "value_name",
    "operation",
    "details",
    // Persistence artifacts
    "artifact_type",
    "path_or_key",
    "service_name",
    "service_path",
    "task_name",
    "task_content",
    // Tampering
    "log_type",
    "action",
    "tool_name",
    "method",
    // Memory and injection
    "source_image",
    "target_image",
    "granted_access",
    "injection_type",
    // Scripts and shell commands
    "interpreter",
    "script_path",
    "script_text",
    "shell",
    "command",
    "is_encoded",
    // Network
    "dst_ip",
    "dst_port",
    "proto",
    "query",
];

/// Fact types the Windows fact extractor produces. A rule on any other fact type
/// could never fire, so the loader rejects it.
pub const WINDOWS_FACT_TYPES: &[&str] = &[
    "Exec",
    "OutboundConnect",
    "DnsResolve",
    "CreatePath",
    "DeletePath",
    "PersistArtifact",
    "MemAlloc",
    "ModuleLoad",
    "Injection",
    "RegistryMod",
    "AuthEvent",
    "LogTamper",
    "SecurityToolDisable",
    "ShellCommand",
    "ScriptExec",
];

/// Discriminant name of a fact, matching the names used in playbook files.
pub fn fact_type_name(fact: &Fact) -> &'static str {
    match &fact.fact_type {
        FactType::ProcSpawn { .. } => "ProcSpawn",
        FactType::Exec { .. } => "Exec",
        FactType::OutboundConnect { .. } => "OutboundConnect",
        FactType::InboundConnect { .. } => "InboundConnect",
        FactType::DnsResolve { .. } => "DnsResolve",
        FactType::WritePath { .. } => "WritePath",
        FactType::ReadPath { .. } => "ReadPath",
        FactType::CreatePath { .. } => "CreatePath",
        FactType::DeletePath { .. } => "DeletePath",
        FactType::RenamePath { .. } => "RenamePath",
        FactType::PersistArtifact { .. } => "PersistArtifact",
        FactType::PrivilegeBoundary { .. } => "PrivilegeBoundary",
        FactType::MemWX { .. } => "MemWX",
        FactType::MemAlloc { .. } => "MemAlloc",
        FactType::ModuleLoad { .. } => "ModuleLoad",
        FactType::Injection { .. } => "Injection",
        FactType::RegistryMod { .. } => "RegistryMod",
        FactType::AuthEvent { .. } => "AuthEvent",
        FactType::LogTamper { .. } => "LogTamper",
        FactType::SecurityToolDisable { .. } => "SecurityToolDisable",
        FactType::ShellCommand { .. } => "ShellCommand",
        FactType::ScriptExec { .. } => "ScriptExec",
        FactType::Unknown { .. } => "Unknown",
    }
}

/// Read only view over one fact and the event it came from.
pub struct FactView<'a> {
    fact: &'a Fact,
    event: &'a Event,
}

impl<'a> FactView<'a> {
    pub fn new(fact: &'a Fact, event: &'a Event) -> Self {
        Self { fact, event }
    }

    pub fn fact(&self) -> &'a Fact {
        self.fact
    }

    /// Look up a field by name. Returns None when the field is absent or empty.
    pub fn get(&self, name: &str) -> Option<String> {
        let value = match name {
            "fact_type" => Some(fact_type_name(self.fact).to_string()),
            "host" => Some(self.fact.host_id.clone()),
            "user" => self.user(),
            "process" => match &self.fact.scope_key {
                ScopeKey::Process { key } => Some(key.clone()),
                _ => self.event.proc_key.clone(),
            },
            "event_id" => self.raw("windows.event_id"),
            "channel" => self.raw("windows.channel"),
            "provider" => self.raw("windows.provider"),
            "image" => self.primary_path().map(|p| basename(&p).to_string()),
            "parent_path" => self.parent_path(),
            "parent_image" => self.parent_path().map(|p| basename(&p).to_string()),
            "parent_cmdline" => self.raw_any(&["ParentCommandLine", "parent_cmdline"]),
            "process_path" => self.process_path(),
            "process_image" => self.process_path().map(|p| basename(&p).to_string()),
            "logon_type" => self.raw_any(&["LogonType", "logon_type"]),
            "signed" => self.raw_any(&["Signed", "signed"]),
            "details" => self.raw_any(&["Details", "details"]),
            "service_name" => self.raw_any(&["ServiceName", "service_name"]),
            "service_path" => self.raw_any(&["ImagePath", "ServiceFileName", "image_path"]),
            "task_name" => self.raw_any(&["TaskName", "task_name"]),
            "task_content" => self.raw_any(&["TaskContent", "task_content"]),
            "source_image" => self.raw_any(&["SourceImage", "source_image"]),
            "target_image" => self.raw_any(&["TargetImage", "target_image"]),
            "granted_access" => self.raw_any(&["GrantedAccess", "granted_access"]),
            "script_text" => self.raw_any(&["ScriptBlockText", "Payload", "script_block_text"]),
            _ => self.typed(name).or_else(|| self.raw(name)),
        };
        value.filter(|v| !v.is_empty())
    }

    /// Fields that come straight from the typed fact.
    fn typed(&self, name: &str) -> Option<String> {
        match (&self.fact.fact_type, name) {
            (FactType::Exec { path, .. }, "path") => Some(path.clone()),
            (FactType::Exec { cmdline, .. }, "cmdline") => cmdline.clone(),
            (FactType::Exec { exe_hash, .. }, "exe_hash") => exe_hash.clone(),
            (FactType::Exec { signer, .. }, "signer") => signer.clone(),

            (FactType::AuthEvent { auth_type, .. }, "auth_type") => Some(auth_type_name(auth_type)),
            (FactType::AuthEvent { source, .. }, "source_ip") => source.clone(),
            (FactType::AuthEvent { success, .. }, "success") => Some(success.to_string()),

            (FactType::ModuleLoad { path, .. }, "path") => Some(path.clone()),
            (FactType::ModuleLoad { hash, .. }, "hash") => hash.clone(),
            (FactType::ModuleLoad { signer, .. }, "signer") => signer.clone(),
            (FactType::ModuleLoad { is_kernel, .. }, "is_kernel") => Some(is_kernel.to_string()),

            (FactType::RegistryMod { key, .. }, "key") => Some(key.clone()),
            (FactType::RegistryMod { value_name, .. }, "value_name") => value_name.clone(),
            (FactType::RegistryMod { operation, .. }, "operation") => {
                Some(registry_op_name(operation).to_string())
            }

            (FactType::PersistArtifact { artifact_type, .. }, "artifact_type") => {
                Some(persistence_type_name(artifact_type))
            }
            (FactType::PersistArtifact { path_or_key, .. }, "path_or_key") => {
                Some(path_or_key.clone())
            }

            (FactType::LogTamper { log_type, .. }, "log_type") => Some(log_type.clone()),
            (FactType::LogTamper { action, .. }, "action") => {
                Some(tamper_action_name(action).to_string())
            }
            (FactType::SecurityToolDisable { tool_name, .. }, "tool_name") => {
                Some(tool_name.clone())
            }
            (FactType::SecurityToolDisable { method, .. }, "method") => Some(method.clone()),

            (FactType::Injection { injection_type, .. }, "injection_type") => {
                Some(injection_type_name(injection_type))
            }

            (FactType::ScriptExec { interpreter, .. }, "interpreter") => Some(interpreter.clone()),
            (FactType::ScriptExec { script_path, .. }, "script_path") => script_path.clone(),

            (FactType::ShellCommand { shell, .. }, "shell") => Some(shell.clone()),
            (FactType::ShellCommand { command, .. }, "command") => Some(command.clone()),
            (FactType::ShellCommand { is_encoded, .. }, "is_encoded") => {
                Some(is_encoded.to_string())
            }

            (FactType::CreatePath { path, .. }, "path")
            | (FactType::DeletePath { path, .. }, "path")
            | (FactType::WritePath { path, .. }, "path")
            | (FactType::ReadPath { path, .. }, "path") => Some(path.clone()),

            (FactType::OutboundConnect { dst_ip, .. }, "dst_ip") => Some(dst_ip.clone()),
            (FactType::OutboundConnect { dst_port, .. }, "dst_port") => Some(dst_port.to_string()),
            (FactType::OutboundConnect { proto, .. }, "proto") => Some(proto.clone()),
            (FactType::DnsResolve { query, .. }, "query") => Some(query.clone()),
            _ => None,
        }
    }

    /// The executable or file a fact is about, used for `image`.
    fn primary_path(&self) -> Option<String> {
        match &self.fact.fact_type {
            FactType::Exec { path, .. }
            | FactType::ModuleLoad { path, .. }
            | FactType::CreatePath { path, .. }
            | FactType::DeletePath { path, .. }
            | FactType::WritePath { path, .. }
            | FactType::ReadPath { path, .. } => Some(path.clone()),
            FactType::ShellCommand { shell, .. } => Some(shell.clone()),
            FactType::ScriptExec { interpreter, .. } => Some(interpreter.clone()),
            _ => None,
        }
    }

    fn parent_path(&self) -> Option<String> {
        self.raw_any(&["ParentImage", "ParentProcessName", "parent_exe"])
    }

    /// The process that caused a non process fact (a file write, a module load,
    /// a registry change). For Exec facts this is the new process itself.
    fn process_path(&self) -> Option<String> {
        match &self.fact.fact_type {
            FactType::Exec { path, .. } => Some(path.clone()),
            _ => self.raw_any(&["Image", "process_path", "exe"]),
        }
    }

    /// User the fact is about. Authentication facts carry it directly, other
    /// facts fall back to the event identity key and then to the raw fields
    /// Windows uses for the acting account.
    fn user(&self) -> Option<String> {
        if let FactType::AuthEvent { user, .. } = &self.fact.fact_type {
            if !user.is_empty() && user != "unknown" {
                return Some(user.clone());
            }
        }
        if let Some(identity) = &self.event.identity_key {
            if !identity.is_empty() {
                return Some(identity.clone());
            }
        }
        self.raw_any(&["User", "SubjectUserName", "TargetUserName", "user"])
    }

    fn raw_any(&self, names: &[&str]) -> Option<String> {
        names
            .iter()
            .filter_map(|n| self.raw(n))
            .find(|v| !v.is_empty())
    }

    fn raw(&self, name: &str) -> Option<String> {
        self.event.fields.get(name).and_then(json_to_string)
    }
}

/// Normalize a user name for grouping: drop a DOMAIN\ prefix or an @domain
/// suffix and lowercase the rest, so "CORP\alice", "alice@corp.local" and
/// "Alice" group together.
pub fn normalize_user(user: &str) -> String {
    let without_domain = user.rsplit('\\').next().unwrap_or(user);
    let without_realm = without_domain.split('@').next().unwrap_or(without_domain);
    without_realm.to_lowercase()
}

/// Last path component, accepting both separators.
pub fn basename(path: &str) -> &str {
    path.rsplit(['\\', '/']).next().unwrap_or(path)
}

fn json_to_string(value: &serde_json::Value) -> Option<String> {
    match value {
        serde_json::Value::Null => None,
        serde_json::Value::String(s) => Some(s.clone()),
        serde_json::Value::Bool(b) => Some(b.to_string()),
        serde_json::Value::Number(n) => Some(n.to_string()),
        other => Some(other.to_string()),
    }
}

fn auth_type_name(auth_type: &AuthType) -> String {
    match auth_type {
        AuthType::Interactive => "interactive".to_string(),
        AuthType::Network => "network".to_string(),
        AuthType::Service => "service".to_string(),
        AuthType::Unlock => "unlock".to_string(),
        AuthType::RemoteInteractive => "remote_interactive".to_string(),
        AuthType::CachedInteractive => "cached_interactive".to_string(),
        AuthType::Sudo => "sudo".to_string(),
        AuthType::Su => "su".to_string(),
        AuthType::Ssh => "ssh".to_string(),
        AuthType::Other(s) => s.clone(),
    }
}

fn registry_op_name(op: &RegistryOp) -> &'static str {
    match op {
        RegistryOp::Create => "create",
        RegistryOp::SetValue => "set_value",
        RegistryOp::DeleteValue => "delete_value",
        RegistryOp::DeleteKey => "delete_key",
    }
}

fn persistence_type_name(kind: &PersistenceType) -> String {
    match kind {
        PersistenceType::Service => "service".to_string(),
        PersistenceType::ScheduledTask => "scheduled_task".to_string(),
        PersistenceType::RegistryRunKey => "registry_run_key".to_string(),
        PersistenceType::LaunchAgent => "launch_agent".to_string(),
        PersistenceType::LaunchDaemon => "launch_daemon".to_string(),
        PersistenceType::CronJob => "cron_job".to_string(),
        PersistenceType::SystemdService => "systemd_service".to_string(),
        PersistenceType::SshAuthorizedKey => "ssh_authorized_key".to_string(),
        PersistenceType::ShellProfile => "shell_profile".to_string(),
        PersistenceType::Other(s) => s.clone(),
    }
}

fn tamper_action_name(action: &TamperAction) -> &'static str {
    match action {
        TamperAction::Clear => "clear",
        TamperAction::Delete => "delete",
        TamperAction::Modify => "modify",
        TamperAction::Disable => "disable",
    }
}

fn injection_type_name(kind: &InjectionType) -> String {
    match kind {
        InjectionType::ProcessHollowing => "process_hollowing".to_string(),
        InjectionType::DllInjection => "dll_injection".to_string(),
        InjectionType::RemoteThread => "remote_thread".to_string(),
        InjectionType::ApcInjection => "apc_injection".to_string(),
        InjectionType::PtraceAttach => "ptrace_attach".to_string(),
        InjectionType::DyldInterpose => "dyld_interpose".to_string(),
        InjectionType::MemfdExec => "memfd_exec".to_string(),
        InjectionType::Other(s) => s.clone(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_normalize_user() {
        assert_eq!(normalize_user("CORP\\Alice"), "alice");
        assert_eq!(normalize_user("alice@CORP.LOCAL"), "alice");
        assert_eq!(normalize_user("alice"), "alice");
    }

    #[test]
    fn test_basename() {
        assert_eq!(basename("C:\\Windows\\System32\\cmd.exe"), "cmd.exe");
        assert_eq!(basename("/usr/bin/ls"), "ls");
        assert_eq!(basename("cmd.exe"), "cmd.exe");
    }
}
