//! Canonical event field key definitions
//! All sensors must use these constants exclusively for field names
//! This ensures downstream playbooks/correlation can rely on consistent field names

// === PROCESS FIELDS ===
pub const PROC_PID: &str = "pid";
pub const PROC_PPID: &str = "ppid";
pub const PROC_UID: &str = "uid";
pub const PROC_GID: &str = "gid";
pub const PROC_EXE: &str = "exe";
pub const PROC_COMM: &str = "comm";
pub const PROC_ARGV: &str = "argv";
pub const PROC_CWD: &str = "cwd";
pub const PROC_STATE: &str = "state";

// === FILE FIELDS ===
pub const FILE_PATH: &str = "path";
pub const FILE_INODE: &str = "inode";
pub const FILE_MTIME_MS: &str = "mtime_ms";
pub const FILE_HASH_SHA256: &str = "sha256";

// === NETWORK FIELDS ===
pub const NET_REMOTE_IP: &str = "remote_ip";
pub const NET_REMOTE_PORT: &str = "remote_port";
pub const NET_LOCAL_IP: &str = "local_ip";
pub const NET_LOCAL_PORT: &str = "local_port";
pub const NET_PROTO: &str = "proto";

// === AUTHENTICATION FIELDS ===
pub const AUTH_USER: &str = "user";
pub const AUTH_SRC_IP: &str = "src_ip";
pub const AUTH_METHOD: &str = "method";
pub const AUTH_RESULT: &str = "result";

// === CONTAINER FIELDS ===
pub const CONTAINER_ID: &str = "container_id";
pub const CONTAINER_IMAGE: &str = "image";
pub const CONTAINER_CGROUP: &str = "cgroup";

// === INTEGRITY FIELDS ===
pub const INTEGRITY_TARGET: &str = "target";
pub const INTEGRITY_BEFORE_HASH: &str = "before_hash";
pub const INTEGRITY_AFTER_HASH: &str = "after_hash";
pub const INTEGRITY_REASON: &str = "reason";

// === SENSOR/EVENT METADATA ===
pub const SENSOR_NAME: &str = "sensor";
pub const EVENT_KIND: &str = "kind";
pub const EVENT_SEVERITY: &str = "severity";

// === CANONICAL PRIMITIVE FIELDS ===
// Used by credential_access, discovery, archive_tool_exec, staging_write, network_connection
pub const CRED_TOOL: &str = "cred_tool"; // credential_access: ssh, sudo, gpg, etc.
pub const DISCOVERY_TOOL: &str = "discovery_tool"; // discovery: whoami, id, ps, netstat, etc.
pub const ARCHIVE_TOOL: &str = "archive_tool"; // archive_tool_exec: tar, zip, gzip, etc.
pub const FILE_OP: &str = "op"; // staging_write: "write", "create"
pub const NET_SUSPICIOUS_PORT: &str = "suspicious_port"; // network_connection: bool
pub const PRIMITIVE_SUBTYPE: &str = "primitive_subtype"; // exfiltration only: "archive_tool_exec" | "staging_write"

// === PERSISTENCE CHANGE FIELDS ===
pub const PERSIST_LOCATION: &str = "persist_location"; // path or registry key modified
pub const PERSIST_TYPE: &str = "persist_type"; // "launchagent" | "launchdaemon" | "cron" | "systemd" | "registry" | "profile"
pub const PERSIST_ACTION: &str = "persist_action"; // "create" | "modify" | "delete"

// === DEFENSE EVASION FIELDS ===
pub const EVASION_TARGET: &str = "evasion_target"; // what was tampered: "log", "history", "audit", "security_tool"
pub const EVASION_ACTION: &str = "evasion_action"; // "clear" | "truncate" | "delete" | "disable"

// === PROCESS INJECTION FIELDS ===
pub const INJECT_METHOD: &str = "inject_method"; // "ptrace" | "dyld_insert" | "create_remote_thread" | "hollow"
pub const INJECT_TARGET_PID: &str = "inject_target_pid"; // PID of target process
pub const INJECT_TARGET_EXE: &str = "inject_target_exe"; // Exe of target process

// === AUTH EVENT FIELDS ===
// AUTH_USER, AUTH_SRC_IP, AUTH_METHOD, AUTH_RESULT already defined above

// === SCRIPT EXEC FIELDS ===
pub const SCRIPT_INTERPRETER: &str = "script_interpreter"; // "python" | "bash" | "powershell" | "osascript" | "wscript"
pub const SCRIPT_PATH: &str = "script_path"; // path to script if available
pub const SCRIPT_INLINE: &str = "script_inline"; // true if inline -c/-e execution

// === EUID (effective UID, canonical for all primitives) ===
pub const PROC_EUID: &str = "euid";

// === CLOUD/EXECUTION ===
pub const CLOUD_PLATFORM: &str = "platform";
pub const CLOUD_CLI: &str = "cli_tool";
pub const CLOUD_CONFIG_DIR: &str = "config_dir";

// === MEMORY ===
pub const MEM_ADDRESS: &str = "address";
pub const MEM_PERMS: &str = "perms";
pub const MEM_SIZE: &str = "size";
pub const MEM_TYPE: &str = "map_type";

// === NETWORK SOCKETS ===
pub const SOCKET_PATH: &str = "socket_path";
pub const SOCKET_PERMS: &str = "socket_perms";
pub const SHM_NAME: &str = "shm_name";
pub const SHM_SIZE: &str = "shm_size";

// === MODULE/KERNEL ===
pub const MODULE_NAME: &str = "module_name";
pub const MODULE_SIZE: &str = "module_size";
pub const MODULE_LICENSE: &str = "has_license";

// === USB/HARDWARE ===
pub const USB_PRODUCT: &str = "product";
pub const USB_MANUFACTURER: &str = "manufacturer";
pub const USB_SERIAL: &str = "serial";
pub const USB_CLASS: &str = "class";

// === MISC ===
pub const COUNT: &str = "count";
pub const THRESHOLD: &str = "threshold";
pub const MISC_REASON: &str = "misc_reason";
pub const DEVICE_ID: &str = "device_id";
pub const DEVICE_CLASS: &str = "device_class";

// === PRIVILEGE ESCALATION (LINUX) ===
pub const PRIV_EUID: &str = "euid";
pub const PRIV_SUID: &str = "suid";
pub const PRIV_OLD_EUID: &str = "old_euid";
pub const PRIV_NEW_EUID: &str = "new_euid";
pub const PRIV_EGID: &str = "egid";
pub const PRIV_SGID: &str = "sgid";
pub const PRIV_OLD_EGID: &str = "old_egid";
pub const PRIV_NEW_EGID: &str = "new_egid";
pub const PRIV_CAP_EFFECTIVE: &str = "cap_effective";
pub const PRIV_CAP_PERMITTED: &str = "cap_permitted";

// === NETWORK (EXTENDED) ===
pub const NET_FAMILY: &str = "family";
pub const NET_IS_PRIVATE: &str = "is_private_ip";
pub const NET_IS_LINK_LOCAL: &str = "is_link_local";
pub const NET_OP: &str = "op";
pub const NET_REASON: &str = "net_reason";

/// All valid event field keys (for validation)
pub fn all_valid_keys() -> Vec<&'static str> {
    vec![
        // Process
        PROC_PID,
        PROC_PPID,
        PROC_UID,
        PROC_GID,
        PROC_EXE,
        PROC_COMM,
        PROC_ARGV,
        PROC_CWD,
        PROC_STATE,
        // File
        FILE_PATH,
        FILE_INODE,
        FILE_MTIME_MS,
        FILE_HASH_SHA256,
        // Network
        NET_REMOTE_IP,
        NET_REMOTE_PORT,
        NET_LOCAL_IP,
        NET_LOCAL_PORT,
        NET_PROTO,
        NET_FAMILY,
        NET_IS_PRIVATE,
        NET_IS_LINK_LOCAL,
        NET_OP,
        NET_REASON,
        // Auth
        AUTH_USER,
        AUTH_SRC_IP,
        AUTH_METHOD,
        AUTH_RESULT,
        // Container
        CONTAINER_ID,
        CONTAINER_IMAGE,
        CONTAINER_CGROUP,
        // Integrity
        INTEGRITY_TARGET,
        INTEGRITY_BEFORE_HASH,
        INTEGRITY_AFTER_HASH,
        INTEGRITY_REASON,
        // Metadata
        SENSOR_NAME,
        EVENT_KIND,
        EVENT_SEVERITY,
        // Cloud
        CLOUD_PLATFORM,
        CLOUD_CLI,
        CLOUD_CONFIG_DIR,
        // Memory
        MEM_ADDRESS,
        MEM_PERMS,
        MEM_SIZE,
        MEM_TYPE,
        // Sockets/IPC
        SOCKET_PATH,
        SOCKET_PERMS,
        SHM_NAME,
        SHM_SIZE,
        // Modules
        MODULE_NAME,
        MODULE_SIZE,
        MODULE_LICENSE,
        // USB/Hardware
        USB_PRODUCT,
        USB_MANUFACTURER,
        USB_SERIAL,
        USB_CLASS,
        // Misc
        COUNT,
        THRESHOLD,
        MISC_REASON,
        DEVICE_ID,
        DEVICE_CLASS,
        // Privilege Escalation
        PRIV_EUID,
        PRIV_SUID,
        PRIV_OLD_EUID,
        PRIV_NEW_EUID,
        PRIV_EGID,
        PRIV_SGID,
        PRIV_OLD_EGID,
        PRIV_NEW_EGID,
        PRIV_CAP_EFFECTIVE,
        PRIV_CAP_PERMITTED,
        // Persistence Change
        PERSIST_LOCATION,
        PERSIST_TYPE,
        PERSIST_ACTION,
        // Defense Evasion
        EVASION_TARGET,
        EVASION_ACTION,
        // Process Injection
        INJECT_METHOD,
        INJECT_TARGET_PID,
        INJECT_TARGET_EXE,
        // Script Exec
        SCRIPT_INTERPRETER,
        SCRIPT_PATH,
        SCRIPT_INLINE,
    ]
}
