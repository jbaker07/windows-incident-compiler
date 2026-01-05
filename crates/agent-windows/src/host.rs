//! Host context for Windows sensors
//! Provides minimal shared metadata (hostname, boot_id proxy, timestamp helpers)
//! Windows-compatible version of Linux HostCtx

/// Minimal context object passed to all sensors
#[derive(Clone, Debug)]
pub struct HostCtx {
    pub hostname: String,
    pub boot_id: String,
    pub uid: u32,
    pub gid: u32,
}

impl HostCtx {
    /// Create a new HostCtx by reading system metadata
    pub fn new() -> Self {
        let hostname = hostname::get()
            .ok()
            .and_then(|h| h.to_str().map(|s| s.to_string()))
            .unwrap_or_else(|| "unknown".to_string());

        // On Windows, we don't have /proc/sys/kernel/random/boot_id
        // Use a placeholder or registry-based ID
        let boot_id = Self::get_machine_guid().unwrap_or_else(|_| String::new());

        // Windows doesn't have uid/gid in the same way
        // Use placeholder values
        let uid = 0;
        let gid = 0;

        HostCtx {
            hostname,
            boot_id,
            uid,
            gid,
        }
    }

    /// Current time in milliseconds since UNIX_EPOCH
    pub fn now_ms(&self) -> i64 {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_millis() as i64
    }

    /// Current time in seconds since UNIX_EPOCH (timestamp)
    pub fn now_ts(&self) -> u64 {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs()
    }

    /// Get Windows machine GUID (substitute for boot_id)
    #[cfg(target_os = "windows")]
    fn get_machine_guid() -> std::io::Result<String> {
        use std::process::Command;
        let output = Command::new("reg")
            .args([
                "query",
                "HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Cryptography",
                "/v",
                "MachineGuid",
            ])
            .output()?;

        let out_str = String::from_utf8_lossy(&output.stdout);
        for line in out_str.lines() {
            if line.contains("MachineGuid") {
                if let Some(guid) = line.split_whitespace().last() {
                    return Ok(guid.to_string());
                }
            }
        }
        Ok(String::new())
    }

    #[cfg(not(target_os = "windows"))]
    fn get_machine_guid() -> std::io::Result<String> {
        // Placeholder for non-Windows builds (e.g., cross-compilation)
        Ok("non-windows-placeholder".to_string())
    }
}

impl Default for HostCtx {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_host_ctx_creation() {
        let ctx = HostCtx::new();
        assert!(!ctx.hostname.is_empty());
        assert!(ctx.now_ms() > 0);
        assert!(ctx.now_ts() > 0);
    }
}
