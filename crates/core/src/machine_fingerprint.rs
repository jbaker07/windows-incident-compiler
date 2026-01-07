//! Machine Fingerprint Generation
//!
//! Generates a stable, privacy-preserving machine fingerprint for license binding.
//! The fingerprint is derived from hardware/OS characteristics that are:
//! - Stable across reboots
//! - Unique per machine (with high probability)
//! - Not personally identifiable
//!
//! Fingerprint = SHA256( normalized_machine_guid || cpu_vendor || os_build )

use sha2::{Digest, Sha256};
use std::fmt;

/// A machine fingerprint - a truncated SHA256 hash of machine characteristics.
/// Stored as 16 hex characters (64 bits) for brevity while maintaining uniqueness.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct MachineFingerprint(pub String);

impl MachineFingerprint {
    /// Generate a new machine fingerprint from current hardware.
    /// Returns None if fingerprint generation fails (VM, restricted permissions, etc.)
    pub fn generate() -> Option<Self> {
        let components = gather_machine_components()?;

        let mut hasher = Sha256::new();
        for component in &components {
            hasher.update(component.as_bytes());
            hasher.update(b"|"); // Delimiter
        }

        let hash = hasher.finalize();
        // Take first 8 bytes (16 hex chars) for brevity
        let fingerprint = hex::encode(&hash[..8]);

        Some(MachineFingerprint(fingerprint))
    }

    /// Create a fingerprint from a known string (for testing or portable licenses).
    pub fn from_string(s: &str) -> Self {
        MachineFingerprint(s.to_string())
    }

    /// Check if this fingerprint matches another.
    pub fn matches(&self, other: &MachineFingerprint) -> bool {
        self.0 == other.0
    }

    /// A special "portable" fingerprint that matches any machine.
    /// Used for development/testing licenses.
    pub fn portable() -> Self {
        MachineFingerprint("PORTABLE".to_string())
    }

    /// Check if this is a portable (wildcard) fingerprint.
    pub fn is_portable(&self) -> bool {
        self.0 == "PORTABLE"
    }
}

impl fmt::Display for MachineFingerprint {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

/// Gather machine-specific components for fingerprinting.
/// Returns None if unable to gather sufficient components.
#[cfg(target_os = "windows")]
fn gather_machine_components() -> Option<Vec<String>> {
    use std::process::Command;

    let mut components = Vec::new();

    // 1. Machine GUID from registry (stable, unique per Windows install)
    if let Some(machine_guid) = get_windows_machine_guid() {
        components.push(format!("GUID:{}", machine_guid));
    }

    // 2. CPU model (stable across reboots)
    if let Some(cpu_name) = get_cpu_name() {
        // Normalize: lowercase, remove extra spaces
        let normalized = cpu_name
            .to_lowercase()
            .split_whitespace()
            .collect::<Vec<_>>()
            .join(" ");
        components.push(format!("CPU:{}", normalized));
    }

    // 3. OS build number (ties to this Windows install)
    if let Ok(output) = Command::new("cmd").args(["/c", "ver"]).output() {
        if let Ok(ver) = String::from_utf8(output.stdout) {
            // Extract build number
            if let Some(build) = extract_windows_build(&ver) {
                components.push(format!("BUILD:{}", build));
            }
        }
    }

    // Need at least 2 components for a reasonable fingerprint
    if components.len() >= 2 {
        Some(components)
    } else {
        None
    }
}

#[cfg(not(target_os = "windows"))]
fn gather_machine_components() -> Option<Vec<String>> {
    use std::fs;

    let mut components = Vec::new();

    // 1. Machine ID (Linux)
    if let Ok(machine_id) = fs::read_to_string("/etc/machine-id") {
        components.push(format!("MACHINEID:{}", machine_id.trim()));
    } else if let Ok(machine_id) = fs::read_to_string("/var/lib/dbus/machine-id") {
        components.push(format!("MACHINEID:{}", machine_id.trim()));
    }

    // 2. CPU info
    if let Ok(cpuinfo) = fs::read_to_string("/proc/cpuinfo") {
        for line in cpuinfo.lines() {
            if line.starts_with("model name") {
                if let Some(value) = line.split(':').nth(1) {
                    let normalized = value
                        .trim()
                        .to_lowercase()
                        .split_whitespace()
                        .collect::<Vec<_>>()
                        .join(" ");
                    components.push(format!("CPU:{}", normalized));
                    break;
                }
            }
        }
    }

    // 3. OS release
    if let Ok(release) = fs::read_to_string("/etc/os-release") {
        for line in release.lines() {
            if line.starts_with("BUILD_ID=") || line.starts_with("VERSION_ID=") {
                if let Some(value) = line.split('=').nth(1) {
                    components.push(format!("BUILD:{}", value.trim_matches('"')));
                    break;
                }
            }
        }
    }

    if components.len() >= 2 {
        Some(components)
    } else {
        None
    }
}

/// Get Windows Machine GUID from registry.
#[cfg(target_os = "windows")]
fn get_windows_machine_guid() -> Option<String> {
    use std::process::Command;

    let output = Command::new("reg")
        .args([
            "query",
            r"HKLM\SOFTWARE\Microsoft\Cryptography",
            "/v",
            "MachineGuid",
        ])
        .output()
        .ok()?;

    let stdout = String::from_utf8(output.stdout).ok()?;

    // Parse REG output: "    MachineGuid    REG_SZ    <guid>"
    for line in stdout.lines() {
        if line.contains("MachineGuid") {
            let parts: Vec<&str> = line.split_whitespace().collect();
            if parts.len() >= 3 {
                return Some(parts[parts.len() - 1].to_string());
            }
        }
    }

    None
}

/// Get CPU name/model.
#[cfg(target_os = "windows")]
fn get_cpu_name() -> Option<String> {
    use std::process::Command;

    let output = Command::new("wmic")
        .args(["cpu", "get", "name"])
        .output()
        .ok()?;

    let stdout = String::from_utf8(output.stdout).ok()?;

    // Skip header line, get first data line
    stdout
        .lines()
        .skip(1)
        .find(|line| !line.trim().is_empty())
        .map(|s| s.trim().to_string())
}

/// Extract Windows build number from `ver` output.
#[cfg(target_os = "windows")]
fn extract_windows_build(ver_output: &str) -> Option<String> {
    // Format: "Microsoft Windows [Version 10.0.19045.3803]"
    if let Some(start) = ver_output.find('[') {
        if let Some(end) = ver_output.find(']') {
            let version = &ver_output[start + 1..end];
            // Get the last numeric part (build number)
            if let Some(dot_pos) = version.rfind('.') {
                return Some(version[dot_pos + 1..].to_string());
            }
            return Some(version.to_string());
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_fingerprint_generation() {
        // Should work on most machines, but might return None in some VMs
        let fp = MachineFingerprint::generate();

        if let Some(fp) = fp {
            // Should be 16 hex characters
            assert_eq!(fp.0.len(), 16);
            assert!(fp.0.chars().all(|c| c.is_ascii_hexdigit()));

            // Should be stable (generate twice, same result)
            let fp2 = MachineFingerprint::generate().unwrap();
            assert_eq!(fp.0, fp2.0);
        }
    }

    #[test]
    fn test_portable_fingerprint() {
        let portable = MachineFingerprint::portable();
        assert!(portable.is_portable());
        assert_eq!(portable.0, "PORTABLE");

        let regular = MachineFingerprint::from_string("abc123");
        assert!(!regular.is_portable());
    }

    #[test]
    fn test_fingerprint_matching() {
        let fp1 = MachineFingerprint::from_string("abc123def456");
        let fp2 = MachineFingerprint::from_string("abc123def456");
        let fp3 = MachineFingerprint::from_string("different");

        assert!(fp1.matches(&fp2));
        assert!(!fp1.matches(&fp3));
    }
}
