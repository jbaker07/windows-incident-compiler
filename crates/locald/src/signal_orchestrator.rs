//! Signal orchestrator for routing events through platform-specific detectors
//!
//! Routes canonical Events through the appropriate signal engine based on
//! the detected platform and returns detected signals.

use crate::integrations::ingest::VendorAlertIngester;
use crate::os::linux::LinuxSignalEngine;
use crate::os::macos::MacOSSignalEngine;
use crate::os::windows::WindowsSignalEngine;
use crate::signal_result::SignalResult;
use edr_core::Event;

/// Platform type for signal routing
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Platform {
    Windows,
    MacOS,
    Linux,
}

impl Platform {
    /// Detect the current platform at compile time
    pub fn current() -> Self {
        #[cfg(target_os = "windows")]
        return Platform::Windows;
        #[cfg(target_os = "macos")]
        return Platform::MacOS;
        #[cfg(target_os = "linux")]
        return Platform::Linux;
        #[cfg(not(any(target_os = "windows", target_os = "macos", target_os = "linux")))]
        return Platform::Linux; // Default to Linux for other Unix-like systems
    }
}

/// Multi-platform signal orchestrator
pub struct SignalOrchestrator {
    platform: Platform,
    host: String,
    windows_engine: Option<WindowsSignalEngine>,
    macos_engine: Option<MacOSSignalEngine>,
    linux_engine: Option<LinuxSignalEngine>,
    /// Optional vendor alert ingester for SIEM integration
    ingester: Option<VendorAlertIngester>,
}

impl SignalOrchestrator {
    /// Create a new orchestrator for the current platform
    pub fn new(host: String) -> Self {
        Self::for_platform(host, Platform::current())
    }

    /// Create an orchestrator for a specific platform
    pub fn for_platform(host: String, platform: Platform) -> Self {
        let mut orchestrator = Self {
            platform,
            host: host.clone(),
            windows_engine: None,
            macos_engine: None,
            linux_engine: None,
            ingester: None,
        };

        // Initialize the appropriate engine
        match platform {
            Platform::Windows => {
                orchestrator.windows_engine = Some(WindowsSignalEngine::new(host.clone()));
            }
            Platform::MacOS => {
                orchestrator.macos_engine = Some(MacOSSignalEngine::new(host.clone()));
            }
            Platform::Linux => {
                orchestrator.linux_engine = Some(LinuxSignalEngine::new(host.clone()));
            }
        }

        orchestrator
    }

    /// Process a single event through the signal engine
    pub fn process_event(&mut self, event: &Event) -> Vec<SignalResult> {
        match self.platform {
            Platform::Windows => {
                if let Some(engine) = &mut self.windows_engine {
                    engine.process_event(event)
                } else {
                    Vec::new()
                }
            }
            Platform::MacOS => {
                if let Some(engine) = &mut self.macos_engine {
                    engine.process_event(event)
                } else {
                    Vec::new()
                }
            }
            Platform::Linux => {
                if let Some(engine) = &mut self.linux_engine {
                    engine.process_event(event)
                } else {
                    Vec::new()
                }
            }
        }
    }

    /// Process a batch of events
    pub fn process_batch(&mut self, events: &[Event]) -> Vec<SignalResult> {
        let mut all_signals = Vec::new();
        for event in events {
            all_signals.extend(self.process_event(event));
        }
        all_signals
    }

    /// Get the current platform
    pub fn platform(&self) -> Platform {
        self.platform
    }

    /// Get the hostname
    pub fn host(&self) -> &str {
        &self.host
    }

    /// Enable vendor alert ingestion
    pub fn enable_ingester(&mut self) {
        self.ingester = Some(VendorAlertIngester::new(&self.host));
    }

    /// Get ingester (if enabled)
    pub fn ingester_mut(&mut self) -> Option<&mut VendorAlertIngester> {
        self.ingester.as_mut()
    }

    /// Poll for vendor alerts (returns Facts for hypothesis pipeline)
    pub fn poll_ingest(&mut self) -> Result<Vec<crate::hypothesis::Fact>, String> {
        if let Some(ingester) = &mut self.ingester {
            ingester.poll()
        } else {
            Ok(Vec::new())
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_orchestrator_creation() {
        let orch = SignalOrchestrator::new("TEST_HOST".to_string());
        assert_eq!(orch.host(), "TEST_HOST");
    }

    #[test]
    fn test_platform_specific_orchestrator() {
        let orch = SignalOrchestrator::for_platform("TEST_HOST".to_string(), Platform::Linux);
        assert_eq!(orch.platform(), Platform::Linux);
        assert!(orch.linux_engine.is_some());
        assert!(orch.windows_engine.is_none());
        assert!(orch.macos_engine.is_none());
    }

    #[test]
    fn test_empty_batch_processing() {
        let mut orch = SignalOrchestrator::new("TEST_HOST".to_string());
        let signals = orch.process_batch(&[]);
        assert!(signals.is_empty());
    }
}
