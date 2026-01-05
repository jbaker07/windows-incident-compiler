// locald/signal_orchestrator.rs
// Minimal orchestrator to route canonical events through signal detector and persist results

use crate::core::Event;
use crate::core::signal_result::SignalResult;
use crate::windows::signal_engine::WindowsSignalEngine;

pub struct SignalOrchestrator {
    engine: WindowsSignalEngine,
    host: String,
}

impl SignalOrchestrator {
    pub fn new(host: String) -> Self {
        Self {
            engine: WindowsSignalEngine::new(host.clone()),
            host,
        }
    }

    /// Process event through signal engine, return detected signals
    pub fn process_event(&mut self, event: &Event) -> Vec<SignalResult> {
        self.engine.process_event(event)
    }

    /// Process batch of events
    pub fn process_batch(&mut self, events: &[Event]) -> Vec<SignalResult> {
        let mut all_signals = Vec::new();
        for event in events {
            all_signals.extend(self.process_event(event));
        }
        all_signals
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_orchestrator_creation() {
        let orch = SignalOrchestrator::new("TEST_HOST".to_string());
        assert_eq!(orch.host, "TEST_HOST");
    }
}
