//! Integration Layer: Export incidents and ingest third-party alerts
//!
//! This module provides adapters for:
//! - Export: Incidents → JSONL files for Wazuh/SIEM integration
//! - Ingest: Third-party alerts (Wazuh, Zeek EVE) → VendorAlertFact
//! - Profiles: First-class integration metadata with capabilities
//!
//! Design principles:
//! - File-based JSONL first (lowest friction)
//! - Deterministic scope keys for ingested facts
//! - No coupling to proprietary protocols

pub mod config;
pub mod export;
pub mod ingest;
pub mod metrics;
pub mod profile;
pub mod vendor_alert;

// Re-export key types
pub use config::IntegrationConfig;
pub use export::{ExportSink, ExportedIncident, IncidentExporter};
pub use ingest::{IngestSource, VendorAlertIngester};
pub use metrics::{IntegrationMetrics, MetricsReport};
pub use profile::{
    CapabilitiesMatrix, CapabilitySource, DerivedScopeKey, Fidelity, HealthStatus, IntegrationMode,
    IntegrationProfile, IntegrationProfileStore, IntegrationType, JoinKeySupport, MappedEvent,
    SourceType,
};
pub use vendor_alert::VendorAlertFact;
