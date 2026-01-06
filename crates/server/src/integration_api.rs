//! Integration API endpoints for ui_server
//!
//! Provides REST endpoints for:
//! - GET /api/integrations - List integration profiles + health/stats
//! - GET /api/capabilities - Merged capabilities matrix
//! - GET /api/integrations/:id/sample - Raw + mapped event samples
//!
//! These endpoints surface integration metadata to the UI for visualization.

use axum::{
    extract::{Path, Query, State},
    http::StatusCode,
    response::IntoResponse,
    routing::get,
    Json, Router,
};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::{Arc, RwLock};

// ============================================================================
// Types (mirroring edr_locald::integrations::profile)
// We re-define here to avoid tight coupling between crates
// ============================================================================

/// Fidelity level for fact support
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Fidelity {
    Hard,
    Soft,
    None,
}

/// Integration mode
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum IntegrationMode {
    Export,
    Ingest,
    Both,
}

/// Health status
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum HealthStatus {
    Healthy,
    Warning,
    Error,
    Unknown,
}

/// Integration profile summary for API
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IntegrationProfileApi {
    pub integration_id: String,
    pub name: String,
    pub integration_type: String,
    pub mode: IntegrationMode,
    pub enabled: bool,
    pub health_status: HealthStatus,
    pub mapping_version: String,
    pub last_seen_ts: Option<DateTime<Utc>>,
    pub eps: f64,
    pub parse_error_rate: f64,
    pub events_processed: u64,
    pub facts_created: u64,
    pub facts_supported_count: usize,
    pub join_keys_supported_count: usize,
}

/// Join key support flags
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct JoinKeySupport {
    pub proc_key: bool,
    pub file_key: bool,
    pub socket_key: bool,
    pub identity_key: bool,
    pub dns_attribution: bool,
    pub thread_key: bool,
}

/// Full integration detail for single-item endpoint
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IntegrationDetailApi {
    #[serde(flatten)]
    pub summary: IntegrationProfileApi,
    pub facts_supported: HashMap<String, Fidelity>,
    pub join_keys_supported: JoinKeySupport,
    pub config_source: Option<String>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

/// Source type for capabilities matrix
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SourceType {
    Collector,
    Integration,
}

/// Capability source
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CapabilitySource {
    pub id: String,
    pub name: String,
    pub source_type: SourceType,
    pub mode: IntegrationMode,
    pub health_status: HealthStatus,
}

/// Capabilities matrix response
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CapabilitiesMatrixApi {
    pub sources: Vec<CapabilitySource>,
    pub fact_support: HashMap<String, HashMap<String, Fidelity>>,
    pub join_key_support: HashMap<String, HashMap<String, bool>>,
    pub host_id: Option<String>,
    pub namespace: Option<String>,
}

/// Mapped event sample
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MappedEventSample {
    pub raw_event_id: Option<String>,
    pub raw_json_hash: String,
    pub mapping_version: String,
    pub mapped_at: DateTime<Utc>,
    pub raw_event_summary: Option<String>,
    pub mapped_event: serde_json::Value,
    pub derived_scope_keys: Vec<DerivedScopeKey>,
}

/// Derived scope key with provenance
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DerivedScopeKey {
    pub key: String,
    pub key_type: String,
    pub fidelity: Fidelity,
    pub join_confidence: f64,
    pub confidence_reason: Option<String>,
}

/// Sample events response
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SampleEventsResponse {
    pub integration_id: String,
    pub samples: Vec<MappedEventSample>,
    pub total_available: usize,
}

// ============================================================================
// State and Query Parameters
// ============================================================================

/// Shared state for integration API
#[derive(Clone)]
pub struct IntegrationApiState {
    pub profiles: Arc<RwLock<HashMap<String, IntegrationDetailApi>>>,
    pub samples: Arc<RwLock<HashMap<String, Vec<MappedEventSample>>>>,
    pub collectors: Arc<RwLock<Vec<CollectorInfo>>>,
}

/// Collector info for capabilities matrix
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CollectorInfo {
    pub id: String,
    pub name: String,
    pub platform: String,
    pub facts_supported: Vec<String>,
    pub join_keys_supported: JoinKeySupport,
    pub health_status: HealthStatus,
}

impl IntegrationApiState {
    /// Create a new state with sample data for demo
    pub fn demo() -> Self {
        let mut profiles = HashMap::new();
        let mut samples = HashMap::new();

        // Add Wazuh integration
        let wazuh = create_wazuh_profile();
        profiles.insert("wazuh_main".to_string(), wazuh.clone());

        // Add Zeek integration
        let zeek = create_zeek_profile();
        profiles.insert("zeek_network".to_string(), zeek.clone());

        // Add JSONL export
        let jsonl = create_jsonl_export_profile();
        profiles.insert("jsonl_export".to_string(), jsonl.clone());

        // Add sample events
        samples.insert("wazuh_main".to_string(), vec![create_sample_wazuh_event()]);
        samples.insert("zeek_network".to_string(), vec![create_sample_zeek_event()]);

        // Create collectors
        let collectors = vec![
            CollectorInfo {
                id: "macos_endpoint_security".to_string(),
                name: "macOS Endpoint Security".to_string(),
                platform: "macos".to_string(),
                facts_supported: vec![
                    "exec".to_string(),
                    "proc_spawn".to_string(),
                    "write_path".to_string(),
                    "read_path".to_string(),
                    "create_path".to_string(),
                    "delete_path".to_string(),
                    "outbound_connect".to_string(),
                    "dns_resolve".to_string(),
                    "privilege_boundary".to_string(),
                ],
                join_keys_supported: JoinKeySupport {
                    proc_key: true,
                    file_key: true,
                    socket_key: true,
                    identity_key: true,
                    dns_attribution: true,
                    thread_key: true,
                },
                health_status: HealthStatus::Healthy,
            },
            CollectorInfo {
                id: "windows_etw".to_string(),
                name: "Windows ETW/Sysmon".to_string(),
                platform: "windows".to_string(),
                facts_supported: vec![
                    "exec".to_string(),
                    "proc_spawn".to_string(),
                    "write_path".to_string(),
                    "outbound_connect".to_string(),
                    "dns_resolve".to_string(),
                    "privilege_boundary".to_string(),
                    "mem_wx".to_string(),
                ],
                join_keys_supported: JoinKeySupport {
                    proc_key: true,
                    file_key: true,
                    socket_key: true,
                    identity_key: true,
                    dns_attribution: true,
                    thread_key: true,
                },
                health_status: HealthStatus::Healthy,
            },
            CollectorInfo {
                id: "linux_ebpf".to_string(),
                name: "Linux eBPF".to_string(),
                platform: "linux".to_string(),
                facts_supported: vec![
                    "exec".to_string(),
                    "proc_spawn".to_string(),
                    "write_path".to_string(),
                    "read_path".to_string(),
                    "outbound_connect".to_string(),
                    "inbound_connect".to_string(),
                    "dns_resolve".to_string(),
                ],
                join_keys_supported: JoinKeySupport {
                    proc_key: true,
                    file_key: true,
                    socket_key: true,
                    identity_key: true,
                    dns_attribution: false,
                    thread_key: true,
                },
                health_status: HealthStatus::Healthy,
            },
        ];

        Self {
            profiles: Arc::new(RwLock::new(profiles)),
            samples: Arc::new(RwLock::new(samples)),
            collectors: Arc::new(RwLock::new(collectors)),
        }
    }
}

/// Query parameters for listing integrations
#[derive(Debug, Deserialize)]
pub struct ListIntegrationsQuery {
    #[serde(default)]
    pub mode: Option<String>,
    #[serde(default)]
    pub enabled_only: Option<bool>,
}

/// Query parameters for capabilities
#[derive(Debug, Deserialize)]
pub struct CapabilitiesQuery {
    #[serde(default)]
    pub host_id: Option<String>,
    #[serde(default)]
    pub namespace: Option<String>,
    #[serde(default)]
    pub include_collectors: Option<bool>,
}

/// Query parameters for samples
#[derive(Debug, Deserialize)]
pub struct SampleQuery {
    #[serde(default = "default_limit")]
    pub limit: usize,
}

fn default_limit() -> usize {
    10
}

// ============================================================================
// API Handlers
// ============================================================================

/// GET /api/integrations - List integration profiles
#[allow(dead_code)]
pub async fn list_integrations(
    State(state): State<IntegrationApiState>,
    Query(query): Query<ListIntegrationsQuery>,
) -> impl IntoResponse {
    let profiles = state.profiles.read().unwrap();

    let mut result: Vec<IntegrationProfileApi> = profiles
        .values()
        .filter(|p| {
            // Filter by mode if specified
            if let Some(ref mode_str) = query.mode {
                let mode_match = match mode_str.as_str() {
                    "export" => p.summary.mode == IntegrationMode::Export,
                    "ingest" => p.summary.mode == IntegrationMode::Ingest,
                    "both" => p.summary.mode == IntegrationMode::Both,
                    _ => true,
                };
                if !mode_match {
                    return false;
                }
            }

            // Filter by enabled if specified
            if let Some(enabled_only) = query.enabled_only {
                if enabled_only && !p.summary.enabled {
                    return false;
                }
            }

            true
        })
        .map(|p| p.summary.clone())
        .collect();

    // Sort by name
    result.sort_by(|a, b| a.name.cmp(&b.name));

    Json(serde_json::json!({
        "integrations": result,
        "total": result.len()
    }))
}

/// GET /api/integrations/:id - Get integration detail
#[allow(dead_code)]
pub async fn get_integration(
    State(state): State<IntegrationApiState>,
    Path(integration_id): Path<String>,
) -> impl IntoResponse {
    let profiles = state.profiles.read().unwrap();

    match profiles.get(&integration_id) {
        Some(profile) => Json(serde_json::json!({
            "integration": profile
        }))
        .into_response(),
        None => (
            StatusCode::NOT_FOUND,
            Json(serde_json::json!({
                "error": "Integration not found",
                "integration_id": integration_id
            })),
        )
            .into_response(),
    }
}

/// GET /api/capabilities - Merged capabilities matrix
#[allow(dead_code)]
pub async fn get_capabilities(
    State(state): State<IntegrationApiState>,
    Query(query): Query<CapabilitiesQuery>,
) -> impl IntoResponse {
    let profiles = state.profiles.read().unwrap();
    let collectors = state.collectors.read().unwrap();

    let mut sources = Vec::new();
    let mut fact_support: HashMap<String, HashMap<String, Fidelity>> = HashMap::new();
    let mut join_key_support: HashMap<String, HashMap<String, bool>> = HashMap::new();

    // Add collectors if requested (default: true)
    let include_collectors = query.include_collectors.unwrap_or(true);
    if include_collectors {
        for collector in collectors.iter() {
            sources.push(CapabilitySource {
                id: collector.id.clone(),
                name: collector.name.clone(),
                source_type: SourceType::Collector,
                mode: IntegrationMode::Ingest,
                health_status: collector.health_status,
            });

            // Add fact support (Hard for collectors)
            for fact_type in &collector.facts_supported {
                let entry = fact_support.entry(fact_type.clone()).or_default();
                entry.insert(collector.id.clone(), Fidelity::Hard);
            }

            // Add join key support
            merge_join_keys(
                &mut join_key_support,
                &collector.id,
                &collector.join_keys_supported,
            );
        }
    }

    // Add integrations
    for (id, profile) in profiles.iter() {
        if !profile.summary.enabled {
            continue;
        }

        sources.push(CapabilitySource {
            id: id.clone(),
            name: profile.summary.name.clone(),
            source_type: SourceType::Integration,
            mode: profile.summary.mode,
            health_status: profile.summary.health_status,
        });

        // Add fact support
        for (fact_type, fidelity) in &profile.facts_supported {
            let entry = fact_support.entry(fact_type.clone()).or_default();
            entry.insert(id.clone(), *fidelity);
        }

        // Add join key support
        merge_join_keys(&mut join_key_support, id, &profile.join_keys_supported);
    }

    Json(CapabilitiesMatrixApi {
        sources,
        fact_support,
        join_key_support,
        host_id: query.host_id,
        namespace: query.namespace,
    })
}

/// GET /api/integrations/:id/sample - Get sample events
#[allow(dead_code)]
pub async fn get_samples(
    State(state): State<IntegrationApiState>,
    Path(integration_id): Path<String>,
    Query(query): Query<SampleQuery>,
) -> impl IntoResponse {
    let samples = state.samples.read().unwrap();

    match samples.get(&integration_id) {
        Some(events) => {
            let limited: Vec<_> = events.iter().rev().take(query.limit).cloned().collect();
            Json(SampleEventsResponse {
                integration_id,
                samples: limited,
                total_available: events.len(),
            })
            .into_response()
        }
        None => (
            StatusCode::NOT_FOUND,
            Json(serde_json::json!({
                "error": "Integration not found or no samples available",
                "integration_id": integration_id
            })),
        )
            .into_response(),
    }
}

// ============================================================================
// Helper Functions
// ============================================================================

fn merge_join_keys(
    support: &mut HashMap<String, HashMap<String, bool>>,
    source_id: &str,
    keys: &JoinKeySupport,
) {
    let entries = [
        ("proc_key", keys.proc_key),
        ("file_key", keys.file_key),
        ("socket_key", keys.socket_key),
        ("identity_key", keys.identity_key),
        ("dns_attribution", keys.dns_attribution),
        ("thread_key", keys.thread_key),
    ];

    for (key_name, supported) in entries {
        let entry = support.entry(key_name.to_string()).or_default();
        entry.insert(source_id.to_string(), supported);
    }
}

fn create_wazuh_profile() -> IntegrationDetailApi {
    let now = Utc::now();
    IntegrationDetailApi {
        summary: IntegrationProfileApi {
            integration_id: "wazuh_main".to_string(),
            name: "Wazuh HIDS".to_string(),
            integration_type: "wazuh".to_string(),
            mode: IntegrationMode::Both,
            enabled: true,
            health_status: HealthStatus::Healthy,
            mapping_version: "wazuh_4.x".to_string(),
            last_seen_ts: Some(now - chrono::Duration::seconds(30)),
            eps: 42.5,
            parse_error_rate: 0.002,
            events_processed: 125_432,
            facts_created: 98_765,
            facts_supported_count: 7,
            join_keys_supported_count: 4,
        },
        facts_supported: HashMap::from([
            ("exec".to_string(), Fidelity::Soft),
            ("proc_spawn".to_string(), Fidelity::Soft),
            ("write_path".to_string(), Fidelity::Soft),
            ("outbound_connect".to_string(), Fidelity::Soft),
            ("inbound_connect".to_string(), Fidelity::Soft),
            ("privilege_boundary".to_string(), Fidelity::Soft),
            ("vendor_alert".to_string(), Fidelity::Hard),
        ]),
        join_keys_supported: JoinKeySupport {
            proc_key: true,
            file_key: true,
            socket_key: true,
            identity_key: true,
            dns_attribution: false,
            thread_key: false,
        },
        config_source: Some("/etc/edr/integrations/wazuh.yaml".to_string()),
        created_at: now - chrono::Duration::days(30),
        updated_at: now,
    }
}

fn create_zeek_profile() -> IntegrationDetailApi {
    let now = Utc::now();
    IntegrationDetailApi {
        summary: IntegrationProfileApi {
            integration_id: "zeek_network".to_string(),
            name: "Zeek Network Monitor".to_string(),
            integration_type: "zeek".to_string(),
            mode: IntegrationMode::Ingest,
            enabled: true,
            health_status: HealthStatus::Healthy,
            mapping_version: "zeek_6.x".to_string(),
            last_seen_ts: Some(now - chrono::Duration::seconds(5)),
            eps: 1250.0,
            parse_error_rate: 0.0001,
            events_processed: 5_432_100,
            facts_created: 2_150_000,
            facts_supported_count: 4,
            join_keys_supported_count: 2,
        },
        facts_supported: HashMap::from([
            ("outbound_connect".to_string(), Fidelity::Soft),
            ("inbound_connect".to_string(), Fidelity::Soft),
            ("dns_resolve".to_string(), Fidelity::Hard),
            ("vendor_alert".to_string(), Fidelity::Hard),
        ]),
        join_keys_supported: JoinKeySupport {
            proc_key: false,
            file_key: false,
            socket_key: true,
            identity_key: false,
            dns_attribution: true,
            thread_key: false,
        },
        config_source: Some("/etc/edr/integrations/zeek.yaml".to_string()),
        created_at: now - chrono::Duration::days(15),
        updated_at: now,
    }
}

fn create_jsonl_export_profile() -> IntegrationDetailApi {
    let now = Utc::now();
    IntegrationDetailApi {
        summary: IntegrationProfileApi {
            integration_id: "jsonl_export".to_string(),
            name: "JSONL File Export".to_string(),
            integration_type: "jsonl_file".to_string(),
            mode: IntegrationMode::Export,
            enabled: true,
            health_status: HealthStatus::Healthy,
            mapping_version: "export_1.0".to_string(),
            last_seen_ts: Some(now - chrono::Duration::minutes(5)),
            eps: 0.0, // Export doesn't have eps
            parse_error_rate: 0.0,
            events_processed: 0,
            facts_created: 0,
            facts_supported_count: 13,
            join_keys_supported_count: 0,
        },
        facts_supported: HashMap::from([
            ("exec".to_string(), Fidelity::Hard),
            ("proc_spawn".to_string(), Fidelity::Hard),
            ("write_path".to_string(), Fidelity::Hard),
            ("read_path".to_string(), Fidelity::Hard),
            ("create_path".to_string(), Fidelity::Hard),
            ("delete_path".to_string(), Fidelity::Hard),
            ("outbound_connect".to_string(), Fidelity::Hard),
            ("inbound_connect".to_string(), Fidelity::Hard),
            ("dns_resolve".to_string(), Fidelity::Hard),
            ("privilege_boundary".to_string(), Fidelity::Hard),
            ("mem_wx".to_string(), Fidelity::Hard),
            ("persist_artifact".to_string(), Fidelity::Hard),
            ("vendor_alert".to_string(), Fidelity::Hard),
        ]),
        join_keys_supported: JoinKeySupport::default(),
        config_source: Some("/etc/edr/integrations/export.yaml".to_string()),
        created_at: now - chrono::Duration::days(30),
        updated_at: now,
    }
}

fn create_sample_wazuh_event() -> MappedEventSample {
    let now = Utc::now();
    MappedEventSample {
        raw_event_id: Some("wazuh_1234567".to_string()),
        raw_json_hash: "a1b2c3d4e5f6".to_string(),
        mapping_version: "wazuh_4.x".to_string(),
        mapped_at: now - chrono::Duration::minutes(2),
        raw_event_summary: Some(r#"{"timestamp":"2024-01-15T12:34:56Z","agent":{"name":"win-dc-01","ip":"192.168.1.10"},"rule":{"id":"5501","description":"SSH authentication failure","level":5,"mitre":{"id":["T1110"]}}}"#.to_string()),
        mapped_event: serde_json::json!({
            "fact_type": "vendor_alert",
            "vendor": "wazuh",
            "alert_name": "SSH authentication failure",
            "mitre_tags": ["T1110"],
            "host_hint": "win-dc-01"
        }),
        derived_scope_keys: vec![
            DerivedScopeKey {
                key: "vendoralert:wazuh:win-dc-01:28401".to_string(),
                key_type: "campaign".to_string(),
                fidelity: Fidelity::Soft,
                join_confidence: 0.85,
                confidence_reason: Some("IP+time window match".to_string()),
            },
        ],
    }
}

fn create_sample_zeek_event() -> MappedEventSample {
    let now = Utc::now();
    MappedEventSample {
        raw_event_id: Some("CKhsY42hNpFrP9hWAd".to_string()),
        raw_json_hash: "f6e5d4c3b2a1".to_string(),
        mapping_version: "zeek_6.x".to_string(),
        mapped_at: now - chrono::Duration::seconds(30),
        raw_event_summary: Some(r#"{"ts":1705319696.123,"uid":"CKhsY42hNpFrP9hWAd","id.orig_h":"192.168.1.100","id.resp_h":"8.8.8.8","query":"malicious-c2.example.com"}"#.to_string()),
        mapped_event: serde_json::json!({
            "fact_type": "dns_resolve",
            "query": "malicious-c2.example.com",
            "responses": ["93.184.216.34"]
        }),
        derived_scope_keys: vec![
            DerivedScopeKey {
                key: "dns:malicious-c2.example.com".to_string(),
                key_type: "identity".to_string(),
                fidelity: Fidelity::Hard,
                join_confidence: 1.0,
                confidence_reason: Some("Direct DNS observation".to_string()),
            },
            DerivedScopeKey {
                key: "socket:192.168.1.100:52134->8.8.8.8:53".to_string(),
                key_type: "process".to_string(),
                fidelity: Fidelity::Soft,
                join_confidence: 0.7,
                confidence_reason: Some("Socket correlation, no process context".to_string()),
            },
        ],
    }
}

// ============================================================================
// Router Builder
// ============================================================================

/// Build the integration API router
#[allow(dead_code)]
pub fn integration_api_router(state: IntegrationApiState) -> Router {
    Router::new()
        .route("/api/integrations", get(list_integrations))
        .route("/api/integrations/:id", get(get_integration))
        .route("/api/integrations/:id/sample", get(get_samples))
        .route("/api/capabilities", get(get_capabilities))
        .with_state(state)
}

// ============================================================================
// Bridge Handlers (for integration into main router)
// These handlers create their own state internally for use with AppState
// ============================================================================

/// Bridge handler for list_integrations that creates its own state
pub async fn list_integrations_bridge(
    Query(query): Query<ListIntegrationsQuery>,
) -> impl IntoResponse {
    let state = IntegrationApiState::demo();
    let profiles = state.profiles.read().unwrap();

    let mut result: Vec<IntegrationProfileApi> = profiles
        .values()
        .filter(|p| {
            // Filter by mode if specified
            if let Some(ref mode_str) = query.mode {
                let mode_match = match mode_str.as_str() {
                    "export" => p.summary.mode == IntegrationMode::Export,
                    "ingest" => p.summary.mode == IntegrationMode::Ingest,
                    "both" => p.summary.mode == IntegrationMode::Both,
                    _ => true,
                };
                if !mode_match {
                    return false;
                }
            }

            // Filter by enabled if specified
            if let Some(enabled_only) = query.enabled_only {
                if enabled_only && !p.summary.enabled {
                    return false;
                }
            }

            true
        })
        .map(|p| p.summary.clone())
        .collect();

    // Sort by name
    result.sort_by(|a, b| a.name.cmp(&b.name));

    Json(serde_json::json!({
        "integrations": result,
        "total": result.len()
    }))
}

/// Bridge handler for get_integration that creates its own state
pub async fn get_integration_bridge(Path(integration_id): Path<String>) -> impl IntoResponse {
    let state = IntegrationApiState::demo();
    let profiles = state.profiles.read().unwrap();

    match profiles.get(&integration_id) {
        Some(profile) => Json(serde_json::json!({
            "integration": profile
        }))
        .into_response(),
        None => (
            StatusCode::NOT_FOUND,
            Json(serde_json::json!({
                "error": "Integration not found",
                "integration_id": integration_id
            })),
        )
            .into_response(),
    }
}

/// Bridge handler for get_capabilities that creates its own state
pub async fn get_capabilities_bridge(Query(query): Query<CapabilitiesQuery>) -> impl IntoResponse {
    let state = IntegrationApiState::demo();
    let profiles = state.profiles.read().unwrap();
    let collectors = state.collectors.read().unwrap();

    let mut sources = Vec::new();
    let mut fact_support: HashMap<String, HashMap<String, Fidelity>> = HashMap::new();
    let mut join_key_support: HashMap<String, HashMap<String, bool>> = HashMap::new();

    // Add collectors if requested (default: true)
    let include_collectors = query.include_collectors.unwrap_or(true);
    if include_collectors {
        for collector in collectors.iter() {
            sources.push(CapabilitySource {
                id: collector.id.clone(),
                name: collector.name.clone(),
                source_type: SourceType::Collector,
                mode: IntegrationMode::Ingest,
                health_status: collector.health_status,
            });

            // Add fact support (Hard for collectors)
            for fact_type in &collector.facts_supported {
                let entry = fact_support.entry(fact_type.clone()).or_default();
                entry.insert(collector.id.clone(), Fidelity::Hard);
            }

            // Add join key support
            merge_join_keys(
                &mut join_key_support,
                &collector.id,
                &collector.join_keys_supported,
            );
        }
    }

    // Add integrations
    for (id, profile) in profiles.iter() {
        if !profile.summary.enabled {
            continue;
        }

        sources.push(CapabilitySource {
            id: id.clone(),
            name: profile.summary.name.clone(),
            source_type: SourceType::Integration,
            mode: profile.summary.mode,
            health_status: profile.summary.health_status,
        });

        // Add fact support
        for (fact_type, fidelity) in &profile.facts_supported {
            let entry = fact_support.entry(fact_type.clone()).or_default();
            entry.insert(id.clone(), *fidelity);
        }

        // Add join key support
        merge_join_keys(&mut join_key_support, id, &profile.join_keys_supported);
    }

    Json(CapabilitiesMatrixApi {
        sources,
        fact_support,
        join_key_support,
        host_id: query.host_id,
        namespace: query.namespace,
    })
}

/// Bridge handler for get_samples that creates its own state
pub async fn get_samples_bridge(
    Path(integration_id): Path<String>,
    Query(query): Query<SampleQuery>,
) -> impl IntoResponse {
    let state = IntegrationApiState::demo();
    let samples = state.samples.read().unwrap();

    match samples.get(&integration_id) {
        Some(events) => {
            let limited: Vec<_> = events.iter().rev().take(query.limit).cloned().collect();
            Json(SampleEventsResponse {
                integration_id,
                samples: limited,
                total_available: events.len(),
            })
            .into_response()
        }
        None => (
            StatusCode::NOT_FOUND,
            Json(serde_json::json!({
                "error": "Integration not found or no samples available",
                "integration_id": integration_id
            })),
        )
            .into_response(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::body::Body;
    use axum::http::Request;
    use tower::ServiceExt;

    #[tokio::test]
    async fn test_list_integrations() {
        let state = IntegrationApiState::demo();
        let app = integration_api_router(state);

        let response = app
            .oneshot(
                Request::builder()
                    .uri("/api/integrations")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn test_get_capabilities() {
        let state = IntegrationApiState::demo();
        let app = integration_api_router(state);

        let response = app
            .oneshot(
                Request::builder()
                    .uri("/api/capabilities")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn test_get_samples() {
        let state = IntegrationApiState::demo();
        let app = integration_api_router(state);

        let response = app
            .oneshot(
                Request::builder()
                    .uri("/api/integrations/wazuh_main/sample?limit=5")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);
    }
}
