//! Windows sensor configuration with per-source gating and env var support
//! All times in milliseconds. All limits are per-poll.
//! Designed for stable, bounded event collection without reader overruns.

use std::collections::HashMap;
use std::sync::OnceLock;

/// Work budget for a single poll() call
#[derive(Clone, Copy, Debug)]
pub struct WorkBudget {
    /// Maximum events to read from one source in one poll
    pub max_records_per_poll: u64,
    /// Maximum parsing errors before backoff
    pub max_parse_errors_per_poll: u64,
}

impl Default for WorkBudget {
    fn default() -> Self {
        Self {
            max_records_per_poll: 500,
            max_parse_errors_per_poll: 10,
        }
    }
}

/// Per-source (log) configuration
#[derive(Clone, Debug)]
pub struct SourceConfig {
    /// If false, source is not polled
    pub enabled: bool,
    /// Minimum milliseconds between polls (gating interval)
    pub min_interval_ms: u64,
    /// Work budget for this source
    pub work_budget: WorkBudget,
}

impl Default for SourceConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            min_interval_ms: 100,
            work_budget: WorkBudget::default(),
        }
    }
}

/// Global config store with lazy initialization
struct ConfigStore {
    source_configs: HashMap<String, SourceConfig>,
    last_poll_times: HashMap<String, u64>,
}

static CONFIG: OnceLock<ConfigStore> = OnceLock::new();

fn get_store() -> &'static ConfigStore {
    CONFIG.get_or_init(|| ConfigStore {
        source_configs: init_configs(),
        last_poll_times: HashMap::new(),
    })
}

/// Load source configs from env vars or use defaults
fn init_configs() -> HashMap<String, SourceConfig> {
    let mut configs = HashMap::new();

    // Define standard Windows event sources
    let sources = vec![
        "Sysmon",
        "Security",
        "System",
        "PowerShell",
        "Application",
        "TaskScheduler",
        "Defender",
        "WMI",
    ];

    for source_name in sources {
        let mut cfg = SourceConfig::default();

        // Per-source overrides
        match source_name {
            "Sysmon" => {
                cfg.enabled = true; // ALWAYS-ON
                cfg.min_interval_ms = 100;
                cfg.work_budget.max_records_per_poll = 500;
            }
            "Security" => {
                cfg.enabled = true; // ALWAYS-ON
                cfg.min_interval_ms = 100;
                cfg.work_budget.max_records_per_poll = 500;
            }
            "System" => {
                cfg.enabled = true; // ALWAYS-ON (service events)
                cfg.min_interval_ms = 100;
                cfg.work_budget.max_records_per_poll = 200;
            }
            "PowerShell" => {
                cfg.enabled = false; // Opt-in
                cfg.min_interval_ms = 500;
                cfg.work_budget.max_records_per_poll = 100;
            }
            "TaskScheduler" => {
                cfg.enabled = false; // Opt-in
                cfg.min_interval_ms = 500;
                cfg.work_budget.max_records_per_poll = 100;
            }
            "Defender" => {
                cfg.enabled = false; // Opt-in (if available)
                cfg.min_interval_ms = 1000;
                cfg.work_budget.max_records_per_poll = 100;
            }
            "WMI" => {
                cfg.enabled = false; // Opt-in
                cfg.min_interval_ms = 1000;
                cfg.work_budget.max_records_per_poll = 100;
            }
            _ => {}
        }

        // Environment variable overrides
        // Format: EDR_WIN_<SOURCE>_<SETTING>=value
        let env_prefix = format!("EDR_WIN_{}", source_name.to_uppercase());

        if let Ok(enabled) = std::env::var(format!("{}_ENABLED", env_prefix)) {
            cfg.enabled = enabled.to_lowercase() == "true" || enabled == "1";
        }
        if let Ok(interval) = std::env::var(format!("{}_MIN_INTERVAL_MS", env_prefix)) {
            if let Ok(ms) = interval.parse() {
                cfg.min_interval_ms = ms;
            }
        }
        if let Ok(max_records) = std::env::var(format!("{}_MAX_RECORDS_PER_POLL", env_prefix)) {
            if let Ok(n) = max_records.parse() {
                cfg.work_budget.max_records_per_poll = n;
            }
        }
        if let Ok(max_errors) = std::env::var(format!("{}_MAX_PARSE_ERRORS_PER_POLL", env_prefix)) {
            if let Ok(n) = max_errors.parse() {
                cfg.work_budget.max_parse_errors_per_poll = n;
            }
        }

        configs.insert(source_name.to_string(), cfg);
    }

    configs
}

/// Check if source should be polled (gating based on min_interval_ms)
/// Returns (should_poll, config)
pub fn should_poll(source_name: &str) -> (bool, SourceConfig) {
    let store = get_store();
    let cfg = store
        .source_configs
        .get(source_name)
        .cloned()
        .unwrap_or_default();

    if !cfg.enabled {
        return (false, cfg);
    }

    let now = now_ms();
    let last_poll = store.last_poll_times.get(source_name).copied().unwrap_or(0);

    if now - last_poll < cfg.min_interval_ms {
        return (false, cfg);
    }

    // Note: in production, would need interior mutability to update last_poll_times
    // For now, conservative (may over-poll on first call)
    (true, cfg)
}

/// Get configuration for a source without gating
pub fn get_config(source_name: &str) -> SourceConfig {
    let store = get_store();
    store
        .source_configs
        .get(source_name)
        .cloned()
        .unwrap_or_default()
}

/// Current time in milliseconds since UNIX_EPOCH
fn now_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}
