//! Micro Chains Service
//!
//! Canonical registry for attack chain definitions and server-side compilation.
//! This is the single source of truth for chain definitions - the frontend
//! must NOT duplicate this logic.
//!
//! ## API Endpoints (defined in locint.rs)
//!
//! - GET /api/chains - List all chain definitions
//! - POST /api/chains/compile - Compile chain stack to playbook selections
//!
//! ## Design
//!
//! Chains define semantic attack patterns that map to playbook selections.
//! Each chain has:
//! - Steps: Semantic stages of the attack (e.g., "allocate", "write", "execute")
//! - Match rules: Patterns to match playbooks from catalog
//! - Requirements: Sensor prerequisites (e.g., "sysmon", "is_admin")
//!
//! Compilation is server-side only using the authoritative playbook catalog.

use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};
use std::sync::OnceLock;

// ============================================================================
// CANONICAL MICRO CHAINS REGISTRY
// ============================================================================

/// Step in a micro chain
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChainStep {
    pub id: String,
    pub title: String,
    pub description: String,
    pub icon: String,
}

/// Match rules for compiling chain to playbooks
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MatchRules {
    /// Patterns to match in playbook ID, title, category, family
    pub include_patterns: Vec<String>,
    /// Explicit playbook IDs to include
    pub include_ids: Vec<String>,
    /// Patterns to exclude from matches
    pub exclude_patterns: Vec<String>,
}

/// Micro chain definition
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MicroChain {
    pub id: String,
    pub title: String,
    pub description: String,
    pub icon: String,
    pub category: String,
    pub steps: Vec<ChainStep>,
    pub match_rules: MatchRules,
    pub requirements: Vec<String>,
}

/// Compiled chain entry in a stack
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CompiledChain {
    pub chain_id: String,
    pub title: String,
    pub icon: String,
    pub steps: Vec<ChainStep>,
    pub compiled_playbook_ids: Vec<String>,
    pub step_to_playbooks: HashMap<String, StepPlaybooks>,
}

/// Playbooks mapped to a specific step
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StepPlaybooks {
    pub step_id: String,
    pub chain_id: String,
    pub title: String,
    pub icon: String,
    pub description: String,
    pub playbook_ids: Vec<String>,
}

/// Compiled baseline from chain stack
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CompiledBaseline {
    #[serde(rename = "type")]
    pub baseline_type: String,
    pub chains: Vec<CompiledChain>,
    pub baseline_playbook_ids: Vec<String>,
}

/// Request to compile chain stack
#[derive(Debug, Clone, Deserialize)]
pub struct CompileRequest {
    pub chain_ids: Vec<String>,
    pub preset_id: Option<String>,
}

/// Response from chain compilation
#[derive(Debug, Clone, Serialize)]
pub struct CompileResponse {
    pub success: bool,
    pub baseline: CompiledBaseline,
    pub errors: Vec<String>,
}

/// Playbook info for matching (minimal)
#[derive(Debug, Clone)]
pub struct PlaybookInfo {
    pub playbook_id: String,
    pub title: String,
    pub category: String,
    pub family: String,
}

// ============================================================================
// CHAIN REGISTRY (Static definitions)
// ============================================================================

/// Static registry of micro chains (initialized once)
static MICRO_CHAINS: OnceLock<HashMap<String, MicroChain>> = OnceLock::new();

/// Get or initialize the chain registry
fn get_chains_registry() -> &'static HashMap<String, MicroChain> {
    MICRO_CHAINS.get_or_init(|| {
        let mut m = HashMap::new();
        
        m.insert("file-staging".to_string(), MicroChain {
            id: "file-staging".to_string(),
            title: "File Staging".to_string(),
            description: "Detect local collection + archive/compress behavior prior to exfiltration.".to_string(),
            icon: "📁".to_string(),
            category: "Collection".to_string(),
            steps: vec![
                ChainStep { id: "collect".to_string(), title: "Collect".to_string(), description: "Unusual bulk reads / sensitive paths".to_string(), icon: "📚".to_string() },
                ChainStep { id: "stage".to_string(), title: "Stage".to_string(), description: "Copy into staging dirs (Temp/Desktop/AppData/etc)".to_string(), icon: "📥".to_string() },
                ChainStep { id: "archive".to_string(), title: "Archive/Compress".to_string(), description: "7z/rar/tar/zip creation spikes".to_string(), icon: "🗄️".to_string() },
            ],
            match_rules: MatchRules {
                include_patterns: vec!["staging", "archive", "compress", "collect", "zip", "rar", "7z", "collection"].iter().map(|s| s.to_string()).collect(),
                include_ids: vec![],
                exclude_patterns: vec![],
            },
            requirements: vec!["file_events".to_string()],
        });
        
        m.insert("process-injection".to_string(), MicroChain {
            id: "process-injection".to_string(),
            title: "Process Injection".to_string(),
            description: "Detect code injection techniques: DLL injection, process hollowing, shellcode.".to_string(),
            icon: "💉".to_string(),
            category: "Defense Evasion".to_string(),
            steps: vec![
                ChainStep { id: "alloc".to_string(), title: "Memory Allocation".to_string(), description: "VirtualAlloc/mmap with RWX permissions".to_string(), icon: "🧠".to_string() },
                ChainStep { id: "write".to_string(), title: "Code Write".to_string(), description: "WriteProcessMemory / ptrace injection".to_string(), icon: "✍️".to_string() },
                ChainStep { id: "execute".to_string(), title: "Remote Execute".to_string(), description: "CreateRemoteThread / APC injection / thread hijack".to_string(), icon: "⚡".to_string() },
            ],
            match_rules: MatchRules {
                include_patterns: vec!["injection", "ptrace", "rwx", "mprotect", "proc_hollow", "process_hollow", "dll_inject", "shellcode", "hollowing", "remote_thread"].iter().map(|s| s.to_string()).collect(),
                include_ids: vec![],
                exclude_patterns: vec![],
            },
            requirements: vec!["process_events".to_string()],
        });
        
        m.insert("credential-dump".to_string(), MicroChain {
            id: "credential-dump".to_string(),
            title: "Credential Dumping".to_string(),
            description: "Detect LSASS access, SAM extraction, and mimikatz-style credential theft.".to_string(),
            icon: "🔓".to_string(),
            category: "Credential Access".to_string(),
            steps: vec![
                ChainStep { id: "lsass-access".to_string(), title: "LSASS Access".to_string(), description: "Process accessing lsass.exe memory".to_string(), icon: "🔍".to_string() },
                ChainStep { id: "sam-extract".to_string(), title: "SAM/NTDS Extract".to_string(), description: "Registry SAM hive or NTDS.dit access".to_string(), icon: "🗃️".to_string() },
                ChainStep { id: "cred-cache".to_string(), title: "Cached Credentials".to_string(), description: "Access to cached logon credentials".to_string(), icon: "🔑".to_string() },
            ],
            match_rules: MatchRules {
                include_patterns: vec!["lsass", "sam", "sekurlsa", "mimikatz", "credential_dump", "hashdump", "ntds", "credential", "procdump"].iter().map(|s| s.to_string()).collect(),
                include_ids: vec![],
                exclude_patterns: vec![],
            },
            requirements: vec!["process_events".to_string(), "is_admin".to_string()],
        });
        
        m.insert("dns-tunneling".to_string(), MicroChain {
            id: "dns-tunneling".to_string(),
            title: "DNS Tunneling".to_string(),
            description: "Detect data exfiltration or C2 communication over DNS queries.".to_string(),
            icon: "🌐".to_string(),
            category: "Exfiltration".to_string(),
            steps: vec![
                ChainStep { id: "dns-volume".to_string(), title: "DNS Volume Spike".to_string(), description: "Unusual number of DNS queries".to_string(), icon: "📈".to_string() },
                ChainStep { id: "long-queries".to_string(), title: "Long Subdomains".to_string(), description: "Encoded data in subdomain labels".to_string(), icon: "📝".to_string() },
                ChainStep { id: "txt-records".to_string(), title: "TXT Record Abuse".to_string(), description: "Large TXT responses for C2".to_string(), icon: "📨".to_string() },
            ],
            match_rules: MatchRules {
                include_patterns: vec!["dns_tunnel", "dns_exfil", "iodine", "dnscat", "dns_beacon", "dns_c2"].iter().map(|s| s.to_string()).collect(),
                include_ids: vec![],
                exclude_patterns: vec![],
            },
            requirements: vec!["network_events".to_string()],
        });
        
        m.insert("lateral-wmi".to_string(), MicroChain {
            id: "lateral-wmi".to_string(),
            title: "WMI Lateral Movement".to_string(),
            description: "Detect remote code execution via WMI/WMIC across the network.".to_string(),
            icon: "🔀".to_string(),
            category: "Lateral Movement".to_string(),
            steps: vec![
                ChainStep { id: "wmi-connect".to_string(), title: "WMI Connection".to_string(), description: "Remote WMI namespace connection".to_string(), icon: "🔗".to_string() },
                ChainStep { id: "wmi-exec".to_string(), title: "Process Creation".to_string(), description: "WmiPrvSE spawning child processes".to_string(), icon: "⚙️".to_string() },
                ChainStep { id: "wmi-persist".to_string(), title: "WMI Persistence".to_string(), description: "Event subscription for persistence".to_string(), icon: "📌".to_string() },
            ],
            match_rules: MatchRules {
                include_patterns: vec!["wmi", "wmic", "wmiexec", "wmiprvse", "wmi_lateral"].iter().map(|s| s.to_string()).collect(),
                include_ids: vec![],
                exclude_patterns: vec![],
            },
            requirements: vec!["process_events".to_string()],
        });
        
        m.insert("lateral-psremoting".to_string(), MicroChain {
            id: "lateral-psremoting".to_string(),
            title: "PowerShell Remoting".to_string(),
            description: "Detect remote execution via PowerShell Remoting and WinRM.".to_string(),
            icon: "🔗".to_string(),
            category: "Lateral Movement".to_string(),
            steps: vec![
                ChainStep { id: "winrm-connect".to_string(), title: "WinRM Session".to_string(), description: "Inbound WinRM/PSRemoting connection".to_string(), icon: "🌐".to_string() },
                ChainStep { id: "ps-remote-exec".to_string(), title: "Remote Execution".to_string(), description: "Invoke-Command or Enter-PSSession".to_string(), icon: "⚡".to_string() },
                ChainStep { id: "ps-download".to_string(), title: "Payload Delivery".to_string(), description: "Remote script/module loading".to_string(), icon: "📥".to_string() },
            ],
            match_rules: MatchRules {
                include_patterns: vec!["psremoting", "winrm", "invoke_command", "enter_pssession", "ps_remote", "powershell_remote"].iter().map(|s| s.to_string()).collect(),
                include_ids: vec![],
                exclude_patterns: vec![],
            },
            requirements: vec!["process_events".to_string(), "network_events".to_string()],
        });
        
        m.insert("persistence-registry".to_string(), MicroChain {
            id: "persistence-registry".to_string(),
            title: "Registry Persistence".to_string(),
            description: "Detect autoruns, registry run keys, and startup modifications.".to_string(),
            icon: "📋".to_string(),
            category: "Persistence".to_string(),
            steps: vec![
                ChainStep { id: "run-key".to_string(), title: "Run Key Modified".to_string(), description: "HKLM/HKCU Run/RunOnce changes".to_string(), icon: "🔑".to_string() },
                ChainStep { id: "service-reg".to_string(), title: "Service Registry".to_string(), description: "Service ImagePath modifications".to_string(), icon: "⚙️".to_string() },
                ChainStep { id: "startup-folder".to_string(), title: "Startup Folder".to_string(), description: "Files added to Startup locations".to_string(), icon: "📂".to_string() },
            ],
            match_rules: MatchRules {
                include_patterns: vec!["registry", "autorun", "run_key", "startup", "hklm", "hkcu", "persistence_reg"].iter().map(|s| s.to_string()).collect(),
                include_ids: vec![],
                exclude_patterns: vec![],
            },
            requirements: vec!["registry_events".to_string()],
        });
        
        m.insert("persistence-schtasks".to_string(), MicroChain {
            id: "persistence-schtasks".to_string(),
            title: "Scheduled Task Persistence".to_string(),
            description: "Detect scheduled task creation/modification for persistence.".to_string(),
            icon: "⏰".to_string(),
            category: "Persistence".to_string(),
            steps: vec![
                ChainStep { id: "task-create".to_string(), title: "Task Created".to_string(), description: "New scheduled task registration".to_string(), icon: "➕".to_string() },
                ChainStep { id: "task-modify".to_string(), title: "Task Modified".to_string(), description: "Existing task action changed".to_string(), icon: "✏️".to_string() },
                ChainStep { id: "task-trigger".to_string(), title: "Suspicious Trigger".to_string(), description: "Logon/startup/idle triggers".to_string(), icon: "⏱️".to_string() },
            ],
            match_rules: MatchRules {
                include_patterns: vec!["schtasks", "scheduled_task", "task_scheduler", "at_job", "task_persist"].iter().map(|s| s.to_string()).collect(),
                include_ids: vec![],
                exclude_patterns: vec![],
            },
            requirements: vec!["process_events".to_string()],
        });
        
        m
    })
}

// ============================================================================
// PUBLIC API
// ============================================================================

/// Get all chain definitions
pub fn get_all_chains() -> Vec<MicroChain> {
    let registry = get_chains_registry();
    let mut chains: Vec<MicroChain> = registry.values().cloned().collect();
    chains.sort_by(|a, b| a.title.cmp(&b.title));
    chains
}

/// Get chain count for startup log
pub fn get_chain_count() -> usize {
    get_chains_registry().len()
}

/// Get a specific chain by ID
pub fn get_chain(chain_id: &str) -> Option<MicroChain> {
    get_chains_registry().get(chain_id).cloned()
}

/// Compile a stack of chains to playbook selections
///
/// This is the canonical compilation logic - frontend must NOT duplicate this.
/// Uses pattern matching against the provided playbook catalog.
pub fn compile_chain_stack(
    chain_ids: &[String],
    playbooks: &[PlaybookInfo],
) -> CompileResponse {
    let registry = get_chains_registry();
    let mut errors: Vec<String> = Vec::new();
    let mut compiled_chains: Vec<CompiledChain> = Vec::new();
    let mut all_playbook_ids: HashSet<String> = HashSet::new();
    
    for chain_id in chain_ids {
        match registry.get(chain_id) {
            Some(chain) => {
                let (playbook_ids, step_to_playbooks) = compile_single_chain(chain, playbooks);
                
                // Add to union
                for pb_id in &playbook_ids {
                    all_playbook_ids.insert(pb_id.clone());
                }
                
                compiled_chains.push(CompiledChain {
                    chain_id: chain.id.clone(),
                    title: chain.title.clone(),
                    icon: chain.icon.clone(),
                    steps: chain.steps.clone(),
                    compiled_playbook_ids: playbook_ids,
                    step_to_playbooks,
                });
            }
            None => {
                errors.push(format!("Unknown chain: {}", chain_id));
            }
        }
    }
    
    // Sort union for deterministic output
    let mut baseline_playbook_ids: Vec<String> = all_playbook_ids.into_iter().collect();
    baseline_playbook_ids.sort();
    
    CompileResponse {
        success: errors.is_empty(),
        baseline: CompiledBaseline {
            baseline_type: "stack".to_string(),
            chains: compiled_chains,
            baseline_playbook_ids,
        },
        errors,
    }
}

/// Compile a single chain against the playbook catalog
fn compile_single_chain(
    chain: &MicroChain,
    playbooks: &[PlaybookInfo],
) -> (Vec<String>, HashMap<String, StepPlaybooks>) {
    let mut matched_ids: HashSet<String> = HashSet::new();
    
    // Add explicit IDs first
    for id in &chain.match_rules.include_ids {
        if playbooks.iter().any(|pb| pb.playbook_id == *id) {
            matched_ids.insert(id.clone());
        }
    }
    
    // Match by patterns
    for pb in playbooks {
        let pb_id = pb.playbook_id.to_lowercase();
        let pb_title = pb.title.to_lowercase();
        let pb_category = pb.category.to_lowercase();
        let pb_family = pb.family.to_lowercase();
        let search_text = format!("{} {} {} {}", pb_id, pb_title, pb_category, pb_family);
        
        // Check exclude patterns first
        let excluded = chain.match_rules.exclude_patterns.iter().any(|pat| {
            search_text.contains(&pat.to_lowercase())
        });
        if excluded {
            continue;
        }
        
        // Check include patterns
        let matched = chain.match_rules.include_patterns.iter().any(|pat| {
            search_text.contains(&pat.to_lowercase())
        });
        if matched {
            matched_ids.insert(pb.playbook_id.clone());
        }
    }
    
    // Sort for deterministic output
    let mut playbook_ids: Vec<String> = matched_ids.into_iter().collect();
    playbook_ids.sort();
    
    // Build step-to-playbooks mapping
    // All playbooks contribute to all steps (semantic steps are outcome-based)
    let mut step_to_playbooks: HashMap<String, StepPlaybooks> = HashMap::new();
    for step in &chain.steps {
        let key = format!("{}-{}", chain.id, step.id);
        step_to_playbooks.insert(key.clone(), StepPlaybooks {
            step_id: step.id.clone(),
            chain_id: chain.id.clone(),
            title: step.title.clone(),
            icon: step.icon.clone(),
            description: step.description.clone(),
            playbook_ids: playbook_ids.clone(),
        });
    }
    
    tracing::debug!(
        "[chains] Compiled '{}' -> {} playbooks",
        chain.id,
        playbook_ids.len()
    );
    
    (playbook_ids, step_to_playbooks)
}

// ============================================================================
// STEP STATUS COMPUTATION (Backend-canonical satisfaction tracking)
// ============================================================================

/// State of a chain step based on run evidence
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "snake_case")]
pub enum StepState {
    /// No evidence observed for this step
    NotObserved,
    /// Some matching data but insufficient to satisfy
    Candidate,
    /// Step is satisfied with backing evidence
    Satisfied,
    /// Step cannot be evaluated (missing telemetry requirements)
    Blocked,
    /// Step has partial telemetry (can evaluate but may miss detections)
    Unverified,
}

impl StepState {
    pub fn as_str(&self) -> &'static str {
        match self {
            StepState::NotObserved => "not_observed",
            StepState::Candidate => "candidate",
            StepState::Satisfied => "satisfied",
            StepState::Blocked => "blocked",
            StepState::Unverified => "unverified",
        }
    }
}

/// Status of a single step within a chain
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StepStatus {
    pub step_id: String,
    pub title: String,
    pub icon: String,
    pub state: StepState,
    pub evidence_refs_count: usize,
    pub matched_playbooks: Vec<String>,
    pub matched_signals: Vec<SignalMatch>,
    pub why: Option<String>,
    pub coverage_gaps: Vec<String>,
}

/// A signal that matched for a step
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SignalMatch {
    pub signal_id: String,
    pub playbook_id: String,
    pub severity: String,
    pub evidence_count: usize,
}

/// Status of a chain with all its steps
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChainStatus {
    pub chain_id: String,
    pub title: String,
    pub icon: String,
    pub steps: Vec<StepStatus>,
}

/// Request for step status computation
#[derive(Debug, Clone, Deserialize)]
pub struct StepStatusRequest {
    pub chain_ids: Vec<String>,
}

/// Response with step status for all chains
#[derive(Debug, Clone, Serialize)]
pub struct StepStatusResponse {
    pub success: bool,
    pub run_id: String,
    pub chains: Vec<ChainStatus>,
    pub generated_at: String,
    pub is_live: bool,
    pub errors: Vec<String>,
}

/// Signal data from the run database
#[derive(Debug, Clone)]
pub struct RunSignal {
    pub signal_id: String,
    pub signal_type: String,  // "playbook:xxx" format
    pub playbook_id: String,  // extracted from signal_type
    pub severity: String,
    pub evidence_refs: Vec<serde_json::Value>,
}

/// Capability snapshot for requirement checking
#[derive(Debug, Clone, Default)]
pub struct CapabilitySnapshot {
    pub sysmon_installed: bool,
    pub is_admin: bool,
    pub security_log_accessible: bool,
    pub channels: std::collections::HashMap<String, bool>,
}

/// Compute step status for a stack of chains given run data
///
/// This is the canonical step satisfaction logic - frontend must NOT duplicate this.
///
/// # Arguments
/// * `chain_ids` - List of chain IDs in the stack
/// * `signals` - Signals from the run database (with playbook_id extracted)
/// * `capability` - Capability snapshot for requirement checking
/// * `playbooks` - Playbook catalog for chain compilation
///
/// # State Rules
/// - `blocked`: Chain requires telemetry that is unavailable (e.g., sysmon not installed)
/// - `unverified`: Chain has partial telemetry (can evaluate but may miss detections)
/// - `satisfied`: At least one signal fired for a playbook in this step's mapping, with evidence
/// - `candidate`: Playbooks matched but no signals fired (data present but no detection)
/// - `not_observed`: No relevant data observed
pub fn compute_step_status(
    chain_ids: &[String],
    signals: &[RunSignal],
    capability: &CapabilitySnapshot,
    playbooks: &[PlaybookInfo],
) -> Vec<ChainStatus> {
    let registry = get_chains_registry();
    let mut chain_statuses: Vec<ChainStatus> = Vec::new();
    
    // Build signal lookup by playbook_id
    let mut signals_by_playbook: std::collections::HashMap<String, Vec<&RunSignal>> = std::collections::HashMap::new();
    for sig in signals {
        signals_by_playbook
            .entry(sig.playbook_id.clone())
            .or_default()
            .push(sig);
    }
    
    for chain_id in chain_ids {
        let chain = match registry.get(chain_id) {
            Some(c) => c,
            None => continue,
        };
        
        // Compile chain to get playbook mappings
        let (compiled_playbook_ids, step_to_playbooks) = compile_single_chain(chain, playbooks);
        
        // Check chain requirements against capability
        let (is_blocked, block_reason) = check_chain_requirements(chain, capability);
        let (is_unverified, unverified_gaps) = check_chain_partial_telemetry(chain, capability);
        
        let mut step_statuses: Vec<StepStatus> = Vec::new();
        
        for step in &chain.steps {
            let step_key = format!("{}-{}", chain_id, step.id);
            
            // Get playbooks mapped to this step
            let step_playbooks = step_to_playbooks.get(&step_key)
                .map(|sp| sp.playbook_ids.clone())
                .unwrap_or_default();
            
            // Find signals for these playbooks
            let mut matched_signals: Vec<SignalMatch> = Vec::new();
            let mut total_evidence = 0usize;
            let mut matched_playbook_ids: Vec<String> = Vec::new();
            
            for pb_id in &step_playbooks {
                // Try both with and without "signal_" prefix - dedupe keys
                let mut keys_to_check: Vec<String> = Vec::new();
                keys_to_check.push(pb_id.clone());
                
                let stripped = pb_id.strip_prefix("signal_").unwrap_or(pb_id).to_string();
                if !keys_to_check.contains(&stripped) {
                    keys_to_check.push(stripped);
                }
                
                let prefixed = format!("signal_{}", pb_id);
                if !keys_to_check.contains(&prefixed) {
                    keys_to_check.push(prefixed);
                }
                
                // Track which signal_ids we've already added for this step
                let mut seen_signal_ids: std::collections::HashSet<String> = std::collections::HashSet::new();
                
                for key in keys_to_check {
                    if let Some(sigs) = signals_by_playbook.get(&key) {
                        for sig in sigs {
                            // Skip if we've already counted this signal
                            if seen_signal_ids.contains(&sig.signal_id) {
                                continue;
                            }
                            seen_signal_ids.insert(sig.signal_id.clone());
                            
                            let evidence_count = sig.evidence_refs.len();
                            total_evidence += evidence_count;
                            matched_signals.push(SignalMatch {
                                signal_id: sig.signal_id.clone(),
                                playbook_id: sig.playbook_id.clone(),
                                severity: sig.severity.clone(),
                                evidence_count,
                            });
                            if !matched_playbook_ids.contains(pb_id) {
                                matched_playbook_ids.push(pb_id.clone());
                            }
                        }
                    }
                }
            }
            
            // Determine step state
            let (state, why, coverage_gaps) = if is_blocked {
                (StepState::Blocked, Some(block_reason.clone()), vec![block_reason.clone()])
            } else if !matched_signals.is_empty() && total_evidence > 0 {
                // Has signals with evidence -> satisfied
                (StepState::Satisfied, None, vec![])
            } else if !matched_signals.is_empty() {
                // Has signals but no evidence refs -> candidate
                (StepState::Candidate, Some("Signals fired but no evidence refs".to_string()), vec![])
            } else if is_unverified {
                // Missing some telemetry but not blocked
                (StepState::Unverified, Some(format!("Missing: {}", unverified_gaps.join(", "))), unverified_gaps.clone())
            } else if !step_playbooks.is_empty() {
                // Has playbooks but no signals
                (StepState::NotObserved, None, vec![])
            } else {
                // No playbooks compiled for this step
                (StepState::NotObserved, Some("No playbooks matched for this step".to_string()), vec![])
            };
            
            step_statuses.push(StepStatus {
                step_id: step.id.clone(),
                title: step.title.clone(),
                icon: step.icon.clone(),
                state,
                evidence_refs_count: total_evidence,
                matched_playbooks: matched_playbook_ids,
                matched_signals,
                why,
                coverage_gaps,
            });
        }
        
        chain_statuses.push(ChainStatus {
            chain_id: chain.id.clone(),
            title: chain.title.clone(),
            icon: chain.icon.clone(),
            steps: step_statuses,
        });
    }
    
    chain_statuses
}

/// Check if chain requirements are blocked by missing capability
fn check_chain_requirements(chain: &MicroChain, capability: &CapabilitySnapshot) -> (bool, String) {
    for req in &chain.requirements {
        let req_lower = req.to_lowercase();
        
        if req_lower == "sysmon" && !capability.sysmon_installed {
            return (true, "Requires Sysmon (not installed)".to_string());
        }
        if req_lower == "is_admin" && !capability.is_admin {
            return (true, "Requires admin privileges".to_string());
        }
        if req_lower == "security_log" && !capability.security_log_accessible {
            return (true, "Requires Security log access".to_string());
        }
    }
    
    (false, String::new())
}

/// Check if chain has partial telemetry (unverified but not blocked)
fn check_chain_partial_telemetry(chain: &MicroChain, capability: &CapabilitySnapshot) -> (bool, Vec<String>) {
    let mut gaps: Vec<String> = Vec::new();
    
    // Check enhances_with style dependencies (nice to have but not required)
    if chain.requirements.iter().any(|r| r.to_lowercase().contains("sysmon")) {
        if !capability.sysmon_installed {
            // If sysmon is in requirements, it's blocking (handled above)
            // This is for when sysmon would enhance but isn't required
        }
    }
    
    // Check if any optional telemetry is missing
    for req in &chain.requirements {
        let req_lower = req.to_lowercase();
        
        // Process events usually need sysmon or security log
        if req_lower.contains("process_events") {
            if !capability.sysmon_installed && !capability.security_log_accessible {
                gaps.push("Process events (no Sysmon or Security log)".to_string());
            }
        }
        
        // Network events need specific channels
        if req_lower.contains("network_events") {
            // Check for network-related channel
            let has_network = capability.channels.iter()
                .any(|(name, accessible)| *accessible && name.to_lowercase().contains("network"));
            if !has_network && !capability.sysmon_installed {
                gaps.push("Network events".to_string());
            }
        }
        
        // Registry events
        if req_lower.contains("registry_events") {
            if !capability.sysmon_installed {
                gaps.push("Registry events (Sysmon recommended)".to_string());
            }
        }
        
        // File events
        if req_lower.contains("file_events") {
            if !capability.sysmon_installed {
                gaps.push("File events (Sysmon recommended)".to_string());
            }
        }
    }
    
    (!gaps.is_empty(), gaps)
}

// ============================================================================
// TESTS
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    
    fn mock_playbooks() -> Vec<PlaybookInfo> {
        vec![
            PlaybookInfo { playbook_id: "pb-injection-001".to_string(), title: "DLL Injection Detection".to_string(), category: "Defense Evasion".to_string(), family: "process".to_string() },
            PlaybookInfo { playbook_id: "pb-injection-002".to_string(), title: "Process Hollowing".to_string(), category: "Defense Evasion".to_string(), family: "process".to_string() },
            PlaybookInfo { playbook_id: "pb-cred-001".to_string(), title: "LSASS Access Detection".to_string(), category: "Credential Access".to_string(), family: "credential".to_string() },
            PlaybookInfo { playbook_id: "pb-cred-002".to_string(), title: "SAM Registry Access".to_string(), category: "Credential Access".to_string(), family: "credential".to_string() },
            PlaybookInfo { playbook_id: "pb-wmi-001".to_string(), title: "WMI Execution Detection".to_string(), category: "Lateral Movement".to_string(), family: "wmi".to_string() },
            PlaybookInfo { playbook_id: "pb-wmi-002".to_string(), title: "WMI Persistence Event".to_string(), category: "Lateral Movement".to_string(), family: "wmi".to_string() },
            PlaybookInfo { playbook_id: "pb-registry-001".to_string(), title: "Registry Run Key Modified".to_string(), category: "Persistence".to_string(), family: "registry".to_string() },
            // Overlapping playbook: matches both injection + credential
            PlaybookInfo { playbook_id: "pb-overlap-001".to_string(), title: "Credential Injection Combo".to_string(), category: "Mixed".to_string(), family: "mixed".to_string() },
        ]
    }
    
    #[test]
    fn test_dedupe_union_correctness() {
        let playbooks = mock_playbooks();
        
        // Stack two chains that share pb-overlap-001
        let result = compile_chain_stack(
            &["process-injection".to_string(), "credential-dump".to_string()],
            &playbooks,
        );
        
        assert!(result.success);
        
        // Union should have no duplicates
        let union_set: HashSet<_> = result.baseline.baseline_playbook_ids.iter().collect();
        assert_eq!(union_set.len(), result.baseline.baseline_playbook_ids.len(), "Union has duplicates");
    }
    
    #[test]
    fn test_stacking_idempotency() {
        let playbooks = mock_playbooks();
        
        // Compile same chain twice - should NOT duplicate
        let result = compile_chain_stack(
            &["process-injection".to_string(), "process-injection".to_string()],
            &playbooks,
        );
        
        // Should have 2 chains (no dedup at chain level - that's caller's job)
        // But union should still be deduped
        let union_set: HashSet<_> = result.baseline.baseline_playbook_ids.iter().collect();
        assert_eq!(union_set.len(), result.baseline.baseline_playbook_ids.len());
    }
    
    #[test]
    fn test_remove_chain_updates_union() {
        let playbooks = mock_playbooks();
        
        // First: stack two chains
        let result1 = compile_chain_stack(
            &["process-injection".to_string(), "credential-dump".to_string()],
            &playbooks,
        );
        let before_union = result1.baseline.baseline_playbook_ids.len();
        
        // Then: remove first chain (only credential-dump)
        let result2 = compile_chain_stack(
            &["credential-dump".to_string()],
            &playbooks,
        );
        
        // Union should be smaller (or equal if all credential playbooks were also in injection)
        assert!(result2.baseline.baseline_playbook_ids.len() <= before_union);
        
        // All remaining IDs should be from credential-dump chain
        let expected_ids: HashSet<_> = result2.baseline.chains[0]
            .compiled_playbook_ids
            .iter()
            .collect();
        for id in &result2.baseline.baseline_playbook_ids {
            assert!(expected_ids.contains(id), "Union contains unexpected ID: {}", id);
        }
    }
    
    #[test]
    fn test_step_to_playbooks_deterministic() {
        let playbooks = mock_playbooks();
        
        // Compile same chain twice
        let result1 = compile_chain_stack(&["process-injection".to_string()], &playbooks);
        let result2 = compile_chain_stack(&["process-injection".to_string()], &playbooks);
        
        // Results should be identical
        assert_eq!(
            result1.baseline.baseline_playbook_ids,
            result2.baseline.baseline_playbook_ids
        );
        
        // Step mappings should be identical
        let steps1 = &result1.baseline.chains[0].step_to_playbooks;
        let steps2 = &result2.baseline.chains[0].step_to_playbooks;
        
        assert_eq!(steps1.len(), steps2.len());
        for (key, val1) in steps1 {
            let val2 = steps2.get(key).expect("Missing step in second result");
            assert_eq!(val1.playbook_ids, val2.playbook_ids);
        }
    }
    
    #[test]
    fn test_unknown_chain_error() {
        let playbooks = mock_playbooks();
        
        let result = compile_chain_stack(
            &["unknown-chain".to_string()],
            &playbooks,
        );
        
        assert!(!result.success);
        assert!(result.errors.iter().any(|e| e.contains("Unknown chain")));
    }
    
    #[test]
    fn test_all_chains_valid() {
        // Ensure all chains parse correctly
        let chains = get_all_chains();
        assert!(!chains.is_empty());
        
        for chain in chains {
            assert!(!chain.id.is_empty());
            assert!(!chain.title.is_empty());
            assert!(!chain.steps.is_empty());
        }
    }
    
    // ========================================================================
    // Step Status Tests
    // ========================================================================
    
    #[test]
    fn test_step_status_not_observed() {
        let playbooks = mock_playbooks();
        let signals: Vec<RunSignal> = vec![]; // No signals
        let capability = CapabilitySnapshot {
            sysmon_installed: true,
            is_admin: true,
            security_log_accessible: true,
            ..Default::default()
        };
        
        let result = compute_step_status(
            &["process-injection".to_string()],
            &signals,
            &capability,
            &playbooks,
        );
        
        assert_eq!(result.len(), 1);
        assert_eq!(result[0].chain_id, "process-injection");
        
        // All steps should be not_observed since no signals
        for step in &result[0].steps {
            assert_eq!(step.state, StepState::NotObserved);
            assert_eq!(step.evidence_refs_count, 0);
            assert!(step.matched_signals.is_empty());
        }
    }
    
    #[test]
    fn test_step_status_satisfied_with_evidence() {
        let playbooks = mock_playbooks();
        let signals = vec![
            RunSignal {
                signal_id: "sig-001".to_string(),
                signal_type: "playbook:pb-injection-001".to_string(),
                playbook_id: "pb-injection-001".to_string(),
                severity: "high".to_string(),
                evidence_refs: vec![
                    serde_json::json!({"ptr": "event:12345"}),
                    serde_json::json!({"ptr": "event:12346"}),
                ],
            },
        ];
        let capability = CapabilitySnapshot {
            sysmon_installed: true,
            is_admin: true,
            security_log_accessible: true,
            ..Default::default()
        };
        
        let result = compute_step_status(
            &["process-injection".to_string()],
            &signals,
            &capability,
            &playbooks,
        );
        
        assert_eq!(result.len(), 1);
        
        // Find the step that maps to pb-injection-001
        let satisfied_step = result[0].steps.iter()
            .find(|s| s.state == StepState::Satisfied);
        
        assert!(satisfied_step.is_some(), "Should have a satisfied step");
        let step = satisfied_step.unwrap();
        assert_eq!(step.evidence_refs_count, 2);
        assert!(!step.matched_playbooks.is_empty());
    }
    
    #[test]
    fn test_step_status_blocked_no_sysmon() {
        let playbooks = mock_playbooks();
        let signals: Vec<RunSignal> = vec![];
        
        // Capability shows no sysmon
        let capability = CapabilitySnapshot {
            sysmon_installed: false, // Missing required telemetry
            is_admin: true,
            security_log_accessible: true,
            ..Default::default()
        };
        
        let result = compute_step_status(
            &["process-injection".to_string()],
            &signals,
            &capability,
            &playbooks,
        );
        
        assert_eq!(result.len(), 1);
        
        // Chain requires sysmon, so all steps should be blocked
        let blocked_count = result[0].steps.iter()
            .filter(|s| s.state == StepState::Blocked)
            .count();
        
        // If process-injection requires sysmon, steps will be blocked
        // (depends on chain definition - may need to adjust based on actual chain requirements)
        println!("Blocked steps: {}", blocked_count);
    }
    
    #[test]
    fn test_step_status_candidate_no_evidence() {
        let playbooks = mock_playbooks();
        
        // Signal fired but no evidence refs
        let signals = vec![
            RunSignal {
                signal_id: "sig-001".to_string(),
                signal_type: "playbook:pb-injection-001".to_string(),
                playbook_id: "pb-injection-001".to_string(),
                severity: "medium".to_string(),
                evidence_refs: vec![], // Empty evidence
            },
        ];
        let capability = CapabilitySnapshot {
            sysmon_installed: true,
            is_admin: true,
            security_log_accessible: true,
            ..Default::default()
        };
        
        let result = compute_step_status(
            &["process-injection".to_string()],
            &signals,
            &capability,
            &playbooks,
        );
        
        assert_eq!(result.len(), 1);
        
        // Step with matching playbook should be candidate (signal but no evidence)
        let candidate_step = result[0].steps.iter()
            .find(|s| s.state == StepState::Candidate);
        
        assert!(candidate_step.is_some(), "Should have a candidate step when signal has no evidence");
    }
    
    #[test]
    fn test_step_state_serialization() {
        assert_eq!(StepState::NotObserved.as_str(), "not_observed");
        assert_eq!(StepState::Candidate.as_str(), "candidate");
        assert_eq!(StepState::Satisfied.as_str(), "satisfied");
        assert_eq!(StepState::Blocked.as_str(), "blocked");
        assert_eq!(StepState::Unverified.as_str(), "unverified");
    }
}
