//! YAML detection playbooks.
//!
//! The files in `playbooks/windows/` are the single source of detection logic
//! for edr-locald. This module loads them, validates them, and runs them.
//!
//! ```text
//! playbooks/windows/*.yaml
//!        |  loader: pick the directory, apply EDR_SELECTED_PLAYBOOKS
//!        v
//!   schema: parse, reject unknown keys, compile regexes, check ATT&CK IDs
//!        |
//!        v
//!   engine: Event -> extract_facts -> rule conditions -> PlaybookMatch
//!        |
//!        v
//!   edr-locald: signals table + signal_explanations table
//! ```

pub mod engine;
pub mod fields;
pub mod loader;
pub mod schema;

pub use engine::{MatchedFact, PlaybookEngine, PlaybookMatch};
pub use fields::{FactView, VIEW_FIELDS, WINDOWS_FACT_TYPES};
pub use loader::{
    load_dir, load_from_env, parse_selection, resolve_playbook_dir, LoadError, LoadReport,
    Platform, ResolvedDir, ENV_PLAYBOOKS_DIR, ENV_PLAYBOOK_DIR_ALIAS, ENV_SELECTED_PLAYBOOKS,
    STATUS_FILE_NAME,
};
pub use schema::{
    parse_playbook, Playbook, Rule, Severity, TechniqueRef, ATTACK_TACTICS, ATTACK_VERSION,
    RETIRED_TECHNIQUES,
};
