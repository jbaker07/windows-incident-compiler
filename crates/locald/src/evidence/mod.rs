//! Evidence System: Stable pointers, deref rules, and integrity verification
//!
//! EvidencePtr provides stable, replay-deterministic references to telemetry records.
//! Supports deref to canonical DB records or fallback to raw segment files.
//!
//! Ship Hardening: Path safety validation prevents directory traversal attacks.

mod deref;
mod evidence_ptr;
mod evidence_store;
pub mod path_safety;

pub use deref::{DerefResult, DerefStatus, EvidenceDeref};
pub use evidence_ptr::{EvidenceIntegrityError, EvidencePtr};
pub use evidence_store::{EvidenceStore, StoredRecord};
pub use path_safety::{
    safe_join, validate_path_component, validate_path_within_root, validate_relative_path,
    validate_segment_id, PathValidationError,
};
