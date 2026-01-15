//! Team Module
//!
//! This module contains Team tier features for collaborative case management.
//! All services are pure functions - the handler layer in locint.rs calls these.
//!
//! ## Sub-modules
//!
//! - `store`: Case store configuration and status
//! - `cases`: Case CRUD operations
//! - `publish`: Run publishing to case store
//! - `aggregate`: Aggregate views across runs in a case

pub mod aggregate;
pub mod cases;
pub mod publish;
pub mod store;

// Re-export commonly used items
pub use store::{CaseStoreLock, get_store_dir, safe_case_path_join};
pub use cases::generate_case_id;
