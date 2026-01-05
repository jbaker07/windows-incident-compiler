// locald/baseline/mod.rs
// Shared baseline system for all OSes

pub mod baseline_query;
pub mod baseline_store;
pub mod baseline_update;
pub mod types;

pub use baseline_query::BaselineQuery;
pub use baseline_store::BaselineStore;
pub use baseline_update::BaselineUpdater;
pub use types::HostBaseline;
