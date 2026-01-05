// workbench/mod.rs
// Attack Documentation Workbench - Core module
// The product: capture, analyze, edit, export beautiful reports

pub mod document;
pub mod session;
pub mod export;
pub mod api;

pub use document::{Document, Section, EventSelection, Annotation};
pub use session::{CaptureSession, SessionState};
pub use export::{ExportFormat, ExportOptions, Exporter};
