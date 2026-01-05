// workbench crate lib.rs
// Attack Documentation Workbench - capture, analyze, edit, export

pub mod api;
pub mod document;
pub mod export;
pub mod session;

pub use api::{get_technique, search_techniques, MitreTechnique, MITRE_TECHNIQUES};
pub use document::{Annotation, Document, EventSelection, Section};
pub use export::{ExportFormat, ExportOptions, Exporter};
pub use session::{CaptureSession, SessionState};
