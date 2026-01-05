// locald/scoring/mod.rs
// Advanced scoring layer: optional Mahalanobis + EllipticEnvelope + KRIM

pub mod scored_signal;
pub mod mahalanobis;
pub mod elliptic_envelope_lite;
pub mod krim_lite;
pub mod scoring_engine;

pub use scored_signal::ScoredSignal;
pub use scoring_engine::ScoringEngine;
