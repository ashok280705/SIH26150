//! # confidence
//!
//! Confidence engine: scoring, normalization, margin calculation, decision order,
//! and exclusive attribution ownership.

#![forbid(unsafe_code)]

pub mod config;
pub mod result;
pub mod engine;

pub use config::ConfidenceConfig;
pub use result::{AttributionStatus, Classification, ClassifiedDetectionResult};
pub use engine::ConfidenceEngine;
