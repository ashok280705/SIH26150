//! # confidence
//!
//! Confidence engine: scoring, normalization, margin calculation, decision order,
//! and exclusive attribution ownership.

#![forbid(unsafe_code)]

pub mod config;
pub mod engine;
pub mod result;

pub use config::ConfidenceConfig;
pub use engine::ConfidenceEngine;
pub use result::{AttributionStatus, Classification, ClassifiedDetectionResult};
