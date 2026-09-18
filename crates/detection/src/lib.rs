//! # detection
//!
//! Multi-vendor storage structure detectors, topology profiling, and the Detection_Orchestrator.

#![forbid(unsafe_code)]

pub mod output;
pub mod detector;
pub mod topology;
pub mod detectors;
pub mod orchestrator;

pub use output::{DetectionStatus, DetectorOutput};
pub use detector::Detector;
pub use topology::{PartitionCandidate, StorageTopology, StorageTopologyProfiler, TopologyType};
pub use orchestrator::DetectionOrchestrator;
pub use detectors::{CpPlusUbsDetector, DahuaDetector, HikvisionDetector, HoneywellDetector, UniviewDetector, TplinkDetector};
