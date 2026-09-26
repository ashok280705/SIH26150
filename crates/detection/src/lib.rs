//! # detection
//!
//! Multi-vendor storage structure detectors, topology profiling, and the Detection_Orchestrator.

#![forbid(unsafe_code)]

pub mod detector;
pub mod detectors;
pub mod orchestrator;
pub mod output;
pub mod topology;

pub use detector::Detector;
pub use detectors::{
    CpPlusUbsDetector, DahuaDetector, HikvisionDetector, HoneywellDetector, TplinkDetector,
    UniviewDetector,
};
pub use orchestrator::DetectionOrchestrator;
pub use output::{DetectionStatus, DetectorOutput};
pub use topology::{PartitionCandidate, StorageTopology, StorageTopologyProfiler, TopologyType};
