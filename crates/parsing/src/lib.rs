//! # Parsing Orchestrator
//!
//! Exposes a unified interface to run all phases of an OEM parser.

pub mod orchestrator;

pub use orchestrator::{ParsingOrchestrator, ParsingResult};
pub use parsers_core::{ContainerRecord, ReconstructedStream, ReconstructionProvider};
