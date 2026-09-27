//! # parsers-core
//!
//! Core parsing traits for OEM parsers, plus the OEM/generic boundary types in
//! [`storage`] that let the recovery engine reason about physical ranges without ever
//! interpreting an OEM index format.
//!
//! [`contract`] is the executable form of the [`Parser`] contract: one harness every OEM
//! parser is tested against, so "compliant" means the same thing for every OEM and a new one
//! inherits the definition rather than writing its own.

#![forbid(unsafe_code)]

pub mod contract;
pub mod parser;
pub mod reconstruction;
pub mod storage;

pub use contract::{run_parser_contract, CheckOutcome, ContractCheck, ContractReport};
pub use parser::Parser;
pub use reconstruction::{ReconstructedStream, ReconstructionProvider};
pub use storage::{
    AllocationEvidence, CircularBufferEvidence, ContainerRecord, IndexAuthority, IndexedRecording,
    RecordingIndex, StorageGeometry,
};
