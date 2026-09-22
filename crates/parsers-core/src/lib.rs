//! # parsers-core
//!
//! Core parsing traits for OEM parsers, plus the OEM/generic boundary types in
//! [`storage`] that let the recovery engine reason about physical ranges without ever
//! interpreting an OEM index format.

#![forbid(unsafe_code)]

pub mod parser;
pub mod storage;

pub use parser::Parser;
pub use storage::{
    AllocationEvidence, CircularBufferEvidence, ContainerRecord, IndexAuthority, IndexedRecording,
    RecordingIndex, StorageGeometry,
};
