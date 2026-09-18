//! # TP-Link VIGI NVR OEM Parser
//!
//! Production-quality, read-only storage analyzer for TP-Link VIGI NVR.
//! Implements forensic architecture matching the system topology guidelines.

pub mod parser;
pub mod types;
pub mod ext4;
pub mod raw_layout;
pub mod sqlite_reader;
pub mod zone;
pub mod recording_index;
pub mod encryption;
pub mod recovery;

pub use parser::TplinkParser;
