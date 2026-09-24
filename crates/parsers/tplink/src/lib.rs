//! # TP-Link VIGI NVR OEM Parser
//!
//! Production-quality, read-only storage analyzer for TP-Link VIGI NVR.
//! Implements forensic architecture matching the system topology guidelines.

pub mod encryption;
pub mod ext4;
pub mod parser;
pub mod raw_layout;
pub mod recording_index;
pub mod recovery;
pub mod sqlite_reader;
pub mod types;
pub mod zone;

pub use parser::TplinkParser;
