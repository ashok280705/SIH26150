//! # Windows Forensic Physical Disk Acquisition Subsystem
//!
//! Provides deterministic physical acquisition, device enumeration, safety assessment,
//! adaptive bad-sector isolation, streaming RAW image writing, and independent two-pass
//! cryptographic verification.
//!
//! Architectural Boundary:
//! - `SourceDevice`: Physical acquisition abstraction (strictly read-only `GENERIC_READ`).
//! - `EvidenceReader`: Forensic evidence analysis abstraction.

pub mod error;
pub mod types;
pub mod source;
pub mod writer;
pub mod verify;
pub mod manifest;
pub mod engine;
pub mod safety;

#[cfg(windows)]
pub mod windows;

pub use error::AcquisitionError;
pub use types::*;
pub use source::{SourceDevice, MockSourceDevice};
pub use writer::ImageWriter;
pub use verify::verify_image_file;
pub use manifest::AcquisitionManifest;
pub use engine::{run_acquisition, ProgressCallback};
pub use safety::assess_safety;

#[cfg(windows)]
pub use windows::{WindowsSourceDevice, enumerate_physical_devices, assess_windows_safety};
