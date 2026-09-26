//! # Detector Trait
//!
//! Generic storage detection interface driven by versioned OEM profiles (Req 3.1, 6.4, 2.5).
//!
//! Key invariants:
//! - Consumes profile data only; no magic values or offsets are hard-coded in source (Req 2.5).
//! - Detectors reason over storage-structure evidence only — content/payload interpretation is downstream (Req 3.1).
//! - Produces `DetectorOutput` without claiming attribution (Req 2.6).

use evidence_reader::EvidenceReader;
use forensic_core::{ForensicError, OemProfile};

use crate::output::DetectorOutput;

/// Common interface implemented by per-OEM storage structure detectors.
pub trait Detector: Send + Sync {
    /// The unique OEM identifier (e.g. "dahua", "hikvision", "honeywell", "cpplus_ubs", "uniview").
    fn oem_key(&self) -> &'static str;

    /// Execute storage structure detection over the given evidence reader using profile rules.
    fn detect(
        &self,
        reader: &dyn EvidenceReader,
        profile: &OemProfile,
    ) -> Result<DetectorOutput, ForensicError>;
}
