//! # Reconstruction Provider Interface
//!
//! Exposes stream reconstruction for OEM parsers that support translating a recording or
//! chain identifier into ordered evidence payload regions.

use evidence_reader::EvidenceReader;
use forensic_core::{ForensicError, OemProfile, Region};
use serde::{Deserialize, Serialize};

/// A reconstructed video stream assembled from OEM evidence structures.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReconstructedStream {
    /// Ordered byte regions in the evidence source that form the elementary or container video stream.
    pub payload_regions: Vec<Region>,
    /// Normalized camera/channel index.
    pub channel: u32,
    /// Detailed provenance description of the reconstructed chain/clip.
    pub description: String,
}

/// Interface for OEM parsers capable of reconstructing recording chains/clips into video streams.
pub trait ReconstructionProvider: Send + Sync {
    /// Reconstruct one recording by its identifier (chain_id or recording_id).
    fn reconstruct_recording(
        &self,
        reader: &dyn EvidenceReader,
        profile: &OemProfile,
        recording_id: &str,
    ) -> Result<Option<ReconstructedStream>, ForensicError>;
}
