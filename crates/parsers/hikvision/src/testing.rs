//! # In-memory evidence reader for exercising the Hikvision structure readers
//!
//! A [`MemReader`] presents a `Vec<u8>` through the read-only [`EvidenceReader`] trait so
//! the Hikvision structure readers can be driven over exact byte layouts without touching
//! the filesystem.
//!
//! It is compiled unconditionally (not behind `#[cfg(test)]`) so this crate's integration
//! tests under `tests/` can use it too. It exposes no write path to real evidence: it owns
//! its own buffer and implements the same read-only trait every production reader does.

use evidence_reader::{EvidenceReader, SourceKind};
use forensic_core::ForensicError;

/// An owned byte buffer presented as read-only evidence.
#[derive(Debug, Clone)]
pub struct MemReader {
    data: Vec<u8>,
    path: String,
}

impl MemReader {
    /// Wrap a byte buffer.
    pub fn new(data: Vec<u8>) -> Self {
        Self {
            data,
            path: "mem://hikvision-structure-test".to_string(),
        }
    }

    /// Wrap a byte buffer with a specific reported source path.
    pub fn with_path(data: Vec<u8>, path: impl Into<String>) -> Self {
        Self {
            data,
            path: path.into(),
        }
    }

    /// The underlying bytes, for a test that needs to assert on what it built.
    pub fn bytes(&self) -> &[u8] {
        &self.data
    }
}

impl EvidenceReader for MemReader {
    fn len(&self) -> u64 {
        self.data.len() as u64
    }

    fn read_at(&self, offset: u64, buf: &mut [u8]) -> Result<usize, ForensicError> {
        // Out-of-bounds is an error, not a zero-fill, so a reader bug cannot masquerade as
        // a region of zeros — which a parser could then misread as a blank B-tree entry or
        // an empty clip slot.
        if offset >= self.len() {
            return Err(ForensicError::out_of_bounds(
                "MemReader::read_at",
                offset,
                buf.len() as u64,
                self.len(),
            ));
        }
        let start = offset as usize;
        let n = (self.data.len() - start).min(buf.len());
        buf[..n].copy_from_slice(&self.data[start..start + n]);
        Ok(n)
    }

    fn source_kind(&self) -> SourceKind {
        SourceKind::Raw
    }

    fn source_path(&self) -> &str {
        &self.path
    }
}

/// Byte builders for the Hikvision container structures.
///
/// These construct **format-accurate** bytes from the same documented field layout the
/// parser reads, so a test asserts against structure rather than against a copied byte
/// array. They are compiled unconditionally so integration tests and the shared fixture
/// generator can use them.
///
/// They build container/stream parts only. Whole-volume assembly (boot structure, HIKBTREE
/// pages, block footers) lives in the workspace fixture crate, which composes these.
pub mod build {
    /// An MPEG-PS pack header: 20 bytes, with `serial` big-endian at `+16`.
    pub fn pack(serial: u32) -> Vec<u8> {
        let mut p = vec![0u8; 20];
        p[..4].copy_from_slice(&[0x00, 0x00, 0x01, 0xBA]);
        p[16..20].copy_from_slice(&serial.to_be_bytes());
        p
    }

    /// A PES-style part.
    ///
    /// `payload_offset` is the value the documented `(u16BE@+7 & 0xFFF) + 9` formula must
    /// produce, and the declared length field is set so `u16BE@+4 + 6` equals the part's real
    /// total size. Building it this way means a test cannot pass against a parser that reads
    /// the fields at the wrong offsets.
    ///
    /// Panics if `payload_offset < 9`, which the formula cannot express.
    pub fn pes(stream_id: u8, payload: &[u8], payload_offset: u64) -> Vec<u8> {
        assert!(
            payload_offset >= 9,
            "the payload-offset formula cannot express an offset below 9"
        );
        let total = payload_offset + payload.len() as u64;
        let declared = u16::try_from(total - 6).expect("a PES part must fit a u16 length field");
        let mut p = vec![0u8; total as usize];
        p[..3].copy_from_slice(&[0x00, 0x00, 0x01]);
        p[3] = stream_id;
        p[4..6].copy_from_slice(&declared.to_be_bytes());
        let field = (payload_offset - 9) as u16;
        p[7..9].copy_from_slice(&field.to_be_bytes());
        p[payload_offset as usize..].copy_from_slice(payload);
        p
    }

    /// An `OFNI` information part: the tag, a little-endian i32 length, then the body.
    pub fn ofni(body: &[u8]) -> Vec<u8> {
        let mut p = Vec::new();
        p.extend_from_slice(b"OFNI");
        p.extend_from_slice(&(body.len() as i32).to_le_bytes());
        p.extend_from_slice(body);
        p
    }

    /// Annex-B H.264 elementary stream: SPS, PPS, an IDR slice and a non-IDR slice.
    pub fn h264_es() -> Vec<u8> {
        let mut v = Vec::new();
        v.extend_from_slice(&[0x00, 0x00, 0x00, 0x01, 0x67, 0x42, 0x00, 0x1E, 0x8D, 0x68]); // SPS (7)
        v.extend_from_slice(&[0x00, 0x00, 0x00, 0x01, 0x68, 0xCE, 0x3C, 0x80]); // PPS (8)
        v.extend_from_slice(&[0x00, 0x00, 0x01, 0x65, 0x88, 0x84, 0x00, 0x21, 0xFF]); // IDR (5)
        v.extend_from_slice(&[0x00, 0x00, 0x01, 0x41, 0x9A, 0x02, 0x04, 0x11]); // non-IDR (1)
        v
    }

    /// Annex-B H.265 elementary stream: VPS, SPS, PPS and an IDR_W_RADL slice.
    ///
    /// The second header byte of each NAL is real (`0x01` => `nuh_layer_id` 0,
    /// `nuh_temporal_id_plus1` 1). That is what distinguishes genuine HEVC from an H.264
    /// P-slice byte whose type field coincidentally reads as an HEVC VPS.
    pub fn h265_es() -> Vec<u8> {
        let mut v = Vec::new();
        v.extend_from_slice(&[0x00, 0x00, 0x00, 0x01, 0x40, 0x01, 0x0C, 0x01, 0xFF]); // VPS (32)
        v.extend_from_slice(&[0x00, 0x00, 0x00, 0x01, 0x42, 0x01, 0x01, 0x01, 0x60]); // SPS (33)
        v.extend_from_slice(&[0x00, 0x00, 0x00, 0x01, 0x44, 0x01, 0xC1, 0x72, 0xB4]); // PPS (34)
        v.extend_from_slice(&[0x00, 0x00, 0x01, 0x26, 0x01, 0xAF, 0x06, 0x18]); // IDR_W_RADL (19)
        v
    }

    /// A complete MPEG-PS clip: pack header, system header, then `video_parts` video PES
    /// parts carrying `es`.
    ///
    /// This is the shape a real Hikvision clip presents, and the shape the carver must find
    /// at its true extent.
    pub fn clip(serial: u32, es: &[u8], video_parts: usize) -> Vec<u8> {
        let mut v = pack(serial);
        v.extend_from_slice(&pes(0xBB, &[0x11; 8], 14));
        for _ in 0..video_parts {
            v.extend_from_slice(&pes(0xE0, es, 14));
        }
        v
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_pes_builder_satisfies_the_documented_length_formula() {
        // If this drifts, every test built on it silently stops testing the real layout.
        let payload = [0xAAu8; 32];
        let p = build::pes(0xE0, &payload, 14);
        let declared = u16::from_be_bytes([p[4], p[5]]) as u64;
        assert_eq!(declared + 6, p.len() as u64, "partLength = u16BE@+4 + 6");
        let field = u16::from_be_bytes([p[7], p[8]]) as u64;
        assert_eq!(
            (field & 0xFFF) + 9,
            14,
            "payload offset = (u16BE@+7 & 0xFFF) + 9"
        );
        assert_eq!(&p[14..], &payload);
    }

    #[test]
    fn the_pack_builder_places_the_serial_big_endian_at_sixteen() {
        let p = build::pack(0x1234_5678);
        assert_eq!(p.len(), 20);
        assert_eq!(&p[..4], &[0x00, 0x00, 0x01, 0xBA]);
        assert_eq!(
            u32::from_be_bytes([p[16], p[17], p[18], p[19]]),
            0x1234_5678
        );
    }

    #[test]
    fn the_ofni_builder_writes_a_little_endian_length() {
        let o = build::ofni(b"abc");
        assert_eq!(&o[..4], b"OFNI");
        assert_eq!(i32::from_le_bytes([o[4], o[5], o[6], o[7]]), 3);
        assert_eq!(&o[8..], b"abc");
    }

    #[test]
    fn short_reads_are_reported_as_short_not_padded() {
        let r = MemReader::new(vec![1, 2, 3, 4]);
        let mut buf = [0u8; 8];
        assert_eq!(r.read_at(2, &mut buf).unwrap(), 2);
        assert_eq!(&buf[..2], &[3, 4]);
    }

    #[test]
    fn reading_past_the_end_is_an_error_not_zeros() {
        let r = MemReader::new(vec![1, 2, 3, 4]);
        let mut buf = [0u8; 4];
        assert!(r.read_at(4, &mut buf).is_err());
        assert!(r.read_at(u64::MAX, &mut buf).is_err());
    }

    #[test]
    fn read_exact_at_refuses_a_short_read() {
        let r = MemReader::new(vec![1, 2, 3, 4]);
        assert!(r.read_exact_at(0, 4).is_ok());
        assert!(r.read_exact_at(2, 4).is_err());
    }
}
