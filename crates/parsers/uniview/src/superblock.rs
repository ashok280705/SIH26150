//! # SUPER block
//!
//! The SUPER block is the first `0x4000` bytes of the disk. Its layout (CONFIRMED):
//!
//! | Offset | Size | Field |
//! |---|---|---|
//! | `+0x00` | 4 | magic, u32 LE — `0x1367` OLD, `0x1587` NEW |
//! | `+0x14` | 5 | Last Write Super Data Time (packed timestamp) |
//! | `+0x1C` | 5 | Start Storage Time (packed timestamp) |
//! | `+0x2C` | 0x40 | EcPortId — an opaque 64-byte field |
//!
//! The magic alone identifies the filesystem and its generation. EcPortId and the
//! timestamps are parsed and preserved but never required: they are corroboration, and no
//! validation rule is invented for EcPortId.
//!
//! ## disktool `.h3crd` exports
//!
//! disktool's `-r data` command writes a `.h3crd` file: a 0x68-byte header beginning with
//! the tag `"iVS8000@huawei-3com"` (and a u32 constant `0x56B4C275`), then UI at 0x4000, one
//! unit's DI at 0x14000 with SPtoI re-based to start at 16, and raw DATA from 0x54000. That is
//! an OLD-shaped single-unit image with the SUPER replaced by the export header, so it is
//! recognised here as [`SuperRecognition::H3crdExport`] (OLD generation) and parsed by the
//! same code. The tag is checked **only when neither SUPER magic matches**, so raw-disk
//! recognition is unchanged. An export is a normalized artifact, not a physical disk layout,
//! and is labelled as such everywhere it is reported.

use evidence_reader::EvidenceReader;
use forensic_core::{ForensicError, ValidationState, ValidationStateKind};
use serde::{Deserialize, Serialize};

use crate::field::FieldEvidence;
use crate::layout::{bytes_at, u32_at, vs, Confidence, Generation, UniviewLayout};
use crate::timestamp::UnvTimestamp;

/// Whether the evidence carries a Uniview SUPER.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum SuperRecognition {
    /// A profile-declared magic matched and the whole SUPER block was readable.
    Recognized { generation: Generation },
    /// A magic matched but the image ends inside the SUPER block.
    Truncated {
        generation: Generation,
        available: u64,
    },
    /// The magic bytes match neither generation.
    MagicMismatch { observed_hex: String },
    /// Not even the magic could be read.
    NotFound { reason: String },
    /// A disktool `.h3crd` export: OLD-shaped single-unit artifact, not a physical disk.
    ///
    /// `constant_matched` records whether the header's u32 constant (`0x56B4C275`, at the
    /// profile's STRONG-INFERENCE offset) was found. It is corroboration only.
    H3crdExport { constant_matched: Option<bool> },
}

impl SuperRecognition {
    pub fn generation(&self) -> Option<Generation> {
        match self {
            Self::Recognized { generation } | Self::Truncated { generation, .. } => {
                Some(*generation)
            }
            // The export reproduces the OLD layout (UI at 0x4000, unit 1 at 0x14000).
            Self::H3crdExport { .. } => Some(Generation::Old),
            _ => None,
        }
    }

    pub fn label(&self) -> String {
        match self {
            Self::Recognized { generation } => format!("recognized ({} generation)", generation.label()),
            Self::Truncated { generation, available } => format!(
                "{} generation magic present but only {available} byte(s) of the SUPER block are \
                 in the image",
                generation.label()
            ),
            Self::MagicMismatch { observed_hex } => {
                format!("SUPER magic mismatch (observed {observed_hex})")
            }
            Self::NotFound { reason } => format!("SUPER not readable: {reason}"),
            Self::H3crdExport { constant_matched } => format!(
                "Uniview disktool .h3crd export (OLD-shaped single-unit normalized artifact, not an \
                 original physical disk layout; header constant {})",
                match constant_matched {
                    Some(true) => "present",
                    Some(false) => "not found at the expected offset",
                    None => "not readable",
                }
            ),
        }
    }

    pub fn validation(&self) -> ValidationState {
        match self {
            Self::Recognized { .. } => vs(
                ValidationStateKind::Pass,
                format!("Uniview SUPER {}", self.label()),
                "read_super",
                "uniview_super",
            ),
            Self::H3crdExport { .. } => vs(
                ValidationStateKind::Pass,
                self.label(),
                "read_super",
                "uniview_h3crd_export",
            ),
            Self::Truncated { .. } => vs(
                ValidationStateKind::Review,
                format!("Uniview SUPER {}", self.label()),
                "read_super",
                "uniview_super",
            ),
            Self::MagicMismatch { .. } | Self::NotFound { .. } => vs(
                ValidationStateKind::Unknown,
                format!("not a Uniview filesystem: {}", self.label()),
                "read_super",
                "uniview_super",
            ),
        }
    }
}

/// The parsed SUPER block.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct UniviewSuper {
    pub recognition: SuperRecognition,
    /// Physical offset of the SUPER block.
    pub offset: u64,
    /// Raw magic value as read (u32 LE), if four bytes were available.
    pub magic_raw: Option<u32>,
    pub last_write_time: Option<UnvTimestamp>,
    pub start_storage_time: Option<UnvTimestamp>,
    /// The opaque 64-byte EcPortId, verbatim.
    pub ec_port_id: Option<Vec<u8>>,
}

impl UniviewSuper {
    pub fn generation(&self) -> Option<Generation> {
        self.recognition.generation()
    }

    /// Whether this is a disktool `.h3crd` export rather than a raw disk.
    pub fn is_h3crd_export(&self) -> bool {
        matches!(self.recognition, SuperRecognition::H3crdExport { .. })
    }

    /// EcPortId printable rendering: ASCII up to the first NUL, when it is printable.
    ///
    /// Reported only as a convenience next to the raw bytes; no structure is inferred from it.
    pub fn ec_port_id_text(&self) -> Option<String> {
        let raw = self.ec_port_id.as_ref()?;
        let end = raw.iter().position(|&b| b == 0).unwrap_or(raw.len());
        let s = &raw[..end];
        (!s.is_empty() && s.iter().all(|b| b.is_ascii_graphic() || *b == b' '))
            .then(|| String::from_utf8_lossy(s).into_owned())
    }

    /// Field-level evidence for every SUPER field that was read.
    pub fn fields(&self, layout: &UniviewLayout) -> Vec<FieldEvidence> {
        let mut out = Vec::new();
        if self.is_h3crd_export() {
            let tag = layout.h3crd_tag.clone().unwrap_or_default();
            out.push(FieldEvidence::new(
                "h3crd.header_tag",
                self.offset,
                (tag.len() as u32).saturating_mul(8),
                None,
                &tag,
                None,
                format!(
                    "disktool export tag {:?}: this is a normalized .h3crd artifact, not a raw disk",
                    String::from_utf8_lossy(&tag)
                ),
                Confidence::Confirmed,
            ));
            return out;
        }
        if let Some(m) = self.magic_raw {
            out.push(FieldEvidence::new(
                "super.magic",
                self.offset + layout.magic_offset as u64,
                32,
                None,
                &m.to_le_bytes(),
                Some(u64::from(m)),
                match self.generation() {
                    Some(g) => format!("0x{m:04X} = {} generation", g.label()),
                    None => format!("0x{m:08X} matches no Uniview generation"),
                },
                Confidence::Confirmed,
            ));
        }
        for (name, ts) in [
            ("super.last_write_super_data_time", &self.last_write_time),
            ("super.start_storage_time", &self.start_storage_time),
        ] {
            if let Some(t) = ts {
                out.push(FieldEvidence::new(
                    name,
                    t.field_offset,
                    40,
                    None,
                    &t.raw,
                    Some(t.raw_value()),
                    t.label(),
                    Confidence::Confirmed,
                ));
            }
        }
        if let Some(raw) = &self.ec_port_id {
            out.push(FieldEvidence::new(
                "super.ec_port_id",
                self.offset + layout.ec_port_id_offset as u64,
                (raw.len() as u32) * 8,
                None,
                raw,
                None,
                match self.ec_port_id_text() {
                    Some(t) => format!("opaque 64-byte field (printable prefix: {t:?})"),
                    None => "opaque 64-byte field".to_string(),
                },
                Confidence::Confirmed,
            ));
        }
        out
    }
}

/// Read and parse the SUPER block. Never fails on malformed evidence: the answer is carried
/// in [`UniviewSuper::recognition`]. Only a reader-level failure is an `Err`.
pub fn read_super(
    reader: &dyn EvidenceReader,
    layout: &UniviewLayout,
) -> Result<UniviewSuper, ForensicError> {
    let offset = layout.super_offset;
    let image_len = reader.len();
    let blank = |recognition| UniviewSuper {
        recognition,
        offset,
        magic_raw: None,
        last_write_time: None,
        start_storage_time: None,
        ec_port_id: None,
    };

    if offset >= image_len {
        return Ok(blank(SuperRecognition::NotFound {
            reason: format!("the image is {image_len} byte(s); the SUPER block starts at {offset}"),
        }));
    }
    let available = (image_len - offset).min(layout.super_size);
    let mut buf = vec![0u8; usize::try_from(available).unwrap_or(0)];
    let n = reader.read_at(offset, &mut buf)?;
    buf.truncate(n);

    let Some(magic_bytes) = bytes_at(&buf, layout.magic_offset, 4) else {
        return Ok(blank(SuperRecognition::NotFound {
            reason: format!("only {n} byte(s) are readable; the 4-byte magic is not complete"),
        }));
    };
    let magic_raw = u32_at(&buf, layout.magic_offset);

    let Some(generation) = layout.generation_for_magic(magic_bytes) else {
        // Only when no raw-disk magic matched: a disktool .h3crd export header.
        if let Some(tag) = layout.h3crd_tag.as_deref().filter(|t| !t.is_empty()) {
            if buf.starts_with(tag) {
                let constant_matched = if (layout.h3crd_constant_offset as u64)
                    < layout.h3crd_header_size
                {
                    u32_at(&buf, layout.h3crd_constant_offset).map(|v| v == layout.h3crd_constant)
                } else {
                    None
                };
                return Ok(UniviewSuper {
                    magic_raw,
                    ..blank(SuperRecognition::H3crdExport { constant_matched })
                });
            }
        }
        return Ok(UniviewSuper {
            magic_raw,
            ..blank(SuperRecognition::MagicMismatch {
                observed_hex: hex::encode(magic_bytes),
            })
        });
    };

    let ts = |field_off: usize| {
        bytes_at(&buf, field_off, layout.timestamp_size).map(|raw| {
            UnvTimestamp::decode(
                raw,
                offset + field_off as u64,
                layout.timestamp_plausible_min_year,
                layout.timestamp_plausible_max_year,
            )
        })
    };

    let recognition = if (buf.len() as u64) < layout.super_size {
        SuperRecognition::Truncated {
            generation,
            available: buf.len() as u64,
        }
    } else {
        SuperRecognition::Recognized { generation }
    };

    Ok(UniviewSuper {
        recognition,
        offset,
        magic_raw,
        last_write_time: ts(layout.super_last_write_time_offset),
        start_storage_time: ts(layout.super_start_storage_time_offset),
        ec_port_id: bytes_at(&buf, layout.ec_port_id_offset, layout.ec_port_id_size)
            .map(<[u8]>::to_vec),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::layout::tests_support::uniview_profile;
    use crate::testing::{build, SparseReader};
    use crate::timestamp::{encode, TimestampStatus};

    fn layout() -> UniviewLayout {
        UniviewLayout::from_profile(&uniview_profile())
    }

    #[test]
    fn old_and_new_magic_identify_the_generation() {
        let l = layout();
        for (gen, magic) in [(Generation::Old, 0x1367u32), (Generation::New, 0x1587u32)] {
            let r = SparseReader::new(0x8000).with(0, &build::super_block(magic, None, None, None));
            let s = read_super(&r, &l).unwrap();
            assert_eq!(
                s.recognition,
                SuperRecognition::Recognized { generation: gen }
            );
            assert_eq!(s.magic_raw, Some(magic));
        }
    }

    #[test]
    fn a_disktool_h3crd_export_is_recognised_as_an_old_shaped_artifact() {
        let l = layout();
        let hdr = build::h3crd_header();
        let r = SparseReader::new(0x8000).with(0, &hdr);
        let s = read_super(&r, &l).unwrap();
        assert_eq!(
            s.recognition,
            SuperRecognition::H3crdExport {
                constant_matched: Some(true)
            }
        );
        assert_eq!(s.generation(), Some(Generation::Old));
        assert!(s.is_h3crd_export());
        assert!(s
            .recognition
            .label()
            .contains("not an original physical disk"));
        assert_eq!(s.fields(&l)[0].name, "h3crd.header_tag");

        // Tag present, constant absent: still an export, flagged.
        let mut no_const = hdr.clone();
        no_const[0x64..0x68].copy_from_slice(&[0; 4]);
        let s = read_super(&SparseReader::new(0x8000).with(0, &no_const), &l).unwrap();
        assert_eq!(
            s.recognition,
            SuperRecognition::H3crdExport {
                constant_matched: Some(false)
            }
        );

        // A raw-disk magic always wins: the tag is consulted only when no magic matched.
        let r = SparseReader::new(0x8000).with(0, &build::super_block(0x1367, None, None, None));
        assert!(!read_super(&r, &l).unwrap().is_h3crd_export());
        // A truncated tag is not an export.
        let r = SparseReader::new(10).with(0, &hdr[..10]);
        assert!(!read_super(&r, &l).unwrap().is_h3crd_export());
    }

    #[test]
    fn unknown_magic_is_not_uniview() {
        let r = SparseReader::new(0x8000).with(0, &build::super_block(0x1234, None, None, None));
        let s = read_super(&r, &layout()).unwrap();
        assert!(matches!(
            s.recognition,
            SuperRecognition::MagicMismatch { .. }
        ));
        assert_eq!(s.generation(), None);
        assert_eq!(
            s.recognition.validation().state,
            ValidationStateKind::Unknown
        );
    }

    #[test]
    fn a_truncated_super_is_reported_not_trusted() {
        let full = build::super_block(0x1587, None, None, None);
        let r = SparseReader::new(0x100).with(0, &full[..0x100]);
        let s = read_super(&r, &layout()).unwrap();
        assert_eq!(
            s.recognition,
            SuperRecognition::Truncated {
                generation: Generation::New,
                available: 0x100
            }
        );
        assert_eq!(
            s.recognition.validation().state,
            ValidationStateKind::Review
        );

        for len in [0u64, 1, 3] {
            let r = SparseReader::new(len).with(0, &full[..len as usize]);
            let s = read_super(&r, &layout()).unwrap();
            assert!(
                matches!(s.recognition, SuperRecognition::NotFound { .. }),
                "len {len}"
            );
        }
    }

    #[test]
    fn parses_timestamps_and_ec_port_id_at_their_offsets() {
        let mut port = [0u8; 64];
        port[..6].copy_from_slice(b"EC1001");
        let sb = build::super_block(
            0x1367,
            Some(encode(2023, 7, 4, 10, 11, 12)),
            Some(encode(2022, 1, 2, 3, 4, 5)),
            Some(port),
        );
        let r = SparseReader::new(0x8000).with(0, &sb);
        let s = read_super(&r, &layout()).unwrap();
        let lw = s.last_write_time.as_ref().unwrap();
        assert_eq!(lw.field_offset, 0x14);
        assert_eq!(lw.wall_clock().as_deref(), Some("2023-07-04T10:11:12"));
        let st = s.start_storage_time.as_ref().unwrap();
        assert_eq!(st.field_offset, 0x1C);
        assert_eq!(st.wall_clock().as_deref(), Some("2022-01-02T03:04:05"));
        assert_eq!(s.ec_port_id.as_deref(), Some(&port[..]));
        assert_eq!(s.ec_port_id_text().as_deref(), Some("EC1001"));

        let fields = s.fields(&layout());
        let ec = fields
            .iter()
            .find(|f| f.name == "super.ec_port_id")
            .unwrap();
        assert_eq!(ec.physical_offset, 0x2C);
        assert_eq!(ec.size_bits, 512);
    }

    #[test]
    fn malformed_timestamps_and_strings_do_not_block_recognition() {
        let sb = build::super_block(0x1587, Some([0xFF; 5]), Some([0; 5]), Some([0xFF; 64]));
        let r = SparseReader::new(0x8000).with(0, &sb);
        let s = read_super(&r, &layout()).unwrap();
        assert_eq!(
            s.recognition,
            SuperRecognition::Recognized {
                generation: Generation::New
            }
        );
        assert_eq!(
            s.last_write_time.as_ref().unwrap().status,
            TimestampStatus::Invalid
        );
        assert_eq!(
            s.start_storage_time.as_ref().unwrap().status,
            TimestampStatus::Empty
        );
        assert_eq!(
            s.ec_port_id_text(),
            None,
            "non-printable EcPortId gets no text rendering"
        );
    }
}
