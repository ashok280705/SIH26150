//! # Version-aware DHFS volume recognition
//!
//! The first eight bytes of a Dahua volume carry the filesystem signature:
//!
//! ```text
//!   offset 0   44 48 46 53 34 2E 31 00    "DHFS4.1\0"
//! ```
//!
//! This module answers one question — *which* DHFS is this? — and it distinguishes four
//! answers that the previous implementation collapsed into two:
//!
//! | Outcome                                  | Meaning                                          |
//! |------------------------------------------|--------------------------------------------------|
//! | [`DhfsRecognition::Dhfs41`]              | recognised DHFS 4.1; the partition model applies |
//! | [`DhfsRecognition::UnsupportedVariant`]  | DHFS, but a version this platform cannot parse   |
//! | [`DhfsRecognition::Malformed`]           | DHFS magic present, version field unreadable     |
//! | [`DhfsRecognition::NotDhfs`]             | not a DHFS volume at all                         |
//!
//! Keeping `UnsupportedVariant` and `Malformed` apart matters forensically. "We recognise
//! this filesystem but not this revision of it" licenses an examiner to look for a
//! firmware-specific profile. "The structure where the revision should be is damaged"
//! licenses a damage finding. Reporting either as a clean parse would be wrong, and
//! reporting both as "not Dahua" would discard a true positive.
//!
//! Nothing here interprets geometry. On a real DHFS 4.1 volume the authoritative geometry
//! lives in the partition table (see [`crate::partition`]), not in fields at fixed
//! superblock offsets.

use evidence_reader::EvidenceReader;
use forensic_core::{ForensicError, OemProfile, Region, ValidationState, ValidationStateKind};
use serde::{Deserialize, Serialize};

use crate::layout::{key, magic, u64_from, usize_from, vs};

/// The recognised identity of a DHFS volume.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum DhfsRecognition {
    /// A recognised DHFS 4.1 volume. The DHFS 4.1 partition/block-table model applies.
    Dhfs41 {
        /// The signature bytes exactly as read, so provenance can quote them.
        signature: Vec<u8>,
    },
    /// The `DHFS` family magic is present but the version suffix is one this platform has
    /// no structural evidence for. Nothing beyond the signature may be interpreted.
    UnsupportedVariant {
        /// Printable rendering of the version suffix, e.g. `"5.0"`.
        version_label: String,
        signature: Vec<u8>,
        reason: String,
    },
    /// The `DHFS` family magic is present but the bytes where the version belongs are not
    /// a readable version — the volume header is damaged or truncated.
    ///
    /// This is deliberately **not** treated as a valid volume. Interpreting structures
    /// behind a malformed header is how a parser invents a filesystem.
    Malformed { signature: Vec<u8>, reason: String },
    /// No DHFS family magic at offset 0.
    NotDhfs { reason: String },
}

impl DhfsRecognition {
    /// Whether the DHFS 4.1 structure set may be parsed.
    pub fn is_dhfs41(&self) -> bool {
        matches!(self, DhfsRecognition::Dhfs41 { .. })
    }

    /// Whether any DHFS family magic was found, regardless of version support.
    pub fn is_dhfs_family(&self) -> bool {
        !matches!(self, DhfsRecognition::NotDhfs { .. })
    }

    /// Stable short label for logs and reports.
    pub fn label(&self) -> &'static str {
        match self {
            Self::Dhfs41 { .. } => "dhfs-4.1",
            Self::UnsupportedVariant { .. } => "dhfs-unsupported-variant",
            Self::Malformed { .. } => "dhfs-malformed",
            Self::NotDhfs { .. } => "not-dhfs",
        }
    }

    /// The validation outcome this recognition implies.
    ///
    /// Only a recognised DHFS 4.1 volume is `Pass`. A malformed or unsupported variant is
    /// `Review` — it is a real observation that needs a human — and a non-DHFS volume is
    /// `Unknown`, because the Dahua parser simply does not apply to it.
    pub fn validation(&self) -> ValidationState {
        const OP: &str = "dhfs_recognition";
        const SUBJECT: &str = "volume_signature";
        match self {
            Self::Dhfs41 { signature } => vs(
                ValidationStateKind::Pass,
                format!(
                    "DHFS 4.1 volume signature verified at offset 0 ({})",
                    hex_ascii(signature)
                ),
                OP,
                SUBJECT,
            ),
            Self::UnsupportedVariant {
                version_label,
                signature,
                reason,
            } => vs(
                ValidationStateKind::Review,
                format!(
                    "DHFS family magic present at offset 0 ({}) declaring version '{version_label}', \
                     which this platform has no structural evidence for: {reason}. No DHFS \
                     structure beyond the signature was interpreted",
                    hex_ascii(signature)
                ),
                OP,
                SUBJECT,
            ),
            Self::Malformed { signature, reason } => vs(
                ValidationStateKind::Review,
                format!(
                    "DHFS family magic present at offset 0 ({}) but the volume header is malformed: \
                     {reason}. No DHFS structure was interpreted behind it",
                    hex_ascii(signature)
                ),
                OP,
                SUBJECT,
            ),
            Self::NotDhfs { reason } => vs(
                ValidationStateKind::Unknown,
                format!("no DHFS volume signature at offset 0: {reason}"),
                OP,
                SUBJECT,
            ),
        }
    }

    /// The physical extent of the volume signature, when one was read.
    pub fn signature_region(&self) -> Option<Region> {
        let len = match self {
            Self::Dhfs41 { signature }
            | Self::UnsupportedVariant { signature, .. }
            | Self::Malformed { signature, .. } => signature.len() as u64,
            Self::NotDhfs { .. } => return None,
        };
        Region::new(0, len).ok()
    }
}

/// Render bytes as `hex (ascii)` for an evidence string.
fn hex_ascii(bytes: &[u8]) -> String {
    let hex = bytes
        .iter()
        .map(|b| format!("{b:02X}"))
        .collect::<Vec<_>>()
        .join(" ");
    let ascii: String = bytes
        .iter()
        .map(|b| {
            if b.is_ascii_graphic() {
                *b as char
            } else {
                '.'
            }
        })
        .collect();
    format!("{hex} = \"{ascii}\"")
}

/// Recognise the DHFS volume at offset 0.
///
/// Reads only the signature bytes. A short or unreadable read is reported as
/// [`DhfsRecognition::NotDhfs`] (nothing to recognise) or [`DhfsRecognition::Malformed`]
/// (family magic present, version truncated) rather than propagating an error: "this is
/// not our volume" and "our volume is damaged" are both findings, not I/O failures.
pub fn recognize(
    reader: &dyn EvidenceReader,
    profile: &OemProfile,
) -> Result<DhfsRecognition, ForensicError> {
    // The family magic — the 4-byte "DHFS" prefix — is what decides whether this parser
    // applies at all. Without a profile-declared pattern there is nothing to verify
    // against, and guessing is exactly what this module exists to avoid.
    let family = match magic(profile, "dhfs_magic") {
        Some(m) => m,
        None => {
            return Ok(DhfsRecognition::NotDhfs {
                reason: "the profile declares no DHFS family signature, so the volume cannot be \
                         verified"
                    .to_string(),
            })
        }
    };
    let full = magic(profile, "dhfs41_magic");
    let signature_len = u64_from(
        profile,
        key::DHFS41_MAGIC_LENGTH,
        full.as_ref().map(|m| m.len() as u64).unwrap_or(8),
    )
    .max(family.len() as u64) as usize;

    if reader.len() < family.len() as u64 {
        return Ok(DhfsRecognition::NotDhfs {
            reason: format!(
                "evidence is {} byte(s), shorter than the {}-byte DHFS family signature",
                reader.len(),
                family.len()
            ),
        });
    }

    // Read up to the full signature width, tolerating a short read so a volume truncated
    // inside its own header is still classified rather than erroring out.
    let want = signature_len.min(reader.len() as usize);
    let mut buf = vec![0u8; want];
    let read = match reader.read_at(0, &mut buf) {
        Ok(n) => n,
        Err(e) => {
            return Ok(DhfsRecognition::NotDhfs {
                reason: format!("offset 0 could not be read: {e}"),
            })
        }
    };
    buf.truncate(read);

    if !buf.starts_with(&family) {
        return Ok(DhfsRecognition::NotDhfs {
            reason: format!(
                "offset 0 holds {} which does not match the DHFS family signature",
                hex_ascii(&buf[..buf.len().min(family.len())])
            ),
        });
    }

    // Exact DHFS 4.1 match: the full declared signature is present verbatim.
    if let Some(full) = full.as_ref() {
        if buf.len() >= full.len() && &buf[..full.len()] == full.as_slice() {
            return Ok(DhfsRecognition::Dhfs41 {
                signature: buf[..full.len()].to_vec(),
            });
        }
    }

    // Family magic present, but not the recognised 4.1 signature. Decide between a
    // readable-but-unsupported version and a malformed header by looking at whether the
    // version suffix is printable text at all.
    let suffix = &buf[family.len()..];
    if suffix.is_empty() {
        return Ok(DhfsRecognition::Malformed {
            signature: buf.clone(),
            reason: format!(
                "the volume ends after the {}-byte family magic, so no version suffix is present",
                family.len()
            ),
        });
    }

    let trimmed: Vec<u8> = suffix.iter().copied().take_while(|b| *b != 0).collect();
    let printable =
        !trimmed.is_empty() && trimmed.iter().all(|b| b.is_ascii_graphic() || *b == b' ');

    if printable {
        let version_label = String::from_utf8_lossy(&trimmed).trim().to_string();
        Ok(DhfsRecognition::UnsupportedVariant {
            version_label: version_label.clone(),
            signature: buf.clone(),
            reason: format!(
                "the version suffix reads as '{version_label}', and the profile declares structure \
                 offsets for DHFS 4.1 only"
            ),
        })
    } else {
        Ok(DhfsRecognition::Malformed {
            signature: buf.clone(),
            reason: format!(
                "the {} byte(s) following the family magic are not a printable version suffix ({})",
                suffix.len(),
                hex_ascii(suffix)
            ),
        })
    }
}

/// Descriptive fields some Dahua volumes carry in the first sector.
///
/// These are **provisional**: the platform has evidence that recorders write model,
/// serial and volume-label text near the start of the volume, but not that the offsets are
/// stable across firmware. They are therefore read as descriptive strings only, never used
/// to derive geometry, and any field that does not read as text is simply absent.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct VolumeDescriptors {
    pub model: Option<String>,
    pub serial: Option<String>,
    pub volume_label: Option<String>,
}

impl VolumeDescriptors {
    /// Whether any descriptor was recovered.
    pub fn is_empty(&self) -> bool {
        self.model.is_none() && self.serial.is_none() && self.volume_label.is_none()
    }
}

/// Read the provisional descriptive fields from the first sector.
///
/// Returns an empty set rather than an error when the sector is unreadable: descriptive
/// text is never load-bearing, so its absence must not fail a run.
pub fn read_descriptors(reader: &dyn EvidenceReader, profile: &OemProfile) -> VolumeDescriptors {
    let size = u64_from(profile, key::SUPERBLOCK_SIZE, 512);
    if size == 0 || reader.len() < size {
        return VolumeDescriptors::default();
    }
    let buf = match reader.read_exact_at(0, size as usize) {
        Ok(b) => b,
        Err(_) => return VolumeDescriptors::default(),
    };
    VolumeDescriptors {
        model: crate::layout::ascii_at(
            &buf,
            usize_from(profile, key::SB_MODEL_OFFSET, 48),
            usize_from(profile, key::SB_MODEL_LEN, 16),
        ),
        serial: crate::layout::ascii_at(
            &buf,
            usize_from(profile, key::SB_SERIAL_OFFSET, 64),
            usize_from(profile, key::SB_SERIAL_LEN, 32),
        ),
        volume_label: crate::layout::ascii_at(
            &buf,
            usize_from(profile, key::SB_VOLUME_LABEL_OFFSET, 96),
            usize_from(profile, key::SB_VOLUME_LABEL_LEN, 16),
        ),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::layout::tests_support::dahua_profile;
    use crate::testing::MemReader;

    fn reader(bytes: Vec<u8>) -> MemReader {
        MemReader::new(bytes)
    }

    fn volume(prefix: &[u8], total: usize) -> MemReader {
        let mut b = vec![0u8; total];
        b[..prefix.len()].copy_from_slice(prefix);
        reader(b)
    }

    #[test]
    fn a_real_dhfs41_signature_is_recognised() {
        let p = dahua_profile();
        let r = volume(b"DHFS4.1\0", 4096);
        let got = recognize(&r, &p).unwrap();
        assert!(got.is_dhfs41(), "{got:?}");
        assert_eq!(got.validation().state, ValidationStateKind::Pass);
        assert_eq!(got.signature_region(), Some(Region::new(0, 8).unwrap()));
        assert!(got.validation().reason.contains("DHFS4.1"));
    }

    #[test]
    fn a_non_dahua_volume_is_not_dhfs_and_is_not_an_error() {
        let p = dahua_profile();
        let r = volume(b"NTFS    ", 4096);
        let got = recognize(&r, &p).unwrap();
        assert!(matches!(got, DhfsRecognition::NotDhfs { .. }), "{got:?}");
        assert!(!got.is_dhfs_family());
        // Not applicable is Unknown, never Pass and never Fail.
        assert_eq!(got.validation().state, ValidationStateKind::Unknown);
    }

    #[test]
    fn a_later_dhfs_version_is_unsupported_not_malformed_and_not_valid() {
        let p = dahua_profile();
        let r = volume(b"DHFS5.0\0", 4096);
        let got = recognize(&r, &p).unwrap();
        match &got {
            DhfsRecognition::UnsupportedVariant { version_label, .. } => {
                assert_eq!(version_label, "5.0");
            }
            other => panic!("expected UnsupportedVariant, got {other:?}"),
        }
        assert!(
            !got.is_dhfs41(),
            "an unsupported variant must not be parsed as 4.1"
        );
        assert!(got.is_dhfs_family(), "it is still a Dahua filesystem");
        assert_eq!(got.validation().state, ValidationStateKind::Review);
    }

    #[test]
    fn a_damaged_version_suffix_is_malformed_never_silently_valid() {
        let p = dahua_profile();
        // Binary garbage where the version text belongs.
        let r = volume(&[b'D', b'H', b'F', b'S', 0x01, 0xFF, 0x7F, 0x03], 4096);
        let got = recognize(&r, &p).unwrap();
        assert!(matches!(got, DhfsRecognition::Malformed { .. }), "{got:?}");
        assert!(!got.is_dhfs41());
        assert_eq!(got.validation().state, ValidationStateKind::Review);
        assert!(got.validation().reason.contains("malformed"));
    }

    #[test]
    fn a_volume_truncated_inside_its_own_signature_is_malformed() {
        let p = dahua_profile();
        let r = reader(b"DHFS".to_vec());
        let got = recognize(&r, &p).unwrap();
        assert!(matches!(got, DhfsRecognition::Malformed { .. }), "{got:?}");
    }

    #[test]
    fn a_volume_shorter_than_the_family_magic_is_not_dhfs() {
        let p = dahua_profile();
        let got = recognize(&reader(b"DH".to_vec()), &p).unwrap();
        assert!(matches!(got, DhfsRecognition::NotDhfs { .. }), "{got:?}");
    }

    #[test]
    fn an_empty_volume_is_not_dhfs() {
        let p = dahua_profile();
        let got = recognize(&reader(Vec::new()), &p).unwrap();
        assert!(matches!(got, DhfsRecognition::NotDhfs { .. }), "{got:?}");
    }

    #[test]
    fn recognition_labels_are_distinct() {
        let labels = [
            DhfsRecognition::Dhfs41 { signature: vec![] }.label(),
            DhfsRecognition::UnsupportedVariant {
                version_label: "x".into(),
                signature: vec![],
                reason: "x".into(),
            }
            .label(),
            DhfsRecognition::Malformed {
                signature: vec![],
                reason: "x".into(),
            }
            .label(),
            DhfsRecognition::NotDhfs { reason: "x".into() }.label(),
        ];
        let unique: std::collections::BTreeSet<_> = labels.iter().collect();
        assert_eq!(unique.len(), 4);
    }

    #[test]
    fn descriptors_are_read_as_text_and_missing_text_stays_absent() {
        let p = dahua_profile();
        let mut b = vec![0u8; 512];
        b[..8].copy_from_slice(b"DHFS4.1\0");
        b[48..48 + 13].copy_from_slice(b"DHI-XVR5216AN");
        b[96..96 + 12].copy_from_slice(b"DVR_REC_VOL0");
        let d = read_descriptors(&reader(b), &p);
        assert_eq!(d.model.as_deref(), Some("DHI-XVR5216AN"));
        assert_eq!(d.volume_label.as_deref(), Some("DVR_REC_VOL0"));
        assert!(
            d.serial.is_none(),
            "an all-zero field is absent, not empty-string"
        );
        assert!(!d.is_empty());
    }

    #[test]
    fn descriptors_on_a_truncated_volume_are_empty_not_an_error() {
        let p = dahua_profile();
        let d = read_descriptors(&reader(b"DHFS4.1\0".to_vec()), &p);
        assert!(d.is_empty());
    }
}
