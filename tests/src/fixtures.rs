//! # Synthetic Fixture Generator
//!
//! Produces small, deterministic evidence images for all five OEM profile shapes.
//! Every fixture is labeled `synthetic` and is explicitly NOT real OEM evidence
//! (Req 19.7, 19.11).
//!
//! Same seed → same bytes, so corpus cases stay deterministic.
//!
//! Fixture shapes:
//! - Normal: valid-looking structure at expected offsets
//! - Sparse: large regions of zeros (unallocated)
//! - Truncated: image cut short before the expected end
//! - Fragmented: structures placed at non-contiguous offsets
//! - OverlappingSignature: multiple OEM signatures in the same region
//! - WrongOffset: structures placed at unexpected offsets
//! - LoneMagic: only a magic value, no supporting structure
//! - Overwritten: structures present but marked as overwritten/zeroed

use std::collections::hash_map::DefaultHasher;
use std::hash::{Hash, Hasher};
use std::io::Write;
use std::path::{Path, PathBuf};

/// The five supported OEM shapes for fixture generation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum OemShape {
    Dahua,
    Hikvision,
    Honeywell,
    CpPlusUbs,
    Uniview,
}

impl OemShape {
    /// All five OEM shapes.
    pub fn all() -> &'static [OemShape] {
        &[
            OemShape::Dahua,
            OemShape::Hikvision,
            OemShape::Honeywell,
            OemShape::CpPlusUbs,
            OemShape::Uniview,
        ]
    }

    /// Name string for the OEM shape.
    pub fn name(&self) -> &'static str {
        match self {
            Self::Dahua => "dahua",
            Self::Hikvision => "hikvision",
            Self::Honeywell => "honeywell",
            Self::CpPlusUbs => "cpplus_ubs",
            Self::Uniview => "uniview",
        }
    }
}

/// The shape/scenario of the fixture.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum FixtureShape {
    /// Valid-looking structure at expected offsets.
    Normal,
    /// Large regions of zeros (unallocated).
    Sparse,
    /// Image cut short before expected end.
    Truncated,
    /// Structures at non-contiguous offsets.
    Fragmented,
    /// Multiple OEM signatures in the same region.
    OverlappingSignature,
    /// Structures at unexpected offsets.
    WrongOffset,
    /// Only a magic value, no supporting structure.
    LoneMagic,
    /// Structures present but overwritten/zeroed.
    Overwritten,
    /// Known negative signature (e.g. standard FAT32 instead of OEM).
    KnownNegative,
    /// Corrupted metadata/index structures.
    Corrupted,
    /// Partial evidence, missing most structure.
    Partial,
    /// Magic string appears but is just user data (false positive).
    FalsePositive,
    /// Missing a video frame in a sequence.
    MissingFrame,
    /// Explicitly marked deleted structures.
    Deleted,
    /// Orphaned data chunks with no index.
    Orphaned,
    /// Model signature not found in profile applicability.
    UnknownModel,
    /// Firmware signature not found in profile applicability.
    UnknownFirmware,
}

impl FixtureShape {
    /// All fixture shapes.
    pub fn all() -> &'static [FixtureShape] {
        &[
            FixtureShape::Normal,
            FixtureShape::Sparse,
            FixtureShape::Truncated,
            FixtureShape::Fragmented,
            FixtureShape::OverlappingSignature,
            FixtureShape::WrongOffset,
            FixtureShape::LoneMagic,
            FixtureShape::Overwritten,
            FixtureShape::KnownNegative,
            FixtureShape::Corrupted,
            FixtureShape::Partial,
            FixtureShape::FalsePositive,
            FixtureShape::MissingFrame,
            FixtureShape::Deleted,
            FixtureShape::Orphaned,
            FixtureShape::UnknownModel,
            FixtureShape::UnknownFirmware,
        ]
    }

    pub fn name(&self) -> &'static str {
        match self {
            Self::Normal => "normal",
            Self::Sparse => "sparse",
            Self::Truncated => "truncated",
            Self::Fragmented => "fragmented",
            Self::OverlappingSignature => "overlapping_signature",
            Self::WrongOffset => "wrong_offset",
            Self::LoneMagic => "lone_magic",
            Self::Overwritten => "overwritten",
            Self::KnownNegative => "known_negative",
            Self::Corrupted => "corrupted",
            Self::Partial => "partial",
            Self::FalsePositive => "false_positive",
            Self::MissingFrame => "missing_frame",
            Self::Deleted => "deleted",
            Self::Orphaned => "orphaned",
            Self::UnknownModel => "unknown_model",
            Self::UnknownFirmware => "unknown_firmware",
        }
    }
}

/// A synthetic fixture: small deterministic evidence image.
///
/// Always labeled `synthetic` — never described as real OEM forensic evidence.
#[derive(Debug, Clone)]
pub struct SyntheticFixture {
    /// Always "synthetic" — this is NOT real OEM evidence.
    pub label: &'static str,
    /// Which OEM shape this fixture mimics.
    pub oem_shape: OemShape,
    /// The scenario shape.
    pub fixture_shape: FixtureShape,
    /// The seed used to generate this fixture.
    pub seed: u64,
    /// The generated bytes.
    pub bytes: Vec<u8>,
}

impl SyntheticFixture {
    /// The fixture size in bytes.
    pub fn len(&self) -> usize {
        self.bytes.len()
    }

    /// Whether the fixture is empty.
    pub fn is_empty(&self) -> bool {
        self.bytes.is_empty()
    }

    /// Write the fixture to a file and return the path.
    pub fn write_to_dir(&self, dir: &Path) -> std::io::Result<PathBuf> {
        let filename = format!(
            "synthetic_{}_{}_{}.raw",
            self.oem_shape.name(),
            self.fixture_shape.name(),
            self.seed
        );
        let path = dir.join(filename);
        let mut file = std::fs::File::create(&path)?;
        file.write_all(&self.bytes)?;
        Ok(path)
    }
}

/// Generate a deterministic synthetic fixture.
///
/// Same `(oem_shape, fixture_shape, seed)` → same bytes, every time.
pub fn generate_fixture(
    oem_shape: OemShape,
    fixture_shape: FixtureShape,
    seed: u64,
) -> SyntheticFixture {
    // Deterministic pseudo-random byte generator from the seed.
    let mut rng = DeterministicRng::new(seed, oem_shape, fixture_shape);

    let bytes = match fixture_shape {
        FixtureShape::Normal => generate_normal(&mut rng, oem_shape),
        FixtureShape::Sparse => generate_sparse(&mut rng, oem_shape),
        FixtureShape::Truncated => generate_truncated(&mut rng, oem_shape),
        FixtureShape::Fragmented => generate_fragmented(&mut rng, oem_shape),
        FixtureShape::OverlappingSignature => generate_overlapping(&mut rng, oem_shape),
        FixtureShape::WrongOffset => generate_wrong_offset(&mut rng, oem_shape),
        FixtureShape::LoneMagic => generate_lone_magic(&mut rng, oem_shape),
        FixtureShape::Overwritten => generate_overwritten(&mut rng, oem_shape),
        FixtureShape::KnownNegative => generate_known_negative(&mut rng, oem_shape),
        FixtureShape::Corrupted => generate_corrupted(&mut rng, oem_shape),
        FixtureShape::Partial => generate_partial(&mut rng, oem_shape),
        FixtureShape::FalsePositive => generate_false_positive(&mut rng, oem_shape),
        FixtureShape::MissingFrame => generate_missing_frame(&mut rng, oem_shape),
        FixtureShape::Deleted => generate_deleted(&mut rng, oem_shape),
        FixtureShape::Orphaned => generate_orphaned(&mut rng, oem_shape),
        FixtureShape::UnknownModel => generate_unknown_model(&mut rng, oem_shape),
        FixtureShape::UnknownFirmware => generate_unknown_firmware(&mut rng, oem_shape),
    };

    SyntheticFixture {
        label: "synthetic",
        oem_shape,
        fixture_shape,
        seed,
        bytes,
    }
}

/// A simple deterministic pseudo-random number generator.
///
/// This is NOT a cryptographic RNG — it's deterministic for test reproducibility.
struct DeterministicRng {
    state: u64,
}

impl DeterministicRng {
    fn new(seed: u64, oem: OemShape, shape: FixtureShape) -> Self {
        let mut hasher = DefaultHasher::new();
        seed.hash(&mut hasher);
        oem.hash(&mut hasher);
        shape.hash(&mut hasher);
        Self {
            state: hasher.finish(),
        }
    }

    fn next_u8(&mut self) -> u8 {
        self.state = self.state.wrapping_mul(6364136223846793005).wrapping_add(1442695040888963407);
        (self.state >> 33) as u8
    }

    fn fill(&mut self, buf: &mut [u8]) {
        for byte in buf.iter_mut() {
            *byte = self.next_u8();
        }
    }
}

/// Get a synthetic primary "magic" bytes pattern for an OEM shape.
fn synthetic_magic(oem: OemShape) -> &'static [u8] {
    match oem {
        OemShape::Dahua => b"DHFS",
        OemShape::Hikvision => b"HIK_",
        OemShape::Honeywell => b"HONEYWELL",
        OemShape::CpPlusUbs => b"UBS_",
        OemShape::Uniview => b"UNIV",
    }
}

/// Secondary corroborating tag for an OEM shape.
fn synthetic_corroborating_tag(oem: OemShape) -> &'static [u8] {
    match oem {
        OemShape::Dahua => b"DHAV",
        OemShape::Hikvision => b"HKSEG",
        OemShape::Honeywell => b"MPRO",
        OemShape::CpPlusUbs => b"CPPLUS",
        OemShape::Uniview => b"EC1001",
    }
}

const FIXTURE_SIZE: usize = 8192; // 8 KiB — small enough for fast tests

fn generate_normal(rng: &mut DeterministicRng, oem: OemShape) -> Vec<u8> {
    let mut buf = vec![0u8; FIXTURE_SIZE];
    // Place primary magic at offset 0.
    let magic = synthetic_magic(oem);
    buf[..magic.len()].copy_from_slice(magic);
    // Fill structure area with deterministic data.
    rng.fill(&mut buf[magic.len()..512]);
    // Place secondary corroborating tag at offset 512.
    let tag = synthetic_corroborating_tag(oem);
    buf[512..512 + tag.len()].copy_from_slice(tag);
    // Fill remaining data area.
    rng.fill(&mut buf[512 + tag.len()..]);
    buf
}


fn generate_sparse(rng: &mut DeterministicRng, oem: OemShape) -> Vec<u8> {
    let mut buf = vec![0u8; FIXTURE_SIZE * 4]; // Larger, mostly zeros.
    let magic = synthetic_magic(oem);
    buf[..magic.len()].copy_from_slice(magic);
    rng.fill(&mut buf[magic.len()..512]);
    // Data at end only — middle is sparse (zeros).
    rng.fill(&mut buf[FIXTURE_SIZE * 3..]);
    buf
}

fn generate_truncated(rng: &mut DeterministicRng, oem: OemShape) -> Vec<u8> {
    let mut buf = generate_normal(rng, oem);
    // Truncate to half size.
    buf.truncate(FIXTURE_SIZE / 2);
    buf
}

fn generate_fragmented(rng: &mut DeterministicRng, oem: OemShape) -> Vec<u8> {
    let mut buf = vec![0u8; FIXTURE_SIZE * 2];
    let magic = synthetic_magic(oem);
    // Place magic at offset 0 and at a non-contiguous offset.
    buf[..magic.len()].copy_from_slice(magic);
    rng.fill(&mut buf[magic.len()..256]);
    let second_offset = FIXTURE_SIZE + 1024;
    if second_offset + magic.len() <= buf.len() {
        buf[second_offset..second_offset + magic.len()].copy_from_slice(magic);
        rng.fill(&mut buf[second_offset + magic.len()..second_offset + 256]);
    }
    buf
}

fn generate_overlapping(rng: &mut DeterministicRng, _oem: OemShape) -> Vec<u8> {
    let mut buf = vec![0u8; FIXTURE_SIZE];
    // Place multiple different OEM-shape magics to simulate ambiguity.
    for (i, shape) in OemShape::all().iter().enumerate() {
        let offset = i * 512;
        if offset + 16 <= buf.len() {
            let magic = synthetic_magic(*shape);
            let end = (offset + magic.len()).min(buf.len());
            buf[offset..end].copy_from_slice(&magic[..end - offset]);
        }
    }
    rng.fill(&mut buf[2560..]);
    buf
}

fn generate_wrong_offset(rng: &mut DeterministicRng, oem: OemShape) -> Vec<u8> {
    let mut buf = vec![0u8; FIXTURE_SIZE];
    let magic = synthetic_magic(oem);
    // Place magic at an unexpected offset instead of 0.
    let wrong_offset = 777;
    buf[wrong_offset..wrong_offset + magic.len()].copy_from_slice(magic);
    rng.fill(&mut buf[wrong_offset + magic.len()..wrong_offset + 512]);
    buf
}

fn generate_lone_magic(rng: &mut DeterministicRng, oem: OemShape) -> Vec<u8> {
    let mut buf = vec![0u8; FIXTURE_SIZE];
    let magic = synthetic_magic(oem);
    // Only the magic value, nothing else — should NOT pass detection.
    buf[..magic.len()].copy_from_slice(magic);
    let _ = rng; // Unused for this shape.
    buf
}

fn generate_overwritten(rng: &mut DeterministicRng, oem: OemShape) -> Vec<u8> {
    let mut buf = generate_normal(rng, oem);
    // Zero out the structure area to simulate overwriting.
    for byte in buf[0..512].iter_mut() {
        *byte = 0;
    }
    buf
}

fn generate_known_negative(rng: &mut DeterministicRng, _oem: OemShape) -> Vec<u8> {
    let mut buf = vec![0u8; FIXTURE_SIZE];
    rng.fill(&mut buf);
    // Put FAT32 magic instead
    buf[82..82+8].copy_from_slice(b"FAT32   ");
    buf
}

fn generate_corrupted(rng: &mut DeterministicRng, oem: OemShape) -> Vec<u8> {
    let mut buf = generate_normal(rng, oem);
    // Scramble the index area
    rng.fill(&mut buf[512..1024]);
    buf
}

fn generate_partial(rng: &mut DeterministicRng, oem: OemShape) -> Vec<u8> {
    let mut buf = generate_normal(rng, oem);
    // Trim to just past the header
    buf.truncate(600);
    buf
}

fn generate_false_positive(rng: &mut DeterministicRng, oem: OemShape) -> Vec<u8> {
    let mut buf = vec![0u8; FIXTURE_SIZE];
    rng.fill(&mut buf);
    // Place magic in middle of random data
    let magic = synthetic_magic(oem);
    buf[4096..4096+magic.len()].copy_from_slice(magic);
    buf
}

fn generate_missing_frame(rng: &mut DeterministicRng, oem: OemShape) -> Vec<u8> {
    let mut buf = generate_normal(rng, oem);
    // Zero out a chunk simulating a missing frame
    for byte in buf[4096..5120].iter_mut() {
        *byte = 0;
    }
    buf
}

fn generate_deleted(rng: &mut DeterministicRng, oem: OemShape) -> Vec<u8> {
    let mut buf = generate_normal(rng, oem);
    // Set a common deleted marker (e.g., 0xE5 in FAT, or just zeroes in header)
    buf[0] = 0xE5;
    buf
}

fn generate_orphaned(rng: &mut DeterministicRng, _oem: OemShape) -> Vec<u8> {
    let mut buf = vec![0u8; FIXTURE_SIZE];
    // No headers, just random data imitating video frames
    rng.fill(&mut buf);
    buf
}

fn generate_unknown_model(rng: &mut DeterministicRng, oem: OemShape) -> Vec<u8> {
    let mut buf = generate_normal(rng, oem);
    // Overwrite the corroborating tag with a valid but unknown tag
    let tag = synthetic_corroborating_tag(oem);
    buf[512..512+tag.len()].copy_from_slice(&vec![b'X'; tag.len()]);
    buf
}

fn generate_unknown_firmware(rng: &mut DeterministicRng, oem: OemShape) -> Vec<u8> {
    let mut buf = generate_normal(rng, oem);
    // Alter firmware version strings (dummy)
    buf[1024..1024+4].copy_from_slice(b"V9.9");
    buf
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fixture_reproducibility() {
        // Same seed → same bytes (Property: deterministic fixtures).
        let a = generate_fixture(OemShape::Dahua, FixtureShape::Normal, 42);
        let b = generate_fixture(OemShape::Dahua, FixtureShape::Normal, 42);
        assert_eq!(a.bytes, b.bytes);
        assert_eq!(a.label, "synthetic");
    }

    #[test]
    fn different_seeds_produce_different_bytes() {
        let a = generate_fixture(OemShape::Dahua, FixtureShape::Normal, 42);
        let b = generate_fixture(OemShape::Dahua, FixtureShape::Normal, 43);
        assert_ne!(a.bytes, b.bytes);
    }

    #[test]
    fn different_oems_produce_different_bytes() {
        let a = generate_fixture(OemShape::Dahua, FixtureShape::Normal, 42);
        let b = generate_fixture(OemShape::Hikvision, FixtureShape::Normal, 42);
        assert_ne!(a.bytes, b.bytes);
    }

    #[test]
    fn all_fixtures_labeled_synthetic() {
        for oem in OemShape::all() {
            for shape in FixtureShape::all() {
                let fixture = generate_fixture(*oem, *shape, 1);
                assert_eq!(fixture.label, "synthetic");
                assert!(!fixture.is_empty());
            }
        }
    }

    #[test]
    fn five_oem_shapes_available() {
        assert_eq!(OemShape::all().len(), 5);
    }

    #[test]
    fn all_fixture_shapes_available() {
        assert_eq!(FixtureShape::all().len(), 17);
    }

    #[test]
    fn sparse_fixture_has_zeros() {
        let fixture = generate_fixture(OemShape::Dahua, FixtureShape::Sparse, 1);
        // Middle section should be zeros (sparse).
        let middle = &fixture.bytes[FIXTURE_SIZE..FIXTURE_SIZE * 2];
        assert!(middle.iter().all(|b| *b == 0));
    }

    #[test]
    fn truncated_fixture_is_shorter() {
        let normal = generate_fixture(OemShape::Dahua, FixtureShape::Normal, 1);
        let truncated = generate_fixture(OemShape::Dahua, FixtureShape::Truncated, 1);
        assert!(truncated.len() < normal.len());
    }

    #[test]
    fn lone_magic_has_minimal_content() {
        let fixture = generate_fixture(OemShape::Dahua, FixtureShape::LoneMagic, 1);
        let magic = synthetic_magic(OemShape::Dahua);
        // Magic is present.
        assert_eq!(&fixture.bytes[..magic.len()], magic);
        // Rest is zeros.
        assert!(fixture.bytes[magic.len()..512].iter().all(|b| *b == 0));
    }

    #[test]
    fn overwritten_has_zeroed_header() {
        let fixture = generate_fixture(OemShape::Dahua, FixtureShape::Overwritten, 1);
        assert!(fixture.bytes[..512].iter().all(|b| *b == 0));
    }
}
