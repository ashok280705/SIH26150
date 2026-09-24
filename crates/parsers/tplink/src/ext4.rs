//! # EXT4 Superblock Reader
//! Minimal read-only EXT4 parser for verifying boundaries.

use evidence_reader::EvidenceReader;
use forensic_core::ForensicError;

pub struct Ext4Superblock;

impl Ext4Superblock {
    pub fn read_magic(reader: &dyn EvidenceReader, offset: u64) -> Result<u16, ForensicError> {
        let mut buf = [0u8; 2];
        let sb_magic_offset = offset + 1024 + 0x38;
        if reader.read_at(sb_magic_offset, &mut buf)? == 2 {
            Ok(u16::from_le_bytes(buf))
        } else {
            Err(ForensicError::corrupt(
                "ext4",
                "Failed to read superblock magic",
            ))
        }
    }
}
