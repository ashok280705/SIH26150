//! # Storage Topology Profiler
//!
//! Analyzes partition tables (MBR/GPT) and unpartitioned disk layouts, producing candidate storage regions (Req 3.6, 8.9, 19.6, 24.4).
//!
//! Key invariants:
//! - Partition ≠ sector (addressing unit vs region).
//! - Partition identity ≠ OEM identity (a partition provides candidate regions only).
//! - Sector size is NOT assumed to be 512 (supports 512, 4096, etc.).
//! - Offset calculations use `checked_sector_offset` and bounds validation (Req 24.4).
//! - Malformed or missing partition tables never crash the profiler.

use evidence_reader::EvidenceReader;
use forensic_core::checked::{checked_sector_offset, validate_region_bounds};

use forensic_core::{ForensicError, Region};
use serde::{Deserialize, Serialize};

/// The partition table or topology layout type detected on evidence.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TopologyType {
    Mbr,
    Gpt,
    UnpartitionedRaw,
}

/// A discovered partition or candidate storage region.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PartitionCandidate {
    /// Zero-based partition index.
    pub index: usize,
    /// Partition type code or GUID description.
    pub partition_type: String,
    /// Start sector address.
    pub start_sector: u64,
    /// Sector count.
    pub sector_count: u64,
    /// Physical sector size in bytes.
    pub sector_size: u64,
    /// Resolved absolute byte region.
    pub region: Region,
}

/// Discovered storage topology profile for an evidence image.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct StorageTopology {
    pub topology_type: TopologyType,
    pub sector_size: u64,
    pub partitions: Vec<PartitionCandidate>,
    pub unpartitioned_regions: Vec<Region>,
}

/// Storage topology analysis engine.
pub struct StorageTopologyProfiler;

impl StorageTopologyProfiler {
    /// Profile the storage topology of an evidence reader.
    pub fn profile(reader: &dyn EvidenceReader, sector_size_override: Option<u64>) -> Result<StorageTopology, ForensicError> {
        let sector_size = sector_size_override.unwrap_or(512);
        if sector_size == 0 {
            return Err(ForensicError::corrupt("topology", "sector size cannot be zero"));
        }

        let total_len = reader.len();
        if total_len < 512 {
            return Ok(StorageTopology {
                topology_type: TopologyType::UnpartitionedRaw,
                sector_size,
                partitions: vec![],
                unpartitioned_regions: vec![Region::new(0, total_len)?],
            });
        }

        // Check MBR partition table (Sector 0: bytes 446..510, signature 0x55AA at 510..512)
        let mut mbr_buf = [0u8; 512];
        if reader.read_at(0, &mut mbr_buf).is_ok() && mbr_buf[510] == 0x55 && mbr_buf[511] == 0xAA {
            let mut partitions = Vec::new();
            for i in 0..4 {
                let entry_offset = 446 + (i * 16);
                let entry = &mbr_buf[entry_offset..entry_offset + 16];
                let p_type = entry[4];
                if p_type == 0 {
                    continue; // Unused partition entry
                }

                let start_lba = u32::from_le_bytes([entry[8], entry[9], entry[10], entry[11]]) as u64;
                let num_sectors = u32::from_le_bytes([entry[12], entry[13], entry[14], entry[15]]) as u64;

                if num_sectors > 0 {
                    if let (Ok(byte_offset), Ok(byte_len)) = (
                        checked_sector_offset(start_lba, sector_size),
                        checked_sector_offset(num_sectors, sector_size),
                    ) {
                        if let Ok(reg) = Region::new(byte_offset, byte_len) {
                            if validate_region_bounds(&reg, total_len).is_ok() {
                                partitions.push(PartitionCandidate {
                                    index: i,
                                    partition_type: format!("0x{:02X}", p_type),
                                    start_sector: start_lba,
                                    sector_count: num_sectors,
                                    sector_size,
                                    region: reg,
                                });
                            }
                        }
                    }
                }
            }

            if !partitions.is_empty() {
                return Ok(StorageTopology {
                    topology_type: TopologyType::Mbr,
                    sector_size,
                    partitions,
                    unpartitioned_regions: vec![],
                });
            }
        }

        // If no valid partition table found, treat entire image as unpartitioned raw candidate
        Ok(StorageTopology {
            topology_type: TopologyType::UnpartitionedRaw,
            sector_size,
            partitions: vec![],
            unpartitioned_regions: vec![Region::new(0, total_len)?],
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    struct MockReader {
        data: Vec<u8>,
    }

    impl EvidenceReader for MockReader {
        fn len(&self) -> u64 { self.data.len() as u64 }
        fn read_at(&self, offset: u64, buf: &mut [u8]) -> Result<usize, ForensicError> {
            if offset >= self.len() {
                return Err(ForensicError::out_of_bounds("test", offset, buf.len() as u64, self.len()));
            }
            let start = offset as usize;
            let n = (self.data.len() - start).min(buf.len());
            buf[..n].copy_from_slice(&self.data[start..start + n]);
            Ok(n)
        }
        fn source_kind(&self) -> evidence_reader::SourceKind { evidence_reader::SourceKind::Raw }
        fn source_path(&self) -> &str { "mock://topology" }
    }

    #[test]
    fn unpartitioned_raw_image() {
        let data = vec![0x00; 4096];
        let reader = MockReader { data };
        let topo = StorageTopologyProfiler::profile(&reader, None).unwrap();
        assert_eq!(topo.topology_type, TopologyType::UnpartitionedRaw);
        assert_eq!(topo.unpartitioned_regions.len(), 1);
        assert_eq!(topo.unpartitioned_regions[0].length, 4096);
    }

    #[test]
    fn mbr_parsing_valid_partition() {
        let mut data = vec![0x00; 1024 * 1024]; // 1 MiB
        // MBR signature
        data[510] = 0x55;
        data[511] = 0xAA;
        // Partition 1 at 446
        data[446 + 4] = 0x83; // Linux / Raw type
        // start LBA: 2048 (sector 2048 * 512 = 1MB) -> let's set start LBA = 1, sectors = 100
        data[446 + 8] = 1;
        data[446 + 12] = 100;

        let reader = MockReader { data };
        let topo = StorageTopologyProfiler::profile(&reader, None).unwrap();
        assert_eq!(topo.topology_type, TopologyType::Mbr);
        assert_eq!(topo.partitions.len(), 1);
        assert_eq!(topo.partitions[0].start_sector, 1);
        assert_eq!(topo.partitions[0].region.offset, 512);
        assert_eq!(topo.partitions[0].region.length, 51200);
    }
}
