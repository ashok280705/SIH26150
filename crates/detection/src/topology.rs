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

use forensic_core::{Finding, ForensicError, Region};
use serde::{Deserialize, Serialize};

/// The partition table or topology layout type detected on evidence.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TopologyType {
    /// Master Boot Record partition table (parsed by [`StorageTopologyProfiler::profile`]).
    Mbr,
    /// GUID Partition Table.
    ///
    /// **Reserved / not implemented.** The profiler does not parse GPT headers or entries
    /// yet; this variant exists so the type is forward-compatible, but no code path
    /// currently produces it. GPT-formatted evidence is classified as
    /// [`TopologyType::UnpartitionedRaw`] until real GPT support is added.
    Gpt,
    /// No recognized partition table; the whole image is treated as one candidate region.
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
    /// Additive forensic findings recorded during topology analysis (e.g. malformed,
    /// out-of-bounds, or overlapping MBR entries). This never alters the set of
    /// partition candidates; it preserves facts that would otherwise be discarded.
    #[serde(default)]
    pub findings: Vec<Finding>,
}

/// Storage topology analysis engine.
pub struct StorageTopologyProfiler;

impl StorageTopologyProfiler {
    /// Profile the storage topology of an evidence reader.
    ///
    /// The set of in-bounds partition candidates is computed exactly as before: only
    /// valid, in-bounds, typed, non-zero-length entries become `PartitionCandidate`s.
    /// In addition, malformed, out-of-bounds, and overlapping entries are recorded as
    /// additive [`Finding`]s so no forensic fact is silently discarded. Out-of-bounds
    /// partitions are NOT added to the candidate list (that preserves existing detector
    /// behavior); their safe clamped region is carried inside the finding instead.
    pub fn profile(
        reader: &dyn EvidenceReader,
        sector_size_override: Option<u64>,
    ) -> Result<StorageTopology, ForensicError> {
        let sector_size = sector_size_override.unwrap_or(512);
        if sector_size == 0 {
            return Err(ForensicError::corrupt("topology", "sector size cannot be zero"));
        }

        // Additive forensic findings gathered during MBR analysis. Collected at function
        // scope so they are reported regardless of which topology branch returns.
        let mut findings: Vec<Finding> = Vec::new();

        let total_len = reader.len();
        if total_len < 512 {
            return Ok(StorageTopology {
                topology_type: TopologyType::UnpartitionedRaw,
                sector_size,
                partitions: vec![],
                unpartitioned_regions: vec![Region::new(0, total_len)?],
                findings,
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
                let start_lba =
                    u32::from_le_bytes([entry[8], entry[9], entry[10], entry[11]]) as u64;
                let num_sectors =
                    u32::from_le_bytes([entry[12], entry[13], entry[14], entry[15]]) as u64;

                // A6: an unused (type 0x00) entry is normal per the MBR convention and
                // is skipped without a finding — UNLESS it also declares geometry, which
                // is anomalous and worth preserving.
                if p_type == 0 {
                    if start_lba != 0 || num_sectors != 0 {
                        findings.push(Finding::info(
                            "mbr.entry.unused_with_geometry",
                            format!(
                                "MBR entry {i} has type 0x00 (unused) but declares start_lba={start_lba}, sectors={num_sectors}"
                            ),
                            Region::point(0),
                        ));
                    }
                    continue; // Existing behavior preserved: not a partition candidate.
                }

                // A6: a typed entry with zero length is malformed and skipped.
                if num_sectors == 0 {
                    findings.push(Finding::warning(
                        "mbr.entry.zero_length",
                        format!(
                            "MBR entry {i} (type 0x{p_type:02X}) declares zero sectors and is skipped"
                        ),
                        Region::point(0),
                    ));
                    continue; // Existing behavior preserved: never a candidate.
                }

                // Compute the declared byte region using checked arithmetic.
                let (byte_offset, byte_len) = match (
                    checked_sector_offset(start_lba, sector_size),
                    checked_sector_offset(num_sectors, sector_size),
                ) {
                    (Ok(o), Ok(l)) => (o, l),
                    _ => {
                        // A6: sector arithmetic overflow — preserve the fact, skip entry.
                        findings.push(Finding::error(
                            "mbr.partition.sector_overflow",
                            format!(
                                "MBR entry {i} (type 0x{p_type:02X}) sector arithmetic overflows: start_lba={start_lba}, sectors={num_sectors}, sector_size={sector_size}"
                            ),
                            Region::point(0),
                        ));
                        continue;
                    }
                };

                let declared = match Region::new(byte_offset, byte_len) {
                    Ok(r) => r,
                    Err(_) => {
                        findings.push(Finding::error(
                            "mbr.partition.region_overflow",
                            format!(
                                "MBR entry {i} (type 0x{p_type:02X}) declared region overflows u64: offset={byte_offset}, length={byte_len}"
                            ),
                            Region::point(0),
                        ));
                        continue;
                    }
                };

                if validate_region_bounds(&declared, total_len).is_ok() {
                    // In-bounds partition: existing behavior — push the candidate as-is.
                    partitions.push(PartitionCandidate {
                        index: i,
                        partition_type: format!("0x{:02X}", p_type),
                        start_sector: start_lba,
                        sector_count: num_sectors,
                        sector_size,
                        region: declared,
                    });
                } else {
                    // A4: the declared partition extends beyond the evidence. Preserve
                    // the ORIGINAL declared region in the finding and record a safe
                    // clamped region for any downstream consumer that wants it. The
                    // candidate list is intentionally NOT extended (an out-of-bounds
                    // entry was dropped before, and detectors must keep seeing the same
                    // candidates). We never read outside evidence bounds.
                    let safe = if byte_offset < total_len {
                        Region::new(byte_offset, total_len - byte_offset)
                            .unwrap_or_else(|_| Region::point(byte_offset))
                    } else {
                        // Entirely beyond the evidence: no readable bytes.
                        Region::point(byte_offset.min(total_len))
                    };
                    findings.push(
                        Finding::warning(
                            "mbr.partition.out_of_bounds",
                            format!(
                                "MBR entry {i} (type 0x{p_type:02X}) declares {declared} which extends beyond evidence length {total_len}; clamped to {safe} for safe access"
                            ),
                            safe,
                        )
                        .with_declared(declared),
                    );
                }
            }

            // A5: detect overlapping partition candidates using the existing
            // Region::overlaps. Record a finding per overlapping pair; candidates are
            // never merged, reordered, deleted, or otherwise altered.
            for a in 0..partitions.len() {
                for b in (a + 1)..partitions.len() {
                    let pa = &partitions[a];
                    let pb = &partitions[b];
                    if pa.region.overlaps(&pb.region) {
                        let overlap = pa
                            .region
                            .intersection(&pb.region)
                            .unwrap_or_else(|| Region::point(pa.region.offset));
                        findings.push(Finding::warning(
                            "mbr.partition.overlap",
                            format!(
                                "MBR partitions {} ({}) and {} ({}) overlap on {}",
                                pa.index, pa.region, pb.index, pb.region, overlap
                            ),
                            overlap,
                        ));
                    }
                }
            }

            if !partitions.is_empty() {
                return Ok(StorageTopology {
                    topology_type: TopologyType::Mbr,
                    sector_size,
                    partitions,
                    unpartitioned_regions: vec![],
                    findings,
                });
            }
        }

        // If no valid partition table found, treat entire image as unpartitioned raw candidate
        Ok(StorageTopology {
            topology_type: TopologyType::UnpartitionedRaw,
            sector_size,
            partitions: vec![],
            unpartitioned_regions: vec![Region::new(0, total_len)?],
            findings,
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
        // Valid, in-bounds, single partition: no findings manufactured.
        assert!(
            topo.findings.is_empty(),
            "unexpected findings: {:?}",
            topo.findings
        );
    }

    // --- A4/A5/A6 test helpers ---

    /// Build an `n`-byte buffer with a valid MBR signature and write partition entries.
    fn mbr_image(total_len: usize, entries: &[(u8, u32, u32)]) -> Vec<u8> {
        let mut data = vec![0x00u8; total_len];
        data[510] = 0x55;
        data[511] = 0xAA;
        for (i, (p_type, start_lba, num_sectors)) in entries.iter().enumerate() {
            let base = 446 + i * 16;
            data[base + 4] = *p_type;
            data[base + 8..base + 12].copy_from_slice(&start_lba.to_le_bytes());
            data[base + 12..base + 16].copy_from_slice(&num_sectors.to_le_bytes());
        }
        data
    }

    fn find_code<'a>(topo: &'a StorageTopology, code: &str) -> Option<&'a forensic_core::Finding> {
        topo.findings.iter().find(|f| f.code == code)
    }

    #[test]
    fn a4_out_of_bounds_partition_is_clamped_and_recorded_not_added() {
        // Partition 0: valid, in bounds. Partition 1: declared far beyond the image.
        let total_len = 1_000_000;
        let data = mbr_image(
            total_len,
            &[
                (0x83, 1, 100),        // [512, 51712) — valid
                (0x83, 1000, 100_000), // [512000, 51712000) — out of bounds
            ],
        );
        let reader = MockReader { data };
        let topo = StorageTopologyProfiler::profile(&reader, None).unwrap();

        // Existing behavior preserved: only the in-bounds partition is a candidate.
        assert_eq!(topo.topology_type, TopologyType::Mbr);
        assert_eq!(topo.partitions.len(), 1);
        assert_eq!(topo.partitions[0].region.offset, 512);

        // A finding preserves the malformed declaration and a safe clamped region.
        let f = find_code(&topo, "mbr.partition.out_of_bounds")
            .expect("expected an out_of_bounds finding");
        let declared = f.declared_region.expect("declared region must be preserved");
        assert_eq!(declared.offset, 512_000);
        assert_eq!(declared.length, 51_200_000); // original declaration, not clamped
                                                  // Safe region is clamped to the image and is readable.
        assert_eq!(f.region.offset, 512_000);
        assert_eq!(f.region.end().unwrap(), total_len as u64);
    }

    #[test]
    fn a5_overlapping_partitions_are_recorded_not_merged() {
        // A: [512, 512512)  B: [256000, 768000) — overlap on [256000, 512512).
        let total_len = 1_000_000;
        let data = mbr_image(total_len, &[(0x83, 1, 1000), (0x07, 500, 1000)]);
        let reader = MockReader { data };
        let topo = StorageTopologyProfiler::profile(&reader, None).unwrap();

        // Both candidates are preserved unchanged (no merge, no winner chosen).
        assert_eq!(topo.partitions.len(), 2);
        let f = find_code(&topo, "mbr.partition.overlap").expect("expected an overlap finding");
        assert_eq!(f.region.offset, 256_000);
        assert_eq!(f.region.end().unwrap(), 512_512);
    }

    #[test]
    fn a6_zero_length_typed_entry_is_recorded_and_skipped() {
        // Only a zero-length typed entry: no candidate, falls through to raw, but the
        // finding is preserved.
        let total_len = 4096;
        let data = mbr_image(total_len, &[(0x83, 1, 0)]);
        let reader = MockReader { data };
        let topo = StorageTopologyProfiler::profile(&reader, None).unwrap();

        assert_eq!(topo.topology_type, TopologyType::UnpartitionedRaw);
        assert!(topo.partitions.is_empty());
        assert!(find_code(&topo, "mbr.entry.zero_length").is_some());
    }

    #[test]
    fn a6_unused_entry_with_geometry_is_recorded() {
        let total_len = 4096;
        let data = mbr_image(total_len, &[(0x00, 5, 10)]);
        let reader = MockReader { data };
        let topo = StorageTopologyProfiler::profile(&reader, None).unwrap();
        assert!(find_code(&topo, "mbr.entry.unused_with_geometry").is_some());
    }

    #[test]
    fn a6_ordinary_unused_entries_produce_no_findings() {
        // A single valid partition; the other three entries are all-zero (ordinary
        // unused). No findings should be manufactured for the empty entries.
        let total_len = 1_000_000;
        let data = mbr_image(total_len, &[(0x83, 1, 100)]);
        let reader = MockReader { data };
        let topo = StorageTopologyProfiler::profile(&reader, None).unwrap();
        assert_eq!(topo.partitions.len(), 1);
        assert!(
            topo.findings.is_empty(),
            "unexpected findings: {:?}",
            topo.findings
        );
    }

    #[test]
    fn a4_partition_ending_exactly_at_image_end_is_valid() {
        // [512, 51712) with total_len == 51712: ends exactly at the image end.
        let total_len = 51_712;
        let data = mbr_image(total_len, &[(0x83, 1, 100)]);
        let reader = MockReader { data };
        let topo = StorageTopologyProfiler::profile(&reader, None).unwrap();
        assert_eq!(topo.partitions.len(), 1);
        assert_eq!(topo.partitions[0].region.end().unwrap(), total_len as u64);
        assert!(
            topo.findings.is_empty(),
            "unexpected findings: {:?}",
            topo.findings
        );
    }
}
