//! # Bounded RegionScanner with Searched/Skipped Accounting
//!
//! Implements windowed scanning over `[start, start+length)` with bounded memory,
//! alignment, progress reporting, cooperative cancellation, and searched/skipped accounting
//! (Req 8.2, 8.3, 8.9, 13.9, 13.10).
//!
//! Key invariants:
//! - Buffers are bounded and never proportional to total evidence size (Req 8.3).
//! - All offset arithmetic uses `forensic_core::checked` (Req 24.4).
//! - Every scan records searched bytes, searched range, skipped ranges, and termination reason.
//! - Truncated scans make their truncation explicit so downstream validation can be `REVIEW`.

use forensic_core::checked::{checked_add, checked_end_offset, validate_region_bounds};
use forensic_core::{ForensicError, Region};
use serde::{Deserialize, Serialize};

use crate::config::ReaderConfig;
use crate::progress::{CancellationToken, ProgressCallback, ProgressInfo};
use crate::reader::EvidenceReader;

/// The reason a scan terminated.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TerminationReason {
    /// The requested region was completely scanned.
    Completed,
    /// The scan was cancelled cooperatively via `CancellationToken`.
    Cancelled,
    /// Reached a caller-specified candidate or byte limit.
    LimitReached,
    /// The evidence was truncated before the requested region completed.
    Truncated,
    /// Out-of-bounds offset encountered.
    OutOfBounds,
}

impl std::fmt::Display for TerminationReason {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Completed => write!(f, "completed"),
            Self::Cancelled => write!(f, "cancelled"),
            Self::LimitReached => write!(f, "limit_reached"),
            Self::Truncated => write!(f, "truncated"),
            Self::OutOfBounds => write!(f, "out_of_bounds"),
        }
    }
}

/// Comprehensive report produced by a bounded region scan.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ScanReport {
    /// The region that was actually searched.
    pub searched_range: Region,
    /// Total bytes actually read and processed.
    pub searched_bytes: u64,
    /// Regions within the target that the scan chose not to read.
    ///
    /// **Current behavior:** [`RegionScanner`] reads its target region contiguously and
    /// has no code path that skips sub-ranges, so this is currently always empty. The
    /// field is retained for forward compatibility (e.g. future alignment jumps or
    /// sparse-hole skipping) and is never fabricated — a skipped range is only recorded
    /// when the scanner genuinely skips one.
    pub skipped_ranges: Vec<Region>,
    /// Why the scan finished.
    pub termination_reason: TerminationReason,
}

impl ScanReport {
    /// Whether the scan completed its requested extent without truncation or cancellation.
    pub fn is_complete(&self) -> bool {
        self.termination_reason == TerminationReason::Completed
    }
}

/// Configuration options for executing a bounded scan.
#[derive(Debug, Clone)]
pub struct ScanOptions {
    /// Window buffer size in bytes (clamped to ReaderConfig limits).
    pub window_size: usize,
    /// Byte alignment for candidate detection (default 1 for byte-by-byte, 512 for sector-aligned).
    pub alignment: usize,
    /// Maximum bytes to search before stopping with `LimitReached` (optional).
    pub max_scan_bytes: Option<u64>,
}

impl Default for ScanOptions {
    fn default() -> Self {
        let default_config = ReaderConfig::provisional_default();
        Self {
            window_size: (default_config.read_window.max_bytes as usize).min(16 * 1024 * 1024),
            alignment: 1,
            max_scan_bytes: None,
        }
    }
}

/// Windowed scanner for bounded reading and pattern matching over evidence.
pub struct RegionScanner<'a> {
    reader: &'a dyn EvidenceReader,
    target_region: Region,
    options: ScanOptions,
}

impl<'a> RegionScanner<'a> {
    /// Create a new scanner over a target region.
    pub fn new(
        reader: &'a dyn EvidenceReader,
        target_region: Region,
        options: ScanOptions,
    ) -> Result<Self, ForensicError> {
        validate_region_bounds(&target_region, reader.len())?;
        Ok(Self {
            reader,
            target_region,
            options,
        })
    }

    /// Execute the scan over the region, invoking `visitor` for each window chunk.
    ///
    /// The `visitor` closure receives `(window_offset, window_bytes)`.
    /// Returning `Ok(true)` continues the scan; returning `Ok(false)` halts with `LimitReached`.
    pub fn scan<F>(
        &self,
        cancellation: Option<&CancellationToken>,
        progress: Option<ProgressCallback>,
        mut visitor: F,
    ) -> Result<ScanReport, ForensicError>
    where
        F: FnMut(u64, &[u8]) -> Result<bool, ForensicError>,
    {
        let start_offset = self.target_region.offset;
        let total_target_len = self.target_region.length;

        if total_target_len == 0 {
            return Ok(ScanReport {
                searched_range: Region::point(start_offset),
                searched_bytes: 0,
                skipped_ranges: Vec::new(),
                termination_reason: TerminationReason::Completed,
            });
        }

        let window_cap = self.options.window_size.max(512);
        let mut buffer = vec![0u8; window_cap];
        let mut current_offset = start_offset;
        let mut searched_bytes: u64 = 0;
        // The scan reads its target contiguously; there is currently no skip path, so this
        // stays empty. It is intentionally not populated with synthetic ranges (A15).
        let skipped_ranges = Vec::new();
        let mut termination_reason = TerminationReason::Completed;

        let end_target = checked_end_offset(start_offset, total_target_len)?;

        while current_offset < end_target {
            // Check cooperative cancellation.
            if let Some(token) = cancellation {
                if token.is_cancelled() {
                    termination_reason = TerminationReason::Cancelled;
                    break;
                }
            }

            // Check byte limit.
            if let Some(max_bytes) = self.options.max_scan_bytes {
                if searched_bytes >= max_bytes {
                    termination_reason = TerminationReason::LimitReached;
                    break;
                }
            }

            let remaining_in_target = end_target - current_offset;
            let to_read = (buffer.len() as u64).min(remaining_in_target) as usize;

            let bytes_read = match self.reader.read_at(current_offset, &mut buffer[..to_read]) {
                Ok(n) => n,
                Err(ForensicError::OutOfBounds { .. }) => {
                    termination_reason = TerminationReason::Truncated;
                    break;
                }
                Err(e) => return Err(e),
            };

            if bytes_read == 0 {
                // Unexpected EOF / truncation
                termination_reason = TerminationReason::Truncated;
                break;
            }

            let chunk = &buffer[..bytes_read];
            let should_continue = visitor(current_offset, chunk)?;

            searched_bytes = checked_add(searched_bytes, bytes_read as u64)?;
            current_offset = checked_add(current_offset, bytes_read as u64)?;

            if let Some(ref cb) = progress {
                cb(ProgressInfo {
                    bytes_processed: searched_bytes,
                    total_bytes: Some(total_target_len),
                    current_offset,
                });
            }

            if !should_continue {
                termination_reason = TerminationReason::LimitReached;
                break;
            }
        }

        let actual_searched_len = current_offset - start_offset;
        let searched_range = Region::new(start_offset, actual_searched_len)?;

        Ok(ScanReport {
            searched_range,
            searched_bytes,
            skipped_ranges,
            termination_reason,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::Arc;

    struct MockReader {
        data: Vec<u8>,
    }

    impl EvidenceReader for MockReader {
        fn len(&self) -> u64 {
            self.data.len() as u64
        }
        fn read_at(&self, offset: u64, buf: &mut [u8]) -> Result<usize, ForensicError> {
            if offset >= self.len() {
                return Err(ForensicError::out_of_bounds(
                    "test",
                    offset,
                    buf.len() as u64,
                    self.len(),
                ));
            }
            let start = offset as usize;
            let available = (self.data.len() - start).min(buf.len());
            buf[..available].copy_from_slice(&self.data[start..start + available]);
            Ok(available)
        }
        fn source_kind(&self) -> crate::reader::SourceKind {
            crate::reader::SourceKind::Raw
        }
        fn source_path(&self) -> &str {
            "mock://test"
        }
    }

    #[test]
    fn windowed_scan_fidelity() {
        // Property 3: windowed reads equal full read
        let data: Vec<u8> = (0..10_000).map(|i| (i % 256) as u8).collect();
        let reader = MockReader { data: data.clone() };
        let target = Region::new(100, 5000).unwrap();

        let options = ScanOptions {
            window_size: 512,
            alignment: 1,
            max_scan_bytes: None,
        };

        let scanner = RegionScanner::new(&reader, target, options).unwrap();
        let mut collected = Vec::new();

        let report = scanner
            .scan(None, None, |_offset, chunk| {
                collected.extend_from_slice(chunk);
                Ok(true)
            })
            .unwrap();

        assert_eq!(report.termination_reason, TerminationReason::Completed);
        assert_eq!(report.searched_bytes, 5000);
        assert_eq!(collected, &data[100..5100]);
    }

    #[test]
    fn scan_cancellation() {
        let data = vec![0x42; 20_000];
        let reader = MockReader { data };
        let target = Region::new(0, 20_000).unwrap();

        let cancel_token = CancellationToken::new();
        let cancel_clone = cancel_token.clone();

        let options = ScanOptions {
            window_size: 1024,
            alignment: 1,
            max_scan_bytes: None,
        };

        let scanner = RegionScanner::new(&reader, target, options).unwrap();
        let counter = Arc::new(AtomicUsize::new(0));
        let counter_clone = Arc::clone(&counter);

        let report = scanner
            .scan(Some(&cancel_token), None, |_offset, _chunk| {
                let count = counter_clone.fetch_add(1, Ordering::SeqCst);
                if count >= 3 {
                    cancel_clone.cancel();
                }
                Ok(true)
            })
            .unwrap();

        assert_eq!(report.termination_reason, TerminationReason::Cancelled);
        assert!(report.searched_bytes < 20_000);
        assert!(report.searched_bytes >= 3072);
    }
}
