//! # SourceDevice Physical Acquisition Abstraction
//!
//! Separates physical source acquisition from forensic analysis (`EvidenceReader`).
//! Guarantee: Source handles are strictly read-only (`GENERIC_READ`).

use crate::error::AcquisitionError;
use crate::types::PhysicalSource;

/// Abstraction for a readable physical storage source.
pub trait SourceDevice: Send + Sync {
    /// Device path (e.g. `\\.\PhysicalDrive1` or synthetic test path).
    fn path(&self) -> &str;

    /// Total capacity in bytes.
    fn capacity(&self) -> u64;

    /// Logical sector size in bytes (e.g. 512, 4096).
    fn logical_sector_size(&self) -> u32;

    /// Physical sector size in bytes (e.g. 512, 4096).
    fn physical_sector_size(&self) -> u32;

    /// Read bytes into `buf` at `offset`.
    ///
    /// Must adhere to sector alignment constraints required by the backing I/O mode.
    fn read_exact_at(&self, offset: u64, buf: &mut [u8]) -> Result<usize, AcquisitionError>;

    /// Source device metadata, if enumerated.
    fn metadata(&self) -> Option<&PhysicalSource> {
        None
    }
}

/// A synthetic in-memory SourceDevice for testing and validation.
///
/// Supports injecting bad sector ranges and simulated read failures.
#[derive(Debug, Clone)]
pub struct MockSourceDevice {
    pub path: String,
    pub data: Vec<u8>,
    pub logical_sector_size: u32,
    pub physical_sector_size: u32,
    /// Offset ranges that fail on read: `(start_offset, length, fail_count_remaining)`
    pub bad_ranges: std::sync::Arc<std::sync::Mutex<Vec<(u64, u64, u32)>>>,
}

impl MockSourceDevice {
    pub fn new(path: impl Into<String>, data: Vec<u8>) -> Self {
        Self {
            path: path.into(),
            data,
            logical_sector_size: 512,
            physical_sector_size: 512,
            bad_ranges: std::sync::Arc::new(std::sync::Mutex::new(Vec::new())),
        }
    }

    pub fn with_sector_size(mut self, logical: u32, physical: u32) -> Self {
        self.logical_sector_size = logical;
        self.physical_sector_size = physical;
        self
    }

    /// Inject a bad range that fails with an I/O error `retries` times before succeeding (or infinite if retries == u32::MAX).
    pub fn inject_bad_range(&self, start: u64, len: u64, retries_before_success: u32) {
        let mut guard = self.bad_ranges.lock().unwrap();
        guard.push((start, len, retries_before_success));
    }
}

impl SourceDevice for MockSourceDevice {
    fn path(&self) -> &str {
        &self.path
    }

    fn capacity(&self) -> u64 {
        self.data.len() as u64
    }

    fn logical_sector_size(&self) -> u32 {
        self.logical_sector_size
    }

    fn physical_sector_size(&self) -> u32 {
        self.physical_sector_size
    }

    fn read_exact_at(&self, offset: u64, buf: &mut [u8]) -> Result<usize, AcquisitionError> {
        if offset >= self.capacity() {
            return Ok(0);
        }

        let to_read = buf.len().min((self.capacity() - offset) as usize);

        // Check injected errors
        {
            let mut guard = self.bad_ranges.lock().unwrap();
            for (bad_start, bad_len, retries_left) in guard.iter_mut() {
                let bad_end = *bad_start + *bad_len;
                let req_end = offset + to_read as u64;

                // Overlap check
                if offset < bad_end && req_end > *bad_start {
                    if *retries_left > 0 {
                        if *retries_left != u32::MAX {
                            *retries_left -= 1;
                        }
                        return Err(AcquisitionError::SourceReadFailed {
                            offset,
                            len: to_read,
                            os_error: Some(23), // Win32 ERROR_CRC (cyclic redundancy check / bad sector)
                            message: format!("Simulated CRC bad sector error at offset {offset}"),
                        });
                    }
                }
            }
        }

        buf[..to_read].copy_from_slice(&self.data[offset as usize..offset as usize + to_read]);
        Ok(to_read)
    }
}
