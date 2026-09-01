//! # Read-Only Memory-Mapped Region Support
//!
//! Provides safe, bounded, read-only memory mappings for evidence chunks (Req 8.4, 1.6).
//!
//! Key invariants:
//! - Mappings are strictly read-only (`PROT_READ` / `PAGE_READONLY`).
//! - No writable mapping is ever created (Req 1.6).
//! - Large evidence files never force a full-image mapping.

use forensic_core::checked::validate_region_bounds;
use forensic_core::{ForensicError, Region};
use std::fs::File;
use std::os::fd::AsRawFd;
use std::ptr::NonNull;

/// A bounded, read-only memory-mapped region.
pub struct ReadOnlyMmap {
    ptr: NonNull<u8>,
    mapped_len: usize,
    region: Region,
    offset_in_map: usize,
}

// Safety: The memory mapping is immutable (PROT_READ) and does not mutate.
unsafe impl Send for ReadOnlyMmap {}
unsafe impl Sync for ReadOnlyMmap {}

impl ReadOnlyMmap {
    /// Map a bounded region of a file read-only.
    ///
    /// Validates bounds against the total file length before mapping.
    pub fn map_region(file: &File, region: Region, total_len: u64) -> Result<Self, ForensicError> {
        validate_region_bounds(&region, total_len)?;

        if region.length == 0 {
            return Err(ForensicError::corrupt("mmap_region", "cannot mmap zero-length region"));
        }

        #[cfg(unix)]
        {
            let page_size = unsafe { libc::sysconf(libc::_SC_PAGESIZE) as u64 };
            let page_size = if page_size == 0 { 4096 } else { page_size };

            let aligned_offset = (region.offset / page_size) * page_size;
            let offset_in_map = (region.offset - aligned_offset) as usize;
            let mapped_len = offset_in_map + region.length as usize;

            let fd = file.as_raw_fd();
            let ptr = unsafe {
                libc::mmap(
                    std::ptr::null_mut(),
                    mapped_len,
                    libc::PROT_READ,
                    libc::MAP_PRIVATE,
                    fd,
                    aligned_offset as libc::off_t,
                )
            };

            if ptr == libc::MAP_FAILED {
                return Err(ForensicError::io(
                    format!("mmap region [0x{:X}..0x{:X})", region.offset, region.offset + region.length),
                    std::io::Error::last_os_error(),
                ));
            }

            let non_null = NonNull::new(ptr as *mut u8).ok_or_else(|| {
                ForensicError::corrupt("mmap_region", "mmap returned null pointer")
            })?;

            Ok(Self {
                ptr: non_null,
                mapped_len,
                region,
                offset_in_map,
            })
        }

        #[cfg(not(unix))]
        {
            Err(ForensicError::UnsupportedFormat {
                format: "mmap".into(),
                reason: "mmap is only supported on Unix targets in this build".into(),
            })
        }
    }

    /// Access the mapped bytes corresponding to the requested region.
    pub fn as_slice(&self) -> &[u8] {
        unsafe {
            let start = self.ptr.as_ptr().add(self.offset_in_map);
            std::slice::from_raw_parts(start, self.region.length as usize)
        }
    }

    /// The mapped evidence region.
    pub fn region(&self) -> &Region {
        &self.region
    }
}

impl std::ops::Deref for ReadOnlyMmap {
    type Target = [u8];

    fn deref(&self) -> &Self::Target {
        self.as_slice()
    }
}

impl AsRef<[u8]> for ReadOnlyMmap {
    fn as_ref(&self) -> &[u8] {
        self.as_slice()
    }
}

impl Drop for ReadOnlyMmap {
    fn drop(&mut self) {
        #[cfg(unix)]
        unsafe {
            libc::munmap(self.ptr.as_ptr() as *mut libc::c_void, self.mapped_len);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    #[test]
    fn mmap_reads_correct_bytes() {
        let mut temp_path = std::env::temp_dir();
        temp_path.push(format!("mmap_test_{}.raw", uuid::Uuid::new_v4()));

        let test_data: Vec<u8> = (0..8192).map(|i| (i % 256) as u8).collect();
        {
            let mut f = File::create(&temp_path).unwrap();
            f.write_all(&test_data).unwrap();
        }

        let file = File::open(&temp_path).unwrap();
        let region = Region::new(100, 500).unwrap();
        let mmap = ReadOnlyMmap::map_region(&file, region, 8192).unwrap();

        assert_eq!(mmap.len(), 500);
        assert_eq!(&mmap[..], &test_data[100..600]);

        let _ = std::fs::remove_file(&temp_path);
    }
}
