//! # Raw/.dd/.img Reader Backend
//!
//! Implements `EvidenceReader` for raw binary image files and physical disks, opening
//! sources with read-only OS handles (Req 1.1, 1.6, 1.7, 8.1, 8.7).
//!
//! Key invariants:
//! - Sources are opened with read-only OS handles (O_RDONLY / GENERIC_READ).
//! - No code path acquires a writable handle to evidence.
//! - E01 returns `UnsupportedFormat` (gated by OPEN-1).

use std::fs::File;
use std::io::{Read, Seek, SeekFrom};
use std::path::{Path, PathBuf};
use std::sync::Mutex;

use forensic_core::ForensicError;

use crate::reader::{EvidenceReader, SourceKind};

/// A read-only reader for `.raw`, `.dd`, `.img` files and physical disks.
///
/// Opens the source with a read-only OS handle. The file handle is wrapped in a `Mutex`
/// for interior mutability (seeking) while keeping the reader `Send + Sync`.
pub struct RawReader {
    file: Mutex<File>,
    len: u64,
    path: PathBuf,
    source_kind: SourceKind,
}

impl RawReader {
    /// Open a raw image file in read-only mode.
    ///
    /// The file is opened with `File::open()` which uses `O_RDONLY` on Unix.
    /// E01 files are rejected with `UnsupportedFormat`.
    pub fn open(path: impl AsRef<Path>) -> Result<Self, ForensicError> {
        let path = path.as_ref();

        // Check for E01 — not implemented (OPEN-1).
        if let Some(ext) = path.extension().and_then(|e| e.to_str()) {
            let ext_lower = ext.to_lowercase();
            if ext_lower == "e01" || ext_lower.starts_with("e0") {
                return Err(ForensicError::UnsupportedFormat {
                    format: "E01/EWF".into(),
                    reason: "E01 support is gated by OPEN-1; use .raw/.dd/.img instead".into(),
                });
            }
        }

        // Open read-only (File::open = O_RDONLY on Unix, GENERIC_READ on Windows).
        let file = File::open(path)
            .map_err(|e| ForensicError::io(format!("opening evidence at {}", path.display()), e))?;

        let metadata = file.metadata().map_err(|e| {
            ForensicError::io(format!("reading metadata for {}", path.display()), e)
        })?;
        let len = metadata.len();

        // Determine source kind from extension.
        let source_kind = match path.extension().and_then(|e| e.to_str()) {
            Some(ext) => match ext.to_lowercase().as_str() {
                "dd" => SourceKind::Dd,
                "img" => SourceKind::Img,
                _ => SourceKind::Raw,
            },
            None => SourceKind::Raw,
        };

        Ok(Self {
            file: Mutex::new(file),
            len,
            path: path.to_path_buf(),
            source_kind,
        })
    }

    /// Open a physical disk device in read-only mode.
    ///
    /// **Unix-only.** This method is compiled only on Unix targets (`#[cfg(unix)]`); it
    /// determines the device size by seeking to the end of the block device. There is no
    /// Windows physical-disk backend at present — on Windows this method does not exist.
    #[cfg(unix)]
    pub fn open_device(path: impl AsRef<Path>) -> Result<Self, ForensicError> {
        let path = path.as_ref();
        let file = File::open(path)
            .map_err(|e| ForensicError::io(format!("opening device at {}", path.display()), e))?;

        // Get device size via seek to end.
        let mut f = file;
        let len = f.seek(SeekFrom::End(0)).map_err(|e| {
            ForensicError::io(format!("seeking to end of device {}", path.display()), e)
        })?;
        f.seek(SeekFrom::Start(0)).map_err(|e| {
            ForensicError::io(format!("seeking to start of device {}", path.display()), e)
        })?;

        Ok(Self {
            file: Mutex::new(f),
            len,
            path: path.to_path_buf(),
            source_kind: SourceKind::PhysicalDisk,
        })
    }

    /// Open a physical disk device in read-only mode on Windows (`\\.\PhysicalDriveN`, `\\.\Volume{...}`).
    #[cfg(windows)]
    pub fn open_device(
        path: impl AsRef<Path>,
    ) -> Result<crate::windows::WindowsPhysicalReader, ForensicError> {
        crate::windows::WindowsPhysicalReader::open(path)
    }
}

impl EvidenceReader for RawReader {
    fn len(&self) -> u64 {
        self.len
    }

    fn read_at(&self, offset: u64, buf: &mut [u8]) -> Result<usize, ForensicError> {
        if buf.is_empty() {
            return Ok(0);
        }

        // Bounds check using checked arithmetic.
        if offset >= self.len {
            return Err(ForensicError::out_of_bounds(
                "read_at: offset beyond source",
                offset,
                buf.len() as u64,
                self.len,
            ));
        }

        let mut file = self.file.lock().map_err(|_| {
            ForensicError::io(
                "locking file handle",
                std::io::Error::other("mutex poisoned"),
            )
        })?;

        file.seek(SeekFrom::Start(offset))
            .map_err(|e| ForensicError::io(format!("seeking to offset {offset}"), e))?;

        // Limit read to remaining bytes.
        let remaining = (self.len - offset) as usize;
        let to_read = buf.len().min(remaining);

        file.read(&mut buf[..to_read])
            .map_err(|e| ForensicError::io(format!("reading at offset {offset}"), e))
    }

    fn source_kind(&self) -> SourceKind {
        self.source_kind
    }

    fn source_path(&self) -> &str {
        self.path.to_str().unwrap_or("<non-utf8 path>")
    }
}

// Debug impl that doesn't expose the file handle.
impl std::fmt::Debug for RawReader {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RawReader")
            .field("path", &self.path)
            .field("len", &self.len)
            .field("source_kind", &self.source_kind)
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn open_nonexistent_file() {
        let result = RawReader::open("/nonexistent/evidence.raw");
        assert!(result.is_err());
    }

    #[test]
    fn e01_rejected() {
        let result = RawReader::open("/any/path/evidence.E01");
        match result {
            Err(ForensicError::UnsupportedFormat { format, .. }) => {
                assert!(format.contains("E01"));
            }
            other => panic!("expected UnsupportedFormat, got {other:?}"),
        }
    }

    #[test]
    fn reader_is_send_sync() {
        fn assert_send_sync<T: Send + Sync>() {}
        assert_send_sync::<RawReader>();
    }

    #[test]
    fn test_platform_independent_read_boundaries() {
        use std::io::Write;
        let mut temp_path = std::env::temp_dir();
        temp_path.push(format!("raw_boundary_test_{}.raw", uuid::Uuid::new_v4()));

        let file_len = 256;
        let test_data: Vec<u8> = (0..file_len).map(|i| i as u8).collect();
        {
            let mut f = std::fs::File::create(&temp_path).unwrap();
            f.write_all(&test_data).unwrap();
        }

        let reader = RawReader::open(&temp_path).unwrap();
        assert_eq!(reader.len(), file_len as u64);

        // 1. Zero-length reads at 0, midpoint, and EOF
        let mut empty_buf = [0u8; 0];
        assert_eq!(reader.read_at(0, &mut empty_buf).unwrap(), 0);
        assert_eq!(reader.read_at(128, &mut empty_buf).unwrap(), 0);
        assert_eq!(reader.read_at(256, &mut empty_buf).unwrap(), 0);

        // 2. Exact full read
        let mut full_buf = vec![0u8; file_len];
        assert_eq!(reader.read_at(0, &mut full_buf).unwrap(), file_len);
        assert_eq!(full_buf, test_data);

        // 3. Boundary reads: read last 10 bytes exactly
        let mut tail_buf = [0u8; 10];
        assert_eq!(reader.read_at(246, &mut tail_buf).unwrap(), 10);
        assert_eq!(&tail_buf[..], &test_data[246..256]);

        // 4. Short reads: buffer larger than remaining bytes at offset
        let mut oversized_buf = [0u8; 20];
        let bytes_read = reader.read_at(250, &mut oversized_buf).unwrap();
        assert_eq!(bytes_read, 6);
        assert_eq!(&oversized_buf[..6], &test_data[250..256]);

        // 5. Out-of-range reads: offset == len
        let mut buf = [0u8; 4];
        let err = reader.read_at(256, &mut buf).unwrap_err();
        match err {
            ForensicError::OutOfBounds { offset, source_len, .. } => {
                assert_eq!(offset, 256);
                assert_eq!(source_len, 256);
            }
            other => panic!("expected OutOfBounds, got {other:?}"),
        }

        // 6. Out-of-range reads: offset > len
        let err = reader.read_at(300, &mut buf).unwrap_err();
        assert!(matches!(err, ForensicError::OutOfBounds { .. }));

        // 7. Large offsets
        let err = reader.read_at(u64::MAX - 50, &mut buf).unwrap_err();
        assert!(matches!(err, ForensicError::OutOfBounds { .. }));

        let _ = std::fs::remove_file(&temp_path);
    }
}
