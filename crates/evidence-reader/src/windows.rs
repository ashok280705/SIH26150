//! # Windows Physical Drive and Device Reader
//!
//! Provides read-only access to physical block devices (`\\.\PhysicalDriveN`, `\\.\Volume{...}`)
//! on Windows systems using Win32 API handles.
//!
//! Invariants:
//! - Device handles are opened exclusively read-only (`GENERIC_READ`).
//! - Shared read and write (`FILE_SHARE_READ | FILE_SHARE_WRITE`) to avoid collision with OS volume locks.
//! - Exact capacity is queried using `IOCTL_DISK_GET_LENGTH_INFO`.
//! - No write method exists at the type level.
//! - All Win32 FFI is isolated within this module behind `#[cfg(windows)]`.

#![cfg(windows)]

use std::path::{Path, PathBuf};
use std::sync::Mutex;

use forensic_core::ForensicError;
use windows_sys::Win32::Foundation::{
    CloseHandle, GetLastError, GENERIC_READ, HANDLE, INVALID_HANDLE_VALUE,
};
use windows_sys::Win32::Storage::FileSystem::{
    CreateFileW, ReadFile, SetFilePointerEx, FILE_ATTRIBUTE_NORMAL, FILE_SHARE_READ,
    FILE_SHARE_WRITE, OPEN_EXISTING,
};
use windows_sys::Win32::System::Ioctl::IOCTL_DISK_GET_LENGTH_INFO;
use windows_sys::Win32::System::IO::DeviceIoControl;

use crate::reader::{EvidenceReader, SourceKind};

#[repr(C)]
#[derive(Default, Clone, Copy)]
struct GetLengthInformation {
    length: i64,
}

/// Safe wrapper around a read-only Win32 device HANDLE.
pub struct WindowsPhysicalReader {
    handle: Mutex<HANDLE>,
    len: u64,
    path: PathBuf,
    sector_size: u32,
}

// Safety: WindowsPhysicalReader protects its HANDLE access with a Mutex,
// exposing only read operations and satisfying Send + Sync.
unsafe impl Send for WindowsPhysicalReader {}
unsafe impl Sync for WindowsPhysicalReader {}

impl Drop for WindowsPhysicalReader {
    fn drop(&mut self) {
        if let Ok(guard) = self.handle.lock() {
            let h = *guard;
            if h != std::ptr::null_mut() && h != INVALID_HANDLE_VALUE {
                unsafe {
                    CloseHandle(h);
                }
            }
        }
    }
}

impl WindowsPhysicalReader {
    /// Opens a physical disk or volume path (e.g. `\\.\PhysicalDrive0`) read-only.
    pub fn open(path: impl AsRef<Path>) -> Result<Self, ForensicError> {
        let path_ref = path.as_ref();
        let path_str = path_ref.to_string_lossy();

        // Convert path to wide string (UTF-16, null terminated)
        let wide_path: Vec<u16> = path_str.encode_utf16().chain(std::iter::once(0)).collect();

        let handle = unsafe {
            CreateFileW(
                wide_path.as_ptr(),
                GENERIC_READ,
                FILE_SHARE_READ | FILE_SHARE_WRITE,
                std::ptr::null(),
                OPEN_EXISTING,
                FILE_ATTRIBUTE_NORMAL,
                std::ptr::null_mut(),
            )
        };

        if handle == INVALID_HANDLE_VALUE {
            let err = unsafe { GetLastError() };
            return Err(ForensicError::io(
                format!("Failed to open physical drive '{}'", path_str),
                std::io::Error::from_raw_os_error(err as i32),
            ));
        }

        // Query exact device capacity via IOCTL_DISK_GET_LENGTH_INFO
        let mut length_info = GetLengthInformation::default();
        let mut bytes_returned = 0u32;

        let success = unsafe {
            DeviceIoControl(
                handle,
                IOCTL_DISK_GET_LENGTH_INFO,
                std::ptr::null(),
                0,
                &mut length_info as *mut _ as *mut _,
                std::mem::size_of::<GetLengthInformation>() as u32,
                &mut bytes_returned,
                std::ptr::null_mut(),
            )
        };

        let len = if success != 0 && length_info.length > 0 {
            length_info.length as u64
        } else {
            // Fallback: try seeking to end if IOCTL fails (e.g., for regular file opened as device)
            let mut end_pos = 0i64;
            let seek_ok = unsafe { SetFilePointerEx(handle, 0, &mut end_pos, 2 /* FILE_END */) };
            if seek_ok != 0 && end_pos >= 0 {
                // Seek back to start
                let mut zero_pos = 0i64;
                unsafe {
                    SetFilePointerEx(handle, 0, &mut zero_pos, 0 /* FILE_BEGIN */);
                }
                end_pos as u64
            } else {
                let err = unsafe { GetLastError() };
                unsafe {
                    CloseHandle(handle);
                }
                return Err(ForensicError::io(
                    format!("Failed to determine capacity for device '{}'", path_str),
                    std::io::Error::from_raw_os_error(err as i32),
                ));
            }
        };

        Ok(Self {
            handle: Mutex::new(handle),
            len,
            path: path_ref.to_path_buf(),
            sector_size: 512,
        })
    }

    /// Access the detected sector size.
    pub fn sector_size(&self) -> u32 {
        self.sector_size
    }
}

impl EvidenceReader for WindowsPhysicalReader {
    fn len(&self) -> u64 {
        self.len
    }

    fn read_at(&self, offset: u64, buf: &mut [u8]) -> Result<usize, ForensicError> {
        if buf.is_empty() {
            return Ok(0);
        }

        if offset >= self.len {
            return Err(ForensicError::out_of_bounds(
                "WindowsPhysicalReader::read_at: offset beyond device capacity",
                offset,
                buf.len() as u64,
                self.len,
            ));
        }

        let remaining = (self.len - offset) as usize;
        let to_read = buf.len().min(remaining);

        let guard = self.handle.lock().map_err(|_| {
            ForensicError::io(
                "Locking physical drive handle",
                std::io::Error::other("mutex poisoned"),
            )
        })?;
        let handle = *guard;

        // Set file pointer to requested offset
        let mut new_pos = 0i64;
        let seek_res =
            unsafe { SetFilePointerEx(handle, offset as i64, &mut new_pos, 0 /* FILE_BEGIN */) };
        if seek_res == 0 {
            let err = unsafe { GetLastError() };
            return Err(ForensicError::io(
                format!("Failed to seek to offset {offset} on physical drive"),
                std::io::Error::from_raw_os_error(err as i32),
            ));
        }

        let mut bytes_read = 0u32;
        let read_res = unsafe {
            ReadFile(
                handle,
                buf.as_mut_ptr() as *mut _,
                to_read as u32,
                &mut bytes_read,
                std::ptr::null_mut(),
            )
        };

        if read_res == 0 {
            let err = unsafe { GetLastError() };
            return Err(ForensicError::io(
                format!("Failed to read {to_read} bytes at offset {offset} on physical drive"),
                std::io::Error::from_raw_os_error(err as i32),
            ));
        }

        Ok(bytes_read as usize)
    }

    fn source_kind(&self) -> SourceKind {
        SourceKind::PhysicalDisk
    }

    fn source_path(&self) -> &str {
        self.path.to_str().unwrap_or("<non-utf8 physical path>")
    }
}

impl std::fmt::Debug for WindowsPhysicalReader {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("WindowsPhysicalReader")
            .field("path", &self.path)
            .field("len", &self.len)
            .field("sector_size", &self.sector_size)
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn physical_reader_is_send_sync() {
        fn assert_send_sync<T: Send + Sync>() {}
        assert_send_sync::<WindowsPhysicalReader>();
    }

    #[test]
    fn open_nonexistent_physical_drive_fails_with_io_error() {
        let result = WindowsPhysicalReader::open(r"\\.\PhysicalDrive9999");
        assert!(result.is_err());
        match result {
            Err(ForensicError::Io { context, .. }) => {
                assert!(context.contains("PhysicalDrive9999"));
            }
            other => panic!("expected ForensicError::Io, got {other:?}"),
        }
    }
}
