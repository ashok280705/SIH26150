//! # Windows Physical Source Device
//!
//! Exclusively uses read-only Win32 OS handles (`GENERIC_READ`).
//! Never requests write access under any circumstance.

#![cfg(windows)]

use std::sync::Mutex;
use windows_sys::Win32::Foundation::{
    CloseHandle, GetLastError, ERROR_ACCESS_DENIED, ERROR_BAD_UNIT, ERROR_DEV_NOT_EXIST,
    ERROR_DEVICE_NOT_CONNECTED, ERROR_FILE_NOT_FOUND, GENERIC_READ, HANDLE, INVALID_HANDLE_VALUE,
};
use windows_sys::Win32::Storage::FileSystem::{
    CreateFileW, ReadFile, SetFilePointerEx, FILE_ATTRIBUTE_NORMAL, FILE_SHARE_READ,
    FILE_SHARE_WRITE, OPEN_EXISTING,
};
use windows_sys::Win32::System::Ioctl::IOCTL_DISK_GET_LENGTH_INFO;
use windows_sys::Win32::System::IO::DeviceIoControl;

use crate::error::AcquisitionError;
use crate::source::SourceDevice;
use crate::types::PhysicalSource;

#[repr(C)]
#[derive(Default, Clone, Copy)]
struct GetLengthInformation {
    length: i64,
}

#[repr(C)]
#[derive(Default, Clone, Copy)]
struct DiskGeometry {
    cylinders: i64,
    media_type: u32,
    tracks_per_cylinder: u32,
    sectors_per_track: u32,
    bytes_per_sector: u32,
}

#[repr(C)]
#[derive(Default, Clone, Copy)]
struct DiskGeometryEx {
    geometry: DiskGeometry,
    disk_size: i64,
    data: [u8; 1],
}

const IOCTL_DISK_GET_DRIVE_GEOMETRY_EX: u32 = 0x000700A0;

/// Read-only physical source device backed by a Win32 file handle.
pub struct WindowsSourceDevice {
    handle: Mutex<HANDLE>,
    path: String,
    capacity: u64,
    logical_sector_size: u32,
    physical_sector_size: u32,
    metadata: Option<PhysicalSource>,
}

unsafe impl Send for WindowsSourceDevice {}
unsafe impl Sync for WindowsSourceDevice {}

impl Drop for WindowsSourceDevice {
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

impl WindowsSourceDevice {
    /// Opens a physical block device (e.g. `\\.\PhysicalDrive0`) strictly read-only.
    pub fn open(path: &str, metadata: Option<PhysicalSource>) -> Result<Self, AcquisitionError> {
        let wide_path: Vec<u16> = path.encode_utf16().chain(std::iter::once(0)).collect();

        // Open strictly read-only with shared read/write
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
            if err == ERROR_ACCESS_DENIED {
                return Err(AcquisitionError::SourceAccessDenied {
                    path: path.to_string(),
                    message: "Access denied. Administrative privileges are required for PhysicalDrive acquisition.".to_string(),
                });
            }
            return Err(AcquisitionError::SourceOpenFailed {
                path: path.to_string(),
                os_error: Some(err as i32),
                message: format!("Win32 CreateFileW failed with error code {err}"),
            });
        }

        // Query length
        let mut length_info = GetLengthInformation::default();
        let mut bytes_returned = 0u32;
        let success_len = unsafe {
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

        let capacity = if success_len != 0 && length_info.length > 0 {
            length_info.length as u64
        } else if let Some(ref meta) = metadata {
            meta.capacity
        } else {
            let err = unsafe { GetLastError() };
            unsafe { CloseHandle(handle) };
            return Err(AcquisitionError::SourceOpenFailed {
                path: path.to_string(),
                os_error: Some(err as i32),
                message: "Failed to determine device capacity via IOCTL_DISK_GET_LENGTH_INFO".to_string(),
            });
        };

        // Query geometry for sector sizes
        let mut geom_ex = DiskGeometryEx::default();
        let mut geom_returned = 0u32;
        let success_geom = unsafe {
            DeviceIoControl(
                handle,
                IOCTL_DISK_GET_DRIVE_GEOMETRY_EX,
                std::ptr::null(),
                0,
                &mut geom_ex as *mut _ as *mut _,
                std::mem::size_of::<DiskGeometryEx>() as u32,
                &mut geom_returned,
                std::ptr::null_mut(),
            )
        };

        let logical_sector_size = if success_geom != 0 && geom_ex.geometry.bytes_per_sector > 0 {
            geom_ex.geometry.bytes_per_sector
        } else if let Some(ref meta) = metadata {
            meta.logical_sector_size
        } else {
            512 // Standard default fallback
        };

        let physical_sector_size = if let Some(ref meta) = metadata {
            meta.physical_sector_size
        } else {
            logical_sector_size
        };

        Ok(Self {
            handle: Mutex::new(handle),
            path: path.to_string(),
            capacity,
            logical_sector_size,
            physical_sector_size,
            metadata,
        })
    }
}

impl SourceDevice for WindowsSourceDevice {
    fn path(&self) -> &str {
        &self.path
    }

    fn capacity(&self) -> u64 {
        self.capacity
    }

    fn logical_sector_size(&self) -> u32 {
        self.logical_sector_size
    }

    fn physical_sector_size(&self) -> u32 {
        self.physical_sector_size
    }

    fn metadata(&self) -> Option<&PhysicalSource> {
        self.metadata.as_ref()
    }

    fn read_exact_at(&self, offset: u64, buf: &mut [u8]) -> Result<usize, AcquisitionError> {
        if buf.is_empty() {
            return Ok(0);
        }

        if offset >= self.capacity {
            return Ok(0);
        }

        let remaining = (self.capacity - offset) as usize;
        let to_read = buf.len().min(remaining);

        let guard = self.handle.lock().map_err(|_| {
            AcquisitionError::SourceReadFailed {
                offset,
                len: to_read,
                os_error: None,
                message: "Handle mutex poisoned".to_string(),
            }
        })?;
        let handle = *guard;

        let mut new_pos = 0i64;
        let seek_ok = unsafe {
            SetFilePointerEx(handle, offset as i64, &mut new_pos, 0 /* FILE_BEGIN */)
        };

        if seek_ok == 0 {
            let err = unsafe { GetLastError() };
            if err == ERROR_DEVICE_NOT_CONNECTED
                || err == ERROR_FILE_NOT_FOUND
                || err == ERROR_DEV_NOT_EXIST
                || err == ERROR_BAD_UNIT
            {
                return Err(AcquisitionError::SourceDisconnected {
                    offset,
                    message: format!("Device disappeared or disconnected during seek (Win32 code {err})"),
                });
            }
            return Err(AcquisitionError::SourceReadFailed {
                offset,
                len: to_read,
                os_error: Some(err as i32),
                message: format!("SetFilePointerEx to offset {offset} failed with Win32 code {err}"),
            });
        }

        let mut bytes_read = 0u32;
        let read_ok = unsafe {
            ReadFile(
                handle,
                buf.as_mut_ptr() as *mut _,
                to_read as u32,
                &mut bytes_read,
                std::ptr::null_mut(),
            )
        };

        if read_ok == 0 {
            let err = unsafe { GetLastError() };
            if err == ERROR_DEVICE_NOT_CONNECTED
                || err == ERROR_FILE_NOT_FOUND
                || err == ERROR_DEV_NOT_EXIST
                || err == ERROR_BAD_UNIT
            {
                return Err(AcquisitionError::SourceDisconnected {
                    offset,
                    message: format!("Device disconnected during ReadFile (Win32 code {err})"),
                });
            }
            return Err(AcquisitionError::SourceReadFailed {
                offset,
                len: to_read,
                os_error: Some(err as i32),
                message: format!("ReadFile at offset {offset} failed with Win32 code {err}"),
            });
        }

        Ok(bytes_read as usize)
    }
}
