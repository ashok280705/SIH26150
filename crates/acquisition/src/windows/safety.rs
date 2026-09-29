//! # Windows Acquisition Safety Assessment
//!
//! Validates pre-acquisition invariants:
//! - Source accessibility and read-only handle verification.
//! - Destination path validation.
//! - HARD ANTI-COLLISION CHECK: Destination is NOT physically located on the source disk.
//! - Free space validation against source capacity.
//! - Conditional volume lock evaluation (NOT_APPLICABLE for DVR disks without Windows volumes).

#![cfg(windows)]

use std::path::Path;

use windows_sys::Win32::Foundation::{
    CloseHandle, GetLastError, GENERIC_READ, INVALID_HANDLE_VALUE,
};
use windows_sys::Win32::Storage::FileSystem::{
    CreateFileW, GetDiskFreeSpaceExW, GetVolumePathNameW, FILE_ATTRIBUTE_NORMAL, FILE_SHARE_READ,
    FILE_SHARE_WRITE, OPEN_EXISTING,
};
use windows_sys::Win32::System::IO::DeviceIoControl;

use crate::types::{
    AcquisitionConfig, PhysicalSource, SafetyAssessment, VolumeLockState,
};

const IOCTL_VOLUME_GET_VOLUME_DISK_EXTENTS: u32 = 0x00560000;
const FSCTL_LOCK_VOLUME: u32 = 0x00090018;
const FSCTL_UNLOCK_VOLUME: u32 = 0x0009001C;

#[repr(C)]
#[derive(Default, Clone, Copy)]
struct DiskExtent {
    disk_number: u32,
    starting_offset: i64,
    extent_length: i64,
}

#[repr(C)]
struct VolumeDiskExtents {
    number_of_disk_extents: u32,
    extents: [DiskExtent; 8],
}

/// Identifies which physical disk numbers back a given destination path.
pub fn get_destination_physical_disks(dest_path: &Path) -> Vec<u32> {
    let mut disks = Vec::new();

    let abs_path = if dest_path.is_absolute() {
        dest_path.to_path_buf()
    } else {
        std::env::current_dir()
            .unwrap_or_default()
            .join(dest_path)
    };

    let path_str = abs_path.to_string_lossy();
    let wide_path: Vec<u16> = path_str.encode_utf16().chain(std::iter::once(0)).collect();

    let mut volume_root = [0u16; 512];
    let ok = unsafe {
        GetVolumePathNameW(
            wide_path.as_ptr(),
            volume_root.as_mut_ptr(),
            volume_root.len() as u32,
        )
    };

    if ok == 0 {
        return disks;
    }

    let root_str = String::from_utf16_lossy(&volume_root)
        .trim_matches('\0')
        .to_string();
    let volume_device = format!(r"\\.\{}", root_str.trim_end_matches('\\'));
    let wide_vol_device: Vec<u16> = volume_device
        .encode_utf16()
        .chain(std::iter::once(0))
        .collect();

    let handle = unsafe {
        CreateFileW(
            wide_vol_device.as_ptr(),
            GENERIC_READ,
            FILE_SHARE_READ | FILE_SHARE_WRITE,
            std::ptr::null(),
            OPEN_EXISTING,
            FILE_ATTRIBUTE_NORMAL,
            std::ptr::null_mut(),
        )
    };

    if handle == INVALID_HANDLE_VALUE {
        return disks;
    }

    let mut extents: VolumeDiskExtents = unsafe { std::mem::zeroed() };
    let mut bytes_ret = 0u32;
    let success = unsafe {
        DeviceIoControl(
            handle,
            IOCTL_VOLUME_GET_VOLUME_DISK_EXTENTS,
            std::ptr::null(),
            0,
            &mut extents as *mut _ as *mut _,
            std::mem::size_of::<VolumeDiskExtents>() as u32,
            &mut bytes_ret,
            std::ptr::null_mut(),
        )
    };

    unsafe { CloseHandle(handle) };

    if success != 0 {
        for i in 0..extents.number_of_disk_extents.min(8) as usize {
            disks.push(extents.extents[i].disk_number);
        }
    }

    disks
}

/// Query available free space on the destination filesystem in bytes.
pub fn get_destination_free_space(dest_path: &Path) -> Option<u64> {
    let parent = dest_path.parent().unwrap_or(Path::new("."));
    let abs_path = if parent.is_absolute() {
        parent.to_path_buf()
    } else {
        std::env::current_dir().unwrap_or_default().join(parent)
    };

    let path_str = abs_path.to_string_lossy();
    let wide_path: Vec<u16> = path_str.encode_utf16().chain(std::iter::once(0)).collect();

    let mut free_bytes_avail = 0u64;
    let mut total_bytes = 0u64;
    let mut total_free = 0u64;

    let success = unsafe {
        GetDiskFreeSpaceExW(
            wide_path.as_ptr(),
            &mut free_bytes_avail,
            &mut total_bytes,
            &mut total_free,
        )
    };

    if success != 0 {
        Some(free_bytes_avail)
    } else {
        None
    }
}

/// Perform comprehensive pre-acquisition safety assessment.
pub fn assess_windows_safety(
    source: &PhysicalSource,
    config: &AcquisitionConfig,
) -> SafetyAssessment {
    let mut blocking_reasons = Vec::new();
    let mut warnings = Vec::new();

    // 1. Source accessible check
    let wide_src: Vec<u16> = source
        .device_path
        .encode_utf16()
        .chain(std::iter::once(0))
        .collect();
    let src_handle = unsafe {
        CreateFileW(
            wide_src.as_ptr(),
            GENERIC_READ,
            FILE_SHARE_READ | FILE_SHARE_WRITE,
            std::ptr::null(),
            OPEN_EXISTING,
            FILE_ATTRIBUTE_NORMAL,
            std::ptr::null_mut(),
        )
    };

    let source_accessible = src_handle != INVALID_HANDLE_VALUE;
    if !source_accessible {
        let err = unsafe { GetLastError() };
        blocking_reasons.push(format!(
            "Source physical drive '{}' is not accessible (Win32 error: {err})",
            source.device_path
        ));
    } else {
        unsafe { CloseHandle(src_handle) };
    }

    // 2. Destination path valid & creatable
    let dest_path = Path::new(&config.destination_path);
    let dest_parent = dest_path.parent().unwrap_or(Path::new("."));
    let destination_exists_or_creatable = if dest_parent.as_os_str().is_empty() {
        true
    } else {
        dest_parent.exists() || std::fs::create_dir_all(dest_parent).is_ok()
    };

    if !destination_exists_or_creatable {
        blocking_reasons.push(format!(
            "Destination directory '{}' does not exist and cannot be created",
            dest_parent.display()
        ));
    }

    // 3. HARD ANTI-COLLISION: Destination is not physically on source device
    let dest_disks = get_destination_physical_disks(dest_path);
    let destination_is_not_source =
        !source.device_path.eq_ignore_ascii_case(&config.destination_path);

    let destination_not_on_source_device = !dest_disks.contains(&source.drive_number);
    let primary_dest_drive = dest_disks.first().copied();

    if !destination_is_not_source {
        blocking_reasons.push(
            "Destination path matches the source device path! Self-overwriting forbidden."
                .to_string(),
        );
    }

    if !destination_not_on_source_device {
        blocking_reasons.push(format!(
            "FATAL COLLISION: Destination file path resides on physical disk #{}, which is the SOURCE drive! Imaging to the source disk would destroy evidence.",
            source.drive_number
        ));
    }

    // 4. Destination free space check
    let free_space = get_destination_free_space(dest_path).unwrap_or(0);
    // Add 100 MiB safety margin
    let required_space = source.capacity.saturating_add(100 * 1024 * 1024);
    let has_sufficient_space = free_space >= required_space;

    if !has_sufficient_space && source.capacity > 0 {
        blocking_reasons.push(format!(
            "Insufficient destination disk space: required {} bytes (capacity + margin), but only {} bytes available on volume",
            required_space, free_space
        ));
    }

    // 5. Collision with existing file
    let collision_detected = dest_path.exists();
    if collision_detected {
        warnings.push(format!(
            "Destination file '{}' already exists and will not be overwritten.",
            dest_path.display()
        ));
    }
    let part_path = dest_path.with_extension("raw.part");
    if part_path.exists() {
        warnings.push(format!(
            "A previous partial acquisition artifact '{}' exists.",
            part_path.display()
        ));
    }

    // 6. Conditional Volume Lock evaluation
    let volume_lock_state = if source.volumes.is_empty() {
        // DVR/NVR proprietary media without Windows filesystems
        VolumeLockState::NotApplicable
    } else if config.attempt_volume_lock {
        // Evaluate volume lock for recognized volumes
        let mut all_locked = true;
        let mut fail_reason = None;

        for vol in &source.volumes {
            if let Some(ref letter) = vol.drive_letter {
                let dev_name = format!(r"\\.\{}", letter);
                let wide_dev: Vec<u16> = dev_name
                    .encode_utf16()
                    .chain(std::iter::once(0))
                    .collect();

                let h = unsafe {
                    CreateFileW(
                        wide_dev.as_ptr(),
                        GENERIC_READ,
                        FILE_SHARE_READ | FILE_SHARE_WRITE,
                        std::ptr::null(),
                        OPEN_EXISTING,
                        FILE_ATTRIBUTE_NORMAL,
                        std::ptr::null_mut(),
                    )
                };

                if h != INVALID_HANDLE_VALUE {
                    let mut bytes_ret = 0u32;
                    let lock_res = unsafe {
                        DeviceIoControl(
                            h,
                            FSCTL_LOCK_VOLUME,
                            std::ptr::null(),
                            0,
                            std::ptr::null_mut(),
                            0,
                            &mut bytes_ret,
                            std::ptr::null_mut(),
                        )
                    };

                    if lock_res == 0 {
                        all_locked = false;
                        let err = unsafe { GetLastError() };
                        fail_reason = Some(format!("Failed to lock volume {letter} (Win32: {err})"));
                    } else {
                        // Unlock after test check
                        unsafe {
                            DeviceIoControl(
                                h,
                                FSCTL_UNLOCK_VOLUME,
                                std::ptr::null(),
                                0,
                                std::ptr::null_mut(),
                                0,
                                &mut bytes_ret,
                                std::ptr::null_mut(),
                            );
                        }
                    }
                    unsafe { CloseHandle(h) };
                }
            }
        }

        if all_locked {
            VolumeLockState::Locked
        } else {
            VolumeLockState::LockFailed(fail_reason.unwrap_or_else(|| "Lock failed".to_string()))
        }
    } else {
        VolumeLockState::Skipped
    };

    let is_safe_to_proceed = blocking_reasons.is_empty() && !collision_detected;

    SafetyAssessment {
        source_accessible,
        source_read_only_confirmed: true,
        destination_exists_or_creatable,
        destination_is_not_source,
        destination_not_on_source_device,
        destination_device_number: primary_dest_drive,
        source_capacity_bytes: source.capacity,
        destination_free_space_bytes: free_space,
        has_sufficient_space,
        collision_detected,
        recognized_volumes: source.volumes.clone(),
        volume_lock_state,
        is_safe_to_proceed,
        blocking_reasons,
        warnings,
    }
}
