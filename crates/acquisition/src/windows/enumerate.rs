//! # Windows Physical Drive Enumeration
//!
//! Enumerates physical disk devices (`\\.\PhysicalDrive0..N`) and retrieves
//! hardware identifiers, capacity, geometry, OS write-protection state, and
//! recognized Windows volume mappings using read-only Win32 IOCTL queries.

#![cfg(windows)]

use std::collections::HashMap;

use windows_sys::Win32::Foundation::{
    CloseHandle, GetLastError, ERROR_ACCESS_DENIED, ERROR_FILE_NOT_FOUND, ERROR_WRITE_PROTECT,
    GENERIC_READ, INVALID_HANDLE_VALUE,
};
use windows_sys::Win32::Storage::FileSystem::{
    CreateFileW, GetDriveTypeW, GetLogicalDriveStringsW, GetVolumeInformationW,
    FILE_ATTRIBUTE_NORMAL, FILE_SHARE_READ, FILE_SHARE_WRITE, OPEN_EXISTING,
};
use windows_sys::Win32::System::Ioctl::IOCTL_DISK_GET_LENGTH_INFO;
use windows_sys::Win32::System::IO::DeviceIoControl;

use crate::types::{BusType, PhysicalSource, VolumeInfo};

const IOCTL_STORAGE_QUERY_PROPERTY: u32 = 0x002D1400;
const IOCTL_DISK_GET_DRIVE_GEOMETRY_EX: u32 = 0x000700A0;
const IOCTL_DISK_IS_WRITABLE: u32 = 0x00070024;
const IOCTL_VOLUME_GET_VOLUME_DISK_EXTENTS: u32 = 0x00560000;

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

#[repr(C)]
struct StoragePropertyQuery {
    property_id: u32, // 0 = StorageDeviceProperty, 7 = StorageAccessAlignmentProperty
    query_type: u32,  // 0 = PropertyStandardQuery
    additional_parameters: [u8; 1],
}

#[repr(C)]
struct StorageAccessAlignmentDescriptor {
    version: u32,
    size: u32,
    bytes_per_cache_line: u32,
    bytes_offset_for_cache_alignment: u32,
    bytes_per_logical_sector: u32,
    bytes_per_physical_sector: u32,
    bytes_offset_for_partition_alignment: u32,
}

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

fn map_bus_type(code: u32) -> BusType {
    match code {
        1 => BusType::Scsi,
        2 => BusType::Atapi,
        3 => BusType::Sata, // ATA
        7 => BusType::Usb,
        8 => BusType::Raid,
        11 => BusType::Sata,
        14 | 15 => BusType::Virtual,
        17 => BusType::Nvme,
        _ => BusType::Unknown,
    }
}

fn extract_ascii_string(buf: &[u8], offset: u32) -> Option<String> {
    if offset == 0 || offset as usize >= buf.len() {
        return None;
    }
    let slice = &buf[offset as usize..];
    let end = slice.iter().position(|&b| b == 0).unwrap_or(slice.len());
    let s = String::from_utf8_lossy(&slice[..end]).trim().to_string();
    if s.is_empty() {
        None
    } else {
        Some(s)
    }
}

/// Enumerate mapped Windows volumes and identify which physical drive each volume belongs to.
fn map_drive_volumes() -> HashMap<u32, Vec<VolumeInfo>> {
    let mut map: HashMap<u32, Vec<VolumeInfo>> = HashMap::new();

    // Query logical drives
    let mut buf = [0u16; 512];
    let len = unsafe { GetLogicalDriveStringsW(buf.len() as u32, buf.as_mut_ptr()) };
    if len == 0 || len >= buf.len() as u32 {
        return map;
    }

    let mut start = 0;
    while start < len as usize {
        let end = buf[start..]
            .iter()
            .position(|&c| c == 0)
            .map(|p| start + p)
            .unwrap_or(len as usize);
        if end == start {
            break;
        }

        let drive_root_wide = &buf[start..=end]; // includes null
        let drive_root = String::from_utf16_lossy(&buf[start..end]);
        start = end + 1;

        // Only inspect fixed or removable drives (DRIVE_REMOVABLE = 2, DRIVE_FIXED = 3)
        let drive_type = unsafe { GetDriveTypeW(drive_root_wide.as_ptr()) };
        if drive_type != 2 && drive_type != 3 {
            continue;
        }

        let letter = drive_root.trim_end_matches('\\').to_string();
        let volume_device_path = format!(r"\\.\{}", letter);
        let wide_volume_path: Vec<u16> = volume_device_path
            .encode_utf16()
            .chain(std::iter::once(0))
            .collect();

        let handle = unsafe {
            CreateFileW(
                wide_volume_path.as_ptr(),
                GENERIC_READ,
                FILE_SHARE_READ | FILE_SHARE_WRITE,
                std::ptr::null(),
                OPEN_EXISTING,
                FILE_ATTRIBUTE_NORMAL,
                std::ptr::null_mut(),
            )
        };

        if handle == INVALID_HANDLE_VALUE {
            continue;
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

        if success != 0 && extents.number_of_disk_extents > 0 {
            // Get filesystem and label
            let mut volume_name = [0u16; 260];
            let mut fs_name = [0u16; 260];
            let info_ok = unsafe {
                GetVolumeInformationW(
                    drive_root_wide.as_ptr(),
                    volume_name.as_mut_ptr(),
                    volume_name.len() as u32,
                    std::ptr::null_mut(),
                    std::ptr::null_mut(),
                    std::ptr::null_mut(),
                    fs_name.as_mut_ptr(),
                    fs_name.len() as u32,
                )
            };

            let label = if info_ok != 0 {
                let name = String::from_utf16_lossy(&volume_name)
                    .trim_matches('\0')
                    .to_string();
                if name.is_empty() {
                    None
                } else {
                    Some(name)
                }
            } else {
                None
            };

            let filesystem = if info_ok != 0 {
                let fs = String::from_utf16_lossy(&fs_name)
                    .trim_matches('\0')
                    .to_string();
                if fs.is_empty() {
                    None
                } else {
                    Some(fs)
                }
            } else {
                None
            };

            for i in 0..extents.number_of_disk_extents.min(8) as usize {
                let disk_num = extents.extents[i].disk_number;
                let vol_info = VolumeInfo {
                    volume_path: drive_root.clone(),
                    drive_letter: Some(letter.clone()),
                    label: label.clone(),
                    filesystem: filesystem.clone(),
                    capacity: extents.extents[i].extent_length as u64,
                };
                map.entry(disk_num).or_default().push(vol_info);
            }
        }
    }

    map
}

/// Enumerate all connected physical disk drives on Windows.
pub fn enumerate_physical_devices() -> Vec<PhysicalSource> {
    let mut devices = Vec::new();
    let volume_map = map_drive_volumes();

    // Query physical drives 0 through 32
    for drive_number in 0..32 {
        let path = format!(r"\\.\PhysicalDrive{}", drive_number);
        let wide_path: Vec<u16> = path.encode_utf16().chain(std::iter::once(0)).collect();

        // Open strictly read-only
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
            // If drive does not exist, continue scanning a few more, then break
            if err == ERROR_FILE_NOT_FOUND {
                if drive_number > 8 {
                    // Reasonable stopping threshold when no drives found after drive 8
                    break;
                }
                continue;
            }
            if err == ERROR_ACCESS_DENIED {
                // Device exists but elevated privileges are missing
                tracing::warn!(
                    "PhysicalDrive{} exists but access was denied (elevation required)",
                    drive_number
                );
            }
            continue;
        }

        // 1. Capacity
        let mut length_info = GetLengthInformation::default();
        let mut bytes_ret = 0u32;
        let success_len = unsafe {
            DeviceIoControl(
                handle,
                IOCTL_DISK_GET_LENGTH_INFO,
                std::ptr::null(),
                0,
                &mut length_info as *mut _ as *mut _,
                std::mem::size_of::<GetLengthInformation>() as u32,
                &mut bytes_ret,
                std::ptr::null_mut(),
            )
        };

        let capacity = if success_len != 0 && length_info.length > 0 {
            length_info.length as u64
        } else {
            0
        };

        // 2. Geometry
        let mut geom_ex = DiskGeometryEx::default();
        let success_geom = unsafe {
            DeviceIoControl(
                handle,
                IOCTL_DISK_GET_DRIVE_GEOMETRY_EX,
                std::ptr::null(),
                0,
                &mut geom_ex as *mut _ as *mut _,
                std::mem::size_of::<DiskGeometryEx>() as u32,
                &mut bytes_ret,
                std::ptr::null_mut(),
            )
        };

        let logical_sector_size = if success_geom != 0 && geom_ex.geometry.bytes_per_sector > 0 {
            geom_ex.geometry.bytes_per_sector
        } else {
            512
        };

        // 3. Storage Device Descriptor (Vendor, Product/Model, Serial, BusType, Removable)
        let mut query = StoragePropertyQuery {
            property_id: 0, // StorageDeviceProperty
            query_type: 0,  // PropertyStandardQuery
            additional_parameters: [0],
        };
        let mut desc_buf = vec![0u8; 1024];
        let success_desc = unsafe {
            DeviceIoControl(
                handle,
                IOCTL_STORAGE_QUERY_PROPERTY,
                &mut query as *mut _ as *mut _,
                std::mem::size_of::<StoragePropertyQuery>() as u32,
                desc_buf.as_mut_ptr() as *mut _,
                desc_buf.len() as u32,
                &mut bytes_ret,
                std::ptr::null_mut(),
            )
        };

        let (vendor, model, serial, bus_type, removable) = if success_desc != 0 && bytes_ret >= 32 {
            let vendor_offset = u32::from_ne_bytes(desc_buf[16..20].try_into().unwrap_or_default());
            let product_offset =
                u32::from_ne_bytes(desc_buf[20..24].try_into().unwrap_or_default());
            let serial_offset =
                u32::from_ne_bytes(desc_buf[28..32].try_into().unwrap_or_default());
            let bus_type_code =
                u32::from_ne_bytes(desc_buf[32..36].try_into().unwrap_or_default());
            let is_removable = desc_buf[8] != 0;

            let v = extract_ascii_string(&desc_buf, vendor_offset);
            let m = extract_ascii_string(&desc_buf, product_offset);
            let s = extract_ascii_string(&desc_buf, serial_offset);
            let b = map_bus_type(bus_type_code);

            (v, m, s, b, is_removable)
        } else {
            (None, None, None, BusType::Unknown, false)
        };

        // 4. Physical sector size via StorageAccessAlignmentProperty
        let mut align_query = StoragePropertyQuery {
            property_id: 7, // StorageAccessAlignmentProperty
            query_type: 0,
            additional_parameters: [0],
        };
        let mut align_desc: StorageAccessAlignmentDescriptor = unsafe { std::mem::zeroed() };
        let success_align = unsafe {
            DeviceIoControl(
                handle,
                IOCTL_STORAGE_QUERY_PROPERTY,
                &mut align_query as *mut _ as *mut _,
                std::mem::size_of::<StoragePropertyQuery>() as u32,
                &mut align_desc as *mut _ as *mut _,
                std::mem::size_of::<StorageAccessAlignmentDescriptor>() as u32,
                &mut bytes_ret,
                std::ptr::null_mut(),
            )
        };

        let physical_sector_size = if success_align != 0 && align_desc.bytes_per_physical_sector > 0
        {
            align_desc.bytes_per_physical_sector
        } else {
            logical_sector_size
        };

        // 5. OS Write-protection status
        let is_writable = unsafe {
            DeviceIoControl(
                handle,
                IOCTL_DISK_IS_WRITABLE,
                std::ptr::null(),
                0,
                std::ptr::null_mut(),
                0,
                &mut bytes_ret,
                std::ptr::null_mut(),
            )
        };
        let os_write_protected = if is_writable == 0 {
            let err = unsafe { GetLastError() };
            err == ERROR_WRITE_PROTECT
        } else {
            false
        };

        unsafe { CloseHandle(handle) };

        let volumes = volume_map.get(&drive_number).cloned().unwrap_or_default();

        devices.push(PhysicalSource {
            drive_number,
            device_path: path,
            vendor,
            model,
            serial,
            bus_type,
            capacity,
            logical_sector_size,
            physical_sector_size,
            removable,
            os_write_protected,
            volumes,
        });
    }

    devices
}
