//! # Windows Physical Drive Acquisition Implementation
//!
//! Exclusively uses read-only Win32 API handles (`GENERIC_READ`).
//! Provides physical device enumeration, sector geometry query, safety checks,
//! volume collision checks, and WindowsSourceDevice implementation.

pub mod device;
pub mod enumerate;
pub mod safety;

pub use device::WindowsSourceDevice;
pub use enumerate::enumerate_physical_devices;
pub use safety::assess_windows_safety;
