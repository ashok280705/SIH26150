# VidForge — Windows Forensic Physical-Disk Hardware Test Matrix & Verification Plan

## 1. Overview
This test plan provides validation guidelines and verification procedures for physical acquisition on dedicated Windows test hardware.
**Safety Rule**: Dedicated test media must always be used. Never perform physical testing on active production evidence.

---

## 2. Hardware Test Matrix

| Test ID | Media Type & Interface | Sector Geometry | Volume / Filesystem State | Expected Behavior & Verification Invariants |
| :--- | :--- | :--- | :--- | :--- |
| **HW-01** | Internal SATA HDD (e.g. 500 GB / 1 TB Seagate/WD) | 512-byte Native (512n) | No Windows filesystem (raw/proprietary DVR format such as DHFS4.1) | `VolumeLockState = NOT_APPLICABLE`. No volume lock required. Clean sequential acquisition. Pass-1 == Pass-2. Manifest accurately notes sector size and bus type `SATA`. |
| **HW-02** | External USB 3.0 to SATA Bridge / Enclosure | 512e (512 logical, 4096 physical) | Windows recognized partition (e.g. FAT32/NTFS) | Dismount and volume lock evaluated. If volume locked, lock status recorded. `PhysicalSectorSize = 4096`, `LogicalSectorSize = 512`. Streaming read aligns to logical sectors. |
| **HW-03** | Advanced Format 4Kn Disk (e.g. Enterprise SAS/SATA via adapter) | 4096-byte Native (4Kn) | Proprietary DVR or unpartitioned | Buffer alignment and read operations must strictly align to 4096-byte increments. Windows API reports `BytesPerSector = 4096`. |
| **HW-04** | Hardware Write-Blocked Device (Tableau/CRU/WiebeTech) | 512n or 512e | Any | Examiner records attestation of write-blocker serial/model in UI. Software records `hardware_write_blocker_attestation` in manifest. Software does **not** assert software-verified hardware write blocker. |
| **HW-05** | Write-Protected USB Flash / SD Card (Physical switch or OS read-only) | 512n | FAT32 / exFAT | IOCTL `IOCTL_DISK_IS_WRITABLE` returns read-only error (`ERROR_WRITE_PROTECT`). Acquired cleanly with `is_read_only = true`. |
| **HW-06** | Destination on Same Physical Disk as Source | Any | Partitioned (Source Disk = Dest Disk) | **Hard Safety Anti-Collision**: Engine checks volume disk extents and identifies collision. Safety assessment aborts with `SafetyViolation::DestinationOnSourceDevice`. Acquisition blocked. |
| **HW-07** | Target Drive Low Disk Space | Any | Destination free space < source capacity | Pre-flight safety check aborts with `SafetyViolation::InsufficientFreeSpace`. Acquisition blocked. |
| **HW-08** | Transient / Simulated Read Errors | Dedicated test drive with known bad sectors / simulated LBA drops | Any | Large read fails -> engine adapts to sector-by-sector read -> retries -> recovers salvageable sectors -> unrecoverable sectors are strictly zero-filled -> offsets and ranges logged in `bad_sectors` and `unresolved_ranges` -> source read hash marked incomplete -> image pass-1 hash covers exact written bytes -> Pass-2 verifies exact image. |
| **HW-09** | Abrupt Physical Disconnection | USB Bridge unplugged during acquisition | Any | Windows API returns device disconnection error (`ERROR_DEVICE_NOT_CONNECTED` or `ERROR_FILE_NOT_FOUND`). Engine handles as fatal hardware disconnection error without misclassifying the remainder of the disk as bad sectors. Partial file retained as `.raw.part`, manifest records failed status. |

---

## 3. Pre-Acquisition Safety Checklist
1. Launch VidForge with Windows Administrator elevation.
2. Select target case.
3. Enumerate physical devices; verify target `PhysicalDriveN` matches target disk serial, model, and capacity.
4. If a hardware write blocker is connected, verify write-blocker LED indicators and enter the examiner attestation.
5. Select destination directory on an independent physical storage volume. Verify destination free space exceeds source drive capacity.
6. Verify safety assessment passes green.

---

## 4. Post-Acquisition Verification Protocol
1. Verify Pass-1 image hashes (MD5 and SHA-256) match Pass-2 image verification hashes.
2. Verify image file is finalized from `.raw.part` to `.raw`.
3. Verify `<image>.raw.json` manifest is written and valid JSON.
4. Register image as evidence in VidForge.
5. Launch downstream detection and OEM parser analysis on the registered evidence. Confirm timeline and media recovery complete with identical output compared to direct acquisition.
