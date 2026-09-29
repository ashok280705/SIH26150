//! # Forensic Acquisition Engine
//!
//! Executes deterministic, sequential physical acquisition with adaptive read recovery,
//! sector-level isolation, zero-fill accounting, and strictly write-verified Pass-1 hashing.

use std::path::PathBuf;
use std::time::Instant;

use chrono::Utc;
use md5::Md5;
use sha2::{Digest, Sha256};
use uuid::Uuid;

use evidence_reader::CancellationToken;

use crate::error::AcquisitionError;
use crate::manifest::AcquisitionManifest;
use crate::source::SourceDevice;
use crate::types::{
    AcquisitionConfig, AcquisitionProgress, AcquisitionResult, AcquisitionStatus,
    BadSectorRange, BadSectorStatus, PhysicalSource, SafetyAssessment,
};
use crate::verify::verify_image_file;
use crate::writer::ImageWriter;

pub type ProgressCallback = Box<dyn Fn(AcquisitionProgress) + Send + Sync>;

/// Runs the complete forensic acquisition workflow.
pub fn run_acquisition(
    source: &dyn SourceDevice,
    metadata: Option<&PhysicalSource>,
    config: &AcquisitionConfig,
    safety: &SafetyAssessment,
    cancel_token: Option<&CancellationToken>,
    progress_callback: Option<ProgressCallback>,
) -> Result<AcquisitionResult, AcquisitionError> {
    let acquisition_id = Uuid::new_v4();
    let start_time = Utc::now();
    let timer_start = Instant::now();

    // Destination target path
    let final_raw_path = PathBuf::from(&config.destination_path);

    // 1. Initialize image writer (staging to .raw.part)
    let mut writer = ImageWriter::create(&final_raw_path)?;
    let _part_path = writer.part_path().to_path_buf();

    let total_bytes = source.capacity();
    let logical_sector = source.logical_sector_size() as usize;
    let chunk_size = (config.chunk_size / logical_sector).max(1) * logical_sector;

    let mut pass1_md5 = Md5::new();
    let mut pass1_sha256 = Sha256::new();

    let mut offset = 0u64;
    let mut bytes_written = 0u64;
    let mut bad_sectors: Vec<BadSectorRange> = Vec::new();
    let mut unreadable_bytes = 0u64;

    let mut last_progress_report = Instant::now();

    // 2. Acquisition sequential read loop
    while offset < total_bytes {
        // Check cancellation
        if let Some(token) = cancel_token {
            if token.is_cancelled() {
                let _ = writer.finish_staging();
                return Err(AcquisitionError::Cancelled);
            }
        }

        let to_read = chunk_size.min((total_bytes - offset) as usize);
        let mut buffer = vec![0u8; to_read];

        match source.read_exact_at(offset, &mut buffer) {
            Ok(n) if n > 0 => {
                let valid_chunk = &buffer[..n];

                // Write output
                writer.write_chunk(valid_chunk)?;

                // INVARIANT: Pass-1 hash is updated strictly AFTER successful output write
                pass1_md5.update(valid_chunk);
                pass1_sha256.update(valid_chunk);

                bytes_written += n as u64;
                offset += n as u64;
            }
            Ok(_) => {
                // Unexpected 0-byte read before reaching declared capacity
                break;
            }
            Err(AcquisitionError::SourceDisconnected { message, .. }) => {
                // Device disappeared! Stop immediately; do NOT treat entire disk as bad sectors.
                let _ = writer.finish_staging();
                return Err(AcquisitionError::SourceDisconnected {
                    offset,
                    message,
                });
            }
            Err(_e) => {
                // Read failed on this chunk -> Adaptive read recovery down to logical sector boundary
                let num_sectors = (to_read + logical_sector - 1) / logical_sector;

                for sec_idx in 0..num_sectors {
                    let sec_offset = offset + (sec_idx * logical_sector) as u64;
                    if sec_offset >= total_bytes {
                        break;
                    }
                    let sec_to_read = logical_sector.min((total_bytes - sec_offset) as usize);
                    let mut sec_buf = vec![0u8; sec_to_read];

                    let mut sector_success = false;
                    let mut retries_used = 0u32;
                    let mut last_os_error = None;

                    // Retry sector read
                    for retry in 0..=config.max_retries {
                        if let Some(token) = cancel_token {
                            if token.is_cancelled() {
                                let _ = writer.finish_staging();
                                return Err(AcquisitionError::Cancelled);
                            }
                        }

                        match source.read_exact_at(sec_offset, &mut sec_buf) {
                            Ok(sn) if sn > 0 => {
                                sector_success = true;
                                retries_used = retry;

                                writer.write_chunk(&sec_buf[..sn])?;
                                pass1_md5.update(&sec_buf[..sn]);
                                pass1_sha256.update(&sec_buf[..sn]);
                                bytes_written += sn as u64;
                                break;
                            }
                            Err(AcquisitionError::SourceDisconnected { message, .. }) => {
                                let _ = writer.finish_staging();
                                return Err(AcquisitionError::SourceDisconnected {
                                    offset: sec_offset,
                                    message,
                                });
                            }
                            Err(AcquisitionError::SourceReadFailed { os_error, .. }) => {
                                last_os_error = os_error;
                                retries_used = retry + 1;
                            }
                            Err(_) => {
                                retries_used = retry + 1;
                            }
                            Ok(_) => {
                                retries_used = retry + 1;
                            }
                        }
                    }

                    if !sector_success {
                        // Sector unrecoverable -> deterministic zero-fill
                        let zero_sector = vec![0u8; sec_to_read];

                        // Write deterministic zero bytes
                        writer.write_chunk(&zero_sector)?;

                        // Pass-1 hash includes the zero-filled sector that was successfully written
                        pass1_md5.update(&zero_sector);
                        pass1_sha256.update(&zero_sector);
                        bytes_written += sec_to_read as u64;
                        unreadable_bytes += sec_to_read as u64;

                        let start_lba = sec_offset / (logical_sector as u64);
                        bad_sectors.push(BadSectorRange {
                            offset: sec_offset,
                            length: sec_to_read as u64,
                            start_lba,
                            sector_count: 1,
                            status: BadSectorStatus::ZeroFilled,
                            win32_error: last_os_error.map(|e| e as u32),
                            retry_count: retries_used,
                        });
                    }
                }

                offset += to_read as u64;
            }
        }

        // Throttle progress updates to ~100ms
        if last_progress_report.elapsed().as_millis() >= 100 {
            last_progress_report = Instant::now();
            let elapsed = timer_start.elapsed().as_secs_f64();
            let throughput = if elapsed > 0.0 {
                (bytes_written as f64 / elapsed) as u64
            } else {
                0
            };
            let percentage = if total_bytes > 0 {
                (bytes_written as f64 / total_bytes as f64) * 100.0
            } else {
                0.0
            };
            let remaining_bytes = total_bytes.saturating_sub(bytes_written);
            let eta_seconds = if throughput > 0 {
                Some(remaining_bytes / throughput)
            } else {
                None
            };

            if let Some(ref cb) = progress_callback {
                cb(AcquisitionProgress {
                    bytes_processed: bytes_written,
                    total_bytes,
                    percentage,
                    throughput_bytes_per_sec: throughput,
                    elapsed_seconds: elapsed,
                    eta_seconds,
                    bad_sector_count: bad_sectors.len() as u64,
                    unreadable_bytes,
                    current_phase: "acquiring".to_string(),
                });
            }
        }
    }

    // 3. Flush staging image file to disk
    let closed_part_path = writer.finish_staging()?;

    let pass1_md5_hex = hex::encode(pass1_md5.finalize());
    let pass1_sha256_hex = hex::encode(pass1_sha256.finalize());

    // Report entering verification phase
    if let Some(ref cb) = progress_callback {
        cb(AcquisitionProgress {
            bytes_processed: bytes_written,
            total_bytes,
            percentage: 100.0,
            throughput_bytes_per_sec: 0,
            elapsed_seconds: timer_start.elapsed().as_secs_f64(),
            eta_seconds: None,
            bad_sector_count: bad_sectors.len() as u64,
            unreadable_bytes,
            current_phase: "verifying".to_string(),
        });
    }

    // 4. PASS-2: Independent Verification Pass
    let verification = match verify_image_file(
        &closed_part_path,
        &pass1_md5_hex,
        &pass1_sha256_hex,
        cancel_token,
        None,
    ) {
        Ok(rec) => rec,
        Err(e) => {
            // VERIFICATION FAILED: DO NOT finalize/promote image!
            return Err(e);
        }
    };

    // 5. Finalization: Promote .raw.part -> .raw
    ImageWriter::promote_to_final(&closed_part_path, &final_raw_path)?;

    let end_time = Utc::now();
    let status = if bad_sectors.is_empty() {
        AcquisitionStatus::Complete
    } else {
        AcquisitionStatus::Partial
    };

    // Default metadata if not supplied
    let default_meta = PhysicalSource {
        drive_number: 0,
        device_path: source.path().to_string(),
        vendor: None,
        model: None,
        serial: None,
        bus_type: crate::types::BusType::Unknown,
        capacity: total_bytes,
        logical_sector_size: source.logical_sector_size(),
        physical_sector_size: source.physical_sector_size(),
        removable: false,
        os_write_protected: false,
        volumes: vec![],
    };
    let meta_ref = metadata.unwrap_or(&default_meta);

    // 6. Generate and save Acquisition Manifest (<image_path>.raw.json)
    let manifest = AcquisitionManifest::build(
        acquisition_id,
        config,
        meta_ref,
        safety,
        verification.clone(),
        status,
        start_time,
        end_time,
        &final_raw_path,
        bytes_written,
        bad_sectors.clone(),
    );
    let manifest_path = manifest.write_to_file(&final_raw_path)?;

    // Report completed
    if let Some(ref cb) = progress_callback {
        cb(AcquisitionProgress {
            bytes_processed: bytes_written,
            total_bytes,
            percentage: 100.0,
            throughput_bytes_per_sec: 0,
            elapsed_seconds: timer_start.elapsed().as_secs_f64(),
            eta_seconds: Some(0),
            bad_sector_count: bad_sectors.len() as u64,
            unreadable_bytes,
            current_phase: "completed".to_string(),
        });
    }

    Ok(AcquisitionResult {
        acquisition_id,
        case_id: config.case_id,
        status,
        image_path: final_raw_path,
        manifest_path,
        bytes_written,
        bad_sectors,
        verification,
        elapsed_seconds: timer_start.elapsed().as_secs_f64(),
    })
}
