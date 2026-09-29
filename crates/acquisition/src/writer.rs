//! # Forensic Streaming Image Writer
//!
//! Streams output to `<path>.raw.part` in bounded sequential writes.
//! The partial file is ONLY promoted to `<path>.raw` after independent
//! cryptographic verification (Pass-2 hash == Pass-1 hash).

use std::fs::{File, OpenOptions};
use std::io::{BufWriter, Write};
use std::path::{Path, PathBuf};

use crate::error::AcquisitionError;

/// Bounded sequential image writer writing to a `.part` staging file.
pub struct ImageWriter {
    final_path: PathBuf,
    part_path: PathBuf,
    writer: BufWriter<File>,
    bytes_written: u64,
}

impl ImageWriter {
    /// Open a new streaming image writer.
    ///
    /// Fails if the final destination file already exists (preventing accidental overwrite).
    pub fn create(final_path: impl AsRef<Path>) -> Result<Self, AcquisitionError> {
        let final_path = final_path.as_ref().to_path_buf();

        if final_path.exists() {
            return Err(AcquisitionError::DestinationExists {
                path: final_path.display().to_string(),
            });
        }

        // Parent directory must exist
        if let Some(parent) = final_path.parent() {
            if !parent.as_os_str().is_empty() {
                std::fs::create_dir_all(parent)?;
            }
        }

        let mut part_path_str = final_path.to_string_lossy().to_string();
        if !part_path_str.ends_with(".part") {
            part_path_str.push_str(".part");
        }
        let part_path = PathBuf::from(part_path_str);

        // Open staging .part file for writing (create or truncate)
        let file = OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .open(&part_path)
            .map_err(|e| AcquisitionError::DestinationWriteFailed {
                path: part_path.display().to_string(),
                message: format!("Failed to create staging image file: {e}"),
            })?;

        // 1 MiB buffer for buffered sequential writes
        let writer = BufWriter::with_capacity(1024 * 1024, file);

        Ok(Self {
            final_path,
            part_path,
            writer,
            bytes_written: 0,
        })
    }

    /// Write an exact chunk of bytes to the staging file.
    pub fn write_chunk(&mut self, chunk: &[u8]) -> Result<(), AcquisitionError> {
        self.writer
            .write_all(chunk)
            .map_err(|e| AcquisitionError::DestinationWriteFailed {
                path: self.part_path.display().to_string(),
                message: format!("Failed writing chunk ({} bytes): {e}", chunk.len()),
            })?;
        self.bytes_written += chunk.len() as u64;
        Ok(())
    }

    /// Total bytes written so far.
    pub fn bytes_written(&self) -> u64 {
        self.bytes_written
    }

    /// Path to the staging `.part` file.
    pub fn part_path(&self) -> &Path {
        &self.part_path
    }

    /// Path to the target final `.raw` file.
    pub fn final_path(&self) -> &Path {
        &self.final_path
    }

    /// Flush all buffers and sync to disk, returning the closed `.part` file path.
    pub fn finish_staging(mut self) -> Result<PathBuf, AcquisitionError> {
        self.writer
            .flush()
            .map_err(|e| AcquisitionError::DestinationWriteFailed {
                path: self.part_path.display().to_string(),
                message: format!("Failed to flush buffers: {e}"),
            })?;

        let file = self
            .writer
            .into_inner()
            .map_err(|e| AcquisitionError::DestinationWriteFailed {
                path: self.part_path.display().to_string(),
                message: format!("Failed to unwrap buffer: {e}"),
            })?;

        file.sync_all()
            .map_err(|e| AcquisitionError::DestinationWriteFailed {
                path: self.part_path.display().to_string(),
                message: format!("Failed to sync file to disk: {e}"),
            })?;

        Ok(self.part_path)
    }

    /// Atomically rename `.raw.part` to `.raw` ONLY after verification has succeeded.
    pub fn promote_to_final(part_path: &Path, final_path: &Path) -> Result<(), AcquisitionError> {
        std::fs::rename(part_path, final_path).map_err(|e| {
            AcquisitionError::DestinationWriteFailed {
                path: final_path.display().to_string(),
                message: format!(
                    "Failed to promote verified image from '{}' to '{}': {e}",
                    part_path.display(),
                    final_path.display()
                ),
            }
        })?;
        Ok(())
    }
}
