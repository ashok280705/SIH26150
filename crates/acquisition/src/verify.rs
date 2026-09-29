//! # Independent Cryptographic Image Verification (Pass-2)
//!
//! Re-opens the flushed image staging file on disk, reads it sequentially,
//! computes independent MD5 and SHA-256 hashes, and compares against Pass-1.

use std::fs::File;
use std::io::Read;
use std::path::Path;

use chrono::Utc;
use md5::Md5;
use sha2::{Digest, Sha256};

use evidence_reader::CancellationToken;

use crate::error::AcquisitionError;
use crate::types::{VerificationRecord, VerificationStatus};

/// Perform independent Pass-2 verification over the written staging image file.
pub fn verify_image_file(
    image_path: &Path,
    pass1_md5: &str,
    pass1_sha256: &str,
    cancel_token: Option<&CancellationToken>,
    progress_callback: Option<&dyn Fn(u64, u64)>,
) -> Result<VerificationRecord, AcquisitionError> {
    let mut file = File::open(image_path).map_err(|e| AcquisitionError::DestinationWriteFailed {
        path: image_path.display().to_string(),
        message: format!("Failed to open staging image for Pass-2 verification: {e}"),
    })?;

    let file_len = file
        .metadata()
        .map(|m| m.len())
        .unwrap_or(0);

    let mut md5_hasher = Md5::new();
    let mut sha256_hasher = Sha256::new();

    // 1 MiB bounded read buffer
    let mut buffer = vec![0u8; 1024 * 1024];
    let mut bytes_verified = 0u64;

    loop {
        if let Some(token) = cancel_token {
            if token.is_cancelled() {
                return Err(AcquisitionError::Cancelled);
            }
        }

        let n = file.read(&mut buffer).map_err(|e| AcquisitionError::DestinationWriteFailed {
            path: image_path.display().to_string(),
            message: format!("Read error during Pass-2 verification at offset {bytes_verified}: {e}"),
        })?;

        if n == 0 {
            break;
        }

        let chunk = &buffer[..n];
        md5_hasher.update(chunk);
        sha256_hasher.update(chunk);
        bytes_verified += n as u64;

        if let Some(cb) = progress_callback {
            cb(bytes_verified, file_len);
        }
    }

    let pass2_md5 = hex::encode(md5_hasher.finalize());
    let pass2_sha256 = hex::encode(sha256_hasher.finalize());

    let md5_matches = pass1_md5.eq_ignore_ascii_case(&pass2_md5);
    let sha256_matches = pass1_sha256.eq_ignore_ascii_case(&pass2_sha256);

    let verified_at = Some(Utc::now());

    if md5_matches && sha256_matches {
        Ok(VerificationRecord {
            pass1_md5: pass1_md5.to_string(),
            pass1_sha256: pass1_sha256.to_string(),
            pass2_md5: Some(pass2_md5),
            pass2_sha256: Some(pass2_sha256),
            status: VerificationStatus::Verified,
            details: Some(format!(
                "Pass-1 and Pass-2 MD5 and SHA-256 match perfectly ({bytes_verified} bytes verified)"
            )),
            verified_at,
        })
    } else {
        let mut reasons = Vec::new();
        if !md5_matches {
            reasons.push(format!("MD5 mismatch: Pass-1 '{pass1_md5}' vs Pass-2 '{pass2_md5}'"));
        }
        if !sha256_matches {
            reasons.push(format!("SHA-256 mismatch: Pass-1 '{pass1_sha256}' vs Pass-2 '{pass2_sha256}'"));
        }

        let _details = reasons.join("; ");

        // Return error with VerificationRecord details
        Err(AcquisitionError::VerificationFailed {
            algorithm: if !md5_matches && !sha256_matches {
                "MD5 and SHA-256".to_string()
            } else if !md5_matches {
                "MD5".to_string()
            } else {
                "SHA-256".to_string()
            },
            pass1_hash: format!("MD5={pass1_md5}, SHA256={pass1_sha256}"),
            pass2_hash: format!("MD5={pass2_md5}, SHA256={pass2_sha256}"),
        })
    }
}
