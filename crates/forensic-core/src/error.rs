//! # Forensic Error Types
//!
//! The canonical error enum for all forensic operations. Every fallible function in the
//! forensic core crates returns `Result<T, ForensicError>` — malformed evidence is data,
//! not a crash (Req 24.1).
//!
//! No `unwrap`/`expect` is permitted on evidence-derived values.

/// The canonical error type for all forensic operations.
///
/// Each variant represents a category of failure that the platform can encounter when
/// processing evidence. Malformed evidence produces an error value, never a panic.
#[derive(Debug, thiserror::Error)]
pub enum ForensicError {
    /// An I/O error occurred while reading evidence or writing an artifact.
    #[error("I/O error: {context} — {source}")]
    Io {
        context: String,
        source: std::io::Error,
    },

    /// A read or computation references a byte range outside the evidence source bounds.
    #[error(
        "out of bounds: {context} (offset={offset}, length={length}, source_len={source_len})"
    )]
    OutOfBounds {
        context: String,
        offset: u64,
        length: u64,
        source_len: u64,
    },

    /// The evidence format is not supported (e.g. E01 before OPEN-1 is resolved).
    #[error("unsupported format: {format} — {reason}")]
    UnsupportedFormat { format: String, reason: String },

    /// An OEM profile failed schema validation or contains invalid data.
    #[error("profile invalid: {profile_id} — {reason}")]
    ProfileInvalid { profile_id: String, reason: String },

    /// The evidence structure is corrupt, truncated, or internally inconsistent.
    #[error("corrupt structure: {context} — {reason}")]
    CorruptStructure { context: String, reason: String },

    /// A write was attempted against evidence or the evidence directory.
    #[error("write denied: {path} — {reason}")]
    WriteDenied { path: String, reason: String },

    /// A codec/decode operation failed (video, compression, etc.).
    #[error("decode failed: {context} — {reason}")]
    DecodeFailed { context: String, reason: String },

    /// The operation was cancelled by the user or a timeout.
    #[error("cancelled: {context} (bytes_processed={bytes_processed})")]
    Cancelled {
        context: String,
        bytes_processed: u64,
    },

    /// An integer overflow or impossible value was detected in evidence-derived arithmetic.
    #[error("arithmetic overflow: {context}")]
    ArithmeticOverflow { context: String },
}

impl ForensicError {
    /// Convenience: wrap a `std::io::Error` with context.
    pub fn io(context: impl Into<String>, source: std::io::Error) -> Self {
        Self::Io {
            context: context.into(),
            source,
        }
    }

    /// Convenience: out-of-bounds with full diagnostic context.
    pub fn out_of_bounds(
        context: impl Into<String>,
        offset: u64,
        length: u64,
        source_len: u64,
    ) -> Self {
        Self::OutOfBounds {
            context: context.into(),
            offset,
            length,
            source_len,
        }
    }

    /// Convenience: corrupt structure.
    pub fn corrupt(context: impl Into<String>, reason: impl Into<String>) -> Self {
        Self::CorruptStructure {
            context: context.into(),
            reason: reason.into(),
        }
    }

    /// Convenience: arithmetic overflow.
    pub fn overflow(context: impl Into<String>) -> Self {
        Self::ArithmeticOverflow {
            context: context.into(),
        }
    }
}

// ForensicError is not Clone because std::io::Error is not Clone. This is intentional:
// errors are consumed, not copied.

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn io_error_displays_context() {
        let err = ForensicError::io(
            "reading sector 42",
            std::io::Error::new(std::io::ErrorKind::UnexpectedEof, "truncated"),
        );
        let msg = format!("{err}");
        assert!(msg.contains("reading sector 42"), "got: {msg}");
        assert!(msg.contains("truncated"), "got: {msg}");
    }

    #[test]
    fn out_of_bounds_displays_offsets() {
        let err = ForensicError::out_of_bounds("header read", 1000, 512, 800);
        let msg = format!("{err}");
        assert!(msg.contains("1000"), "got: {msg}");
        assert!(msg.contains("512"), "got: {msg}");
        assert!(msg.contains("800"), "got: {msg}");
    }

    #[test]
    fn overflow_displays_context() {
        let err = ForensicError::overflow("sector_size * start_sector");
        let msg = format!("{err}");
        assert!(msg.contains("sector_size * start_sector"), "got: {msg}");
    }

    #[test]
    fn all_variants_are_error() {
        // Ensure every variant implements std::error::Error (compile-time via thiserror,
        // but exercised here as a smoke test).
        let errors: Vec<Box<dyn std::error::Error>> = vec![
            Box::new(ForensicError::io("test", std::io::Error::other("x"))),
            Box::new(ForensicError::out_of_bounds("test", 0, 0, 0)),
            Box::new(ForensicError::UnsupportedFormat {
                format: "E01".into(),
                reason: "gated by OPEN-1".into(),
            }),
            Box::new(ForensicError::ProfileInvalid {
                profile_id: "dahua-v1".into(),
                reason: "missing evidence_status".into(),
            }),
            Box::new(ForensicError::corrupt("header", "bad magic")),
            Box::new(ForensicError::WriteDenied {
                path: "/evidence/disk.raw".into(),
                reason: "evidence is read-only".into(),
            }),
            Box::new(ForensicError::DecodeFailed {
                context: "h264 frame".into(),
                reason: "truncated NAL".into(),
            }),
            Box::new(ForensicError::Cancelled {
                context: "hash scan".into(),
                bytes_processed: 1024,
            }),
            Box::new(ForensicError::overflow("test")),
        ];
        for e in &errors {
            // Just verify Display doesn't panic
            let _ = format!("{e}");
        }
        assert_eq!(errors.len(), 9, "should cover all variants");
    }
}
