//! # Progress Reporting and Cooperative Cancellation
//!
//! Provides cooperative cancellation tokens and progress callback traits for
//! long-running evidence reads, region scans, and streaming hash computations (Req 8.5, 8.6, 24.3).
//!
//! Key invariants:
//! - Cancellation returns `ForensicError::Cancelled { bytes_processed }` with searched extent preserved.
//! - Interrupted or cancelled reads return a defined result rather than crashing or panicking (Req 24.3).

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

/// Cooperative cancellation token that can be shared across threads.
#[derive(Debug, Clone, Default)]
pub struct CancellationToken {
    cancelled: Arc<AtomicBool>,
}

impl CancellationToken {
    /// Create a new, uncancelled token.
    pub fn new() -> Self {
        Self {
            cancelled: Arc::new(AtomicBool::new(false)),
        }
    }

    /// Construct a CancellationToken sharing an existing Arc<AtomicBool>.
    pub fn from_arc(cancelled: Arc<AtomicBool>) -> Self {
        Self { cancelled }
    }

    /// Return a clone of the inner Arc<AtomicBool> for inter-crate token sharing.
    pub fn inner_arc(&self) -> Arc<AtomicBool> {
        Arc::clone(&self.cancelled)
    }

    /// Trigger cancellation.
    pub fn cancel(&self) {
        self.cancelled.store(true, Ordering::SeqCst);
    }

    /// Check if cancellation has been requested.
    pub fn is_cancelled(&self) -> bool {
        self.cancelled.load(Ordering::SeqCst)
    }

    /// Check cancellation, returning an error if cancelled.
    pub fn check_cancelled(
        &self,
        context: impl Into<String>,
        bytes_processed: u64,
    ) -> Result<(), forensic_core::ForensicError> {
        if self.is_cancelled() {
            Err(forensic_core::ForensicError::Cancelled {
                context: context.into(),
                bytes_processed,
            })
        } else {
            Ok(())
        }
    }
}

/// Progress notification details passed to callbacks.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ProgressInfo {
    /// Bytes processed so far in the current operation.
    pub bytes_processed: u64,
    /// Total bytes expected to process, if known.
    pub total_bytes: Option<u64>,
    /// Current evidence offset reached.
    pub current_offset: u64,
}

impl ProgressInfo {
    /// Progress fraction between 0.0 and 1.0, if total_bytes is known and non-zero.
    pub fn fraction(&self) -> Option<f64> {
        self.total_bytes.and_then(|total| {
            if total == 0 {
                None
            } else {
                Some((self.bytes_processed as f64 / total as f64).clamp(0.0, 1.0))
            }
        })
    }
}

/// Type alias for progress callback closures.
pub type ProgressCallback<'a> = Box<dyn Fn(ProgressInfo) + Send + Sync + 'a>;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn token_initial_state() {
        let token = CancellationToken::new();
        assert!(!token.is_cancelled());
        assert!(token.check_cancelled("test", 0).is_ok());
    }

    #[test]
    fn token_cancellation_triggers() {
        let token = CancellationToken::new();
        let clone = token.clone();
        clone.cancel();
        assert!(token.is_cancelled());
        let err = token.check_cancelled("scanner", 1024).unwrap_err();
        match err {
            forensic_core::ForensicError::Cancelled {
                context,
                bytes_processed,
            } => {
                assert_eq!(context, "scanner");
                assert_eq!(bytes_processed, 1024);
            }
            other => panic!("expected Cancelled, got {:?}", other),
        }
    }

    #[test]
    fn progress_fraction() {
        let info = ProgressInfo {
            bytes_processed: 50,
            total_bytes: Some(100),
            current_offset: 500,
        };
        assert_eq!(info.fraction(), Some(0.5));
    }
}
