//! # RecordingReader — a test-only instrumented `EvidenceReader`
//!
//! `RecordingReader` is **test infrastructure only**. It implements the read-only
//! [`EvidenceReader`] trait over an in-memory buffer and records every call so tests can
//! assert exactly which byte ranges were touched, in what order, and with what result.
//!
//! It supports deterministic fault injection keyed by **call index** (the Nth
//! `read_at`) or by **offset**:
//!
//! * hard failures (simulating a bad sector / backend I/O error), and
//! * short reads (the backend returns fewer bytes than requested for a valid region).
//!
//! This lets tests exercise partial reads, failure propagation, "no unexpected reads",
//! and the strictness of [`EvidenceReader::read_exact_at`] (a short read must NOT become
//! a successful `Ok(buffer)`), and provides the deterministic-sequence primitive a future
//! retry-policy test would build on. **No retry behavior is implemented here.**
//!
//! Production reader behavior is not modified in any way by this type.

use std::sync::Mutex;

use evidence_reader::{EvidenceReader, SourceKind};
use forensic_core::{ForensicError, RangeSet, Region};

/// The outcome recorded for a single `read_at` call.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ReadCallResult {
    /// The call returned `Ok(bytes_read)`.
    Ok(usize),
    /// The call returned an error, captured as its context string.
    Err(String),
}

/// A single recorded `read_at` invocation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReadCall {
    /// The absolute offset requested.
    pub offset: u64,
    /// The number of bytes requested (the length of the caller's buffer).
    pub requested_len: usize,
    /// What the call returned.
    pub result: ReadCallResult,
}

/// Which condition triggers an injected fault.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Trigger {
    /// The Nth (0-based) `read_at` call.
    Call(usize),
    /// Any `read_at` whose start offset equals this value.
    Offset(u64),
}

/// A test-only instrumented, deterministic [`EvidenceReader`].
pub struct RecordingReader {
    data: Vec<u8>,
    source_path: String,
    fail_rules: Vec<(Trigger, String)>,
    short_rules: Vec<(Trigger, usize)>,
    calls: Mutex<Vec<ReadCall>>,
}

impl RecordingReader {
    /// Create a reader backed by explicit bytes.
    pub fn new(data: Vec<u8>) -> Self {
        Self {
            data,
            source_path: "recording://test".to_string(),
            fail_rules: Vec::new(),
            short_rules: Vec::new(),
            calls: Mutex::new(Vec::new()),
        }
    }

    /// Create a reader of `len` bytes filled with a deterministic pattern (`i % 256`).
    pub fn with_pattern(len: usize) -> Self {
        let data = (0..len).map(|i| (i % 256) as u8).collect();
        Self::new(data)
    }

    /// Inject a hard failure on the Nth (0-based) `read_at` call.
    #[must_use]
    pub fn fail_at_call(mut self, call_index: usize, context: impl Into<String>) -> Self {
        self.fail_rules
            .push((Trigger::Call(call_index), context.into()));
        self
    }

    /// Inject a hard failure whenever a `read_at` starts at `offset`.
    #[must_use]
    pub fn fail_at_offset(mut self, offset: u64, context: impl Into<String>) -> Self {
        self.fail_rules
            .push((Trigger::Offset(offset), context.into()));
        self
    }

    /// Cap the bytes returned by the Nth (0-based) `read_at` call to `max_bytes`,
    /// simulating a short read on an otherwise valid region.
    #[must_use]
    pub fn short_read_at_call(mut self, call_index: usize, max_bytes: usize) -> Self {
        self.short_rules
            .push((Trigger::Call(call_index), max_bytes));
        self
    }

    /// Cap the bytes returned for any `read_at` starting at `offset` to `max_bytes`.
    #[must_use]
    pub fn short_read_at_offset(mut self, offset: u64, max_bytes: usize) -> Self {
        self.short_rules.push((Trigger::Offset(offset), max_bytes));
        self
    }

    /// A snapshot of every recorded call, in invocation order.
    pub fn calls(&self) -> Vec<ReadCall> {
        self.calls.lock().expect("recording mutex poisoned").clone()
    }

    /// The number of `read_at` calls recorded so far.
    pub fn call_count(&self) -> usize {
        self.calls.lock().expect("recording mutex poisoned").len()
    }

    /// The total number of bytes successfully returned across all recorded calls.
    pub fn total_bytes_read(&self) -> usize {
        self.calls
            .lock()
            .expect("recording mutex poisoned")
            .iter()
            .map(|c| match c.result {
                ReadCallResult::Ok(n) => n,
                ReadCallResult::Err(_) => 0,
            })
            .sum()
    }

    /// The canonical union of every requested `[offset, offset + requested_len)` range.
    ///
    /// Useful for asserting that reads stayed within an expected window (e.g. that a
    /// bounded operation never touched bytes outside the region it was given).
    pub fn requested_range_set(&self) -> RangeSet {
        let mut set = RangeSet::new();
        for c in self.calls().iter() {
            if let Ok(region) = Region::new(c.offset, c.requested_len as u64) {
                // add() only fails on overflow, which a valid region cannot exhibit.
                let _ = set.add(region);
            }
        }
        set
    }

    fn record(&self, offset: u64, requested_len: usize, result: ReadCallResult) {
        self.calls
            .lock()
            .expect("recording mutex poisoned")
            .push(ReadCall {
                offset,
                requested_len,
                result,
            });
    }

    fn injected_failure(&self, call_index: usize, offset: u64) -> Option<String> {
        self.fail_rules.iter().find_map(|(trigger, ctx)| {
            let matches = match trigger {
                Trigger::Call(i) => *i == call_index,
                Trigger::Offset(o) => *o == offset,
            };
            matches.then(|| ctx.clone())
        })
    }

    fn short_read_cap(&self, call_index: usize, offset: u64) -> Option<usize> {
        self.short_rules
            .iter()
            .filter_map(|(trigger, max_bytes)| {
                let matches = match trigger {
                    Trigger::Call(i) => *i == call_index,
                    Trigger::Offset(o) => *o == offset,
                };
                matches.then_some(*max_bytes)
            })
            .min()
    }
}

impl EvidenceReader for RecordingReader {
    fn len(&self) -> u64 {
        self.data.len() as u64
    }

    fn read_at(&self, offset: u64, buf: &mut [u8]) -> Result<usize, ForensicError> {
        // 0-based index of this call. The reader is intended for single-threaded test use,
        // so reading the count here and recording at the end yields a stable index.
        let call_index = self.call_count();
        let requested_len = buf.len();

        // Out-of-range request: offset beyond the source. This mirrors the OutOfBounds
        // semantics of the real readers and is distinct from a short read.
        if offset >= self.len() {
            let err = ForensicError::out_of_bounds(
                "RecordingReader read past end",
                offset,
                requested_len as u64,
                self.len(),
            );
            self.record(
                offset,
                requested_len,
                ReadCallResult::Err("out_of_bounds".to_string()),
            );
            return Err(err);
        }

        // Injected hard failure (by call index or offset).
        if let Some(ctx) = self.injected_failure(call_index, offset) {
            self.record(offset, requested_len, ReadCallResult::Err(ctx.clone()));
            return Err(ForensicError::io(
                ctx,
                std::io::Error::other("injected read failure"),
            ));
        }

        let available = (self.len() - offset) as usize;
        let mut to_read = requested_len.min(available);
        if let Some(cap) = self.short_read_cap(call_index, offset) {
            to_read = to_read.min(cap);
        }

        let start = offset as usize;
        buf[..to_read].copy_from_slice(&self.data[start..start + to_read]);
        self.record(offset, requested_len, ReadCallResult::Ok(to_read));
        Ok(to_read)
    }

    fn source_kind(&self) -> SourceKind {
        SourceKind::Raw
    }

    fn source_path(&self) -> &str {
        &self.source_path
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn expected_read_returns_correct_bytes_and_is_recorded() {
        let reader = RecordingReader::with_pattern(256);
        let mut buf = [0u8; 4];
        let n = reader.read_at(10, &mut buf).unwrap();
        assert_eq!(n, 4);
        assert_eq!(buf, [10, 11, 12, 13]);

        let calls = reader.calls();
        assert_eq!(calls.len(), 1);
        assert_eq!(calls[0].offset, 10);
        assert_eq!(calls[0].requested_len, 4);
        assert_eq!(calls[0].result, ReadCallResult::Ok(4));
    }

    #[test]
    fn no_unexpected_reads_are_made() {
        let reader = RecordingReader::with_pattern(4096);
        let bounded = evidence_reader::BoundedReader::new(&reader, 100, 50).unwrap();
        let _ = bounded.read_exact_at(0, 10).unwrap();

        // Every access must have landed inside [100, 150) on the parent.
        let accessed = reader.requested_range_set();
        let window = Region::new(100, 50).unwrap();
        assert!(
            accessed.iter().all(|r| window.contains(r.offset)),
            "reads escaped the bounded window: {:?}",
            reader.calls()
        );
        // Nothing at offset 0 (the start of the parent) was ever touched.
        assert!(!reader.requested_range_set().contains(0));
    }

    #[test]
    fn out_of_range_request_is_distinct_error_and_recorded() {
        let reader = RecordingReader::with_pattern(100);
        let mut buf = [0u8; 8];
        let err = reader.read_at(200, &mut buf).unwrap_err();
        assert!(matches!(err, ForensicError::OutOfBounds { .. }));
        assert_eq!(
            reader.calls()[0].result,
            ReadCallResult::Err("out_of_bounds".to_string())
        );
    }

    #[test]
    fn injected_failure_by_call_index_propagates() {
        let reader = RecordingReader::with_pattern(256).fail_at_call(1, "bad sector at call 1");
        let mut buf = [0u8; 4];
        // Call 0 succeeds.
        assert!(reader.read_at(0, &mut buf).is_ok());
        // Call 1 fails deterministically.
        let err = reader.read_at(8, &mut buf).unwrap_err();
        assert!(matches!(err, ForensicError::Io { .. }));
        assert_eq!(reader.call_count(), 2);
    }

    #[test]
    fn injected_failure_by_offset_propagates() {
        let reader = RecordingReader::with_pattern(4096).fail_at_offset(0x800, "bad sector");
        let mut buf = [0u8; 16];
        assert!(reader.read_at(0, &mut buf).is_ok());
        let err = reader.read_at(0x800, &mut buf).unwrap_err();
        assert!(matches!(err, ForensicError::Io { .. }));
    }

    #[test]
    fn short_read_returns_fewer_bytes_via_read_at() {
        let reader = RecordingReader::with_pattern(256).short_read_at_offset(0, 3);
        let mut buf = [0u8; 16];
        let n = reader.read_at(0, &mut buf).unwrap();
        assert_eq!(n, 3, "short read should cap the returned bytes");
        assert_eq!(reader.calls()[0].result, ReadCallResult::Ok(3));
    }

    #[test]
    fn short_read_makes_read_exact_at_fail_strictly() {
        // A short read on a valid region must NOT become a successful read_exact_at.
        let reader = RecordingReader::with_pattern(256).short_read_at_offset(0, 3);
        let result = reader.read_exact_at(0, 16);
        assert!(
            result.is_err(),
            "read_exact_at must reject a short read, not zero-fill or truncate"
        );
    }

    #[test]
    fn multiple_reads_are_recorded_in_order() {
        let reader = RecordingReader::with_pattern(1024);
        let mut buf = [0u8; 8];
        reader.read_at(0, &mut buf).unwrap();
        reader.read_at(64, &mut buf).unwrap();
        reader.read_at(128, &mut buf).unwrap();

        let offsets: Vec<u64> = reader.calls().iter().map(|c| c.offset).collect();
        assert_eq!(offsets, vec![0, 64, 128]);
        assert_eq!(reader.total_bytes_read(), 24);
    }

    #[test]
    fn deterministic_failure_sequence_is_reproducible() {
        // The same configuration produces the same call/result sequence every run — the
        // primitive a future retry-policy test would rely on (no retry implemented here).
        // Each run uses a fresh reader, because the reader is deliberately stateful
        // (it records calls, so the call index advances across reads).
        let run = || {
            let reader = RecordingReader::with_pattern(256).fail_at_call(2, "transient");
            let mut buf = [0u8; 4];
            let mut outcomes = Vec::new();
            for off in [0u64, 8, 16, 24] {
                outcomes.push(reader.read_at(off, &mut buf).is_ok());
            }
            outcomes
        };
        assert_eq!(run(), run());
        assert_eq!(run(), vec![true, true, false, true]);
    }
}
