//! # Observability of the index-aware recovery pipeline
//!
//! Asserts that the pipeline is actually observable, not merely that a metrics struct
//! exists: the structured `tracing` output is captured and every counter a forensic
//! engineer needs to reconstruct the run is checked for.
//!
//! This lives in its own test binary on purpose. `tracing::subscriber::set_default`
//! installs a **thread-local** subscriber, but `tracing`'s max-level hint is global — so a
//! sibling test running concurrently in the same binary can cause events to be filtered
//! out mid-run and make this test flaky. One test per binary removes that interaction
//! without resorting to a global subscriber that would leak into other tests.

mod common;

use common::{bounds, build_fixture, dahua_profile, open_fixture, profiles_dir};
use forensic_core::{EvidenceId, ProfileRegistry};
use parser_dahua::DahuaParser;
use recovery::{RecoveryEngine, RecoveryRequest};

/// A `tracing` writer that collects output into a shared buffer.
#[derive(Clone)]
struct CapturingWriter(std::sync::Arc<std::sync::Mutex<Vec<u8>>>);

impl std::io::Write for CapturingWriter {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        // A poisoned lock means another thread panicked; report it as an I/O error rather
        // than propagating a second panic out of the writer.
        match self.0.lock() {
            Ok(mut guard) => guard.extend_from_slice(buf),
            Err(_) => {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::Other,
                    "capture buffer lock poisoned",
                ))
            }
        }
        Ok(buf.len())
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

impl<'a> tracing_subscriber::fmt::MakeWriter<'a> for CapturingWriter {
    type Writer = CapturingWriter;
    fn make_writer(&'a self) -> Self::Writer {
        self.clone()
    }
}

#[test]
fn the_pipeline_emits_the_forensic_engineering_counters() {
    use tracing_subscriber::layer::SubscriberExt;

    let buffer = std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
    let subscriber = tracing_subscriber::registry().with(
        tracing_subscriber::fmt::layer()
            .with_writer(CapturingWriter(buffer.clone()))
            .with_ansi(false)
            .with_target(true),
    );
    let _guard = tracing::subscriber::set_default(subscriber);

    let fx = build_fixture();
    let (_dir, reader) = open_fixture(&fx);
    let registry = ProfileRegistry::load_from_dir(&profiles_dir()).unwrap();
    let profile = dahua_profile(&registry);
    let parser = DahuaParser::default();

    let outcome = RecoveryEngine::new()
        .execute_recovery(RecoveryRequest {
            evidence_id: EvidenceId::new(),
            reader: &reader,
            profile,
            oem_key: "dahua",
            parser: &parser,
            bounds: &bounds(),
            scan_window: None,
            read_window_bytes: None,
        })
        .unwrap();

    let logged = String::from_utf8_lossy(&buffer.lock().unwrap()).to_string();

    // ── Every required counter appears in the run summary ───────────────────
    for field in [
        "oem_key",
        "profile_id",
        "geometry_available",
        "video_region",
        "index_region",
        "block_size",
        "authoritative_index",
        "index_declared_entries",
        "index_entry_count",
        "claimed_range_count",
        "claimed_bytes",
        "unclaimed_region_count",
        "unclaimed_bytes",
        "orphan_eligible_region_count",
        "orphan_eligible_bytes",
        "scan_region_count",
        "scanned_bytes",
        "bytes_avoided_vs_full_scan",
        "candidate_count",
        "active=",
        "orphaned=",
        "unindexed=",
        "corrupted=",
        "validation_failures",
        "skipped_ranges",
        "truncated",
        "cancelled",
    ] {
        assert!(
            logged.contains(field),
            "the run summary is missing `{field}`.\nEmitted:\n{logged}"
        );
    }

    // ── The staged pipeline is traceable ────────────────────────────────────
    assert!(
        logged.contains("OEM storage geometry established"),
        "storage interpretation must be logged as its own step:\n{logged}"
    );
    assert!(
        logged.contains("OEM recording index read"),
        "index discovery must be logged as its own step:\n{logged}"
    );
    assert!(
        logged.contains("recovery plan built"),
        "the claimed/unclaimed comparison must be logged:\n{logged}"
    );
    assert!(
        logged.contains("index-aware recovery run complete"),
        "the run summary must be emitted:\n{logged}"
    );

    // ── Per-candidate decisions record the claim that produced them ─────────
    assert!(
        logged.contains("recovery candidate produced"),
        "each candidate decision must be traceable:\n{logged}"
    );
    // Both orphan discovery paths are distinguishable in the log. They are different evidence:
    // one is a metadata-described recording the recorder no longer reaches, the other is video in
    // a region the block table governs but does not claim.
    assert!(
        logged.contains("available-metadata-probe"),
        "the metadata-driven orphan path must be visible:\n{logged}"
    );
    assert!(
        logged.contains("unclaimed-scan-in-index-scope"),
        "the unclaimed-in-scope orphan path must be visible:\n{logged}"
    );
    assert!(
        logged.contains("index-claimed-probe"),
        "the indexed discovery method must be visible:\n{logged}"
    );
    assert!(
        logged.contains("Orphaned"),
        "the orphan state must be visible in the per-candidate log:\n{logged}"
    );
    // Structural recovery is distinguishable from window classification.
    assert!(
        logged.contains("oem-container-record"),
        "the framing that bounded each fragment must be visible:\n{logged}"
    );
    for field in [
        "available_claim_count",
        "available_bytes",
        "container_record_candidates",
    ] {
        assert!(
            logged.contains(field),
            "the run summary is missing `{field}`.\nEmitted:\n{logged}"
        );
    }

    // ── Byte totals in the log agree with the returned metrics ──────────────
    assert!(
        logged.contains(&outcome.metrics.claimed_bytes.to_string()),
        "logged claimed_bytes must match the returned metrics"
    );
    assert!(
        logged.contains(&outcome.metrics.unclaimed_bytes.to_string()),
        "logged unclaimed_bytes must match the returned metrics"
    );

    // ── Raw evidence content is never logged ────────────────────────────────
    //
    // Naming a structure ("the DIDX index at 0x… parsed") is exactly what a forensic
    // engineer needs and is not evidence content. What must never appear is the evidence
    // *bytes*: a hex dump, a payload excerpt, or a decoded stream fragment.
    //
    // The check is for a long unbroken run of hex digits, which is what any byte dump
    // looks like and which nothing in this pipeline's legitimate output produces (offsets
    // are short hex, counts are decimal).
    //
    // `fragment_id` is excluded before the scan. It is a digest of the evidence id and the
    // fragment's physical range — a derived identifier, not evidence content — and stripping it
    // keeps the heuristic tight on everything else rather than forcing the threshold up.
    let scanned: String = logged
        .split_whitespace()
        .filter(|tok| !tok.starts_with("fragment_id="))
        .collect::<Vec<_>>()
        .join(" ");
    let longest_hex_run = scanned
        .split(|c: char| !c.is_ascii_hexdigit())
        .map(|s| s.len())
        .max()
        .unwrap_or(0);
    assert!(
        longest_hex_run <= 16,
        "log output contains a {longest_hex_run}-digit hex run, which looks like an \
         evidence byte dump:\n{logged}"
    );

    // And none of the fixture's actual payload bytes, in any common encoding.
    let payload_marker = &fx.segments[2].payload[..12];
    assert!(
        !logged.contains(&hex_encode(payload_marker)),
        "log output must not contain evidence payload bytes:\n{logged}"
    );
    assert!(
        !logged.contains(&String::from_utf8_lossy(payload_marker).to_string()),
        "log output must not contain evidence payload bytes:\n{logged}"
    );
}

fn hex_encode(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}
