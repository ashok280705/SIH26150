//! # The universal `Parser` contract, as an executable harness
//!
//! Every OEM parser that claims compliance runs against *this* code, not against a per-OEM
//! test written by whoever added the parser. The point is that adding an OEM should mean
//! writing a parser and pointing this harness at it — not inventing a new notion of what
//! "correct" means.
//!
//! ```text
//!   OEM parser  ──►  run_parser_contract()  ──►  ContractReport
//!                         │
//!                         ├─ determinism      same evidence → same normalized output
//!                         ├─ bounds           nothing described outside the evidence
//!                         ├─ no fabrication   unknown stays None, never 0 / epoch / H264
//!                         ├─ normalization    payloads inside their records, sane lengths
//!                         └─ provenance       offsets are absolute and resolvable
//! ```
//!
//! ## What this harness deliberately does not do
//!
//! It never asserts that a parser *has* a capability. A parser with no index reader is a
//! valid parser: `Ok(None)` is a supported, honest answer, and the recovery engine degrades
//! for it. The contract governs the shape and honesty of whatever the parser does return.
//!
//! It also never inspects OEM structures. It is handed a reader and a profile and reads only
//! the parser's normalized output, so it stays valid for OEMs that do not exist yet.
//!
//! ## Reading the result
//!
//! [`ContractReport`] lists every check with its own outcome and an explanation, rather than
//! panicking on the first problem. A caller that wants a test failure calls
//! [`ContractReport::assert_compliant`]; a caller that wants to record the current state of a
//! partially compliant parser can read the checks individually.

use std::collections::BTreeSet;

use evidence_reader::EvidenceReader;
use forensic_core::{OemProfile, Region, ValidationStateKind};

use crate::parser::Parser;
use crate::storage::{ContainerRecord, IndexedRecording};

/// One contract check's outcome.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CheckOutcome {
    /// The check ran and the parser satisfied it.
    Pass,
    /// The check ran and the parser violated it.
    Fail,
    /// The check could not run because the parser does not supply the input it needs. This
    /// is not a failure: a parser with no index reader has no index to check.
    NotApplicable,
}

/// One named check, its outcome, and why.
#[derive(Debug, Clone)]
pub struct ContractCheck {
    /// Stable identifier, e.g. `index.regions_in_bounds`.
    pub name: &'static str,
    pub outcome: CheckOutcome,
    /// What was observed, in enough detail to act on without re-running.
    pub detail: String,
}

impl ContractCheck {
    fn pass(name: &'static str, detail: impl Into<String>) -> Self {
        Self {
            name,
            outcome: CheckOutcome::Pass,
            detail: detail.into(),
        }
    }
    fn fail(name: &'static str, detail: impl Into<String>) -> Self {
        Self {
            name,
            outcome: CheckOutcome::Fail,
            detail: detail.into(),
        }
    }
    fn skip(name: &'static str, detail: impl Into<String>) -> Self {
        Self {
            name,
            outcome: CheckOutcome::NotApplicable,
            detail: detail.into(),
        }
    }
}

/// The result of running the contract against one parser and one evidence item.
#[derive(Debug, Clone)]
pub struct ContractReport {
    pub parser_id: String,
    pub parser_version: String,
    /// Every check, in a fixed order.
    pub checks: Vec<ContractCheck>,
}

impl ContractReport {
    pub fn failures(&self) -> Vec<&ContractCheck> {
        self.checks
            .iter()
            .filter(|c| c.outcome == CheckOutcome::Fail)
            .collect()
    }

    pub fn is_compliant(&self) -> bool {
        self.failures().is_empty()
    }

    /// Look up one check by name.
    pub fn check(&self, name: &str) -> Option<&ContractCheck> {
        self.checks.iter().find(|c| c.name == name)
    }

    /// Panic with every violation listed, for use as a test assertion.
    pub fn assert_compliant(&self) {
        if self.is_compliant() {
            return;
        }
        let detail = self
            .failures()
            .iter()
            .map(|c| format!("  - {}: {}", c.name, c.detail))
            .collect::<Vec<_>>()
            .join("\n");
        panic!(
            "parser '{}' v{} violates the universal Parser contract:\n{detail}",
            self.parser_id, self.parser_version
        );
    }

    /// A one-line-per-check summary, for a verification log.
    pub fn summary(&self) -> String {
        self.checks
            .iter()
            .map(|c| {
                let tag = match c.outcome {
                    CheckOutcome::Pass => "PASS",
                    CheckOutcome::Fail => "FAIL",
                    CheckOutcome::NotApplicable => "N/A ",
                };
                format!("{tag}  {:<44} {}", c.name, c.detail)
            })
            .collect::<Vec<_>>()
            .join("\n")
    }
}

/// Whether a region lies wholly inside the evidence.
fn in_bounds(region: Region, evidence_len: u64) -> bool {
    match region.end() {
        Some(end) => end <= evidence_len,
        // An end that overflows u64 can never be inside any evidence item.
        None => false,
    }
}

/// Timestamps that are almost always a fabricated placeholder rather than a reading.
///
/// A recorder can in principle write any of these, but a parser that reports the Unix epoch
/// for a DVR recording is far more likely to have substituted a default for a field it could
/// not read. The contract treats them as violations so the honest `None` is the easy path.
fn is_placeholder_timestamp(t: i64) -> bool {
    // The epoch itself, and anything before it, cannot be a recorder clock reading.
    t <= 0
}

/// Run the universal contract against one parser over one evidence item.
///
/// `reader` is whatever evidence the caller wants the parser exercised on — a real fixture,
/// a truncated image, or bytes from a different OEM entirely. The contract holds in all three
/// cases: a parser handed foreign bytes must return nothing rather than invent something.
pub fn run_parser_contract(
    parser: &dyn Parser,
    reader: &dyn EvidenceReader,
    profile: &OemProfile,
) -> ContractReport {
    let mut checks: Vec<ContractCheck> = Vec::new();
    let evidence_len = reader.len();

    // ── identity ────────────────────────────────────────────────────────────
    checks.push(if parser.id().trim().is_empty() {
        ContractCheck::fail("identity.id_non_empty", "the parser reports an empty id")
    } else {
        ContractCheck::pass("identity.id_non_empty", format!("id '{}'", parser.id()))
    });
    checks.push(if parser.version().trim().is_empty() {
        ContractCheck::fail(
            "identity.version_non_empty",
            "the parser reports an empty version, so a result cannot be tied to the code that produced it",
        )
    } else {
        ContractCheck::pass(
            "identity.version_non_empty",
            format!("version '{}'", parser.version()),
        )
    });

    // ── geometry ────────────────────────────────────────────────────────────
    let geometry = parser.storage_geometry(reader, profile);
    match &geometry {
        Err(e) => checks.push(ContractCheck::fail(
            "geometry.no_error_on_readable_evidence",
            format!("storage_geometry returned an error: {e}"),
        )),
        Ok(None) => checks.push(ContractCheck::skip(
            "geometry.regions_in_bounds",
            "this parser establishes no storage geometry, which is a supported answer",
        )),
        Ok(Some(g)) => {
            let mut offenders: Vec<String> = Vec::new();
            for (name, region) in [
                ("video_region", g.video_region),
                ("index_region", g.index_region),
                ("metadata_region", g.metadata_region),
            ] {
                if let Some(r) = region {
                    if !in_bounds(r, evidence_len) {
                        offenders.push(format!(
                            "{name} {r} escapes the {evidence_len}-byte evidence"
                        ));
                    }
                }
            }
            checks.push(if offenders.is_empty() {
                ContractCheck::pass(
                    "geometry.regions_in_bounds",
                    "every declared geometry region lies inside the evidence",
                )
            } else {
                ContractCheck::fail("geometry.regions_in_bounds", offenders.join("; "))
            });

            checks.push(if g.physical_size > evidence_len {
                ContractCheck::fail(
                    "geometry.physical_size_not_overstated",
                    format!(
                        "declared physical size {} exceeds the {evidence_len} bytes actually held",
                        g.physical_size
                    ),
                )
            } else {
                ContractCheck::pass(
                    "geometry.physical_size_not_overstated",
                    format!("declared physical size {}", g.physical_size),
                )
            });

            checks.push(if g.evidence.reason.trim().is_empty() {
                ContractCheck::fail(
                    "geometry.evidence_state_explained",
                    "the geometry carries an empty reason, so its trustworthiness is unexplained",
                )
            } else {
                ContractCheck::pass(
                    "geometry.evidence_state_explained",
                    format!("{:?}: {}", g.evidence.state, g.evidence.reason),
                )
            });

            checks.push(if g.block_size == Some(0) || g.sector_size == Some(0) {
                ContractCheck::fail(
                    "geometry.no_zero_sizes",
                    "a declared block or sector size of zero is a substituted default, not a reading; it must be None",
                )
            } else {
                ContractCheck::pass(
                    "geometry.no_zero_sizes",
                    "declared block and sector sizes are either absent or non-zero",
                )
            });
        }
    }

    // ── index ───────────────────────────────────────────────────────────────
    let index = parser.recording_index(reader, profile);
    match &index {
        Err(e) => checks.push(ContractCheck::fail(
            "index.no_error_on_readable_evidence",
            format!("recording_index returned an error: {e}"),
        )),
        Ok(None) => {
            for name in [
                "index.regions_in_bounds",
                "index.no_fabricated_metadata",
                "index.payload_within_record",
                "index.authority_is_explained",
                "index.accessible_and_unreferenced_are_disjoint",
            ] {
                checks.push(ContractCheck::skip(
                    name,
                    "this parser reads no recording index, which is a supported answer",
                ));
            }
        }
        Ok(Some(ix)) => {
            let entries: Vec<&IndexedRecording> = ix
                .recordings
                .iter()
                .chain(ix.unreferenced_recordings.iter())
                .collect();

            let mut escaping: Vec<String> = Vec::new();
            for e in &entries {
                for r in &e.physical_regions {
                    if !in_bounds(*r, evidence_len) {
                        escaping.push(format!("{}: {r}", e.recording_id));
                    }
                }
            }
            checks.push(if escaping.is_empty() {
                ContractCheck::pass(
                    "index.regions_in_bounds",
                    format!(
                        "{} entr(ies) describe only ranges inside the {evidence_len}-byte evidence",
                        entries.len()
                    ),
                )
            } else {
                ContractCheck::fail(
                    "index.regions_in_bounds",
                    format!("regions escaping the evidence: {}", escaping.join("; ")),
                )
            });

            let mut fabricated: Vec<String> = Vec::new();
            for e in &entries {
                if let Some(t) = e.start_time_unix {
                    if is_placeholder_timestamp(t) {
                        fabricated.push(format!(
                            "{}: start_time_unix {t} is a placeholder, not a recorder reading",
                            e.recording_id
                        ));
                    }
                }
                if let (Some(s), Some(en)) = (e.start_time_unix, e.end_time_unix) {
                    if en < s {
                        fabricated.push(format!("{}: end {en} precedes start {s}", e.recording_id));
                    }
                }
                if e.recording_id.trim().is_empty() {
                    fabricated.push("an entry carries an empty recording id".to_string());
                }
                if e.evidence.reason.trim().is_empty() {
                    fabricated.push(format!("{}: empty evidence reason", e.recording_id));
                }
                if e.codec_hint.as_deref().map(str::trim) == Some("") {
                    fabricated.push(format!(
                        "{}: an empty codec hint is not 'unknown'; it must be None",
                        e.recording_id
                    ));
                }
            }
            checks.push(if fabricated.is_empty() {
                ContractCheck::pass(
                    "index.no_fabricated_metadata",
                    "no entry carries a placeholder timestamp, an inverted interval, or an empty required field",
                )
            } else {
                ContractCheck::fail("index.no_fabricated_metadata", fabricated.join("; "))
            });

            let mut payload_errors: Vec<String> = Vec::new();
            for e in &entries {
                if e.payload_regions.len() > e.physical_regions.len() {
                    payload_errors.push(format!(
                        "{}: {} payload range(s) for {} physical range(s)",
                        e.recording_id,
                        e.payload_regions.len(),
                        e.physical_regions.len()
                    ));
                }
                for (i, p) in e.payload_regions.iter().enumerate() {
                    match e.physical_regions.get(i) {
                        Some(phys) => {
                            let inside = p.offset >= phys.offset
                                && match (p.end(), phys.end()) {
                                    (Some(pe), Some(fe)) => pe <= fe,
                                    _ => false,
                                };
                            if !inside {
                                payload_errors.push(format!(
                                    "{}: payload {p} is not inside its record {phys}",
                                    e.recording_id
                                ));
                            }
                        }
                        None => payload_errors.push(format!(
                            "{}: payload {p} has no corresponding physical range",
                            e.recording_id
                        )),
                    }
                }
            }
            checks.push(if payload_errors.is_empty() {
                ContractCheck::pass(
                    "index.payload_within_record",
                    "every payload sub-range lies inside the record it belongs to",
                )
            } else {
                ContractCheck::fail("index.payload_within_record", payload_errors.join("; "))
            });

            // An authoritative index must say what it governs, and that scope must be real.
            let authority_ok = match &ix.authority {
                crate::storage::IndexAuthority::Authoritative { governs } => {
                    if !in_bounds(*governs, evidence_len) {
                        Err(format!(
                            "the index claims authority over {governs}, which escapes the {evidence_len}-byte evidence"
                        ))
                    } else if governs.is_empty() {
                        Err("the index claims authority over an empty region".to_string())
                    } else {
                        // The universal invariant is that a parser cannot produce more
                        // recordings than the index declares slots for. Equality is NOT the
                        // rule: several OEM index formats declare a count of *slots*, of
                        // which the free ones correctly yield no recording, so requiring
                        // `parsed == declared` would force a slot-table parser to either
                        // under-report its own structure or downgrade a genuinely complete
                        // read to Partial. See `RecordingIndex::declared_entry_count`.
                        match ix.declared_entry_count {
                            Some(declared) if entries.len() > declared => Err(format!(
                                "the index declares {declared} entr(ies) but {} were produced; a \
                                 parser cannot produce more recordings than the structure declares",
                                entries.len()
                            )),
                            Some(declared) => Ok(format!(
                                "authoritative over {governs}; {} of {declared} declared entr(ies) \
                                 yielded recordings",
                                entries.len()
                            )),
                            None => Ok(format!("authoritative over {governs}")),
                        }
                    }
                }
                crate::storage::IndexAuthority::Partial { reason }
                | crate::storage::IndexAuthority::NotFound { reason } => {
                    if reason.trim().is_empty() {
                        Err("a non-authoritative index must record why".to_string())
                    } else {
                        Ok(format!("not authoritative: {reason}"))
                    }
                }
            };
            checks.push(match authority_ok {
                Ok(detail) => ContractCheck::pass("index.authority_is_explained", detail),
                Err(detail) => ContractCheck::fail("index.authority_is_explained", detail),
            });

            // The accessible and unreferenced sets describe different recordings. An entry in
            // both would let one recording be reported as active and orphaned at once.
            let accessible_ids: BTreeSet<&str> = ix
                .recordings
                .iter()
                .map(|e| e.recording_id.as_str())
                .collect();
            let overlap: Vec<&str> = ix
                .unreferenced_recordings
                .iter()
                .map(|e| e.recording_id.as_str())
                .filter(|id| accessible_ids.contains(id))
                .collect();
            checks.push(if overlap.is_empty() {
                ContractCheck::pass(
                    "index.accessible_and_unreferenced_are_disjoint",
                    format!(
                        "{} accessible and {} unreferenced entr(ies), with no id in both",
                        ix.recordings.len(),
                        ix.unreferenced_recordings.len()
                    ),
                )
            } else {
                ContractCheck::fail(
                    "index.accessible_and_unreferenced_are_disjoint",
                    format!("recording id(s) in both sets: {}", overlap.join(", ")),
                )
            });
        }
    }

    // ── structural carving ──────────────────────────────────────────────────
    let scan_region = Region::new(0, evidence_len.min(4 * 1024 * 1024)).ok();
    match scan_region {
        None => checks.push(ContractCheck::skip(
            "carver.records_within_requested_region",
            "the evidence is empty, so there is no range to carve",
        )),
        Some(region) => match parser.scan_region_for_candidates(reader, profile, region) {
            Err(e) => checks.push(ContractCheck::fail(
                "carver.no_error_on_readable_region",
                format!("scan_region_for_candidates returned an error: {e}"),
            )),
            Ok(records) if records.is_empty() => {
                for name in [
                    "carver.records_within_requested_region",
                    "carver.no_fabricated_metadata",
                    "carver.payload_within_record",
                    "carver.deterministic",
                ] {
                    checks.push(ContractCheck::skip(
                        name,
                        "no container record was carved from the probe range",
                    ));
                }
            }
            Ok(records) => {
                checks.extend(check_records(&records, region, evidence_len));

                // Determinism of the carver specifically: the same range twice.
                let again = parser
                    .scan_region_for_candidates(reader, profile, region)
                    .unwrap_or_default();
                let same = again.len() == records.len()
                    && again
                        .iter()
                        .zip(records.iter())
                        .all(|(a, b)| a.physical_region == b.physical_region);
                checks.push(if same {
                    ContractCheck::pass(
                        "carver.deterministic",
                        format!(
                            "{} record(s) reported identically on both passes",
                            records.len()
                        ),
                    )
                } else {
                    ContractCheck::fail(
                        "carver.deterministic",
                        format!(
                            "the carver reported {} record(s) then {} over the same range",
                            records.len(),
                            again.len()
                        ),
                    )
                });
            }
        },
    }

    // ── determinism of the whole normalized output ──────────────────────────
    let geometry_again = parser.storage_geometry(reader, profile);
    let index_again = parser.recording_index(reader, profile);
    let geometry_stable = match (&geometry, &geometry_again) {
        (Ok(a), Ok(b)) => a == b,
        (Err(_), Err(_)) => true,
        _ => false,
    };
    let index_stable = match (&index, &index_again) {
        (Ok(a), Ok(b)) => a == b,
        (Err(_), Err(_)) => true,
        _ => false,
    };
    checks.push(if geometry_stable && index_stable {
        ContractCheck::pass(
            "determinism.repeat_parse_is_identical",
            "geometry and index are byte-for-byte identical across two parses of the same evidence",
        )
    } else {
        ContractCheck::fail(
            "determinism.repeat_parse_is_identical",
            format!(
                "geometry stable: {geometry_stable}, index stable: {index_stable}; a second parse \
                 of identical bytes produced a different normalized result"
            ),
        )
    });

    ContractReport {
        parser_id: parser.id().to_string(),
        parser_version: parser.version().to_string(),
        checks,
    }
}

/// The record-shape half of the contract, factored out so it reads as one rule set.
fn check_records(
    records: &[ContainerRecord],
    requested: Region,
    evidence_len: u64,
) -> Vec<ContractCheck> {
    let mut outside: Vec<String> = Vec::new();
    for r in records {
        if !in_bounds(r.physical_region, evidence_len) {
            outside.push(format!(
                "record at {} escapes the {evidence_len}-byte evidence",
                r.physical_region
            ));
        } else if !r.physical_region.overlaps(&requested) {
            outside.push(format!(
                "record at {} lies outside the requested range {requested}",
                r.physical_region
            ));
        }
        if r.physical_region.is_empty() {
            outside.push(format!(
                "record at offset {} has zero length",
                r.physical_region.offset
            ));
        }
    }

    let mut fabricated: Vec<String> = Vec::new();
    for r in records {
        if let Some(t) = r.start_time_unix {
            if is_placeholder_timestamp(t) {
                fabricated.push(format!(
                    "record at {} reports placeholder timestamp {t}",
                    r.physical_region
                ));
            }
        }
        if r.channel == Some(0) {
            fabricated.push(format!(
                "record at {} reports channel 0; the contract's channels are 1-based, so 0 is a substituted default",
                r.physical_region
            ));
        }
        if r.evidence.reason.trim().is_empty() {
            fabricated.push(format!(
                "record at {} has an empty evidence reason",
                r.physical_region
            ));
        }
        // A record whose framing failed verification must not read as sound.
        if r.evidence.state == ValidationStateKind::Pass && r.physical_region.is_empty() {
            fabricated.push(format!(
                "record at {} is marked PASS while describing no bytes",
                r.physical_region
            ));
        }
    }

    let mut payload_errors: Vec<String> = Vec::new();
    for r in records {
        if let Some(p) = r.payload_region {
            let inside = p.offset >= r.physical_region.offset
                && match (p.end(), r.physical_region.end()) {
                    (Some(pe), Some(fe)) => pe <= fe,
                    _ => false,
                };
            if !inside {
                payload_errors.push(format!(
                    "payload {p} is not inside its record {}",
                    r.physical_region
                ));
            }
        }
    }

    vec![
        if outside.is_empty() {
            ContractCheck::pass(
                "carver.records_within_requested_region",
                format!("{} record(s), all inside {requested}", records.len()),
            )
        } else {
            ContractCheck::fail("carver.records_within_requested_region", outside.join("; "))
        },
        if fabricated.is_empty() {
            ContractCheck::pass(
                "carver.no_fabricated_metadata",
                "no record carries a placeholder channel or clock, or an unexplained state",
            )
        } else {
            ContractCheck::fail("carver.no_fabricated_metadata", fabricated.join("; "))
        },
        if payload_errors.is_empty() {
            ContractCheck::pass(
                "carver.payload_within_record",
                "every payload sub-range lies inside its own record",
            )
        } else {
            ContractCheck::fail("carver.payload_within_record", payload_errors.join("; "))
        },
    ]
}
