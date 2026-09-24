//! # reporting
//!
//! The `Reporting_Service`: PDF, JSON, and CSV reports carrying hashes, provenance, chain
//! of custody, capability stages, validation states, and stated limitations.
//!
//! Constraints this crate must uphold:
//!
//! * Reports are forensically defensible, documenting provenance, integrity, limitations,
//!   and chain of custody. They never claim legal admissibility (Req 17).
//! * Every conclusion cites the evidence it rests on: source offsets, profile version and
//!   hash, `Evidence_Status`, and `rule_match_status`.
//! * Capabilities that were executed are reported separately from capabilities that are
//!   unsupported or did not run. An operation that did not run is never `PASS` (Req 21, 22).
//! * A profile-only match is never presented as a reconstruction.
//!
#![forbid(unsafe_code)]

pub mod csv;
pub mod formatted;
pub mod json;
pub mod model;
pub mod provenance;

pub use csv::CsvReportExporter;
pub use formatted::FormattedReportExporter;
pub use json::JsonReportExporter;
pub use model::ForensicReport;
pub use provenance::ReportAuditor;
