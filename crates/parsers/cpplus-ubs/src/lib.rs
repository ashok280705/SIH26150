//! # parser-cpplus-ubs
//!
//! CP Plus / UBS storage parser. Implements the common `Parser` interface (Req 6.3) over
//! evidence attributed to the UBS storage family.
//!
//! **Attribution honesty.** UBS storage research has not established OEM exclusivity, so
//! this family stays "UBS storage / CP Plus-compatible candidate". A matching UBS signature
//! never by itself yields `confirmed` CP Plus attribution (Req 2, 10).
//!
//! All factual knowledge — signatures, page sizes, offsets, structure layouts, validation
//! rules, applicability, and weights — is supplied by versioned profile data under
//! `profiles/cpplus/`, each rule carrying an `Evidence_Status`. Known research values ship
//! non-`validated` and model/firmware-scoped; nothing is declared as a source constant
//! (Req 6.1, 11.5).
//!
//! The parser interprets storage into `Recording`s, `TimeEvidence`, `TimelineEvent`
//! candidates, and a `StructureReport`. It supplies recovery *knowledge* but does not
//! orchestrate recovery, does not build the unified timeline, and never makes the final OEM
//! attribution (Req 3, 12, 15.1).
//!
//! Skeleton only — the parser lands in P3-011.

#![forbid(unsafe_code)]

pub mod parser;

pub use parser::CpPlusUbsParser;
