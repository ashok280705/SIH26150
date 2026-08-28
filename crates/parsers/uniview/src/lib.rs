//! # parser-uniview
//!
//! Uniview parser. Uniview is a **currently supported target OEM, not future work**, with
//! full parity alongside Dahua, Hikvision, Honeywell, and CP Plus/UBS (Req 25.1). It
//! implements the same common `Parser` interface as every other OEM (Req 6.3).
//!
//! All Uniview factual knowledge — the storage-region vocabulary, magic and version
//! candidates, port-identifier form, timestamp encoding, and the index and
//! timestamp-to-block mapping — is supplied by versioned profile data under
//! `profiles/uniview/`, each rule carrying an `Evidence_Status`. None of it is treated as a
//! universal fact unless its `Evidence_Status` is `validated`, and none of it is declared as
//! a source constant (Req 25.3, 6.1, 11.5).
//!
//! Parse flow (Req 25.5): detection → super metadata → region identification → index →
//! timestamp-to-block mapping → data region → video payload → frame validation →
//! `Recording`. The parser never builds the unified timeline and never makes the final OEM
//! attribution.
//!
//! Corroborating evidence such as a port identifier or a timestamp is validated by profile
//! rules and is never alone treated as proof of Uniview (Req 25.4). Uniview edge cases —
//! missing superblock, magic at an unexpected location, lone magic, corrupted metadata,
//! invalid timestamp, region inconsistency, missing index, orphan data, fragmentation,
//! overwrite, truncation, out-of-bounds block, conflicting candidates, unknown variant —
//! are handled with checked arithmetic and without panic (Req 25.7, 24).
//!
//! Skeleton only — the parser lands in P3-012, its edge-case suite in P3-015.

#![forbid(unsafe_code)]
