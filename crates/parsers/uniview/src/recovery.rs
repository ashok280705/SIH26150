//! # Uniview recovery, by evidential basis
//!
//! Recovery here is limited to what the known Uniview structure can defend, and every item
//! says which of three bases it rests on:
//!
//! | Basis | What it is | Confidence |
//! |---|---|---|
//! | [`RecoveryBasis::Indexed`]    | a declared DI entry → SPtoI → DATA block(s) | the block is CONFIRMED; a multi-block extent is a STRONG INFERENCE |
//! | [`RecoveryBasis::Structural`] | DATA-block ranges inside valid unit geometry that no DI entry references | content UNKNOWN |
//! | [`RecoveryBasis::Heuristic`]  | residual DI slots beyond the declared count that still decode | TENTATIVE |
//!
//! ## What is never claimed
//!
//! * There is no known Uniview deletion structure, so nothing here is reported as
//!   "deleted". A structural range is *unreferenced*; a residual slot is *residue*.
//! * The rewrited flag says the ring has wrapped, not which bytes were overwritten.
//! * No structural or heuristic item is a confirmed recording, and none carries a codec.
//!
//! All reads are read-only and bounded to valid unit geometry.

use evidence_reader::EvidenceReader;
use forensic_core::{ForensicError, Region};
use serde::{Deserialize, Serialize};

use crate::di::{self, DiHeaderState, SpanBasis};
use crate::layout::Confidence;
use crate::timestamp::UnvTimestamp;
use crate::volume::{self, UniviewVolume};

/// The evidential basis of a recovery item.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum RecoveryBasis {
    Indexed,
    Structural,
    Heuristic,
}

/// One recoverable (or examinable) range.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RecoveryItem {
    pub basis: RecoveryBasis,
    /// Confidence that the range holds recorder DATA as described.
    pub confidence: Confidence,
    pub unit: u32,
    pub di_entry_index: Option<u32>,
    pub di_entry_offset: Option<u64>,
    pub timestamp: Option<UnvTimestamp>,
    pub sptoi: Option<u16>,
    pub span_basis: Option<SpanBasis>,
    /// Exact physical ranges, clipped to the image.
    pub regions: Vec<Region>,
    /// Whether the first block of the range holds any non-zero byte. `None` if not probed.
    pub nonzero_probe: Option<bool>,
    pub description: String,
}

/// What to include beyond the indexed items.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct RecoveryOptions {
    pub include_structural: bool,
    pub include_heuristic: bool,
    /// Read the first block of structural ranges to report whether they are all-zero.
    pub probe_content: bool,
}

impl Default for RecoveryOptions {
    fn default() -> Self {
        Self {
            include_structural: true,
            include_heuristic: true,
            probe_content: true,
        }
    }
}

/// The recovery report for one volume.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct UniviewRecoveryReport {
    pub items: Vec<RecoveryItem>,
    pub indexed: u64,
    pub structural: u64,
    pub heuristic: u64,
    /// Whether the profile's item cap stopped the report early.
    pub truncated: bool,
    pub notes: Vec<String>,
}

impl UniviewRecoveryReport {
    pub fn of_basis(&self, basis: RecoveryBasis) -> impl Iterator<Item = &RecoveryItem> {
        self.items.iter().filter(move |i| i.basis == basis)
    }

    fn push(&mut self, cap: usize, item: RecoveryItem) -> bool {
        if self.items.len() >= cap {
            self.truncated = true;
            return false;
        }
        match item.basis {
            RecoveryBasis::Indexed => self.indexed += 1,
            RecoveryBasis::Structural => self.structural += 1,
            RecoveryBasis::Heuristic => self.heuristic += 1,
        }
        self.items.push(item);
        true
    }
}

fn probe_nonzero(
    reader: &dyn EvidenceReader,
    region: &Region,
    block: u64,
) -> Result<bool, ForensicError> {
    let len = usize::try_from(region.length.min(block)).unwrap_or(0);
    if len == 0 {
        return Ok(false);
    }
    Ok(reader
        .read_exact_at(region.offset, len)?
        .iter()
        .any(|&b| b != 0))
}

/// Subtract `taken` (ascending, disjoint) from `whole`.
fn gaps(whole: Region, taken: &[Region]) -> Vec<Region> {
    let mut out = Vec::new();
    let end = whole.offset.saturating_add(whole.length);
    let mut cursor = whole.offset;
    for t in taken {
        let t_end = t.offset.saturating_add(t.length);
        if t_end <= cursor || t.offset >= end {
            continue;
        }
        if t.offset > cursor {
            if let Ok(r) = Region::new(cursor, t.offset - cursor) {
                out.push(r);
            }
        }
        cursor = cursor.max(t_end);
    }
    if cursor < end {
        if let Ok(r) = Region::new(cursor, end - cursor) {
            out.push(r);
        }
    }
    out
}

/// Build the recovery report. Non-Uniview evidence yields an empty report.
pub fn build_recovery_report(
    reader: &dyn EvidenceReader,
    volume: &UniviewVolume,
    options: RecoveryOptions,
) -> Result<UniviewRecoveryReport, ForensicError> {
    let mut report = UniviewRecoveryReport {
        items: Vec::new(),
        indexed: 0,
        structural: 0,
        heuristic: 0,
        truncated: false,
        notes: vec![
            "INDEXED items follow a declared DI entry's SPtoI to its DATA block; multi-block \
             extents are inferred from the adjacent SPtoI"
                .into(),
            "STRUCTURAL items are DATA ranges no DI entry references; they are unreferenced, not \
             deleted, and their content is not asserted"
                .into(),
            "HEURISTIC items are residual DI slots beyond the declared count; they are candidates \
             for examination, never confirmed recordings"
                .into(),
        ],
    };
    if !volume.is_uniview() {
        return Ok(report);
    }
    if volume.ui.as_ref().and_then(|u| u.rewrited()) == Some(true) {
        report.notes.push(
            "the rewrited flag is set: the storage ring has wrapped at least once, so older DATA \
             may have been overwritten; which ranges were overwritten is not recorded"
                .into(),
        );
    }
    let l = &volume.layout;
    let cap = l.recovery_max_items;
    let block = l.data_block_size;

    'units: for u in &volume.units {
        let Some(detail) = volume::unit_detail(reader, volume, u.unit)? else {
            continue;
        };

        // ── INDEXED ─────────────────────────────────────────────────────────
        for s in &detail.spans {
            let Some(region) = s.region else { continue };
            let entry = detail.di.entries.iter().find(|e| e.index == s.entry_index);
            let ok = report.push(
                cap,
                RecoveryItem {
                    basis: RecoveryBasis::Indexed,
                    confidence: if s.basis.is_lower_bound() {
                        Confidence::Confirmed
                    } else {
                        Confidence::StrongInference
                    },
                    unit: u.unit,
                    di_entry_index: Some(s.entry_index),
                    di_entry_offset: entry.map(|e| e.offset),
                    timestamp: entry.map(|e| e.timestamp.clone()),
                    sptoi: Some(s.start_sptoi),
                    span_basis: Some(s.basis),
                    regions: vec![region],
                    nonzero_probe: None,
                    description: format!(
                        "unit {} DI entry {} -> SPtoI {} -> {} block(s) at 0x{:X} ({}{})",
                        u.unit,
                        s.entry_index,
                        s.start_sptoi,
                        s.blocks,
                        region.offset,
                        s.basis.label(),
                        if s.truncated_by_image {
                            ", clipped by the end of the image"
                        } else {
                            ""
                        }
                    ),
                },
            );
            if !ok {
                break 'units;
            }
        }

        // ── STRUCTURAL ──────────────────────────────────────────────────────
        if options.include_structural && !matches!(u.header_state, DiHeaderState::NotPresent) {
            let data_start = u
                .unit_base
                .saturating_add(l.di_blocks().saturating_mul(block));
            let unit_end = u.unit_base.saturating_add(u.bytes_in_image);
            if unit_end > data_start {
                let whole = Region::new(data_start, unit_end - data_start)?;
                for g in gaps(whole, &u.data_regions) {
                    let probe = if options.probe_content {
                        Some(probe_nonzero(reader, &g, block)?)
                    } else {
                        None
                    };
                    let ok = report.push(
                        cap,
                        RecoveryItem {
                            basis: RecoveryBasis::Structural,
                            confidence: Confidence::Unknown,
                            unit: u.unit,
                            di_entry_index: None,
                            di_entry_offset: None,
                            timestamp: None,
                            sptoi: None,
                            span_basis: None,
                            regions: vec![g],
                            nonzero_probe: probe,
                            description: format!(
                                "unit {} ({} DI): DATA range 0x{:X}..0x{:X} ({} block(s)) is \
                                 referenced by no DI entry; content not asserted{}",
                                u.unit,
                                u.header_state.label(),
                                g.offset,
                                g.offset.saturating_add(g.length),
                                g.length.div_ceil(block.max(1)),
                                match probe {
                                    Some(true) => "; its first block holds non-zero bytes",
                                    Some(false) => "; its first block is all zero",
                                    None => "",
                                }
                            ),
                        },
                    );
                    if !ok {
                        break 'units;
                    }
                }
            }
        }

        // ── HEURISTIC ───────────────────────────────────────────────────────
        if options.include_heuristic {
            for e in di::scan_residual_slots(reader, l, &detail.di)? {
                let Some(off) = e.data_offset else { continue };
                let Ok(region) = Region::new(off, block) else {
                    continue;
                };
                let referenced = u.data_regions.iter().any(|r| r.overlaps(&region));
                let ok = report.push(
                    cap,
                    RecoveryItem {
                        basis: RecoveryBasis::Heuristic,
                        confidence: Confidence::Tentative,
                        unit: u.unit,
                        di_entry_index: Some(e.index),
                        di_entry_offset: Some(e.offset),
                        timestamp: Some(e.timestamp.clone()),
                        sptoi: Some(e.sptoi),
                        span_basis: None,
                        regions: vec![region],
                        nonzero_probe: None,
                        description: format!(
                            "unit {} residual DI slot {} (beyond the declared count) decodes to {} and \
                             SPtoI {} -> 0x{off:X}; candidate only{}",
                            u.unit,
                            e.index,
                            e.timestamp.label(),
                            e.sptoi,
                            if referenced {
                                "; that block is also referenced by the current index, so the slot \
                                 likely predates a rewrite"
                            } else {
                                ""
                            }
                        ),
                    },
                );
                if !ok {
                    break 'units;
                }
            }
        }
    }
    if report.truncated {
        report.notes.push(format!(
            "the report stopped at the profile item cap ({cap}); remaining items were not listed"
        ));
    }
    Ok(report)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn gaps_are_the_exact_complement() {
        let r = |o, l| Region::new(o, l).unwrap();
        assert_eq!(
            gaps(r(0, 100), &[r(10, 10), r(50, 60)]),
            vec![r(0, 10), r(20, 30)]
        );
        assert_eq!(gaps(r(0, 100), &[]), vec![r(0, 100)]);
        assert_eq!(gaps(r(0, 100), &[r(0, 100)]), Vec::<Region>::new());
        assert_eq!(gaps(r(100, 10), &[r(0, 50)]), vec![r(100, 10)]);
    }
}
