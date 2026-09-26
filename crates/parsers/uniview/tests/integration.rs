//! End-to-end tests of the Uniview structure set through the public `Parser` interface and
//! the crate's extraction, recovery and report APIs, over the real versioned profile.

use evidence_reader::EvidenceReader;
use forensic_core::{OemProfile, Region, ValidationStateKind};
use parser_uniview::testing::{build, image, SparseReader};
use parser_uniview::volume::{self, RECORDING_ID_PREFIX};
use parser_uniview::{
    extract_di_entry, extract_recording, forensic_report, Confidence, DiHeaderState, Generation,
    RecoveryBasis, RecoveryOptions, SpanBasis, UniviewLayout, UniviewParser, VendorFlow,
};
use parsers_core::storage::{AllocationEvidence, IndexAuthority};
use parsers_core::Parser;
use sha2::{Digest, Sha256};

fn profile() -> OemProfile {
    let path = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../../profiles/uniview/uniview-ubifs-v1.0.toml"
    );
    OemProfile::from_file(std::path::Path::new(path)).expect("uniview profile loads")
}

fn layout() -> UniviewLayout {
    UniviewLayout::from_profile(&profile())
}

const OLD_U1: u64 = 0x0001_4000;
const NEW_U1: u64 = 0x1001_4000;
const BLOCK: u64 = 0x4000;

// ── OLD generation, end to end ──────────────────────────────────────────────────

#[test]
fn old_volume_every_stage() {
    let p = profile();
    let r = image::small_old_volume(&layout());
    let parser = UniviewParser::default();

    let fs = parser.parse_filesystem(&r, &p).unwrap();
    assert_eq!(
        fs[0].validation_state.state,
        ValidationStateKind::Pass,
        "{}",
        fs[0].validation_state.reason
    );
    assert!(fs[0].validation_state.reason.contains("OLD"));

    let md = parser.parse_metadata(&r, &p).unwrap();
    assert_eq!(
        md[0].validation_state.state,
        ValidationStateKind::Pass,
        "{}",
        md[0].validation_state.reason
    );
    assert!(md[0].validation_state.reason.contains("FLOW"));

    let vs = parser.validate_structure(&r, &p).unwrap();
    assert_eq!(
        vs[0].validation_state.state,
        ValidationStateKind::Pass,
        "{}",
        vs[0].validation_state.reason
    );

    let (recs, runs) = parser.parse_recordings(&r, &p).unwrap();
    assert_eq!(runs[0].validation_state.state, ValidationStateKind::Pass);
    assert_eq!(
        recs.len(),
        1,
        "one index group per unit with usable entries"
    );
    let rec = &recs[0];
    assert_eq!(rec.channel, 0, "channel is unknown");
    // SPtoI 16 -> 20 (4 blocks), 20 -> 25 (5 blocks), 25 terminal (1 block): merged 10 blocks.
    assert_eq!(
        rec.source_offsets,
        vec![Region::new(OLD_U1 + 16 * BLOCK, 10 * BLOCK).unwrap()]
    );
    assert_eq!(
        rec.time.recorder_native.as_ref().unwrap().iso_8601,
        "2024-05-03T10:00:00",
        "earliest DI timestamp, native digits"
    );
    assert_eq!(rec.time.timezone, forensic_core::TimeZoneState::Unknown);

    let (events, runs) = parser.extract_timeline_events(&r, &p).unwrap();
    assert_eq!(runs[0].validation_state.state, ValidationStateKind::Pass);
    assert_eq!(events.len(), 1);
    assert!(events[0].description.contains("channel unknown"));
}

#[test]
fn old_volume_geometry_and_index() {
    let p = profile();
    let r = image::small_old_volume(&layout());
    let parser = UniviewParser::default();

    let g = parser.storage_geometry(&r, &p).unwrap().expect("geometry");
    assert_eq!(g.metadata_region, Some(Region::new(0, 0x4000).unwrap()));
    assert_eq!(g.index_region, Some(Region::new(0x4000, 0x10000).unwrap()));
    assert_eq!(g.video_region.unwrap().offset, OLD_U1);
    assert_eq!(g.block_size, Some(BLOCK));
    assert_eq!(
        g.oem_fields.get("uniview.generation").map(String::as_str),
        Some("OLD")
    );
    assert!(g.oem_fields["uniview.scan.total_write_bytes"].starts_with(&(9 * 0x4000).to_string()));
    assert!(g.oem_fields["uniview.scan.total_write_bytes"].contains("NOT the vendor FLOW"));
    assert!(
        g.oem_fields["uniview.flow.vendor"].starts_with("refused"),
        "the fixture's rewrited flag is set"
    );
    assert!(g.oem_fields["uniview.ui.rewrited"].starts_with("set"));
    assert_eq!(g.oem_fields["uniview.ui.current_unit_raw"], "2");
    assert_eq!(
        g.oem_fields["uniview.ui.written_unit_count"], "1",
        "OLD: raw - 1"
    );
    assert_eq!(g.oem_fields["uniview.source"], "raw Uniview disk image");

    let ix = parser.recording_index(&r, &p).unwrap().expect("index");
    assert!(
        matches!(ix.authority, IndexAuthority::Partial { .. }),
        "never authoritative"
    );
    assert!(!ix.authority.is_authoritative());
    assert_eq!(
        ix.declared_entry_count,
        Some(3),
        "record count 4 includes the header record"
    );
    assert_eq!(ix.recordings.len(), 1);
    let e = &ix.recordings[0];
    assert_eq!(e.recording_id, format!("{RECORDING_ID_PREFIX}1"));
    assert_eq!(e.channel, None);
    assert_eq!(e.codec_hint, None);
    assert!(e.payload_regions.is_empty(), "DATA framing is unknown");
    assert_eq!(e.allocation, AllocationEvidence::Unknown);
    assert_eq!(e.start_time_unix, Some(1_714_730_400)); // 2024-05-03T10:00:00 read as UTC
    assert_eq!(e.end_time_unix, Some(1_714_730_520));
    assert_eq!(e.oem_metadata["uniview.span_basis.adjacent_sptoi"], "2");
    assert_eq!(e.oem_metadata["uniview.span_basis.terminal_entry"], "1");
    assert_eq!(e.oem_metadata["uniview.di.record_count_raw"], "4");
    assert_eq!(
        e.oem_metadata["uniview.unit_time_index.offset"], "0x4010",
        "OLD unit 1 at UI + 2*8"
    );
    assert!(e.oem_metadata["uniview.unit_time_index.lock"].starts_with("11 "));
    assert!(
        ix.unreferenced_recordings.is_empty(),
        "heuristic residue never enters the index"
    );
}

#[test]
fn old_volume_raw_extraction_is_exact_and_hashed() {
    let l = layout();
    let r = image::small_old_volume(&l);
    let vol = volume::read_volume(&r, &profile()).unwrap();

    let x = extract_recording(&r, &vol, "unv:u1")
        .unwrap()
        .expect("extracts");
    assert_eq!(x.bytes.len() as u64, 10 * BLOCK);
    assert_eq!(
        &x.bytes[..BLOCK as usize],
        build::data_block(0x16).as_slice()
    );
    assert_eq!(
        &x.bytes[(4 * BLOCK) as usize..(5 * BLOCK) as usize],
        build::data_block(0x20).as_slice()
    );
    assert_eq!(x.sha256, hex::encode(Sha256::digest(&x.bytes)));
    assert!(x.content_note.contains("UNKNOWN"));

    // Records 1..3 carry SPtoI 16, 20, 25; record 3 is the terminal entry.
    let one = extract_di_entry(&r, &vol, 1, 3).unwrap().expect("entry 3");
    assert_eq!(
        one.regions,
        vec![Region::new(OLD_U1 + 25 * BLOCK, BLOCK).unwrap()]
    );
    assert_eq!(one.bytes, build::data_block(0x25));

    assert!(extract_recording(&r, &vol, "unv:u9").unwrap().is_none());
    assert!(extract_recording(&r, &vol, "hikclip:b1").unwrap().is_none());
    assert!(extract_di_entry(&r, &vol, 1, 99).unwrap().is_none());
}

#[test]
fn old_volume_recovery_separates_indexed_structural_and_heuristic() {
    let r = image::small_old_volume(&layout());
    let vol = volume::read_volume(&r, &profile()).unwrap();
    let rep = parser_uniview::recovery::build_recovery_report(&r, &vol, RecoveryOptions::default())
        .unwrap();

    let indexed: Vec<_> = rep.of_basis(RecoveryBasis::Indexed).collect();
    assert_eq!(indexed.len(), 3);
    assert_eq!(
        indexed[0].confidence,
        Confidence::StrongInference,
        "multi-block extent is inferred"
    );
    assert_eq!(indexed[2].span_basis, Some(SpanBasis::TerminalEntry));
    assert_eq!(
        indexed[2].confidence,
        Confidence::Confirmed,
        "the selected block itself is confirmed"
    );

    // DATA after the indexed range (blocks 26..80, the end of the image) is unreferenced, and
    // its content is not asserted. Block 50 carries data, but the range's first block is zero.
    let structural: Vec<_> = rep.of_basis(RecoveryBasis::Structural).collect();
    assert_eq!(structural.len(), 1);
    assert_eq!(
        structural[0].regions,
        vec![Region::new(OLD_U1 + 26 * BLOCK, 54 * BLOCK).unwrap()]
    );
    assert_eq!(structural[0].confidence, Confidence::Unknown);
    assert_eq!(structural[0].nonzero_probe, Some(false));
    assert!(!structural[0].description.contains("deleted"));

    let heuristic: Vec<_> = rep.of_basis(RecoveryBasis::Heuristic).collect();
    assert_eq!(
        heuristic.len(),
        1,
        "the residual slot beyond the declared count"
    );
    assert_eq!(heuristic[0].sptoi, Some(40));
    assert_eq!(
        heuristic[0].di_entry_index,
        Some(4),
        "record 4 lies beyond the record count of 4"
    );
    assert_eq!(heuristic[0].confidence, Confidence::Tentative);
    assert!(rep.notes.iter().any(|n| n.contains("rewrited flag is set")));
}

#[test]
fn old_volume_report_serialises_with_field_evidence_and_limitations() {
    let r = image::small_old_volume(&layout());
    let rep = forensic_report(&r, &profile(), RecoveryOptions::default()).unwrap();
    assert_eq!(rep.generation, Some(Generation::Old));
    let magic = rep
        .super_fields
        .iter()
        .find(|f| f.name == "super.magic")
        .unwrap();
    assert_eq!(
        (magic.physical_offset, magic.raw_value, magic.confidence),
        (0, Some(0x1367), Confidence::Confirmed)
    );
    assert!(rep
        .ui_fields
        .iter()
        .any(|f| f.name == "ui.field_04" && f.confidence == Confidence::Unknown));
    assert_eq!(rep.units.len(), 1);
    assert!(rep.units[0]
        .di_header_fields
        .iter()
        .any(|f| f.name == "di.header_08_0f" && f.confidence == Confidence::Unknown));
    assert_eq!(rep.scan_total_write_bytes, 9 * 0x4000);
    assert_eq!(
        rep.vendor_flow,
        VendorFlow::RefusedRewrited { rewrited_raw: 1 }
    );
    let ti = rep.units[0]
        .time_index
        .as_ref()
        .expect("unit 1 time-index entry");
    assert_eq!((ti.offset, ti.lock), (0x4010, 11));
    assert!(rep.units[0]
        .time_index_fields
        .iter()
        .any(|f| f.name == "unit.time_index.lock" && f.confidence == Confidence::Unknown));
    assert!(rep.index_authority.starts_with("PARTIAL"));
    assert!(rep.known_limitations.iter().any(|l| l.contains("lock")));
    assert!(rep.known_limitations.iter().any(|l| l.contains("field A")));
    let json = serde_json::to_string(&rep).unwrap();
    assert!(json.contains("\"confidence\":\"unknown\""));
}

// ── NEW generation, end to end ──────────────────────────────────────────────────

#[test]
fn new_volume_every_stage_geometry_and_index() {
    let p = profile();
    let l = layout();
    let r = image::new_volume(&l);
    let parser = UniviewParser::default();

    let fs = parser.parse_filesystem(&r, &p).unwrap();
    assert_eq!(
        fs[0].validation_state.state,
        ValidationStateKind::Pass,
        "{}",
        fs[0].validation_state.reason
    );
    assert!(fs[0].validation_state.reason.contains("NEW"));

    let vol = volume::read_volume(&r, &p).unwrap();
    assert_eq!(vol.generation(), Some(Generation::New));
    assert_eq!(vol.units.len(), 2);
    assert_eq!(vol.units[0].unit_base, NEW_U1);
    assert_eq!(vol.units[1].unit_base, NEW_U1 + 0x1000_0000);
    let ui = vol.ui.as_ref().unwrap();
    assert_eq!(ui.region_name(), "UI-CTL");
    assert_eq!(ui.current_unit_raw(), Some(1));
    assert_eq!(ui.unit_count(&l), Some(2), "NEW: raw + 1");
    // Storage unit u's time-index entry is UI-DATA global index u - 1.
    let t1 = vol.units[0].time_index.as_ref().unwrap();
    let t2 = vol.units[1].time_index.as_ref().unwrap();
    assert_eq!((t1.offset, t1.index, t1.lock), (0x14000, 0, 100));
    assert_eq!((t2.offset, t2.index, t2.lock), (0x14008, 1, 200));
    let ud = vol.ui_data.as_ref().unwrap();
    assert_eq!(ud.populated_units.len(), 2);
    assert_eq!(ud.populated_units[1].offset, 0x14000 + 0x10000);
    assert_eq!(ud.populated_units[1].summary.lock_min, Some(101));
    assert_eq!(vol.scan_total_write_bytes(), 21 * 0x4000);
    assert_eq!(
        vol.vendor_flow(),
        VendorFlow::Computed {
            unit_count: 2,
            total_bytes: 21 * 0x4000
        }
    );

    let ix = parser.recording_index(&r, &p).unwrap().unwrap();
    assert_eq!(ix.recordings.len(), 2);
    // SPtoI 16 -> 26 -> 36 (terminal): 10 + 10 + 1 blocks, merged.
    assert_eq!(
        ix.recordings[0].physical_regions,
        vec![Region::new(NEW_U1 + 16 * BLOCK, 21 * BLOCK).unwrap()]
    );
    assert_eq!(
        ix.recordings[1].physical_regions,
        vec![Region::new(NEW_U1 + 0x1000_0000 + 16 * BLOCK, BLOCK).unwrap()]
    );

    let (recs, _) = parser.parse_recordings(&r, &p).unwrap();
    assert_eq!(recs.len(), 2);
    let md = parser.parse_metadata(&r, &p).unwrap();
    assert!(md[0].validation_state.reason.contains("UI-DATA"));

    let x = extract_recording(&r, &vol, "unv:u2").unwrap().unwrap();
    assert_eq!(x.bytes, build::data_block(4));
    assert_eq!(x.regions[0].offset, NEW_U1 + 0x1000_0000 + 16 * BLOCK);
}

#[test]
fn the_same_di_bytes_resolve_to_generation_specific_data_offsets() {
    let l = layout();
    let entry = build::di_entry(build::timestamp(2024, 1, 1, 0, 0, 0), 0, 100, [0; 8]);
    for (magic, gen, base) in [
        (0x1367u32, Generation::Old, OLD_U1),
        (0x1587u32, Generation::New, NEW_U1),
    ] {
        let len = base + 0x1000_0000;
        let mut r = SparseReader::new(len).with(0, &image::super_for(magic));
        image::place_unit(&mut r, &l, gen, &image::UnitSpec::new(1, 1, vec![entry]));
        let mut p = profile();
        p.layout.insert("uniview_ui_data_scan_max_units".into(), 4);
        let vol = volume::read_volume(&r, &p).unwrap();
        assert_eq!(
            vol.units[0].data_regions,
            vec![Region::new(base + 100 * BLOCK, BLOCK).unwrap()]
        );
    }
}

// ── Corruption and truncation ───────────────────────────────────────────────────

#[test]
fn corrupted_and_truncated_structures_never_panic_and_are_reported() {
    let p = profile();
    let l = layout();
    let parser = UniviewParser::default();

    let run_all = |r: &SparseReader| {
        parser.validate_structure(r, &p).unwrap();
        parser.parse_filesystem(r, &p).unwrap();
        parser.parse_metadata(r, &p).unwrap();
        parser.parse_recordings(r, &p).unwrap();
        parser.extract_timeline_events(r, &p).unwrap();
        parser.storage_geometry(r, &p).unwrap();
        parser.recording_index(r, &p).unwrap();
        forensic_report(r, &p, RecoveryOptions::default()).unwrap()
    };

    // Truncated SUPER.
    let full = image::super_for(0x1367);
    let r = SparseReader::new(0x200).with(0, &full[..0x200]);
    let rep = run_all(&r);
    assert!(rep.super_recognition.contains("only 512 byte(s)"));
    assert_eq!(
        parser.parse_filesystem(&r, &p).unwrap()[0]
            .validation_state
            .state,
        ValidationStateKind::Review
    );

    // Image ends inside UI.
    let r = SparseReader::new(0x4008).with(0, &full);
    run_all(&r);
    assert_eq!(
        parser.parse_filesystem(&r, &p).unwrap()[0]
            .validation_state
            .state,
        ValidationStateKind::Review
    );

    // Invalid DI count, invalid SPtoI, malformed timestamps, garbage EcPortId.
    let mut sb = build::super_block(0x1367, Some([0xFF; 5]), Some([0xEE; 5]), Some([0xFF; 64]));
    sb[0x100] = 0xAB;
    let len = OLD_U1 + 0x1000_0000 + 0x40000 + 64 * BLOCK;
    let mut r = SparseReader::new(len).with(0, &sb);
    r.place(0x4000, &build::old_ui(0xFFFF_FFFF, 0, 0, &[(1, [0xFF; 8])]));
    image::place_unit(
        &mut r,
        &l,
        Generation::Old,
        &image::UnitSpec::new(
            1,
            0,
            vec![build::di_entry(
                build::timestamp(2024, 1, 1, 0, 0, 0),
                0,
                16,
                [0; 8],
            )],
        )
        .with_declared_count(0x7FFF_FFFF),
    );
    image::place_unit(
        &mut r,
        &l,
        Generation::Old,
        &image::UnitSpec::new(
            2,
            5,
            vec![
                build::di_entry([0xFF; 5], 0, 20, [0; 8]),
                build::di_entry(build::timestamp(2024, 1, 1, 0, 0, 0), 0, 3, [0; 8]),
                build::di_entry(build::timestamp(2024, 1, 1, 0, 0, 1), 0, 0x3FFF, [0; 8]),
                [0; 16],
            ],
        ),
    );
    let rep = run_all(&r);
    let vol = volume::read_volume(&r, &p).unwrap();
    assert!(matches!(
        vol.units[0].header_state,
        DiHeaderState::CountAbnormal { .. }
    ));
    assert_eq!(
        vol.units[0].usable_entries, 1,
        "an abnormal count is reported and parsing continues"
    );
    assert_eq!(vol.units[1].invalid_timestamps, 1, "the 0xFF.. time");
    assert_eq!(
        vol.units[1].blank_entries, 1,
        "a blank slot inside the declared count"
    );
    assert_eq!(vol.units[1].sptoi_into_di, 1);
    assert_eq!(vol.units[1].sptoi_outside_image, 1);
    assert_eq!(vol.units[1].usable_entries, 0);
    assert_eq!(vol.units.len(), 2, "the image ends 64 blocks into unit 2");
    assert_eq!(
        vol.scan_total_write_bytes(),
        5,
        "the scan statistic skips a unit whose count is abnormal"
    );
    assert_eq!(
        vol.vendor_flow(),
        VendorFlow::ReadFailure {
            unit_count: 0xFFFF_FFFE,
            first_unreadable_unit: 3,
            partial_total_bytes: 5
        },
        "disktool would stop at the first declared unit with no DI in the image"
    );
    assert!(rep.current_unit_consistency.unwrap().contains("outside"));
    assert_eq!(
        parser.validate_structure(&r, &p).unwrap()[0]
            .validation_state
            .state,
        ValidationStateKind::Review
    );
    let (recs, runs) = parser.parse_recordings(&r, &p).unwrap();
    assert_eq!(recs.len(), 1, "unit 1's decodable entry is still reported");
    assert_eq!(runs[0].validation_state.state, ValidationStateKind::Review);
    let ix = parser.recording_index(&r, &p).unwrap().unwrap();
    assert_eq!(ix.recordings.len(), 1);
    assert_eq!(ix.recordings[0].evidence.state, ValidationStateKind::Review);
    assert!(parser.validate_structure(&r, &p).unwrap()[0]
        .validation_state
        .reason
        .contains("data index head abnormal"));

    // Unknown magic: nothing asserted.
    let r = SparseReader::new(0x100000).with(0, &build::super_block(0x5649_4E55, None, None, None));
    let rep = run_all(&r);
    assert_eq!(rep.generation, None);
    assert!(rep.recovery.is_none());
}

#[test]
fn every_read_is_bounded_on_a_single_byte_image() {
    let p = profile();
    for len in [
        0u64, 1, 4, 0x3FFF, 0x4000, 0x4001, 0x13FFF, 0x14000, 0x14001,
    ] {
        let r = SparseReader::new(len).with(0, &image::super_for(0x1587));
        let rep = forensic_report(&r, &p, RecoveryOptions::default()).unwrap();
        assert!(!rep.known_limitations.is_empty(), "len {len}");
        assert_eq!(r.len(), len);
    }
}

// ── Vendor FLOW ─────────────────────────────────────────────────────────────────

/// An OLD image with three units whose DI write counters are given, and a UI declaring
/// `raw_current_unit` with the given rewrited flag.
fn flow_image(raw_current_unit: u32, rewrited: u16, writes: [u32; 3]) -> SparseReader {
    let l = layout();
    let len = OLD_U1 + 2 * 0x1000_0000 + 0x40000;
    let mut r = SparseReader::new(len).with(0, &image::super_for(0x1367));
    r.place(0x4000, &build::old_ui(raw_current_unit, 0, rewrited, &[]));
    for (i, w) in writes.iter().enumerate() {
        image::place_unit(
            &mut r,
            &l,
            Generation::Old,
            &image::UnitSpec::new(i as u32 + 1, *w, vec![]),
        );
    }
    r
}

#[test]
fn vendor_flow_matches_disktool_and_the_scan_statistic_stays_separate() {
    let p = profile();
    // OLD raw 3 -> units 1..=2; unit 3 is in the image but not declared.
    let vol = volume::read_volume(&flow_image(3, 0, [0x100, 0x200, 0x400]), &p).unwrap();
    assert_eq!(vol.units.len(), 3);
    assert_eq!(
        vol.vendor_flow(),
        VendorFlow::Computed {
            unit_count: 2,
            total_bytes: 0x300
        }
    );
    assert_eq!(
        vol.scan_total_write_bytes(),
        0x700,
        "the scan covers every unit in the image"
    );

    // disktool sign-extends the 32-bit counter.
    let vol = volume::read_volume(&flow_image(3, 0, [0x100, 0xFFFF_FFFF, 0]), &p).unwrap();
    assert_eq!(
        vol.vendor_flow(),
        VendorFlow::Computed {
            unit_count: 2,
            total_bytes: 0xFF
        }
    );
    assert_eq!(vol.scan_total_write_bytes(), 0x100 + 0xFFFF_FFFF);

    // Refused whenever the rewrited flag is non-zero.
    for flag in [1u16, 2, 0x100] {
        let vol = volume::read_volume(&flow_image(3, flag, [1, 2, 4]), &p).unwrap();
        assert_eq!(
            vol.vendor_flow(),
            VendorFlow::RefusedRewrited { rewrited_raw: flag }
        );
        assert_eq!(
            vol.scan_total_write_bytes(),
            7,
            "the scan statistic is still available"
        );
    }

    // A declared unit missing from the image stops the vendor computation.
    let vol = volume::read_volume(&flow_image(10, 0, [1, 2, 4]), &p).unwrap();
    assert_eq!(
        vol.vendor_flow(),
        VendorFlow::ReadFailure {
            unit_count: 9,
            first_unreadable_unit: 4,
            partial_total_bytes: 7
        }
    );

    // OLD raw 1 -> zero written units; raw 0 -> -1, reported and summing nothing.
    let vol = volume::read_volume(&flow_image(1, 0, [1, 2, 4]), &p).unwrap();
    assert_eq!(
        vol.vendor_flow(),
        VendorFlow::Computed {
            unit_count: 0,
            total_bytes: 0
        }
    );
    let vol = volume::read_volume(&flow_image(0, 0, [1, 2, 4]), &p).unwrap();
    assert_eq!(
        vol.vendor_flow(),
        VendorFlow::Computed {
            unit_count: -1,
            total_bytes: 0
        }
    );
}

// ── disktool .h3crd export ──────────────────────────────────────────────────────

#[test]
fn a_disktool_h3crd_export_is_parsed_as_an_old_shaped_single_unit_artifact() {
    let p = profile();
    let unit_entry = build::time_index_entry(build::timestamp(2024, 7, 1, 9, 0, 0), 77);
    // Original SPtoI 100, 104, 110 with the end boundary at 115: 15 blocks copied, re-based
    // to SPtoI 16, 20, 26 in the export.
    let r = image::h3crd_export(unit_entry, &[100, 104, 110], 115);
    assert_eq!(r.len(), 0x54000 + 15 * BLOCK);
    let parser = UniviewParser::default();

    let fs = parser.parse_filesystem(&r, &p).unwrap();
    assert_eq!(
        fs[0].validation_state.state,
        ValidationStateKind::Pass,
        "{}",
        fs[0].validation_state.reason
    );
    assert!(fs[0].validation_state.reason.contains(".h3crd"));

    let vol = volume::read_volume(&r, &p).unwrap();
    assert!(vol.is_h3crd_export());
    assert_eq!(vol.generation(), Some(Generation::Old));
    assert_eq!(vol.units.len(), 1);
    let u = &vol.units[0];
    assert_eq!(u.unit_base, OLD_U1);
    assert_eq!(
        u.header.as_ref().unwrap().entry_count,
        3,
        "an export's count is the copied entries"
    );
    assert_eq!(u.usable_entries, 3);
    // 16 -> 20 (4), 20 -> 26 (6), 26 -> end of the copied DATA (5): exactly the 15 blocks.
    assert_eq!(
        u.data_regions,
        vec![Region::new(0x54000, 15 * BLOCK).unwrap()]
    );
    assert_eq!(u.span_basis_counts.get("export_data_end"), Some(&1));
    let ti = u.time_index.as_ref().unwrap();
    assert_eq!((ti.offset, ti.lock), (0x4010, 77));

    let x = extract_recording(&r, &vol, "unv:u1").unwrap().unwrap();
    assert_eq!(x.bytes.len() as u64, 15 * BLOCK);
    assert_eq!(
        &x.bytes[..BLOCK as usize],
        build::data_block(0x80).as_slice()
    );

    let summary = volume::volume_summary(&vol);
    assert!(summary["uniview.source"].contains(".h3crd"));
    assert!(
        !summary.contains_key("uniview.super.magic"),
        "an export has no SUPER magic"
    );
    assert_eq!(
        vol.vendor_flow(),
        VendorFlow::Computed {
            unit_count: 1,
            total_bytes: 0
        }
    );

    let ix = parser.recording_index(&r, &p).unwrap().unwrap();
    assert!(
        ix.recordings[0].oem_metadata["uniview.source"].contains("not an original physical disk")
    );
    let rep = forensic_report(&r, &p, RecoveryOptions::default()).unwrap();
    assert!(rep.source_kind.contains(".h3crd"));
    assert_eq!(rep.super_fields[0].name, "h3crd.header_tag");
    assert_eq!(
        rep.recovery.unwrap().structural,
        0,
        "all copied DATA is referenced"
    );
}

#[test]
fn a_truncated_h3crd_export_never_panics() {
    let p = profile();
    let full = image::h3crd_export([0; 8], &[100, 101], 102);
    let bytes = full.materialize();
    for len in [
        0x13u64, 0x68, 0x4000, 0x4010, 0x14000, 0x14010, 0x14020, 0x54000,
    ] {
        let r = SparseReader::new(len).with(0, &bytes[..len as usize]);
        let rep = forensic_report(&r, &p, RecoveryOptions::default()).unwrap();
        assert!(rep.source_kind.contains(".h3crd"), "len {len}");
    }
}
