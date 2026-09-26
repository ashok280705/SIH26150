//! # Dahua DHFS 4.1 through the production recovery engine
//!
//! Drives the **real production recovery entry point** (`RecoveryEngine::execute_recovery`) with
//! the **real Dahua parser** and the **real versioned profile loaded from `profiles/`**, over a
//! format-accurate synthetic DHFS 4.1 image. Nothing is mocked:
//!
//! ```text
//!   DHFS 4.1 image (format-accurate fixture)
//!        ↓  DahuaParser::storage_geometry   — partition table → partition info → geometry
//!        ↓  DahuaParser::recording_index    — block tables → chains → accessible + available
//!        ↓  claims::build_claim_map         — RangeSet claimed / available / unclaimed
//!        ↓  plan::plan_recovery             — bounded probes and sweeps
//!        ↓  levels::scan_target_all         — OEM structural carve, many records per target
//!        ↓  classification::classify_region_state
//!        ↓  Active / Orphaned / Unindexed
//! ```
//!
//! ## What the fixture represents
//!
//! A single-partition XVR volume with:
//!
//! * a **two-block** channel-1 recording (blocks 1 → 2), the tail partially filled;
//! * a one-block channel-2 recording (block 3) carrying its own DHII frame index;
//! * block 4: occupied, fully described by the block table, but reachable from no first block —
//!   the *available* case, which is an orphan finding and **not** a deletion finding;
//! * blocks 0 and 5: unused slots, which are not deletion markers either;
//! * one DHAV frame in slack past the partition's video region — unindexed video.
//!
//! Every offset asserted on is read back from the fixture's own reported layout, so the test
//! checks the layout that was actually built rather than copied constants.
//!
//! The fixture is synthetic. It proves the parser reads these structures; it does not prove
//! compatibility with any particular Dahua firmware.

use evidence_reader::{EvidenceReader, RawReader};
use forensic_core::{
    CancelToken, DataState, EvidenceId, ProfileRegistry, RecoveryBounds, RecoveryLevel,
    RecoveryStatus, Region, ValidationStateKind,
};
use forensic_tests::dahua_fixtures::{self as fx, realistic};
use parsers_core::Parser;
use recovery::{RecoveryEngine, RecoveryRequest};
use std::path::{Path, PathBuf};

fn profiles_dir() -> PathBuf {
    for p in ["profiles", "../profiles", "../../profiles"] {
        if Path::new(p).exists() {
            return PathBuf::from(p);
        }
    }
    panic!("could not locate profiles/");
}

fn registry() -> ProfileRegistry {
    ProfileRegistry::load_from_dir(&profiles_dir()).expect("profiles load")
}

fn bounds() -> RecoveryBounds {
    RecoveryBounds {
        max_scan_bytes: u64::MAX,
        max_scan_regions: u32::MAX,
        max_candidates: u32::MAX,
        max_hypotheses: 1024,
        max_search_depth: None,
        cancel: CancelToken::new(),
        time_limit: None,
    }
}

/// The fixture written to a real file, opened through the production read-only reader.
struct Fixture {
    image: fx::DhfsImage,
    reader: RawReader,
    _dir: tempfile::TempDir,
}

fn fixture() -> Fixture {
    let image = fx::realistic_xvr_volume();
    let dir = tempfile::tempdir().expect("temp dir");
    let path = image
        .write_to_dir(dir.path(), "dahua_dhfs41.raw")
        .expect("write fixture");
    let reader = RawReader::open(path.to_str().unwrap()).expect("evidence opens read-only");
    Fixture {
        image,
        reader,
        _dir: dir,
    }
}

fn region_of(image: &fx::DhfsImage, block: u32) -> Region {
    let p = image.partition(0).expect("partition 0");
    let b = p.block(block).expect("block");
    Region::new(b.offset, b.claimed_length.expect("a claimed length")).unwrap()
}

fn run(f: &Fixture, evidence_id: EvidenceId) -> recovery::RecoveryOutcome {
    let reg = registry();
    let profile = reg
        .find_applicable("dahua", None, None, None)
        .expect("profile");
    let orchestrator = parsing::ParsingOrchestrator::new();
    let parser = orchestrator
        .parser_for("dahua")
        .expect("registered Dahua parser");
    RecoveryEngine::new()
        .execute_recovery(RecoveryRequest {
            evidence_id,
            reader: &f.reader,
            profile,
            oem_key: "dahua",
            parser,
            bounds: &bounds(),
            scan_window: None,
            read_window_bytes: None,
        })
        .expect("recovery runs")
}

// ── Geometry ───────────────────────────────────────────────────────────────────

#[test]
fn geometry_is_derived_from_the_partition_table_not_from_superblock_fields() {
    let f = fixture();
    let reg = registry();
    let profile = reg.find_applicable("dahua", None, None, None).unwrap();
    let parser = parser_dahua::DahuaParser::default();

    let g = parser
        .storage_geometry(&f.reader, profile)
        .unwrap()
        .expect("DHFS 4.1 geometry");
    let p = f.image.partition(0).unwrap();

    assert_eq!(g.physical_size, f.reader.len());
    assert_eq!(g.sector_size, Some(fx::SECTOR));
    assert_eq!(g.block_size, Some(fx::VIDEO_BLOCK));
    assert_eq!(
        g.index_region.map(|r| r.offset),
        Some(p.block_table_offset),
        "the block table is located through IndexStartSector, not a fixed superblock field"
    );
    assert_eq!(
        g.video_region.map(|r| r.offset),
        Some(p.video_base),
        "the video region is located through VideoStartSector"
    );
    assert_eq!(
        g.video_region.map(|r| r.length),
        Some(p.blocks.len() as u64 * fx::VIDEO_BLOCK)
    );
    assert_eq!(g.evidence.state, ValidationStateKind::Pass);
    // Per-partition geometry survives the collapse into one span.
    assert_eq!(
        g.oem_fields.get("dhfs_variant").map(|s| s.as_str()),
        Some("DHFS4.1")
    );
    assert_eq!(
        g.oem_fields.get("partition_count").map(|s| s.as_str()),
        Some("1")
    );
    assert_eq!(
        g.oem_fields
            .get("secondary_partition_table_present")
            .map(|s| s.as_str()),
        Some("false")
    );
    // No wrap evidence exists in a DHFS 4.1 block table, so none is claimed.
    assert_eq!(
        g.circular_buffer,
        parsers_core::storage::CircularBufferEvidence::Unknown
    );
}

// ── The recording index ────────────────────────────────────────────────────────

#[test]
fn block_chains_become_accessible_and_available_recording_sets() {
    let f = fixture();
    let reg = registry();
    let profile = reg.find_applicable("dahua", None, None, None).unwrap();
    let parser = parser_dahua::DahuaParser::default();

    let index = parser
        .recording_index(&f.reader, profile)
        .unwrap()
        .expect("recording index");

    assert!(
        index.authority.is_authoritative(),
        "a completely read block table is a complete statement about its partition: {}",
        index.evidence.reason
    );

    let accessible: Vec<&str> = index
        .recordings
        .iter()
        .map(|r| r.recording_id.as_str())
        .collect();
    assert_eq!(
        accessible,
        vec![realistic::CH1_CHAIN_ID, realistic::CH2_CHAIN_ID],
        "only chains traversed from a declared first block are accessible"
    );
    let available: Vec<&str> = index
        .unreferenced_recordings
        .iter()
        .map(|r| r.recording_id.as_str())
        .collect();
    assert_eq!(available, vec![realistic::AVAILABLE_CHAIN_ID]);

    // The multi-block recording claims both of its blocks, in chain order.
    let ch1 = &index.recordings[0];
    assert_eq!(ch1.partition, Some(0));
    assert_eq!(ch1.channel, Some(1));
    assert_eq!(
        ch1.physical_regions,
        vec![
            region_of(&f.image, realistic::CH1_HEAD_BLOCK),
            region_of(&f.image, realistic::CH1_TAIL_BLOCK)
        ],
        "a Dahua recording is a chain of blocks, not one contiguous range"
    );
    assert_eq!(
        ch1.oem_metadata
            .get("dahua_block_numbers")
            .map(|s| s.as_str()),
        Some("1,2")
    );
    assert_eq!(
        ch1.oem_metadata
            .get("dahua_chain_validity")
            .map(|s| s.as_str()),
        Some("complete")
    );
    // The recorder's own clock reached the entry, decoded rather than assumed.
    assert!(ch1.start_time_unix.is_some());
    assert!(ch1.end_time_unix.is_some());
    assert!(ch1.end_time_unix.unwrap() > ch1.start_time_unix.unwrap());
}

#[test]
fn an_unused_block_slot_is_never_reported_as_deleted() {
    let f = fixture();
    let reg = registry();
    let profile = reg.find_applicable("dahua", None, None, None).unwrap();
    let parser = parser_dahua::DahuaParser::default();
    let index = parser.recording_index(&f.reader, profile).unwrap().unwrap();

    // Neither set references the empty slots.
    let empty = region_of_block_offset(&f.image, realistic::EMPTY_BLOCK);
    for entry in index
        .recordings
        .iter()
        .chain(index.unreferenced_recordings.iter())
    {
        assert!(
            !entry.physical_regions.iter().any(|r| r.contains(empty)),
            "an unused block must not be claimed by any recording"
        );
        // And no entry anywhere asserts deallocation, because DHFS 4.1 carries no tombstone.
        assert_eq!(
            entry.allocation,
            parsers_core::storage::AllocationEvidence::Unknown
        );
        assert!(entry
            .oem_metadata
            .get("dahua_deletion_evidence")
            .unwrap()
            .contains("no deletion conclusion"));
    }
}

fn region_of_block_offset(image: &fx::DhfsImage, block: u32) -> u64 {
    image.partition(0).unwrap().block(block).unwrap().offset
}

// ── Claim algebra ──────────────────────────────────────────────────────────────

#[test]
fn claimed_available_and_unclaimed_partition_the_address_space_exactly() {
    let f = fixture();
    let outcome = run(&f, EvidenceId::new());
    let map = &outcome.plan.claim_map;

    // Per-entry claims preserve the block → range provenance exactly.
    let per_entry: Vec<Region> = map.claims.iter().map(|c| c.region).collect();
    assert_eq!(
        per_entry,
        vec![
            region_of(&f.image, realistic::CH1_HEAD_BLOCK),
            region_of(&f.image, realistic::CH1_TAIL_BLOCK),
            region_of(&f.image, realistic::CH2_BLOCK),
        ],
        "each accessible block contributes its own claim, traceable to its chain"
    );
    assert_eq!(
        map.claims
            .iter()
            .map(|c| c.recording_id.as_str())
            .collect::<Vec<_>>(),
        vec![
            realistic::CH1_CHAIN_ID,
            realistic::CH1_CHAIN_ID,
            realistic::CH2_CHAIN_ID
        ],
        "the two blocks of the multi-block recording both point at its chain"
    );
    // The canonical RangeSet merges the two physically adjacent blocks of the channel-1
    // recording, which is correct: it is a set of bytes, not a list of records.
    let head = region_of(&f.image, realistic::CH1_HEAD_BLOCK);
    let tail = region_of(&f.image, realistic::CH1_TAIL_BLOCK);
    assert_eq!(
        head.end(),
        Some(tail.offset),
        "the fixture places them adjacently"
    );
    assert_eq!(
        map.claimed.ranges(),
        &[
            Region::new(head.offset, head.length + tail.length).unwrap(),
            region_of(&f.image, realistic::CH2_BLOCK),
        ],
        "adjacent claims merge in the canonical set without double counting"
    );
    assert_eq!(
        map.claimed_bytes(),
        head.length + tail.length + region_of(&f.image, realistic::CH2_BLOCK).length
    );
    assert_eq!(
        map.available.ranges(),
        &[region_of(&f.image, realistic::AVAILABLE_BLOCK)],
        "the available range is the unreachable block's extent"
    );
    // Every byte is accounted for exactly once.
    assert_eq!(
        map.claimed_bytes() + map.available_bytes() + map.unclaimed_bytes(),
        f.reader.len()
    );
    // And the available range is not also swept as unknown space.
    let available_offset = region_of_block_offset(&f.image, realistic::AVAILABLE_BLOCK);
    assert!(map.available_at(available_offset).is_some());
    assert!(map.claim_at(available_offset).is_none());
    assert!(!map.unclaimed.contains(available_offset));
}

#[test]
fn the_plan_probes_described_ranges_and_sweeps_only_undescribed_space() {
    let f = fixture();
    let outcome = run(&f, EvidenceId::new());

    let probes = outcome
        .plan
        .targets
        .iter()
        .filter(|t| t.discovery_method == recovery::DiscoveryMethod::IndexClaimedProbe)
        .count();
    assert_eq!(probes, 3, "one probe per accessible block");

    let available_probes: Vec<&recovery::ScanTarget> = outcome
        .plan
        .targets
        .iter()
        .filter(|t| t.discovery_method == recovery::DiscoveryMethod::AvailableMetadataProbe)
        .collect();
    assert_eq!(available_probes.len(), 1);
    assert_eq!(
        available_probes[0].region.offset,
        region_of_block_offset(&f.image, realistic::AVAILABLE_BLOCK)
    );

    // The plan reads far less than the whole image, and says by how much.
    assert!(outcome.plan.planned_bytes < outcome.plan.full_scan_bytes());
    assert!(outcome.plan.bytes_avoided() > 0);
    assert!(outcome.plan.rationale.contains("available claim(s)"));
    assert_eq!(outcome.metrics.available_claim_count, 1);
    assert!(outcome.metrics.bytes_avoided_vs_full_scan > 0);
}

// ── Classification ─────────────────────────────────────────────────────────────

#[test]
fn accessible_chains_are_active_available_is_orphaned_and_slack_video_is_unindexed() {
    let f = fixture();
    let outcome = run(&f, EvidenceId::new());

    for c in &outcome.candidates {
        eprintln!(
            "  0x{:X} len {} -> {:?}/{:?} {:?}",
            c.source_offsets[0].offset,
            c.source_offsets[0].length,
            c.data_state,
            c.recovery_status,
            c.recovery_level
        );
    }

    // Active: the frames inside the accessible chains' blocks.
    let active: Vec<u64> = outcome
        .candidates
        .iter()
        .filter(|c| c.data_state == DataState::Active)
        .map(|c| c.source_offsets[0].offset)
        .collect();
    assert!(
        !active.is_empty(),
        "the accessible chains' frames must reach Active"
    );
    let p = f.image.partition(0).unwrap();
    let mut expected_active: Vec<u64> = Vec::new();
    for b in [
        realistic::CH1_HEAD_BLOCK,
        realistic::CH1_TAIL_BLOCK,
        realistic::CH2_BLOCK,
    ] {
        expected_active.extend(p.block(b).unwrap().frame_offsets.iter().copied());
    }
    expected_active.sort_unstable();
    let mut got = active.clone();
    got.sort_unstable();
    assert_eq!(
        got, expected_active,
        "every frame in every accessible block is a candidate, and only those are Active"
    );

    // Orphaned: the available block's frame, reached through the recorder's own metadata.
    let orphaned: Vec<&forensic_core::RecoveryCandidate> = outcome
        .candidates
        .iter()
        .filter(|c| c.data_state == DataState::Orphaned)
        .collect();
    assert_eq!(orphaned.len(), 1);
    assert_eq!(
        orphaned[0].source_offsets[0].offset,
        p.block(realistic::AVAILABLE_BLOCK).unwrap().frame_offsets[0]
    );
    assert_eq!(orphaned[0].recovery_level, RecoveryLevel::L2);
    assert_eq!(orphaned[0].recovery_status, RecoveryStatus::Recoverable);
    assert!(
        orphaned[0]
            .provenance
            .validation_state
            .reason
            .contains("not evidence of deletion"),
        "an orphan finding must say it is not a deletion finding: {}",
        orphaned[0].provenance.validation_state.reason
    );

    // Unindexed: the loose frame in slack past the partition's video region.
    let unindexed: Vec<u64> = outcome
        .candidates
        .iter()
        .filter(|c| c.data_state == DataState::Unindexed)
        .map(|c| c.source_offsets[0].offset)
        .collect();
    assert_eq!(unindexed, f.image.loose_frame_offsets);

    // Nothing is called deleted or overwritten without evidence for it.
    assert_eq!(
        outcome.metrics.deleted_count, 0,
        "unindexed and available data must never be reported as deleted"
    );
    assert_eq!(outcome.metrics.overwritten_count, 0);
    assert_eq!(outcome.metrics.orphaned_count, 1);
    assert!(outcome.metrics.active_count >= 4);
    assert_eq!(outcome.metrics.available_candidate_count, 1);
}

#[test]
fn the_partition_table_corroborates_detection_on_a_real_dhfs41_layout() {
    // On a real DHFS 4.1 volume the video region starts megabytes in, so a frame tag is nowhere
    // near the start of the disk. Corroboration has to come from a filesystem structure at a
    // known offset — the partition table identifier — or the volume reads as a lone magic and is
    // downgraded to Insufficient.
    let f = fixture();
    let first_frame = f
        .image
        .partition(0)
        .unwrap()
        .block(realistic::CH1_HEAD_BLOCK)
        .unwrap()
        .frame_offsets[0];
    assert!(
        first_frame > 65536,
        "the fixture's first frame is at 0x{first_frame:X}, well past any header window"
    );

    let outputs = detection::orchestrator::DetectionOrchestrator::new()
        .run(&f.reader, &registry())
        .unwrap();
    let dahua = outputs.iter().find(|o| o.oem_key == "dahua").unwrap();
    assert_eq!(
        dahua.status,
        detection::DetectionStatus::Confirmed,
        "the partition table must corroborate the volume signature: {:?}",
        dahua.warnings
    );
    assert!(
        dahua
            .evidence
            .iter()
            .any(|e| e.kind == "partition_table_identifier"),
        "the corroborating structure must be recorded as evidence"
    );
    assert!(dahua
        .evidence
        .iter()
        .any(|e| e.kind == "dhfs41_volume_signature"));

    // And it still reaches Confirmed through the confidence engine's own decision tree.
    let classified = confidence::engine::ConfidenceEngine::classify(
        &outputs,
        &registry(),
        &confidence::config::ConfidenceConfig::provisional_default(),
    )
    .unwrap();
    assert_eq!(classified.detector_output.oem_key, "dahua");
    assert_eq!(
        classified.classification,
        confidence::result::Classification::Confirmed,
        "{}",
        classified.explanation
    );
}

#[test]
fn detecting_the_oem_does_not_make_anything_active() {
    // The load-bearing separation: a volume whose block table cannot be read is still
    // recognisably Dahua, and nothing on it may be reported as an active recording.
    let mut image = fx::realistic_xvr_volume();
    // Point IndexStartSector far outside the image, so the partition verifies but its block
    // table cannot be located. The volume signature and partition table are left intact.
    let info_at = image.partition(0).unwrap().info_offset as usize;
    image.bytes[info_at + 68..info_at + 72].copy_from_slice(&0x3FFF_FFFFi32.to_le_bytes());

    let dir = tempfile::tempdir().unwrap();
    let path = image
        .write_to_dir(dir.path(), "dahua_no_table.raw")
        .unwrap();
    let reader = RawReader::open(path.to_str().unwrap()).unwrap();

    // Detection still confirms Dahua.
    let reg = registry();
    let outputs = detection::orchestrator::DetectionOrchestrator::new()
        .run(&reader, &reg)
        .unwrap();
    let dahua = outputs.iter().find(|o| o.oem_key == "dahua").unwrap();
    assert_eq!(dahua.status, detection::DetectionStatus::Confirmed);

    let profile = reg.find_applicable("dahua", None, None, None).unwrap();
    let orchestrator = parsing::ParsingOrchestrator::new();
    let parser = orchestrator.parser_for("dahua").unwrap();
    let outcome = RecoveryEngine::new()
        .execute_recovery(RecoveryRequest {
            evidence_id: EvidenceId::new(),
            reader: &reader,
            profile,
            oem_key: "dahua",
            parser,
            bounds: &bounds(),
            scan_window: None,
            read_window_bytes: None,
        })
        .unwrap();

    assert_eq!(
        outcome.metrics.active_count, 0,
        "recognising the OEM is not evidence that any region is an active recording"
    );
    assert_eq!(
        outcome.metrics.orphaned_count, 0,
        "and not evidence of orphaning either"
    );
    assert_eq!(outcome.metrics.deleted_count, 0);
    assert!(
        outcome.metrics.unindexed_count > 0,
        "the video that is physically there is reported at the conservative state"
    );
    assert!(!outcome.metrics.authoritative_index);
}

// ── Multiple candidates per scan region ────────────────────────────────────────

#[test]
fn one_scan_region_yields_every_frame_in_it_rather_than_one_candidate() {
    let f = fixture();
    let outcome = run(&f, EvidenceId::new());
    let p = f.image.partition(0).unwrap();

    // Block 1 holds two frames and is probed once. Both must appear.
    let head = p.block(realistic::CH1_HEAD_BLOCK).unwrap();
    assert_eq!(
        head.frame_offsets.len(),
        2,
        "the fixture puts two frames here"
    );
    let from_head: Vec<u64> = outcome
        .candidates
        .iter()
        .map(|c| c.source_offsets[0].offset)
        .filter(|o| head.frame_offsets.contains(o))
        .collect();
    assert_eq!(
        from_head.len(),
        2,
        "one probe of one block produced {} candidate(s); a scan region is not one recording",
        from_head.len()
    );

    // Every candidate's bounds are a DHAV record's, not a scan window's.
    let by_record = outcome
        .fragments
        .iter()
        .filter(|fr| fr.framing == recovery::FragmentFraming::OemContainerRecord)
        .count();
    assert_eq!(
        by_record,
        outcome.fragments.len(),
        "every fragment should be bounded by the OEM record that describes it"
    );
    assert_eq!(
        outcome.metrics.container_record_candidate_count,
        outcome.candidates.len()
    );

    // A fragment's physical length is the frame's declared length, not the probe length.
    for fr in &outcome.fragments {
        assert!(
            fr.physical_region.length < recovery::CLAIM_PROBE_BYTES,
            "a fragment must describe its record ({} bytes), not the whole probe",
            fr.physical_region.length
        );
        assert!(
            fr.payload_region.is_some(),
            "payload separated from framing"
        );
        let payload = fr.payload_region.unwrap();
        assert!(
            payload.offset > fr.physical_region.offset
                && payload.end().unwrap() < fr.physical_region.end().unwrap(),
            "the payload must sit strictly inside the record's framing"
        );
    }
}

// ── Forensic provenance ────────────────────────────────────────────────────────

#[test]
fn every_candidate_traces_back_to_the_callers_evidence_item_and_exact_offsets() {
    let f = fixture();
    let evidence_id = EvidenceId::new();
    let outcome = run(&f, evidence_id);

    assert!(!outcome.candidates.is_empty());
    for (c, fr) in outcome.candidates.iter().zip(outcome.fragments.iter()) {
        assert_eq!(
            c.provenance.source_evidence_id, evidence_id,
            "the engine must never mint an evidence id"
        );
        assert_eq!(fr.evidence_id, evidence_id);
        assert!(c
            .provenance
            .source_regions
            .iter()
            .all(|sr| sr.evidence_id == evidence_id));
        // The candidate's offsets and the fragment's agree, and both are absolute.
        assert_eq!(c.source_offsets, vec![fr.physical_region]);
        assert!(fr.physical_region.offset > 0);
        assert!(fr.physical_region.end().unwrap() <= f.reader.len());
        // The fragment id is derived from those exact inputs, so it is reproducible.
        assert!(
            fr.id_is_consistent(),
            "fragment id {} does not match its own evidence id and range",
            fr.fragment_id
        );
        // Real digests, never a zero-filled placeholder.
        assert_ne!(
            c.provenance.output_hash,
            forensic_core::Hash::sha256(vec![0; 32])
        );
        assert_eq!(
            c.provenance.parser_version.as_deref(),
            Some("dahua-dhfs-parser@2.0.0")
        );
        assert!(c.provenance.profile_hash.is_some());
    }

    // Fragment ids are unique per fragment.
    let ids: std::collections::BTreeSet<&str> = outcome
        .fragments
        .iter()
        .map(|fr| fr.fragment_id.as_str())
        .collect();
    assert_eq!(ids.len(), outcome.fragments.len());
}

#[test]
fn recorder_metadata_is_known_only_where_evidence_supplied_it() {
    let f = fixture();
    let outcome = run(&f, EvidenceId::new());
    let p = f.image.partition(0).unwrap();

    for fr in &outcome.fragments {
        let in_partition = p
            .blocks
            .iter()
            .any(|b| b.frame_offsets.contains(&fr.physical_region.offset));
        if in_partition {
            // Inside a described block: the block table supplied channel, partition, times and
            // the parent chain.
            assert!(fr.camera_id.is_known(), "channel from block-table metadata");
            assert_eq!(fr.partition.value(), Some(&0));
            assert!(fr.timestamp_unix.is_known());
            assert!(
                fr.parent_recording.is_known(),
                "a fragment inside a chain knows which recording it belongs to"
            );
            assert!(fr
                .parent_recording
                .value()
                .unwrap()
                .starts_with("dahua:p0:blk"));
        } else {
            // In slack: no OEM metadata describes these bytes, so no chain and no partition.
            assert!(!fr.parent_recording.is_known());
            assert!(!fr.partition.is_known());
            // The frame's own header still carries a channel and a clock, and that is read
            // evidence rather than an invention.
            assert!(
                fr.camera_id.is_known(),
                "a carved DHAV frame's own header supplies its channel"
            );
            assert!(fr.timestamp_unix.is_known());
        }
        // Confidence is always explained, never a bare number.
        assert!(fr.confidence.is_known());
        let basis = match &fr.confidence {
            recovery::FieldEvidence::Known { source, .. } => source.clone(),
            recovery::FieldEvidence::Unknown { reason } => reason.clone(),
        };
        assert!(
            basis.contains('+'),
            "confidence must list its components: {basis}"
        );
    }
}

#[test]
fn oem_specific_evidence_survives_the_generic_layer() {
    let f = fixture();
    let outcome = run(&f, EvidenceId::new());
    let fr = outcome
        .fragments
        .iter()
        .find(|fr| fr.discovery_method == recovery::DiscoveryMethod::IndexClaimedProbe)
        .expect("an index-claimed fragment");

    // Dahua facts the generic engine never interprets, but never discards either.
    assert_eq!(
        fr.oem_metadata.get("dhav_frame_kind").map(|s| s.as_str()),
        Some("video-key-frame")
    );
    assert!(fr.oem_metadata.contains_key("dahua_timestamp_raw"));
    assert!(fr.oem_metadata.contains_key("dahua_channel_evidence"));
    assert!(fr.oem_metadata.contains_key("dhav_declared_total_length"));
    assert_eq!(
        fr.oem_metadata
            .get("dhav_trailer_tag_verified")
            .map(|s| s.as_str()),
        Some("true")
    );
    assert!(fr.oem_metadata.contains_key("dhav_resolution"));
    assert_eq!(
        fr.oem_metadata
            .get("oem_declared_codec")
            .map(|s| s.as_str()),
        Some("H.264")
    );
}

// ── A secondary partition table downgrades the whole accessible set ────────────

#[test]
fn a_secondary_partition_table_turns_every_recording_available_not_deleted() {
    // Same volume, plus a second partition table: the partitioning has changed, so the block
    // metadata can no longer be treated as the recorder's current accessible set.
    let base = fx::realistic_xvr_volume();
    let mut image = base.clone();
    let table = fx::build_partition_table(fx::PARTITION_ID_GEN0, &[(1, 128)]);
    let at = fx::PARTITION_TABLE_SECONDARY_A as usize;
    image.bytes[at..at + table.len()].copy_from_slice(&table);

    let dir = tempfile::tempdir().unwrap();
    let path = image
        .write_to_dir(dir.path(), "dahua_repartitioned.raw")
        .unwrap();
    let reader = RawReader::open(path.to_str().unwrap()).unwrap();

    let reg = registry();
    let profile = reg.find_applicable("dahua", None, None, None).unwrap();
    let parser = parser_dahua::DahuaParser::default();
    let index = parser.recording_index(&reader, profile).unwrap().unwrap();

    assert!(
        index.recordings.is_empty(),
        "nothing is accessible once the partitioning has changed"
    );
    assert_eq!(index.unreferenced_recordings.len(), 3);
    for e in &index.unreferenced_recordings {
        let reason = e.oem_metadata.get("dahua_availability_reason").unwrap();
        assert!(reason.contains("available rather than accessible"));
        assert!(
            reason.contains("not evidence of deletion"),
            "a re-partitioned volume is not a deletion finding"
        );
    }

    let orchestrator = parsing::ParsingOrchestrator::new();
    let outcome = RecoveryEngine::new()
        .execute_recovery(RecoveryRequest {
            evidence_id: EvidenceId::new(),
            reader: &reader,
            profile,
            oem_key: "dahua",
            parser: orchestrator.parser_for("dahua").unwrap(),
            bounds: &bounds(),
            scan_window: None,
            read_window_bytes: None,
        })
        .unwrap();

    assert_eq!(outcome.metrics.active_count, 0);
    assert!(
        outcome.metrics.orphaned_count >= 4,
        "every frame becomes an orphan finding"
    );
    assert_eq!(outcome.metrics.deleted_count, 0);
}

// ── Bounds, determinism, read-only ─────────────────────────────────────────────

#[test]
fn a_truncated_run_is_review_never_pass() {
    let f = fixture();
    let reg = registry();
    let profile = reg.find_applicable("dahua", None, None, None).unwrap();
    let orchestrator = parsing::ParsingOrchestrator::new();
    let tight = RecoveryBounds {
        max_scan_bytes: 4096,
        ..bounds()
    };
    let outcome = RecoveryEngine::new()
        .execute_recovery(RecoveryRequest {
            evidence_id: EvidenceId::new(),
            reader: &f.reader,
            profile,
            oem_key: "dahua",
            parser: orchestrator.parser_for("dahua").unwrap(),
            bounds: &tight,
            scan_window: None,
            read_window_bytes: None,
        })
        .unwrap();

    assert!(outcome.run.truncated);
    assert_eq!(
        outcome.run.validation_state.state,
        ValidationStateKind::Review,
        "a bounded search cannot guarantee a global optimum"
    );
    assert_eq!(outcome.run.reason, "Search bounds reached");
    assert!(outcome.metrics.truncated);
}

#[test]
fn a_cancelled_run_is_review_and_stops_promptly() {
    let f = fixture();
    let reg = registry();
    let profile = reg.find_applicable("dahua", None, None, None).unwrap();
    let orchestrator = parsing::ParsingOrchestrator::new();
    let cancelled = RecoveryBounds {
        cancel: {
            let t = CancelToken::new();
            t.cancel();
            t
        },
        ..bounds()
    };
    let outcome = RecoveryEngine::new()
        .execute_recovery(RecoveryRequest {
            evidence_id: EvidenceId::new(),
            reader: &f.reader,
            profile,
            oem_key: "dahua",
            parser: orchestrator.parser_for("dahua").unwrap(),
            bounds: &cancelled,
            scan_window: None,
            read_window_bytes: None,
        })
        .unwrap();

    assert!(outcome.run.cancelled);
    assert!(outcome.candidates.is_empty());
    assert_eq!(
        outcome.run.validation_state.state,
        ValidationStateKind::Review
    );
}

#[test]
fn recovery_does_not_modify_the_evidence_image() {
    let f = fixture();
    let before = std::fs::read(f.reader.source_path()).expect("read fixture");
    let _ = run(&f, EvidenceId::new());
    let after = std::fs::read(f.reader.source_path()).expect("read fixture");
    assert_eq!(
        before, after,
        "evidence is read-only at the type level and in fact"
    );
}

#[test]
fn two_runs_over_the_same_evidence_produce_identical_findings() {
    let f = fixture();
    let evidence_id = EvidenceId::new();
    let a = run(&f, evidence_id);
    let b = run(&f, evidence_id);

    let key = |o: &recovery::RecoveryOutcome| -> Vec<(u64, u64, String, String)> {
        o.candidates
            .iter()
            .zip(o.fragments.iter())
            .map(|(c, fr)| {
                (
                    c.source_offsets[0].offset,
                    c.source_offsets[0].length,
                    format!("{:?}", c.data_state),
                    fr.fragment_id.clone(),
                )
            })
            .collect()
    };
    assert_eq!(key(&a), key(&b));
    assert_eq!(a.plan.planned_bytes, b.plan.planned_bytes);
    assert_eq!(a.metrics.claimed_bytes, b.metrics.claimed_bytes);
}

#[test]
fn a_scan_window_narrows_reasoning_without_rebasing_offsets() {
    let f = fixture();
    let p = f.image.partition(0).unwrap();
    let block = p.block(realistic::CH2_BLOCK).unwrap();
    let window = Region::new(block.offset, fx::VIDEO_BLOCK).unwrap();

    let reg = registry();
    let profile = reg.find_applicable("dahua", None, None, None).unwrap();
    let orchestrator = parsing::ParsingOrchestrator::new();
    let outcome = RecoveryEngine::new()
        .execute_recovery(RecoveryRequest {
            evidence_id: EvidenceId::new(),
            reader: &f.reader,
            profile,
            oem_key: "dahua",
            parser: orchestrator.parser_for("dahua").unwrap(),
            bounds: &bounds(),
            scan_window: Some(window),
            read_window_bytes: None,
        })
        .unwrap();

    assert_eq!(outcome.plan.universe, window);
    assert!(!outcome.candidates.is_empty());
    for c in &outcome.candidates {
        let o = c.source_offsets[0].offset;
        assert!(
            o >= window.offset && o < window.end().unwrap(),
            "0x{o:X} is outside the window, so offsets were rebased"
        );
        assert!(o > 0, "absolute offsets, never zero-based");
    }
    // Only this block's frames are in scope.
    let got: Vec<u64> = outcome
        .candidates
        .iter()
        .map(|c| c.source_offsets[0].offset)
        .collect();
    assert_eq!(got, block.frame_offsets);
}
