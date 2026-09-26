//! # Phase 3: Parsing Contract Tests
//!
//! Enforces the hostile-input parser contract (Req 24.1, 24.2, 24.3, 24.4).
//! Ensures the core models (TimeEvidence, Recording, TimelineEvent) uphold immutability
//! and separation properties (Req 4.5).

use forensic_core::checked::{checked_sector_offset, validate_region_bounds};
use forensic_core::{
    ClockCorrection, EvidenceId, ForensicError, Hash, NormalizedTime, Provenance,
    RecorderNativeTime, Region, TimeEvidence, ValidationState,
};

#[test]
fn property_8_time_evidence_immutability_under_normalization() {
    let source = Provenance::new(
        EvidenceId(uuid::Uuid::new_v4()),
        Hash::sha256(vec![0; 32]),
        vec![],
        "test_component",
        "1.0",
        Hash::sha256(vec![0; 32]),
        ValidationState::pass("reason", "operation", "subject").unwrap(),
    );

    // 1. Create a TimeEvidence instance with raw data.
    let mut time = TimeEvidence::new(1693526400, "unix_seconds", source.clone());

    // 2. The raw value must not be modified when recorder_native is populated.
    time.recorder_native = Some(RecorderNativeTime {
        iso_8601: "2023-09-01T00:00:00".to_string(),
    });

    assert_eq!(time.raw.value, 1693526400);
    assert_eq!(time.raw.format, "unix_seconds");

    // 3. Normalization must not mutate raw or recorder_native.
    time.normalized = Some(NormalizedTime {
        iso_8601: "2023-09-01T00:00:00Z".to_string(),
        method: "assumed_utc".to_string(),
    });

    assert_eq!(time.raw.value, 1693526400);
    assert_eq!(
        time.recorder_native.as_ref().unwrap().iso_8601,
        "2023-09-01T00:00:00"
    );

    // 4. Clock correction must not mutate raw or recorder_native.
    time.correction = Some(ClockCorrection {
        method: "ntp_anchor".to_string(),
        anchor_evidence: source.clone(),
        offset_seconds: 3600,
        drift_rate: None,
        residual_seconds: None,
    });

    assert_eq!(time.raw.value, 1693526400);
    assert_eq!(
        time.recorder_native.as_ref().unwrap().iso_8601,
        "2023-09-01T00:00:00"
    );
}

#[test]
fn adversarial_checked_arithmetic_prevents_overflow() {
    // Attempting to calculate a sector offset that overflows u64
    let sector_index: u64 = u64::MAX;
    let sector_size: u64 = 512;

    // checked_sector_offset(sector, size)
    // u64::MAX * 512 -> Overflows!
    let result = checked_sector_offset(sector_index, sector_size);

    assert!(result.is_err());
    match result {
        Err(ForensicError::ArithmeticOverflow { .. }) => {}
        _ => panic!("Expected ArithmeticOverflow error!"),
    }
}

#[test]
fn adversarial_region_bounds_validation() {
    let region = Region {
        offset: 1000,
        length: 500, // Ends at 1500
    };

    // Total evidence size is only 1200 bytes.
    let evidence_size = 1200;

    let result = validate_region_bounds(&region, evidence_size);

    assert!(result.is_err());
    match result {
        Err(ForensicError::OutOfBounds { .. }) => {}
        _ => panic!("Expected OutOfBounds error!"),
    }
}
