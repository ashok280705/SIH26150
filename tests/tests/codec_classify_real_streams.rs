//! Verifies codec classification against REAL encoded elementary streams.
//!
//! Regression guard: the H.264 P-slice header 0x41 reinterprets to HEVC
//! nal_unit_type 32 (VPS) if only the first header byte is validated, which made
//! every real AVC stream score as HEVC.

use recovery::{VideoCodec, VideoReconstructor};
use std::path::Path;

fn read_fixture(name: &str) -> Option<Vec<u8>> {
    for base in [".fixture_build", "../.fixture_build"] {
        let p = Path::new(base).join(name);
        if p.exists() {
            return std::fs::read(p).ok();
        }
    }
    None
}

#[test]
fn real_h264_stream_is_not_misclassified_as_h265() {
    let Some(bytes) = read_fixture("ch1.h264") else {
        eprintln!("skipping: .fixture_build/ch1.h264 not present (run generate_dahua_raw.py)");
        return;
    };
    let ev = VideoReconstructor::classify_codec(&bytes);
    eprintln!(
        "h264 fixture -> codec={:?} h264_score={} h265_score={} ({})",
        ev.codec, ev.h264_score, ev.h265_score, ev.validation.reason
    );
    assert_eq!(ev.codec, VideoCodec::H264, "real H.264 must classify as H264");
    assert!(ev.h264_score > ev.h265_score, "H.264 evidence must dominate");
}

#[test]
fn real_hevc_stream_classifies_as_h265() {
    let Some(bytes) = read_fixture("ch2.hevc") else {
        eprintln!("skipping: .fixture_build/ch2.hevc not present (run generate_dahua_raw.py)");
        return;
    };
    let ev = VideoReconstructor::classify_codec(&bytes);
    eprintln!(
        "hevc fixture -> codec={:?} h264_score={} h265_score={} ({})",
        ev.codec, ev.h264_score, ev.h265_score, ev.validation.reason
    );
    assert_eq!(ev.codec, VideoCodec::H265, "real HEVC must classify as H265");
}
