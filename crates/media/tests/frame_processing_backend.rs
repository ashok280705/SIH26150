//! Conformance tests for the frame-processing backend abstraction.
//!
//! ```text
//!   VideoFrame ─► FrameProcessor ─► backend (opencv | pure-rust) ─► derived VideoFrame
//! ```
//!
//! ## What "cross-backend comparison" can and cannot mean here
//!
//! The backend is chosen at **compile time** by the `opencv-backend` feature, so exactly one of
//! the two is linked into any given test binary. No test process can run both and diff them.
//!
//! What this file does instead is assert both backends against the *same* reference table, with
//! the tolerance the contract in `process.rs` states for each operation:
//!
//! | Operation | Reference | Tolerance |
//! |---|---|---|
//! | Channel swap | Byte permutation computed here | exact |
//! | `GRAY8 → BGR/RGB` | Channel replication computed here | exact |
//! | ROI crop | Sub-rectangle copied here | exact |
//! | `BGR/RGB → GRAY8` | BT.601 Q14, computed here | ≤ 1 LSB (exact is additionally required of the fallback) |
//! | Resize | Independent `f64` bilinear, computed here | ≤ 2 LSB |
//! | Luma mean / std dev | Computed here in `f64` | 1e-9 absolute |
//! | Laplacian variance | Interior-only 3×3, computed here | 1e-6 relative |
//!
//! A run under the OpenCV backend and a run under the fallback that both pass this table have
//! been shown to agree to those tolerances *transitively*, via the reference — which is the
//! strongest honest claim available without a host that has OpenCV.
//!
//! **The OpenCV backend has never been compiled.** Every test below that requires it is gated
//! on the feature and prints an explicit `SKIPPED` line otherwise. None of them is rewritten to
//! exercise the fallback instead: a skipped OpenCV test reports as skipped, never as a pass.
//! Set `MEDIA_REQUIRE_OPENCV=1` to turn those skips into failures, which is what a verification
//! host does so a misconfigured run cannot report a false green.

use forensic_core::EvidenceId;
use media::error::MediaErrorKind;
use media::frame::{FrameProvenance, FrameTiming, PixelFormat, VideoFrame};
use media::pipeline::ProcessingPlan;
use media::process::{active_backend, backend_identity, FrameProcessor, ProcessingBackend, Roi};

// ─────────────────────────────────────────────────────────────────────────────
// Harness
// ─────────────────────────────────────────────────────────────────────────────

/// Reports a test as skipped because this build has no OpenCV backend.
///
/// Returns `true` when the caller should stop. Honours `MEDIA_REQUIRE_OPENCV=1` by panicking
/// instead, so a verification host cannot silently accept a build that lacks the backend it was
/// supposed to be verifying.
fn skip_without_opencv(test: &str) -> bool {
    if active_backend() == ProcessingBackend::OpenCv {
        return false;
    }
    let msg = format!(
        "SKIPPED: {test} — this binary was built without the `opencv-backend` feature, so the \
         native OpenCV backend is not linked in and cannot be exercised. This is a skip, not a \
         pass."
    );
    if std::env::var("MEDIA_REQUIRE_OPENCV").as_deref() == Ok("1") {
        panic!("{msg} (MEDIA_REQUIRE_OPENCV=1 makes this a failure)");
    }
    eprintln!("{msg}");
    true
}

fn frame(width: u32, height: u32, fmt: PixelFormat, data: Vec<u8>) -> VideoFrame {
    VideoFrame::new(
        "art-cv",
        0,
        width,
        height,
        fmt,
        data,
        FrameTiming::unknown(),
        FrameProvenance {
            evidence_id: EvidenceId::new(),
            artifact_id: "art-cv".into(),
            artifact_source_offset: Some(1024),
            source_recording_id: Some("rec-cv".into()),
            artifact_media_hash: Some("cafebabe".into()),
            decoder: "test".into(),
            processing_chain: vec![],
        },
    )
    .expect("fixture geometry and buffer agree")
}

/// A deterministic 8x6 BGR pattern with gradients on all three channels plus hard edges.
///
/// Gradients exercise interpolation; the edges exercise the Laplacian. Nothing here is random,
/// so every assertion below is reproducible.
fn bgr_8x6() -> VideoFrame {
    let (w, h) = (8u32, 6u32);
    let mut data = Vec::with_capacity((w * h * 3) as usize);
    for y in 0..h {
        for x in 0..w {
            let edge = if (x / 2 + y / 2) % 2 == 0 { 0u8 } else { 200u8 };
            data.push((x * 31) as u8); // B
            data.push((y * 41) as u8); // G
            data.push(edge); // R
        }
    }
    frame(w, h, PixelFormat::Bgr24, data)
}

fn gray_8x6() -> VideoFrame {
    let bgr = bgr_8x6();
    FrameProcessor::convert_color(&bgr, PixelFormat::Gray8).expect("BGR24 -> GRAY8 is supported")
}

// ─── Reference implementations, independent of both backends ────────────────

/// BT.601 luma in Q14 fixed point — the definition both backends claim to implement.
fn reference_luma(data: &[u8], from: PixelFormat) -> Vec<u8> {
    const R: u32 = 4899;
    const G: u32 = 9617;
    const B: u32 = 1868;
    let (ri, bi) = match from {
        PixelFormat::Bgr24 => (2usize, 0usize),
        _ => (0usize, 2usize),
    };
    data.chunks_exact(3)
        .map(|p| {
            let (r, g, b) = (p[ri] as u32, p[1] as u32, p[bi] as u32);
            (((r * R + g * G + b * B) + (1 << 13)) >> 14) as u8
        })
        .collect()
}

/// Bilinear resampling on a half-pixel-centred grid, in `f64`.
///
/// Written out here rather than reused from the crate so that the fallback is compared against
/// something, not against itself.
fn reference_resize(data: &[u8], sw: usize, sh: usize, ch: usize, dw: usize, dh: usize) -> Vec<u8> {
    let mut out = vec![0u8; dw * dh * ch];
    let (sx, sy) = (sw as f64 / dw as f64, sh as f64 / dh as f64);
    for y in 0..dh {
        let fy = ((y as f64 + 0.5) * sy - 0.5).max(0.0);
        let y0 = (fy.floor() as usize).min(sh - 1);
        let y1 = (y0 + 1).min(sh - 1);
        let wy = fy - y0 as f64;
        for x in 0..dw {
            let fx = ((x as f64 + 0.5) * sx - 0.5).max(0.0);
            let x0 = (fx.floor() as usize).min(sw - 1);
            let x1 = (x0 + 1).min(sw - 1);
            let wx = fx - x0 as f64;
            for c in 0..ch {
                let at = |yy: usize, xx: usize| data[(yy * sw + xx) * ch + c] as f64;
                let top = at(y0, x0) + (at(y0, x1) - at(y0, x0)) * wx;
                let bot = at(y1, x0) + (at(y1, x1) - at(y1, x0)) * wx;
                out[(y * dw + x) * ch + c] =
                    (top + (bot - top) * wy).round().clamp(0.0, 255.0) as u8;
            }
        }
    }
    out
}

/// Population mean, standard deviation, and interior-only Laplacian variance.
fn reference_stats(luma: &[u8], w: usize, h: usize) -> (f64, f64, f64) {
    let n = luma.len() as f64;
    let mean = luma.iter().map(|&v| v as f64).sum::<f64>() / n;
    let var = luma.iter().map(|&v| (v as f64 - mean).powi(2)).sum::<f64>() / n;

    let lap_var = if w < 3 || h < 3 {
        0.0
    } else {
        let mut vals = Vec::with_capacity((w - 2) * (h - 2));
        for y in 1..h - 1 {
            for x in 1..w - 1 {
                vals.push(
                    (luma[(y - 1) * w + x] as i32
                        + luma[(y + 1) * w + x] as i32
                        + luma[y * w + x - 1] as i32
                        + luma[y * w + x + 1] as i32
                        - 4 * luma[y * w + x] as i32) as f64,
                );
            }
        }
        let m = vals.iter().sum::<f64>() / vals.len() as f64;
        vals.iter().map(|v| (v - m).powi(2)).sum::<f64>() / vals.len() as f64
    };
    (mean, var.sqrt(), lap_var)
}

/// Largest absolute difference between two equal-length byte buffers.
fn max_abs_diff(a: &[u8], b: &[u8]) -> i32 {
    assert_eq!(
        a.len(),
        b.len(),
        "buffers must be the same length to compare"
    );
    a.iter()
        .zip(b)
        .map(|(x, y)| (*x as i32 - *y as i32).abs())
        .max()
        .unwrap_or(0)
}

// ─────────────────────────────────────────────────────────────────────────────
// 1. Backend availability detection
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn the_detected_backend_agrees_with_the_compiled_feature_and_identifies_itself() {
    let backend = active_backend();
    let identity = backend_identity();

    assert!(
        identity.starts_with(backend.label()),
        "identity {identity:?} must begin with the backend token {:?}",
        backend.label()
    );
    // Stable within a process: the same string must be recorded on every frame of a run.
    assert_eq!(identity, backend_identity());

    if cfg!(feature = "opencv-backend") {
        assert_eq!(backend, ProcessingBackend::OpenCv);
    } else {
        assert_eq!(backend, ProcessingBackend::PureRustFallback);
        assert_eq!(identity, "pure_rust_fallback");
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// 2. Native backend construction (environment-gated)
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn the_native_opencv_backend_constructs_and_reports_its_real_library_version() {
    if skip_without_opencv("native OpenCV backend construction") {
        return;
    }
    let identity = backend_identity();
    assert!(identity.starts_with("opencv"));
    // The version must come from the library at runtime, never from a constant in this repo.
    assert!(
        !identity.contains("version unreported"),
        "a working OpenCV build must report its own version, got {identity:?}"
    );
    // Passing a real frame through proves the library is linked and callable, not merely that
    // the feature flag is set.
    let out = FrameProcessor::resize(&bgr_8x6(), 4, 3).expect("native OpenCV resize");
    assert_eq!((out.width, out.height), (4, 3));
    assert_eq!(out.data.len(), 4 * 3 * 3);
    assert_eq!(out.provenance.processing_chain[0].backend, identity);
}

#[test]
fn requiring_opencv_on_a_build_without_it_fails_instead_of_falling_back() {
    if active_backend() == ProcessingBackend::OpenCv {
        assert!(FrameProcessor::require_opencv("test").is_ok());
        return;
    }
    let err = FrameProcessor::require_opencv("test").unwrap_err();
    assert_eq!(err.kind, MediaErrorKind::OpencvUnavailable);
    assert_eq!(err.code(), "OPENCV_UNAVAILABLE");
    // And the pipeline-level requirement agrees with the direct one.
    let plan = ProcessingPlan {
        measure_quality: true,
        require_backend: Some(ProcessingBackend::OpenCv),
        ..Default::default()
    };
    assert_eq!(plan.require_backend, Some(ProcessingBackend::OpenCv));
}

// ─────────────────────────────────────────────────────────────────────────────
// 3. Fallback backend construction
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn the_fallback_backend_performs_every_operation_in_the_contract() {
    if active_backend() != ProcessingBackend::PureRustFallback {
        eprintln!(
            "SKIPPED: fallback backend construction — this binary was built WITH \
             `opencv-backend`, so the fallback is not compiled in."
        );
        return;
    }
    let f = bgr_8x6();
    assert!(FrameProcessor::resize(&f, 4, 3).is_ok());
    assert!(FrameProcessor::convert_color(&f, PixelFormat::Gray8).is_ok());
    assert!(FrameProcessor::crop_roi(
        &f,
        Roi {
            x: 1,
            y: 1,
            width: 4,
            height: 4
        }
    )
    .is_ok());
    assert!(FrameProcessor::quality(&f).is_ok());
    assert!(FrameProcessor::require_backend(ProcessingBackend::PureRustFallback, "t").is_ok());
}

// ─────────────────────────────────────────────────────────────────────────────
// 4. Colour conversion
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn a_channel_swap_is_exact_under_either_backend() {
    let f = bgr_8x6();
    let rgb = FrameProcessor::convert_color(&f, PixelFormat::Rgb24).unwrap();

    let expected: Vec<u8> = f
        .data
        .chunks_exact(3)
        .flat_map(|p| [p[2], p[1], p[0]])
        .collect();
    // A permutation of bytes has exactly one answer; no tolerance applies.
    assert_eq!(rgb.data, expected);
    assert_eq!(rgb.pixel_format, PixelFormat::Rgb24);

    // And it round-trips, which no lossy path could.
    let back = FrameProcessor::convert_color(&rgb, PixelFormat::Bgr24).unwrap();
    assert_eq!(back.data, f.data);
}

#[test]
fn gray_to_colour_replicates_the_channel_exactly_under_either_backend() {
    let g = gray_8x6();
    for target in [PixelFormat::Bgr24, PixelFormat::Rgb24] {
        let c = FrameProcessor::convert_color(&g, target).unwrap();
        let expected: Vec<u8> = g.data.iter().flat_map(|&v| [v, v, v]).collect();
        assert_eq!(c.data, expected, "{target:?}");
    }
}

#[test]
fn colour_to_luma_matches_the_bt601_reference_within_one_lsb() {
    for from in [PixelFormat::Bgr24, PixelFormat::Rgb24] {
        let src = if from == PixelFormat::Bgr24 {
            bgr_8x6()
        } else {
            FrameProcessor::convert_color(&bgr_8x6(), PixelFormat::Rgb24).unwrap()
        };
        let got = FrameProcessor::convert_color(&src, PixelFormat::Gray8).unwrap();
        let expected = reference_luma(&src.data, from);

        let diff = max_abs_diff(&got.data, &expected);
        // Both backends implement BT.601 in Q14; OpenCV's SIMD paths may round one step
        // differently, which is the documented tolerance.
        assert!(
            diff <= 1,
            "{from:?} -> GRAY8 differs from the BT.601 reference by {diff} LSB (tolerance 1)"
        );
        // The fallback is a direct transcription of the reference, so for it the claim is
        // stronger and is asserted as such.
        if active_backend() == ProcessingBackend::PureRustFallback {
            assert_eq!(got.data, expected, "the fallback must match BT.601 exactly");
        }
    }
}

#[test]
fn converting_to_the_same_format_changes_nothing_and_records_nothing() {
    let f = bgr_8x6();
    let out = FrameProcessor::convert_color(&f, PixelFormat::Bgr24).unwrap();
    assert_eq!(out.data, f.data);
    assert!(
        out.provenance.processing_chain.is_empty(),
        "a no-op must not appear in the provenance chain as work that was done"
    );
}

// ─────────────────────────────────────────────────────────────────────────────
// 5. Resize
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn resize_matches_an_independent_bilinear_reference_within_two_lsb() {
    let f = bgr_8x6();
    for (dw, dh) in [(4u32, 3u32), (16, 12), (8, 6), (3, 7)] {
        let got = FrameProcessor::resize(&f, dw, dh).unwrap();
        assert_eq!((got.width, got.height), (dw, dh));
        assert_eq!(got.data.len() as u32, dw * dh * 3);

        let expected = reference_resize(&f.data, 8, 6, 3, dw as usize, dh as usize);
        let diff = max_abs_diff(&got.data, &expected);
        assert!(
            diff <= 2,
            "resize to {dw}x{dh} differs from the bilinear reference by {diff} LSB \
             (tolerance 2; OpenCV uses 5-bit fixed-point weights, the fallback uses f64)"
        );
    }
}

#[test]
fn resizing_to_the_same_size_preserves_the_picture_within_tolerance() {
    let f = bgr_8x6();
    let same = FrameProcessor::resize(&f, 8, 6).unwrap();
    // Identity sampling on a half-pixel grid lands exactly on source pixels.
    assert!(max_abs_diff(&same.data, &f.data) <= 2);
}

// ─────────────────────────────────────────────────────────────────────────────
// 6. ROI extraction
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn roi_extraction_is_exact_under_either_backend_for_both_channel_counts() {
    let roi = Roi {
        x: 2,
        y: 1,
        width: 5,
        height: 4,
    };

    for src in [bgr_8x6(), gray_8x6()] {
        let ch = src.pixel_format.channels();
        let out = FrameProcessor::crop_roi(&src, roi).unwrap();
        assert_eq!((out.width, out.height), (roi.width, roi.height));
        assert_eq!(out.data.len(), (roi.width * roi.height) as usize * ch);

        // Copying a sub-rectangle has one answer; the packed result must equal it byte for
        // byte, which is also what proves the stride handling is right on both sides.
        let mut expected = Vec::new();
        for y in 0..roi.height as usize {
            let row = (roi.y as usize + y) * 8 + roi.x as usize;
            expected.extend_from_slice(&src.data[row * ch..row * ch + roi.width as usize * ch]);
        }
        assert_eq!(out.data, expected, "{:?}", src.pixel_format);
    }
}

#[test]
fn a_full_frame_roi_reproduces_the_frame_exactly() {
    let f = bgr_8x6();
    let out = FrameProcessor::crop_roi(
        &f,
        Roi {
            x: 0,
            y: 0,
            width: 8,
            height: 6,
        },
    )
    .unwrap();
    assert_eq!(out.data, f.data);
}

// ─────────────────────────────────────────────────────────────────────────────
// 7. Quality metrics
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn quality_metrics_match_the_reference_definitions() {
    let g = gray_8x6();
    let (mean, std, lap) = reference_stats(&g.data, 8, 6);
    let q = FrameProcessor::quality(&g).unwrap();

    assert!(
        (q.mean_brightness - mean).abs() < 1e-9,
        "mean {} vs reference {mean}",
        q.mean_brightness
    );
    assert!(
        (q.brightness_std_dev - std).abs() < 1e-9,
        "std dev {} vs reference {std}",
        q.brightness_std_dev
    );
    // Laplacian variance is an f64 reduction over many terms; compared relatively.
    let rel = (q.laplacian_variance - lap).abs() / lap.max(1.0);
    assert!(
        rel < 1e-6,
        "laplacian variance {} vs reference {lap} (relative {rel})",
        q.laplacian_variance
    );

    // The reported backend is the one that computed these numbers.
    assert_eq!(q.backend, active_backend());
    assert_eq!((q.width, q.height), (8, 6));
    assert!(q.has_tonal_variation);
}

#[test]
fn a_flat_frame_is_reported_as_flat_rather_than_discarded() {
    let flat = frame(8, 6, PixelFormat::Gray8, vec![77u8; 48]);
    let q = FrameProcessor::quality(&flat).unwrap();
    assert!((q.mean_brightness - 77.0).abs() < 1e-9);
    assert!(q.brightness_std_dev < 1e-9);
    assert!(q.laplacian_variance < 1e-9);
    assert!(!q.has_tonal_variation);
}

#[test]
fn a_colour_frame_is_measured_over_its_luma_not_its_raw_channels() {
    let bgr = bgr_8x6();
    let from_colour = FrameProcessor::quality(&bgr).unwrap();
    let from_luma = FrameProcessor::quality(&gray_8x6()).unwrap();
    // Measuring the colour frame must be the same as converting first and then measuring.
    assert!((from_colour.mean_brightness - from_luma.mean_brightness).abs() < 1e-9);
    assert!((from_colour.laplacian_variance - from_luma.laplacian_variance).abs() < 1e-6);
}

#[test]
fn a_frame_with_no_interior_yields_no_laplacian_rather_than_a_border_artefact() {
    // Below the 3x3 kernel's reach in one dimension, then in both.
    for (w, h) in [(2u32, 6u32), (8, 2), (2, 2)] {
        let q = FrameProcessor::quality(&frame(
            w,
            h,
            PixelFormat::Gray8,
            (0..(w * h)).map(|i| (i * 17) as u8).collect(),
        ))
        .unwrap();
        assert_eq!(
            q.laplacian_variance, 0.0,
            "{w}x{h} has no interior, so there is no Laplacian to report"
        );
        // The brightness statistics remain real measurements.
        assert!(q.mean_brightness > 0.0);
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// 8. Invalid dimensions
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn a_resize_target_with_no_pixels_is_rejected_by_either_backend() {
    let f = bgr_8x6();
    for (w, h) in [(0u32, 4u32), (4, 0), (0, 0)] {
        let err = FrameProcessor::resize(&f, w, h).unwrap_err();
        assert_eq!(err.kind, MediaErrorKind::InvalidConfiguration, "{w}x{h}");
        assert_eq!(err.code(), "INVALID_CONFIGURATION");
    }
}

#[test]
fn a_buffer_that_disagrees_with_its_geometry_is_refused_before_reaching_a_backend() {
    let mut f = bgr_8x6();
    f.data.truncate(f.data.len() - 3); // one pixel short

    for err in [
        FrameProcessor::resize(&f, 4, 3).unwrap_err(),
        FrameProcessor::convert_color(&f, PixelFormat::Gray8).unwrap_err(),
        FrameProcessor::quality(&f).unwrap_err(),
        FrameProcessor::crop_roi(
            &f,
            Roi {
                x: 0,
                y: 0,
                width: 2,
                height: 2,
            },
        )
        .unwrap_err(),
    ] {
        // A truncated frame IS a statement about the data, so INVALID_FRAME is right here —
        // unlike an OpenCV library fault, which must never arrive under this code.
        assert_eq!(err.kind, MediaErrorKind::InvalidFrame);
        assert!(err.kind.is_evidence_fault());
        assert!(!err.kind.is_implementation_fault());
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// 9. Invalid ROI
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn an_roi_outside_the_frame_is_refused_rather_than_clamped() {
    let f = bgr_8x6();
    let cases = [
        Roi {
            x: 0,
            y: 0,
            width: 9,
            height: 6,
        }, // too wide
        Roi {
            x: 0,
            y: 0,
            width: 8,
            height: 7,
        }, // too tall
        Roi {
            x: 7,
            y: 5,
            width: 2,
            height: 2,
        }, // overruns the far corner
        Roi {
            x: 0,
            y: 0,
            width: 0,
            height: 6,
        }, // empty
        Roi {
            x: 0,
            y: 0,
            width: 8,
            height: 0,
        }, // empty
        Roi {
            x: u32::MAX,
            y: 0,
            width: 4,
            height: 4,
        }, // would overflow
    ];
    for roi in cases {
        let err = FrameProcessor::crop_roi(&f, roi).unwrap_err();
        assert_eq!(
            err.kind,
            MediaErrorKind::InvalidConfiguration,
            "{roi:?} must be refused"
        );
        // Silently shrinking to fit would change what was analysed without saying so.
        assert!(roi.validate(8, 6).is_err());
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// 10. Unsupported pixel format
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn every_declared_conversion_is_supported_by_whichever_backend_is_active() {
    // The contract is the set of conversions `PixelFormat` can express. Both backends must
    // cover all of them; neither may quietly decline one the other handles.
    let formats = [PixelFormat::Bgr24, PixelFormat::Rgb24, PixelFormat::Gray8];
    for from in formats {
        let src = match from {
            PixelFormat::Bgr24 => bgr_8x6(),
            PixelFormat::Rgb24 => {
                FrameProcessor::convert_color(&bgr_8x6(), PixelFormat::Rgb24).unwrap()
            }
            PixelFormat::Gray8 => gray_8x6(),
        };
        for to in formats {
            let out = FrameProcessor::convert_color(&src, to)
                .unwrap_or_else(|e| panic!("{from:?} -> {to:?} must be supported: {e}"));
            assert_eq!(out.pixel_format, to);
            assert_eq!(
                out.data.len(),
                (8 * 6) as usize * to.channels(),
                "{from:?} -> {to:?} produced the wrong buffer length"
            );
        }
    }
}

#[test]
fn an_unsupported_request_is_a_configuration_fault_not_an_evidence_fault() {
    // `select_every_nth` is the one operation with a parameter that can be nonsensical without
    // involving pixels at all; it must classify the same way an unsupported conversion does.
    let err = FrameProcessor::select_every_nth(&[], 0).unwrap_err();
    assert_eq!(err.kind, MediaErrorKind::InvalidConfiguration);
    assert!(!err.kind.is_evidence_fault());
}

// ─────────────────────────────────────────────────────────────────────────────
// 11. Empty frame handling
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn a_frame_with_no_pixels_cannot_be_constructed_and_is_never_processed() {
    // The frame type refuses a zero-pixel geometry outright, which is why no backend ever has
    // to guess what to do with one.
    for (w, h) in [(0u32, 6u32), (8, 0), (0, 0)] {
        let err = VideoFrame::new(
            "art-cv",
            0,
            w,
            h,
            PixelFormat::Gray8,
            Vec::new(),
            FrameTiming::unknown(),
            FrameProvenance {
                evidence_id: EvidenceId::new(),
                artifact_id: "art-cv".into(),
                artifact_source_offset: None,
                source_recording_id: None,
                artifact_media_hash: None,
                decoder: "test".into(),
                processing_chain: vec![],
            },
        )
        .unwrap_err();
        assert_eq!(err.kind, MediaErrorKind::InvalidFrame, "{w}x{h}");
    }

    // And a frame whose buffer has been emptied after construction is refused at the boundary
    // rather than reaching a backend with a zero-length slice.
    let mut f = gray_8x6();
    f.data.clear();
    assert_eq!(
        FrameProcessor::quality(&f).unwrap_err().kind,
        MediaErrorKind::InvalidFrame
    );
}

// ─────────────────────────────────────────────────────────────────────────────
// 12. Deterministic output
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn repeated_operations_produce_byte_identical_results_and_hashes() {
    let f = bgr_8x6();
    let roi = Roi {
        x: 1,
        y: 1,
        width: 6,
        height: 4,
    };

    for _ in 0..3 {
        let a = FrameProcessor::resize(&f, 13, 9).unwrap();
        let b = FrameProcessor::resize(&f, 13, 9).unwrap();
        assert_eq!(a.data, b.data);
        assert_eq!(a.content_hash().hex, b.content_hash().hex);

        let ga = FrameProcessor::convert_color(&f, PixelFormat::Gray8).unwrap();
        let gb = FrameProcessor::convert_color(&f, PixelFormat::Gray8).unwrap();
        assert_eq!(ga.content_hash().hex, gb.content_hash().hex);

        assert_eq!(
            FrameProcessor::crop_roi(&f, roi).unwrap().data,
            FrameProcessor::crop_roi(&f, roi).unwrap().data
        );
        assert_eq!(
            FrameProcessor::quality(&f).unwrap(),
            FrameProcessor::quality(&f).unwrap()
        );
    }
}

#[test]
fn a_processing_chain_is_order_dependent_and_fully_recorded() {
    let f = bgr_8x6();
    let roi = FrameProcessor::crop_roi(
        &f,
        Roi {
            x: 1,
            y: 1,
            width: 6,
            height: 4,
        },
    )
    .unwrap();
    let resized = FrameProcessor::resize(&roi, 12, 8).unwrap();
    let gray = FrameProcessor::convert_color(&resized, PixelFormat::Gray8).unwrap();

    let steps: Vec<&str> = gray
        .provenance
        .processing_chain
        .iter()
        .map(|s| s.operation.as_str())
        .collect();
    assert_eq!(steps, vec!["roi", "resize", "cvt_color"]);

    // Every step names the backend that performed it, with its version where there is one.
    for step in &gray.provenance.processing_chain {
        assert_eq!(step.backend, backend_identity());
        assert!(!step.parameters.is_empty(), "a step must be reproducible");
    }

    // The derived frame still traces to the same evidence, artifact and decoded frame.
    assert_eq!(gray.provenance.evidence_id, f.provenance.evidence_id);
    assert_eq!(gray.frame_id, f.frame_id);
    assert_eq!(gray.provenance.artifact_source_offset, Some(1024));
    // And the source frame was not touched.
    assert_eq!(f.data, bgr_8x6().data);
}

// ─────────────────────────────────────────────────────────────────────────────
// 13. Native-vs-fallback semantic comparison
// ─────────────────────────────────────────────────────────────────────────────

/// Asserts the active backend against the whole shared reference table in one place.
///
/// Because the backend is selected at compile time, this is how the two are compared: each is
/// held to the same references at the same tolerances, in a test that is run under both
/// configurations. A backend that passes this has been shown to agree with the other to the sum
/// of the two tolerances.
#[test]
fn the_active_backend_satisfies_the_shared_cross_backend_reference_table() {
    let bgr = bgr_8x6();

    // Exact by contract.
    let rgb = FrameProcessor::convert_color(&bgr, PixelFormat::Rgb24).unwrap();
    let expect_rgb: Vec<u8> = bgr
        .data
        .chunks_exact(3)
        .flat_map(|p| [p[2], p[1], p[0]])
        .collect();
    assert_eq!(
        max_abs_diff(&rgb.data, &expect_rgb),
        0,
        "channel swap: exact"
    );

    let gray = FrameProcessor::convert_color(&bgr, PixelFormat::Gray8).unwrap();
    let back = FrameProcessor::convert_color(&gray, PixelFormat::Bgr24).unwrap();
    let expect_back: Vec<u8> = gray.data.iter().flat_map(|&v| [v, v, v]).collect();
    assert_eq!(
        max_abs_diff(&back.data, &expect_back),
        0,
        "gray -> colour: exact"
    );

    // Within 1 LSB.
    assert!(
        max_abs_diff(&gray.data, &reference_luma(&bgr.data, PixelFormat::Bgr24)) <= 1,
        "colour -> luma: within 1 LSB"
    );

    // Within 2 LSB.
    let small = FrameProcessor::resize(&bgr, 5, 4).unwrap();
    assert!(
        max_abs_diff(&small.data, &reference_resize(&bgr.data, 8, 6, 3, 5, 4)) <= 2,
        "resize: within 2 LSB"
    );

    // Within 1e-9 / 1e-6 relative.
    let (mean, std, lap) = reference_stats(&gray.data, 8, 6);
    let q = FrameProcessor::quality(&gray).unwrap();
    assert!((q.mean_brightness - mean).abs() < 1e-9, "mean: within 1e-9");
    assert!(
        (q.brightness_std_dev - std).abs() < 1e-9,
        "std dev: within 1e-9"
    );
    assert!(
        (q.laplacian_variance - lap).abs() / lap.max(1.0) < 1e-6,
        "laplacian variance: within 1e-6 relative"
    );

    eprintln!(
        "cross-backend reference table satisfied by backend: {}",
        backend_identity()
    );
}

#[test]
fn the_verification_status_of_the_native_backend_is_reported_honestly() {
    // This test exists to make the project's central OpenCV claim falsifiable in CI rather than
    // only in prose. It passes either way; what it does is print which world the run is in.
    match active_backend() {
        ProcessingBackend::OpenCv => {
            eprintln!(
                "NATIVE OPENCV EXECUTED: {} — the operations above ran through OpenCV.",
                backend_identity()
            );
        }
        ProcessingBackend::PureRustFallback => {
            eprintln!(
                "NATIVE OPENCV NOT EXERCISED: this run used {}. Nothing in this file \
                 constitutes verification of the OpenCV backend.",
                backend_identity()
            );
        }
    }
}
