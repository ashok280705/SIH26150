//! # Clock drift correction
//!
//! Computes and applies a recorder-clock correction from trusted external time
//! anchors, so a DVR whose internal clock is offset or drifting can be mapped onto
//! real time. This is the "Correct Clock Drift" step of the normalization stage.
//!
//! Forensic constraints:
//! * The correction is **derived from evidence** (anchor points), never guessed. With
//!   no anchors there is no correction, and the recorder time is left as-is with an
//!   Unknown/Uncorrected state — a clock is never silently assumed accurate.
//! * The raw and recorder-native times are untouched; a correction only produces a new
//!   normalized value alongside them (Req 4 separation of time fields).
//! * A single anchor yields a constant offset only (no drift is invented from one
//!   point). Two or more anchors yield a linear offset+drift fit with a reported
//!   residual, so the quality of the fit is visible.
//!
//! Model: `corrected(t) = t + offset_seconds + drift_rate * t`, where `t` is a Unix
//! epoch in seconds. This is exactly the intercept/slope of a least-squares line
//! `reference = a + b·recorder`, stored as `offset_seconds = a` and
//! `drift_rate = b - 1` (extra seconds of error per recorder second).

use forensic_core::{ClockCorrection, Provenance};
use serde::{Deserialize, Serialize};

/// A trusted (recorder_time, reference_time) correspondence used to fit the clock.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ClockAnchor {
    /// The recorder's own clock reading at the anchor moment, Unix epoch seconds.
    pub recorder_epoch_seconds: i64,
    /// The trusted external time for the same moment, Unix epoch seconds.
    pub reference_epoch_seconds: i64,
    /// Where the reference came from (e.g. "NTP log", "photographed wall clock").
    pub source: String,
}

/// Compute a clock correction from one or more anchors.
///
/// Returns `None` when there are no anchors (no basis for a correction). The supplied
/// `anchor_evidence` provenance is attached to the resulting correction so the
/// derivation is auditable.
pub fn compute_correction(
    anchors: &[ClockAnchor],
    anchor_evidence: Provenance,
) -> Option<ClockCorrection> {
    match anchors.len() {
        0 => None,
        1 => {
            let a = &anchors[0];
            let offset = a.reference_epoch_seconds - a.recorder_epoch_seconds;
            Some(ClockCorrection {
                method: format!("single-anchor constant offset from {}", a.source),
                anchor_evidence,
                offset_seconds: offset,
                drift_rate: None,
                residual_seconds: Some(0.0),
            })
        }
        _ => {
            // Least-squares fit reference = a + b·recorder.
            let n = anchors.len() as f64;
            let xs: Vec<f64> = anchors.iter().map(|a| a.recorder_epoch_seconds as f64).collect();
            let ys: Vec<f64> = anchors.iter().map(|a| a.reference_epoch_seconds as f64).collect();
            let mean_x = xs.iter().sum::<f64>() / n;
            let mean_y = ys.iter().sum::<f64>() / n;

            let mut sxx = 0.0;
            let mut sxy = 0.0;
            for i in 0..anchors.len() {
                let dx = xs[i] - mean_x;
                sxx += dx * dx;
                sxy += dx * (ys[i] - mean_y);
            }

            // Degenerate case: all anchors share one recorder time -> average offset,
            // no drift can be resolved.
            if sxx.abs() < f64::EPSILON {
                let offset = (mean_y - mean_x).round() as i64;
                return Some(ClockCorrection {
                    method: "multi-anchor average offset (recorder times coincident; drift unresolved)".into(),
                    anchor_evidence,
                    offset_seconds: offset,
                    drift_rate: None,
                    residual_seconds: None,
                });
            }

            let b = sxy / sxx; // slope
            let a = mean_y - b * mean_x; // intercept at recorder t = 0

            // Worst-case residual across the anchors.
            let mut max_resid = 0.0f64;
            for i in 0..anchors.len() {
                let predicted = a + b * xs[i];
                let resid = (predicted - ys[i]).abs();
                if resid > max_resid {
                    max_resid = resid;
                }
            }

            Some(ClockCorrection {
                method: format!("least-squares offset+drift fit over {} anchors", anchors.len()),
                anchor_evidence,
                offset_seconds: a.round() as i64,
                drift_rate: Some(b - 1.0),
                residual_seconds: Some(max_resid),
            })
        }
    }
}

/// Apply a correction to a recorder Unix-epoch time, returning corrected epoch seconds.
///
/// `corrected(t) = t + offset_seconds + drift_rate * t`.
pub fn apply_correction(recorder_epoch_seconds: i64, correction: &ClockCorrection) -> i64 {
    let t = recorder_epoch_seconds as f64;
    let drift = correction.drift_rate.unwrap_or(0.0);
    (t + correction.offset_seconds as f64 + drift * t).round() as i64
}

#[cfg(test)]
mod tests {
    use super::*;
    use forensic_core::{Hash, ValidationState};

    fn prov() -> Provenance {
        Provenance::new(
            forensic_core::EvidenceId::new(),
            Hash::sha256(vec![0; 32]),
            vec![],
            "test",
            "1.0",
            Hash::sha256(vec![0; 32]),
            ValidationState::pass("anchor", "trusted", "clock").unwrap(),
        )
    }

    #[test]
    fn no_anchors_yields_no_correction() {
        assert!(compute_correction(&[], prov()).is_none());
    }

    #[test]
    fn single_anchor_is_constant_offset() {
        // Recorder reads 1000, real time is 1120: clock is 120s slow.
        let anchors = vec![ClockAnchor {
            recorder_epoch_seconds: 1000,
            reference_epoch_seconds: 1120,
            source: "NTP".into(),
        }];
        let c = compute_correction(&anchors, prov()).unwrap();
        assert_eq!(c.offset_seconds, 120);
        assert!(c.drift_rate.is_none());
        // Applying it maps recorder 5000 -> 5120.
        assert_eq!(apply_correction(5000, &c), 5120);
    }

    #[test]
    fn two_anchors_resolve_drift() {
        // Recorder gains 1s per 100s: reference = recorder * 0.99 ... construct cleanly.
        // At recorder=0, real=100 (offset 100). At recorder=1000, real=1090 (drift -0.01/s).
        let anchors = vec![
            ClockAnchor { recorder_epoch_seconds: 0, reference_epoch_seconds: 100, source: "a".into() },
            ClockAnchor { recorder_epoch_seconds: 1000, reference_epoch_seconds: 1090, source: "b".into() },
        ];
        let c = compute_correction(&anchors, prov()).unwrap();
        assert_eq!(c.offset_seconds, 100);
        let drift = c.drift_rate.unwrap();
        assert!((drift - (-0.01)).abs() < 1e-9, "drift was {drift}");
        // corrected(500) = 500 + 100 + (-0.01)*500 = 595
        assert_eq!(apply_correction(500, &c), 595);
        // Residual should be ~0 for a perfect two-point line.
        assert!(c.residual_seconds.unwrap() < 1e-6);
    }

    #[test]
    fn perfect_clock_has_zero_offset_and_drift() {
        let anchors = vec![
            ClockAnchor { recorder_epoch_seconds: 1000, reference_epoch_seconds: 1000, source: "a".into() },
            ClockAnchor { recorder_epoch_seconds: 2000, reference_epoch_seconds: 2000, source: "b".into() },
        ];
        let c = compute_correction(&anchors, prov()).unwrap();
        assert_eq!(c.offset_seconds, 0);
        assert!(c.drift_rate.unwrap().abs() < 1e-9);
        assert_eq!(apply_correction(1500, &c), 1500);
    }

    #[test]
    fn noisy_anchors_report_residual() {
        // Three roughly-linear points with noise -> non-zero residual reported.
        let anchors = vec![
            ClockAnchor { recorder_epoch_seconds: 0, reference_epoch_seconds: 10, source: "a".into() },
            ClockAnchor { recorder_epoch_seconds: 100, reference_epoch_seconds: 115, source: "b".into() },
            ClockAnchor { recorder_epoch_seconds: 200, reference_epoch_seconds: 209, source: "c".into() },
        ];
        let c = compute_correction(&anchors, prov()).unwrap();
        assert!(c.drift_rate.is_some());
        assert!(c.residual_seconds.unwrap() > 0.0);
    }
}
