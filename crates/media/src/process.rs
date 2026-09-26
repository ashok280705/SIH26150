//! Image processing over decoded frames.
//!
//! Every operation here runs on real pixel data produced by [`crate::decode`]. Nothing in this
//! module synthesizes a frame.
//!
//! ## Why there are two backends
//!
//! The `opencv` crate links against a native OpenCV installation. A build host without it
//! cannot compile the dependency at all, so making it mandatory would make the whole workspace
//! unbuildable on some machines. It is therefore behind the **`opencv-backend`** cargo feature.
//!
//! The important property is that the two backends are never confused:
//!
//! * [`active_backend`] reports which one this binary was compiled with, and
//!   [`backend_identity`] reports it together with the native library's own version string.
//! * Every [`crate::frame::ProcessingStep`] records that identity, so a report can never claim
//!   OpenCV processed a frame that the fallback processed.
//! * [`FrameProcessor::require_backend`] lets a caller *demand* a specific backend and fail
//!   loudly when this build cannot provide it. [`crate::pipeline::ProcessingPlan`] exposes the
//!   same requirement, so the pipeline never silently substitutes one backend for the other.
//! * **Every** measurement is produced by the backend that is named. In particular the quality
//!   statistics below are computed by OpenCV under the OpenCV backend and by Rust under the
//!   fallback — the reported backend is never a label attached to someone else's arithmetic.
//!
//! The fallback is a genuine implementation, not a stub: it resizes bilinearly, converts colour
//! with the same BT.601 luma coefficients OpenCV uses, crops regions and computes quality
//! metrics. It exists so the pipeline is complete and testable on any host, not to stand in for
//! OpenCV in a claim.
//!
//! ## Equivalence between the backends, and its limits
//!
//! The two backends implement the *same contract*, not the same code. How closely their
//! numbers agree differs per operation, and the honest statement differs too:
//!
//! | Operation | Relationship | Status |
//! |---|---|---|
//! | Channel swap (`BGR24 ↔ RGB24`) | Byte-identical. A permutation of bytes has one answer. | Established by construction. |
//! | `GRAY8 → BGR24/RGB24` | Byte-identical. Replicating one channel has one answer. | Established by construction. |
//! | ROI crop | Byte-identical. Copying a sub-rectangle has one answer. | Established by construction. |
//! | `BGR24/RGB24 → GRAY8` | *Expected* byte-identical: both use BT.601 weights in Q14 fixed point with the same rounding (`(x + 1<<13) >> 14`). | **Expected, not demonstrated.** OpenCV's `COLOR_BGR2GRAY` has never been executed against this fallback — see below. Under SIMD/IPP dispatch OpenCV may differ by ±1 LSB. |
//! | Resize (`INTER_LINEAR`) | Approximately equal, **≈ ±2 LSB** per channel. | Expected, not demonstrated. The fallback interpolates in `f64` and rounds half-up; OpenCV uses 5-bit fixed-point weights. The half-pixel-centred sampling grid is the same, so the difference is quantisation, not geometry. |
//! | Luma mean / standard deviation | Same definition (population, not sample), both in `f64`. Relative agreement ≈ `1e-9`. | Expected, not demonstrated. |
//! | Laplacian variance | Same 3×3 kernel over the **interior only** (see [`FrameQuality::laplacian_variance`]). Relative agreement ≈ `1e-9`. | Expected, not demonstrated. |
//!
//! "Expected, not demonstrated" means exactly that: the implementations were written to the
//! same definition, but no machine has yet run both and compared them. The comparison test
//! exists — `crates/media/tests/frame_processing_backend.rs` — and reports `SKIPPED` rather
//! than passing when the OpenCV backend is not compiled in. It has never reported anything
//! else. See `docs/MEDIA_PIPELINE_VERIFICATION.md`.
//!
//! ## Determinism
//!
//! The fallback is deterministic outright: integer and `f64` arithmetic with a fixed evaluation
//! order and no dispatch.
//!
//! The OpenCV backend is *constrained* toward determinism, which is a weaker and more specific
//! claim. What is actually controlled is documented on [`backend_identity`]. This does not make
//! the application globally deterministic and is not offered as such.

use crate::error::{MediaError, MediaErrorKind, MediaResult};
use crate::frame::{PixelFormat, ProcessingStep, VideoFrame};
use serde::{Deserialize, Serialize};
use std::borrow::Cow;

/// Which implementation performs image operations in this build.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ProcessingBackend {
    OpenCv,
    PureRustFallback,
}

impl ProcessingBackend {
    /// The short, stable token for this backend, without any version information.
    pub fn label(&self) -> &'static str {
        match self {
            Self::OpenCv => "opencv",
            Self::PureRustFallback => "pure_rust_fallback",
        }
    }
}

/// The capability token this build advertises for image processing.
#[cfg(feature = "opencv-backend")]
pub const BACKEND_CAPABILITY: &str = "opencv_frame_processing";
/// The capability token this build advertises for image processing.
#[cfg(not(feature = "opencv-backend"))]
pub const BACKEND_CAPABILITY: &str = "fallback_frame_processing";

/// The backend compiled into this binary.
pub const fn active_backend() -> ProcessingBackend {
    #[cfg(feature = "opencv-backend")]
    {
        ProcessingBackend::OpenCv
    }
    #[cfg(not(feature = "opencv-backend"))]
    {
        ProcessingBackend::PureRustFallback
    }
}

/// The backend identity recorded on every processed frame.
///
/// This is what makes a processing step reproducible: `"pure_rust_fallback"` identifies code in
/// this repository at a known revision, and `"opencv <version> (single-threaded)"` identifies
/// the native library that actually ran, read from OpenCV itself at runtime. No version is ever
/// guessed or hard-coded; if OpenCV declines to report one, the identity says
/// `"opencv (version unreported)"` rather than inventing a number.
///
/// ## What "(single-threaded)" asserts, precisely
///
/// On first use the OpenCV backend calls `cv::setNumThreads(1)`, removing the thread-count
/// dependence of OpenCV's parallel loops. Combined with this module's exclusive use of `Mat`
/// (never `UMat`, the only type through which OpenCV dispatches to OpenCL), that pins the two
/// sources of run-to-run variation this module could otherwise be exposed to.
///
/// It asserts nothing beyond that. It does **not** claim the application is globally
/// deterministic, and it does not eliminate differences between two *different* OpenCV builds —
/// SIMD and IPP code paths are selected at build time, which is precisely why the version
/// string is recorded alongside it. If the thread-count call fails, the suffix is omitted and
/// the identity reads `"opencv <version>"`, so the provenance never claims a configuration that
/// was not applied.
pub fn backend_identity() -> &'static str {
    backend::identity()
}

/// A rectangular region of interest, in pixels.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct Roi {
    pub x: u32,
    pub y: u32,
    pub width: u32,
    pub height: u32,
}

impl Roi {
    /// Checks the region lies wholly inside `(frame_w, frame_h)`.
    ///
    /// A region that overruns the frame is rejected rather than clamped: silently shrinking an
    /// examiner's requested region would change what was analysed without saying so.
    pub fn validate(&self, frame_w: u32, frame_h: u32) -> MediaResult<()> {
        if self.width == 0 || self.height == 0 {
            return Err(MediaError::new(
                MediaErrorKind::InvalidConfiguration,
                "Roi::validate",
                format!("region {}x{} has no pixels", self.width, self.height),
            ));
        }
        let right = self.x.checked_add(self.width);
        let bottom = self.y.checked_add(self.height);
        match (right, bottom) {
            (Some(r), Some(b)) if r <= frame_w && b <= frame_h => Ok(()),
            _ => Err(MediaError::new(
                MediaErrorKind::InvalidConfiguration,
                "Roi::validate",
                format!(
                    "region ({},{}) {}x{} does not fit inside a {frame_w}x{frame_h} frame",
                    self.x, self.y, self.width, self.height
                ),
            )),
        }
    }
}

/// Luma statistics, as computed by whichever backend is active.
///
/// Split out from [`FrameQuality`] because this is the part each backend computes itself. The
/// definitions both backends implement:
///
/// * `mean` — arithmetic mean of the luma plane.
/// * `std_dev` — **population** standard deviation (divisor `N`, not `N-1`).
/// * `laplacian_variance` — population variance of the 3×3 Laplacian, evaluated over the
///   **interior** pixels only (`1..w-1`, `1..h-1`), i.e. with no border extrapolation. Zero for
///   a frame narrower or shorter than three pixels, which has no interior.
#[derive(Debug, Clone, Copy, PartialEq)]
pub(crate) struct LumaStats {
    pub mean: f64,
    pub std_dev: f64,
    pub laplacian_variance: f64,
}

/// Measured image-quality indicators for one frame.
#[derive(Debug, Clone, Copy, PartialEq, Serialize, Deserialize)]
pub struct FrameQuality {
    pub width: u32,
    pub height: u32,
    /// Mean luma in 0..=255.
    pub mean_brightness: f64,
    /// Population standard deviation of luma. Near zero means a flat, featureless picture.
    pub brightness_std_dev: f64,
    /// Variance of the 3x3 Laplacian over luma. Low values indicate blur or a flat frame.
    ///
    /// Evaluated over interior pixels only, with no border extrapolation, so that the value
    /// depends on the picture rather than on a choice of border convention. A frame with no
    /// interior (either dimension below three pixels) yields `0.0`.
    pub laplacian_variance: f64,
    /// Whether the frame carries any tonal variation at all.
    ///
    /// A uniformly flat frame is still a real decoded frame; this flags it for an examiner
    /// rather than discarding it.
    pub has_tonal_variation: bool,
    /// The backend that computed the numbers above — not merely the one this build has.
    pub backend: ProcessingBackend,
}

/// Reusable image operations over standardized frames.
pub struct FrameProcessor;

impl FrameProcessor {
    /// Fails with `OPENCV_UNAVAILABLE` unless this build has the OpenCV backend.
    ///
    /// Retained for callers that specifically need the real thing; it is
    /// [`Self::require_backend`] specialised to [`ProcessingBackend::OpenCv`].
    pub fn require_opencv(operation: &str) -> MediaResult<()> {
        Self::require_backend(ProcessingBackend::OpenCv, operation)
    }

    /// Fails unless `required` is the backend this build will actually use.
    ///
    /// Both directions are enforced. Asking for OpenCV on a build without it yields
    /// `OPENCV_UNAVAILABLE`; asking for the fallback on an OpenCV build yields
    /// `INVALID_CONFIGURATION`, because on such a build the fallback is not compiled and
    /// running OpenCV instead would be exactly the silent substitution this exists to prevent.
    pub fn require_backend(required: ProcessingBackend, operation: &str) -> MediaResult<()> {
        let active = active_backend();
        if required == active {
            return Ok(());
        }
        match required {
            ProcessingBackend::OpenCv => Err(MediaError::new(
                MediaErrorKind::OpencvUnavailable,
                operation,
                "the OpenCV backend was explicitly required, but this binary was built without \
                 the `opencv-backend` feature; no OpenCV operation was performed and none was \
                 substituted",
            )),
            ProcessingBackend::PureRustFallback => Err(MediaError::new(
                MediaErrorKind::InvalidConfiguration,
                operation,
                "the pure-Rust fallback backend was explicitly required, but this binary was \
                 built with the `opencv-backend` feature and the fallback is not compiled into \
                 it; OpenCV was not substituted",
            )),
        }
    }

    /// Rescales a frame to exact dimensions.
    pub fn resize(frame: &VideoFrame, width: u32, height: u32) -> MediaResult<VideoFrame> {
        if width == 0 || height == 0 {
            return Err(MediaError::new(
                MediaErrorKind::InvalidConfiguration,
                "resize",
                format!("target {width}x{height} has no pixels"),
            ));
        }
        check_buffer(
            "resize",
            &frame.data,
            frame.width,
            frame.height,
            frame.pixel_format,
        )?;
        let data = backend::resize(
            &frame.data,
            frame.width,
            frame.height,
            frame.pixel_format,
            width,
            height,
        )?;
        check_buffer("resize", &data, width, height, frame.pixel_format)?;
        derive(
            frame,
            width,
            height,
            frame.pixel_format,
            data,
            ProcessingStep {
                operation: "resize".into(),
                parameters: format!("{}x{} -> {width}x{height}", frame.width, frame.height),
                backend: backend_identity().into(),
            },
        )
    }

    /// Converts a frame's pixel layout.
    pub fn convert_color(frame: &VideoFrame, target: PixelFormat) -> MediaResult<VideoFrame> {
        if frame.pixel_format == target {
            return Ok(frame.clone());
        }
        check_buffer(
            "cvt_color",
            &frame.data,
            frame.width,
            frame.height,
            frame.pixel_format,
        )?;
        let data = backend::convert_color(
            &frame.data,
            frame.width,
            frame.height,
            frame.pixel_format,
            target,
        )?;
        check_buffer("cvt_color", &data, frame.width, frame.height, target)?;
        derive(
            frame,
            frame.width,
            frame.height,
            target,
            data,
            ProcessingStep {
                operation: "cvt_color".into(),
                parameters: format!("{:?} -> {:?}", frame.pixel_format, target),
                backend: backend_identity().into(),
            },
        )
    }

    /// Extracts a region of interest as a frame in its own right.
    pub fn crop_roi(frame: &VideoFrame, roi: Roi) -> MediaResult<VideoFrame> {
        roi.validate(frame.width, frame.height)?;
        check_buffer(
            "roi",
            &frame.data,
            frame.width,
            frame.height,
            frame.pixel_format,
        )?;
        let data = backend::crop(
            &frame.data,
            frame.width,
            frame.height,
            frame.pixel_format,
            roi,
        )?;
        check_buffer("roi", &data, roi.width, roi.height, frame.pixel_format)?;
        derive(
            frame,
            roi.width,
            roi.height,
            frame.pixel_format,
            data,
            ProcessingStep {
                operation: "roi".into(),
                parameters: format!("({},{}) {}x{}", roi.x, roi.y, roi.width, roi.height),
                backend: backend_identity().into(),
            },
        )
    }

    /// Computes image-quality indicators over the frame's luma.
    ///
    /// The statistics are computed by the active backend, and [`FrameQuality::backend`] names
    /// that backend truthfully: under `opencv-backend` OpenCV itself produces every number
    /// here, not merely the colour conversion that precedes them.
    pub fn quality(frame: &VideoFrame) -> MediaResult<FrameQuality> {
        check_buffer(
            "quality",
            &frame.data,
            frame.width,
            frame.height,
            frame.pixel_format,
        )?;
        // An already-grayscale frame is measured in place. Cloning it, as this used to, copied
        // the whole picture once per frame for no purpose.
        let luma: Cow<'_, [u8]> = match frame.pixel_format {
            PixelFormat::Gray8 => Cow::Borrowed(frame.data.as_slice()),
            other => Cow::Owned(backend::convert_color(
                &frame.data,
                frame.width,
                frame.height,
                other,
                PixelFormat::Gray8,
            )?),
        };

        if luma.is_empty() {
            return Err(MediaError::new(
                MediaErrorKind::InvalidFrame,
                "quality",
                "frame has no pixels",
            ));
        }

        let stats = backend::luma_stats(&luma, frame.width, frame.height)?;
        Ok(FrameQuality {
            width: frame.width,
            height: frame.height,
            mean_brightness: stats.mean,
            brightness_std_dev: stats.std_dev,
            laplacian_variance: stats.laplacian_variance,
            has_tonal_variation: stats.std_dev * stats.std_dev > f64::EPSILON,
            backend: active_backend(),
        })
    }

    /// Selects frames from a decoded sequence by a reusable policy.
    ///
    /// Sampling during decoding (see [`crate::decode::ExtractionMode`]) is cheaper and should be
    /// preferred; this exists for selecting within an already-decoded set, where re-decoding
    /// would be wasteful.
    pub fn select_every_nth(frames: &[VideoFrame], n: usize) -> MediaResult<Vec<&VideoFrame>> {
        if n == 0 {
            return Err(MediaError::new(
                MediaErrorKind::InvalidConfiguration,
                "select_every_nth",
                "a selection interval of 0 selects no frames",
            ));
        }
        Ok(frames.iter().step_by(n).collect())
    }
}

/// Checks a buffer against a declared geometry before it reaches a backend.
///
/// Both backends index this buffer arithmetically; a length that disagrees with the geometry is
/// a structural fault in the frame and is caught here, once, rather than becoming an
/// out-of-bounds panic in the fallback or an opaque `Mat` construction error under OpenCV.
fn check_buffer(
    operation: &'static str,
    data: &[u8],
    width: u32,
    height: u32,
    fmt: PixelFormat,
) -> MediaResult<()> {
    let expected = fmt.frame_len(width, height).ok_or_else(|| {
        MediaError::new(
            MediaErrorKind::InvalidFrame,
            operation,
            format!("frame geometry {width}x{height} overflows an address"),
        )
    })?;
    if expected == 0 {
        return Err(MediaError::new(
            MediaErrorKind::InvalidFrame,
            operation,
            format!("frame geometry {width}x{height} has no pixels"),
        ));
    }
    if data.len() != expected {
        return Err(MediaError::new(
            MediaErrorKind::InvalidFrame,
            operation,
            format!(
                "buffer is {} bytes but {width}x{height} {fmt:?} requires {expected}",
                data.len()
            ),
        ));
    }
    Ok(())
}

/// Builds a derived frame that keeps the source frame's identity and provenance chain.
///
/// The frame id, artifact id, index and timing are carried over verbatim, and the new
/// processing step is appended. A processed frame therefore still traces to the same decoded
/// frame, the same media artifact and the same evidence.
fn derive(
    source: &VideoFrame,
    width: u32,
    height: u32,
    pixel_format: PixelFormat,
    data: Vec<u8>,
    step: ProcessingStep,
) -> MediaResult<VideoFrame> {
    let mut provenance = source.provenance.clone();
    provenance.processing_chain.push(step);
    VideoFrame::new(
        source.artifact_id.clone(),
        source.frame_index,
        width,
        height,
        pixel_format,
        data,
        source.timing.clone(),
        provenance,
    )
}

/// The pure-Rust backend. Compiled when `opencv-backend` is off.
#[cfg(not(feature = "opencv-backend"))]
mod backend {
    use super::*;

    pub(super) fn identity() -> &'static str {
        "pure_rust_fallback"
    }

    pub(super) fn resize(
        data: &[u8],
        src_w: u32,
        src_h: u32,
        fmt: PixelFormat,
        dst_w: u32,
        dst_h: u32,
    ) -> MediaResult<Vec<u8>> {
        let ch = fmt.channels();
        let (sw, sh) = (src_w as usize, src_h as usize);
        let (dw, dh) = (dst_w as usize, dst_h as usize);
        let mut out = vec![0u8; dw * dh * ch];

        // Bilinear over a half-pixel-centred grid: the same sampling convention OpenCV's
        // INTER_LINEAR uses, so the two backends agree to within the quantisation difference
        // documented at the top of this module. Both are deterministic.
        let scale_x = sw as f64 / dw as f64;
        let scale_y = sh as f64 / dh as f64;
        for y in 0..dh {
            let fy = ((y as f64 + 0.5) * scale_y - 0.5).max(0.0);
            let y0 = (fy.floor() as usize).min(sh - 1);
            let y1 = (y0 + 1).min(sh - 1);
            let wy = fy - y0 as f64;
            for x in 0..dw {
                let fx = ((x as f64 + 0.5) * scale_x - 0.5).max(0.0);
                let x0 = (fx.floor() as usize).min(sw - 1);
                let x1 = (x0 + 1).min(sw - 1);
                let wx = fx - x0 as f64;
                for c in 0..ch {
                    let p00 = data[(y0 * sw + x0) * ch + c] as f64;
                    let p01 = data[(y0 * sw + x1) * ch + c] as f64;
                    let p10 = data[(y1 * sw + x0) * ch + c] as f64;
                    let p11 = data[(y1 * sw + x1) * ch + c] as f64;
                    let top = p00 + (p01 - p00) * wx;
                    let bottom = p10 + (p11 - p10) * wx;
                    let v = top + (bottom - top) * wy;
                    out[(y * dw + x) * ch + c] = v.round().clamp(0.0, 255.0) as u8;
                }
            }
        }
        Ok(out)
    }

    pub(super) fn convert_color(
        data: &[u8],
        width: u32,
        height: u32,
        from: PixelFormat,
        to: PixelFormat,
    ) -> MediaResult<Vec<u8>> {
        let px = width as usize * height as usize;
        match (from, to) {
            (PixelFormat::Bgr24, PixelFormat::Rgb24) | (PixelFormat::Rgb24, PixelFormat::Bgr24) => {
                let mut out = vec![0u8; px * 3];
                for i in 0..px {
                    out[i * 3] = data[i * 3 + 2];
                    out[i * 3 + 1] = data[i * 3 + 1];
                    out[i * 3 + 2] = data[i * 3];
                }
                Ok(out)
            }
            (PixelFormat::Bgr24, PixelFormat::Gray8) | (PixelFormat::Rgb24, PixelFormat::Gray8) => {
                // BT.601 luma in the same Q14 fixed point OpenCV's COLOR_BGR2GRAY uses. The two
                // backends are therefore *expected* to agree byte for byte; that expectation is
                // asserted by the cross-backend test and has not yet been observed to hold,
                // because no host has run both. See the module docs.
                const R: u32 = 4899; // 0.299 * 2^14
                const G: u32 = 9617; // 0.587 * 2^14
                const B: u32 = 1868; // 0.114 * 2^14
                let (ri, bi) = match from {
                    PixelFormat::Bgr24 => (2usize, 0usize),
                    _ => (0usize, 2usize),
                };
                let mut out = vec![0u8; px];
                for i in 0..px {
                    let r = data[i * 3 + ri] as u32;
                    let g = data[i * 3 + 1] as u32;
                    let b = data[i * 3 + bi] as u32;
                    out[i] = (((r * R + g * G + b * B) + (1 << 13)) >> 14) as u8;
                }
                Ok(out)
            }
            (PixelFormat::Gray8, PixelFormat::Bgr24) | (PixelFormat::Gray8, PixelFormat::Rgb24) => {
                let mut out = vec![0u8; px * 3];
                for i in 0..px {
                    let v = data[i];
                    out[i * 3] = v;
                    out[i * 3 + 1] = v;
                    out[i * 3 + 2] = v;
                }
                Ok(out)
            }
            (a, b) if a == b => Ok(data.to_vec()),
            (a, b) => Err(unsupported_conversion(a, b)),
        }
    }

    pub(super) fn crop(
        data: &[u8],
        src_w: u32,
        _src_h: u32,
        fmt: PixelFormat,
        roi: Roi,
    ) -> MediaResult<Vec<u8>> {
        let ch = fmt.channels();
        let sw = src_w as usize;
        let mut out = Vec::with_capacity(roi.width as usize * roi.height as usize * ch);
        for y in 0..roi.height as usize {
            let row = (roi.y as usize + y) * sw + roi.x as usize;
            let start = row * ch;
            let end = start + roi.width as usize * ch;
            out.extend_from_slice(&data[start..end]);
        }
        Ok(out)
    }

    pub(super) fn luma_stats(luma: &[u8], width: u32, height: u32) -> MediaResult<LumaStats> {
        let n = luma.len() as f64;
        let sum: f64 = luma.iter().map(|&v| v as f64).sum();
        let mean = sum / n;
        let variance = luma
            .iter()
            .map(|&v| {
                let d = v as f64 - mean;
                d * d
            })
            .sum::<f64>()
            / n;
        Ok(LumaStats {
            mean,
            std_dev: variance.sqrt(),
            laplacian_variance: laplacian_variance(luma, width, height),
        })
    }

    /// Population variance of the 3x3 Laplacian over interior pixels, the standard focus/blur
    /// indicator. Border pixels are excluded rather than extrapolated, so the result does not
    /// depend on a border convention. See [`LumaStats`].
    fn laplacian_variance(luma: &[u8], width: u32, height: u32) -> f64 {
        let (w, h) = (width as usize, height as usize);
        if w < 3 || h < 3 {
            return 0.0;
        }
        let mut sum = 0.0f64;
        let mut sum_sq = 0.0f64;
        let mut count = 0.0f64;
        for y in 1..h - 1 {
            for x in 1..w - 1 {
                let c = luma[y * w + x] as i32;
                let lap = (luma[(y - 1) * w + x] as i32
                    + luma[(y + 1) * w + x] as i32
                    + luma[y * w + x - 1] as i32
                    + luma[y * w + x + 1] as i32
                    - 4 * c) as f64;
                sum += lap;
                sum_sq += lap * lap;
                count += 1.0;
            }
        }
        if count == 0.0 {
            return 0.0;
        }
        let mean = sum / count;
        (sum_sq / count) - mean * mean
    }
}

/// The OpenCV backend. Compiled when `opencv-backend` is on.
///
/// Every operation wraps the frame buffer in a `Mat` **without copying it** and calls the
/// corresponding OpenCV function, so a frame processed here has genuinely passed through
/// OpenCV — including the quality statistics, which are `cv::meanStdDev` and `cv::Laplacian`
/// rather than Rust arithmetic wearing an OpenCV label.
#[cfg(feature = "opencv-backend")]
mod backend {
    use super::*;
    use opencv::boxed_ref::BoxedRef;
    use opencv::core::{Mat, MatTraitConst, Rect, Size, Vec3b};
    use opencv::imgproc;
    use std::sync::OnceLock;

    /// Cached backend identity, including the native library's own version string.
    ///
    /// Built once. The determinism configuration is applied in the same initialisation so the
    /// identity can only report a setting that was actually applied.
    pub(super) fn identity() -> &'static str {
        static IDENTITY: OnceLock<String> = OnceLock::new();
        IDENTITY.get_or_init(|| {
            // Read the version from OpenCV rather than from the `opencv` crate's own version:
            // what matters forensically is the library that executes, not the binding.
            let version = opencv::core::get_version_string()
                .ok()
                .filter(|v| !v.trim().is_empty());

            // Pin OpenCV's parallel loops to a single thread. This removes the run-to-run
            // variation that a thread-count-dependent reduction could introduce. It is
            // process-global OpenCV state and is set once, here.
            //
            // OpenCL needs no corresponding call: OpenCV dispatches to it only through `UMat`,
            // and this module uses `Mat` exclusively.
            let single_threaded = opencv::core::set_num_threads(1).is_ok();

            match (version, single_threaded) {
                (Some(v), true) => format!("opencv {v} (single-threaded)"),
                (Some(v), false) => format!("opencv {v}"),
                (None, true) => "opencv (version unreported, single-threaded)".to_string(),
                (None, false) => "opencv (version unreported)".to_string(),
            }
        })
    }

    fn cv_err(op: &'static str) -> impl Fn(opencv::Error) -> MediaError {
        move |e| {
            // OPENCV_OPERATION_FAILED, never INVALID_FRAME: OpenCV failing is a fact about this
            // host's image library, not about the evidence.
            MediaError::new(
                MediaErrorKind::OpencvOperationFailed,
                op,
                format!("OpenCV operation failed: {e}"),
            )
        }
    }

    /// Wraps a packed frame buffer as a `Mat` of the correct type, **borrowing** the pixels.
    ///
    /// `new_rows_cols_with_bytes::<T>` constructs the `Mat` at the right type directly
    /// (`CV_8UC1` for `u8`, `CV_8UC3` for `Vec3b`), so there is no reshape and no copy. The
    /// returned `BoxedRef` borrows `data` for its lifetime, which is what keeps the pixels
    /// alive for exactly as long as OpenCV may read them.
    ///
    /// Rows are `width * channels` bytes with no padding — FFmpeg's `-f rawvideo` output is
    /// tightly packed, and [`super::check_buffer`] has already confirmed the exact length — so
    /// the `Mat`'s stride matches the buffer's and no row-alignment adjustment is needed.
    fn as_mat<'a>(
        data: &'a [u8],
        width: u32,
        height: u32,
        fmt: PixelFormat,
    ) -> MediaResult<BoxedRef<'a, Mat>> {
        let (rows, cols) = (height as i32, width as i32);
        match fmt.channels() {
            1 => Mat::new_rows_cols_with_data::<u8>(rows, cols, data)
                .map_err(cv_err("mat_wrap_gray8")),
            3 => Mat::new_rows_cols_with_bytes::<Vec3b>(rows, cols, data)
                .map_err(cv_err("mat_wrap_bgr24")),
            n => Err(MediaError::new(
                MediaErrorKind::InvalidConfiguration,
                "mat_wrap",
                format!("{n}-channel frames are not supported by this backend"),
            )),
        }
    }

    /// Copies a `Mat`'s pixels out as a packed byte buffer.
    ///
    /// `data_bytes` refuses a non-continuous `Mat`, so a view (an ROI) must be materialised
    /// before it reaches here; that is the one copy this backend cannot avoid, because the
    /// caller's contract is a packed buffer.
    fn mat_bytes(m: &Mat) -> MediaResult<Vec<u8>> {
        Ok(m.data_bytes().map_err(cv_err("mat_data_bytes"))?.to_vec())
    }

    pub(super) fn resize(
        data: &[u8],
        src_w: u32,
        src_h: u32,
        fmt: PixelFormat,
        dst_w: u32,
        dst_h: u32,
    ) -> MediaResult<Vec<u8>> {
        let _ = identity(); // ensure the determinism configuration is applied before any work
        let src = as_mat(data, src_w, src_h, fmt)?;
        let mut dst = Mat::default();
        imgproc::resize(
            &src,
            &mut dst,
            Size::new(dst_w as i32, dst_h as i32),
            0.0,
            0.0,
            imgproc::INTER_LINEAR,
        )
        .map_err(cv_err("imgproc_resize"))?;
        mat_bytes(&dst)
    }

    pub(super) fn convert_color(
        data: &[u8],
        width: u32,
        height: u32,
        from: PixelFormat,
        to: PixelFormat,
    ) -> MediaResult<Vec<u8>> {
        let code = match (from, to) {
            (PixelFormat::Bgr24, PixelFormat::Rgb24) => imgproc::COLOR_BGR2RGB,
            (PixelFormat::Rgb24, PixelFormat::Bgr24) => imgproc::COLOR_RGB2BGR,
            (PixelFormat::Bgr24, PixelFormat::Gray8) => imgproc::COLOR_BGR2GRAY,
            (PixelFormat::Rgb24, PixelFormat::Gray8) => imgproc::COLOR_RGB2GRAY,
            (PixelFormat::Gray8, PixelFormat::Bgr24) => imgproc::COLOR_GRAY2BGR,
            (PixelFormat::Gray8, PixelFormat::Rgb24) => imgproc::COLOR_GRAY2RGB,
            (a, b) if a == b => return Ok(data.to_vec()),
            (a, b) => return Err(unsupported_conversion(a, b)),
        };
        let _ = identity();
        let src = as_mat(data, width, height, from)?;
        let mut dst = Mat::default();
        // `cvt_color_def` takes OpenCV's own defaults for `dstCn` (derive from the code) and,
        // on versions that have it, the algorithm hint. Spelling those out here would pin this
        // code to one OpenCV release for no gain.
        imgproc::cvt_color_def(&src, &mut dst, code).map_err(cv_err("imgproc_cvt_color"))?;
        mat_bytes(&dst)
    }

    pub(super) fn crop(
        data: &[u8],
        src_w: u32,
        src_h: u32,
        fmt: PixelFormat,
        roi: Roi,
    ) -> MediaResult<Vec<u8>> {
        let _ = identity();
        let src = as_mat(data, src_w, src_h, fmt)?;
        let region = Mat::roi(
            &*src,
            Rect::new(
                roi.x as i32,
                roi.y as i32,
                roi.width as i32,
                roi.height as i32,
            ),
        )
        .map_err(cv_err("mat_roi"))?;
        // A ROI view shares the source's stride and is therefore not continuous; cloning
        // materialises the cropped pixels as a packed buffer, which is the caller's contract.
        let owned = region.try_clone().map_err(cv_err("roi_clone"))?;
        mat_bytes(&owned)
    }

    pub(super) fn luma_stats(luma: &[u8], width: u32, height: u32) -> MediaResult<LumaStats> {
        let _ = identity();
        let src = as_mat(luma, width, height, PixelFormat::Gray8)?;

        // `cv::meanStdDev` computes the POPULATION standard deviation (divisor N), which is the
        // definition the fallback implements too.
        let (mean, std_dev) = mean_std_dev(&*src, "meanstddev_luma")?;

        // The Laplacian, then its variance over the interior only. OpenCV extrapolates the
        // border (BORDER_DEFAULT); cropping the interior away discards those extrapolated
        // pixels so that this matches the fallback's definition exactly rather than
        // approximately. A frame with no interior has no Laplacian to speak of.
        let laplacian_variance = if width < 3 || height < 3 {
            0.0
        } else {
            let mut lap = Mat::default();
            imgproc::laplacian(
                &*src,
                &mut lap,
                opencv::core::CV_64F,
                1,   // ksize 1 selects the 3x3 kernel [[0,1,0],[1,-4,1],[0,1,0]]
                1.0, // scale
                0.0, // delta
                opencv::core::BORDER_DEFAULT,
            )
            .map_err(cv_err("imgproc_laplacian"))?;
            let interior = Mat::roi(&lap, Rect::new(1, 1, width as i32 - 2, height as i32 - 2))
                .map_err(cv_err("laplacian_interior_roi"))?;
            let (_, lap_std) = mean_std_dev(&*interior, "meanstddev_laplacian")?;
            lap_std * lap_std
        };

        Ok(LumaStats {
            mean,
            std_dev,
            laplacian_variance,
        })
    }

    /// `cv::meanStdDev` over a single-channel `Mat`, returning channel 0.
    fn mean_std_dev(m: &Mat, op: &'static str) -> MediaResult<(f64, f64)> {
        let mut mean = Mat::default();
        let mut stddev = Mat::default();
        opencv::core::mean_std_dev_def(m, &mut mean, &mut stddev).map_err(cv_err(op))?;
        let mean_v = *mean.at_2d::<f64>(0, 0).map_err(cv_err(op))?;
        let std_v = *stddev.at_2d::<f64>(0, 0).map_err(cv_err(op))?;
        Ok((mean_v, std_v))
    }
}

/// The single error both backends raise for a conversion neither implements.
///
/// An unsupported conversion is a property of the *request*, not of the host or the evidence,
/// so it is `INVALID_CONFIGURATION` under either backend. Keeping one constructor is what makes
/// that identical rather than merely similar.
fn unsupported_conversion(from: PixelFormat, to: PixelFormat) -> MediaError {
    MediaError::new(
        MediaErrorKind::InvalidConfiguration,
        "convert_color",
        format!("no conversion from {from:?} to {to:?}"),
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::frame::{FrameProvenance, FrameTiming};
    use forensic_core::EvidenceId;

    fn frame(width: u32, height: u32, fmt: PixelFormat, data: Vec<u8>) -> VideoFrame {
        VideoFrame::new(
            "art-1",
            3,
            width,
            height,
            fmt,
            data,
            FrameTiming::from_offset(Some(0.12), crate::frame::TimestampSource::Pts, None),
            FrameProvenance {
                evidence_id: EvidenceId::new(),
                artifact_id: "art-1".into(),
                artifact_source_offset: Some(4096),
                source_recording_id: Some("rec-9".into()),
                artifact_media_hash: Some("abc".into()),
                decoder: "ffmpeg rawvideo".into(),
                processing_chain: vec![],
            },
        )
        .unwrap()
    }

    /// A 2x2 BGR frame with four distinct colours.
    fn bgr_2x2() -> VideoFrame {
        frame(
            2,
            2,
            PixelFormat::Bgr24,
            vec![
                255, 0, 0, // blue
                0, 255, 0, // green
                0, 0, 255, // red
                255, 255, 255, // white
            ],
        )
    }

    #[test]
    fn resize_produces_the_requested_geometry_and_a_correctly_sized_buffer() {
        let out = FrameProcessor::resize(&bgr_2x2(), 4, 4).unwrap();
        assert_eq!((out.width, out.height), (4, 4));
        assert_eq!(out.data.len(), 4 * 4 * 3);
        assert_eq!(out.pixel_format, PixelFormat::Bgr24);
    }

    #[test]
    fn resize_is_deterministic() {
        let a = FrameProcessor::resize(&bgr_2x2(), 7, 5).unwrap();
        let b = FrameProcessor::resize(&bgr_2x2(), 7, 5).unwrap();
        assert_eq!(a.data, b.data);
        assert_eq!(a.content_hash().hex, b.content_hash().hex);
    }

    #[test]
    fn a_zero_target_size_is_rejected() {
        assert_eq!(
            FrameProcessor::resize(&bgr_2x2(), 0, 4).unwrap_err().kind,
            MediaErrorKind::InvalidConfiguration
        );
    }

    #[test]
    fn bgr_to_rgb_swaps_the_outer_channels() {
        let out = FrameProcessor::convert_color(&bgr_2x2(), PixelFormat::Rgb24).unwrap();
        assert_eq!(out.pixel_format, PixelFormat::Rgb24);
        // The blue pixel BGR(255,0,0) becomes RGB(0,0,255).
        assert_eq!(&out.data[0..3], &[0, 0, 255]);
        // The red pixel BGR(0,0,255) becomes RGB(255,0,0).
        assert_eq!(&out.data[6..9], &[255, 0, 0]);
    }

    #[test]
    fn bgr_to_gray_uses_bt601_luma_weights() {
        let out = FrameProcessor::convert_color(&bgr_2x2(), PixelFormat::Gray8).unwrap();
        assert_eq!(out.pixel_format, PixelFormat::Gray8);
        assert_eq!(out.data.len(), 4);
        // 0.114*255 = 29.07, 0.587*255 = 149.7, 0.299*255 = 76.2, white = 255.
        assert_eq!(out.data, vec![29, 150, 76, 255]);
    }

    #[test]
    fn gray_expands_back_to_three_equal_channels() {
        let gray = frame(2, 1, PixelFormat::Gray8, vec![10, 200]);
        let out = FrameProcessor::convert_color(&gray, PixelFormat::Bgr24).unwrap();
        assert_eq!(out.data, vec![10, 10, 10, 200, 200, 200]);
    }

    #[test]
    fn converting_to_the_same_format_is_a_no_op_that_adds_no_processing_step() {
        let f = bgr_2x2();
        let out = FrameProcessor::convert_color(&f, PixelFormat::Bgr24).unwrap();
        assert_eq!(out.data, f.data);
        assert!(out.provenance.processing_chain.is_empty());
    }

    #[test]
    fn roi_extracts_exactly_the_requested_region() {
        // A 3x3 grayscale ramp.
        let f = frame(
            3,
            3,
            PixelFormat::Gray8,
            vec![0, 1, 2, 10, 11, 12, 20, 21, 22],
        );
        let out = FrameProcessor::crop_roi(
            &f,
            Roi {
                x: 1,
                y: 1,
                width: 2,
                height: 2,
            },
        )
        .unwrap();
        assert_eq!((out.width, out.height), (2, 2));
        assert_eq!(out.data, vec![11, 12, 21, 22]);
    }

    #[test]
    fn a_roi_that_overruns_the_frame_is_rejected_not_clamped() {
        let f = bgr_2x2();
        let err = FrameProcessor::crop_roi(
            &f,
            Roi {
                x: 1,
                y: 1,
                width: 5,
                height: 5,
            },
        )
        .unwrap_err();
        assert_eq!(err.kind, MediaErrorKind::InvalidConfiguration);

        let empty = Roi {
            x: 0,
            y: 0,
            width: 0,
            height: 2,
        };
        assert!(empty.validate(2, 2).is_err());
    }

    #[test]
    fn processing_preserves_the_link_back_to_the_decoded_frame_and_the_evidence() {
        let f = bgr_2x2();
        let evidence = f.provenance.evidence_id;
        let resized = FrameProcessor::resize(&f, 4, 4).unwrap();
        let gray = FrameProcessor::convert_color(&resized, PixelFormat::Gray8).unwrap();

        assert_eq!(gray.artifact_id, "art-1");
        assert_eq!(gray.frame_index, 3);
        assert_eq!(gray.frame_id, "art-1:frame:3");
        assert_eq!(gray.provenance.evidence_id, evidence);
        assert_eq!(gray.provenance.artifact_source_offset, Some(4096));
        assert_eq!(
            gray.provenance.source_recording_id.as_deref(),
            Some("rec-9")
        );
        // Timing survives processing untouched.
        assert_eq!(gray.timing.presentation_timestamp_secs, Some(0.12));
        // Both operations are recorded, in order, with the backend that performed them.
        let chain = &gray.provenance.processing_chain;
        assert_eq!(chain.len(), 2);
        assert_eq!(chain[0].operation, "resize");
        assert_eq!(chain[1].operation, "cvt_color");
        assert_eq!(chain[0].backend, backend_identity());
    }

    #[test]
    fn the_recorded_backend_identity_names_the_compiled_backend() {
        let id = backend_identity();
        assert!(
            id.starts_with(active_backend().label()),
            "identity {id:?} must begin with the backend token {:?}",
            active_backend().label()
        );
        // Stable across calls: it is what a second report must be able to reproduce.
        assert_eq!(id, backend_identity());
        #[cfg(not(feature = "opencv-backend"))]
        assert_eq!(id, "pure_rust_fallback");
    }

    #[test]
    fn quality_metrics_are_measured_from_real_pixels() {
        // A flat mid-grey frame: no tonal variation, no edges.
        let flat = frame(8, 8, PixelFormat::Gray8, vec![128u8; 64]);
        let q = FrameProcessor::quality(&flat).unwrap();
        assert!((q.mean_brightness - 128.0).abs() < 1e-9);
        assert!(q.brightness_std_dev < 1e-9);
        assert!(q.laplacian_variance < 1e-9);
        assert!(!q.has_tonal_variation);
        assert_eq!((q.width, q.height), (8, 8));

        // A hard checkerboard: high variance and strong Laplacian response.
        let mut checker = vec![0u8; 64];
        for (i, p) in checker.iter_mut().enumerate() {
            *p = if (i / 8 + i % 8) % 2 == 0 { 0 } else { 255 };
        }
        let q2 = FrameProcessor::quality(&frame(8, 8, PixelFormat::Gray8, checker)).unwrap();
        assert!(q2.has_tonal_variation);
        assert!(q2.laplacian_variance > q.laplacian_variance);
        assert!(q2.brightness_std_dev > 100.0);
    }

    #[test]
    fn a_frame_with_no_interior_has_no_laplacian_rather_than_a_fabricated_one() {
        // 2x2 is below the 3x3 kernel's reach. Both backends return 0.0 rather than
        // extrapolating a border to manufacture a value.
        let q = FrameProcessor::quality(&frame(2, 2, PixelFormat::Gray8, vec![0, 255, 255, 0]))
            .unwrap();
        assert_eq!(q.laplacian_variance, 0.0);
        // The brightness statistics are still real.
        assert!((q.mean_brightness - 127.5).abs() < 1e-9);
    }

    #[test]
    fn quality_works_on_colour_frames_by_converting_to_luma_first() {
        let q = FrameProcessor::quality(&bgr_2x2()).unwrap();
        // mean of [29, 150, 76, 255]
        assert!((q.mean_brightness - 127.5).abs() < 0.01);
        assert_eq!(q.backend, active_backend());
    }

    #[test]
    fn a_frame_whose_buffer_disagrees_with_its_geometry_never_reaches_a_backend() {
        // `VideoFrame::new` will not build such a frame, so it is constructed by hand here to
        // exercise the guard that stands between the abstraction and the backends.
        let mut f = frame(4, 4, PixelFormat::Gray8, vec![7u8; 16]);
        f.data.truncate(10);
        for err in [
            FrameProcessor::resize(&f, 2, 2).unwrap_err(),
            FrameProcessor::convert_color(&f, PixelFormat::Bgr24).unwrap_err(),
            FrameProcessor::quality(&f).unwrap_err(),
        ] {
            assert_eq!(err.kind, MediaErrorKind::InvalidFrame);
        }
    }

    #[test]
    fn frame_selection_is_reusable_and_rejects_a_zero_interval() {
        let frames: Vec<VideoFrame> = (0..10)
            .map(|_| frame(2, 1, PixelFormat::Gray8, vec![1, 2]))
            .collect();
        assert_eq!(
            FrameProcessor::select_every_nth(&frames, 3).unwrap().len(),
            4
        );
        assert_eq!(
            FrameProcessor::select_every_nth(&frames, 1).unwrap().len(),
            10
        );
        assert_eq!(
            FrameProcessor::select_every_nth(&frames, 0)
                .unwrap_err()
                .kind,
            MediaErrorKind::InvalidConfiguration
        );
    }

    #[test]
    fn the_reported_backend_matches_the_compiled_feature() {
        #[cfg(feature = "opencv-backend")]
        {
            assert_eq!(active_backend(), ProcessingBackend::OpenCv);
            assert!(FrameProcessor::require_opencv("t").is_ok());
            assert!(FrameProcessor::require_backend(ProcessingBackend::OpenCv, "t").is_ok());
            // Demanding the fallback on an OpenCV build cannot be honoured, and OpenCV is not
            // quietly run in its place.
            assert_eq!(
                FrameProcessor::require_backend(ProcessingBackend::PureRustFallback, "t")
                    .unwrap_err()
                    .kind,
                MediaErrorKind::InvalidConfiguration
            );
        }
        #[cfg(not(feature = "opencv-backend"))]
        {
            assert_eq!(active_backend(), ProcessingBackend::PureRustFallback);
            // A build without OpenCV says so explicitly rather than implying it has it.
            assert_eq!(
                FrameProcessor::require_opencv("t").unwrap_err().kind,
                MediaErrorKind::OpencvUnavailable
            );
            assert_eq!(
                FrameProcessor::require_backend(ProcessingBackend::OpenCv, "t")
                    .unwrap_err()
                    .kind,
                MediaErrorKind::OpencvUnavailable
            );
            assert!(
                FrameProcessor::require_backend(ProcessingBackend::PureRustFallback, "t").is_ok()
            );
        }
    }
}
