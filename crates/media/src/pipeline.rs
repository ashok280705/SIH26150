//! The end-to-end media pipeline, wired together.
//!
//! ```text
//!   MediaArtifact  (derived file + upstream provenance)
//!        │
//!        ▼  validate::validate_artifact  — ffprobe, evaluated
//!   ValidationReport
//!        │  only when status == VALID
//!        ▼  decode::decode_frames_with   — ffmpeg -f rawvideo, streaming
//!   VideoFrame …
//!        │
//!        ▼  process::FrameProcessor      — colour / resize / ROI / quality
//!   processed VideoFrame …
//!        │
//!        ▼  analysis::AnalysisPipeline   — only if an engine is registered
//!   AnalysisResult  (or AI_ANALYSIS_NOT_CONFIGURED)
//! ```
//!
//! The report this produces states, for every stage, whether it ran and what it concluded. A
//! stage that did not run is reported as not run — there is no field here whose default reads
//! as success.

use crate::analysis::{AnalysisInput, AnalysisPipeline, AnalysisResult, AI_NOT_CONFIGURED};
use crate::artifact::{MediaArtifact, ValidationStatus};
use crate::decode::{self, DecodeReport, DecodeRequest, FrameAction};
use crate::error::{MediaError, MediaResult};
use crate::frame::{PixelFormat, VideoFrame};
use crate::process::{FrameProcessor, FrameQuality, ProcessingBackend, Roi};
use crate::tools::MediaToolchain;
use crate::validate::{self, ValidationReport};
use serde::{Deserialize, Serialize};

/// What to do to each decoded frame before analysis.
///
/// An empty plan is legitimate: it means frames are decoded and handed on unchanged.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct ProcessingPlan {
    /// Crop to this region first, when set.
    pub roi: Option<Roi>,
    /// Then rescale to these dimensions, when set.
    pub resize_to: Option<(u32, u32)>,
    /// Then convert to this pixel layout, when set.
    pub convert_to: Option<PixelFormat>,
    /// Compute quality indicators for each processed frame.
    pub measure_quality: bool,
    /// Demand a specific image-processing backend, rather than accepting whichever one this
    /// build has.
    ///
    /// * `None` — the default and the behaviour of every caller that predates this field: use
    ///   the compiled backend, whichever it is. What ran is still reported, on every
    ///   [`crate::frame::ProcessingStep`] and in the run summary.
    /// * `Some(_)` — the run fails before decoding starts unless this build will actually use
    ///   that backend. Requesting OpenCV on a build without it fails with `OPENCV_UNAVAILABLE`;
    ///   requesting the fallback on an OpenCV build fails with `INVALID_CONFIGURATION`. In
    ///   neither case is the other backend substituted.
    ///
    /// This exists so that "OpenCV was requested" can never quietly become "the fallback ran".
    #[serde(default)]
    pub require_backend: Option<ProcessingBackend>,
}

impl ProcessingPlan {
    pub fn is_empty(&self) -> bool {
        self.roi.is_none()
            && self.resize_to.is_none()
            && self.convert_to.is_none()
            && !self.measure_quality
    }

    /// Checks the backend requirement, if any, against what this build will actually run.
    fn check_backend(&self) -> MediaResult<()> {
        match self.require_backend {
            Some(required) => {
                FrameProcessor::require_backend(required, "ProcessingPlan::require_backend")
            }
            None => Ok(()),
        }
    }

    fn apply(&self, frame: VideoFrame) -> MediaResult<(VideoFrame, Option<FrameQuality>)> {
        let mut f = frame;
        if let Some(roi) = self.roi {
            f = FrameProcessor::crop_roi(&f, roi)?;
        }
        if let Some((w, h)) = self.resize_to {
            f = FrameProcessor::resize(&f, w, h)?;
        }
        if let Some(fmt) = self.convert_to {
            f = FrameProcessor::convert_color(&f, fmt)?;
        }
        let quality = if self.measure_quality {
            Some(FrameProcessor::quality(&f)?)
        } else {
            None
        };
        Ok((f, quality))
    }
}

/// How a stage of the pipeline ended.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum StageOutcome {
    /// The stage ran and succeeded.
    Completed,
    /// The stage ran and failed, with the media error code.
    Failed(String),
    /// The stage did not run, and why.
    NotRun(String),
}

impl StageOutcome {
    pub fn succeeded(&self) -> bool {
        matches!(self, Self::Completed)
    }
}

/// The full account of one pipeline run.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct MediaPipelineReport {
    pub artifact_id: String,
    pub validation: ValidationReport,
    pub validation_outcome: StageOutcome,
    pub decode_outcome: StageOutcome,
    pub decode: Option<DecodeReport>,
    pub processing_outcome: StageOutcome,
    /// Number of frames on which the processing plan actually performed an operation.
    ///
    /// An empty plan performs no operations, so this is `0` for one however many frames were
    /// decoded. A frame that merely passed through a plan that asked for nothing has not been
    /// processed, and counting it here would make `processing_outcome: NOT_RUN` sit next to a
    /// non-zero processed count. Use [`Self::frames_decoded`] for how many pictures came out of
    /// FFmpeg.
    pub frames_processed: u64,
    pub analysis_outcome: StageOutcome,
    pub analysis: Option<AnalysisResult>,
    /// Per-frame metadata, without pixel buffers, for the API and reports.
    pub frame_metadata: Vec<serde_json::Value>,
    pub quality: Vec<FrameQuality>,
}

impl MediaPipelineReport {
    /// Whether real frames were decoded. The only honest basis for the word "decoded".
    pub fn frames_decoded(&self) -> u64 {
        self.decode
            .as_ref()
            .map(|d| d.metrics.frames_emitted)
            .unwrap_or(0)
    }

    /// Whether AI inference actually ran. The only honest basis for "AI analysed".
    pub fn ai_analysis_performed(&self) -> bool {
        self.analysis
            .as_ref()
            .map(|a| a.inference_performed())
            .unwrap_or(false)
    }

    /// Whether image processing actually ran over at least one frame.
    ///
    /// The only honest basis for saying a backend processed anything. `processing_backend` in
    /// the summary names the backend this build *selected*; this says whether it did any work.
    pub fn processing_performed(&self) -> bool {
        self.processing_outcome.succeeded() && self.frames_processed > 0
    }

    /// A compact status object for API responses and UI labels.
    ///
    /// Every claim here is gated on the corresponding operation having happened: `decoded` is
    /// false unless frames came out of FFmpeg, and `ai_analyzed` is false unless an engine ran.
    ///
    /// `processing_backend` is the one field here that is a *capability* rather than an event:
    /// it names the backend this build would use. Whether it ran is `processing_performed`,
    /// with `processing_status` and `frames_processed` giving the detail. The combination
    /// `processing_backend: "opencv …"` with `processing_performed: false` therefore reads as
    /// "this build has OpenCV and did not use it", never as "OpenCV processed these frames".
    pub fn status_summary(&self) -> serde_json::Value {
        serde_json::json!({
            "artifact_id": self.artifact_id,
            "artifact_found": self.validation.error_code.as_deref() != Some("MEDIA_NOT_FOUND"),
            "validation_status": self.validation.status.label(),
            "validated": self.validation.status == ValidationStatus::Valid,
            "codec": self.validation.probe.as_ref()
                .map(|p| p.video_codec().label())
                .unwrap_or_else(|| "UNKNOWN".into()),
            "resolution": self.validation.probe.as_ref()
                .and_then(|p| p.geometry())
                .map(|(w, h)| format!("{w}x{h}"))
                .unwrap_or_else(|| "UNKNOWN".into()),
            "duration_secs": self.validation.probe.as_ref()
                .and_then(|p| p.effective_duration()),
            "decode_status": self.decode_outcome,
            "decoded": self.frames_decoded() > 0,
            "frames_extracted": self.frames_decoded(),
            "frames_processed": self.frames_processed,
            "processing_backend": crate::process::backend_identity(),
            "processing_performed": self.processing_performed(),
            "processing_status": self.processing_outcome,
            "ai_status": self.analysis.as_ref()
                .map(|a| a.status.clone())
                .unwrap_or_else(|| AI_NOT_CONFIGURED.to_string()),
            "ai_analyzed": self.ai_analysis_performed(),
            "errors": self.errors(),
        })
    }

    /// Every error code this run produced, in stage order.
    pub fn errors(&self) -> Vec<String> {
        let mut out = Vec::new();
        for stage in [
            &self.validation_outcome,
            &self.decode_outcome,
            &self.processing_outcome,
            &self.analysis_outcome,
        ] {
            if let StageOutcome::Failed(code) = stage {
                out.push(code.clone());
            }
        }
        out
    }
}

/// The media subsystem's entry point.
#[derive(Debug)]
pub struct MediaPipeline {
    toolchain: MediaToolchain,
    analysis: AnalysisPipeline,
}

impl Default for MediaPipeline {
    fn default() -> Self {
        Self::new(MediaToolchain::default())
    }
}

impl MediaPipeline {
    /// A pipeline with no analysis engine. AI reports `AI_ANALYSIS_NOT_CONFIGURED`.
    pub fn new(toolchain: MediaToolchain) -> Self {
        Self {
            toolchain,
            analysis: AnalysisPipeline::not_configured(),
        }
    }

    pub fn with_analysis(mut self, analysis: AnalysisPipeline) -> Self {
        self.analysis = analysis;
        self
    }

    pub fn toolchain(&self) -> &MediaToolchain {
        &self.toolchain
    }

    pub fn analysis(&self) -> &AnalysisPipeline {
        &self.analysis
    }

    /// Runs validation, decoding, processing and (if configured) analysis.
    ///
    /// Frames are retained only up to `retain_frames`, so a long recording can be validated and
    /// decoded end to end while only a bounded number of pictures is ever resident. The frames
    /// that are retained are returned alongside the report.
    pub async fn run(
        &self,
        artifact: &mut MediaArtifact,
        request: &DecodeRequest,
        plan: &ProcessingPlan,
        retain_frames: usize,
    ) -> MediaPipelineReport {
        // An explicit backend requirement is a property of this build, not of the media, so it
        // is settled before anything is probed, decoded or read. Failing here rather than
        // substituting the other backend is the whole point of the field: a run that asked for
        // OpenCV and got the fallback would be indistinguishable, after the fact, from one that
        // asked for nothing.
        if let Err(e) = plan.check_backend() {
            let reason = "the required image-processing backend is unavailable";
            return MediaPipelineReport {
                artifact_id: artifact.artifact_id.clone(),
                validation: ValidationReport::not_run(&artifact.artifact_id, reason),
                validation_outcome: StageOutcome::NotRun(reason.into()),
                decode_outcome: StageOutcome::NotRun(reason.into()),
                decode: None,
                processing_outcome: StageOutcome::Failed(e.code().to_string()),
                frames_processed: 0,
                analysis_outcome: StageOutcome::NotRun("no frames were processed".into()),
                analysis: None,
                frame_metadata: Vec::new(),
                quality: Vec::new(),
            };
        }

        let validation = validate::validate_artifact(&self.toolchain, artifact).await;
        let validation_outcome = match validation.status {
            ValidationStatus::Valid => StageOutcome::Completed,
            _ => StageOutcome::Failed(
                validation
                    .error_code
                    .clone()
                    .unwrap_or_else(|| validation.status.label().to_string()),
            ),
        };

        let mut report = MediaPipelineReport {
            artifact_id: artifact.artifact_id.clone(),
            validation,
            validation_outcome,
            decode_outcome: StageOutcome::NotRun("validation did not pass".into()),
            decode: None,
            processing_outcome: StageOutcome::NotRun("no frames were decoded".into()),
            frames_processed: 0,
            analysis_outcome: StageOutcome::NotRun("no frames were decoded".into()),
            analysis: None,
            frame_metadata: Vec::new(),
            quality: Vec::new(),
        };

        if !report.validation_outcome.succeeded() {
            return report;
        }

        // Decode, applying the processing plan as each frame arrives so that nothing larger
        // than `retain_frames` pictures is ever held.
        let mut retained: Vec<VideoFrame> = Vec::new();
        let mut processed: u64 = 0;
        let mut quality = Vec::new();
        let mut metadata = Vec::new();
        let mut processing_error: Option<MediaError> = None;

        let decode_result = decode::decode_frames_with(&self.toolchain, artifact, request, |f| {
            match plan.apply(f) {
                Ok((frame, q)) => {
                    // Counted only when the plan actually asked for an operation. A frame that
                    // passed through an empty plan was carried, not processed.
                    if !plan.is_empty() {
                        processed += 1;
                    }
                    metadata.push(frame.metadata());
                    if let Some(q) = q {
                        quality.push(q);
                    }
                    if retained.len() < retain_frames {
                        retained.push(frame);
                    }
                    Ok(FrameAction::Continue)
                }
                Err(e) => {
                    processing_error = Some(e.clone());
                    Err(e)
                }
            }
        })
        .await;

        match decode_result {
            Ok(d) => {
                report.decode_outcome = StageOutcome::Completed;
                report.decode = Some(d);
            }
            Err(e) => {
                // A failure inside the processing plan is a processing failure, not a decode
                // failure, even though it surfaced through the decode loop.
                if let Some(pe) = &processing_error {
                    report.processing_outcome = StageOutcome::Failed(pe.code().to_string());
                    report.decode_outcome =
                        StageOutcome::NotRun("aborted by a frame-processing failure".into());
                } else {
                    report.decode_outcome = StageOutcome::Failed(e.code().to_string());
                }
                report.frames_processed = processed;
                report.frame_metadata = metadata;
                report.quality = quality;
                return report;
            }
        }

        report.frames_processed = processed;
        report.frame_metadata = metadata;
        report.quality = quality;
        report.processing_outcome = if plan.is_empty() {
            StageOutcome::NotRun("no processing operations were requested".into())
        } else {
            StageOutcome::Completed
        };

        // Analysis. With no engine this is an explicit not-configured result, never a silent
        // success and never a fabricated detection.
        match AnalysisInput::from_frames(
            artifact.provenance.evidence_id,
            artifact.artifact_id.clone(),
            artifact.media_hash.as_ref().map(|h| h.hex.clone()),
            retained,
        ) {
            Ok(input) => match self.analysis.analyze(&input) {
                Ok(result) => {
                    report.analysis_outcome = if result.inference_performed() {
                        StageOutcome::Completed
                    } else {
                        StageOutcome::NotRun(AI_NOT_CONFIGURED.to_string())
                    };
                    report.analysis = Some(result);
                }
                Err(e) => {
                    report.analysis_outcome = StageOutcome::Failed(e.code().to_string());
                }
            },
            Err(e) => {
                report.analysis_outcome = StageOutcome::NotRun(e.code().to_string());
            }
        }

        report
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::artifact::{MediaProvenance, ReconstructionMethod};
    use crate::tools::{MediaConfig, ToolAvailability};
    use forensic_core::EvidenceId;
    use std::io::Write;

    fn toolchain_without_tools() -> MediaToolchain {
        MediaToolchain::with_availability(
            ToolAvailability::NotFound { searched: vec![] },
            ToolAvailability::NotFound { searched: vec![] },
            MediaConfig::default(),
        )
    }

    #[tokio::test]
    async fn without_ffprobe_the_run_stops_at_validation_and_claims_nothing() {
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path().join("a.mp4");
        std::fs::File::create(&p)
            .unwrap()
            .write_all(b"bytes")
            .unwrap();

        let mut art = MediaArtifact::from_derived_file(
            "art-1",
            &p,
            ReconstructionMethod::ExternallyProvided,
            MediaProvenance::new(EvidenceId::new()),
        )
        .unwrap();

        let pipeline = MediaPipeline::new(toolchain_without_tools());
        let report = pipeline
            .run(
                &mut art,
                &DecodeRequest::sequential(),
                &ProcessingPlan::default(),
                4,
            )
            .await;

        let s = report.status_summary();
        assert_eq!(s["validation_status"], "VALIDATION_UNAVAILABLE");
        assert_eq!(s["validated"], false);
        assert_eq!(s["decoded"], false);
        assert_eq!(s["frames_extracted"], 0);
        assert_eq!(s["ai_analyzed"], false);
        assert_eq!(s["ai_status"], "AI_ANALYSIS_NOT_CONFIGURED");
        assert_eq!(s["codec"], "UNKNOWN");
        assert_eq!(s["resolution"], "UNKNOWN");
        assert!(matches!(report.decode_outcome, StageOutcome::NotRun(_)));
        assert!(report.errors().contains(&"FFPROBE_UNAVAILABLE".to_string()));
    }

    #[tokio::test]
    async fn a_missing_artifact_is_reported_as_not_found_and_nothing_downstream_runs() {
        let dir = tempfile::tempdir().unwrap();
        let real = dir.path().join("real.mp4");
        std::fs::File::create(&real)
            .unwrap()
            .write_all(b"x")
            .unwrap();
        let mut art = MediaArtifact::from_derived_file(
            "art-1",
            &real,
            ReconstructionMethod::ExternallyProvided,
            MediaProvenance::new(EvidenceId::new()),
        )
        .unwrap();
        art.path = dir.path().join("vanished.mp4");

        let report = MediaPipeline::new(toolchain_without_tools())
            .run(
                &mut art,
                &DecodeRequest::sequential(),
                &ProcessingPlan::default(),
                1,
            )
            .await;

        assert_eq!(report.status_summary()["artifact_found"], false);
        assert!(report.errors().contains(&"MEDIA_NOT_FOUND".to_string()));
        assert_eq!(report.frames_decoded(), 0);
        assert!(!report.ai_analysis_performed());
    }

    #[test]
    fn an_empty_processing_plan_is_reported_as_not_run_rather_than_completed() {
        assert!(ProcessingPlan::default().is_empty());
        let plan = ProcessingPlan {
            measure_quality: true,
            ..Default::default()
        };
        assert!(!plan.is_empty());
        // A plan with only a backend requirement still asks for no operations.
        assert!(ProcessingPlan {
            require_backend: Some(crate::process::active_backend()),
            ..Default::default()
        }
        .is_empty());
    }

    #[test]
    fn a_backend_requirement_defaults_to_none_and_deserializes_from_a_plan_without_it() {
        assert_eq!(ProcessingPlan::default().require_backend, None);
        // Callers and stored configurations that predate the field keep working unchanged.
        let plan: ProcessingPlan = serde_json::from_str(
            r#"{"roi":null,"resize_to":null,"convert_to":null,"measure_quality":true}"#,
        )
        .unwrap();
        assert_eq!(plan.require_backend, None);
        assert!(plan.check_backend().is_ok());
    }

    #[test]
    fn requiring_the_backend_this_build_has_is_satisfied_and_the_other_one_is_refused() {
        let ok = ProcessingPlan {
            require_backend: Some(crate::process::active_backend()),
            ..Default::default()
        };
        assert!(ok.check_backend().is_ok());

        let other = match crate::process::active_backend() {
            ProcessingBackend::OpenCv => ProcessingBackend::PureRustFallback,
            ProcessingBackend::PureRustFallback => ProcessingBackend::OpenCv,
        };
        let refused = ProcessingPlan {
            require_backend: Some(other),
            ..Default::default()
        };
        let err = refused.check_backend().unwrap_err();
        // Whichever direction, the run is refused rather than silently served by the backend
        // that happens to be compiled in.
        assert!(matches!(
            err.kind,
            crate::error::MediaErrorKind::OpencvUnavailable
                | crate::error::MediaErrorKind::InvalidConfiguration
        ));
    }

    #[tokio::test]
    async fn an_unsatisfiable_backend_requirement_stops_the_run_before_any_decoding() {
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path().join("a.mp4");
        std::fs::File::create(&p)
            .unwrap()
            .write_all(b"bytes")
            .unwrap();
        let mut art = MediaArtifact::from_derived_file(
            "art-1",
            &p,
            ReconstructionMethod::ExternallyProvided,
            MediaProvenance::new(EvidenceId::new()),
        )
        .unwrap();

        let other = match crate::process::active_backend() {
            ProcessingBackend::OpenCv => ProcessingBackend::PureRustFallback,
            ProcessingBackend::PureRustFallback => ProcessingBackend::OpenCv,
        };
        let plan = ProcessingPlan {
            measure_quality: true,
            require_backend: Some(other),
            ..Default::default()
        };
        let report = MediaPipeline::new(toolchain_without_tools())
            .run(&mut art, &DecodeRequest::sequential(), &plan, 4)
            .await;

        assert!(matches!(report.processing_outcome, StageOutcome::Failed(_)));
        assert!(matches!(report.decode_outcome, StageOutcome::NotRun(_)));
        assert_eq!(report.frames_processed, 0);
        assert!(!report.processing_performed());
    }

    #[test]
    fn the_summary_separates_the_selected_backend_from_whether_it_did_anything() {
        // The dangerous reading this guards against is `processing_backend: opencv` being taken
        // to mean OpenCV processed something. It never does on its own.
        let report = MediaPipelineReport {
            artifact_id: "art-1".into(),
            validation: ValidationReport {
                artifact_id: "art-1".into(),
                status: ValidationStatus::Unavailable,
                error_code: Some("FFPROBE_UNAVAILABLE".into()),
                checks: Vec::new(),
                probe: None,
                ffprobe_exit_code: None,
                ffprobe_stderr_tail: None,
                ffprobe_version: None,
                duration_ms: 0,
                validated_at: chrono::Utc::now(),
            },
            validation_outcome: StageOutcome::Failed("FFPROBE_UNAVAILABLE".into()),
            decode_outcome: StageOutcome::NotRun("validation did not pass".into()),
            decode: None,
            processing_outcome: StageOutcome::NotRun("no frames were decoded".into()),
            frames_processed: 0,
            analysis_outcome: StageOutcome::NotRun("no frames were decoded".into()),
            analysis: None,
            frame_metadata: Vec::new(),
            quality: Vec::new(),
        };
        let s = report.status_summary();
        // The backend is always named — it is a capability of this build.
        assert_eq!(s["processing_backend"], crate::process::backend_identity());
        // But nothing was processed, and the summary says so in its own field.
        assert_eq!(s["processing_performed"], false);
        assert_eq!(s["frames_processed"], 0);
        assert!(!report.processing_performed());
    }

    #[test]
    fn a_processing_plan_applies_its_operations_in_order() {
        use crate::frame::{FrameProvenance, FrameTiming};
        // 4x4 grey ramp.
        let data: Vec<u8> = (0..16u8).map(|i| i * 16).collect();
        let f = VideoFrame::new(
            "art-1",
            0,
            4,
            4,
            PixelFormat::Gray8,
            data,
            FrameTiming::unknown(),
            FrameProvenance {
                evidence_id: EvidenceId::new(),
                artifact_id: "art-1".into(),
                artifact_source_offset: None,
                source_recording_id: None,
                artifact_media_hash: None,
                decoder: "test".into(),
                processing_chain: vec![],
            },
        )
        .unwrap();

        let plan = ProcessingPlan {
            roi: Some(Roi {
                x: 1,
                y: 1,
                width: 2,
                height: 2,
            }),
            resize_to: Some((4, 4)),
            convert_to: Some(PixelFormat::Bgr24),
            measure_quality: true,
            require_backend: None,
        };
        let (out, quality) = plan.apply(f).unwrap();
        assert_eq!((out.width, out.height), (4, 4));
        assert_eq!(out.pixel_format, PixelFormat::Bgr24);
        assert_eq!(out.data.len(), 4 * 4 * 3);
        let chain: Vec<&str> = out
            .provenance
            .processing_chain
            .iter()
            .map(|s| s.operation.as_str())
            .collect();
        assert_eq!(chain, vec!["roi", "resize", "cvt_color"]);
        assert!(quality.is_some());
    }

    #[test]
    fn stage_outcomes_distinguish_not_run_from_failed() {
        assert!(StageOutcome::Completed.succeeded());
        assert!(!StageOutcome::NotRun("x".into()).succeeded());
        assert!(!StageOutcome::Failed("DECODE_FAILED".into()).succeeded());
    }
}
