//! The media → AI boundary.
//!
//! This module defines what an analysis engine receives and what it returns. It contains **no
//! inference and no detector**, and it is not a placeholder for one: with no engine registered,
//! [`AnalysisPipeline::analyze`] returns [`AI_NOT_CONFIGURED`] and produces zero findings.
//!
//! The rule this enforces is simple and absolute: **a detection is only ever reported when an
//! engine actually inferred it.** There is no code path in this crate that emits a label or a
//! confidence for an input it did not analyse. A caller that wants detections must register a
//! real [`AnalysisEngine`]; until one exists, the honest answer is the not-configured status,
//! and that is what the API and UI must display.
//!
//! The engine receives [`AnalysisInput`], which carries standardized [`VideoFrame`]s and
//! nothing else. It has no way to learn whether the recording came from a Hikvision, Dahua,
//! Uniview, CP-Plus, Honeywell or TP-Link recorder, because that information is not in the
//! type.

use crate::error::{MediaError, MediaErrorKind, MediaResult};
use crate::frame::VideoFrame;
use chrono::{DateTime, Utc};
use forensic_core::EvidenceId;
use serde::{Deserialize, Serialize};

/// The status string reported wherever AI analysis is surfaced and no engine is configured.
pub const AI_NOT_CONFIGURED: &str = "AI_ANALYSIS_NOT_CONFIGURED";

/// Frames handed to an analysis engine, with the provenance needed to attribute results.
#[derive(Debug, Clone, PartialEq)]
pub struct AnalysisInput {
    pub evidence_id: EvidenceId,
    pub artifact_id: String,
    /// The media artifact's digest, so a result names the exact derived bytes analysed.
    pub artifact_media_hash: Option<String>,
    pub frames: Vec<VideoFrame>,
}

impl AnalysisInput {
    /// Builds an input from decoded frames.
    ///
    /// Rejects an empty frame set: running "analysis" over nothing and reporting a result would
    /// be exactly the fabrication this module exists to prevent.
    pub fn from_frames(
        evidence_id: EvidenceId,
        artifact_id: impl Into<String>,
        artifact_media_hash: Option<String>,
        frames: Vec<VideoFrame>,
    ) -> MediaResult<Self> {
        if frames.is_empty() {
            return Err(MediaError::new(
                MediaErrorKind::FrameExtractionFailed,
                "AnalysisInput::from_frames",
                "no decoded frames were supplied; there is nothing to analyse",
            ));
        }
        Ok(Self {
            evidence_id,
            artifact_id: artifact_id.into(),
            artifact_media_hash,
            frames,
        })
    }

    pub fn frame_count(&self) -> usize {
        self.frames.len()
    }
}

/// One observation an engine made about one frame.
///
/// There is no constructor here that does not take a `frame_id`: a finding that cannot name the
/// frame it came from is a detached result, and detached results are not admissible.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct FrameObservation {
    /// The exact frame this observation concerns.
    pub frame_id: String,
    pub frame_index: u64,
    /// SHA-256 of the analysed frame's pixels, so the observation is bound to those bytes.
    pub frame_sha256: String,
    pub label: String,
    pub confidence: f64,
    /// Region within the frame, when the engine localised the observation.
    pub region: Option<crate::process::Roi>,
}

/// The outcome of an analysis request.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct AnalysisResult {
    pub evidence_id: String,
    pub artifact_id: String,
    pub artifact_media_hash: Option<String>,
    /// `AI_ANALYSIS_NOT_CONFIGURED`, or the engine's own status token.
    pub status: String,
    /// The engine that produced this result, or `None` when none ran.
    pub engine: Option<EngineIdentity>,
    pub frames_submitted: usize,
    /// Frames the engine actually processed. Zero whenever no engine ran.
    pub frames_analyzed: usize,
    pub observations: Vec<FrameObservation>,
    /// Mandatory label: nothing here is ground truth.
    pub is_ai_assisted: bool,
    pub produced_at: DateTime<Utc>,
}

impl AnalysisResult {
    /// The result for "no engine is configured": explicit, and empty.
    pub fn not_configured(input: &AnalysisInput) -> Self {
        Self {
            evidence_id: input.evidence_id.to_string(),
            artifact_id: input.artifact_id.clone(),
            artifact_media_hash: input.artifact_media_hash.clone(),
            status: AI_NOT_CONFIGURED.to_string(),
            engine: None,
            frames_submitted: input.frame_count(),
            frames_analyzed: 0,
            observations: Vec::new(),
            is_ai_assisted: true,
            produced_at: Utc::now(),
        }
    }

    /// Whether any inference actually ran.
    ///
    /// The UI must gate the words "AI analysed" on this, not on the request having been made.
    pub fn inference_performed(&self) -> bool {
        self.engine.is_some() && self.frames_analyzed > 0
    }
}

/// Identity of an engine that performed inference.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EngineIdentity {
    pub name: String,
    pub version: String,
    /// The model identifier, where the engine uses one.
    pub model: Option<String>,
}

/// The interface a real analysis engine implements.
///
/// This crate ships no implementation. A host application that has one registers it with
/// [`AnalysisPipeline::with_engine`].
pub trait AnalysisEngine: Send + Sync {
    fn identity(&self) -> EngineIdentity;

    /// Performs inference over the supplied frames.
    ///
    /// An implementation must only return observations it actually inferred, and every
    /// observation must name a frame from `input`.
    fn analyze(&self, input: &AnalysisInput) -> MediaResult<Vec<FrameObservation>>;
}

/// Routes decoded frames to an engine, when one exists.
#[derive(Default)]
pub struct AnalysisPipeline {
    engine: Option<std::sync::Arc<dyn AnalysisEngine>>,
}

impl std::fmt::Debug for AnalysisPipeline {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AnalysisPipeline")
            .field("engine", &self.engine.as_ref().map(|e| e.identity().name))
            .finish()
    }
}

impl AnalysisPipeline {
    /// A pipeline with no engine. Every request returns `AI_ANALYSIS_NOT_CONFIGURED`.
    pub fn not_configured() -> Self {
        Self { engine: None }
    }

    pub fn with_engine(engine: std::sync::Arc<dyn AnalysisEngine>) -> Self {
        Self {
            engine: Some(engine),
        }
    }

    pub fn is_configured(&self) -> bool {
        self.engine.is_some()
    }

    /// The status token to display for this pipeline before any request runs.
    pub fn status(&self) -> String {
        match &self.engine {
            Some(e) => format!("AI_ENGINE_CONFIGURED:{}", e.identity().name),
            None => AI_NOT_CONFIGURED.to_string(),
        }
    }

    /// Submits frames for analysis.
    ///
    /// With no engine, returns the not-configured result: zero observations, zero frames
    /// analysed. Observations an engine returns are checked against the submitted frames, and
    /// any that name a frame that was not submitted are rejected outright — a result must be
    /// traceable to the frame, artifact and evidence it came from.
    pub fn analyze(&self, input: &AnalysisInput) -> MediaResult<AnalysisResult> {
        let Some(engine) = &self.engine else {
            return Ok(AnalysisResult::not_configured(input));
        };

        let observations = engine.analyze(input)?;
        let known: std::collections::HashSet<&str> =
            input.frames.iter().map(|f| f.frame_id.as_str()).collect();
        if let Some(stray) = observations
            .iter()
            .find(|o| !known.contains(o.frame_id.as_str()))
        {
            return Err(MediaError::new(
                MediaErrorKind::InvalidFrame,
                "AnalysisPipeline::analyze",
                format!(
                    "engine returned an observation for frame '{}', which was not submitted; \
                     a finding that cannot be traced to a submitted frame is rejected",
                    stray.frame_id
                ),
            ));
        }

        Ok(AnalysisResult {
            evidence_id: input.evidence_id.to_string(),
            artifact_id: input.artifact_id.clone(),
            artifact_media_hash: input.artifact_media_hash.clone(),
            status: "AI_ANALYSIS_COMPLETED".to_string(),
            engine: Some(engine.identity()),
            frames_submitted: input.frame_count(),
            frames_analyzed: input.frame_count(),
            observations,
            is_ai_assisted: true,
            produced_at: Utc::now(),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::frame::{FrameProvenance, FrameTiming, PixelFormat};

    fn frame(index: u64) -> VideoFrame {
        VideoFrame::new(
            "art-1",
            index,
            2,
            1,
            PixelFormat::Gray8,
            vec![index as u8, 9],
            FrameTiming::unknown(),
            FrameProvenance {
                evidence_id: EvidenceId::new(),
                artifact_id: "art-1".into(),
                artifact_source_offset: Some(1024),
                source_recording_id: None,
                artifact_media_hash: Some("hash".into()),
                decoder: "ffmpeg rawvideo".into(),
                processing_chain: vec![],
            },
        )
        .unwrap()
    }

    fn input() -> AnalysisInput {
        AnalysisInput::from_frames(
            EvidenceId::new(),
            "art-1",
            Some("media-hash".into()),
            vec![frame(0), frame(1)],
        )
        .unwrap()
    }

    #[test]
    fn with_no_engine_the_pipeline_reports_not_configured_and_no_detections() {
        let p = AnalysisPipeline::not_configured();
        assert!(!p.is_configured());
        assert_eq!(p.status(), "AI_ANALYSIS_NOT_CONFIGURED");

        let r = p.analyze(&input()).unwrap();
        assert_eq!(r.status, AI_NOT_CONFIGURED);
        assert!(r.observations.is_empty());
        assert_eq!(r.frames_analyzed, 0);
        assert_eq!(r.frames_submitted, 2);
        assert!(!r.inference_performed());
        assert!(r.engine.is_none());
        // Even a not-configured result stays bound to its evidence and artifact.
        assert_eq!(r.artifact_id, "art-1");
        assert_eq!(r.artifact_media_hash.as_deref(), Some("media-hash"));
    }

    #[test]
    fn analysis_over_zero_frames_is_refused_rather_than_answered() {
        let err = AnalysisInput::from_frames(EvidenceId::new(), "art-1", None, vec![]).unwrap_err();
        assert_eq!(err.kind, MediaErrorKind::FrameExtractionFailed);
    }

    struct CountingEngine;
    impl AnalysisEngine for CountingEngine {
        fn identity(&self) -> EngineIdentity {
            EngineIdentity {
                name: "counting-test-engine".into(),
                version: "0.0.1".into(),
                model: None,
            }
        }
        /// Deliberately *not* a detector: it reports a measured property of the frame it was
        /// given, so the test exercises the plumbing without inventing a detection.
        fn analyze(&self, input: &AnalysisInput) -> MediaResult<Vec<FrameObservation>> {
            Ok(input
                .frames
                .iter()
                .map(|f| FrameObservation {
                    frame_id: f.frame_id.clone(),
                    frame_index: f.frame_index,
                    frame_sha256: f.content_hash().hex,
                    label: format!("pixel_count:{}", f.data.len()),
                    confidence: 1.0,
                    region: None,
                })
                .collect())
        }
    }

    #[test]
    fn a_configured_engine_produces_results_bound_to_the_submitted_frames() {
        let p = AnalysisPipeline::with_engine(std::sync::Arc::new(CountingEngine));
        assert!(p.is_configured());
        let inp = input();
        let r = p.analyze(&inp).unwrap();
        assert!(r.inference_performed());
        assert_eq!(r.frames_analyzed, 2);
        assert_eq!(r.observations.len(), 2);
        assert_eq!(r.observations[0].frame_id, inp.frames[0].frame_id);
        assert_eq!(
            r.observations[0].frame_sha256,
            inp.frames[0].content_hash().hex
        );
        assert!(r.is_ai_assisted);
        assert_eq!(r.engine.unwrap().name, "counting-test-engine");
    }

    struct DetachedEngine;
    impl AnalysisEngine for DetachedEngine {
        fn identity(&self) -> EngineIdentity {
            EngineIdentity {
                name: "detached".into(),
                version: "0".into(),
                model: None,
            }
        }
        fn analyze(&self, _input: &AnalysisInput) -> MediaResult<Vec<FrameObservation>> {
            Ok(vec![FrameObservation {
                frame_id: "some-other-artifact:frame:99".into(),
                frame_index: 99,
                frame_sha256: "0".into(),
                label: "person".into(),
                confidence: 0.94,
                region: None,
            }])
        }
    }

    #[test]
    fn an_observation_that_names_an_unsubmitted_frame_is_rejected() {
        let p = AnalysisPipeline::with_engine(std::sync::Arc::new(DetachedEngine));
        let err = p.analyze(&input()).unwrap_err();
        assert_eq!(err.kind, MediaErrorKind::InvalidFrame);
        assert!(err.detail.contains("frame:99"));
    }

    #[test]
    fn inference_performed_is_false_unless_an_engine_actually_processed_frames() {
        let mut r = AnalysisResult::not_configured(&input());
        assert!(!r.inference_performed());
        // An engine identity alone is not enough; frames must have been processed.
        r.engine = Some(EngineIdentity {
            name: "x".into(),
            version: "1".into(),
            model: None,
        });
        assert!(!r.inference_performed());
        r.frames_analyzed = 1;
        assert!(r.inference_performed());
    }
}
