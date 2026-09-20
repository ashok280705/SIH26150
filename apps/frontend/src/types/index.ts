export type ValidationStateKind = 'PASS' | 'REVIEW' | 'FAIL' | 'UNKNOWN';

export interface ValidationState {
  state: ValidationStateKind;
  reason: string;
  operation: string;
  subject: string;
}

export type SourceState = 'read_only' | 'read_write' | 'unknown';
export type ImageFormat = 'raw' | 'dd' | 'img' | 'e01' | 'physical_disk' | string;
export type AcquisitionStatus = 'complete' | 'partial' | 'failed' | 'unknown';

export interface Case {
  id: string;
  name: string;
  description: string;
  examiner: string;
  created_at: string;
  updated_at: string;
}

export interface Evidence {
  id: string;
  case_id: string;
  source_device: string;
  acquisition_time: string;
  capacity: number;
  image_format: ImageFormat;
  responsible_examiner: string;
  acquisition_tool?: string;
  acquisition_tool_version?: string;
  source_state: SourceState;
  acquisition_id?: string;
  path: string;
  registered_at: string;
}

export interface Acquisition {
  id: string;
  evidence_id: string;
  status: AcquisitionStatus;
  tool?: string;
  tool_version?: string;
  map_reference?: string;
  map_hash?: string;
  bad_sector_ranges: { offset: number; length: number }[];
  unresolved_ranges: { offset: number; length: number }[];
  verification: ValidationState;
  created_at: string;
}

export interface SourceSafetyReport {
  source_state: SourceState;
  decision: 'accepted' | 'rejected';
  reason: string;
  inspected_at: string;
}

export interface CustodyEvent {
  timestamp: string;
  examiner: string;
  action: string;
  artifact_id?: string;
  result: string;
  case_id: string;
}

export interface HexChunkResponse {
  evidence_id: string;
  offset: number;
  length: number;
  hex: string;
  total_source_len: number;
}

export type CapabilityStage = 'NOT_IMPLEMENTED' | 'PARTIAL' | 'IMPLEMENTED';

export interface CapabilityStages {
  detection: CapabilityStage;
  profiling: CapabilityStage;
  parsing: CapabilityStage;
  reconstruction: CapabilityStage;
  validation: CapabilityStage;
}

export type EvidenceStatus = 'VALIDATED' | 'PROVISIONAL' | 'MODEL_SPECIFIC' | 'FIRMWARE_SPECIFIC' | 'UNVALIDATED';
export type RuleMatchStatus = 'MATCH' | 'PARTIAL' | 'MISMATCH' | 'ABSENT';

export interface EvidenceItem {
  id: string;
  evidence_status: EvidenceStatus;
  rule_match_status: RuleMatchStatus;
  offset_start?: number;
  offset_end?: number;
  signature_name?: string;
  metadata_key?: string;
  description: string;
  is_exclusive: boolean;
}

export type AttributionStatus = 'Confirmed' | 'CompatibleCandidate' | 'Ambiguous' | 'Unknown' | 'Insufficient';

export interface ConfidenceConfig {
  config_version: string;
  config_hash: string;
  min_confidence: number;
  min_margin: number;
  min_quality: number;
}

export interface ClassifiedDetectionResult {
  oem_key: string;
  attribution_status: AttributionStatus;
  classification: string;
  confidence_score: number;
  margin: number;
  quality_score: number;
  evidence_items: EvidenceItem[];
  profile_version: string;
  profile_hash: string;
  config_version: string;
  config_hash: string;
  warnings: string[];
  validation: ValidationState;
}

export interface PartitionCandidate {
  index: number;
  partition_type: string;
  start_sector: number;
  sector_count: number;
  sector_size: number;
  region: { offset: number; length: number };
}

export interface StorageTopology {
  topology_type: string;
  sector_size: number;
  partitions: PartitionCandidate[];
  unpartitioned_regions: { offset: number; length: number }[];
}

export interface ParserRun {
  id: string;
  evidence_id: string;
  parser_id: string;
  parser_version: string;
  operation_name: string;
  validation: ValidationState;
  started_at: string;
  completed_at: string;
}

export interface TimeEvidence {
  raw_value: number;
  recorder_native: string;
  normalized_utc: string | null;
  reference_time: string | null;
  timezone_state: 'known' | 'unknown' | 'inferred';
}

export interface Recording {
  id: string;
  evidence_id: string;
  channel_id: number;
  start_time: TimeEvidence;
  end_time: TimeEvidence;
  codec: string;
  frame_count: number;
  offset_start: number;
  offset_end: number;
  is_deleted: boolean;
  is_fragmented: boolean;
}

export interface DeletedCandidate {
  id: string;
  offset_start: number;
  reason: string;
  validation: ValidationState;
}

export type DataState = 'Active' | 'Deleted' | 'Orphaned' | 'Corrupted' | 'Overwritten';
export type RecoveryStatus = 'Recoverable' | 'PartiallyRecoverable' | 'Unrecoverable';
export type RecoveryLevel = 'L1' | 'L2' | 'L3';

/**
 * A recovery candidate as returned by POST /api/evidence/:id/recovery.
 *
 * Nullable fields are genuinely unknown for the evidence — they are not filled
 * with placeholder values so the UI can state "Unknown" instead of implying a
 * measurement that was never made.
 */
export interface RecoveryCandidateUI {
  id: string;
  channel: number;
  time_native: string | null;
  time_normalized: string | null;
  timezone_state: string;
  duration_sec: number | null;
  data_state: DataState;
  recovery_status: RecoveryStatus;
  recovery_level: RecoveryLevel;
  source_offset: number;
  source_length: number;
  integrity_status: string;
  codec: string;
  validation: ValidationState;
  nal_unit_count: number;
  has_native_artifact: boolean;
  has_derived_artifact: boolean;
}

/** Raw backend RecoveryRun (forensic_core::RecoveryRun) plus scan totals. */
export interface RecoveryResponse {
  oem_key: string;
  candidates: RecoveryCandidateUI[];
  run: {
    searched_bytes: number;
    skipped_ranges: { offset: number; length: number }[];
    candidate_count: number;
    accepted: number;
    rejected: number;
    truncated: boolean;
    cancelled: boolean;
    validation_state: ValidationState;
    reason: string;
  };
  total_bytes: number;
  skipped_bytes: number;
}

export type OrderingMode = 'Normalized' | 'RecorderNative' | 'Physical';

/**
 * A forensic_core::Hash as serialised over the API.
 *
 * It is an object, not a string — `value` is the hex-encoded digest. Rendering the
 * whole object in JSX throws "Objects are not valid as a React child", so always
 * read `.value` (or use `hashHex`).
 */
export interface ForensicHash {
  algorithm: string;
  value: string;
}

/** Hex digest of a backend hash, tolerating a plain string or a missing value. */
export function hashHex(hash: ForensicHash | string | null | undefined): string | null {
  if (!hash) return null;
  if (typeof hash === 'string') return hash;
  return hash.value ?? null;
}

/** A backend forensic_core::TimelineEvent as serialised over the API. */
export interface TimelineEventApi {
  channel: number;
  description: string;
  source_offsets: { offset: number; length: number }[];
  parser_id: string;
  parser_version: string;
  profile_id: string;
  profile_hash: ForensicHash | string;
  time: {
    raw: { value: number; format: string };
    recorder_native: { iso_8601: string } | null;
    normalized: { iso_8601: string; method: string } | null;
    reference: { iso_8601: string; source: string } | null;
    timezone: 'Unknown' | { Known: string };
    correction: unknown | null;
  };
}

/** Response of GET /api/evidence/:id/timeline (timeline::UnifiedTimeline). */
export interface UnifiedTimelineResponse {
  oem_key: string;
  ordering: OrderingMode;
  has_unknown_timezones: boolean;
  validation: ValidationState;
  events: TimelineEventApi[];
}

// ── Pipeline (POST /api/evidence/:id/pipeline/run) ──────────────────────────

export type PipelineStageName =
  | 'intake'
  | 'detection'
  | 'confidence'
  | 'threshold_gate'
  | 'oem_extraction'
  | 'unified_extraction'
  | 'analyst_review'
  | 'parsed_gate'
  | 'preliminary_timeline'
  | 'gap_gate'
  | 'recovery'
  | 'recovery_gate'
  | 'final_timeline';

export type StageStatus = 'completed' | 'skipped' | 'requires_analyst';

export interface StageRecord {
  stage: PipelineStageName;
  status: StageStatus;
  detail: string;
}

/** A recorded gate decision (serde-tagged by `gate`). */
export interface GateRecord {
  gate: 'threshold' | 'parsed' | 'gaps' | 'recovery';
  decision: string;
  reason?: string;
  confidence?: number;
  min_confidence?: number;
  margin?: number;
  min_margin?: number;
}

export interface AttributionSummary {
  oem_key: string;
  classification: string;
  attribution_status: string;
  confidence: number;
  margin: number;
  evidence_quality: number;
  explanation: string;
}

export type PipelineOutcome =
  | 'completed_no_gaps'
  | 'completed_after_recovery'
  | 'completed_partial_recovery'
  | 'requires_analyst';

export interface GapCoverage {
  total_bytes: number;
  accounted_bytes: number;
  unaccounted_bytes: number;
  coverage_ratio: number;
}

/** A per-channel temporal gap in the unified timeline (timeline::TimelineGap). */
export interface TimelineGap {
  channel: number;
  starts_after_iso: string;
  ends_before_iso: string;
  gap_seconds: number;
  previous_offset: number;
  next_offset: number;
  reason: string;
}

export interface GapAnalysis {
  temporal_gaps: TimelineGap[];
  coverage: GapCoverage;
  events_with_unknown_timezone: number;
  events_without_normalized_time: number;
  gaps_present: boolean;
  validation: ValidationState;
}

// ── Per-recording timeline (timeline::sessions) ─────────────────────────────

/** One stored stream packet projected onto the recording-session view. */
export interface RecordingSegment {
  channel: number;
  start_native: string | null;
  start_normalized: string | null;
  source_offset: number;
  source_length: number;
}

/** A window inside a recording where footage is absent (timeline::SessionGap). */
export interface SessionGap {
  starts_after_native: string | null;
  ends_before_native: string | null;
  starts_after_normalized: string;
  ends_before_normalized: string;
  missing_seconds: number;
  previous_offset: number;
  next_offset: number;
  reason: string;
}

/** A contiguous recording produced by one camera (timeline::RecordingSession). */
export interface RecordingSession {
  id: string;
  channel: number;
  start_native: string | null;
  end_native: string | null;
  start_normalized: string;
  end_normalized: string;
  timezone: string;
  segment_count: number;
  span_seconds: number;
  covered_seconds: number;
  missing_seconds: number;
  coverage_ratio: number;
  nominal_segment_seconds: number;
  gaps: SessionGap[];
  segments: RecordingSegment[];
}

/** The full per-recording view for an evidence image (timeline::RecordingTimeline). */
export interface RecordingTimeline {
  sessions: RecordingSession[];
  channel_count: number;
  total_segments: number;
  total_recordings: number;
  total_missing_seconds: number;
  recordings_without_time: number;
  method: string;
}

export interface PipelineRun {
  stages: StageRecord[];
  gates: GateRecord[];
  attribution: AttributionSummary | null;
  oem_key_used: string | null;
  used_unified_fallback: boolean;
  parsing: { parser_runs: unknown[]; recordings: unknown[]; timeline_events: unknown[] } | null;
  preliminary_timeline: { events: unknown[] } | null;
  recordings_timeline: RecordingTimeline | null;
  gap_analysis: GapAnalysis | null;
  recovery: { candidates: unknown[]; run: unknown; decision: string } | null;
  final_timeline: { events: unknown[] } | null;
  correlation_groups: unknown[];
  outcome: PipelineOutcome;
  requires_analyst: boolean;
  analyst_reasons: string[];
}

export interface RecoveryRunUI {
  searched_bytes: number;
  total_bytes: number;
  skipped_bytes: number;
  candidate_count: number;
  accepted: number;
  rejected: number;
  truncated: boolean;
  validation_state: ValidationState;
}

export interface FfmpegInfo {
  available: boolean;
  executable_path: string | null;
  version: string | null;
  source: any;
  capabilities: string[];
}

export interface ArtifactRecord {
  id: string;
  kind: string;
  evidence_id: string;
  output_path: string;
  description: string;
  created_at: string;
  sha256: string;
  producing_component: string;
  component_version: string;
  validation_state: string;
  validation_reason: string;
  source_regions: { offset: number; length: number; description?: string }[];
}

export interface ArtifactVerificationResult {
  artifact_id: string;
  stored_sha256: string;
  computed_sha256: string;
  status: 'MATCH' | 'MISMATCH';
  verified_at: string;
  size_bytes: number;
}

export interface ReconstructResponse {
  recording_id: string;
  evidence_id: string;
  channel: number;
  codec: string;
  codec_evidence: any;
  elementary_stream: {
    artifact_id: string;
    kind: string;
    output_path: string;
    sha256: string;
    size_bytes: number;
  };
  remux: {
    artifact_id: string;
    kind: string;
    output_path: string;
    sha256: string;
    size_bytes: number;
    ffmpeg_version: string;
    arguments: string[];
    validation_state: ValidationState;
    video_url: string;
  } | null;
  ffmpeg_status: FfmpegInfo;
}
