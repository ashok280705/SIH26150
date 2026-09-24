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

/** Wire format of `forensic_core::capability::CapabilityStage` (`serde(rename_all = "snake_case")`). */
export type CapabilityStage = 'not_implemented' | 'partial' | 'implemented';

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

/**
 * Physical state of the data on the medium.
 *
 * `Orphaned` requires positive evidence: an authoritative recording index governs those
 * bytes and does not reference them. `Unindexed` records an *absence* of index evidence
 * and must never be presented as a deletion finding.
 */
export type DataState =
  | 'Active'
  | 'Deleted'
  | 'Orphaned'
  | 'Unindexed'
  | 'Corrupted'
  | 'Overwritten';
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
  /** `null` when no index entry supplied a channel (carved video has none). */
  channel: number | null;
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
  /** How the candidate was found: an index-claimed probe, or a scan of unclaimed space. */
  discovery_method: string;
  /** Why this candidate received its `data_state`. Safe to display verbatim. */
  state_reason: string;
  /** The recovery engine's stable fragment id; post it back so the artifact traces to it. */
  fragment_id?: string | null;
  /** Every physical range of the candidate's recording, in recording order. */
  source_regions?: { offset: number; length: number }[];
  /** The OEM recording this candidate belongs to, when metadata established one. */
  parent_recording?: string | null;
  /**
   * Post back as `recording_chain_id` for a frame-accurate export. `null` when only the
   * raw `source_regions` (container bytes) can be exported.
   */
  recording_chain_id?: string | null;
  /** Whether the bounds are an OEM container record's or a scan window's. */
  framing?: string | null;
  /** OEM-specific facts read from the structures, verbatim. */
  oem_metadata?: Record<string, string>;
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
  /** Observability counters for the index-aware recovery run. */
  metrics: RecoveryMetrics;
  /** How the scan space was derived from OEM evidence, in plain language. */
  plan_rationale: string;
}

/**
 * Counters describing one index-aware recovery run: what the recorder's index claimed,
 * what physical space that left unclaimed, and how the discovered candidates classified.
 */
export interface RecoveryMetrics {
  oem_key: string;
  profile_id: string;
  geometry_available: boolean;
  /** `"offset:length"` of the OEM-declared video payload region, if established. */
  video_region: string | null;
  index_region: string | null;
  block_size: number | null;
  /** True only when the index was fully parsed; required before any orphan finding. */
  authoritative_index: boolean;
  index_declared_entries: number | null;
  index_entry_count: number;
  claimed_range_count: number;
  claimed_bytes: number;
  unclaimed_region_count: number;
  unclaimed_bytes: number;
  orphan_eligible_region_count: number;
  orphan_eligible_bytes: number;
  scan_region_count: number;
  scanned_bytes: number;
  bytes_avoided_vs_full_scan: number;
  candidate_count: number;
  active_count: number;
  orphaned_count: number;
  unindexed_count: number;
  deleted_count: number;
  corrupted_count: number;
  overwritten_count: number;
  validation_failures: number;
  skipped_range_count: number;
  truncated: boolean;
  cancelled: boolean;
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
  /** Byte length of the segment before the gap. Recoverable region is
   *  [previous_offset + previous_length, next_offset]. */
  previous_length: number;
  next_offset: number;
  reason: string;
}

// ── Gap-targeted recovery (POST /api/evidence/:id/recovery/gap) ─────────────

export interface GapRecoverySlot {
  index: number;
  /** "L1" | "L2" | "L3", or null when nothing could be carved. */
  level: 'L1' | 'L2' | 'L3' | null;
  /**
   * `null` when no video was found in this slot.
   *
   * Finding nothing is an absence of evidence, so the backend asserts no state at all —
   * in particular not `Deleted`. This endpoint has no recording index, so it also never
   * returns `Active` or `Orphaned`; for index-backed states use the main recovery endpoint.
   */
  data_state: DataState | null;
  /** `null` when no candidate was produced for this slot. */
  recovery_status: RecoveryStatus | null;
  start_offset_sec: number;
  end_offset_sec: number;
  offset: number;
  /** Absolute offset of the first Annex-B start code in the slot (the recovered stream
   *  data), or `offset` when the slot has no start code. The Hex button jumps here. */
  data_offset?: number;
  length: number;
  codec: string;
  nal_unit_count: number;
  validation_state: string;
  reason: string;
}

export interface GapRecoveryResponse {
  channel: number;
  oem_key: string;
  scan_start: number;
  scan_end: number;
  nominal_seconds: number;
  num_slots: number;
  total_seconds: number;
  recovered_seconds: number;
  unrecovered_seconds: number;
  decision: 'completely_recovered' | 'partially_recovered' | 'not_recovered';
  slots: GapRecoverySlot[];
}

export interface GapRecoveryRequest {
  channel: number;
  scan_start: number;
  scan_end: number;
  gap_seconds: number;
  nominal_seconds: number;
  oem_key?: string;
}

/** A gap selected in the timeline and handed to the Recovery Engine to recover. */
export interface GapRecoveryTarget {
  channel: number;
  scanStart: number;
  scanEnd: number;
  gapSeconds: number;
  nominalSeconds: number;
  startNative: string | null;
  startNormalized: string;
  endNative: string | null;
  endNormalized: string;
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
