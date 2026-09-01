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

export type PartitionType = 'Unknown' | 'OEM_Data' | 'OEM_Index' | 'FAT' | 'NTFS' | 'Linux_EXT' | 'Swap' | 'Empty';

export interface PartitionGeometry {
  id: string;
  start_sector: number;
  length_sectors: number;
  partition_type: PartitionType;
  fs_signature?: string;
}

export interface CandidateRegion {
  geometry: PartitionGeometry;
  oem_key: string;
  confidence_score: number;
  provenance_evidence: EvidenceItem[];
}

export interface StorageTopology {
  geometry_type: 'MBR' | 'GPT' | 'RAW' | 'UNKNOWN';
  total_sectors?: number;
  partitions: PartitionGeometry[];
  unpartitioned_ranges: { start: number; length: number }[];
  candidate_regions: CandidateRegion[];
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
