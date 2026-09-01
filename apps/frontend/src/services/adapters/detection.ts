import { AttributionStatus, ClassifiedDetectionResult, EvidenceItem, EvidenceStatus, RuleMatchStatus, ValidationState } from '../../types';

function normalizeAttributionStatus(val: string | undefined): AttributionStatus {
  if (!val) return 'Unknown';
  const lower = val.toLowerCase().replace(/_/g, '');
  if (lower === 'confirmed') return 'Confirmed';
  if (lower === 'compatiblecandidate') return 'CompatibleCandidate';
  if (lower === 'ambiguous') return 'Ambiguous';
  if (lower === 'insufficient') return 'Insufficient';
  return 'Unknown';
}

function normalizeEvidenceStatus(val: string | undefined): EvidenceStatus {
  if (!val) return 'UNVALIDATED';
  const lower = val.toLowerCase();
  if (lower === 'validated') return 'VALIDATED';
  if (lower === 'provisional' || lower === 'indicative' || lower === 'tentative') return 'PROVISIONAL';
  if (lower === 'model_specific') return 'MODEL_SPECIFIC';
  if (lower === 'firmware_specific') return 'FIRMWARE_SPECIFIC';
  return 'UNVALIDATED';
}

function normalizeRuleMatchStatus(val: string | undefined): RuleMatchStatus {
  if (!val) return 'ABSENT';
  const lower = val.toLowerCase();
  if (lower === 'match' || lower === 'confirmed') return 'MATCH';
  if (lower === 'partial' || lower === 'inconclusive') return 'PARTIAL';
  if (lower === 'mismatch') return 'MISMATCH';
  return 'ABSENT';
}

export function normalizeDetectionResponse(rawItem: any): ClassifiedDetectionResult {
  const oemKey = rawItem.top_candidate || rawItem.detector_output?.oem_key || rawItem.oem_key || 'Unknown';
  const attributionStatus = normalizeAttributionStatus(rawItem.attribution_status);
  const confidenceScore = Number(rawItem.confidence ?? rawItem.confidence_score ?? 0);
  const qualityScore = Number(rawItem.evidence_quality ?? rawItem.quality_score ?? 0);
  const margin = Number(rawItem.margin ?? 0);

  const rawEvidence = rawItem.detector_output?.evidence || rawItem.evidence_items || [];
  const evidenceItems: EvidenceItem[] = rawEvidence.map((e: any, idx: number) => ({
    id: e.id || `ev-${idx}`,
    evidence_status: normalizeEvidenceStatus(e.evidence_status),
    rule_match_status: normalizeRuleMatchStatus(e.rule_match_status),
    offset_start: e.offset_start ?? e.offset,
    offset_end: e.offset_end ?? (e.offset != null && e.length != null ? e.offset + e.length : undefined),
    signature_name: e.signature_name || e.rule_name,
    metadata_key: e.metadata_key,
    description: e.description || e.explanation || 'Evidence matched rule',
    is_exclusive: Boolean(e.is_exclusive),
  }));

  const validationState: ValidationState = rawItem.validation_state || rawItem.validation || {
    state: 'PASS',
    reason: rawItem.explanation || 'Detection completed successfully',
    operation: 'detection_classification',
    subject: oemKey,
  };

  return {
    oem_key: oemKey,
    attribution_status: attributionStatus,
    classification: String(rawItem.classification || attributionStatus),
    confidence_score: confidenceScore,
    margin,
    quality_score: qualityScore,
    evidence_items: evidenceItems,
    profile_version: rawItem.profile_version || '1.0.0',
    profile_hash: rawItem.profile_hash || (rawItem.config_hash ? String(rawItem.config_hash) : ''),
    config_version: rawItem.config_version || '1.0.0',
    config_hash: rawItem.config_hash ? String(rawItem.config_hash) : '',
    warnings: rawItem.warnings || [],
    validation: validationState,
  };
}
