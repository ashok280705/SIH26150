import { Case, Evidence, Acquisition, SourceSafetyReport, CustodyEvent, HexChunkResponse, CapabilityStages, ClassifiedDetectionResult, StorageTopology, ParserRun, Recording, ExaminerTimezone, PhysicalSource, SafetyAssessment, AcquisitionJobStatus } from '../types';
import { normalizeDetectionResponse } from './adapters/detection';
import { RecoveryResponse, UnifiedTimelineResponse, OrderingMode, PipelineRun } from '../types';
import { FfmpegInfo, ArtifactRecord, ArtifactVerificationResult, ReconstructResponse } from '../types';
import { GapRecoveryRequest, GapRecoveryResponse } from '../types';

declare global {
  interface Window {
    __VIDFORGE_API_BASE__?: string;
    __VIDFORGE_AUTH_TOKEN__?: string;
  }
}

/**
 * Resolves the base URL for the backend API according to priority:
 * 1. Desktop runtime injection: `window.__VIDFORGE_API_BASE__`
 * 2. Vite environment variable: `import.meta.env.VITE_API_BASE`
 * 3. Default fallback for development/browser mode: `'/api'`
 */
export function getApiBase(): string {
  if (typeof window !== 'undefined' && window.__VIDFORGE_API_BASE__) {
    return window.__VIDFORGE_API_BASE__.replace(/\/+$/, '');
  }
  const envBase = (import.meta as any).env?.VITE_API_BASE;
  if (envBase) {
    return envBase.replace(/\/+$/, '');
  }
  return '/api';
}

function getHeaders(customHeaders?: HeadersInit): Headers {
  const headers = new Headers(customHeaders || {});
  if (typeof window !== 'undefined' && window.__VIDFORGE_AUTH_TOKEN__) {
    headers.set('Authorization', `Bearer ${window.__VIDFORGE_AUTH_TOKEN__}`);
  }
  return headers;
}

/**
 * Unified fetch wrapper ensuring all API requests:
 * - Route to the configured runtime base (`getApiBase()`)
 * - Inject Authorization headers if desktop/session authentication is configured
 * - Strip duplicate `/api` path segments seamlessly
 */
export async function apiFetch(path: string, init?: RequestInit): Promise<Response> {
  const base = getApiBase();
  const cleanPath = path.startsWith('/api/')
    ? path.slice(4)
    : path === '/api'
    ? ''
    : path.startsWith('/')
    ? path
    : `/${path}`;

  const url = `${base}${cleanPath}`;
  const headers = getHeaders(init?.headers);
  return fetch(url, { ...init, headers });
}

export async function createCase(data: { name: string; description: string; examiner: string }): Promise<Case> {
  const res = await apiFetch('/cases', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(data),
  });
  if (!res.ok) {
    const err = await res.json();
    throw new Error(err.error || 'Failed to create case');
  }
  return res.json();
}

export async function listCases(): Promise<Case[]> {
  const res = await apiFetch('/cases');
  if (!res.ok) {
    const err = await res.json();
    throw new Error(err.error || 'Failed to list cases');
  }
  return res.json();
}

export async function getCase(id: string): Promise<Case> {
  const cleanId = id.replace('case-', '');
  const res = await apiFetch(`/cases/${cleanId}`);
  if (!res.ok) {
    const err = await res.json();
    throw new Error(err.error || 'Failed to get case');
  }
  return res.json();
}

export async function registerEvidence(caseId: string, input: any): Promise<{ evidence: Evidence; acquisition?: Acquisition; ingest_hash: string }> {
  const cleanId = caseId.replace('case-', '');
  const res = await apiFetch(`/cases/${cleanId}/evidence`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(input),
  });
  if (!res.ok) {
    const err = await res.json();
    throw new Error(err.error || 'Failed to register evidence');
  }
  return res.json();
}

export async function listCaseEvidence(caseId: string): Promise<Evidence[]> {
  const cleanId = caseId.replace('case-', '');
  const res = await apiFetch(`/cases/${cleanId}/evidence`);
  if (!res.ok) {
    const err = await res.json();
    throw new Error(err.error || 'Failed to list case evidence');
  }
  return res.json();
}

export async function getEvidence(id: string): Promise<Evidence> {
  const cleanId = id.replace('evidence-', '');
  const res = await apiFetch(`/evidence/${cleanId}`);
  if (!res.ok) {
    const err = await res.json();
    throw new Error(err.error || 'Failed to get evidence');
  }
  return res.json();
}

export async function getSourceSafety(evidenceId: string): Promise<SourceSafetyReport> {
  const cleanId = evidenceId.replace('evidence-', '');
  const res = await apiFetch(`/evidence/${cleanId}/safety`);
  if (!res.ok) {
    const err = await res.json();
    throw new Error(err.error || 'Failed to get source safety report');
  }
  return res.json();
}

export async function getCustodyLog(caseId: string): Promise<CustodyEvent[]> {
  const cleanId = caseId.replace('case-', '');
  const res = await apiFetch(`/cases/${cleanId}/custody`);
  if (!res.ok) {
    const err = await res.json();
    throw new Error(err.error || 'Failed to get chain of custody log');
  }
  return res.json();
}

export async function readEvidenceBytes(evidenceId: string, offset: number, length: number): Promise<HexChunkResponse> {
  const cleanId = evidenceId.replace('evidence-', '');
  const res = await apiFetch(`/evidence/${cleanId}/bytes?offset=${offset}&length=${length}`);
  if (!res.ok) {
    const err = await res.json();
    throw new Error(err.error || 'Failed to read bytes');
  }
  return res.json();
}

export async function searchEvidence(evidenceId: string, offset: string | number, term: string, searchType: 'hex' | 'ascii'): Promise<{ found_offset: number | null }> {
  const cleanId = evidenceId.replace('evidence-', '');
  const res = await apiFetch(`/evidence/${cleanId}/search?offset=${offset}&term=${encodeURIComponent(term)}&search_type=${searchType}`);
  if (!res.ok) {
    const err = await res.json();
    throw new Error(err.error || 'Failed to search bytes');
  }
  return res.json();
}

export async function getCapabilities(): Promise<Record<string, CapabilityStages>> {
  const res = await apiFetch('/capabilities');
  if (!res.ok) {
    const err = await res.json();
    throw new Error(err.error || 'Failed to get capabilities');
  }
  return res.json();
}

export async function runDetection(evidenceId: string): Promise<ClassifiedDetectionResult[]> {
  const cleanId = evidenceId.replace('evidence-', '');
  const res = await apiFetch(`/evidence/${cleanId}/detection`, { method: 'POST' });
  if (!res.ok) {
    const err = await res.json();
    throw new Error(err.error || 'Failed to run detection');
  }
  const rawList = await res.json();
  if (Array.isArray(rawList)) {
    return rawList.map(normalizeDetectionResponse);
  }
  return [normalizeDetectionResponse(rawList)];
}

export async function getTopology(evidenceId: string): Promise<StorageTopology> {
  const cleanId = evidenceId.replace('evidence-', '');
  const res = await apiFetch(`/evidence/${cleanId}/topology`);
  if (!res.ok) {
    const err = await res.json();
    throw new Error(err.error || 'Failed to get topology');
  }
  return res.json();
}

export async function runParsing(evidenceId: string, oemKey: string): Promise<{ parser_runs: ParserRun[], recordings: Recording[], timeline_events: any[] }> {
  const cleanId = evidenceId.replace('evidence-', '');
  const res = await apiFetch(`/evidence/${cleanId}/parsing`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ oem_key: oemKey })
  });
  if (!res.ok) {
    const err = await res.json();
    throw new Error(err.error || 'Failed to run parsing');
  }
  return res.json();
}

/**
 * Runs the entire forensic pipeline in one pass synchronously and returns the audited run.
 */
export async function runFullPipeline(evidenceId: string): Promise<PipelineRun> {
  const cleanId = evidenceId.replace('evidence-', '');
  const res = await apiFetch(`/evidence/${cleanId}/pipeline/run`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
  });
  if (!res.ok) {
    const err = await res.json().catch(() => ({}));
    throw new Error(err.error || 'Failed to run pipeline');
  }
  return res.json();
}

export interface PipelineJobProgress {
  stage: string;
  stage_name: string;
  stage_index: number;
  total_stages: number;
  description: string;
  fraction?: number;
}

export interface PipelineJobStatus {
  job_id: string;
  evidence_id: string;
  state: 'queued' | 'running' | 'completed' | 'cancelled' | 'failed';
  stage?: string;
  progress?: PipelineJobProgress;
  error?: string;
  result?: PipelineRun;
}

/**
 * Starts an asynchronous pipeline run job for the evidence.
 */
export async function startPipelineJob(evidenceId: string): Promise<{ job_id: string; state: string }> {
  const cleanId = evidenceId.replace('evidence-', '');
  const res = await apiFetch(`/evidence/${cleanId}/pipeline/start`, {
    method: 'POST',
  });
  if (!res.ok) {
    const err = await res.json().catch(() => ({}));
    throw new Error(err.error || 'Failed to start pipeline job');
  }
  return res.json();
}

/**
 * Queries the current progress, state, and outcome of an asynchronous pipeline job.
 */
export async function getPipelineJobStatus(jobId: string): Promise<PipelineJobStatus> {
  const res = await apiFetch(`/jobs/${jobId}`);
  if (!res.ok) {
    const err = await res.json().catch(() => ({}));
    throw new Error(err.error || 'Failed to query pipeline job');
  }
  return res.json();
}

/**
 * Requests cancellation of an asynchronous pipeline job.
 */
export async function cancelPipelineJob(jobId: string): Promise<{ job_id: string; state: string; message: string }> {
  const res = await apiFetch(`/jobs/${jobId}/cancel`, {
    method: 'POST',
  });
  if (!res.ok) {
    const err = await res.json().catch(() => ({}));
    throw new Error(err.error || 'Failed to cancel pipeline job');
  }
  return res.json();
}

/** Fetch the generated report as text plus its self-verifying hash and id. */
export async function fetchReport(
  evidenceId: string,
  format: 'json' | 'markdown' | 'csv' = 'json'
): Promise<{ body: string; reportId: string | null; sha256: string | null; contentType: string }> {
  const cleanId = evidenceId.replace('evidence-', '');
  const res = await apiFetch(`/evidence/${cleanId}/report?format=${format}`);
  if (!res.ok) {
    const err = await res.json().catch(() => ({}));
    throw new Error(err.error || 'Failed to generate report');
  }
  return {
    body: await res.text(),
    reportId: res.headers.get('X-Report-Id'),
    sha256: res.headers.get('X-Report-SHA256'),
    contentType: res.headers.get('Content-Type') || 'application/json',
  };
}

/**
 * Runs a bounded recovery scan. Candidates are derived from structures the parser
 * actually located in the image; the OEM is auto-detected unless `oemKey` is given.
 */
export async function runRecovery(evidenceId: string, oemKey?: string): Promise<RecoveryResponse> {
  const cleanId = evidenceId.replace('evidence-', '');
  const res = await apiFetch(`/evidence/${cleanId}/recovery`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(oemKey ? { oem_key: oemKey } : {})
  });
  if (!res.ok) {
    const err = await res.json();
    throw new Error(err.error || 'Failed to run recovery');
  }
  return res.json();
}

/**
 * Fetches the unified cross-camera timeline. Ordering is applied server-side by
 * TimelineEngine so the deterministic tie-break rules stay authoritative.
 */
export async function getTimeline(
  evidenceId: string,
  ordering: OrderingMode = 'Normalized',
  oemKey?: string
): Promise<UnifiedTimelineResponse> {
  const cleanId = evidenceId.replace('evidence-', '');
  const params = new URLSearchParams({ ordering });
  if (oemKey) params.set('oem_key', oemKey);
  const res = await apiFetch(`/evidence/${cleanId}/timeline?${params.toString()}`);
  if (!res.ok) {
    const err = await res.json();
    throw new Error(err.error || 'Failed to load timeline');
  }
  return res.json();
}

export async function getFfmpegStatus(): Promise<FfmpegInfo> {
  const res = await apiFetch('/ffmpeg/status');
  if (!res.ok) {
    const err = await res.json();
    throw new Error(err.error || 'Failed to get FFmpeg status');
  }
  return res.json();
}

export interface ReconstructPayload {
  offset_start?: number;
  length?: number;
  channel?: number;
  oem_key?: string;
  /** Explicit ordered physical ranges, e.g. every block of an engine-discovered recording. */
  regions?: { offset: number; length: number }[];
  /** The recovery engine's fragment id, carried onto the artifact's provenance. */
  fragment_id?: string;
  /**
   * An OEM recording id the parser can reconstruct frame-accurately (Dahua `dahua:...`,
   * Hikvision `hikclip:...`). Preferred over ranges: the server exports the parser's own
   * payload order rather than raw container bytes.
   */
  recording_chain_id?: string;
}

export async function reconstructRecording(
  evidenceId: string,
  recordingId: string,
  payload?: ReconstructPayload
): Promise<ReconstructResponse> {
  const cleanEvId = evidenceId.replace('evidence-', '');
  const recPath = encodeURIComponent(recordingId);

  const res = await apiFetch(`/evidence/${cleanEvId}/recordings/${recPath}/reconstruct`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(payload || {}),
  });
  if (!res.ok) {
    const err = await res.json();
    throw new Error(err.error || 'Failed to reconstruct recording');
  }
  return res.json();
}

export async function getArtifact(artifactId: string): Promise<ArtifactRecord> {
  const res = await apiFetch(`/artifacts/${artifactId}`);
  if (!res.ok) {
    const err = await res.json();
    throw new Error(err.error || 'Failed to fetch artifact');
  }
  return res.json();
}

/**
 * Runs a staged L1->L2->L3 recovery over one detected gap's byte region and returns
 * which time sub-ranges were recovered at which level and which remain missing.
 */
export async function recoverGap(evidenceId: string, req: GapRecoveryRequest): Promise<GapRecoveryResponse> {
  const cleanId = evidenceId.replace('evidence-', '');
  const res = await apiFetch(`/evidence/${cleanId}/recovery/gap`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(req),
  });
  if (!res.ok) {
    const err = await res.json();
    throw new Error(err.error || 'Failed to run gap recovery');
  }
  return res.json();
}

export async function verifyArtifact(artifactId: string): Promise<ArtifactVerificationResult> {
  const res = await apiFetch(`/artifacts/${artifactId}/verify`, { method: 'POST' });
  if (!res.ok) {
    const err = await res.json();
    throw new Error(err.error || 'Failed to verify artifact');
  }
  return res.json();
}

export async function listEvidenceArtifacts(evidenceId: string): Promise<ArtifactRecord[]> {
  const cleanId = evidenceId.replace('evidence-', '');
  const res = await apiFetch(`/evidence/${cleanId}/artifacts`);
  if (!res.ok) {
    const err = await res.json();
    throw new Error(err.error || 'Failed to fetch evidence artifacts');
  }
  return res.json();
}

/** Assigns an examiner-established timezone to an evidence image. */
export async function setEvidenceTimezone(
  evidenceId: string,
  payload: { timezone: string; source: string; examiner?: string; established_by?: string; notes?: string }
): Promise<ExaminerTimezone> {
  const cleanId = evidenceId.replace('evidence-', '');
  const res = await apiFetch(`/evidence/${cleanId}/timezone`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(payload),
  });
  if (!res.ok) {
    const err = await res.json().catch(() => ({}));
    throw new Error(err.error || 'Failed to set evidence timezone');
  }
  return res.json();
}

/** Removes examiner-established timezone, reverting interpretation to filesystem facts. */
export async function clearEvidenceTimezone(
  evidenceId: string
): Promise<{ status: string; message: string }> {
  const cleanId = evidenceId.replace('evidence-', '');
  const res = await apiFetch(`/evidence/${cleanId}/timezone`, {
    method: 'DELETE',
  });
  if (!res.ok) {
    const err = await res.json().catch(() => ({}));
    throw new Error(err.error || 'Failed to clear evidence timezone');
  }
  return res.json();
}

/** Retrieves the current examiner-established timezone for evidence. */
export async function getEvidenceTimezone(
  evidenceId: string
): Promise<{ evidence_id: string; examiner_timezone: ExaminerTimezone | null }> {
  const cleanId = evidenceId.replace('evidence-', '');
  const res = await apiFetch(`/evidence/${cleanId}/timezone`);
  if (!res.ok) {
    const err = await res.json().catch(() => ({}));
    throw new Error(err.error || 'Failed to get evidence timezone');
  }
  return res.json();
}

/** Lists enumerated physical drives available on the Windows host. */
export async function listAcquisitionDevices(): Promise<PhysicalSource[]> {
  const res = await apiFetch('/acquisition/devices');
  if (!res.ok) {
    const err = await res.json().catch(() => ({}));
    throw new Error(err.error || 'Failed to enumerate physical devices');
  }
  return res.json();
}

/** Evaluates safety invariants for a physical source and destination path. */
export async function assessAcquisitionSafety(
  source: PhysicalSource,
  config: any
): Promise<SafetyAssessment> {
  const res = await apiFetch('/acquisition/assess', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ source, config }),
  });
  if (!res.ok) {
    const err = await res.json().catch(() => ({}));
    throw new Error(err.error || 'Safety assessment rejected');
  }
  return res.json();
}

/** Initiates an asynchronous physical disk acquisition job. */
export async function startAcquisitionJob(input: {
  source_drive: number;
  destination_path: string;
  case_id: string;
  examiner: string;
  chunk_size?: number;
  max_retries?: number;
  attestation: any;
  attempt_volume_lock?: boolean;
}): Promise<{ job_id: string; state: string }> {
  const cleanCaseId = input.case_id.replace('case-', '');
  const res = await apiFetch('/acquisition/jobs', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({
      ...input,
      case_id: cleanCaseId,
    }),
  });
  if (!res.ok) {
    const err = await res.json().catch(() => ({}));
    throw new Error(err.error || 'Failed to start acquisition job');
  }
  return res.json();
}

/** Polls the real-time status of an acquisition job. */
export async function getAcquisitionJob(jobId: string): Promise<AcquisitionJobStatus> {
  const res = await apiFetch(`/acquisition/jobs/${jobId}`);
  if (!res.ok) {
    const err = await res.json().catch(() => ({}));
    throw new Error(err.error || 'Failed to query acquisition job');
  }
  return res.json();
}

/** Cancels an active or queued acquisition job. */
export async function cancelAcquisitionJob(jobId: string): Promise<{ job_id: string; state: string; message: string }> {
  const res = await apiFetch(`/acquisition/jobs/${jobId}/cancel`, {
    method: 'POST',
  });
  if (!res.ok) {
    const err = await res.json().catch(() => ({}));
    throw new Error(err.error || 'Failed to cancel acquisition job');
  }
  return res.json();
}

/** Registers a finalized, verified physical acquisition as active VidForge evidence. */
export async function registerAcquisitionEvidence(
  jobId: string,
  options?: { examiner_timezone?: string }
): Promise<{ evidence: Evidence; acquisition: Acquisition; ingest_hash: string }> {
  const res = await apiFetch(`/acquisition/jobs/${jobId}/register`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(options || {}),
  });
  if (!res.ok) {
    const err = await res.json().catch(() => ({}));
    throw new Error(err.error || 'Failed to register acquisition evidence');
  }
  return res.json();
}
