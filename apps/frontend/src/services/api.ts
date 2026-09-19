import { Case, Evidence, Acquisition, SourceSafetyReport, CustodyEvent, HexChunkResponse, CapabilityStages, ClassifiedDetectionResult, StorageTopology, ParserRun, Recording } from '../types';

const API_BASE = '/api';

export async function createCase(data: { name: string; description: string; examiner: string }): Promise<Case> {
  const res = await fetch(`${API_BASE}/cases`, {
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
  const res = await fetch(`${API_BASE}/cases`);
  if (!res.ok) {
    const err = await res.json();
    throw new Error(err.error || 'Failed to list cases');
  }
  return res.json();
}

export async function getCase(id: string): Promise<Case> {
  const cleanId = id.replace('case-', '');
  const res = await fetch(`${API_BASE}/cases/${cleanId}`);
  if (!res.ok) {
    const err = await res.json();
    throw new Error(err.error || 'Failed to get case');
  }
  return res.json();
}

export async function registerEvidence(caseId: string, input: any): Promise<{ evidence: Evidence; acquisition?: Acquisition; ingest_hash: string }> {
  const cleanId = caseId.replace('case-', '');
  const res = await fetch(`${API_BASE}/cases/${cleanId}/evidence`, {
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
  const res = await fetch(`${API_BASE}/cases/${cleanId}/evidence`);
  if (!res.ok) {
    const err = await res.json();
    throw new Error(err.error || 'Failed to list case evidence');
  }
  return res.json();
}

export async function getEvidence(id: string): Promise<Evidence> {
  const cleanId = id.replace('evidence-', '');
  const res = await fetch(`${API_BASE}/evidence/${cleanId}`);
  if (!res.ok) {
    const err = await res.json();
    throw new Error(err.error || 'Failed to get evidence');
  }
  return res.json();
}

export async function getSourceSafety(evidenceId: string): Promise<SourceSafetyReport> {
  const cleanId = evidenceId.replace('evidence-', '');
  const res = await fetch(`${API_BASE}/evidence/${cleanId}/safety`);
  if (!res.ok) {
    const err = await res.json();
    throw new Error(err.error || 'Failed to get source safety report');
  }
  return res.json();
}

export async function getCustodyLog(caseId: string): Promise<CustodyEvent[]> {
  const cleanId = caseId.replace('case-', '');
  const res = await fetch(`${API_BASE}/cases/${cleanId}/custody`);
  if (!res.ok) {
    const err = await res.json();
    throw new Error(err.error || 'Failed to get chain of custody log');
  }
  return res.json();
}

export async function readEvidenceBytes(evidenceId: string, offset: number, length: number): Promise<HexChunkResponse> {
  const cleanId = evidenceId.replace('evidence-', '');
  const res = await fetch(`${API_BASE}/evidence/${cleanId}/bytes?offset=${offset}&length=${length}`);
  if (!res.ok) {
    const err = await res.json();
    throw new Error(err.error || 'Failed to read bytes');
  }
  return res.json();
}

export async function searchEvidence(evidenceId: string, offset: string | number, term: string, searchType: 'hex' | 'ascii'): Promise<{ found_offset: number | null }> {
  const cleanId = evidenceId.replace('evidence-', '');
  const res = await fetch(`${API_BASE}/evidence/${cleanId}/search?offset=${offset}&term=${encodeURIComponent(term)}&search_type=${searchType}`);
  if (!res.ok) {
    const err = await res.json();
    throw new Error(err.error || 'Failed to search bytes');
  }
  return res.json();
}

export async function getCapabilities(): Promise<Record<string, CapabilityStages>> {
  const res = await fetch(`${API_BASE}/capabilities`);
  if (!res.ok) {
    const err = await res.json();
    throw new Error(err.error || 'Failed to get capabilities');
  }
  return res.json();
}

import { normalizeDetectionResponse } from './adapters/detection';

export async function runDetection(evidenceId: string): Promise<ClassifiedDetectionResult[]> {
  const cleanId = evidenceId.replace('evidence-', '');
  const res = await fetch(`${API_BASE}/evidence/${cleanId}/detection`, { method: 'POST' });
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
  const res = await fetch(`${API_BASE}/evidence/${cleanId}/topology`);
  if (!res.ok) {
    const err = await res.json();
    throw new Error(err.error || 'Failed to get topology');
  }
  return res.json();
}

export async function runParsing(evidenceId: string, oemKey: string): Promise<{ parser_runs: ParserRun[], recordings: Recording[], timeline_events: any[] }> {
  const cleanId = evidenceId.replace('evidence-', '');
  const res = await fetch(`${API_BASE}/evidence/${cleanId}/parsing`, {
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

import { FfmpegInfo, ArtifactRecord, ArtifactVerificationResult, ReconstructResponse } from '../types';

export async function getFfmpegStatus(): Promise<FfmpegInfo> {
  const res = await fetch(`${API_BASE}/ffmpeg/status`);
  if (!res.ok) {
    const err = await res.json();
    throw new Error(err.error || 'Failed to get FFmpeg status');
  }
  return res.json();
}

export async function reconstructRecording(
  evidenceId: string,
  recordingId: string,
  payload?: { offset_start?: number; length?: number; channel?: number; oem_key?: string }
): Promise<ReconstructResponse> {
  const cleanEvId = evidenceId.replace('evidence-', '');
  const cleanRecId = recordingId.includes('-') && recordingId.length === 36 ? recordingId : uuidv4();

  const res = await fetch(`${API_BASE}/evidence/${cleanEvId}/recordings/${cleanRecId}/reconstruct`, {
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
  const res = await fetch(`${API_BASE}/artifacts/${artifactId}`);
  if (!res.ok) {
    const err = await res.json();
    throw new Error(err.error || 'Failed to fetch artifact');
  }
  return res.json();
}

export async function verifyArtifact(artifactId: string): Promise<ArtifactVerificationResult> {
  const res = await fetch(`${API_BASE}/artifacts/${artifactId}/verify`, { method: 'POST' });
  if (!res.ok) {
    const err = await res.json();
    throw new Error(err.error || 'Failed to verify artifact');
  }
  return res.json();
}

export async function listEvidenceArtifacts(evidenceId: string): Promise<ArtifactRecord[]> {
  const cleanId = evidenceId.replace('evidence-', '');
  const res = await fetch(`${API_BASE}/evidence/${cleanId}/artifacts`);
  if (!res.ok) {
    const err = await res.json();
    throw new Error(err.error || 'Failed to list artifacts');
  }
  return res.json();
}

function uuidv4(): string {
  return 'xxxxxxxx-xxxx-4xxx-yxxx-xxxxxxxxxxxx'.replace(/[xy]/g, function(c) {
    const r = Math.random() * 16 | 0, v = c == 'x' ? r : (r & 0x3 | 0x8);
    return v.toString(16);
  });
}
