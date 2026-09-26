import React, { useState, useEffect } from 'react';
import {
  Video, HardDrive, RefreshCw, Play, Wrench, Scissors,
  CheckCircle2, XCircle, Layers, Filter,
} from 'lucide-react';
import {
  Evidence, GapRecoveryTarget, GapRecoveryResponse, GapRecoverySlot, RecordingSession,
  ReconstructResponse, GapAnalysis, RecoveryTargetType,
} from '../types';
import { runFullPipeline, recoverGap, reconstructRecording } from '../services/api';
import { ContextHelp } from '../components/onboarding/ContextHelp';
import { VideoPlayer } from '../components/video/VideoPlayer';
import { WorkflowState, RecoveryOutcome } from '../workflow';

interface RecoveryViewProps {
  evidence: Evidence | null;
  evidenceList?: Evidence[];
  onSelectEvidence?: (e: Evidence) => void;
  onNavigateToHex: (offset: number) => void;
  workflow?: WorkflowState;
  onWorkflow?: (patch: Partial<WorkflowState>) => void;
  gapTarget?: GapRecoveryTarget | null;
  onClearGapTarget?: () => void;
}

export interface RecoveryTargetItem extends GapRecoveryTarget {
  id: string;
  targetType: RecoveryTargetType;
  length: number;
  source: string;
  reason: string;
  sessionRef?: string | null;
}

export type GapItem = RecoveryTargetItem;

/** Add seconds to a recorder-native wall clock and return "HH:MM:SS" (no tz shift). */
function nativeTimeAdd(target: GapRecoveryTarget, offsetSec: number): string {
  if (!target.startNative && !target.startNormalized) {
    return '—';
  }
  const m = (target.startNative || '').match(/^(\d{4})-(\d{2})-(\d{2})[T ](\d{2}):(\d{2}):(\d{2})/);
  if (m) {
    const t = Date.UTC(+m[1], +m[2] - 1, +m[3], +m[4], +m[5], +m[6]) + offsetSec * 1000;
    const d = new Date(t);
    const p = (n: number) => String(n).padStart(2, '0');
    return `${p(d.getUTCHours())}:${p(d.getUTCMinutes())}:${p(d.getUTCSeconds())}`;
  }
  if (target.startNormalized) {
    const base = new Date(target.startNormalized).getTime();
    if (!isNaN(base)) return new Date(base + offsetSec * 1000).toLocaleTimeString();
  }
  return `+${offsetSec}s`;
}

function fmtDur(s: number): string {
  if (s < 60) return `${s}s`;
  const m = Math.floor(s / 60), rs = s % 60;
  return `${m}m ${rs}s`;
}

function fmtBytes(bytes: number): string {
  if (bytes < 1024) return `${bytes} B`;
  if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} KB`;
  return `${(bytes / (1024 * 1024)).toFixed(2)} MB`;
}

/**
 * Build recovery target candidates from both:
 * 1. In-session temporal gaps (missing temporal segment within an identified recording)
 * 2. Physical unaccounted storage regions (unindexed physical storage ranges not attributed to parsed recordings)
 */
export function buildRecoveryTargets(
  sessions: RecordingSession[],
  gapAnalysis?: GapAnalysis | null
): RecoveryTargetItem[] {
  const items: RecoveryTargetItem[] = [];

  // 1. Temporal in-session gaps
  for (const s of sessions) {
    for (const g of s.gaps) {
      const scanStart = g.previous_offset + g.previous_length;
      const scanEnd = g.next_offset;
      const length = scanEnd > scanStart ? scanEnd - scanStart : 0;
      items.push({
        id: `temporal-ch${s.channel}-0x${g.next_offset.toString(16)}`,
        targetType: 'temporal_gap',
        channel: s.channel,
        scanStart,
        scanEnd,
        length,
        gapSeconds: g.missing_seconds,
        nominalSeconds: s.nominal_segment_seconds || 10,
        startNative: g.starts_after_native,
        startNormalized: g.starts_after_normalized,
        endNative: g.ends_before_native,
        endNormalized: g.ends_before_normalized,
        source: `Recording Session (Ch ${s.channel})`,
        reason: g.reason || `Missing footage for ${g.missing_seconds}s within recording session`,
        sessionRef: s.id,
      });
    }
  }

  // 2. Physical unaccounted storage regions
  const unaccounted = gapAnalysis?.coverage?.unaccounted_regions ?? [];
  for (let idx = 0; idx < unaccounted.length; idx++) {
    const u = unaccounted[idx];
    const offset = u.region.offset;
    const length = u.region.length;
    const scanEnd = offset + length;
    const nominal = sessions.find((s) => s.nominal_segment_seconds > 0)?.nominal_segment_seconds || 10;

    items.push({
      id: `physical-0x${offset.toString(16)}-0x${scanEnd.toString(16)}`,
      targetType: 'physical_unaccounted',
      channel: 0,
      scanStart: offset,
      scanEnd,
      length,
      gapSeconds: null,
      nominalSeconds: nominal,
      startNative: null,
      startNormalized: null,
      endNative: null,
      endNormalized: null,
      source: 'Physical Coverage Analysis',
      reason: u.reason || `${fmtBytes(length)} unreferenced by parsed recordings`,
      sessionRef: null,
    });
  }

  // Sort by scanStart ascending for predictable physical ordering
  return items.sort((a, b) => a.scanStart - b.scanStart);
}

const LEVEL_META: Record<string, { badge: string; label: string }> = {
  L1: { badge: 'badge-pass', label: 'L1 · Indexed (Active)' },
  L2: { badge: 'badge-review', label: 'L2 · Orphan carve' },
  L3: { badge: 'badge-review', label: 'L3 · Raw carve' },
};

/**
 * The reason no playable container exists, as the server reported it.
 *
 * The previous message named FFmpeg's absence unconditionally, which was a guess: a remux can
 * also fail because the codec cannot be stream-copied or because FFmpeg ran and errored. The
 * server now sends the actual reason in `remux_error`, so it is shown verbatim rather than
 * substituted.
 */
function remuxUnavailableMessage(res: ReconstructResponse): string {
  const base = 'Elementary stream extracted and hashed, but no playable MP4 was produced';
  return res.remux_error ? `${base}: ${res.remux_error}` : `${base}.`;
}

export const RecoveryView: React.FC<RecoveryViewProps> = ({
  evidence,
  evidenceList = [],
  onSelectEvidence,
  onNavigateToHex,
  onWorkflow,
  workflow,
  gapTarget,
  onClearGapTarget,
}) => {
  const [gaps, setGaps] = useState<RecoveryTargetItem[]>([]);
  const [targetFilter, setTargetFilter] = useState<'all' | 'temporal' | 'physical'>('all');
  const [loadingGaps, setLoadingGaps] = useState(false);
  const [selected, setSelected] = useState<RecoveryTargetItem | GapRecoveryTarget | null>(null);
  const [result, setResult] = useState<GapRecoveryResponse | null>(null);
  const [loadingRec, setLoadingRec] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [activePlayback, setActivePlayback] = useState<any | null>(null);
  const [reconstructing, setReconstructing] = useState<number | null>(null);

  // Load the list of recovery candidate targets for the current evidence.
  useEffect(() => {
    setGaps([]);
    setSelected(null);
    setResult(null);
    setError(null);
    setActivePlayback(null);
    if (evidence) loadGaps();
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [evidence?.id]);

  // A gap handed in from the Preliminary Timeline: select and recover it immediately.
  useEffect(() => {
    if (gapTarget && evidence) {
      setSelected(gapTarget);
      runGapRecovery(gapTarget);
    }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [gapTarget, evidence?.id]);

  const loadGaps = async () => {
    if (!evidence) return;
    setLoadingGaps(true);
    try {
      const run = await runFullPipeline(evidence.id);
      const sessions = run.recordings_timeline?.sessions ?? [];
      const targets = buildRecoveryTargets(sessions, run.gap_analysis);
      setGaps(targets);
    } catch (e: any) {
      setError(e?.message || 'Failed to load recovery candidates');
    } finally {
      setLoadingGaps(false);
    }
  };

  const runGapRecovery = async (target: GapRecoveryTarget) => {
    if (!evidence) return;
    // A finite, ordered byte region is required.
    if (!Number.isFinite(target.scanStart) || !Number.isFinite(target.scanEnd) || target.scanEnd <= target.scanStart) {
      setResult(null);
      setError(
        'This recovery target has no valid byte region to scan. ' +
        'Rebuild and restart the API server, then reload.'
      );
      return;
    }
    setLoadingRec(true);
    setError(null);
    setResult(null);
    setActivePlayback(null);
    try {
      const nominal = target.nominalSeconds || 10;
      const regionLen = target.scanEnd - target.scanStart;
      // For physical unaccounted regions without missing_seconds, calculate gap_seconds
      // so num_slots matches reasonable probing windows (e.g. 256KB-512KB per slot)
      const gapSec = (target.gapSeconds != null && target.gapSeconds > 0)
        ? target.gapSeconds
        : Math.max(nominal, Math.min(300, Math.ceil(regionLen / (256 * 1024)) * nominal));

      const res = await recoverGap(evidence.id, {
        channel: target.channel,
        scan_start: target.scanStart,
        scan_end: target.scanEnd,
        gap_seconds: gapSec,
        nominal_seconds: nominal,
        // Lets the server carve with the OEM's own structures (Hikvision MPEG-PS).
        oem_key: workflow?.parserUsed || workflow?.attributedOem || undefined,
      });
      setResult(res);
      const outcome: RecoveryOutcome =
        res.decision === 'completely_recovered' ? 'recovered'
        : res.decision === 'partially_recovered' ? 'partial'
        : 'not_recovered';
      if (onWorkflow) onWorkflow({ recoveryDone: true, recoveryRequired: true, recoveryOutcome: outcome });
    } catch (e: any) {
      setError(e?.message || 'Recovery failed');
    } finally {
      setLoadingRec(false);
    }
  };

  const selectGap = (item: RecoveryTargetItem) => {
    onClearGapTarget?.();
    setSelected(item);
    runGapRecovery(item);
  };

  const playSlot = async (slot: GapRecoverySlot) => {
    if (!evidence || !selected) return;
    setReconstructing(slot.index);
    try {
      const res = await reconstructRecording(evidence.id, `gapslot-${selected.channel}-${slot.index}`, {
        offset_start: slot.offset,
        length: slot.length,
        channel: selected.channel,
      });
      if (res.remux) {
        setActivePlayback({
          videoId: res.remux.artifact_id,
          videoUrl: res.remux.video_url,
          recordingId: `Recovered ${slot.level} · +${slot.start_offset_sec}s`,
          channel: selected.channel,
          oemName: evidence.source_device,
          sourceOffset: slot.offset,
          sourceLength: res.elementary_stream.size_bytes,
          nativeTime: selected.startNative ?? 'Unknown',
          normalizedUtc: selected.startNormalized ?? 'Unknown',
          codec: res.codec || slot.codec,
          elementarySha256: res.elementary_stream.sha256,
          remuxSha256: res.remux.sha256,
          ffmpegVersion: res.remux.ffmpeg_version,
          ffmpegArgs: res.remux.arguments,
          validationState: res.remux.validation_state,
        });
      } else {
        alert(remuxUnavailableMessage(res));
      }
    } catch (e: any) {
      alert(`Reconstruction failed: ${e?.message || e}`);
    } finally {
      setReconstructing(null);
    }
  };

  if (!evidence) {
    return (
      <div className="view-container" data-tour="recovery-view-panel">
        <div className="view-header">
          <div>
            <h1 className="view-title">Gap Recovery Engine</h1>
            <p className="view-subtitle">Select an evidence target to recover detected gaps.</p>
          </div>
        </div>
        <div className="empty-state">
          <Video size={32} />
          <h3>No Evidence Selected</h3>
          <p>Select a DVR/NVR evidence item from the active case to begin.</p>
        </div>
      </div>
    );
  }

  // Per-level summary of the current recovery.
  const levelSeconds = (lvl: string | null) =>
    (result?.slots.filter((s) => s.level === lvl).length ?? 0) * (result?.nominal_seconds ?? 0);

  const decisionMeta =
    result?.decision === 'completely_recovered'
      ? { color: 'var(--success)', badge: 'badge-pass', text: 'COMPLETELY RECOVERED' }
      : result?.decision === 'partially_recovered'
      ? { color: 'var(--warning)', badge: 'badge-review', text: 'PARTIALLY RECOVERED' }
      : { color: 'var(--danger)', badge: 'badge-fail', text: 'NOT RECOVERED' };

  return (
    <div className="view-container" data-tour="recovery-view-panel">
      <div className="view-header">
        <div>
          <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
            <h1 className="view-title">Gap Recovery Engine</h1>
            <ContextHelp
              title="Gap Recovery"
              content="Recovery runs per gap. Pick a detected gap (or use the Recover button in the Preliminary Timeline). The engine probes the gap's byte region as 10s sub-slots with a staged L1 → L2 → L3 cascade and reports which sub-ranges were recovered at which level and which remain missing."
            />
          </div>
          <p className="view-subtitle">Staged L1 → L2 → L3 recovery over one detected gap at a time</p>
        </div>
        <button className="btn btn-secondary" onClick={loadGaps} disabled={loadingGaps}>
          {loadingGaps ? <RefreshCw size={14} className="spin" /> : <RefreshCw size={14} />}
          <span>{loadingGaps ? 'Scanning…' : 'Rescan gaps'}</span>
        </button>
      </div>

      {/* Target evidence bar */}
      <div className="panel" style={{ padding: '16px', marginBottom: '20px', backgroundColor: 'var(--surface)' }}>
        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', flexWrap: 'wrap', gap: '14px' }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: '12px' }}>
            <HardDrive size={18} style={{ color: 'var(--accent)' }} />
            <div>
              <div style={{ fontSize: '11px', textTransform: 'uppercase', color: 'var(--text-muted)', fontWeight: 600 }}>Active Target</div>
              <div style={{ display: 'flex', alignItems: 'center', gap: '8px', marginTop: '2px' }}>
                <strong style={{ fontSize: '14px' }}>{evidence.source_device}</strong>
                <span className="badge badge-info">{evidence.image_format}</span>
              </div>
            </div>
          </div>
          {evidenceList && evidenceList.length > 1 && (
            <select
              className="form-select"
              style={{ width: '220px', padding: '6px 10px', fontSize: '12px' }}
              value={evidence.id}
              onChange={(e) => {
                const found = evidenceList.find((item) => item.id === e.target.value);
                if (found && onSelectEvidence) onSelectEvidence(found);
              }}
            >
              {evidenceList.map((item) => (
                <option key={item.id} value={item.id}>{item.source_device}</option>
              ))}
            </select>
          )}
        </div>
      </div>

      {error && (
        <div className="panel mb-4" style={{ borderLeft: '4px solid var(--danger)' }}>
          <strong>Recovery error</strong>
          <div className="text-muted" style={{ fontSize: '13px', marginTop: '4px' }}>{error}</div>
        </div>
      )}

      {activePlayback && (
        <div style={{ marginBottom: '20px' }}>
          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '8px' }}>
            <h3 style={{ margin: 0, fontSize: '14px', display: 'flex', alignItems: 'center', gap: '6px' }}>
              <Video size={16} style={{ color: 'var(--accent)' }} /> Recovered footage
            </h3>
            <button className="btn btn-secondary btn-sm" onClick={() => setActivePlayback(null)}>Close Player</button>
          </div>
          <VideoPlayer {...activePlayback} onClose={() => setActivePlayback(null)} />
        </div>
      )}

      {/* Staged recovery result for the selected gap / physical candidate */}
      {selected && (
        <div className="panel mb-4" style={{ padding: 0, overflow: 'hidden' }}>
          <div style={{ padding: '16px', borderBottom: '1px solid var(--border)', display: 'flex', alignItems: 'center', justifyContent: 'space-between', flexWrap: 'wrap', gap: '10px' }}>
            <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
              <Scissors size={18} style={{ color: 'var(--danger)' }} />
              <div>
                <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
                  <strong style={{ fontSize: '15px' }}>
                    {selected.targetType === 'physical_unaccounted'
                      ? 'Scanning Physical Storage Candidate'
                      : `Recovering Temporal Gap · Channel ${selected.channel}`}
                  </strong>
                  <span className={selected.targetType === 'physical_unaccounted' ? 'badge badge-info' : 'badge badge-warning'}>
                    {selected.targetType === 'physical_unaccounted' ? 'Unaccounted Storage Region' : 'In-Session Gap'}
                  </span>
                </div>
                <div className="mono" style={{ fontSize: '12px', color: 'var(--text-secondary)', marginTop: '2px' }}>
                  {selected.targetType === 'physical_unaccounted'
                    ? `Region: 0x${selected.scanStart.toString(16).toUpperCase()} → 0x${selected.scanEnd.toString(16).toUpperCase()} (${fmtBytes(selected.length || (selected.scanEnd - selected.scanStart))}) · Basis: Unaccounted storage`
                    : `${nativeTimeAdd(selected, 0)} → ${nativeTimeAdd(selected, selected.gapSeconds || 0)} · missing ${fmtDur(selected.gapSeconds || 0)} · 0x${selected.scanStart.toString(16).toUpperCase()} → 0x${selected.scanEnd.toString(16).toUpperCase()}`}
                </div>
              </div>
            </div>
            {loadingRec && <span className="badge badge-info"><RefreshCw size={11} className="spin" /> recovering…</span>}
          </div>

          {result && (
            <div style={{ padding: '16px' }}>
              {/* Decision + totals */}
              <div style={{ display: 'flex', alignItems: 'center', gap: '12px', flexWrap: 'wrap', marginBottom: '14px' }}>
                <span className={`badge ${decisionMeta.badge}`}>{decisionMeta.text}</span>
                <span style={{ fontSize: '13px', color: 'var(--text-secondary)' }}>
                  Recovered <strong style={{ color: 'var(--text-primary)' }}>{fmtDur(result.recovered_seconds)}</strong> of {fmtDur(result.total_seconds)}
                  {result.unrecovered_seconds > 0 && (
                    <span style={{ color: 'var(--warning)' }}> · {fmtDur(result.unrecovered_seconds)} not recovered</span>
                  )}
                </span>
              </div>

              {/* Per-level summary chips */}
              <div style={{ display: 'flex', gap: '8px', flexWrap: 'wrap', marginBottom: '14px' }}>
                <span className="badge badge-pass">L1 indexed: {fmtDur(levelSeconds('L1'))}</span>
                <span className="badge badge-review">L2 orphan: {fmtDur(levelSeconds('L2'))}</span>
                <span className="badge badge-review">L3 carve: {fmtDur(levelSeconds('L3'))}</span>
                <span className="badge badge-fail">Not recovered: {fmtDur(levelSeconds(null))}</span>
              </div>

              {/* Staged sub-slot breakdown, in time/offset order */}
              <div className="table-container">
                <table className="data-table">
                  <thead>
                    <tr>
                      <th>Sub-range</th>
                      <th>Stage</th>
                      <th>Data state</th>
                      <th>Status</th>
                      <th>Codec</th>
                      <th>Finding</th>
                      <th>Actions</th>
                    </tr>
                  </thead>
                  <tbody>
                    {result.slots.map((slot) => {
                      const meta = slot.level ? LEVEL_META[slot.level] : { badge: 'badge-fail', label: 'Not recovered' };
                      return (
                        <tr key={slot.index}>
                          <td className="mono">
                            {selected.targetType === 'physical_unaccounted'
                              ? `+${slot.start_offset_sec}s → +${slot.end_offset_sec}s`
                              : `${nativeTimeAdd(selected, slot.start_offset_sec)} → ${nativeTimeAdd(selected, slot.end_offset_sec)}`}
                          </td>
                          <td><span className={`badge ${meta.badge}`}>{meta.label}</span></td>
                          {/* A slot where nothing was found carries no data state. Showing
                              "Not established" keeps an absence of evidence from reading as
                              a finding. */}
                          <td>{slot.data_state ?? <span className="text-muted">Not established</span>}</td>
                          <td>
                            {slot.recovery_status == null ? (
                              <span className="text-muted">—</span>
                            ) : (
                              <span className={
                                slot.recovery_status === 'Recoverable' ? 'badge badge-pass'
                                : slot.recovery_status === 'PartiallyRecoverable' ? 'badge badge-review'
                                : 'badge badge-fail'
                              }>{slot.recovery_status}</span>
                            )}
                          </td>
                          <td>{slot.codec}</td>
                          <td className="text-muted" style={{ fontSize: '11px', maxWidth: '260px' }}>{slot.reason}</td>
                          <td>
                            <div style={{ display: 'flex', gap: '6px' }}>
                              {slot.level === 'L1' && (
                                <button
                                  className="btn btn-primary btn-sm"
                                  onClick={() => playSlot(slot)}
                                  disabled={reconstructing === slot.index}
                                  title="Reconstruct and preview this recovered sub-slot"
                                >
                                  {reconstructing === slot.index ? <RefreshCw size={12} className="spin" /> : <Play size={12} />}
                                  <span>{reconstructing === slot.index ? '…' : 'Play'}</span>
                                </button>
                              )}
                              <button
                                className="btn btn-secondary btn-sm"
                                onClick={() => onNavigateToHex(slot.data_offset ?? slot.offset)}
                                title="Open the byte inspector at the recovered stream data (first Annex-B start code) in this sub-range"
                              >
                                Hex
                              </button>
                            </div>
                          </td>
                        </tr>
                      );
                    })}
                  </tbody>
                </table>
              </div>

              {result.decision === 'not_recovered' && (
                <div style={{ marginTop: '12px', display: 'flex', alignItems: 'center', gap: '8px', color: 'var(--danger)', fontSize: '13px' }}>
                  <XCircle size={16} /> No footage could be carved from this candidate region at L1, L2, or L3.
                </div>
              )}
              {result.decision === 'completely_recovered' && (
                <div style={{ marginTop: '12px', display: 'flex', alignItems: 'center', gap: '8px', color: 'var(--success)', fontSize: '13px' }}>
                  <CheckCircle2 size={16} /> Every sub-slot of this candidate region was recovered.
                </div>
              )}
            </div>
          )}
        </div>
      )}

      {/* Recovery Candidates list (Temporal Gaps + Physical Unaccounted Regions) */}
      {(() => {
        const temporalTargets = gaps.filter((g) => g.targetType === 'temporal_gap');
        const physicalTargets = gaps.filter((g) => g.targetType === 'physical_unaccounted');
        const filteredGaps =
          targetFilter === 'temporal' ? temporalTargets
          : targetFilter === 'physical' ? physicalTargets
          : gaps;

        return (
          <div className="panel" style={{ padding: 0, overflow: 'hidden' }}>
            <div className="panel-header" style={{ margin: 0, padding: '16px', display: 'flex', alignItems: 'center', justifyContent: 'space-between', flexWrap: 'wrap', gap: '10px' }}>
              <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
                <Layers size={16} style={{ color: 'var(--accent)' }} />
                <h3 style={{ margin: 0, fontSize: '14px' }}>Recovery Candidates ({gaps.length})</h3>
                <ContextHelp
                  title="Recovery Candidates"
                  content="Candidates for carving include both temporal gaps (continuity shortfalls within identified camera sessions) and physical unaccounted storage regions (unindexed physical disk ranges not attributed to parsed recordings). Both can be carved with the staged L1 → L2 → L3 cascade."
                />
              </div>

              {/* Filter tabs */}
              <div style={{ display: 'flex', alignItems: 'center', gap: '6px' }}>
                <Filter size={13} style={{ color: 'var(--text-muted)' }} />
                <div style={{ display: 'flex', gap: '4px' }}>
                  <button
                    className={`btn btn-sm ${targetFilter === 'all' ? 'btn-primary' : 'btn-secondary'}`}
                    onClick={() => setTargetFilter('all')}
                  >
                    All ({gaps.length})
                  </button>
                  <button
                    className={`btn btn-sm ${targetFilter === 'temporal' ? 'btn-primary' : 'btn-secondary'}`}
                    onClick={() => setTargetFilter('temporal')}
                    title="Gaps within identified camera sessions"
                  >
                    Temporal ({temporalTargets.length})
                  </button>
                  <button
                    className={`btn btn-sm ${targetFilter === 'physical' ? 'btn-primary' : 'btn-secondary'}`}
                    onClick={() => setTargetFilter('physical')}
                    title="Physical unindexed storage regions"
                  >
                    Physical ({physicalTargets.length})
                  </button>
                </div>
              </div>
            </div>

            {filteredGaps.length === 0 ? (
              <div className="empty-state" style={{ padding: '28px' }}>
                <Wrench size={24} />
                <p>
                  {loadingGaps
                    ? 'Scanning for recovery candidates…'
                    : gaps.length === 0
                    ? 'No recovery candidates detected in this evidence. All storage regions are accounted for and all recording sessions are continuous.'
                    : 'No candidates match the selected filter.'}
                </p>
              </div>
            ) : (
              <div className="table-container" style={{ border: 'none', borderTop: '1px solid var(--border)', borderRadius: 0 }}>
                <table className="data-table">
                  <thead>
                    <tr>
                      <th>Type</th>
                      <th>Channel</th>
                      <th>Temporal Window</th>
                      <th>Missing / Size</th>
                      <th>Physical Byte Region</th>
                      <th>Basis / Provenance</th>
                      <th>Action</th>
                    </tr>
                  </thead>
                  <tbody>
                    {filteredGaps.map((g) => {
                      const isSel = selected != null &&
                        selected.scanStart === g.scanStart && selected.scanEnd === g.scanEnd && selected.channel === g.channel;
                      const isTemporal = g.targetType === 'temporal_gap';
                      return (
                        <tr key={g.id} style={isSel ? { background: 'var(--surface-muted)' } : undefined}>
                          <td>
                            <span className={isTemporal ? 'badge badge-warning' : 'badge badge-info'}>
                              {isTemporal ? 'Temporal Gap' : 'Physical Candidate'}
                            </span>
                          </td>
                          <td>
                            {isTemporal ? <strong>Ch {g.channel}</strong> : <span className="text-muted">Unallocated</span>}
                          </td>
                          <td className="mono" style={{ fontSize: '12px' }}>
                            {isTemporal ? (
                              `${nativeTimeAdd(g, 0)} → ${nativeTimeAdd(g, g.gapSeconds ?? 0)}`
                            ) : (
                              <span className="text-muted" style={{ fontSize: '11px' }}>Unindexed storage</span>
                            )}
                          </td>
                          <td style={isTemporal ? { color: 'var(--warning)', fontWeight: 600 } : undefined}>
                            {isTemporal && g.gapSeconds != null ? `${fmtDur(g.gapSeconds)} (${fmtBytes(g.length)})` : fmtBytes(g.length)}
                          </td>
                          <td className="mono" style={{ fontSize: '11px' }}>
                            0x{g.scanStart.toString(16).toUpperCase()} → 0x{g.scanEnd.toString(16).toUpperCase()}
                          </td>
                          <td className="text-muted" style={{ fontSize: '11px', maxWidth: '240px' }} title={g.reason}>
                            {g.reason}
                          </td>
                          <td>
                            <div style={{ display: 'flex', gap: '6px' }}>
                              <button
                                className="btn btn-primary btn-sm"
                                onClick={() => selectGap(g)}
                                disabled={loadingRec && isSel}
                                title="Run staged L1 → L2 → L3 recovery on this candidate range"
                              >
                                {loadingRec && isSel ? <RefreshCw size={12} className="spin" /> : <Wrench size={12} />}
                                <span>Recover</span>
                              </button>
                              <button
                                className="btn btn-secondary btn-sm"
                                onClick={() => onNavigateToHex(g.scanStart)}
                                title="Inspect bytes at start of this candidate range in the Byte Inspector"
                              >
                                Hex
                              </button>
                            </div>
                          </td>
                        </tr>
                      );
                    })}
                  </tbody>
                </table>
              </div>
            )}
          </div>
        );
      })()}
    </div>
  );
};
