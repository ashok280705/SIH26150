import React, { useState, useEffect, useMemo } from 'react';
import {
  RefreshCw, HardDrive, CheckCircle2, AlertTriangle, ArrowRight,
  Film, Clock, Scissors, Video, Play, ChevronUp, ChevronDown, Filter, Calendar,
} from 'lucide-react';
import {
  Evidence, PipelineRun, RecordingSession, SessionGap, GapRecoveryResponse, ReconstructResponse,
} from '../types';
import { runFullPipeline, recoverGap, reconstructRecording } from '../services/api';
import { ContextHelp } from '../components/onboarding/ContextHelp';
import { VideoPlayer } from '../components/video/VideoPlayer';
import { WorkflowState } from '../workflow';

// ── Display helpers (identical semantics to the Preliminary Timeline) ─────────
// Recorder-native strings are naive local wall-clock and are shown verbatim; we only
// reformat for readability, never shifting the clock. When native is absent we fall
// back to the normalized UTC instant.

function parseNative(s: string | null | undefined): { date: string; time: string } | null {
  if (!s) return null;
  const m = s.match(/^(\d{4})-(\d{2})-(\d{2})[T ](\d{2}):(\d{2}):(\d{2})/);
  if (!m) return null;
  const [, y, mo, d, hh, mm, ss] = m;
  return { date: `${d}/${mo}/${y}`, time: `${hh}:${mm}:${ss}` };
}

function fmtDateTime(native: string | null | undefined, normalizedFallback?: string | null): string {
  const p = parseNative(native);
  if (p) return `${p.date} ${p.time}`;
  if (normalizedFallback) {
    const dt = new Date(normalizedFallback);
    if (!isNaN(dt.getTime())) return dt.toLocaleString();
  }
  return '—';
}

function fmtTime(native: string | null | undefined, normalizedFallback?: string | null): string {
  const p = parseNative(native);
  if (p) return p.time;
  if (normalizedFallback) {
    const dt = new Date(normalizedFallback);
    if (!isNaN(dt.getTime())) return dt.toLocaleTimeString();
  }
  return '—';
}

function fmtDate(native: string | null | undefined, normalizedFallback?: string | null): string {
  const p = parseNative(native);
  if (p) return p.date;
  if (normalizedFallback) {
    const dt = new Date(normalizedFallback);
    if (!isNaN(dt.getTime())) return dt.toLocaleDateString();
  }
  return 'Unknown date';
}

function fmtDuration(totalSeconds: number): string {
  const s = Math.max(0, Math.round(totalSeconds));
  if (s < 60) return `${s}s`;
  const m = Math.floor(s / 60);
  const rs = s % 60;
  if (m < 60) return `${m}m ${rs}s`;
  const h = Math.floor(m / 60);
  const rm = m % 60;
  return `${h}h ${String(rm).padStart(2, '0')}m`;
}

function fmtBytes(bytes: number): string {
  if (bytes < 1024) return `${bytes} B`;
  if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} KB`;
  return `${(bytes / (1024 * 1024)).toFixed(2)} MB`;
}

function nativeAddSeconds(native: string | null | undefined, secs: number): string | null {
  if (!native) return null;
  const m = native.match(/^(\d{4})-(\d{2})-(\d{2})[T ](\d{2}):(\d{2}):(\d{2})/);
  if (!m) return null;
  const t = Date.UTC(+m[1], +m[2] - 1, +m[3], +m[4], +m[5], +m[6]) + secs * 1000;
  const d = new Date(t);
  const p = (n: number) => String(n).padStart(2, '0');
  return `${d.getUTCFullYear()}-${p(d.getUTCMonth() + 1)}-${p(d.getUTCDate())}T${p(d.getUTCHours())}:${p(d.getUTCMinutes())}:${p(d.getUTCSeconds())}`;
}

function isoAddSeconds(iso: string, secs: number): string {
  const t = new Date(iso).getTime();
  return isNaN(t) ? iso : new Date(t + secs * 1000).toISOString();
}

// ── Final-timeline row model ──────────────────────────────────────────────────
// The Final Timeline is the post-recovery picture. Every row is either:
//   * recorded  — a segment the parser found directly (green),
//   * recovered — a sub-range the Recovery Engine carved back (L1/L2/L3, blue),
//   * lost      — a sub-range no level could recover ("Ns recording lost", red).
type FinalKind = 'recorded' | 'recovered' | 'lost';

interface FinalRow {
  kind: FinalKind;
  key: string;
  no: number | null;
  channel: number;
  startNative: string | null;
  startNormalized: string;
  endNative: string | null;
  endNormalized: string;
  durationSec: number;
  sizeBytes: number;
  /** Byte offset used for Play/reconstruction. */
  offset: number;
  length: number;
  /** Byte offset the Hex inspector jumps to (recovered rows point at the stream data). */
  hexOffset: number;
  level?: 'L1' | 'L2' | 'L3' | null;
  codec?: string;
  reason?: string;
}

type SortKey = 'no' | 'channel' | 'start' | 'duration' | 'size';
type SortDir = 'asc' | 'desc';

const LEVEL_LABEL: Record<string, string> = {
  L1: 'RECOVERED · L1 indexed',
  L2: 'RECOVERED · L2 orphan',
  L3: 'RECOVERED · L3 carve',
};

/** Stable key for a gap within a session (its ending offset is unique per session). */
function gapKey(session: RecordingSession, gap: SessionGap): string {
  return `${session.id}-0x${gap.next_offset.toString(16)}`;
}

/** Build the flat post-recovery row list: recorded segments + recovered/lost slots. */
function buildRows(
  sessions: RecordingSession[],
  recoveries: Map<string, GapRecoveryResponse>,
): FinalRow[] {
  const footage: FinalRow[] = []; // recorded + recovered (numbered chronologically)
  const lost: FinalRow[] = [];

  for (const s of sessions) {
    const dur = s.nominal_segment_seconds || 0;

    // 1. Directly recorded segments.
    for (const seg of s.segments) {
      const startNorm = seg.start_normalized ?? s.start_normalized;
      footage.push({
        kind: 'recorded',
        key: `rec-${s.id}-${seg.source_offset}`,
        no: 0,
        channel: seg.channel,
        startNative: seg.start_native,
        startNormalized: startNorm,
        endNative: nativeAddSeconds(seg.start_native, dur),
        endNormalized: isoAddSeconds(startNorm, dur),
        durationSec: dur,
        sizeBytes: seg.source_length || 0,
        offset: seg.source_offset,
        length: seg.source_length || 0,
        hexOffset: seg.source_offset,
      });
    }

    // 2. Recovery outcome for each gap: recovered sub-slots + lost sub-slots.
    for (const g of s.gaps) {
      const rec = recoveries.get(gapKey(s, g));
      if (rec && rec.slots.length > 0) {
        for (const slot of rec.slots) {
          const slotDur = Math.max(1, slot.end_offset_sec - slot.start_offset_sec);
          const startNative = nativeAddSeconds(g.starts_after_native, slot.start_offset_sec);
          const startNorm = isoAddSeconds(g.starts_after_normalized, slot.start_offset_sec);
          const common = {
            channel: s.channel,
            startNative,
            startNormalized: startNorm,
            endNative: nativeAddSeconds(g.starts_after_native, slot.end_offset_sec),
            endNormalized: isoAddSeconds(g.starts_after_normalized, slot.end_offset_sec),
            durationSec: slotDur,
            offset: slot.offset,
            length: slot.length,
            hexOffset: slot.data_offset ?? slot.offset,
          };
          if (slot.level) {
            footage.push({
              kind: 'recovered',
              key: `rcv-${s.id}-${g.next_offset}-${slot.index}`,
              no: 0,
              sizeBytes: slot.length,
              level: slot.level,
              codec: slot.codec,
              reason: slot.reason,
              ...common,
            });
          } else {
            lost.push({
              kind: 'lost',
              key: `lost-${s.id}-${g.next_offset}-${slot.index}`,
              no: null,
              sizeBytes: 0,
              codec: slot.codec,
              reason: slot.reason,
              ...common,
            });
          }
        }
      } else {
        // No recovery result for this gap (recovery failed or region invalid):
        // represent the whole gap as a single lost row rather than inventing slots.
        lost.push({
          kind: 'lost',
          key: `lost-${s.id}-${g.next_offset}-whole`,
          no: null,
          channel: s.channel,
          startNative: g.starts_after_native,
          startNormalized: g.starts_after_normalized,
          endNative: g.ends_before_native,
          endNormalized: g.ends_before_normalized,
          durationSec: g.missing_seconds,
          sizeBytes: 0,
          offset: g.next_offset,
          length: 0,
          hexOffset: g.next_offset,
        });
      }
    }
  }

  // Number recorded + recovered footage chronologically (then by channel).
  footage.sort((a, b) => a.startNormalized.localeCompare(b.startNormalized) || a.channel - b.channel);
  footage.forEach((c, i) => { c.no = i + 1; });
  return [...footage, ...lost];
}

function rowWhen(c: FinalRow): { dateKey: string; dateLabel: string; tod: number } | null {
  const m = (c.startNative || '').match(/^(\d{4})-(\d{2})-(\d{2})[T ](\d{2}):(\d{2}):(\d{2})/);
  if (m) {
    const [, y, mo, d, hh, mm, ss] = m;
    return { dateKey: `${y}-${mo}-${d}`, dateLabel: `${d}/${mo}/${y}`, tod: +hh * 3600 + +mm * 60 + +ss };
  }
  const dt = new Date(c.startNormalized);
  if (!isNaN(dt.getTime())) {
    const p = (n: number) => String(n).padStart(2, '0');
    return {
      dateKey: `${dt.getUTCFullYear()}-${p(dt.getUTCMonth() + 1)}-${p(dt.getUTCDate())}`,
      dateLabel: `${p(dt.getUTCDate())}/${p(dt.getUTCMonth() + 1)}/${dt.getUTCFullYear()}`,
      tod: dt.getUTCHours() * 3600 + dt.getUTCMinutes() * 60 + dt.getUTCSeconds(),
    };
  }
  return null;
}

function hhmmToSec(v: string): number | null {
  const m = v.match(/^(\d{1,2}):(\d{2})$/);
  if (!m) return null;
  return +m[1] * 3600 + +m[2] * 60;
}

interface Props {
  evidence: Evidence | null;
  evidenceList?: Evidence[];
  onSelectEvidence?: (e: Evidence) => void;
  onNavigateToHex: (offset: number) => void;
  onWorkflow?: (patch: Partial<WorkflowState>) => void;
}

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

export const TimelineView: React.FC<Props> = ({
  evidence,
  evidenceList = [],
  onSelectEvidence,
  onNavigateToHex,
  onWorkflow,
}) => {
  const [run, setRun] = useState<PipelineRun | null>(null);
  const [recoveries, setRecoveries] = useState<Map<string, GapRecoveryResponse>>(new Map());
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const [sortKey, setSortKey] = useState<SortKey>('start');
  const [sortDir, setSortDir] = useState<SortDir>('asc');
  const [channelFilter, setChannelFilter] = useState<number | 'all'>('all');
  const [statusFilter, setStatusFilter] = useState<'all' | 'recorded' | 'recovered' | 'lost'>('all');
  const [dateFilter, setDateFilter] = useState<string>('all');
  const [timeStart, setTimeStart] = useState<string>('');
  const [timeEnd, setTimeEnd] = useState<string>('');

  const [selectedRow, setSelectedRow] = useState<string | null>(null);
  const [activePlayback, setActivePlayback] = useState<any | null>(null);
  const [reconstructing, setReconstructing] = useState<string | null>(null);
  const [playError, setPlayError] = useState<string | null>(null);

  useEffect(() => {
    setRun(null);
    setRecoveries(new Map());
    setError(null);
    setActivePlayback(null);
    setSelectedRow(null);
    setPlayError(null);
    setDateFilter('all');
    setTimeStart('');
    setTimeEnd('');
    if (evidence) build();
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [evidence?.id]);

  const build = async () => {
    if (!evidence) return;
    setLoading(true);
    setError(null);
    try {
      const r = await runFullPipeline(evidence.id);
      setRun(r);

      // Fold in the Recovery Engine result for every detected gap so recovered
      // footage lands in the timeline and unrecovered footage is marked lost.
      const sessions = r.recordings_timeline?.sessions ?? [];
      const map = new Map<string, GapRecoveryResponse>();
      await Promise.all(
        sessions.flatMap((s) =>
          s.gaps.map(async (g) => {
            const scanStart = g.previous_offset + g.previous_length;
            const scanEnd = g.next_offset;
            if (!Number.isFinite(scanStart) || !Number.isFinite(scanEnd) || scanEnd <= scanStart) return;
            try {
              const res = await recoverGap(evidence.id, {
                channel: s.channel,
                scan_start: scanStart,
                scan_end: scanEnd,
                gap_seconds: g.missing_seconds,
                nominal_seconds: s.nominal_segment_seconds || 10,
                // The OEM the pipeline actually used, so the gap is carved with that OEM's
                // own structures (Hikvision MPEG-PS) rather than generically.
                oem_key: (!r.used_unified_fallback && r.oem_key_used) || undefined,
              });
              map.set(gapKey(s, g), res);
            } catch {
              // Leave this gap unrecovered; buildRows will render it as lost.
            }
          })
        )
      );
      setRecoveries(map);

      // The final timeline is now built — unlock the Video Player and Reports.
      if (onWorkflow) onWorkflow({ finalTimelineBuilt: true });
    } catch (e: any) {
      setError(e?.message || 'Failed to build the final timeline');
    } finally {
      setLoading(false);
    }
  };

  const recordingsTimeline = run?.recordings_timeline ?? null;
  const sessions = recordingsTimeline?.sessions ?? [];

  const allRows = useMemo(() => buildRows(sessions, recoveries), [sessions, recoveries]);
  const channels = useMemo(
    () => Array.from(new Set(allRows.map((c) => c.channel))).sort((a, b) => a - b),
    [allRows]
  );

  const availableDates = useMemo(() => {
    const map = new Map<string, string>();
    for (const c of allRows) {
      const w = rowWhen(c);
      if (w) map.set(w.dateKey, w.dateLabel);
    }
    return Array.from(map.entries())
      .sort((a, b) => a[0].localeCompare(b[0]))
      .map(([key, label]) => ({ key, label }));
  }, [allRows]);

  const rows = useMemo(() => {
    const todStart = hhmmToSec(timeStart);
    const todEnd = hhmmToSec(timeEnd);
    let list = allRows.filter((c) => {
      if (channelFilter !== 'all' && c.channel !== channelFilter) return false;
      if (statusFilter !== 'all' && c.kind !== statusFilter) return false;
      if (dateFilter !== 'all') {
        const w = rowWhen(c);
        if (!w || w.dateKey !== dateFilter) return false;
        if (todStart !== null && w.tod < todStart) return false;
        if (todEnd !== null && w.tod > todEnd + 59) return false;
      }
      return true;
    });
    const dir = sortDir === 'asc' ? 1 : -1;
    list = [...list].sort((a, b) => {
      switch (sortKey) {
        case 'channel': return (a.channel - b.channel) * dir || a.startNormalized.localeCompare(b.startNormalized);
        case 'duration': return (a.durationSec - b.durationSec) * dir;
        case 'size': return (a.sizeBytes - b.sizeBytes) * dir;
        case 'no': return ((a.no ?? Number.MAX_SAFE_INTEGER) - (b.no ?? Number.MAX_SAFE_INTEGER)) * dir;
        case 'start':
        default: return a.startNormalized.localeCompare(b.startNormalized) * dir || (a.channel - b.channel);
      }
    });
    return list;
  }, [allRows, channelFilter, statusFilter, dateFilter, timeStart, timeEnd, sortKey, sortDir]);

  const toggleSort = (key: SortKey) => {
    if (sortKey === key) {
      setSortDir((d) => (d === 'asc' ? 'desc' : 'asc'));
    } else {
      setSortKey(key);
      setSortDir(key === 'start' || key === 'channel' || key === 'no' ? 'asc' : 'desc');
    }
  };

  // Post-recovery totals across all rows.
  const totals = useMemo(() => {
    let recorded = 0, recovered = 0, lost = 0;
    for (const c of allRows) {
      if (c.kind === 'recorded') recorded += c.durationSec;
      else if (c.kind === 'recovered') recovered += c.durationSec;
      else lost += c.durationSec;
    }
    const known = recorded + recovered + lost;
    const coverageAfter = known > 0 ? ((recorded + recovered) / known) * 100 : 0;
    return { recorded, recovered, lost, coverageAfter };
  }, [allRows]);

  const playRow = async (row: FinalRow) => {
    if (!evidence || row.kind === 'lost' || row.length === 0) return;
    setSelectedRow(row.key);
    setReconstructing(row.key);
    setPlayError(null);
    try {
      const res = await reconstructRecording(evidence.id, row.key, {
        offset_start: row.offset,
        length: row.length,
        channel: row.channel,
      });
      if (res.remux) {
        setActivePlayback({
          videoId: res.remux.artifact_id,
          videoUrl: res.remux.video_url,
          recordingId:
            row.kind === 'recovered'
              ? `Recovered ${row.level} · Ch${row.channel} · ${fmtDateTime(row.startNative, row.startNormalized)}`
              : `Ch${row.channel} · ${fmtDateTime(row.startNative, row.startNormalized)}`,
          channel: row.channel,
          oemName: evidence.source_device,
          sourceOffset: row.offset,
          sourceLength: res.elementary_stream.size_bytes,
          nativeTime: row.startNative ?? 'Unknown',
          normalizedUtc: row.startNormalized ?? 'Unknown',
          codec: res.codec || row.codec,
          elementarySha256: res.elementary_stream.sha256,
          remuxSha256: res.remux.sha256,
          ffmpegVersion: res.remux.ffmpeg_version,
          ffmpegArgs: res.remux.arguments,
          validationState: res.remux.validation_state,
        });
      } else {
        setActivePlayback(null);
        setPlayError(remuxUnavailableMessage(res));
      }
    } catch (err: any) {
      setActivePlayback(null);
      setPlayError(err?.message || 'Reconstruction failed');
    } finally {
      setReconstructing(null);
    }
  };

  if (!evidence) {
    return (
      <div className="view-container" data-tour="timeline-view-panel">
        <div className="view-header">
          <div>
            <h1 className="view-title">Final Forensic Timeline</h1>
            <p className="view-subtitle">Select an evidence target to build the final timeline.</p>
          </div>
        </div>
        <div className="empty-state"><Clock size={32} /><h3>No Evidence Selected</h3></div>
      </div>
    );
  }

  const sortIcon = (key: SortKey) =>
    sortKey === key ? (sortDir === 'asc' ? <ChevronUp size={12} /> : <ChevronDown size={12} />) : null;

  const fullyIntact = totals.lost === 0 && totals.recovered === 0;

  return (
    <div className="view-container" data-tour="timeline-view-panel">
      <div className="view-header">
        <div>
          <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
            <h1 className="view-title">Final Forensic Timeline</h1>
            <ContextHelp
              title="Final Timeline"
              content="The post-recovery timeline. It starts from the preliminary recordings, then folds in the Recovery Engine's result: sub-ranges recovered at L1/L2/L3 are added back as recordings, and sub-ranges that no level could recover are marked as lost footage."
            />
          </div>
          <p className="view-subtitle">Recorded + recovered footage merged · unrecovered sub-ranges marked lost</p>
        </div>
        <button className="btn btn-secondary" onClick={build} disabled={loading}>
          {loading ? <RefreshCw size={14} className="spin" /> : <RefreshCw size={14} />}
          <span>Rebuild</span>
        </button>
      </div>

      {/* Target bar */}
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
            <div style={{ display: 'flex', alignItems: 'center', gap: '6px' }}>
              <label style={{ fontSize: '12px', fontWeight: 600, color: 'var(--text-secondary)' }}>Switch Target:</label>
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
            </div>
          )}
        </div>
      </div>

      {error && (
        <div className="panel mb-4" style={{ borderLeft: '4px solid var(--danger)' }}>
          <strong>Failed to build the final timeline</strong>
          <div className="text-muted" style={{ fontSize: '13px', marginTop: '4px' }}>{error}</div>
        </div>
      )}

      {loading && !run && <div className="empty-state"><RefreshCw size={28} className="spin" /><h3>Building final timeline…</h3></div>}

      {run && (
        <>
          {/* ── Timeline & Coverage (post-recovery, per channel) ─────────────── */}
          {recordingsTimeline && sessions.length > 0 && (
            <div className="panel mb-4" style={{ padding: '16px' }}>
              <div style={{ display: 'flex', alignItems: 'center', gap: '8px', marginBottom: '4px' }}>
                <Clock size={18} style={{ color: 'var(--accent)' }} />
                <strong style={{ fontSize: '15px' }}>Timeline &amp; Coverage (post-recovery)</strong>
                <ContextHelp
                  title="Post-recovery Timeline"
                  content="Each channel drawn to scale. Green is originally recorded footage, blue is footage recovered by the engine, and red hatching is footage that remains lost. Click a recovered or lost block to inspect its bytes."
                />
              </div>
              <p className="text-muted" style={{ fontSize: '12px', margin: '0 0 10px' }}>
                Sorted by date · recovered footage folded in · lost footage marked, never filled
              </p>

              {/* Legend */}
              <div style={{ display: 'flex', gap: '16px', flexWrap: 'wrap', fontSize: '11px', color: 'var(--text-secondary)', marginBottom: '14px' }}>
                <LegendSwatch color="var(--success)" label="Recorded" />
                <LegendSwatch color="var(--accent)" label="Recovered (L1–L3)" />
                <LegendSwatch hatch label="Lost" />
              </div>

              {sessions.map((session, idx) => {
                const prev = sessions[idx - 1];
                const showDateHeader =
                  idx === 0 || fmtDate(prev?.start_native, prev?.start_normalized) !== fmtDate(session.start_native, session.start_normalized);
                return (
                  <React.Fragment key={session.id}>
                    {showDateHeader && (
                      <div style={{ fontSize: '11px', textTransform: 'uppercase', letterSpacing: '0.04em', color: 'var(--text-muted)', fontWeight: 700, margin: idx === 0 ? '0 0 8px' : '18px 0 8px' }}>
                        {fmtDate(session.start_native, session.start_normalized)}
                      </div>
                    )}
                    <RecordingCard
                      session={session}
                      recoveries={recoveries}
                      onNavigateToHex={onNavigateToHex}
                    />
                  </React.Fragment>
                );
              })}
            </div>
          )}

          {/* Verdict */}
          <div className="panel mb-4" style={{ borderLeft: `4px solid ${fullyIntact ? 'var(--success)' : totals.lost === 0 ? 'var(--accent)' : 'var(--warning)'}` }}>
            <div style={{ display: 'flex', alignItems: 'flex-start', gap: '12px' }}>
              {totals.lost === 0 ? (
                <CheckCircle2 size={22} style={{ color: fullyIntact ? 'var(--success)' : 'var(--accent)', flexShrink: 0 }} />
              ) : (
                <AlertTriangle size={22} style={{ color: 'var(--warning)', flexShrink: 0 }} />
              )}
              <div>
                <div style={{ display: 'flex', alignItems: 'center', gap: '10px', flexWrap: 'wrap' }}>
                  <strong style={{ fontSize: '15px' }}>Final Coverage</strong>
                  <span className={totals.lost === 0 ? 'badge badge-pass' : 'badge badge-review'}>
                    {totals.coverageAfter.toFixed(1)}% covered after recovery
                  </span>
                </div>
                <div style={{ fontSize: '13px', color: 'var(--text-secondary)', marginTop: '6px' }}>
                  {totals.recovered > 0
                    ? `Recovered ${fmtDuration(totals.recovered)} of previously missing footage.`
                    : 'No footage required recovery.'}
                  {totals.lost > 0 && (
                    <> {fmtDuration(totals.lost)} of footage could not be recovered and is marked lost.</>
                  )}
                </div>
              </div>
            </div>
          </div>

          {/* Metrics */}
          <div className="grid-4 mb-4">
            <div className="stat-card">
              <div className="stat-label">Recorded Footage</div>
              <div className="stat-value" style={{ fontSize: '16px' }}>{fmtDuration(totals.recorded)}</div>
              <div className="stat-sub">found directly by the parser</div>
            </div>
            <div className="stat-card">
              <div className="stat-label">Recovered Footage</div>
              <div className="stat-value" style={{ fontSize: '16px', color: 'var(--accent)' }}>{fmtDuration(totals.recovered)}</div>
              <div className="stat-sub">carved back at L1–L3</div>
            </div>
            <div className="stat-card">
              <div className="stat-label">Lost Footage</div>
              <div className="stat-value" style={{ fontSize: '16px', color: totals.lost > 0 ? 'var(--danger)' : undefined }}>{fmtDuration(totals.lost)}</div>
              <div className="stat-sub">unrecoverable at any level</div>
            </div>
            <div className="stat-card">
              <div className="stat-label">Coverage After Recovery</div>
              <div className="stat-value" style={{ fontSize: '16px' }}>{totals.coverageAfter.toFixed(1)}%</div>
              <div style={{ height: '6px', background: 'var(--surface-muted)', borderRadius: '3px', marginTop: '8px', overflow: 'hidden' }}>
                <div style={{ width: `${totals.coverageAfter}%`, height: '100%', background: 'var(--accent)' }} />
              </div>
            </div>
          </div>

          {/* Inline forensic player */}
          {activePlayback && (
            <div style={{ marginBottom: '20px' }}>
              <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '8px' }}>
                <h3 style={{ margin: 0, fontSize: '14px', display: 'flex', alignItems: 'center', gap: '6px' }}>
                  <Video size={16} style={{ color: 'var(--accent)' }} /> Forensic Clip Player
                </h3>
                <button className="btn btn-secondary btn-sm" onClick={() => { setActivePlayback(null); setSelectedRow(null); }}>Close Player</button>
              </div>
              <VideoPlayer {...activePlayback} onClose={() => { setActivePlayback(null); setSelectedRow(null); }} />
            </div>
          )}

          {playError && (
            <div className="panel mb-4" style={{ borderLeft: '4px solid var(--warning)' }}>
              <strong>Playback note</strong>
              <div className="text-muted" style={{ fontSize: '13px', marginTop: '4px' }}>{playError}</div>
            </div>
          )}

          {/* ── Unified clip list (recorded + recovered + lost) ─────────────── */}
          {recordingsTimeline && (
            <div className="panel mb-4" style={{ padding: '0', overflow: 'hidden' }}>
              <div style={{ padding: '16px', display: 'flex', alignItems: 'center', justifyContent: 'space-between', flexWrap: 'wrap', gap: '10px', borderBottom: '1px solid var(--border)' }}>
                <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
                  <Film size={18} style={{ color: 'var(--accent)' }} />
                  <strong style={{ fontSize: '15px' }}>Final Clip List</strong>
                  <span className="badge badge-info">{rows.length} of {allRows.length}</span>
                  <ContextHelp
                    title="Final Clip List"
                    content="Every recording in the final timeline: originally recorded clips, clips recovered by the engine, and lost sub-ranges. Sort by any column, filter by channel/date/time/status, and press Play to reconstruct a recorded or recovered clip."
                  />
                </div>

                {/* Filters — identical controls to the Preliminary Timeline */}
                <div style={{ display: 'flex', alignItems: 'center', gap: '10px', flexWrap: 'wrap' }}>
                  <div style={{ display: 'flex', alignItems: 'center', gap: '6px' }}>
                    <Filter size={13} style={{ color: 'var(--text-muted)' }} />
                    <label style={{ fontSize: '12px', color: 'var(--text-secondary)' }}>Channel</label>
                    <select
                      className="form-select"
                      style={{ padding: '4px 8px', fontSize: '12px' }}
                      value={channelFilter === 'all' ? 'all' : String(channelFilter)}
                      onChange={(e) => setChannelFilter(e.target.value === 'all' ? 'all' : Number(e.target.value))}
                    >
                      <option value="all">All</option>
                      {channels.map((ch) => (<option key={ch} value={ch}>Ch {ch}</option>))}
                    </select>
                  </div>

                  <div style={{ display: 'flex', alignItems: 'center', gap: '6px' }}>
                    <Calendar size={13} style={{ color: 'var(--text-muted)' }} />
                    <label style={{ fontSize: '12px', color: 'var(--text-secondary)' }}>Date</label>
                    <select
                      className="form-select"
                      style={{ padding: '4px 8px', fontSize: '12px' }}
                      value={dateFilter}
                      onChange={(e) => {
                        const v = e.target.value;
                        setDateFilter(v);
                        if (v === 'all') { setTimeStart(''); setTimeEnd(''); }
                      }}
                    >
                      <option value="all">All dates</option>
                      {availableDates.map((d) => (<option key={d.key} value={d.key}>{d.label}</option>))}
                    </select>
                  </div>

                  {dateFilter !== 'all' && (
                    <div style={{ display: 'flex', alignItems: 'center', gap: '6px' }}>
                      <Clock size={13} style={{ color: 'var(--text-muted)' }} />
                      <label style={{ fontSize: '12px', color: 'var(--text-secondary)' }}>Time</label>
                      <input
                        type="time" step={1} className="form-input"
                        style={{ padding: '3px 6px', fontSize: '12px', width: '120px' }}
                        value={timeStart} onChange={(e) => setTimeStart(e.target.value)} title="From (time of day)"
                      />
                      <ArrowRight size={12} style={{ color: 'var(--text-muted)' }} />
                      <input
                        type="time" step={1} className="form-input"
                        style={{ padding: '3px 6px', fontSize: '12px', width: '120px' }}
                        value={timeEnd} onChange={(e) => setTimeEnd(e.target.value)} title="To (time of day)"
                      />
                      {(timeStart || timeEnd) && (
                        <button className="btn btn-secondary btn-sm" onClick={() => { setTimeStart(''); setTimeEnd(''); }} title="Clear the time range">Clear</button>
                      )}
                    </div>
                  )}

                  <div style={{ display: 'flex', alignItems: 'center', gap: '6px' }}>
                    <label style={{ fontSize: '12px', color: 'var(--text-secondary)' }}>Show</label>
                    <select
                      className="form-select"
                      style={{ padding: '4px 8px', fontSize: '12px' }}
                      value={statusFilter}
                      onChange={(e) => setStatusFilter(e.target.value as any)}
                    >
                      <option value="all">All</option>
                      <option value="recorded">Recorded</option>
                      <option value="recovered">Recovered</option>
                      <option value="lost">Lost</option>
                    </select>
                  </div>
                </div>
              </div>

              {rows.length === 0 ? (
                <div className="text-muted" style={{ fontSize: '13px', padding: '16px' }}>No entries match the current filters.</div>
              ) : (
                <div className="table-container" style={{ border: 'none', borderRadius: 0 }}>
                  <table className="data-table">
                    <thead>
                      <tr>
                        <SortableTh label="#" active={sortKey === 'no'} onClick={() => toggleSort('no')} icon={sortIcon('no')} />
                        <SortableTh label="Channel" active={sortKey === 'channel'} onClick={() => toggleSort('channel')} icon={sortIcon('channel')} />
                        <SortableTh label="Start" active={sortKey === 'start'} onClick={() => toggleSort('start')} icon={sortIcon('start')} />
                        <th>End</th>
                        <SortableTh label="Duration" active={sortKey === 'duration'} onClick={() => toggleSort('duration')} icon={sortIcon('duration')} />
                        <th>Type</th>
                        <SortableTh label="Size" active={sortKey === 'size'} onClick={() => toggleSort('size')} icon={sortIcon('size')} />
                        <th>Actions</th>
                      </tr>
                    </thead>
                    <tbody>
                      {rows.map((row) => {
                        const isLost = row.kind === 'lost';
                        const isRecovered = row.kind === 'recovered';
                        const rowBg = isLost
                          ? { background: 'rgba(220, 38, 38, 0.06)' }
                          : isRecovered
                          ? { background: 'rgba(59, 130, 246, 0.06)' }
                          : selectedRow === row.key
                          ? { background: 'var(--surface-muted)' }
                          : undefined;
                        return (
                          <tr key={row.key} style={rowBg}>
                            <td className="text-muted">{row.no ?? '—'}</td>
                            <td><strong>Ch {row.channel}</strong></td>
                            <td>
                              <div>{fmtDate(row.startNative, row.startNormalized)}</div>
                              <div className="text-muted" style={{ fontSize: '11px' }}>{fmtTime(row.startNative, row.startNormalized)}</div>
                            </td>
                            <td>{fmtTime(row.endNative, row.endNormalized)}</td>
                            <td style={isLost ? { color: 'var(--danger)', fontWeight: 600 } : undefined}>
                              {isLost ? `${fmtDuration(row.durationSec)} recording lost` : fmtDuration(row.durationSec)}
                            </td>
                            <td>
                              {isLost ? (
                                <span className="badge badge-fail" title={row.reason || 'No level could recover this sub-range'}>RECORDING LOST</span>
                              ) : isRecovered ? (
                                <span className="badge badge-review" title={row.reason}>{row.level ? LEVEL_LABEL[row.level] : 'RECOVERED'}</span>
                              ) : (
                                <span className="badge badge-pass">RECORDING</span>
                              )}
                            </td>
                            <td>{isLost ? '—' : fmtBytes(row.sizeBytes)}</td>
                            <td>
                              <div style={{ display: 'flex', gap: '6px' }}>
                                {!isLost && row.length > 0 && (
                                  <button
                                    className="btn btn-primary btn-sm"
                                    onClick={() => playRow(row)}
                                    disabled={reconstructing === row.key}
                                    title="Reconstruct and preview this clip"
                                  >
                                    {reconstructing === row.key ? <RefreshCw size={12} className="spin" /> : <Play size={12} />}
                                    <span>{reconstructing === row.key ? 'Remuxing…' : 'Play'}</span>
                                  </button>
                                )}
                                <button
                                  className="btn btn-secondary btn-sm"
                                  onClick={() => onNavigateToHex(row.hexOffset)}
                                  title={isLost ? "Inspect the lost sub-range's bytes" : "Jump to this clip's bytes in the Byte Inspector"}
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
          )}
        </>
      )}
    </div>
  );
};

// ── Small presentational helpers ──────────────────────────────────────────────
const LegendSwatch: React.FC<{ color?: string; hatch?: boolean; label: string }> = ({ color, hatch, label }) => (
  <span style={{ display: 'inline-flex', alignItems: 'center', gap: '6px' }}>
    <span
      style={{
        width: '14px', height: '10px', borderRadius: '2px',
        background: hatch
          ? 'repeating-linear-gradient(45deg, var(--danger), var(--danger) 3px, rgba(0,0,0,0.15) 3px, rgba(0,0,0,0.15) 6px)'
          : color,
        display: 'inline-block',
      }}
    />
    {label}
  </span>
);

const SortableTh: React.FC<{ label: string; active: boolean; onClick: () => void; icon: React.ReactNode }> = ({ label, active, onClick, icon }) => (
  <th onClick={onClick} style={{ cursor: 'pointer', userSelect: 'none', color: active ? 'var(--accent)' : undefined }}>
    <span style={{ display: 'inline-flex', alignItems: 'center', gap: '3px' }}>{label}{icon}</span>
  </th>
);

// ── One channel card: coverage bar (recorded/recovered/lost) + sub-range list ──
const RecordingCard: React.FC<{
  session: RecordingSession;
  recoveries: Map<string, GapRecoveryResponse>;
  onNavigateToHex: (offset: number) => void;
}> = ({ session, recoveries, onNavigateToHex }) => {
  const span = Math.max(1, session.span_seconds);
  const startMs = new Date(session.start_normalized).getTime();

  // Build coverage overlay blocks from each gap's recovery outcome.
  type Block = {
    left: number; width: number; kind: 'recovered' | 'lost';
    label: string; hexOffset: number;
  };
  const blocks: Block[] = [];
  let recoveredSec = 0;
  let lostSec = 0;

  for (const g of session.gaps) {
    const rec = recoveries.get(gapKey(session, g));
    const gapStartMs = new Date(g.starts_after_normalized).getTime();
    const place = (startSec: number, durSec: number) => {
      const bStart = gapStartMs + startSec * 1000;
      const left = Math.max(0, Math.min(100, ((bStart - startMs) / 1000 / span) * 100));
      const width = Math.max(1, Math.min(100 - left, (durSec / span) * 100));
      return { left, width };
    };

    if (rec && rec.slots.length > 0) {
      for (const slot of rec.slots) {
        const durSec = Math.max(1, slot.end_offset_sec - slot.start_offset_sec);
        const { left, width } = place(slot.start_offset_sec, durSec);
        if (slot.level) {
          recoveredSec += durSec;
          blocks.push({
            left, width, kind: 'recovered',
            label: `Recovered ${slot.level} · ${fmtDuration(durSec)} · ${slot.codec}`,
            hexOffset: slot.data_offset ?? slot.offset,
          });
        } else {
          lostSec += durSec;
          blocks.push({
            left, width, kind: 'lost',
            label: `${fmtDuration(durSec)} recording lost`,
            hexOffset: slot.offset,
          });
        }
      }
    } else {
      // Whole gap unrecovered.
      const { left, width } = place(0, g.missing_seconds);
      lostSec += g.missing_seconds;
      blocks.push({
        left, width, kind: 'lost',
        label: `${fmtDuration(g.missing_seconds)} recording lost`,
        hexOffset: g.next_offset,
      });
    }
  }

  const recordedSec = session.covered_seconds;
  const known = recordedSec + recoveredSec + lostSec;
  const coverageAfter = known > 0 ? ((recordedSec + recoveredSec) / known) * 100 : 100;
  const intact = session.gaps.length === 0;

  return (
    <div style={{ border: '1px solid var(--border)', borderRadius: '8px', padding: '14px', marginBottom: '12px', background: 'var(--surface)' }}>
      {/* Header */}
      <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', flexWrap: 'wrap', gap: '8px', marginBottom: '10px' }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: '10px' }}>
          <Video size={16} style={{ color: 'var(--accent)' }} />
          <strong style={{ fontSize: '14px' }}>Channel {session.channel}</strong>
          <span style={{ fontSize: '13px', color: 'var(--text-secondary)', display: 'flex', alignItems: 'center', gap: '5px' }}>
            <Clock size={13} />
            {fmtDateTime(session.start_native, session.start_normalized)}
            <ArrowRight size={12} />
            {fmtTime(session.end_native, session.end_normalized)}
          </span>
          <span className="badge badge-info">{session.timezone}</span>
        </div>
        <span className={intact ? 'badge badge-pass' : lostSec === 0 ? 'badge badge-info' : 'badge badge-review'}>
          {intact ? 'CONTINUOUS' : lostSec === 0 ? 'FULLY RECOVERED' : `${fmtDuration(lostSec)} LOST`}
        </span>
      </div>

      {/* Coverage bar: green base (recorded), blue (recovered), red hatch (lost) */}
      <div
        title={`${coverageAfter.toFixed(1)}% covered after recovery`}
        style={{ position: 'relative', height: '14px', borderRadius: '4px', background: 'var(--success)', overflow: 'hidden', marginBottom: '8px' }}
      >
        {blocks.map((b, i) => (
          <div
            key={i}
            onClick={() => onNavigateToHex(b.hexOffset)}
            title={`${b.label} · click to inspect 0x${b.hexOffset.toString(16)}`}
            style={{
              position: 'absolute', top: 0, bottom: 0, left: `${b.left}%`, width: `${b.width}%`, cursor: 'pointer',
              background: b.kind === 'recovered'
                ? 'var(--accent)'
                : 'repeating-linear-gradient(45deg, var(--danger), var(--danger) 4px, rgba(0,0,0,0.15) 4px, rgba(0,0,0,0.15) 8px)',
            }}
          />
        ))}
      </div>

      {/* Stats row */}
      <div style={{ display: 'flex', gap: '18px', flexWrap: 'wrap', fontSize: '12px', color: 'var(--text-secondary)', marginBottom: blocks.length ? '10px' : 0 }}>
        <span><strong style={{ color: 'var(--text-primary)' }}>{coverageAfter.toFixed(1)}%</strong> covered</span>
        <span><strong style={{ color: 'var(--text-primary)' }}>{session.segment_count}</strong> recorded segment(s)</span>
        <span>span {fmtDuration(session.span_seconds)}</span>
        <span>recorded {fmtDuration(recordedSec)}</span>
        {recoveredSec > 0 && <span style={{ color: 'var(--accent)' }}>recovered {fmtDuration(recoveredSec)}</span>}
        {lostSec > 0 && <span style={{ color: 'var(--danger)' }}>lost {fmtDuration(lostSec)}</span>}
        <span style={{ color: 'var(--text-muted)' }}>cadence ~{fmtDuration(session.nominal_segment_seconds)}</span>
      </div>

      {/* Recovered / lost sub-range list */}
      {session.gaps.length > 0 && (
        <div style={{ borderTop: '1px dashed var(--border)', paddingTop: '8px' }}>
          {session.gaps.map((g, gi) => {
            const rec = recoveries.get(gapKey(session, g));
            if (rec && rec.slots.length > 0) {
              return rec.slots.map((slot) => {
                const startNative = nativeAddSeconds(g.starts_after_native, slot.start_offset_sec);
                const startNorm = isoAddSeconds(g.starts_after_normalized, slot.start_offset_sec);
                const endNative = nativeAddSeconds(g.starts_after_native, slot.end_offset_sec);
                const endNorm = isoAddSeconds(g.starts_after_normalized, slot.end_offset_sec);
                const hexOffset = slot.data_offset ?? slot.offset;
                const recovered = !!slot.level;
                return (
                  <div
                    key={`${gi}-${slot.index}`}
                    onClick={() => onNavigateToHex(hexOffset)}
                    style={{ display: 'flex', alignItems: 'center', gap: '8px', fontSize: '12px', padding: '3px 0', cursor: 'pointer', color: 'var(--text-secondary)' }}
                  >
                    {recovered
                      ? <CheckCircle2 size={12} style={{ color: 'var(--accent)', flexShrink: 0 }} />
                      : <Scissors size={12} style={{ color: 'var(--danger)', flexShrink: 0 }} />}
                    <span style={{ fontFamily: 'monospace' }}>
                      {fmtTime(startNative, startNorm)}
                      <ArrowRight size={11} style={{ display: 'inline', margin: '0 3px', verticalAlign: 'middle' }} />
                      {fmtTime(endNative, endNorm)}
                    </span>
                    {recovered ? (
                      <span style={{ color: 'var(--accent)' }}>recovered {slot.level} · {slot.codec}</span>
                    ) : (
                      <span style={{ color: 'var(--danger)' }}>{fmtDuration(slot.end_offset_sec - slot.start_offset_sec)} recording lost</span>
                    )}
                    <span style={{ color: 'var(--text-muted)', fontFamily: 'monospace', marginLeft: 'auto' }}>
                      0x{hexOffset.toString(16)}
                    </span>
                  </div>
                );
              });
            }
            // Whole gap unrecovered.
            return (
              <div
                key={`${gi}-whole`}
                onClick={() => onNavigateToHex(g.next_offset)}
                style={{ display: 'flex', alignItems: 'center', gap: '8px', fontSize: '12px', padding: '3px 0', cursor: 'pointer', color: 'var(--text-secondary)' }}
              >
                <Scissors size={12} style={{ color: 'var(--danger)', flexShrink: 0 }} />
                <span style={{ fontFamily: 'monospace' }}>
                  {fmtTime(g.starts_after_native, g.starts_after_normalized)}
                  <ArrowRight size={11} style={{ display: 'inline', margin: '0 3px', verticalAlign: 'middle' }} />
                  {fmtTime(g.ends_before_native, g.ends_before_normalized)}
                </span>
                <span style={{ color: 'var(--danger)' }}>{fmtDuration(g.missing_seconds)} recording lost</span>
                <span style={{ color: 'var(--text-muted)', fontFamily: 'monospace', marginLeft: 'auto' }}>
                  0x{g.previous_offset.toString(16)} → 0x{g.next_offset.toString(16)}
                </span>
              </div>
            );
          })}
        </div>
      )}
    </div>
  );
};
