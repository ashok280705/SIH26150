import React, { useState, useEffect, useMemo } from 'react';
import {
  ListTree, RefreshCw, HardDrive, CheckCircle2, AlertTriangle, ArrowRight,
  Film, Clock, Scissors, Video, Play, ChevronUp, ChevronDown, Filter, Calendar, Wrench,
} from 'lucide-react';
import {
  Evidence, PipelineRun, RecordingSession, GapRecoveryTarget, ReconstructResponse,
} from '../types';
import { runFullPipeline, reconstructRecording } from '../services/api';
import { ContextHelp } from '../components/onboarding/ContextHelp';
import { VideoPlayer } from '../components/video/VideoPlayer';
import { WorkflowState } from '../workflow';

// ── Display helpers ─────────────────────────────────────────────────────────
// Recorder-native strings are naive local wall-clock (e.g. "2026-09-20T10:00:00")
// and are shown verbatim; we only reformat them for readability, never shifting the
// clock. When a native value is absent we fall back to the normalized UTC instant.

/** Split a naive "YYYY-MM-DDTHH:MM:SS" into its date and time parts, if it matches. */
function parseNative(s: string | null | undefined): { date: string; time: string } | null {
  if (!s) return null;
  const m = s.match(/^(\d{4})-(\d{2})-(\d{2})[T ](\d{2}):(\d{2}):(\d{2})/);
  if (!m) return null;
  const [, y, mo, d, hh, mm, ss] = m;
  return { date: `${d}/${mo}/${y}`, time: `${hh}:${mm}:${ss}` };
}

/** "DD/MM/YYYY HH:MM:SS" from a native string, or a UTC fallback. */
function fmtDateTime(native: string | null | undefined, normalizedFallback?: string | null): string {
  const p = parseNative(native);
  if (p) return `${p.date} ${p.time}`;
  if (normalizedFallback) {
    const dt = new Date(normalizedFallback);
    if (!isNaN(dt.getTime())) return dt.toLocaleString();
  }
  return '—';
}

/** "HH:MM:SS" from a native string, or a UTC fallback. */
function fmtTime(native: string | null | undefined, normalizedFallback?: string | null): string {
  const p = parseNative(native);
  if (p) return p.time;
  if (normalizedFallback) {
    const dt = new Date(normalizedFallback);
    if (!isNaN(dt.getTime())) return dt.toLocaleTimeString();
  }
  return '—';
}

/** "DD/MM/YYYY" from a native string, or a UTC fallback. */
function fmtDate(native: string | null | undefined, normalizedFallback?: string | null): string {
  const p = parseNative(native);
  if (p) return p.date;
  if (normalizedFallback) {
    const dt = new Date(normalizedFallback);
    if (!isNaN(dt.getTime())) return dt.toLocaleDateString();
  }
  return 'Unknown date';
}

/** Human-readable duration: "45s", "5m 0s", "1h 05m". */
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

/** Human-readable byte size. */
function fmtBytes(bytes: number): string {
  if (bytes < 1024) return `${bytes} B`;
  if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} KB`;
  return `${(bytes / (1024 * 1024)).toFixed(2)} MB`;
}

// ── Clip model ──────────────────────────────────────────────────────────────
// Each row is ONE recording — a single fixed-length segment (e.g. 10s), mirroring
// the DVR-Examiner clip list where every clip is its own row with its own start,
// end, and duration. Missing footage is surfaced as a distinct "gap" row so it is
// visible in the list, never hidden inside a collapsed session.
interface ClipRow {
  kind: 'clip' | 'gap';
  key: string;
  no: number | null;
  channel: number;
  startNative: string | null;
  startNormalized: string;
  endNative: string | null;
  endNormalized: string;
  durationSec: number;
  sizeBytes: number;
  offset: number;
  length: number;
  // Gap rows only: the recoverable byte region and the channel's cadence.
  scanStart?: number;
  scanEnd?: number;
  nominalSeconds?: number;
}

type SortKey = 'no' | 'channel' | 'start' | 'duration' | 'size';
type SortDir = 'asc' | 'desc';

/** Add seconds to a naive recorder-native wall clock, preserving wall-clock time
 *  (no timezone shift). Returns null if the string can't be parsed. */
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

/** Flatten sessions into per-recording rows. Each stored segment becomes one clip
 *  row whose duration is the measured per-recording length (nominal_segment_seconds,
 *  e.g. 10s). Each session gap becomes a "gap" row of its missing duration. */
function buildRows(sessions: RecordingSession[]): ClipRow[] {
  const clips: ClipRow[] = [];
  const gaps: ClipRow[] = [];
  for (const s of sessions) {
    const dur = s.nominal_segment_seconds || 0;
    for (const seg of s.segments) {
      const startNorm = seg.start_normalized ?? s.start_normalized;
      clips.push({
        kind: 'clip',
        key: `c-${s.id}-${seg.source_offset}`,
        no: 0, // assigned chronologically below
        channel: seg.channel,
        startNative: seg.start_native,
        startNormalized: startNorm,
        endNative: nativeAddSeconds(seg.start_native, dur),
        endNormalized: isoAddSeconds(startNorm, dur),
        durationSec: dur,
        sizeBytes: seg.source_length || 0,
        offset: seg.source_offset,
        length: seg.source_length || 0,
      });
    }
    for (const g of s.gaps) {
      gaps.push({
        kind: 'gap',
        key: `g-${s.id}-${g.next_offset}`,
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
        scanStart: g.previous_offset + g.previous_length,
        scanEnd: g.next_offset,
        nominalSeconds: s.nominal_segment_seconds || 0,
      });
    }
  }
  // Assign stable clip IDs in chronological order (then by channel), so two cameras
  // recording the same instant get adjacent numbers (Ch1 #1, Ch2 #2) instead of
  // per-session numbers that look like duplicates once the list is sorted by time.
  clips.sort((a, b) => a.startNormalized.localeCompare(b.startNormalized) || a.channel - b.channel);
  clips.forEach((c, i) => { c.no = i + 1; });
  return [...clips, ...gaps];
}

/** Extract the date and time-of-day of a row from its recorder-native wall clock
 *  (falling back to the normalized UTC instant). `tod` is seconds since midnight,
 *  used by the time-of-day filter; `dateKey` (YYYY-MM-DD) sorts and matches dates. */
function rowWhen(c: ClipRow): { dateKey: string; dateLabel: string; tod: number } | null {
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

/** Parse an "HH:MM" value into seconds since midnight, or null if empty/invalid. */
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
  onNavigateToRecovery?: (target: GapRecoveryTarget) => void;
  workflow?: WorkflowState;
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

export const PreliminaryTimelineView: React.FC<Props> = ({ evidence, workflow, onWorkflow, onNavigateToHex, onNavigateToRecovery }) => {
  const [run, setRun] = useState<PipelineRun | null>(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);

  // Clip-list controls + playback state (DVR-Examiner style).
  const [sortKey, setSortKey] = useState<SortKey>('start');
  const [sortDir, setSortDir] = useState<SortDir>('asc');
  const [channelFilter, setChannelFilter] = useState<number | 'all'>('all');
  const [statusFilter, setStatusFilter] = useState<'all' | 'clips' | 'gaps'>('all');
  // Date filter (view recordings date-wise) and, once a date is chosen, a
  // time-of-day filter (HH:MM start/end) applied within that date.
  const [dateFilter, setDateFilter] = useState<string>('all');
  const [timeStart, setTimeStart] = useState<string>('');
  const [timeEnd, setTimeEnd] = useState<string>('');
  const [selectedClip, setSelectedClip] = useState<string | null>(null);
  const [activePlayback, setActivePlayback] = useState<any | null>(null);
  const [reconstructing, setReconstructing] = useState<string | null>(null);
  const [playError, setPlayError] = useState<string | null>(null);

  useEffect(() => {
    setRun(null);
    setError(null);
    setActivePlayback(null);
    setSelectedClip(null);
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
      if (onWorkflow) {
        onWorkflow({
          timelineBuilt: true,
          gapsPresent: r.gap_analysis?.gaps_present ?? false,
          coverageRatio: r.gap_analysis?.coverage.coverage_ratio ?? null,
          recoveryRequired: r.gap_analysis?.gaps_present ?? false,
        });
      }
    } catch (e: any) {
      setError(e?.message || 'Failed to build preliminary timeline');
    } finally {
      setLoading(false);
    }
  };

  const recordingsTimeline = run?.recordings_timeline ?? null;
  const sessions = recordingsTimeline?.sessions ?? [];

  const allClips = useMemo(() => buildRows(sessions), [sessions]);
  const channels = useMemo(
    () => Array.from(new Set(allClips.map((c) => c.channel))).sort((a, b) => a - b),
    [allClips]
  );

  // Distinct recording dates present in the image, for the date-wise filter.
  const availableDates = useMemo(() => {
    const map = new Map<string, string>();
    for (const c of allClips) {
      const w = rowWhen(c);
      if (w) map.set(w.dateKey, w.dateLabel);
    }
    return Array.from(map.entries())
      .sort((a, b) => a[0].localeCompare(b[0]))
      .map(([key, label]) => ({ key, label }));
  }, [allClips]);

  const clips = useMemo(() => {
    const todStart = hhmmToSec(timeStart);
    const todEnd = hhmmToSec(timeEnd);
    let rows = allClips.filter((c) => {
      if (channelFilter !== 'all' && c.channel !== channelFilter) return false;
      if (statusFilter === 'clips' && c.kind !== 'clip') return false;
      if (statusFilter === 'gaps' && c.kind !== 'gap') return false;
      // Date-wise filter, then time-of-day within the selected date.
      if (dateFilter !== 'all') {
        const w = rowWhen(c);
        if (!w || w.dateKey !== dateFilter) return false;
        if (todStart !== null && w.tod < todStart) return false;
        if (todEnd !== null && w.tod > todEnd + 59) return false;
      }
      return true;
    });
    const dir = sortDir === 'asc' ? 1 : -1;
    rows = [...rows].sort((a, b) => {
      switch (sortKey) {
        case 'channel': return (a.channel - b.channel) * dir || a.startNormalized.localeCompare(b.startNormalized);
        case 'duration': return (a.durationSec - b.durationSec) * dir;
        case 'size': return (a.sizeBytes - b.sizeBytes) * dir;
        case 'no': return ((a.no ?? Number.MAX_SAFE_INTEGER) - (b.no ?? Number.MAX_SAFE_INTEGER)) * dir;
        case 'start':
        default: return a.startNormalized.localeCompare(b.startNormalized) * dir || (a.channel - b.channel);
      }
    });
    return rows;
  }, [allClips, channelFilter, statusFilter, dateFilter, timeStart, timeEnd, sortKey, sortDir]);

  const toggleSort = (key: SortKey) => {
    if (sortKey === key) {
      setSortDir((d) => (d === 'asc' ? 'desc' : 'asc'));
    } else {
      setSortKey(key);
      setSortDir(key === 'start' || key === 'channel' || key === 'no' ? 'asc' : 'desc');
    }
  };

  const handlePlayClip = async (clip: ClipRow) => {
    if (!evidence || clip.kind !== 'clip') return;
    setSelectedClip(clip.key);
    setReconstructing(clip.key);
    setPlayError(null);
    try {
      const res = await reconstructRecording(evidence.id, clip.key, {
        offset_start: clip.offset,
        length: clip.length,
        channel: clip.channel,
      });
      if (res.remux) {
        setActivePlayback({
          videoId: res.remux.artifact_id,
          videoUrl: res.remux.video_url,
          recordingId: `Ch${clip.channel} · ${fmtDateTime(clip.startNative, clip.startNormalized)}`,
          channel: clip.channel,
          oemName: evidence.source_device,
          sourceOffset: clip.offset,
          sourceLength: res.elementary_stream.size_bytes,
          nativeTime: clip.startNative ?? 'Unknown',
          normalizedUtc: clip.startNormalized ?? 'Unknown',
          codec: res.codec,
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
      <div className="view-container">
        <div className="view-header">
          <div>
            <h1 className="view-title">Preliminary Timeline Construction</h1>
            <p className="view-subtitle">Select an evidence target to build the preliminary timeline.</p>
          </div>
        </div>
        <div className="empty-state"><ListTree size={32} /><h3>No Evidence Selected</h3></div>
      </div>
    );
  }

  const gaps = run?.gap_analysis;
  const coveragePct = gaps ? (gaps.coverage.coverage_ratio * 100).toFixed(1) : null;
  const gapsPresent = gaps?.gaps_present ?? null;

  const sortIcon = (key: SortKey) =>
    sortKey === key ? (sortDir === 'asc' ? <ChevronUp size={12} /> : <ChevronDown size={12} />) : null;

  return (
    <div className="view-container">
      <div className="view-header">
        <div>
          <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
            <h1 className="view-title">Preliminary Timeline Construction</h1>
            <ContextHelp
              title="Preliminary Timeline"
              content="Builds a timeline from the extraction, normalizes timestamps, and detects temporal gaps and unaccounted image regions. Gaps route to the Recovery Engine; no gaps route straight to the Final Timeline."
            />
          </div>
          <p className="view-subtitle">Recovered clips · normalize timestamps · detect gaps · estimate coverage</p>
        </div>
        <button className="btn btn-secondary" onClick={build} disabled={loading}>
          {loading ? <RefreshCw size={14} className="spin" /> : <RefreshCw size={14} />}
          <span>Rebuild</span>
        </button>
      </div>

      {/* Target bar */}
      <div className="panel" style={{ padding: '16px', marginBottom: '20px', backgroundColor: 'var(--surface)' }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: '12px' }}>
          <HardDrive size={18} style={{ color: 'var(--accent)' }} />
          <div>
            <div style={{ fontSize: '11px', textTransform: 'uppercase', color: 'var(--text-muted)', fontWeight: 600 }}>Active Target</div>
            <div style={{ display: 'flex', alignItems: 'center', gap: '8px', marginTop: '2px' }}>
              <strong style={{ fontSize: '14px' }}>{evidence.source_device}</strong>
              <span className="badge badge-info">{evidence.image_format}</span>
              {workflow?.parserUsed && <span className="badge badge-pass">parser: {workflow.parserUsed}</span>}
            </div>
          </div>
        </div>
      </div>

      {error && (
        <div className="panel mb-4" style={{ borderLeft: '4px solid var(--danger)' }}>
          <strong>Failed to build timeline</strong>
          <div className="text-muted" style={{ fontSize: '13px', marginTop: '4px' }}>{error}</div>
        </div>
      )}

      {loading && !run && <div className="empty-state"><RefreshCw size={28} className="spin" /><h3>Building timeline…</h3></div>}

      {run && (
        <>
          {/* ── Timeline & Coverage (per-recording visual with gaps) ───────── */}
          {recordingsTimeline && sessions.length > 0 && (
            <div className="panel mb-4" style={{ padding: '16px' }}>
              <div style={{ display: 'flex', alignItems: 'center', gap: '8px', marginBottom: '4px' }}>
                <Clock size={18} style={{ color: 'var(--accent)' }} />
                <strong style={{ fontSize: '15px' }}>Timeline &amp; Coverage</strong>
                <ContextHelp
                  title="Recording Timeline"
                  content="Each recovered recording drawn to scale on its own track. The green bar is footage that was found; red hatching marks missing footage (gaps) inside the recording. Click a gap to jump to that offset in the Byte Inspector."
                />
              </div>
              <p className="text-muted" style={{ fontSize: '12px', margin: '0 0 14px' }}>
                Sorted by date · gaps marked, never filled
              </p>

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
                    <RecordingCard session={session} onNavigateToHex={onNavigateToHex} />
                  </React.Fragment>
                );
              })}
            </div>
          )}

          {/* Gap verdict */}
          <div
            className="panel mb-4"
            style={{ borderLeft: `4px solid ${gapsPresent ? 'var(--warning)' : 'var(--success)'}` }}
          >
            <div style={{ display: 'flex', alignItems: 'flex-start', gap: '12px' }}>
              {gapsPresent ? (
                <AlertTriangle size={22} style={{ color: 'var(--warning)', flexShrink: 0 }} />
              ) : (
                <CheckCircle2 size={22} style={{ color: 'var(--success)', flexShrink: 0 }} />
              )}
              <div>
                <div style={{ display: 'flex', alignItems: 'center', gap: '10px', flexWrap: 'wrap' }}>
                  <strong style={{ fontSize: '15px' }}>Gap Analysis</strong>
                  <span className={gapsPresent ? 'badge badge-review' : 'badge badge-pass'}>
                    {gapsPresent ? 'GAPS PRESENT' : 'NO GAPS FOUND'}
                  </span>
                </div>
                <div style={{ fontSize: '13px', color: 'var(--text-secondary)', marginTop: '6px' }}>
                  {gaps?.validation.reason}
                </div>
                <div style={{ fontSize: '13px', marginTop: '8px', display: 'flex', alignItems: 'center', gap: '6px', color: 'var(--accent)' }}>
                  <ArrowRight size={14} />
                  {gapsPresent
                    ? 'Proceed to the Recovery Engine (now unlocked) to recover the missing regions.'
                    : 'Proceed to the Final Timeline (now unlocked).'}
                </div>
              </div>
            </div>
          </div>

          {/* Metrics */}
          <div className="grid-4 mb-4">
            <div className="stat-card">
              <div className="stat-label">Recovered Recordings</div>
              <div className="stat-value">{recordingsTimeline?.total_segments ?? 0}</div>
              <div className="stat-sub">{recordingsTimeline?.total_recordings ?? 0} session(s) · {recordingsTimeline?.channel_count ?? 0} channel(s)</div>
            </div>
            <div className="stat-card">
              <div className="stat-label">Image Coverage</div>
              <div className="stat-value" style={{ fontSize: '16px' }}>{coveragePct}%</div>
              {gaps && (
                <div style={{ height: '6px', background: 'var(--surface-muted)', borderRadius: '3px', marginTop: '8px', overflow: 'hidden' }}>
                  <div style={{ width: `${gaps.coverage.coverage_ratio * 100}%`, height: '100%', background: 'var(--accent)' }} />
                </div>
              )}
            </div>
            <div className="stat-card">
              <div className="stat-label">Missing Footage</div>
              <div className="stat-value" style={{ fontSize: '16px' }}>
                {recordingsTimeline ? fmtDuration(recordingsTimeline.total_missing_seconds) : '—'}
              </div>
              <div className="stat-sub">across all recordings</div>
            </div>
            <div className="stat-card">
              <div className="stat-label">Unaccounted</div>
              <div className="stat-value" style={{ fontSize: '16px' }}>
                {gaps ? `${(gaps.coverage.unaccounted_bytes / (1024 * 1024)).toFixed(2)} MB` : '—'}
              </div>
              <div className="stat-sub">not attributed to a recording</div>
            </div>
          </div>

          {/* Inline forensic video player (opens when a clip is played) */}
          {activePlayback && (
            <div style={{ marginBottom: '20px' }}>
              <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '8px' }}>
                <h3 style={{ margin: 0, fontSize: '14px', display: 'flex', alignItems: 'center', gap: '6px' }}>
                  <Video size={16} style={{ color: 'var(--accent)' }} />
                  Forensic Clip Player
                </h3>
                <button className="btn btn-secondary btn-sm" onClick={() => { setActivePlayback(null); setSelectedClip(null); }}>
                  Close Player
                </button>
              </div>
              <VideoPlayer {...activePlayback} onClose={() => { setActivePlayback(null); setSelectedClip(null); }} />
            </div>
          )}

          {playError && (
            <div className="panel mb-4" style={{ borderLeft: '4px solid var(--warning)' }}>
              <strong>Playback note</strong>
              <div className="text-muted" style={{ fontSize: '13px', marginTop: '4px' }}>{playError}</div>
            </div>
          )}

          {/* ── Clip List (DVR-Examiner style) ─────────────────────────────── */}
          {recordingsTimeline && (
            <div className="panel mb-4" style={{ padding: '0', overflow: 'hidden' }}>
              <div style={{ padding: '16px', display: 'flex', alignItems: 'center', justifyContent: 'space-between', flexWrap: 'wrap', gap: '10px', borderBottom: '1px solid var(--border)' }}>
                <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
                  <Film size={18} style={{ color: 'var(--accent)' }} />
                  <strong style={{ fontSize: '15px' }}>Clip List</strong>
                  <span className="badge badge-info">{clips.length} of {allClips.length}</span>
                  <ContextHelp
                    title="Clip List"
                    content="Every recovered recording, located from the parser's byte offsets and organized by date and channel. Sort by any column, filter by channel or status, and press Play to reconstruct and preview a clip. Recordings with internal gaps are flagged so missing footage is never hidden."
                  />
                </div>

                {/* Filters */}
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
                      {channels.map((ch) => (
                        <option key={ch} value={ch}>Ch {ch}</option>
                      ))}
                    </select>
                  </div>

                  {/* Date-wise filter */}
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
                      {availableDates.map((d) => (
                        <option key={d.key} value={d.key}>{d.label}</option>
                      ))}
                    </select>
                  </div>

                  {/* Time-of-day filter — only after a date is selected */}
                  {dateFilter !== 'all' && (
                    <div style={{ display: 'flex', alignItems: 'center', gap: '6px' }}>
                      <Clock size={13} style={{ color: 'var(--text-muted)' }} />
                      <label style={{ fontSize: '12px', color: 'var(--text-secondary)' }}>Time</label>
                      <input
                        type="time"
                        step={1}
                        className="form-input"
                        style={{ padding: '3px 6px', fontSize: '12px', width: '120px' }}
                        value={timeStart}
                        onChange={(e) => setTimeStart(e.target.value)}
                        title="From (time of day)"
                      />
                      <ArrowRight size={12} style={{ color: 'var(--text-muted)' }} />
                      <input
                        type="time"
                        step={1}
                        className="form-input"
                        style={{ padding: '3px 6px', fontSize: '12px', width: '120px' }}
                        value={timeEnd}
                        onChange={(e) => setTimeEnd(e.target.value)}
                        title="To (time of day)"
                      />
                      {(timeStart || timeEnd) && (
                        <button
                          className="btn btn-secondary btn-sm"
                          onClick={() => { setTimeStart(''); setTimeEnd(''); }}
                          title="Clear the time range"
                        >
                          Clear
                        </button>
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
                      <option value="clips">Recordings</option>
                      <option value="gaps">Gaps</option>
                    </select>
                  </div>
                </div>
              </div>

              {clips.length === 0 ? (
                <div className="text-muted" style={{ fontSize: '13px', padding: '16px' }}>
                  No clips match the current filters
                  {recordingsTimeline.recordings_without_time > 0
                    ? ` (${recordingsTimeline.recordings_without_time} recording(s) excluded: unknown timezone).`
                    : '.'}
                </div>
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
                      {clips.map((clip) => {
                        const isGap = clip.kind === 'gap';
                        return (
                          <tr
                            key={clip.key}
                            style={
                              isGap
                                ? { background: 'rgba(217, 119, 6, 0.06)' }
                                : selectedClip === clip.key
                                ? { background: 'var(--surface-muted)' }
                                : undefined
                            }
                          >
                            <td className="text-muted">{clip.no ?? '—'}</td>
                            <td><strong>Ch {clip.channel}</strong></td>
                            <td>
                              <div>{fmtDate(clip.startNative, clip.startNormalized)}</div>
                              <div className="text-muted" style={{ fontSize: '11px' }}>{fmtTime(clip.startNative, clip.startNormalized)}</div>
                            </td>
                            <td>{fmtTime(clip.endNative, clip.endNormalized)}</td>
                            <td style={isGap ? { color: 'var(--warning)', fontWeight: 600 } : undefined}>
                              {fmtDuration(clip.durationSec)}
                            </td>
                            <td>
                              {isGap ? (
                                <span className="badge badge-review" title="Missing footage — recoverable by carving">
                                  GAP · recoverable
                                </span>
                              ) : (
                                <span className="badge badge-pass">RECORDING</span>
                              )}
                            </td>
                            <td>{isGap ? '—' : fmtBytes(clip.sizeBytes)}</td>
                            <td>
                              <div style={{ display: 'flex', gap: '6px' }}>
                                {!isGap && (
                                  <button
                                    className="btn btn-primary btn-sm"
                                    onClick={() => handlePlayClip(clip)}
                                    disabled={reconstructing === clip.key}
                                    title="Reconstruct and preview this 10s recording"
                                  >
                                    {reconstructing === clip.key ? <RefreshCw size={12} className="spin" /> : <Play size={12} />}
                                    <span>{reconstructing === clip.key ? 'Remuxing…' : 'Play'}</span>
                                  </button>
                                )}
                                {isGap && onNavigateToRecovery && (
                                  <button
                                    className="btn btn-primary btn-sm"
                                    onClick={() =>
                                      onNavigateToRecovery({
                                        channel: clip.channel,
                                        scanStart: clip.scanStart ?? clip.offset,
                                        scanEnd: clip.scanEnd ?? clip.offset,
                                        gapSeconds: clip.durationSec,
                                        nominalSeconds: clip.nominalSeconds || 10,
                                        startNative: clip.startNative,
                                        startNormalized: clip.startNormalized,
                                        endNative: clip.endNative,
                                        endNormalized: clip.endNormalized,
                                      })
                                    }
                                    title="Recover this gap in the Recovery Engine (staged L1 → L2 → L3)"
                                  >
                                    <Wrench size={12} />
                                    <span>Recover</span>
                                  </button>
                                )}
                                <button
                                  className="btn btn-secondary btn-sm"
                                  onClick={() => onNavigateToHex(clip.offset)}
                                  title={isGap ? "Inspect the gap's bytes in the Byte Inspector" : "Jump to this clip's bytes in the Byte Inspector"}
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

// ── Sortable table header cell ────────────────────────────────────────────────
const SortableTh: React.FC<{ label: string; active: boolean; onClick: () => void; icon: React.ReactNode }> = ({ label, active, onClick, icon }) => (
  <th onClick={onClick} style={{ cursor: 'pointer', userSelect: 'none', color: active ? 'var(--accent)' : undefined }}>
    <span style={{ display: 'inline-flex', alignItems: 'center', gap: '3px' }}>{label}{icon}</span>
  </th>
);

// ── One recording card: header, coverage bar, stats, and the missing-gap list ──
const RecordingCard: React.FC<{
  session: RecordingSession;
  onNavigateToHex: (offset: number) => void;
}> = ({ session, onNavigateToHex }) => {
  const coveragePct = (session.coverage_ratio * 100).toFixed(1);
  const complete = session.gaps.length === 0;
  const span = Math.max(1, session.span_seconds);
  const startMs = new Date(session.start_normalized).getTime();

  // Position each gap proportionally along the recording's span for the bar overlay.
  const gapBlocks = session.gaps.map((g) => {
    const gStart = new Date(g.starts_after_normalized).getTime();
    const gEnd = new Date(g.ends_before_normalized).getTime();
    const left = Math.max(0, Math.min(100, ((gStart - startMs) / 1000 / span) * 100));
    const width = Math.max(1.5, Math.min(100 - left, ((gEnd - gStart) / 1000 / span) * 100));
    return { left, width, gap: g };
  });

  return (
    <div
      style={{
        border: '1px solid var(--border)',
        borderRadius: '8px',
        padding: '14px',
        marginBottom: '12px',
        background: 'var(--surface)',
      }}
    >
      {/* Header: channel + wall-clock range + verdict */}
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
        <span className={complete ? 'badge badge-pass' : 'badge badge-review'}>
          {complete ? 'CONTINUOUS' : `${session.gaps.length} GAP${session.gaps.length > 1 ? 'S' : ''}`}
        </span>
      </div>

      {/* Coverage bar: green track (found footage), red overlays (missing windows) */}
      <div
        title={`${coveragePct}% of this recording's span was found`}
        style={{ position: 'relative', height: '14px', borderRadius: '4px', background: 'var(--success)', overflow: 'hidden', marginBottom: '8px' }}
      >
        {gapBlocks.map((b, i) => (
          <div
            key={i}
            onClick={() => onNavigateToHex(b.gap.next_offset)}
            title={`Missing ${fmtDuration(b.gap.missing_seconds)} · click to inspect 0x${b.gap.next_offset.toString(16)}`}
            style={{
              position: 'absolute',
              top: 0,
              bottom: 0,
              left: `${b.left}%`,
              width: `${b.width}%`,
              background: 'repeating-linear-gradient(45deg, var(--danger), var(--danger) 4px, rgba(0,0,0,0.15) 4px, rgba(0,0,0,0.15) 8px)',
              cursor: 'pointer',
            }}
          />
        ))}
      </div>

      {/* Stats row */}
      <div style={{ display: 'flex', gap: '18px', flexWrap: 'wrap', fontSize: '12px', color: 'var(--text-secondary)', marginBottom: session.gaps.length ? '10px' : 0 }}>
        <span><strong style={{ color: 'var(--text-primary)' }}>{coveragePct}%</strong> found</span>
        <span><strong style={{ color: 'var(--text-primary)' }}>{session.segment_count}</strong> segment(s)</span>
        <span>span {fmtDuration(session.span_seconds)}</span>
        <span>recorded {fmtDuration(session.covered_seconds)}</span>
        {session.missing_seconds > 0 && (
          <span style={{ color: 'var(--warning)' }}>missing {fmtDuration(session.missing_seconds)}</span>
        )}
        <span style={{ color: 'var(--text-muted)' }}>cadence ~{fmtDuration(session.nominal_segment_seconds)}</span>
      </div>

      {/* Missing-footage list */}
      {session.gaps.length > 0 && (
        <div style={{ borderTop: '1px dashed var(--border)', paddingTop: '8px' }}>
          {session.gaps.map((g, i) => (
            <div
              key={i}
              onClick={() => onNavigateToHex(g.next_offset)}
              style={{ display: 'flex', alignItems: 'center', gap: '8px', fontSize: '12px', padding: '3px 0', cursor: 'pointer', color: 'var(--text-secondary)' }}
            >
              <Scissors size={12} style={{ color: 'var(--danger)', flexShrink: 0 }} />
              <span style={{ fontFamily: 'monospace' }}>
                {fmtTime(g.starts_after_native, g.starts_after_normalized)}
                <ArrowRight size={11} style={{ display: 'inline', margin: '0 3px', verticalAlign: 'middle' }} />
                {fmtTime(g.ends_before_native, g.ends_before_normalized)}
              </span>
              <span style={{ color: 'var(--warning)' }}>missing {fmtDuration(g.missing_seconds)}</span>
              <span style={{ color: 'var(--text-muted)', fontFamily: 'monospace', marginLeft: 'auto' }}>
                0x{g.previous_offset.toString(16)} → 0x{g.next_offset.toString(16)}
              </span>
            </div>
          ))}
        </div>
      )}
    </div>
  );
};
