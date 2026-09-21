import React, { useState, useEffect, useMemo } from 'react';
import { MonitorPlay, RefreshCw, HardDrive, Calendar, Clock, ArrowRight, Filter, Grid3x3, X } from 'lucide-react';
import { Evidence, RecordingSession, SessionGap, GapRecoveryResponse } from '../types';
import { runFullPipeline, recoverGap } from '../services/api';
import { ContextHelp } from '../components/onboarding/ContextHelp';
import { CameraTile, PlaylistSegment } from '../components/video/CameraTile';
import { WorkflowState } from '../workflow';

interface Props {
  evidence: Evidence | null;
  evidenceList?: Evidence[];
  onSelectEvidence?: (e: Evidence) => void;
  workflow?: WorkflowState;
}

// ── Time helpers (same semantics as the Preliminary/Final timelines) ──────────
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

function segWhen(seg: PlaylistSegment): { dateKey: string; dateLabel: string; tod: number } | null {
  const m = (seg.startNative || '').match(/^(\d{4})-(\d{2})-(\d{2})[T ](\d{2}):(\d{2}):(\d{2})/);
  if (m) {
    const [, y, mo, d, hh, mm, ss] = m;
    return { dateKey: `${y}-${mo}-${d}`, dateLabel: `${d}/${mo}/${y}`, tod: +hh * 3600 + +mm * 60 + +ss };
  }
  const dt = new Date(seg.startNormalized);
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

function gapKey(session: RecordingSession, gap: SessionGap): string {
  return `${session.id}-0x${gap.next_offset.toString(16)}`;
}

/** Grid columns for a CCTV wall based on the number of cameras (1, 4, 9, 16…). */
function gridCols(n: number): number {
  if (n <= 1) return 1;
  if (n <= 4) return 2;
  if (n <= 9) return 3;
  if (n <= 16) return 4;
  return 5;
}

/** Build each channel's continuous playlist in final-timeline order:
 *  recorded segments + recovered slots interleaved chronologically, with lost
 *  sub-ranges kept in place so the wall shows "signal lost" for missing footage. */
function buildPlaylists(
  sessions: RecordingSession[],
  recoveries: Map<string, GapRecoveryResponse>,
): Map<number, PlaylistSegment[]> {
  const byChannel = new Map<number, PlaylistSegment[]>();
  const push = (ch: number, seg: PlaylistSegment) => {
    if (!byChannel.has(ch)) byChannel.set(ch, []);
    byChannel.get(ch)!.push(seg);
  };

  for (const s of sessions) {
    const dur = s.nominal_segment_seconds || 0;
    for (const seg of s.segments) {
      const startNorm = seg.start_normalized ?? s.start_normalized;
      push(seg.channel, {
        key: `rec-${s.id}-${seg.source_offset}`,
        kind: 'recorded',
        channel: seg.channel,
        offset: seg.source_offset,
        length: seg.source_length || 0,
        durationSec: dur,
        startNative: seg.start_native,
        startNormalized: startNorm,
        codec: 'unknown',
      });
    }
    for (const g of s.gaps) {
      const rec = recoveries.get(gapKey(s, g));
      if (rec && rec.slots.length > 0) {
        for (const slot of rec.slots) {
          const startNative = nativeAddSeconds(g.starts_after_native, slot.start_offset_sec);
          const startNorm = isoAddSeconds(g.starts_after_normalized, slot.start_offset_sec);
          const slotDur = Math.max(1, slot.end_offset_sec - slot.start_offset_sec);
          push(s.channel, {
            key: slot.level ? `rcv-${s.id}-${g.next_offset}-${slot.index}` : `lost-${s.id}-${g.next_offset}-${slot.index}`,
            kind: slot.level ? 'recovered' : 'lost',
            channel: s.channel,
            offset: slot.offset,
            length: slot.level ? slot.length : 0,
            durationSec: slotDur,
            startNative,
            startNormalized: startNorm,
            codec: slot.codec,
            level: slot.level,
          });
        }
      } else {
        push(s.channel, {
          key: `lost-${s.id}-${g.next_offset}-whole`,
          kind: 'lost',
          channel: s.channel,
          offset: g.next_offset,
          length: 0,
          durationSec: g.missing_seconds,
          startNative: g.starts_after_native,
          startNormalized: g.starts_after_normalized,
          codec: 'unknown',
        });
      }
    }
  }

  for (const list of byChannel.values()) {
    list.sort((a, b) => a.startNormalized.localeCompare(b.startNormalized));
  }
  return byChannel;
}

export const VideoPlayerView: React.FC<Props> = ({ evidence, workflow }) => {
  const [sessions, setSessions] = useState<RecordingSession[]>([]);
  const [recoveries, setRecoveries] = useState<Map<string, GapRecoveryResponse>>(new Map());
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const [dateFilter, setDateFilter] = useState<string>('all');
  const [timeStart, setTimeStart] = useState<string>('');
  const [timeEnd, setTimeEnd] = useState<string>('');
  const [selectedChannel, setSelectedChannel] = useState<number | null>(null);

  const parserKey = workflow?.parserUsed || workflow?.attributedOem || 'unified';

  useEffect(() => {
    setSessions([]);
    setRecoveries(new Map());
    setError(null);
    setSelectedChannel(null);
    setDateFilter('all');
    setTimeStart('');
    setTimeEnd('');
    if (evidence) load();
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [evidence?.id]);

  const load = async () => {
    if (!evidence) return;
    setLoading(true);
    setError(null);
    try {
      const run = await runFullPipeline(evidence.id);
      const sess = run.recordings_timeline?.sessions ?? [];
      setSessions(sess);

      // Fold recovered footage into the wall exactly as the Final Timeline does.
      const map = new Map<string, GapRecoveryResponse>();
      await Promise.all(
        sess.flatMap((s) =>
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
              });
              map.set(gapKey(s, g), res);
            } catch {
              /* leave gap as lost */
            }
          })
        )
      );
      setRecoveries(map);
    } catch (e: any) {
      setError(e?.message || 'Failed to load recordings');
    } finally {
      setLoading(false);
    }
  };

  const playlists = useMemo(() => buildPlaylists(sessions, recoveries), [sessions, recoveries]);
  const channels = useMemo(() => Array.from(playlists.keys()).sort((a, b) => a - b), [playlists]);

  const availableDates = useMemo(() => {
    const m = new Map<string, string>();
    for (const list of playlists.values()) {
      for (const seg of list) {
        const w = segWhen(seg);
        if (w) m.set(w.dateKey, w.dateLabel);
      }
    }
    return Array.from(m.entries()).sort((a, b) => a[0].localeCompare(b[0])).map(([key, label]) => ({ key, label }));
  }, [playlists]);

  // Default to the first recording day once data arrives, like a real NVR opening on a day.
  useEffect(() => {
    if (dateFilter === 'all' && availableDates.length > 0) {
      setDateFilter(availableDates[0].key);
    }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [availableDates]);

  // Per-channel playlist filtered by the selected date + time-of-day window.
  const filteredByChannel = useMemo(() => {
    const todStart = hhmmToSec(timeStart);
    const todEnd = hhmmToSec(timeEnd);
    const out = new Map<number, PlaylistSegment[]>();
    for (const ch of channels) {
      const list = (playlists.get(ch) ?? []).filter((seg) => {
        if (dateFilter === 'all') return true;
        const w = segWhen(seg);
        if (!w || w.dateKey !== dateFilter) return false;
        if (todStart !== null && w.tod < todStart) return false;
        if (todEnd !== null && w.tod > todEnd + 59) return false;
        return true;
      });
      out.set(ch, list);
    }
    return out;
  }, [playlists, channels, dateFilter, timeStart, timeEnd]);

  const cols = gridCols(channels.length);

  if (!evidence) {
    return (
      <div className="view-container">
        <div className="view-header">
          <div>
            <h1 className="view-title">Surveillance Wall</h1>
            <p className="view-subtitle">Select an evidence target to view the camera wall.</p>
          </div>
        </div>
        <div className="empty-state"><MonitorPlay size={32} /><h3>No Evidence Selected</h3></div>
      </div>
    );
  }

  return (
    <div className="view-container">
      <div className="view-header">
        <div>
          <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
            <h1 className="view-title">Surveillance Wall</h1>
            <ContextHelp
              title="Surveillance Wall"
              content="A live-style camera wall built from the final timeline. Pick a date and time, and each channel plays its recordings continuously in order — recovered footage folded in, lost sub-ranges shown as 'signal lost'. Click a camera to enable its playback controls."
            />
          </div>
          <p className="view-subtitle">Continuous per-camera playback in final-timeline order · click a camera for controls</p>
        </div>
        <button className="btn btn-secondary" onClick={load} disabled={loading}>
          {loading ? <RefreshCw size={14} className="spin" /> : <RefreshCw size={14} />}
          <span>Reload</span>
        </button>
      </div>

      {/* Target bar */}
      <div className="panel" style={{ padding: '16px', marginBottom: '16px', backgroundColor: 'var(--surface)' }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: '12px' }}>
          <HardDrive size={18} style={{ color: 'var(--accent)' }} />
          <div>
            <div style={{ fontSize: '11px', textTransform: 'uppercase', color: 'var(--text-muted)', fontWeight: 600 }}>Active Target</div>
            <div style={{ display: 'flex', alignItems: 'center', gap: '8px', marginTop: '2px' }}>
              <strong style={{ fontSize: '14px' }}>{evidence.source_device}</strong>
              <span className="badge badge-info">{evidence.image_format}</span>
              <span className="badge badge-pass">parser: {parserKey}</span>
            </div>
          </div>
        </div>
      </div>

      {error && (
        <div className="panel mb-4" style={{ borderLeft: '4px solid var(--danger)' }}>
          <strong>Error</strong>
          <div className="text-muted" style={{ fontSize: '13px', marginTop: '4px' }}>{error}</div>
        </div>
      )}

      {loading && sessions.length === 0 && (
        <div className="empty-state"><RefreshCw size={28} className="spin" /><h3>Building camera wall…</h3></div>
      )}

      {sessions.length > 0 && (
        <>
          {/* Filter bar — same controls as the Preliminary Timeline */}
          <div className="panel" style={{ padding: '12px 16px', marginBottom: '16px', display: 'flex', alignItems: 'center', gap: '14px', flexWrap: 'wrap' }}>
            <div style={{ display: 'flex', alignItems: 'center', gap: '6px' }}>
              <Filter size={14} style={{ color: 'var(--text-muted)' }} />
              <strong style={{ fontSize: '13px' }}>View</strong>
            </div>

            <div style={{ display: 'flex', alignItems: 'center', gap: '6px' }}>
              <Calendar size={13} style={{ color: 'var(--text-muted)' }} />
              <label style={{ fontSize: '12px', color: 'var(--text-secondary)' }}>Date</label>
              <select
                className="form-select"
                style={{ padding: '4px 8px', fontSize: '12px' }}
                value={dateFilter}
                onChange={(e) => { setDateFilter(e.target.value); if (e.target.value === 'all') { setTimeStart(''); setTimeEnd(''); } }}
              >
                <option value="all">All dates</option>
                {availableDates.map((d) => (<option key={d.key} value={d.key}>{d.label}</option>))}
              </select>
            </div>

            {dateFilter !== 'all' && (
              <div style={{ display: 'flex', alignItems: 'center', gap: '6px' }}>
                <Clock size={13} style={{ color: 'var(--text-muted)' }} />
                <label style={{ fontSize: '12px', color: 'var(--text-secondary)' }}>Time</label>
                <input type="time" step={1} className="form-input" style={{ padding: '3px 6px', fontSize: '12px', width: '118px' }} value={timeStart} onChange={(e) => setTimeStart(e.target.value)} title="From (time of day)" />
                <ArrowRight size={12} style={{ color: 'var(--text-muted)' }} />
                <input type="time" step={1} className="form-input" style={{ padding: '3px 6px', fontSize: '12px', width: '118px' }} value={timeEnd} onChange={(e) => setTimeEnd(e.target.value)} title="To (time of day)" />
                {(timeStart || timeEnd) && (
                  <button className="btn btn-secondary btn-sm" onClick={() => { setTimeStart(''); setTimeEnd(''); }}>Clear</button>
                )}
              </div>
            )}

            <div style={{ marginLeft: 'auto', display: 'flex', alignItems: 'center', gap: '10px' }}>
              <span style={{ display: 'inline-flex', alignItems: 'center', gap: '5px', fontSize: '12px', color: 'var(--text-muted)' }}>
                <Grid3x3 size={13} /> {channels.length} camera{channels.length === 1 ? '' : 's'}
              </span>
              {selectedChannel !== null && (
                <button className="btn btn-secondary btn-sm" onClick={() => setSelectedChannel(null)} title="Hide controls / deselect camera">
                  <X size={12} /><span>Deselect</span>
                </button>
              )}
            </div>
          </div>

          {/* Camera wall */}
          {channels.length === 0 ? (
            <div className="empty-state" style={{ padding: '32px' }}>
              <MonitorPlay size={28} />
              <p>No channels found for this evidence.</p>
            </div>
          ) : (
            <div
              style={{
                display: 'grid',
                gridTemplateColumns: `repeat(${cols}, 1fr)`,
                gap: '10px',
                marginBottom: '16px',
              }}
            >
              {channels.map((ch) => (
                <CameraTile
                  key={`${ch}-${dateFilter}-${timeStart}-${timeEnd}`}
                  evidenceId={evidence.id}
                  cameraLabel={`Camera ${ch}`}
                  channel={ch}
                  playlist={filteredByChannel.get(ch) ?? []}
                  selected={selectedChannel === ch}
                  oemName={parserKey}
                  onSelect={() => setSelectedChannel((prev) => (prev === ch ? prev : ch))}
                />
              ))}
            </div>
          )}

          <div className="panel" style={{ padding: '10px 14px', fontSize: '12px', color: 'var(--text-muted)', display: 'flex', gap: '18px', flexWrap: 'wrap' }}>
            <span>Cameras play automatically and continuously in timeline order.</span>
            <span><strong style={{ color: 'var(--text-secondary)' }}>Click a camera</strong> to enable its playback controls.</span>
            <span style={{ color: 'var(--danger)' }}>“Signal lost” marks footage no recovery level could restore.</span>
          </div>
        </>
      )}
    </div>
  );
};
