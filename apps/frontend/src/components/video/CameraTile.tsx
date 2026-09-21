import React, { useState, useRef, useEffect, useCallback } from 'react';
import {
  Play, Pause, Volume2, VolumeX, Maximize, ChevronLeft, ChevronRight,
  RefreshCw, VideoOff, Circle,
} from 'lucide-react';
import { reconstructRecording } from '../../services/api';

/** One entry in a channel's continuous playlist, in final-timeline order. */
export interface PlaylistSegment {
  key: string;
  kind: 'recorded' | 'recovered' | 'lost';
  channel: number;
  offset: number;
  length: number;
  durationSec: number;
  startNative: string | null;
  startNormalized: string;
  codec: string;
  level?: 'L1' | 'L2' | 'L3' | null;
}

interface CameraTileProps {
  evidenceId: string;
  cameraLabel: string;   // e.g. "Camera 1"
  channel: number;       // e.g. 1
  playlist: PlaylistSegment[];
  selected: boolean;
  oemName: string;
  onSelect: () => void;
}

// A lost sub-range has no bytes to decode; hold the "signal lost" frame briefly so the
// wall keeps cycling instead of freezing on a long gap. The label still states the real
// lost duration.
const LOST_HOLD_MS = 2500;
const ERROR_HOLD_MS = 2500;

function parseWallClock(s?: string | null): number | null {
  if (!s) return null;
  const m = s.match(/(\d{4})-(\d{2})-(\d{2})[T ](\d{2}):(\d{2}):(\d{2})/);
  if (!m) return null;
  const [, y, mo, d, h, mi, se] = m;
  return Date.UTC(+y, +mo - 1, +d, +h, +mi, +se);
}

function formatWallClock(ms: number): string {
  const d = new Date(ms);
  const p = (n: number) => n.toString().padStart(2, '0');
  return `${d.getUTCFullYear()}-${p(d.getUTCMonth() + 1)}-${p(d.getUTCDate())} ` +
    `${p(d.getUTCHours())}:${p(d.getUTCMinutes())}:${p(d.getUTCSeconds())}`;
}

function advanceStamp(base: string | null | undefined, offsetSec: number): string {
  const parsed = parseWallClock(base);
  if (parsed === null) return base || '—';
  return formatWallClock(parsed + Math.floor(offsetSec) * 1000);
}

function fmtDur(totalSeconds: number): string {
  const s = Math.max(0, Math.round(totalSeconds));
  if (s < 60) return `${s}s`;
  const m = Math.floor(s / 60);
  return `${m}m ${s % 60}s`;
}

type Phase = 'idle' | 'loading' | 'playing' | 'lost' | 'error' | 'empty';

export const CameraTile: React.FC<CameraTileProps> = ({
  evidenceId, cameraLabel, channel, playlist, selected, oemName, onSelect,
}) => {
  const videoRef = useRef<HTMLVideoElement | null>(null);
  const containerRef = useRef<HTMLDivElement | null>(null);
  const urlCache = useRef<Map<string, string>>(new Map());
  const holdTimer = useRef<ReturnType<typeof setTimeout> | null>(null);
  const cancelled = useRef(false);

  const [index, setIndex] = useState(0);
  const [phase, setPhase] = useState<Phase>('idle');
  const [isPaused, setIsPaused] = useState(false);
  const [muted, setMuted] = useState(true);
  const [rate, setRate] = useState(1);
  const [clipTime, setClipTime] = useState(0);
  const [clipDur, setClipDur] = useState(0);
  const [note, setNote] = useState<string | null>(null);

  const segment: PlaylistSegment | undefined = playlist[index];

  const clearHold = () => {
    if (holdTimer.current) { clearTimeout(holdTimer.current); holdTimer.current = null; }
  };

  const advance = useCallback(() => {
    setClipTime(0);
    setClipDur(0);
    setIndex((i) => (playlist.length === 0 ? 0 : (i + 1) % playlist.length));
  }, [playlist.length]);

  // Reset when the playlist changes (e.g. new date/time filter).
  useEffect(() => {
    clearHold();
    setIndex(0);
    setPhase(playlist.length === 0 ? 'empty' : 'idle');
    setNote(null);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [playlist]);

  // Load whatever segment the index points at.
  useEffect(() => {
    cancelled.current = false;
    clearHold();
    if (playlist.length === 0) { setPhase('empty'); return; }
    const seg = playlist[index];
    if (!seg) return;

    if (seg.kind === 'lost' || seg.length === 0) {
      setPhase('lost');
      setNote(`${fmtDur(seg.durationSec)} recording lost`);
      if (!isPaused) {
        holdTimer.current = setTimeout(() => { if (!cancelled.current) advance(); }, LOST_HOLD_MS);
      }
      return () => { cancelled.current = true; clearHold(); };
    }

    // Playable clip: reconstruct (cached) then play.
    const cached = urlCache.current.get(seg.key);
    if (cached) {
      setPhase('playing');
      setNote(null);
      queueMicrotask(() => attachAndPlay(cached));
      return () => { cancelled.current = true; clearHold(); };
    }

    setPhase('loading');
    setNote(null);
    (async () => {
      try {
        const res: any = await reconstructRecording(evidenceId, seg.key, {
          offset_start: seg.offset,
          length: seg.length > 0 ? seg.length : 131072,
          channel: seg.channel,
          oem_key: oemName,
        });
        if (cancelled.current) return;
        const url = res?.remux?.video_url;
        if (url) {
          urlCache.current.set(seg.key, url);
          setPhase('playing');
          attachAndPlay(url);
        } else {
          // Stream extracted but no MP4 remux (FFmpeg unavailable): skip forward.
          setPhase('error');
          setNote('MP4 remux unavailable on host');
          if (!isPaused) holdTimer.current = setTimeout(() => { if (!cancelled.current) advance(); }, ERROR_HOLD_MS);
        }
      } catch {
        if (cancelled.current) return;
        setPhase('error');
        setNote('Could not reconstruct this clip');
        if (!isPaused) holdTimer.current = setTimeout(() => { if (!cancelled.current) advance(); }, ERROR_HOLD_MS);
      }
    })();

    return () => { cancelled.current = true; clearHold(); };
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [index, playlist, evidenceId, oemName]);

  const attachAndPlay = (url: string) => {
    const v = videoRef.current;
    if (!v) return;
    if (v.src !== url) v.src = url;
    v.muted = muted;
    v.playbackRate = rate;
    if (!isPaused) {
      v.play().catch(() => { /* autoplay may be blocked until interaction */ });
    }
  };

  // Keep muted/rate in sync with controls.
  useEffect(() => { if (videoRef.current) videoRef.current.muted = muted; }, [muted]);
  useEffect(() => { if (videoRef.current) videoRef.current.playbackRate = rate; }, [rate]);

  const togglePlay = () => {
    const v = videoRef.current;
    setIsPaused((p) => {
      const next = !p;
      if (next) {
        v?.pause();
        clearHold();
      } else {
        if (phase === 'playing') v?.play().catch(() => {});
        else if (phase === 'lost' || phase === 'error') advance();
      }
      return next;
    });
  };

  const seek = (t: number) => {
    const v = videoRef.current;
    if (v && isFinite(t)) { v.currentTime = t; setClipTime(t); }
  };

  const toggleFullscreen = () => {
    const el = containerRef.current;
    if (!el) return;
    if (document.fullscreenElement) document.exitFullscreen();
    else el.requestFullscreen?.();
  };

  useEffect(() => () => { cancelled.current = true; clearHold(); }, []);

  const stampBase = segment?.startNative ?? segment?.startNormalized ?? null;
  const liveStamp = advanceStamp(stampBase, phase === 'playing' ? clipTime : 0);
  const isRecovered = segment?.kind === 'recovered';

  const gridPos = `${index + 1}/${playlist.length || 0}`;

  return (
    <div
      ref={containerRef}
      onClick={onSelect}
      style={{
        position: 'relative',
        background: '#000',
        borderRadius: '6px',
        overflow: 'hidden',
        border: selected ? '2px solid var(--accent)' : '1px solid rgba(255,255,255,0.08)',
        aspectRatio: '16 / 9',
        cursor: 'pointer',
        boxShadow: selected ? '0 0 0 2px rgba(59,130,246,0.35)' : undefined,
      }}
    >
      {/* Video surface */}
      <video
        ref={videoRef}
        playsInline
        muted={muted}
        onPlay={() => setIsPaused(false)}
        onPause={() => { /* keep state; user may have paused */ }}
        onTimeUpdate={() => { const v = videoRef.current; if (v) setClipTime(v.currentTime); }}
        onLoadedMetadata={() => { const v = videoRef.current; if (v) setClipDur(v.duration || 0); }}
        onEnded={() => { if (!isPaused) advance(); }}
        onError={() => {
          if (phase === 'playing') {
            setPhase('error');
            setNote('Decode error for this clip');
            if (!isPaused) holdTimer.current = setTimeout(() => { if (!cancelled.current) advance(); }, ERROR_HOLD_MS);
          }
        }}
        style={{ width: '100%', height: '100%', objectFit: 'contain', background: '#000', display: 'block' }}
      />

      {/* Loading spinner */}
      {phase === 'loading' && (
        <Centered>
          <RefreshCw size={22} className="spin" style={{ color: 'rgba(255,255,255,0.8)' }} />
          <span style={{ color: 'rgba(255,255,255,0.7)', fontSize: '11px', marginTop: '6px' }}>Reconstructing…</span>
        </Centered>
      )}

      {/* Signal lost */}
      {phase === 'lost' && (
        <Centered>
          <VideoOff size={26} style={{ color: 'var(--danger)' }} />
          <span style={{ color: 'var(--danger)', fontSize: '12px', fontWeight: 700, marginTop: '6px', letterSpacing: '0.08em' }}>
            SIGNAL LOST
          </span>
          <span style={{ color: 'rgba(255,255,255,0.7)', fontSize: '11px', marginTop: '2px' }}>{note}</span>
        </Centered>
      )}

      {/* Error / no remux */}
      {phase === 'error' && (
        <Centered>
          <VideoOff size={24} style={{ color: 'var(--warning)' }} />
          <span style={{ color: 'var(--warning)', fontSize: '11px', marginTop: '6px', textAlign: 'center', padding: '0 10px' }}>{note}</span>
        </Centered>
      )}

      {/* Empty playlist */}
      {phase === 'empty' && (
        <Centered>
          <VideoOff size={22} style={{ color: 'rgba(255,255,255,0.4)' }} />
          <span style={{ color: 'rgba(255,255,255,0.5)', fontSize: '11px', marginTop: '6px' }}>No footage in selected window</span>
        </Centered>
      )}

      {/* Top overlay: camera label + REC dot */}
      <div style={{ position: 'absolute', top: 0, left: 0, right: 0, display: 'flex', justifyContent: 'space-between', alignItems: 'center', padding: '6px 8px', background: 'linear-gradient(to bottom, rgba(0,0,0,0.55), transparent)', pointerEvents: 'none' }}>
        <span style={{ color: '#fff', fontSize: '11px', fontWeight: 700, textShadow: '0 1px 2px rgba(0,0,0,0.8)' }}>
          {cameraLabel} · CH{String(channel).padStart(2, '0')}
        </span>
        <span style={{ display: 'inline-flex', alignItems: 'center', gap: '4px' }}>
          {isRecovered && (
            <span className="badge badge-review" style={{ fontSize: '9px', padding: '1px 5px' }}>{segment?.level ?? 'REC'}</span>
          )}
          <Circle size={9} fill={phase === 'playing' && !isPaused ? '#ef4444' : '#64748b'} stroke="none" />
          <span style={{ color: phase === 'playing' && !isPaused ? '#ef4444' : '#94a3b8', fontSize: '10px', fontWeight: 700 }}>
            {phase === 'playing' && !isPaused ? 'LIVE' : 'PAUSED'}
          </span>
        </span>
      </div>

      {/* Bottom overlay: timestamp (always) */}
      <div style={{ position: 'absolute', bottom: selected ? '44px' : '0', left: 0, right: 0, padding: '6px 8px', background: 'linear-gradient(to top, rgba(0,0,0,0.6), transparent)', pointerEvents: 'none', display: 'flex', justifyContent: 'space-between', alignItems: 'flex-end' }}>
        <span className="mono" style={{ color: '#fff', fontSize: '11px', textShadow: '0 1px 2px rgba(0,0,0,0.9)' }}>{liveStamp}</span>
        <span className="mono" style={{ color: 'rgba(255,255,255,0.75)', fontSize: '10px', textShadow: '0 1px 2px rgba(0,0,0,0.9)' }}>clip {gridPos}</span>
      </div>

      {/* CCTV controller — only when this camera is selected */}
      {selected && (
        <div
          onClick={(e) => e.stopPropagation()}
          style={{ position: 'absolute', bottom: 0, left: 0, right: 0, background: 'rgba(2,6,23,0.92)', borderTop: '1px solid rgba(255,255,255,0.12)', padding: '5px 8px', display: 'flex', flexDirection: 'column', gap: '4px' }}
        >
          {/* Scrubber for the current clip */}
          <input
            type="range"
            min={0}
            max={clipDur || 100}
            step={0.05}
            value={clipTime}
            onChange={(e) => seek(parseFloat(e.target.value))}
            disabled={phase !== 'playing'}
            style={{ width: '100%', height: '3px', accentColor: 'var(--accent)', cursor: 'pointer' }}
          />
          <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', gap: '6px' }}>
            <div style={{ display: 'flex', alignItems: 'center', gap: '4px' }}>
              <CtrlBtn title="Previous clip" onClick={() => { clearHold(); setIndex((i) => (i - 1 + playlist.length) % playlist.length); setClipTime(0); }}>
                <ChevronLeft size={15} />
              </CtrlBtn>
              <CtrlBtn title={isPaused ? 'Play' : 'Pause'} onClick={togglePlay} primary>
                {isPaused ? <Play size={15} /> : <Pause size={15} />}
              </CtrlBtn>
              <CtrlBtn title="Next clip" onClick={() => { clearHold(); advance(); }}>
                <ChevronRight size={15} />
              </CtrlBtn>
              <CtrlBtn title={muted ? 'Unmute' : 'Mute'} onClick={() => setMuted((m) => !m)}>
                {muted ? <VolumeX size={13} /> : <Volume2 size={13} />}
              </CtrlBtn>
            </div>
            <div style={{ display: 'flex', alignItems: 'center', gap: '6px' }}>
              <div className="dvr-speed" style={{ transform: 'scale(0.85)', transformOrigin: 'right center' }}>
                {[0.5, 1, 2, 4].map((r) => (
                  <button key={r} className={rate === r ? 'active' : ''} onClick={() => setRate(r)}>{r}x</button>
                ))}
              </div>
              <CtrlBtn title="Fullscreen" onClick={toggleFullscreen}><Maximize size={13} /></CtrlBtn>
            </div>
          </div>
        </div>
      )}
    </div>
  );
};

const Centered: React.FC<{ children: React.ReactNode }> = ({ children }) => (
  <div style={{ position: 'absolute', inset: 0, display: 'flex', flexDirection: 'column', alignItems: 'center', justifyContent: 'center', pointerEvents: 'none' }}>
    {children}
  </div>
);

const CtrlBtn: React.FC<{ title: string; onClick: () => void; primary?: boolean; children: React.ReactNode }> = ({ title, onClick, primary, children }) => (
  <button
    title={title}
    onClick={onClick}
    style={{
      width: primary ? '30px' : '26px', height: primary ? '30px' : '26px',
      display: 'inline-flex', alignItems: 'center', justifyContent: 'center',
      borderRadius: '5px', cursor: 'pointer',
      background: primary ? 'var(--accent)' : 'rgba(255,255,255,0.08)',
      color: primary ? '#fff' : 'rgba(255,255,255,0.85)',
      border: '1px solid rgba(255,255,255,0.12)',
    }}
  >
    {children}
  </button>
);
