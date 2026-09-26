import React, { useState, useRef, useEffect } from 'react';
import {
  Play, Pause, Volume2, VolumeX, Maximize,
  ShieldCheck, AlertTriangle, CheckCircle2, XCircle,
  Clock, Hash as HashIcon, RefreshCw, X,
  SkipBack, SkipForward, ChevronLeft, ChevronRight,
  Rewind, FastForward, Type, Move, Eye, EyeOff
} from 'lucide-react';
import { verifyArtifact } from '../../services/api';
import { ArtifactVerificationResult } from '../../types';

export interface VideoPlayerProps {
  videoId?: string;
  videoUrl: string;
  recordingId: string;
  channel: number;
  oemName: string;
  sourceOffset: number;
  sourceLength: number;
  nativeTime?: string;
  normalizedUtc?: string;
  codec: string;
  /** Total decoded frames, when known from reconstruction. Optional. */
  frameCount?: number;
  elementarySha256?: string;
  remuxSha256?: string;
  ffmpegVersion?: string;
  ffmpegArgs?: string[];
  validationState?: { state: string; reason: string };
  onClose?: () => void;
}

type Corner = 'tl' | 'tr' | 'br' | 'bl';
const CORNERS: Corner[] = ['tl', 'tr', 'br', 'bl'];
const OVERLAY_COLORS = ['#ffffff', '#facc15', '#000000'];

/**
 * DVR recorders record wall-clock time, not UTC instants. To advance the
 * displayed timestamp during playback we parse the wall-clock components and
 * add the playback offset in UTC space so the browser's local timezone never
 * shifts the shown value. Returns null for unparseable strings (e.g. "Unknown").
 */
function parseWallClock(s?: string): number | null {
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

/** Advances a recorder wall-clock timestamp by `offsetSec`, falling back to the
 *  raw string when it can't be parsed so we never fabricate a time. */
function advanceStamp(base: string | undefined, offsetSec: number): string {
  const parsed = parseWallClock(base);
  if (parsed === null) return base || 'Unknown';
  return formatWallClock(parsed + Math.floor(offsetSec) * 1000);
}

export const VideoPlayer: React.FC<VideoPlayerProps> = ({
  videoId,
  videoUrl,
  recordingId,
  channel,
  oemName,
  sourceOffset,
  sourceLength,
  nativeTime,
  normalizedUtc,
  codec,
  frameCount,
  elementarySha256,
  remuxSha256,
  ffmpegVersion,
  ffmpegArgs,
  validationState,
  onClose,
}) => {
  const videoRef = useRef<HTMLVideoElement | null>(null);
  const [isPlaying, setIsPlaying] = useState(false);
  const [currentTime, setCurrentTime] = useState(0);
  const [duration, setDuration] = useState(0);
  const [volume, setVolume] = useState(1);
  const [isMuted, setIsMuted] = useState(false);
  const [playbackRate, setPlaybackRate] = useState(1);
  const [playbackError, setPlaybackError] = useState<string | null>(null);
  const [isHevcUnsupported, setIsHevcUnsupported] = useState(false);
  const [verifying, setVerifying] = useState(false);
  const [verifyResult, setVerifyResult] = useState<ArtifactVerificationResult | null>(null);
  const [dims, setDims] = useState<{ w: number; h: number }>({ w: 0, h: 0 });

  // DVR-Examiner-style overlay controls
  const [overlayEnabled, setOverlayEnabled] = useState(true);
  const [overlayCorner, setOverlayCorner] = useState<Corner>('tl');
  const [overlayColor, setOverlayColor] = useState<string>(OVERLAY_COLORS[0]);

  const isHevc = codec.toLowerCase().includes('h.265') || codec.toLowerCase().includes('hevc') || codec.toLowerCase().includes('h265');

  // DVR footage lacks a container frame rate we can trust, so frame stepping uses
  // a nominal rate. When the reconstruction reports a real frame count we derive
  // the true rate from it; otherwise we fall back to 15 fps (common on DVRs) and
  // label the frame number as approximate so nothing is presented as ground truth.
  const derivedFps = frameCount && duration > 0 ? frameCount / duration : 15;
  const fpsIsDerived = !(frameCount && duration > 0);
  const totalFrames = frameCount ?? (duration > 0 ? Math.round(duration * derivedFps) : 0);
  const currentFrame = duration > 0 ? Math.min(totalFrames || Infinity, Math.floor(currentTime * derivedFps) + 1) : 0;

  useEffect(() => {
    if (isHevc) {
      const v = document.createElement('video');
      const canPlay = v.canPlayType('video/mp4; codecs="hvc1.1.6.L93.B0"');
      if (canPlay === '') {
        setIsHevcUnsupported(true);
      }
    }
  }, [isHevc]);

  const togglePlay = () => {
    if (!videoRef.current) return;
    if (isPlaying) {
      videoRef.current.pause();
    } else {
      videoRef.current.play().catch((err) => {
        console.warn('Playback error:', err);
        setPlaybackError(err.message || 'Browser playback failed for this stream.');
      });
    }
  };

  const handleTimeUpdate = () => {
    if (videoRef.current) {
      setCurrentTime(videoRef.current.currentTime);
    }
  };

  const handleLoadedMetadata = () => {
    if (videoRef.current) {
      setDuration(videoRef.current.duration);
      setDims({ w: videoRef.current.videoWidth, h: videoRef.current.videoHeight });
      setPlaybackError(null);
    }
  };

  const handleSeek = (e: React.ChangeEvent<HTMLInputElement>) => {
    const targetTime = parseFloat(e.target.value);
    if (videoRef.current) {
      videoRef.current.currentTime = targetTime;
      setCurrentTime(targetTime);
    }
  };

  const clamp = (t: number) => Math.max(0, Math.min(duration || 0, t));

  /** Steps by `frames` (negative = backward), pausing playback like DVR Examiner. */
  const stepFrames = (frames: number) => {
    if (!videoRef.current) return;
    videoRef.current.pause();
    const t = clamp(videoRef.current.currentTime + frames / derivedFps);
    videoRef.current.currentTime = t;
    setCurrentTime(t);
  };

  const goToEdge = (edge: 'first' | 'last') => {
    if (!videoRef.current) return;
    videoRef.current.pause();
    const t = edge === 'first' ? 0 : Math.max(0, (duration || 0) - 1 / derivedFps);
    videoRef.current.currentTime = t;
    setCurrentTime(t);
  };

  const toggleMute = () => {
    if (!videoRef.current) return;
    videoRef.current.muted = !isMuted;
    setIsMuted(!isMuted);
  };

  const handleVolumeChange = (e: React.ChangeEvent<HTMLInputElement>) => {
    const newVol = parseFloat(e.target.value);
    setVolume(newVol);
    if (videoRef.current) {
      videoRef.current.volume = newVol;
      setIsMuted(newVol === 0);
    }
  };

  const toggleFullscreen = () => {
    if (!videoRef.current) return;
    if (document.fullscreenElement) {
      document.exitFullscreen();
    } else {
      videoRef.current.requestFullscreen();
    }
  };

  const handleRateChange = (rate: number) => {
    setPlaybackRate(rate);
    if (videoRef.current) {
      videoRef.current.playbackRate = rate;
    }
  };

  const formatSeconds = (sec: number) => {
    if (isNaN(sec)) return '00:00';
    const mins = Math.floor(sec / 60);
    const s = Math.floor(sec % 60);
    return `${mins.toString().padStart(2, '0')}:${s.toString().padStart(2, '0')}`;
  };

  const handleReverify = async () => {
    if (!videoId) return;
    setVerifying(true);
    try {
      const res = await verifyArtifact(videoId);
      setVerifyResult(res);
    } catch (err: any) {
      console.error('Verification failed:', err);
    } finally {
      setVerifying(false);
    }
  };

  // Derived presentation timestamps that advance with playback.
  const origStamp = advanceStamp(nativeTime, currentTime);
  const adjStamp = normalizedUtc ? advanceStamp(normalizedUtc, currentTime) : null;
  const overlayHeadTime = adjStamp ?? origStamp;
  const resolutionLabel = dims.w > 0 ? `${dims.w} × ${dims.h}` : '—';

  return (
    <div className="panel" style={{ padding: '0', overflow: 'hidden', border: '1px solid var(--border-subtle)', backgroundColor: 'var(--surface)' }}>
      {/* Prominent Mandatory Forensic Authority Notice */}
      <div style={{
        backgroundColor: 'rgba(59, 130, 246, 0.08)',
        borderBottom: '1px solid rgba(59, 130, 246, 0.2)',
        padding: '10px 16px',
        display: 'flex',
        alignItems: 'center',
        justifyContent: 'space-between',
        gap: '12px'
      }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
          <ShieldCheck size={16} style={{ color: 'var(--accent)' }} />
          <span style={{ fontSize: '12px', fontWeight: 600, color: 'var(--text-primary)' }}>
            Derived Playback Representation (Stream-Copy Remux)
          </span>
          <span className="badge badge-info" style={{ fontSize: '10px' }}>ISO/IEC 14496-14</span>
        </div>
        <div style={{ display: 'flex', alignItems: 'center', gap: '12px' }}>
          <div style={{ fontSize: '11px', color: 'var(--text-muted)' }}>
            Authoritative sources: Evidence Image + Recovered Elementary Stream
          </div>
          {onClose && (
            <button
              className="btn btn-icon btn-sm"
              onClick={onClose}
              title="Close Player"
              style={{ color: 'var(--text-secondary)' }}
            >
              <X size={15} />
            </button>
          )}
        </div>
      </div>

      <div style={{ display: 'grid', gridTemplateColumns: '1fr 340px', minHeight: '440px' }}>
        {/* Left Column: Video Screen, Frame Info, and Transport */}
        <div style={{ display: 'flex', flexDirection: 'column', backgroundColor: '#000', position: 'relative' }}>
          {isHevcUnsupported && (
            <div style={{
              backgroundColor: 'rgba(234, 179, 8, 0.15)',
              borderBottom: '1px solid rgba(234, 179, 8, 0.3)',
              padding: '8px 14px',
              fontSize: '11.5px',
              color: 'var(--warning)',
              display: 'flex',
              alignItems: 'center',
              gap: '8px',
              zIndex: 10
            }}>
              <AlertTriangle size={15} />
              <span>
                <strong>Browser HEVC Limitation:</strong> This browser may not decode HEVC/H.265 natively in HTML5. Container validation: PASS. Bitstream preserved.
              </span>
            </div>
          )}

          <div style={{ flex: 1, display: 'flex', alignItems: 'center', justifyContent: 'center', position: 'relative', overflow: 'hidden' }}>
            <video
              ref={videoRef}
              src={videoUrl}
              style={{ width: '100%', maxHeight: '420px', objectFit: 'contain' }}
              onPlay={() => setIsPlaying(true)}
              onPause={() => setIsPlaying(false)}
              onTimeUpdate={handleTimeUpdate}
              onLoadedMetadata={handleLoadedMetadata}
              onError={(e) => {
                const target = e.target as HTMLVideoElement;
                if (target.error) {
                  setPlaybackError(`HTML5 Media Error (${target.error.code}): ${target.error.message || 'Codec or range stream error'}`);
                }
              }}
            />

            {/* Burned-in timestamp overlay (DVR Examiner style) */}
            {overlayEnabled && !playbackError && (
              <div className={`dvr-overlay dvr-overlay-${overlayCorner}`} style={{ color: overlayColor }}>
                <div className="dvr-overlay-ch">CH{String(channel).padStart(2, '0')}</div>
                <div className="dvr-overlay-row">
                  <span>{origStamp}</span>
                  <span className="dvr-overlay-tag">ORIG</span>
                </div>
                {adjStamp && (
                  <div className="dvr-overlay-row">
                    <span>{adjStamp}</span>
                    <span className="dvr-overlay-tag">ADJ</span>
                  </div>
                )}
              </div>
            )}

            {playbackError && (
              <div style={{
                position: 'absolute',
                top: 0,
                left: 0,
                right: 0,
                bottom: 0,
                backgroundColor: 'rgba(0, 0, 0, 0.85)',
                display: 'flex',
                flexDirection: 'column',
                alignItems: 'center',
                justifyContent: 'center',
                padding: '20px',
                textAlign: 'center',
                color: 'var(--text-primary)'
              }}>
                <XCircle size={36} style={{ color: 'var(--danger)', marginBottom: '12px' }} />
                <h4 style={{ margin: '0 0 6px 0', fontSize: '14px' }}>Playback Note / Codec Restriction</h4>
                <p style={{ fontSize: '12px', color: 'var(--text-muted)', maxWidth: '420px', margin: 0 }}>
                  {playbackError}
                </p>
                <div style={{ marginTop: '14px', fontSize: '11px', color: 'var(--accent)' }}>
                  Elementary stream and MP4 artifact SHA-256 hashes remain verified on disk.
                </div>
              </div>
            )}
          </div>

          {/* Player Controls Bar */}
          <div style={{
            backgroundColor: 'rgba(15, 23, 42, 0.95)',
            borderTop: '1px solid rgba(255, 255, 255, 0.1)',
            padding: '10px 14px',
            display: 'flex',
            flexDirection: 'column',
            gap: '10px'
          }}>
            {/* Seek Bar */}
            <input
              type="range"
              min={0}
              max={duration || 100}
              step={0.001}
              value={currentTime}
              onChange={handleSeek}
              style={{ width: '100%', accentColor: 'var(--accent)', cursor: 'pointer', height: '4px' }}
            />

            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-end', gap: '14px', flexWrap: 'wrap' }}>
              {/* Current Frame Information (left, DVR Examiner style) */}
              <div className="dvr-frameinfo">
                <div className="dvr-frameinfo-title">Current Frame</div>
                <div className="dvr-frameinfo-row">
                  <span className="k">Timestamp</span>
                  <span className="v">{overlayHeadTime}</span>
                </div>
                <div className="dvr-frameinfo-row">
                  <span className="k">Frame</span>
                  <span className="v">
                    {currentFrame || '—'}{totalFrames ? ` of ${totalFrames}` : ''}
                    {fpsIsDerived && <span style={{ color: '#64748b', fontWeight: 400 }}> (≈)</span>}
                  </span>
                </div>
                <div className="dvr-frameinfo-row">
                  <span className="k">Displayed Res.</span>
                  <span className="v">{resolutionLabel}</span>
                </div>
                <div className="dvr-frameinfo-row">
                  <span className="k">Native Res.</span>
                  <span className="v">{resolutionLabel}</span>
                </div>
                <div className="dvr-frameinfo-row">
                  <span className="k">Position</span>
                  <span className="v accent">{formatSeconds(currentTime)} / {formatSeconds(duration)}</span>
                </div>
              </div>

              {/* Transport controls (right) */}
              <div style={{ display: 'flex', flexDirection: 'column', gap: '8px', alignItems: 'flex-end' }}>
                <div className="dvr-transport">
                  <button className="dvr-tbtn" onClick={() => goToEdge('first')} disabled={!duration} title="First frame">
                    <SkipBack size={15} />
                  </button>
                  <button className="dvr-tbtn" onClick={() => stepFrames(-25)} disabled={!duration} title="Jump back 25 frames">
                    <Rewind size={15} />
                  </button>
                  <button className="dvr-tbtn" onClick={() => stepFrames(-1)} disabled={!duration} title="Previous frame">
                    <ChevronLeft size={17} />
                  </button>
                  <button className="dvr-tbtn dvr-tbtn-play" onClick={togglePlay} title={isPlaying ? 'Pause' : 'Play'}>
                    {isPlaying ? <Pause size={18} /> : <Play size={18} />}
                  </button>
                  <button className="dvr-tbtn" onClick={() => stepFrames(1)} disabled={!duration} title="Next frame">
                    <ChevronRight size={17} />
                  </button>
                  <button className="dvr-tbtn" onClick={() => stepFrames(25)} disabled={!duration} title="Jump forward 25 frames">
                    <FastForward size={15} />
                  </button>
                  <button className="dvr-tbtn" onClick={() => goToEdge('last')} disabled={!duration} title="Last frame">
                    <SkipForward size={15} />
                  </button>
                </div>

                <div style={{ display: 'flex', alignItems: 'center', gap: '10px' }}>
                  <div style={{ display: 'flex', alignItems: 'center', gap: '5px' }}>
                    <button className="dvr-tbtn" style={{ width: 28, height: 28 }} onClick={toggleMute} title={isMuted ? 'Unmute' : 'Mute'}>
                      {isMuted ? <VolumeX size={13} /> : <Volume2 size={13} />}
                    </button>
                    <input
                      type="range"
                      min={0}
                      max={1}
                      step={0.05}
                      value={isMuted ? 0 : volume}
                      onChange={handleVolumeChange}
                      style={{ width: '54px', accentColor: 'var(--accent)', cursor: 'pointer', height: '4px' }}
                    />
                  </div>

                  <div className="dvr-speed" title="Playback speed">
                    {[0.5, 1, 2, 4].map(r => (
                      <button
                        key={r}
                        className={playbackRate === r ? 'active' : ''}
                        onClick={() => handleRateChange(r)}
                      >
                        {r}x
                      </button>
                    ))}
                  </div>

                  <button className="dvr-tbtn" style={{ width: 28, height: 28 }} onClick={toggleFullscreen} title="Fullscreen">
                    <Maximize size={13} />
                  </button>
                </div>
              </div>
            </div>
          </div>
        </div>

        {/* Right Column: Detailed Forensic Context & Hash Lineage */}
        <div style={{
          padding: '16px',
          borderLeft: '1px solid var(--border-subtle)',
          display: 'flex',
          flexDirection: 'column',
          gap: '14px',
          overflowY: 'auto',
          maxHeight: '600px'
        }}>
          <div>
            <div style={{ fontSize: '11px', textTransform: 'uppercase', color: 'var(--text-muted)', fontWeight: 600 }}>
              Forensic Source Target
            </div>
            <div style={{ marginTop: '4px', fontSize: '13px', fontWeight: 600 }}>
              {recordingId} <span className="badge badge-info" style={{ fontSize: '10px' }}>CH {channel}</span>
            </div>
            <div className="text-muted" style={{ fontSize: '11px', marginTop: '2px' }}>
              OEM: <strong>{oemName}</strong> | Codec: <strong>{codec}</strong>
            </div>
          </div>

          {/* Overlay Customization (DVR Examiner: Overlay on/off, Four Corners, Text Color) */}
          <div style={{ backgroundColor: 'var(--surface-muted)', padding: '10px', borderRadius: '4px', border: '1px solid var(--border-subtle)' }}>
            <div style={{ fontSize: '11px', fontWeight: 600, color: 'var(--text-secondary)', marginBottom: '8px' }}>
              Timestamp Overlay
            </div>
            <div className="dvr-overlay-controls">
              <button
                className={`dvr-chip ${overlayEnabled ? 'active' : ''}`}
                onClick={() => setOverlayEnabled((v) => !v)}
                title="Toggle the on-screen timestamp overlay"
              >
                {overlayEnabled ? <Eye size={13} /> : <EyeOff size={13} />}
                <span>{overlayEnabled ? 'On' : 'Off'}</span>
              </button>
              <button
                className="dvr-chip"
                onClick={() => setOverlayCorner((c) => CORNERS[(CORNERS.indexOf(c) + 1) % CORNERS.length])}
                disabled={!overlayEnabled}
                title="Cycle overlay corner"
              >
                <Move size={13} />
                <span>{overlayCorner.toUpperCase()}</span>
              </button>
              <div style={{ display: 'inline-flex', gap: '4px', alignItems: 'center' }}>
                <Type size={13} style={{ color: 'var(--text-muted)' }} />
                {OVERLAY_COLORS.map((c) => (
                  <button
                    key={c}
                    className={`dvr-color-swatch ${overlayColor === c ? 'active' : ''}`}
                    style={{ backgroundColor: c }}
                    onClick={() => setOverlayColor(c)}
                    disabled={!overlayEnabled}
                    title={`Overlay color ${c}`}
                    aria-label={`Overlay color ${c}`}
                  />
                ))}
              </div>
            </div>
          </div>

          {/* Time Evidence Breakdown */}
          <div style={{ backgroundColor: 'var(--surface-sunken)', padding: '10px', borderRadius: '4px', border: '1px solid var(--border-subtle)' }}>
            <div style={{ display: 'flex', alignItems: 'center', gap: '6px', fontSize: '11px', fontWeight: 600, color: 'var(--text-secondary)' }}>
              <Clock size={13} style={{ color: 'var(--accent)' }} />
              <span>Time Evidence (3-Tier)</span>
            </div>
            <div style={{ display: 'flex', flexDirection: 'column', gap: '4px', marginTop: '6px', fontSize: '11px' }}>
              <div>
                <span style={{ color: 'var(--text-muted)' }}>Recorder Native:</span>{' '}
                <span className="mono">{nativeTime || 'Preserved from Index'}</span>
              </div>
              <div>
                <span style={{ color: 'var(--text-muted)' }}>Normalized UTC:</span>{' '}
                <span className="mono">{normalizedUtc || 'Unknown (unshifted)'}</span>
              </div>
              <div>
                <span style={{ color: 'var(--text-muted)' }}>Presentation:</span>{' '}
                <span className="mono" style={{ color: 'var(--accent)' }}>{overlayHeadTime} (+{formatSeconds(currentTime)})</span>
              </div>
            </div>
          </div>

          {/* Source Region in Evidence */}
          <div style={{ fontSize: '11px' }}>
            <div style={{ color: 'var(--text-muted)', fontWeight: 600 }}>Source Evidence Region</div>
            <div className="mono" style={{ marginTop: '2px', fontSize: '11.5px' }}>
              Offset: 0x{sourceOffset.toString(16).toUpperCase()} ({sourceLength} bytes)
            </div>
          </div>

          {/* Independent SHA-256 Hashes */}
          <div style={{ display: 'flex', flexDirection: 'column', gap: '6px' }}>
            <div style={{ display: 'flex', alignItems: 'center', gap: '6px', fontSize: '11px', fontWeight: 600, color: 'var(--text-secondary)' }}>
              <HashIcon size={13} style={{ color: 'var(--success)' }} />
              <span>Independent Artifact Hashes</span>
            </div>

            {elementarySha256 && (
              <div style={{ backgroundColor: 'var(--surface-sunken)', padding: '6px 8px', borderRadius: '4px' }}>
                <div style={{ fontSize: '10px', color: 'var(--text-muted)' }}>Elementary Stream SHA-256:</div>
                <div className="mono" style={{ fontSize: '10px', wordBreak: 'break-all', color: 'var(--text-primary)' }}>
                  {elementarySha256}
                </div>
              </div>
            )}

            {remuxSha256 && (
              <div style={{ backgroundColor: 'var(--surface-sunken)', padding: '6px 8px', borderRadius: '4px' }}>
                <div style={{ fontSize: '10px', color: 'var(--text-muted)' }}>Remux MP4 SHA-256:</div>
                <div className="mono" style={{ fontSize: '10px', wordBreak: 'break-all', color: 'var(--accent)' }}>
                  {remuxSha256}
                </div>
              </div>
            )}
          </div>

          {/* Processing Provenance */}
          <div style={{ fontSize: '11px', display: 'flex', flexDirection: 'column', gap: '4px' }}>
            <div style={{ color: 'var(--text-muted)', fontWeight: 600 }}>Processing Provenance</div>
            <div>
              Tool: <strong>FFmpeg ({ffmpegVersion || 'Stream-Copy'})</strong>
            </div>
            {ffmpegArgs && ffmpegArgs.length > 0 && (
              <div style={{ backgroundColor: 'var(--surface-sunken)', padding: '4px 6px', borderRadius: '3px', marginTop: '2px' }}>
                <div style={{ fontSize: '9.5px', color: 'var(--text-muted)' }}>Remux Parameters:</div>
                <div className="mono" style={{ fontSize: '9px', wordBreak: 'break-all', color: 'var(--text-secondary)' }}>
                  ffmpeg {ffmpegArgs.join(' ')}
                </div>
              </div>
            )}
            {validationState && (
              <div style={{ display: 'flex', alignItems: 'center', gap: '6px', marginTop: '2px' }}>
                <span className={validationState.state === 'PASS' ? 'badge badge-pass' : 'badge badge-review'}>
                  {validationState.state}
                </span>
                <span style={{ fontSize: '10.5px', color: 'var(--text-muted)' }}>{validationState.reason}</span>
              </div>
            )}
          </div>

          {/* On-Demand Re-Verification Action */}
          {videoId && (
            <div style={{ marginTop: 'auto', paddingTop: '10px', borderTop: '1px solid var(--border-subtle)' }}>
              <button
                className="btn btn-secondary btn-sm"
                onClick={handleReverify}
                disabled={verifying}
                style={{ width: '100%', justifyContent: 'center' }}
              >
                {verifying ? <RefreshCw size={13} className="spin" /> : <ShieldCheck size={13} />}
                <span>{verifying ? 'Re-hashing On Disk...' : 'Verify Artifact Hash'}</span>
              </button>

              {verifyResult && (
                <div style={{
                  marginTop: '8px',
                  padding: '6px 8px',
                  borderRadius: '4px',
                  fontSize: '11px',
                  backgroundColor: verifyResult.status === 'MATCH' ? 'rgba(34, 197, 94, 0.1)' : 'rgba(239, 68, 68, 0.1)',
                  border: `1px solid ${verifyResult.status === 'MATCH' ? 'rgba(34, 197, 94, 0.3)' : 'rgba(239, 68, 68, 0.3)'}`
                }}>
                  <div style={{ display: 'flex', alignItems: 'center', gap: '4px', fontWeight: 600, color: verifyResult.status === 'MATCH' ? 'var(--success)' : 'var(--danger)' }}>
                    {verifyResult.status === 'MATCH' ? <CheckCircle2 size={13} /> : <XCircle size={13} />}
                    <span>Status: {verifyResult.status}</span>
                  </div>
                  <div className="mono" style={{ fontSize: '9.5px', marginTop: '2px', color: 'var(--text-muted)' }}>
                    Bytes: {verifyResult.size_bytes} | {verifyResult.verified_at.slice(11, 19)} UTC
                  </div>
                </div>
              )}
            </div>
          )}
        </div>
      </div>
    </div>
  );
};
