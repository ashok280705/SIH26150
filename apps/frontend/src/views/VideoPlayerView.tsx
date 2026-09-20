import React, { useState, useEffect } from 'react';
import { MonitorPlay, RefreshCw, HardDrive, Play, Film } from 'lucide-react';
import { Evidence } from '../types';
import { runParsing, reconstructRecording } from '../services/api';
import { VideoPlayer } from '../components/video/VideoPlayer';
import { ContextHelp } from '../components/onboarding/ContextHelp';
import { WorkflowState } from '../workflow';

interface Props {
  evidence: Evidence | null;
  evidenceList?: Evidence[];
  onSelectEvidence?: (e: Evidence) => void;
  workflow?: WorkflowState;
}

interface RecItem {
  id: string;
  channel: number;
  offset: number;
  length: number;
  codec: string;
  native: string;
  normalized: string | null;
}

export const VideoPlayerView: React.FC<Props> = ({ evidence, evidenceList = [], onSelectEvidence, workflow }) => {
  const [recordings, setRecordings] = useState<RecItem[]>([]);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [activePlayback, setActivePlayback] = useState<any | null>(null);
  const [reconstructing, setReconstructing] = useState<string | null>(null);

  const parserKey = workflow?.parserUsed || workflow?.attributedOem || 'unified';

  useEffect(() => {
    setRecordings([]);
    setActivePlayback(null);
    setError(null);
    if (evidence) load();
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [evidence?.id]);

  const load = async () => {
    if (!evidence) return;
    setLoading(true);
    setError(null);
    try {
      const data = await runParsing(evidence.id, parserKey);
      const recs: RecItem[] = (data.recordings || []).map((r: any, idx: number) => {
        const region = r.source_offsets && r.source_offsets[0] ? r.source_offsets[0] : { offset: 0, length: 0 };
        return {
          id: r.id || `rec-${idx + 1}`,
          channel: r.channel ?? r.channel_id ?? 1,
          offset: region.offset,
          length: region.length,
          codec: r.codec || 'unknown',
          native: r.time?.recorder_native?.iso_8601 || 'Unknown',
          normalized: r.time?.normalized?.iso_8601 || null,
        };
      });
      setRecordings(recs);
    } catch (e: any) {
      setError(e?.message || 'Failed to load recordings');
    } finally {
      setLoading(false);
    }
  };

  const play = async (rec: RecItem) => {
    if (!evidence) return;
    setReconstructing(rec.id);
    try {
      const res = await reconstructRecording(evidence.id, rec.id, {
        offset_start: rec.offset,
        length: rec.length > 0 ? rec.length : 131072,
        channel: rec.channel,
        oem_key: parserKey,
      });
      if (res.remux) {
        setActivePlayback({
          videoId: res.remux.artifact_id,
          videoUrl: res.remux.video_url,
          recordingId: rec.id,
          channel: rec.channel,
          oemName: parserKey,
          sourceOffset: rec.offset,
          sourceLength: res.elementary_stream.size_bytes,
          nativeTime: rec.native,
          normalizedUtc: rec.normalized || undefined,
          codec: res.codec || rec.codec,
          elementarySha256: res.elementary_stream.sha256,
          remuxSha256: res.remux.sha256,
          ffmpegVersion: res.remux.ffmpeg_version,
          ffmpegArgs: res.remux.arguments,
          validationState: res.remux.validation_state,
        });
      } else {
        alert('Elementary stream extracted and hashed. MP4 remux requires FFmpeg on the host.');
      }
    } catch (e: any) {
      setError(e?.message || 'Reconstruction failed');
    } finally {
      setReconstructing(null);
    }
  };

  if (!evidence) {
    return (
      <div className="view-container">
        <div className="view-header">
          <div>
            <h1 className="view-title">Video Player</h1>
            <p className="view-subtitle">Select an evidence target to view recovered recordings.</p>
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
            <h1 className="view-title">Video Player</h1>
            <ContextHelp
              title="Video Player"
              content="Plays back each reconstructed recording. Streams are remuxed to MP4 by FFmpeg from the exact evidence byte range, with hashes shown for provenance."
            />
          </div>
          <p className="view-subtitle">Reconstructed recordings for review, played from the original evidence bytes</p>
        </div>
        <button className="btn btn-secondary" onClick={load} disabled={loading}>
          {loading ? <RefreshCw size={14} className="spin" /> : <RefreshCw size={14} />}
          <span>Reload</span>
        </button>
      </div>

      <div className="panel" style={{ padding: '16px', marginBottom: '20px', backgroundColor: 'var(--surface)' }}>
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

      {activePlayback && (
        <div style={{ marginBottom: '20px' }}>
          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '8px' }}>
            <h3 style={{ margin: 0, fontSize: '14px' }}>Now Playing — Recording {activePlayback.recordingId}</h3>
            <button className="btn btn-secondary btn-sm" onClick={() => setActivePlayback(null)}>Close</button>
          </div>
          <VideoPlayer {...activePlayback} onClose={() => setActivePlayback(null)} />
        </div>
      )}

      <div className="panel" style={{ padding: 0, overflow: 'hidden' }}>
        <div className="panel-header" style={{ margin: 0, padding: '16px' }}>
          <h3 style={{ margin: 0, fontSize: '14px' }}>Recordings ({recordings.length})</h3>
        </div>
        {recordings.length === 0 ? (
          <div className="empty-state" style={{ padding: '32px' }}>
            <Film size={28} />
            <p>{loading ? 'Loading recordings…' : 'No recordings available for playback.'}</p>
          </div>
        ) : (
          <div className="table-container" style={{ border: 'none', borderTop: '1px solid var(--border)' }}>
            <table className="data-table">
              <thead>
                <tr>
                  <th>Channel</th>
                  <th>Codec</th>
                  <th>Recorder Time</th>
                  <th>Offset</th>
                  <th>Size</th>
                  <th>Action</th>
                </tr>
              </thead>
              <tbody>
                {recordings.map((rec) => (
                  <tr key={rec.id}>
                    <td>CH{String(rec.channel).padStart(2, '0')}</td>
                    <td>{rec.codec}</td>
                    <td>{rec.native}</td>
                    <td className="mono" style={{ fontSize: '12px' }}>0x{rec.offset.toString(16).toUpperCase()}</td>
                    <td>{(rec.length / 1024).toFixed(0)} KB</td>
                    <td>
                      <button
                        className="btn btn-primary btn-sm"
                        onClick={() => play(rec)}
                        disabled={reconstructing === rec.id}
                      >
                        {reconstructing === rec.id ? <RefreshCw size={12} className="spin" /> : <Play size={12} />}
                        <span>{reconstructing === rec.id ? 'Reconstructing…' : 'Play'}</span>
                      </button>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </div>
    </div>
  );
};
