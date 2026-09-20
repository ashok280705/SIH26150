import React, { useState, useEffect } from 'react';
import { FileCode2, Play, RefreshCw, AlertCircle, HardDrive, Video } from 'lucide-react';
import { Evidence, ParserRun, Recording, DeletedCandidate, TimeEvidence } from '../types';
import { runParsing, reconstructRecording } from '../services/api';
import { ContextHelp } from '../components/onboarding/ContextHelp';
import { VideoPlayer } from '../components/video/VideoPlayer';
import { WorkflowState } from '../workflow';

interface ParsingViewProps {
  evidence: Evidence | null;
  evidenceList?: Evidence[];
  onSelectEvidence?: (e: Evidence) => void;
  onNavigateToHex: (offset: number) => void;
  workflow?: WorkflowState;
  onWorkflow?: (patch: Partial<WorkflowState>) => void;
}

/** Selectable parsers for the manual (ambiguous/unresolved) path. */
const MANUAL_PARSERS: { key: string; label: string; family: string }[] = [
  { key: 'dahua', label: 'Dahua (DHFS)', family: 'DHFS' },
  { key: 'hikvision', label: 'Hikvision (HIKVISION_FS)', family: 'HIKVISION_FS' },
  { key: 'honeywell', label: 'Honeywell (MAXPRO)', family: 'MAXPRO' },
  { key: 'cpplus_ubs', label: 'CP Plus / UBS', family: 'UBS' },
  { key: 'uniview', label: 'Uniview (UBIFS)', family: 'UBIFS' },
  { key: 'tplink', label: 'TP-Link VIGI NVR', family: 'TPLINK_VIGI_NVR' },
  { key: 'unified', label: 'Unified Fallback (generic carver)', family: 'GENERIC' },
];

function familyFor(oemKey: string): string {
  return MANUAL_PARSERS.find((p) => p.key === oemKey)?.family || 'DHFS';
}

export const ParsingView: React.FC<ParsingViewProps> = ({ 
  evidence, 
  evidenceList = [], 
  onSelectEvidence, 
  onNavigateToHex,
  workflow,
  onWorkflow,
}) => {
  const [loading, setLoading] = useState(false);
  const [detectedOem, setDetectedOem] = useState<string | null>(null);
  const [storageFamily, setStorageFamily] = useState<string | null>(null);
  const [attributionStatus, setAttributionStatus] = useState<string>('UNKNOWN');
  const [recordings, setRecordings] = useState<Recording[]>([]);
  const [deletedCandidates, setDeletedCandidates] = useState<DeletedCandidate[]>([]);
  const [parserRuns, setParserRuns] = useState<ParserRun[]>([]);
  const [activePlayback, setActivePlayback] = useState<any | null>(null);
  const [reconstructing, setReconstructing] = useState<string | null>(null);
  const [selectedParser, setSelectedParser] = useState<string>('');

  const verdict = workflow?.verdict ?? null;
  const isConfirmed = verdict === 'confirmed' && !!workflow?.attributedOem;

  useEffect(() => {
    // Confirmed evidence auto-attaches the attributed parser and runs. Ambiguous or
    // unresolved evidence waits for the analyst to pick a parser manually.
    if (evidence && isConfirmed && workflow?.attributedOem) {
      runParseWith(workflow.attributedOem);
    } else {
      setDetectedOem(null);
      setRecordings([]);
      setDeletedCandidates([]);
      setParserRuns([]);
      setSelectedParser('');
    }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [evidence?.id, verdict, workflow?.attributedOem]);

  // Map the backend's TimeEvidence onto the view model WITHOUT fabricating values.
  // A missing normalized time stays null and an absent timezone stays 'unknown' —
  // the UI never invents a timestamp or silently assumes UTC (Req 4.5–4.7).
  const normalizeTime = (t: any): TimeEvidence => {
    if (!t) {
      return {
        raw_value: 0,
        recorder_native: 'Unknown',
        normalized_utc: null,
        reference_time: null,
        timezone_state: 'unknown',
      };
    }
    const rawVal = typeof t.raw === 'object' ? t.raw?.value ?? 0 : (t.raw_value ?? 0);
    const native =
      typeof t.recorder_native === 'object'
        ? t.recorder_native?.iso_8601 ?? 'Unknown'
        : (t.recorder_native ?? 'Unknown');
    const utc =
      typeof t.normalized === 'object'
        ? t.normalized?.iso_8601 ?? null
        : (t.normalized_utc ?? null);
    const tzState = t.timezone
      ? (typeof t.timezone === 'object' && 'Known' in t.timezone ? 'known' : 'unknown')
      : (t.timezone_state ?? 'unknown');

    return {
      raw_value: rawVal,
      recorder_native: native,
      normalized_utc: utc,
      reference_time: null,
      timezone_state: tzState,
    };
  };

  // Run a specific parser against the evidence and populate the extraction results.
  // Used both for the confirmed (auto) path and the manual (analyst-selected) path.
  const runParseWith = async (oemKey: string) => {
    if (!evidence) return;
    setLoading(true);
    try {
      const oemFormatted =
        oemKey === 'cpplus_ubs'
          ? 'CP Plus / UBS'
          : oemKey === 'unified'
          ? 'Unified Fallback'
          : oemKey.charAt(0).toUpperCase() + oemKey.slice(1);
      setDetectedOem(oemFormatted);
      setStorageFamily(familyFor(oemKey));
      setAttributionStatus(
        isConfirmed ? 'Confirmed' : oemKey === 'unified' ? 'Unified Fallback' : 'Analyst Selected'
      );

      const parseData = await runParsing(evidence.id, oemKey);

      const normalizedRuns: ParserRun[] = (parseData.parser_runs || []).map((run: any, idx: number) => ({
        id: run.id || `run-${idx + 1}`,
        evidence_id: evidence.id,
        parser_id: run.parser_id || `${oemKey}-parser`,
        parser_version: run.parser_version || '1.0.0',
        operation_name: run.operation_name,
        started_at: new Date().toISOString(),
        completed_at: new Date().toISOString(),
        validation: {
          state: run.validation?.state || run.validation_state?.state || 'UNKNOWN',
          reason: run.validation?.reason || run.validation_state?.reason || '',
          operation: run.operation_name,
          subject: run.validation_state?.subject || oemKey,
        },
      }));
      setParserRuns(normalizedRuns);

      const normalizedRecs: Recording[] = (parseData.recordings || []).map((r: any, idx: number) => {
        const startOffset = r.offset_start ?? (r.source_offsets && r.source_offsets[0] ? r.source_offsets[0].offset : 0);
        const endOffset =
          r.offset_end ??
          (r.source_offsets && r.source_offsets[0]
            ? r.source_offsets[0].offset + r.source_offsets[0].length
            : startOffset);
        return {
          id: r.id || `REC-${oemKey.toUpperCase()}-00${idx + 1}`,
          evidence_id: evidence.id,
          channel_id: r.channel_id ?? r.channel ?? 1,
          start_time: normalizeTime(r.start_time || r.time),
          end_time: normalizeTime(r.end_time || r.time),
          codec: r.codec || 'unknown',
          frame_count: r.frame_count || 0,
          offset_start: startOffset,
          offset_end: endOffset,
          is_deleted: r.is_deleted || false,
          is_fragmented: r.is_fragmented || false,
        };
      });
      setRecordings(normalizedRecs);
      setDeletedCandidates([]);

      // Publish extraction result to the workflow so the Preliminary Timeline unlocks.
      const parsed =
        normalizedRecs.length > 0 ||
        normalizedRuns.some((run) => run.validation.state === 'PASS');
      if (onWorkflow) {
        onWorkflow({
          parsingDone: parsed,
          parserUsed: oemKey,
          recordingCount: normalizedRecs.length,
        });
      }
    } catch (err) {
      console.error('Parsing API failed:', err);
    } finally {
      setLoading(false);
    }
  };

  const getValidationBadge = (state: string) => {
    switch (state) {
      case 'PASS': return 'badge badge-pass';
      case 'REVIEW': return 'badge badge-review';
      case 'FAIL': return 'badge badge-fail';
      default: return 'badge badge-unknown';
    }
  };

  if (!evidence) {
    return (
      <div className="view-container" data-tour="parsing-view-panel">
        <div className="view-header">
          <div>
            <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
              <h1 className="view-title">Storage & Recording Parsers</h1>
              <ContextHelp
                title="Proprietary Parsing"
                content="After OEM format detection, proprietary parsers extract video recording tables, channels, and frame boundaries, linking each record to disk offsets."
              />
            </div>
            <p className="view-subtitle">Select an evidence item to view parsed data.</p>
          </div>
        </div>
        <div className="empty-state">
          <FileCode2 size={32} />
          <h3>No Evidence Selected</h3>
          <p>Select a DVR/NVR evidence item from the active case to begin analysis.</p>
        </div>
      </div>
    );
  }

  const capacityMb = (evidence.capacity / (1024 * 1024)).toFixed(2);

  const handlePlayRecording = async (rec: Recording) => {
    if (!evidence) return;
    setReconstructing(rec.id);
    try {
      const oemKey = workflow?.parserUsed || workflow?.attributedOem || 'unified';
      const res = await reconstructRecording(evidence.id, rec.id, {
        offset_start: rec.offset_start,
        length: rec.offset_end > rec.offset_start ? rec.offset_end - rec.offset_start : 131072,
        channel: rec.channel_id,
        oem_key: oemKey,
      });

      if (res.remux) {
        setActivePlayback({
          videoId: res.remux.artifact_id,
          videoUrl: res.remux.video_url,
          recordingId: rec.id,
          channel: rec.channel_id,
          oemName: detectedOem || 'TP-Link VIGI',
          sourceOffset: rec.offset_start,
          sourceLength: res.elementary_stream.size_bytes,
          nativeTime: rec.start_time.recorder_native,
          normalizedUtc: rec.start_time.normalized_utc || undefined,
          codec: res.codec || rec.codec,
          elementarySha256: res.elementary_stream.sha256,
          remuxSha256: res.remux.sha256,
          ffmpegVersion: res.remux.ffmpeg_version,
          ffmpegArgs: res.remux.arguments,
          validationState: res.remux.validation_state,
        });
      } else {
        alert("Elementary stream extracted and hashed. Stream-copy MP4 container remuxing requires FFmpeg on host.");
      }
    } catch (err: any) {
      console.error("Reconstruction failed:", err);
      alert(`Reconstruction failed: ${err.message || err}`);
    } finally {
      setReconstructing(null);
    }
  };

  return (
    <div className="view-container" data-tour="parsing-view-panel">
      <div className="view-header">
        <div>
          <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
            <h1 className="view-title">Storage & Recording Parsers</h1>
            <ContextHelp
              title="Proprietary Parsing"
              content="After OEM format detection, proprietary parsers extract video recording tables, channels, and frame boundaries, linking each record to disk offsets."
            />
          </div>
          <p className="view-subtitle">High-speed extraction of recordings and video index tables</p>
        </div>
        <div>
          {isConfirmed && (
            <button
              className="btn btn-secondary"
              onClick={() => workflow?.attributedOem && runParseWith(workflow.attributedOem)}
              disabled={loading}
            >
              {loading ? <RefreshCw size={14} className="spin" /> : <Play size={14} />}
              <span>{loading ? 'Analyzing Storage...' : 'Re-parse Evidence'}</span>
            </button>
          )}
        </div>
      </div>

      {/* Target Evidence Selector Bar */}
      <div className="panel" style={{ padding: '16px', marginBottom: '20px', backgroundColor: 'var(--surface)' }}>
        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', flexWrap: 'wrap', gap: '14px' }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: '12px' }}>
            <HardDrive size={18} style={{ color: 'var(--accent)' }} />
            <div>
              <div style={{ fontSize: '11px', textTransform: 'uppercase', color: 'var(--text-muted)', fontWeight: 600 }}>
                Active Target Evidence
              </div>
              <div style={{ display: 'flex', alignItems: 'center', gap: '8px', marginTop: '2px' }}>
                <strong style={{ fontSize: '14px' }}>{evidence.source_device}</strong>
                <span className="badge badge-info">{evidence.image_format}</span>
                <span style={{ fontSize: '12px', color: 'var(--text-muted)' }}>
                  ({capacityMb} MB)
                </span>
              </div>
            </div>
          </div>

          {evidenceList && evidenceList.length > 1 && (
            <div style={{ display: 'flex', alignItems: 'center', gap: '6px' }}>
              <label style={{ fontSize: '12px', fontWeight: 600, color: 'var(--text-secondary)' }}>
                Switch Target:
              </label>
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
                  <option key={item.id} value={item.id}>
                    {item.source_device} ({(item.capacity / (1024 * 1024)).toFixed(0)}MB)
                  </option>
                ))}
              </select>
            </div>
          )}
        </div>
      </div>

      {/* Routing banner: confirmed auto-attaches; ambiguous/unresolved needs manual choice */}
      {isConfirmed ? (
        <div className="panel mb-4" style={{ borderLeft: '4px solid var(--success)', padding: '14px 16px' }}>
          <div style={{ fontSize: '13px' }}>
            <strong>Confirmed attribution.</strong> The <strong>{workflow?.attributedOem}</strong> parser was attached automatically and extraction has run.
          </div>
        </div>
      ) : (
        <div className="panel mb-4" style={{ borderLeft: '4px solid var(--warning)', padding: '16px' }}>
          <div style={{ display: 'flex', alignItems: 'flex-start', gap: '10px', flexWrap: 'wrap' }}>
            <AlertCircle size={18} style={{ color: 'var(--warning)', flexShrink: 0, marginTop: '2px' }} />
            <div style={{ flex: 1, minWidth: '260px' }}>
              <strong style={{ fontSize: '14px' }}>
                {verdict === 'ambiguous' ? 'Ambiguous attribution — analyst selection required' : verdict === 'unresolved' ? 'Unresolved — choose a parser or use the fallback' : 'Detection not run'}
              </strong>
              <div className="text-muted" style={{ fontSize: '13px', marginTop: '4px' }}>
                {verdict
                  ? 'Review the extracted evidence in the Byte Inspector, then select the parser to apply. Parser selection is manual on this path — nothing is auto-attributed.'
                  : 'Run Detection & Confidence first to determine attribution.'}
              </div>
              {verdict && (
                <div style={{ display: 'flex', gap: '8px', alignItems: 'center', marginTop: '12px', flexWrap: 'wrap' }}>
                  <select
                    className="form-select"
                    style={{ width: '260px', padding: '7px 10px', fontSize: '13px' }}
                    value={selectedParser}
                    onChange={(e) => setSelectedParser(e.target.value)}
                  >
                    <option value="">Select a parser…</option>
                    {MANUAL_PARSERS.map((p) => (
                      <option key={p.key} value={p.key}>{p.label}</option>
                    ))}
                  </select>
                  <button
                    className="btn btn-primary"
                    disabled={!selectedParser || loading}
                    onClick={() => selectedParser && runParseWith(selectedParser)}
                  >
                    {loading ? <RefreshCw size={14} className="spin" /> : <Play size={14} />}
                    <span>{loading ? 'Parsing…' : 'Apply Parser'}</span>
                  </button>
                  <button className="btn btn-secondary" onClick={() => onNavigateToHex(0)}>
                    Open Byte Inspector
                  </button>
                </div>
              )}
            </div>
          </div>
        </div>
      )}

      <div className="grid-4 mb-4">
        <div className="stat-card">
          <div className="stat-label">Active OEM Profile</div>
          <div className="stat-value" style={{ fontSize: '16px' }}>{detectedOem || 'Not parsed'}</div>
          <div className="stat-sub mt-4">
            <span className={attributionStatus === 'Confirmed' || attributionStatus === 'CompatibleCandidate' ? 'badge badge-pass' : 'badge badge-unknown'}>
              {storageFamily || 'Unknown FS'}
            </span>
          </div>
        </div>
        <div className="stat-card">
          <div className="stat-label">Recordings</div>
          <div className="stat-value">{recordings.length}</div>
          <div className="stat-sub">{recordings.length > 0 ? 'Across active channels' : 'None extracted'}</div>
        </div>
        <div className="stat-card">
          <div className="stat-label">Deleted Candidates</div>
          <div className="stat-value" style={{ color: deletedCandidates.length > 0 ? 'var(--warning)' : 'var(--text-muted)' }}>
            {deletedCandidates.length}
          </div>
          <div className="stat-sub">{deletedCandidates.length > 0 ? 'Recoverable fragments' : 'None detected'}</div>
        </div>
        <div className="stat-card">
          <div className="stat-label">Evidence Capacity</div>
          <div className="stat-value" style={{ fontSize: '16px' }}>
            {capacityMb} MB
          </div>
          <div className="stat-sub">Format: {evidence.image_format}</div>
        </div>
      </div>

      {activePlayback && (
        <div style={{ marginBottom: '20px' }}>
          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '8px' }}>
            <h3 style={{ margin: 0, fontSize: '14px', display: 'flex', alignItems: 'center', gap: '6px' }}>
              <Video size={16} style={{ color: 'var(--accent)' }} />
              Forensic Video Player — Recording {activePlayback.recordingId}
            </h3>
            <button className="btn btn-secondary btn-sm" onClick={() => setActivePlayback(null)}>
              Close Player
            </button>
          </div>
          <VideoPlayer {...activePlayback} onClose={() => setActivePlayback(null)} />
        </div>
      )}

      {recordings.length === 0 && !loading && (
        <div className="panel mb-4" style={{ backgroundColor: 'var(--surface)', borderLeft: '4px solid var(--accent)' }}>
          <div style={{ display: 'flex', gap: '12px', alignItems: 'flex-start' }}>
            <AlertCircle size={20} style={{ color: 'var(--accent)', flexShrink: 0, marginTop: '2px' }} />
            <div>
              <strong>No Proprietary DVR File Structure Detected</strong>
              <div className="text-muted" style={{ fontSize: '13px', marginTop: '4px' }}>
                This image currently does not match known Dahua (DHFS), Hikvision (HIKVISION_FS), Uniview (UBIFS), or CP Plus magic signatures at sector 0.
                You can run a full signature scan on the <strong>Detection</strong> page or inspect raw sectors in the <strong>Byte Inspector</strong>.
              </div>
            </div>
          </div>
        </div>
      )}

      <div style={{ display: 'grid', gridTemplateColumns: '1fr 320px', gap: '20px' }}>
        {/* Main Content Area */}
        <div style={{ display: 'flex', flexDirection: 'column', gap: '20px' }}>
          
          <div className="panel" style={{ padding: '0', overflow: 'hidden' }}>
            <div className="panel-header" style={{ margin: 0, padding: '16px' }}>
              <h3 style={{ margin: 0, fontSize: '14px' }}>Parsed Recordings ({recordings.length})</h3>
            </div>
            {recordings.length > 0 ? (
              <div className="table-container" style={{ border: 'none', borderTop: '1px solid var(--border)', borderRadius: '0' }}>
                <table className="data-table">
                  <thead>
                    <tr>
                      <th>ID / CH</th>
                      <th>Start Time</th>
                      <th>End Time</th>
                      <th>Location</th>
                      <th>Actions</th>
                    </tr>
                  </thead>
                  <tbody>
                    {recordings.map(rec => (
                      <tr key={rec.id}>
                        <td>
                          <div style={{ fontWeight: 600 }}>{rec.id}</div>
                          <div className="text-muted" style={{ fontSize: '11px' }}>CH {rec.channel_id} | {rec.codec} ({rec.frame_count} frames)</div>
                        </td>
                        <td>
                          <div><strong style={{ fontSize: '11px', color: 'var(--text-secondary)' }}>Native:</strong> <span className="mono">{rec.start_time.recorder_native}</span></div>
                          <div style={{ marginTop: '2px' }}>
                            {rec.start_time.timezone_state === 'unknown' ? (
                              <span style={{ color: 'var(--warning)', fontSize: '11.5px', fontWeight: 600 }}>⚠ Timezone Unknown</span>
                            ) : (
                              <span><strong style={{ fontSize: '11px', color: 'var(--text-secondary)' }}>UTC:</strong> <span className="mono">{rec.start_time.normalized_utc}</span></span>
                            )}
                          </div>
                          <div className="text-muted mt-4" style={{ fontSize: '10.5px' }}>Raw: {rec.start_time.raw_value}</div>
                        </td>
                        <td>
                          <div><strong style={{ fontSize: '11px', color: 'var(--text-secondary)' }}>Native:</strong> <span className="mono">{rec.end_time.recorder_native}</span></div>
                          <div style={{ marginTop: '2px' }}>
                            {rec.end_time.timezone_state === 'unknown' ? (
                              <span style={{ color: 'var(--warning)', fontSize: '11.5px', fontWeight: 600 }}>⚠ Timezone Unknown</span>
                            ) : (
                              <span><strong style={{ fontSize: '11px', color: 'var(--text-secondary)' }}>UTC:</strong> <span className="mono">{rec.end_time.normalized_utc}</span></span>
                            )}
                          </div>
                          <div className="text-muted mt-4" style={{ fontSize: '10.5px' }}>Raw: {rec.end_time.raw_value}</div>
                        </td>
                        <td>
                          <div className="mono">0x{rec.offset_start.toString(16).toUpperCase()}</div>
                        </td>
                        <td>
                          <div style={{ display: 'flex', gap: '6px' }}>
                            <button
                              className="btn btn-primary btn-sm"
                              onClick={() => handlePlayRecording(rec)}
                              disabled={reconstructing === rec.id}
                            >
                              {reconstructing === rec.id ? <RefreshCw size={12} className="spin" /> : <Play size={12} />}
                              <span>{reconstructing === rec.id ? 'Remuxing...' : 'Play'}</span>
                            </button>
                            <button className="btn btn-secondary btn-sm" onClick={() => onNavigateToHex(rec.offset_start)}>
                              Hex
                            </button>
                          </div>
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            ) : (
              <div style={{ padding: '24px', textAlign: 'center', color: 'var(--text-muted)', fontSize: '13px' }}>
                No active recordings parsed for this evidence image.
              </div>
            )}
          </div>

          <div className="panel" style={{ padding: '0', overflow: 'hidden' }}>
            <div className="panel-header" style={{ margin: 0, padding: '16px' }}>
              <h3 style={{ margin: 0, fontSize: '14px' }}>Deleted Candidates & Fragments ({deletedCandidates.length})</h3>
            </div>
            {deletedCandidates.length > 0 ? (
              <div className="table-container" style={{ border: 'none', borderTop: '1px solid var(--border)', borderRadius: '0' }}>
                <table className="data-table">
                  <thead>
                    <tr>
                      <th>Offset</th>
                      <th>Reason</th>
                      <th>Validation</th>
                      <th>Action</th>
                    </tr>
                  </thead>
                  <tbody>
                    {deletedCandidates.map(del => (
                      <tr key={del.id}>
                        <td className="mono">0x{del.offset_start.toString(16).toUpperCase()}</td>
                        <td>{del.reason}</td>
                        <td>
                          <span className={getValidationBadge(del.validation.state)}>
                            {del.validation.state}
                          </span>
                        </td>
                        <td>
                          <button className="btn btn-secondary btn-sm" onClick={() => onNavigateToHex(del.offset_start)}>
                            Inspect Hex
                          </button>
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            ) : (
              <div style={{ padding: '24px', textAlign: 'center', color: 'var(--text-muted)', fontSize: '13px' }}>
                No deleted or unindexed stream fragments identified.
              </div>
            )}
          </div>

        </div>

        {/* Sidebar Panel */}
        <div style={{ display: 'flex', flexDirection: 'column', gap: '20px' }}>
          <div className="panel" style={{ padding: '0', overflow: 'hidden' }}>
             <div className="panel-header" style={{ margin: 0, padding: '16px', borderBottom: '1px solid var(--border-subtle)' }}>
                <h3 style={{ margin: 0, fontSize: '14px' }}>Parser Status</h3>
             </div>
             <div style={{ padding: '16px', display: 'flex', flexDirection: 'column', gap: '16px' }}>
                {parserRuns.map(run => (
                  <div key={run.id} style={{ display: 'flex', flexDirection: 'column', gap: '4px' }}>
                    <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                      <span style={{ fontSize: '12.5px', fontWeight: 600 }}>{run.operation_name}</span>
                      <span className={getValidationBadge(run.validation.state)}>
                        {run.validation.state}
                      </span>
                    </div>
                    <div className="text-muted" style={{ fontSize: '11.5px' }}>{run.validation.reason}</div>
                  </div>
                ))}
             </div>
          </div>
        </div>

      </div>
    </div>
  );
};
