import React, { useState, useEffect } from 'react';
import {
  FileSpreadsheet, HardDrive, Download, RefreshCw, ShieldCheck,
  Search, Film, Clock, Wrench, ListTree, FileText, AlertTriangle,
} from 'lucide-react';
import { Evidence } from '../types';
import { fetchReport } from '../services/api';
import { ContextHelp } from '../components/onboarding/ContextHelp';

interface ReportsViewProps {
  evidence: Evidence | null;
  evidenceList?: Evidence[];
  onSelectEvidence?: (e: Evidence) => void;
}

type ReportFormat = 'json' | 'markdown' | 'csv';

// ── Deep report section shapes (mirror crates/reporting/src/model.rs) ────────

interface RegionReport { offset: number; length: number }

interface MatchedIndicatorReport {
  kind: string;
  offset: number;
  length: number;
  matched: boolean;
  evidence_status: string;
  exclusive: boolean;
  weight: number;
  explanation: string;
}

interface DetectionDepthReport {
  image_size_bytes: number;
  method: string;
  storage_family: string;
  detector_status: string;
  confidence: number;
  margin: number;
  evidence_quality: number;
  runner_up: string | null;
  matched_indicators: MatchedIndicatorReport[];
  candidate_regions: RegionReport[];
  bytes_examined: number;
  highest_offset_examined: number;
}

interface ParsedFrameReport {
  channel: number;
  recorder_native_time: string;
  normalized_time: string;
  source_offset: number;
  source_length: number;
  region_count: number;
  codec: string;
  nal_unit_count: number;
  confirmed: boolean;
  confirmation: string;
  integrity_flags: string[];
}

interface ValidationRow { operation: string; subject: string; state: string; reason: string }

interface ParsingDepthReport {
  parser_id: string;
  stages: ValidationRow[];
  total_recordings: number;
  frames: ParsedFrameReport[];
}

interface SessionGapReport {
  starts_after: string;
  ends_before: string;
  missing_seconds: number;
  previous_offset: number;
  next_offset: number;
}

interface SessionReport {
  channel: number;
  start: string;
  end: string;
  timezone: string;
  span_seconds: number;
  covered_seconds: number;
  missing_seconds: number;
  coverage_ratio: number;
  segment_count: number;
  gaps: SessionGapReport[];
}

interface PreliminaryTimelineReport {
  channel_count: number;
  total_segments: number;
  total_recordings: number;
  total_missing_seconds: number;
  coverage_ratio: number;
  accounted_bytes: number;
  unaccounted_bytes: number;
  total_bytes: number;
  sessions: SessionReport[];
}

interface GapRecoveryReport {
  channel: number;
  scan_start: number;
  scan_end: number;
  attempts: number;
  total_seconds: number;
  recovered_seconds: number;
  unrecovered_seconds: number;
  decision: string;
}

interface RecoveryDepthReport {
  algorithm: string;
  searched_bytes: number;
  total_bytes: number;
  gaps_processed: number;
  total_recovered_seconds: number;
  total_unrecovered_seconds: number;
  per_gap: GapRecoveryReport[];
}

interface FinalTimelineReport {
  total_events: number;
  recorded_events: number;
  recovered_events: number;
}

/** Shape of the JSON report we render for preview (subset of ForensicReport). */
interface ReportJson {
  report_id: string;
  generated_at: string;
  examiner_id: string;
  case_id?: string;
  evidence_id?: string;
  evidence_summary: {
    source_path: string;
    image_format: string;
    size_bytes: number;
    sha256: { value: string };
    acquisition_status: string;
    source_safety_decision: string;
  };
  detection_summary: {
    detection_status: string;
    classification: string;
    attribution_status: string;
    primary_oem: string | null;
    confidence_score: number;
  };
  validation_summary: ValidationRow[];
  recordings: unknown[];
  recovery_items: unknown[];
  timeline_events: unknown[];
  limitations: string[];
  // Deep, stage-by-stage sections (optional — a run that halts early omits them).
  detection_depth?: DetectionDepthReport | null;
  parsing_depth?: ParsingDepthReport | null;
  preliminary_timeline?: PreliminaryTimelineReport | null;
  recovery_depth?: RecoveryDepthReport | null;
  final_timeline_summary?: FinalTimelineReport | null;
}

// ── Formatting helpers ───────────────────────────────────────────────────────

const hex = (n: number): string => `0x${Math.max(0, Math.trunc(n)).toString(16).toUpperCase()}`;
const mb = (bytes: number): string => `${(bytes / (1024 * 1024)).toFixed(2)} MB`;
const kb = (bytes: number): string => `${(bytes / 1024).toFixed(1)} KB`;
const bytesh = (bytes: number): string => (bytes >= 1024 * 1024 ? mb(bytes) : bytes >= 1024 ? kb(bytes) : `${bytes} B`);
const dur = (sec: number): string => {
  const s = Math.max(0, Math.trunc(sec));
  if (s < 60) return `${s}s`;
  if (s < 3600) return `${Math.floor(s / 60)}m ${s % 60}s`;
  return `${Math.floor(s / 3600)}h ${Math.floor((s % 3600) / 60)}m`;
};
const pct = (r: number): string => `${(r * 100).toFixed(1)}%`;

const accent = 'var(--accent)';

const SectionHeader: React.FC<{ icon: React.ReactNode; index: number; title: string; sub?: string }> = ({ icon, index, title, sub }) => (
  <div style={{ display: 'flex', alignItems: 'flex-start', gap: '10px', margin: '0 0 12px 0' }}>
    <div style={{ color: accent, marginTop: '1px' }}>{icon}</div>
    <div>
      <h4 style={{ color: accent, margin: 0, fontSize: '14px' }}>{index}. {title}</h4>
      {sub && <div className="text-muted" style={{ fontSize: '12px', marginTop: '2px' }}>{sub}</div>}
    </div>
  </div>
);

const KV: React.FC<{ k: string; children: React.ReactNode; mono?: boolean }> = ({ k, children, mono }) => (
  <div style={{ fontSize: '13px' }}>
    <strong>{k}:</strong> <span className={mono ? 'mono' : undefined} style={mono ? { fontSize: '12px', wordBreak: 'break-all' } : undefined}>{children}</span>
  </div>
);

const sectionStyle: React.CSSProperties = {
  marginTop: '24px',
  paddingTop: '20px',
  borderTop: '1px solid var(--border)',
};

export const ReportsView: React.FC<ReportsViewProps> = ({ evidence, evidenceList = [], onSelectEvidence }) => {
  const [report, setReport] = useState<ReportJson | null>(null);
  const [reportId, setReportId] = useState<string | null>(null);
  const [reportHash, setReportHash] = useState<string | null>(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    setReport(null);
    setError(null);
    if (evidence) loadReport();
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [evidence?.id]);

  const loadReport = async () => {
    if (!evidence) return;
    setLoading(true);
    setError(null);
    try {
      const { body, reportId, sha256 } = await fetchReport(evidence.id, 'json');
      setReport(JSON.parse(body));
      setReportId(reportId);
      setReportHash(sha256);
    } catch (e: any) {
      setError(e?.message || 'Failed to generate report');
      setReport(null);
    } finally {
      setLoading(false);
    }
  };

  const download = async (format: ReportFormat) => {
    if (!evidence) return;
    try {
      const { body, contentType } = await fetchReport(evidence.id, format);
      const ext = format === 'markdown' ? 'md' : format;
      const blob = new Blob([body], { type: contentType });
      const url = URL.createObjectURL(blob);
      const a = document.createElement('a');
      a.href = url;
      a.download = `forensic-report-${evidence.source_device.replace(/\s+/g, '_')}.${ext}`;
      a.click();
      URL.revokeObjectURL(url);
    } catch (e: any) {
      setError(e?.message || `Failed to export ${format}`);
    }
  };

  if (!evidence) {
    return (
      <div className="view-container" data-tour="reports-view-panel">
        <div className="view-header">
          <div>
            <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
              <h1 className="view-title">Forensic Documentation & Reporting</h1>
              <ContextHelp
                title="Forensic Reporting"
                content="Generates a stage-by-stage forensic report from the actual pipeline run — case, selected evidence, detection (with offsets), parsing (with frame confirmation), preliminary timeline, recovery, and the final timeline — with a self-verifying SHA-256."
              />
            </div>
            <p className="view-subtitle">Select an evidence target to generate a forensic examination report.</p>
          </div>
        </div>
        <div className="empty-state">
          <FileSpreadsheet size={32} />
          <h3>No Evidence Selected</h3>
          <p>Select a DVR/NVR evidence item from the active case to begin.</p>
        </div>
      </div>
    );
  }

  const capacityMb = (evidence.capacity / (1024 * 1024)).toFixed(2);

  return (
    <div className="view-container" data-tour="reports-view-panel">
      <div className="view-header">
        <div>
          <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
            <h1 className="view-title">Forensic Documentation & Reporting</h1>
            <ContextHelp
              title="Forensic Reporting"
              content="This report is assembled from the real pipeline run and walks each stage in order: case → selected evidence → detection → parsing → preliminary timeline → recovery → final timeline. The SHA-256 is computed over the exported bytes so the document is self-verifying."
            />
          </div>
          <p className="view-subtitle">Stage-by-stage narrative assembled from the live pipeline run, with offsets, cryptographic provenance, and stated limitations</p>
        </div>
        <div style={{ display: 'flex', gap: '8px' }}>
          <button className="btn btn-secondary" onClick={loadReport} disabled={loading}>
            {loading ? <RefreshCw size={14} className="spin" /> : <RefreshCw size={14} />}
            <span>Regenerate</span>
          </button>
          <button className="btn btn-secondary" onClick={() => download('json')} disabled={!report}>
            <Download size={14} /> JSON
          </button>
          <button className="btn btn-secondary" onClick={() => download('csv')} disabled={!report}>
            <Download size={14} /> CSV
          </button>
          <button className="btn btn-primary" onClick={() => download('markdown')} disabled={!report}>
            <Download size={14} /> Markdown
          </button>
        </div>
      </div>

      {/* Target evidence bar */}
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
                <span style={{ fontSize: '12px', color: 'var(--text-muted)' }}>({capacityMb} MB)</span>
              </div>
            </div>
          </div>
          {evidenceList.length > 1 && (
            <select
              className="form-select"
              style={{ width: '240px', padding: '6px 10px', fontSize: '12px' }}
              value={evidence.id}
              onChange={(e) => {
                const found = evidenceList.find((it) => it.id === e.target.value);
                if (found && onSelectEvidence) onSelectEvidence(found);
              }}
            >
              {evidenceList.map((it) => (
                <option key={it.id} value={it.id}>
                  {it.source_device} ({(it.capacity / (1024 * 1024)).toFixed(0)}MB)
                </option>
              ))}
            </select>
          )}
        </div>
      </div>

      {error && (
        <div className="panel mb-4" style={{ borderLeft: '4px solid var(--danger)' }}>
          <strong>Report generation failed</strong>
          <div className="text-muted" style={{ fontSize: '13px', marginTop: '4px' }}>{error}</div>
        </div>
      )}

      {loading && !report && (
        <div className="empty-state"><RefreshCw size={28} className="spin" /><h3>Generating report…</h3></div>
      )}

      {report && (
        <>
          <div className="panel" style={{ padding: '16px', marginBottom: '16px' }}>
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', flexWrap: 'wrap', gap: '12px' }}>
              <div>
                <div style={{ fontSize: '15px', fontWeight: 700 }}>Report ID: {reportId || report.report_id}</div>
                <div className="mono text-muted" style={{ fontSize: '12px', marginTop: '4px', wordBreak: 'break-all' }}>
                  SHA-256: {reportHash || '—'}
                </div>
              </div>
              <span className="badge badge-pass" style={{ display: 'inline-flex', alignItems: 'center', gap: '4px' }}>
                <ShieldCheck size={14} /> Self-verifying export
              </span>
            </div>
          </div>

          <div className="panel" style={{ padding: '28px', backgroundColor: '#ffffff' }}>
            <div style={{ borderBottom: '2px solid var(--border)', paddingBottom: '14px', marginBottom: '20px' }}>
              <h2 style={{ margin: '0 0 6px 0', fontSize: '19px' }}>DIGITAL FORENSIC EXAMINATION REPORT</h2>
              <div style={{ fontSize: '13px', color: 'var(--text-secondary)' }}>
                Generated {new Date(report.generated_at).toLocaleString()} · Examiner {report.examiner_id}
              </div>
            </div>

            {/* 1 + 2: Case / Evidence side by side */}
            <div className="grid-2 mb-4">
              <div>
                <SectionHeader icon={<FileText size={16} />} index={1} title="Case & Examiner" />
                <div style={{ display: 'flex', flexDirection: 'column', gap: '6px' }}>
                  <KV k="Report ID">{report.report_id}</KV>
                  <KV k="Examiner">{report.examiner_id}</KV>
                  {report.case_id && <KV k="Case ID" mono>{report.case_id}</KV>}
                  {report.evidence_id && <KV k="Evidence ID" mono>{report.evidence_id}</KV>}
                  <KV k="Generated">{new Date(report.generated_at).toLocaleString()}</KV>
                </div>
              </div>
              <div>
                <SectionHeader icon={<HardDrive size={16} />} index={2} title="Selected Evidence & Integrity" />
                <div style={{ display: 'flex', flexDirection: 'column', gap: '6px' }}>
                  <KV k="Source">{report.evidence_summary.source_path}</KV>
                  <KV k="Format">{report.evidence_summary.image_format}</KV>
                  <KV k="Size">{mb(report.evidence_summary.size_bytes)}</KV>
                  <KV k="Acquisition">{report.evidence_summary.acquisition_status}</KV>
                  <KV k="Source safety">{report.evidence_summary.source_safety_decision}</KV>
                  <KV k="SHA-256" mono>{report.evidence_summary.sha256.value}</KV>
                </div>
              </div>
            </div>

            {/* 3: Detection — where the format was found */}
            <div style={sectionStyle}>
              <SectionHeader
                icon={<Search size={16} />}
                index={3}
                title="Detection — Where the Format Was Found"
                sub="Which storage format/OEM was identified, on what offsets the signatures sat, and how much of the image was structurally examined to decide."
              />
              <DetectionSection report={report} />
            </div>

            {/* 4: Parsing — where frames were found and confirmed */}
            <div style={sectionStyle}>
              <SectionHeader
                icon={<Film size={16} />}
                index={4}
                title="Parsing — Where Frames Were Found and How They Were Confirmed"
                sub="Each located recording, the byte offset its stream sits at, the codec classified from the actual bytes, and the NAL evidence that confirmed a decodable frame."
              />
              <ParsingSection report={report} />
            </div>

            {/* 5: Preliminary timeline — coverage and gaps */}
            <div style={sectionStyle}>
              <SectionHeader
                icon={<Clock size={16} />}
                index={5}
                title="Preliminary Timeline — Coverage and Gaps"
                sub="What footage exists per camera before recovery, and exactly where the missing windows are (with the byte region behind each gap)."
              />
              <PreliminaryTimelineSection report={report} />
            </div>

            {/* 6: Recovery engine */}
            <div style={sectionStyle}>
              <SectionHeader
                icon={<Wrench size={16} />}
                index={6}
                title="Recovery Engine — Staged Carving of Missing Footage"
                sub="The staged carving algorithm run over each gap's byte region, how many probes were attempted, and how much footage was recovered versus permanently lost."
              />
              <RecoverySection report={report} />
            </div>

            {/* 7: Final timeline */}
            <div style={sectionStyle}>
              <SectionHeader
                icon={<ListTree size={16} />}
                index={7}
                title="Final Timeline"
                sub="The consolidated timeline after folding recovered footage back into the recorded events."
              />
              <FinalTimelineSection report={report} />
            </div>

            {/* 8: Validation gate decisions */}
            <div style={sectionStyle}>
              <SectionHeader
                icon={<ShieldCheck size={16} />}
                index={8}
                title={`Validation Operations & Gate Decisions (${report.validation_summary.length})`}
              />
              <div className="table-container">
                <table className="data-table">
                  <thead>
                    <tr><th>Operation</th><th>Subject</th><th>Outcome</th><th>Reason</th></tr>
                  </thead>
                  <tbody>
                    {report.validation_summary.map((v, i) => (
                      <tr key={i}>
                        <td className="mono" style={{ fontSize: '12px' }}>{v.operation}</td>
                        <td>{v.subject}</td>
                        <td><StateBadge state={v.state} /></td>
                        <td className="text-muted" style={{ fontSize: '12px' }}>{v.reason}</td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            </div>

            {/* 9: Limitations */}
            <div style={{ backgroundColor: 'var(--surface-muted)', borderRadius: '6px', padding: '16px', borderLeft: '4px solid var(--warning)', marginTop: '24px' }}>
              <div style={{ display: 'flex', alignItems: 'center', gap: '8px', marginBottom: '8px' }}>
                <AlertTriangle size={15} style={{ color: 'var(--warning)' }} />
                <h4 style={{ margin: 0, color: 'var(--warning)', fontSize: '14px' }}>9. Stated Forensic Limitations</h4>
              </div>
              <ol style={{ margin: '0 0 0 16px', padding: 0, fontSize: '12.5px', color: 'var(--text-secondary)', lineHeight: '1.6' }}>
                {report.limitations.map((l, i) => <li key={i}>{l}</li>)}
              </ol>
            </div>
          </div>
        </>
      )}
    </div>
  );
};

// ── Small shared UI bits ─────────────────────────────────────────────────────

const StateBadge: React.FC<{ state: string }> = ({ state }) => {
  const cls =
    state === 'Pass' ? 'badge badge-pass'
    : state === 'Review' ? 'badge badge-review'
    : state === 'DECISION' ? 'badge badge-info'
    : state === 'Fail' ? 'badge badge-fail'
    : 'badge badge-unknown';
  return <span className={cls}>{state}</span>;
};

const EmptyNote: React.FC<{ children: React.ReactNode }> = ({ children }) => (
  <div className="text-muted" style={{ fontSize: '13px', fontStyle: 'italic' }}>{children}</div>
);

const StatChips: React.FC<{ items: { label: string; value: React.ReactNode }[] }> = ({ items }) => (
  <div style={{ display: 'flex', flexWrap: 'wrap', gap: '10px', marginBottom: '14px' }}>
    {items.map((it, i) => (
      <div key={i} style={{ background: 'var(--surface-muted)', border: '1px solid var(--border)', borderRadius: '6px', padding: '8px 12px', minWidth: '120px' }}>
        <div style={{ fontSize: '10.5px', textTransform: 'uppercase', letterSpacing: '0.3px', color: 'var(--text-muted)', fontWeight: 600 }}>{it.label}</div>
        <div style={{ fontSize: '14px', fontWeight: 700, marginTop: '2px' }}>{it.value}</div>
      </div>
    ))}
  </div>
);

// ── Section 3: Detection ─────────────────────────────────────────────────────

const DetectionSection: React.FC<{ report: ReportJson }> = ({ report }) => {
  const d = report.detection_summary;
  const dd = report.detection_depth;

  return (
    <>
      <StatChips items={[
        { label: 'Detection', value: d.detection_status },
        { label: 'Primary OEM', value: d.primary_oem || '—' },
        { label: 'Attribution', value: d.attribution_status },
        { label: 'Confidence', value: pct(d.confidence_score) },
        ...(dd ? [{ label: 'Storage family', value: dd.storage_family }] : []),
      ]} />

      {!dd ? (
        <EmptyNote>No detailed detection trace was captured for this run.</EmptyNote>
      ) : (
        <>
          <div style={{ display: 'flex', flexDirection: 'column', gap: '6px', marginBottom: '14px' }}>
            <KV k="Margin over runner-up">
              {dd.margin.toFixed(3)}{dd.runner_up ? ` (vs ${dd.runner_up})` : ''}
            </KV>
            <KV k="Evidence quality">{dd.evidence_quality.toFixed(2)}</KV>
            <KV k="Search reach">
              probed up to offset <span className="mono">{hex(dd.highest_offset_examined)}</span> within a {mb(dd.image_size_bytes)} image;
              {' '}<strong>{bytesh(dd.bytes_examined)}</strong> structurally examined
            </KV>
            <KV k="Method">{dd.method}</KV>
          </div>

          {dd.matched_indicators.length > 0 && (
            <>
              <div style={{ fontSize: '12.5px', fontWeight: 600, margin: '8px 0 6px' }}>Signature indicators (where each was found)</div>
              <div className="table-container">
                <table className="data-table">
                  <thead>
                    <tr><th>Indicator</th><th>Offset</th><th>Len</th><th>Matched</th><th>Status</th><th>Weight</th><th>Exclusive</th></tr>
                  </thead>
                  <tbody>
                    {dd.matched_indicators.map((m, i) => (
                      <tr key={i}>
                        <td title={m.explanation}>{m.kind}</td>
                        <td className="mono" style={{ fontSize: '12px' }}>{hex(m.offset)}</td>
                        <td>{m.length}</td>
                        <td>{m.matched ? <span className="badge badge-pass">yes</span> : <span className="badge badge-unknown">no</span>}</td>
                        <td>{m.evidence_status}</td>
                        <td>{m.weight.toFixed(2)}</td>
                        <td>{m.exclusive ? 'yes' : 'no'}</td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            </>
          )}

          {dd.candidate_regions.length > 0 && (
            <div style={{ fontSize: '12.5px', marginTop: '12px' }}>
              <strong>Candidate storage regions considered:</strong>{' '}
              {dd.candidate_regions.map((r, i) => (
                <span key={i} className="mono" style={{ fontSize: '12px' }}>
                  {hex(r.offset)}..{hex(r.offset + r.length)}{i < dd.candidate_regions.length - 1 ? ', ' : ''}
                </span>
              ))}
            </div>
          )}
        </>
      )}
    </>
  );
};

// ── Section 4: Parsing ───────────────────────────────────────────────────────

const ParsingSection: React.FC<{ report: ReportJson }> = ({ report }) => {
  const pd = report.parsing_depth;
  if (!pd) return <EmptyNote>No parsing stage output was captured for this run.</EmptyNote>;

  return (
    <>
      <StatChips items={[
        { label: 'Parser', value: pd.parser_id },
        { label: 'Recordings located', value: pd.total_recordings },
        { label: 'Frames confirmed', value: pd.frames.filter((f) => f.confirmed).length },
      ]} />

      {pd.stages.length > 0 && (
        <>
          <div style={{ fontSize: '12.5px', fontWeight: 600, margin: '8px 0 6px' }}>Parser stages</div>
          <div className="table-container">
            <table className="data-table">
              <thead>
                <tr><th>Stage</th><th>Subject</th><th>Outcome</th><th>Reason</th></tr>
              </thead>
              <tbody>
                {pd.stages.map((s, i) => (
                  <tr key={i}>
                    <td className="mono" style={{ fontSize: '12px' }}>{s.operation}</td>
                    <td>{s.subject}</td>
                    <td><StateBadge state={s.state} /></td>
                    <td className="text-muted" style={{ fontSize: '12px' }}>{s.reason}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </>
      )}

      {pd.frames.length > 0 && (
        <>
          <div style={{ fontSize: '12.5px', fontWeight: 600, margin: '14px 0 6px' }}>Located recordings (offset + confirmation)</div>
          <div className="table-container">
            <table className="data-table">
              <thead>
                <tr><th>Ch</th><th>Native Time</th><th>Offset</th><th>Length</th><th>Codec</th><th>NAL Units</th><th>Confirmed</th><th>Integrity</th></tr>
              </thead>
              <tbody>
                {pd.frames.map((f, i) => (
                  <tr key={i}>
                    <td>{f.channel}</td>
                    <td style={{ fontSize: '12px' }}>{f.recorder_native_time}</td>
                    <td className="mono" style={{ fontSize: '12px' }}>{hex(f.source_offset)}</td>
                    <td>{bytesh(f.source_length)}</td>
                    <td>{f.codec}</td>
                    <td title={f.confirmation}>{f.nal_unit_count}</td>
                    <td>{f.confirmed ? <span className="badge badge-pass">yes</span> : <span className="badge badge-review">review</span>}</td>
                    <td style={{ fontSize: '12px' }}>
                      {f.integrity_flags.length === 0
                        ? <span className="text-muted">clean</span>
                        : f.integrity_flags.join(', ')}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </>
      )}
    </>
  );
};

// ── Section 5: Preliminary timeline ──────────────────────────────────────────

const PreliminaryTimelineSection: React.FC<{ report: ReportJson }> = ({ report }) => {
  const pt = report.preliminary_timeline;
  if (!pt) return <EmptyNote>No preliminary timeline was produced for this run.</EmptyNote>;

  return (
    <>
      <StatChips items={[
        { label: 'Channels', value: pt.channel_count },
        { label: 'Recordings', value: pt.total_recordings },
        { label: 'Segments', value: pt.total_segments },
        { label: 'Footage missing', value: dur(pt.total_missing_seconds) },
        { label: 'Image attributed', value: pct(pt.coverage_ratio) },
      ]} />

      <div style={{ fontSize: '12.5px', marginBottom: '12px' }} className="text-muted">
        {bytesh(pt.accounted_bytes)} of {bytesh(pt.total_bytes)} attributed to recordings; {bytesh(pt.unaccounted_bytes)} unallocated / slack.
      </div>

      {pt.sessions.length === 0 ? (
        <EmptyNote>No recording sessions were reconstructed.</EmptyNote>
      ) : (
        pt.sessions.map((s, i) => (
          <div key={i} style={{ border: '1px solid var(--border)', borderRadius: '6px', padding: '12px 14px', marginBottom: '10px' }}>
            <div style={{ display: 'flex', justifyContent: 'space-between', flexWrap: 'wrap', gap: '8px', alignItems: 'center' }}>
              <div style={{ fontSize: '13px', fontWeight: 700 }}>
                Channel {s.channel}
                <span className="text-muted" style={{ fontWeight: 400, marginLeft: '8px', fontSize: '12px' }}>
                  {s.start} → {s.end} ({s.timezone})
                </span>
              </div>
              <div style={{ fontSize: '12px' }}>
                <span className="badge badge-pass">{pct(s.coverage_ratio)} covered</span>{' '}
                <span className="text-muted">{dur(s.covered_seconds)} recorded · {dur(s.missing_seconds)} missing · {s.segment_count} seg</span>
              </div>
            </div>

            {/* coverage bar */}
            <div style={{ height: '8px', borderRadius: '4px', overflow: 'hidden', background: 'var(--danger)', marginTop: '10px', display: 'flex' }}>
              <div style={{ width: pct(s.coverage_ratio), background: 'var(--success, #2ecc71)' }} />
            </div>

            {s.gaps.length > 0 && (
              <div style={{ marginTop: '10px' }}>
                <div style={{ fontSize: '11.5px', fontWeight: 600, color: 'var(--danger)', marginBottom: '4px' }}>
                  {s.gaps.length} missing window(s):
                </div>
                <ul style={{ margin: 0, paddingLeft: '18px', fontSize: '12px', lineHeight: 1.6 }}>
                  {s.gaps.map((g, gi) => (
                    <li key={gi}>
                      {g.starts_after} → {g.ends_before}: <strong>{dur(g.missing_seconds)}</strong> missing,
                      {' '}bytes <span className="mono" style={{ fontSize: '11.5px' }}>{hex(g.previous_offset)}..{hex(g.next_offset)}</span>
                    </li>
                  ))}
                </ul>
              </div>
            )}
          </div>
        ))
      )}
    </>
  );
};

// ── Section 6: Recovery ──────────────────────────────────────────────────────

const RecoverySection: React.FC<{ report: ReportJson }> = ({ report }) => {
  const rd = report.recovery_depth;
  if (!rd) {
    return <EmptyNote>No recovery was required (no in-recording gaps), or no gap produced a recoverable region.</EmptyNote>;
  }

  return (
    <>
      <StatChips items={[
        { label: 'Gaps processed', value: rd.gaps_processed },
        { label: 'Bytes searched', value: `${bytesh(rd.searched_bytes)} / ${bytesh(rd.total_bytes)}` },
        { label: 'Recovered', value: dur(rd.total_recovered_seconds) },
        { label: 'Not recovered', value: dur(rd.total_unrecovered_seconds) },
      ]} />

      <div style={{ fontSize: '12.5px', marginBottom: '12px' }}>
        <strong>Algorithm:</strong> {rd.algorithm}
      </div>

      {rd.per_gap.length === 0 ? (
        <EmptyNote>No gaps were carved.</EmptyNote>
      ) : (
        <div className="table-container">
          <table className="data-table">
            <thead>
              <tr><th>Ch</th><th>Byte Region</th><th>Attempts</th><th>Recovered</th><th>Missing</th><th>Decision</th></tr>
            </thead>
            <tbody>
              {rd.per_gap.map((g, i) => (
                <tr key={i}>
                  <td>{g.channel}</td>
                  <td className="mono" style={{ fontSize: '12px' }}>{hex(g.scan_start)}..{hex(g.scan_end)}</td>
                  <td>{g.attempts}</td>
                  <td>{dur(g.recovered_seconds)}</td>
                  <td>{dur(g.unrecovered_seconds)}</td>
                  <td style={{ fontSize: '12px' }}>{g.decision}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </>
  );
};

// ── Section 7: Final timeline ────────────────────────────────────────────────

const FinalTimelineSection: React.FC<{ report: ReportJson }> = ({ report }) => {
  const ft = report.final_timeline_summary;
  if (!ft) return <EmptyNote>No final timeline was produced for this run.</EmptyNote>;
  return (
    <StatChips items={[
      { label: 'Total events', value: ft.total_events },
      { label: 'Recorded', value: ft.recorded_events },
      { label: 'Recovered folded in', value: ft.recovered_events },
    ]} />
  );
};
