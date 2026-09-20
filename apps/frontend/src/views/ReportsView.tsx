import React, { useState, useEffect } from 'react';
import { FileSpreadsheet, HardDrive, Download, RefreshCw, ShieldCheck } from 'lucide-react';
import { Evidence } from '../types';
import { fetchReport } from '../services/api';
import { ContextHelp } from '../components/onboarding/ContextHelp';

interface ReportsViewProps {
  evidence: Evidence | null;
  evidenceList?: Evidence[];
  onSelectEvidence?: (e: Evidence) => void;
}

type ReportFormat = 'json' | 'markdown' | 'csv';

/** Shape of the JSON report we render for preview (subset of ForensicReport). */
interface ReportJson {
  report_id: string;
  generated_at: string;
  examiner_id: string;
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
  validation_summary: { operation: string; subject: string; state: string; reason: string }[];
  recordings: unknown[];
  recovery_items: { candidate_id: string; recovery_level: string; data_state: string; recovery_status: string }[];
  timeline_events: unknown[];
  limitations: string[];
}

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
                content="Generates a forensic report from the actual pipeline run — evidence integrity, attribution, validation outcomes, recovery, timeline, and stated limitations — with a self-verifying SHA-256."
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
              content="This report is assembled from the real pipeline run. The SHA-256 is computed over the exported bytes so the document is self-verifying."
            />
          </div>
          <p className="view-subtitle">Assembled from the live pipeline run with cryptographic provenance and stated limitations</p>
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

            <div className="grid-2 mb-4">
              <div>
                <h4 style={{ color: 'var(--accent)', margin: '0 0 10px 0', fontSize: '14px' }}>1. Evidence & Integrity</h4>
                <div style={{ fontSize: '13px', display: 'flex', flexDirection: 'column', gap: '6px' }}>
                  <div><strong>Source:</strong> {report.evidence_summary.source_path}</div>
                  <div><strong>Format:</strong> {report.evidence_summary.image_format}</div>
                  <div><strong>Size:</strong> {(report.evidence_summary.size_bytes / (1024 * 1024)).toFixed(2)} MB</div>
                  <div><strong>Acquisition:</strong> {report.evidence_summary.acquisition_status}</div>
                  <div><strong>Source safety:</strong> {report.evidence_summary.source_safety_decision}</div>
                  <div className="mono" style={{ fontSize: '11px', wordBreak: 'break-all' }}>
                    <strong>SHA-256:</strong> {report.evidence_summary.sha256.value}
                  </div>
                </div>
              </div>
              <div>
                <h4 style={{ color: 'var(--accent)', margin: '0 0 10px 0', fontSize: '14px' }}>2. Storage Attribution</h4>
                <div style={{ fontSize: '13px', display: 'flex', flexDirection: 'column', gap: '6px' }}>
                  <div><strong>Detection:</strong> {report.detection_summary.detection_status}</div>
                  <div><strong>Classification:</strong> {report.detection_summary.classification}</div>
                  <div><strong>Attribution:</strong> {report.detection_summary.attribution_status}</div>
                  <div><strong>Primary OEM:</strong> {report.detection_summary.primary_oem || '—'}</div>
                  <div><strong>Confidence:</strong> {(report.detection_summary.confidence_score * 100).toFixed(1)}%</div>
                </div>
              </div>
            </div>

            <div style={{ marginTop: '24px' }}>
              <h4 style={{ color: 'var(--accent)', margin: '0 0 10px 0', fontSize: '14px' }}>
                3. Validation Operations & Gate Decisions ({report.validation_summary.length})
              </h4>
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
                        <td>
                          <span className={
                            v.state === 'Pass' ? 'badge badge-pass'
                            : v.state === 'Review' ? 'badge badge-review'
                            : v.state === 'DECISION' ? 'badge badge-info'
                            : 'badge badge-unknown'
                          }>{v.state}</span>
                        </td>
                        <td className="text-muted" style={{ fontSize: '12px' }}>{v.reason}</td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            </div>

            <div className="grid-2 mb-4" style={{ marginTop: '24px' }}>
              <div>
                <h4 style={{ color: 'var(--accent)', margin: '0 0 10px 0', fontSize: '14px' }}>4. Recordings</h4>
                <div style={{ fontSize: '13px' }}>{report.recordings.length} recording(s) extracted</div>
              </div>
              <div>
                <h4 style={{ color: 'var(--accent)', margin: '0 0 10px 0', fontSize: '14px' }}>5. Recovery Candidates</h4>
                {report.recovery_items.length === 0 ? (
                  <div className="text-muted" style={{ fontSize: '13px' }}>None</div>
                ) : (
                  <ul style={{ margin: 0, paddingLeft: '18px', fontSize: '12.5px' }}>
                    {report.recovery_items.map((r) => (
                      <li key={r.candidate_id}>{r.recovery_level} · {r.data_state}/{r.recovery_status}</li>
                    ))}
                  </ul>
                )}
              </div>
            </div>

            <div style={{ marginTop: '8px' }}>
              <h4 style={{ color: 'var(--accent)', margin: '0 0 10px 0', fontSize: '14px' }}>
                6. Timeline ({report.timeline_events.length} events)
              </h4>
            </div>

            <div style={{ backgroundColor: 'var(--surface-muted)', borderRadius: '6px', padding: '16px', borderLeft: '4px solid var(--warning)', marginTop: '16px' }}>
              <h4 style={{ margin: '0 0 8px 0', color: 'var(--warning)', fontSize: '14px' }}>Stated Forensic Limitations</h4>
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
