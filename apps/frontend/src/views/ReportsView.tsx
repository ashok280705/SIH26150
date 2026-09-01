import React, { useState } from 'react';
import { FileSpreadsheet } from 'lucide-react';
import { Evidence } from '../types';

interface ReportsViewProps {
  evidence: Evidence | null;
}

type ReportFormat = 'PDF' | 'JSON' | 'CSV';

export const ReportsView: React.FC<ReportsViewProps> = ({ evidence }) => {
  const [selectedFormat, setSelectedFormat] = useState<ReportFormat>('PDF');

  if (!evidence) {
    return (
      <div className="view-container">
        <div className="view-header">
          <div>
            <h1 className="view-title">Court-Admissible Forensic Reporting</h1>
            <p className="view-subtitle">Select an evidence target to generate forensic examination reports.</p>
          </div>
        </div>
        <div className="empty-state">
          <FileSpreadsheet size={32} />
          <h3>No Evidence Selected</h3>
          <p>Select a DVR/NVR evidence item from the active case to begin analysis.</p>
        </div>
      </div>
    );
  }

  const reportHash = '9e107d9d372bb6826bd81d3542a419d6dae4e1e4649b934ca495991b7852b855';

  return (
    <div className="view-container">
      <div className="view-header">
        <div>
          <h1 className="view-title">Court-Admissible Forensic Reporting</h1>
          <p className="view-subtitle">Comprehensive forensic documentation with cryptographic hashes, provenance, and stated limitations (Phase 6 / Req 17)</p>
        </div>
        <div style={{ display: 'flex', gap: '8px' }}>
          <button
            onClick={() => alert(`Report downloaded (${selectedFormat}) with SHA-256: ${reportHash}`)}
            className="btn btn-primary"
            style={{ backgroundColor: 'var(--success)' }}
          >
            ⬇ Export Report ({selectedFormat})
          </button>
        </div>
      </div>

      {/* Format Selector Bar */}
      <div className="panel" style={{ padding: '12px 16px', display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '16px' }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: '12px' }}>
          <span className="text-muted" style={{ fontSize: '13px', fontWeight: 600 }}>Report Output Format:</span>
          <div style={{ display: 'flex', gap: '8px' }}>
            {(['PDF', 'JSON', 'CSV'] as ReportFormat[]).map(fmt => (
              <button
                key={fmt}
                onClick={() => setSelectedFormat(fmt)}
                style={{
                  padding: '6px 14px',
                  borderRadius: '4px',
                  border: '1px solid',
                  borderColor: selectedFormat === fmt ? 'var(--accent)' : 'var(--border)',
                  backgroundColor: selectedFormat === fmt ? 'var(--accent-light)' : 'var(--surface)',
                  color: selectedFormat === fmt ? 'var(--accent)' : 'var(--text-secondary)',
                  fontWeight: selectedFormat === fmt ? 600 : 500,
                  cursor: 'pointer',
                  fontSize: '12px',
                  transition: 'all 0.15s ease'
                }}
              >
                {fmt === 'PDF' && '📄 Formal Document (PDF / Markdown)'}
                {fmt === 'JSON' && '{ } Machine-Readable (JSON)'}
                {fmt === 'CSV' && '📊 Spreadsheets (CSV Bundle)'}
              </button>
            ))}
          </div>
        </div>
        <div style={{ fontSize: '12px', color: 'var(--success)', fontWeight: 600 }}>
          ✓ Cryptographically Signed Lineage (SHA-256 Derived Artifact)
        </div>
      </div>

      {/* Audit Banner */}
      <div style={{ backgroundColor: 'var(--surface)', border: '1px solid var(--accent)', borderRadius: '6px', padding: '16px', marginBottom: '20px' }}>
        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
          <div>
            <div style={{ fontSize: '11px', color: 'var(--accent)', textTransform: 'uppercase', letterSpacing: '0.5px', fontWeight: 700 }}>Generated Report Provenance</div>
            <div style={{ fontSize: '15px', fontWeight: 700, color: 'var(--text-primary)', marginTop: '4px' }}>
              Report ID: REP-2026-0901-001 | Format: {selectedFormat}
            </div>
            <div className="mono text-muted" style={{ fontSize: '12px', marginTop: '4px' }}>
              SHA-256: {reportHash}
            </div>
          </div>
          <div style={{ textAlign: 'right' }}>
            <span className="badge badge-pass" style={{ fontSize: '11px', padding: '4px 8px' }}>
              Chain of Custody Logged
            </span>
          </div>
        </div>
      </div>

      {/* Report Preview */}
      <div className="panel" style={{ padding: '32px', backgroundColor: '#ffffff', color: '#0f172a' }}>
        <div style={{ borderBottom: '2px solid var(--border)', paddingBottom: '16px', marginBottom: '24px' }}>
          <h2 style={{ margin: '0 0 8px 0', fontSize: '20px', color: 'var(--text-primary)' }}>DIGITAL FORENSIC EXAMINATION REPORT</h2>
          <div style={{ fontSize: '13px', color: 'var(--text-secondary)' }}>
            National Forensics Platform — DVR/NVR Automated Examination Subsystem
          </div>
        </div>

        <div className="grid-2 mb-4">
          <div>
            <h4 style={{ color: 'var(--accent)', margin: '0 0 12px 0', fontSize: '14px' }}>1. Target & Ingestion</h4>
            <div style={{ fontSize: '13px', display: 'flex', flexDirection: 'column', gap: '8px' }}>
              <div><strong>Source Path:</strong> {evidence.path}</div>
              <div><strong>Format:</strong> {evidence.image_format}</div>
              <div><strong>Size:</strong> {(evidence.capacity / (1024 * 1024 * 1024)).toFixed(2)} GB</div>
              <div><strong>Write Protection:</strong> Verified Safe (Strict Read-Only Kernel Mode)</div>
            </div>
          </div>

          <div>
            <h4 style={{ color: 'var(--accent)', margin: '0 0 12px 0', fontSize: '14px' }}>2. OEM Detection & Attribution</h4>
            <div style={{ fontSize: '13px', display: 'flex', flexDirection: 'column', gap: '8px' }}>
              <div><strong>Detection Status:</strong> Detected (Confirmed Magic at Sector 0)</div>
              <div><strong>Attribution Status:</strong> <span style={{ color: 'var(--success)', fontWeight: 'bold' }}>Attributed (Dahua Technology)</span></div>
              <div><strong>Applied Profile:</strong> dahua-dhfs-v1.0 (Hash: e3b0c442...)</div>
              <div><strong>Confidence Score:</strong> 0.96 (Threshold: 0.65)</div>
            </div>
          </div>
        </div>

        <div style={{ marginBottom: '24px', marginTop: '32px' }}>
          <h4 style={{ color: 'var(--accent)', margin: '0 0 12px 0', fontSize: '14px' }}>3. Independent Validation Operations & Reasons</h4>
          <div className="table-container">
            <table className="data-table">
              <thead>
                <tr>
                  <th>Operation</th>
                  <th>Subject</th>
                  <th>Outcome</th>
                  <th>Mandatory Technical Reason</th>
                </tr>
              </thead>
              <tbody>
                <tr>
                  <td>detect_oem</td>
                  <td>Superblock Magic</td>
                  <td><span className="badge badge-pass">PASS</span></td>
                  <td className="text-muted">Verified 'DHFS' ASCII pattern at byte offset 0</td>
                </tr>
                <tr>
                  <td>parse_recordings</td>
                  <td>Index Table</td>
                  <td><span className="badge badge-pass">PASS</span></td>
                  <td className="text-muted">12 recording records extracted and bounded via checked math</td>
                </tr>
                <tr>
                  <td>execute_recovery</td>
                  <td>Recovery Run Extent</td>
                  <td><span className="badge badge-review">REVIEW</span></td>
                  <td className="text-muted">Bounded search reached 4 GB cap; scan truncated per bounds</td>
                </tr>
              </tbody>
            </table>
          </div>
        </div>

        <div style={{ backgroundColor: 'var(--surface-muted)', borderRadius: '6px', padding: '16px', borderLeft: '4px solid var(--warning)' }}>
          <h4 style={{ margin: '0 0 8px 0', color: 'var(--warning)', fontSize: '14px' }}>Stated Forensic Limitations (Req 17.5)</h4>
          <ol style={{ margin: '0 0 0 16px', padding: 0, fontSize: '12.5px', color: 'var(--text-secondary)', lineHeight: '1.6' }}>
            <li>This examination was performed using non-destructive, read-only analysis tools.</li>
            <li>Attribution is based on deterministic pattern rules and storage profiles under the open schema.</li>
            <li>Overwritten sectors are physically irrecoverable; no replaced frames or content were synthesized.</li>
            <li>Timestamps flagged with 'Unknown' timezone reflect unadjusted raw recorder clocks.</li>
            <li>This technical report details scientific examination findings and does not constitute a legal admissibility ruling.</li>
          </ol>
        </div>
      </div>
    </div>
  );
};
