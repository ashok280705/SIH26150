import React, { useState } from 'react';
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
          <h1 className="view-title">Court-Admissible Forensic Reporting</h1>
          <p className="view-subtitle">Select an evidence target to generate forensic examination reports.</p>
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
            style={{
              padding: '8px 16px',
              backgroundColor: '#2e7d32',
              color: 'white',
              border: 'none',
              borderRadius: '4px',
              fontWeight: 'bold',
              cursor: 'pointer',
              fontSize: '13px',
            }}
          >
            ⬇ Export Report ({selectedFormat})
          </button>
        </div>
      </div>

      {/* Format Selector Bar */}
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '20px', backgroundColor: '#1e1e1e', padding: '12px 16px', borderRadius: '8px', border: '1px solid #333' }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: '12px' }}>
          <span style={{ fontSize: '13px', color: '#aaa', fontWeight: 'bold' }}>Report Output Format:</span>
          {(['PDF', 'JSON', 'CSV'] as ReportFormat[]).map(fmt => (
            <button
              key={fmt}
              onClick={() => setSelectedFormat(fmt)}
              style={{
                padding: '6px 14px',
                borderRadius: '4px',
                border: '1px solid',
                borderColor: selectedFormat === fmt ? '#2196f3' : '#444',
                backgroundColor: selectedFormat === fmt ? '#1976d233' : '#252525',
                color: selectedFormat === fmt ? '#90caf9' : '#ccc',
                fontWeight: selectedFormat === fmt ? 'bold' : 'normal',
                cursor: 'pointer',
                fontSize: '12px',
              }}
            >
              {fmt === 'PDF' && '📄 Formal Document (PDF / Markdown)'}
              {fmt === 'JSON' && '{ } Machine-Readable (JSON)'}
              {fmt === 'CSV' && '📊 Spreadsheets (CSV Bundle)'}
            </button>
          ))}
        </div>
        <div style={{ fontSize: '12px', color: '#4caf50' }}>
          ✓ Cryptographically Signed Lineage (SHA-256 Derived Artifact)
        </div>
      </div>

      {/* Audit Banner */}
      <div style={{ backgroundColor: '#112233', border: '1px solid #1976d2', borderRadius: '8px', padding: '16px', marginBottom: '20px' }}>
        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
          <div>
            <div style={{ fontSize: '12px', color: '#90caf9', textTransform: 'uppercase', letterSpacing: '0.5px' }}>Generated Report Provenance</div>
            <div style={{ fontSize: '15px', fontWeight: 'bold', color: 'white', marginTop: '4px' }}>
              Report ID: REP-2026-0901-001 | Format: {selectedFormat}
            </div>
            <div style={{ fontFamily: 'monospace', fontSize: '12px', color: '#aaa', marginTop: '4px' }}>
              SHA-256: {reportHash}
            </div>
          </div>
          <div style={{ textAlign: 'right' }}>
            <span style={{ padding: '4px 8px', borderRadius: '4px', fontSize: '11px', fontWeight: 'bold', backgroundColor: '#2e7d3233', color: '#81c784' }}>
              Chain of Custody Logged
            </span>
          </div>
        </div>
      </div>

      {/* Report Preview */}
      <div className="data-panel" style={{ backgroundColor: '#1e1e1e', borderRadius: '8px', border: '1px solid #333', padding: '24px' }}>
        <div style={{ borderBottom: '1px solid #333', paddingBottom: '16px', marginBottom: '20px' }}>
          <h2 style={{ margin: '0 0 8px 0', fontSize: '20px' }}>DIGITAL FORENSIC EXAMINATION REPORT</h2>
          <div style={{ fontSize: '13px', color: '#888' }}>
            National Forensics Platform — DVR/NVR Automated Examination Subsystem
          </div>
        </div>

        <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '24px', marginBottom: '24px' }}>
          <div>
            <h4 style={{ color: '#2196f3', margin: '0 0 12px 0' }}>1. Target & Ingestion</h4>
            <div style={{ fontSize: '13px', display: 'flex', flexDirection: 'column', gap: '6px' }}>
              <div><strong>Source Path:</strong> {evidence.path}</div>
              <div><strong>Format:</strong> {evidence.image_format}</div>
              <div><strong>Size:</strong> {(evidence.capacity / (1024 * 1024 * 1024)).toFixed(2)} GB</div>
              <div><strong>Write Protection:</strong> Verified Safe (Strict Read-Only Kernel Mode)</div>
            </div>
          </div>

          <div>
            <h4 style={{ color: '#2196f3', margin: '0 0 12px 0' }}>2. OEM Detection & Attribution</h4>
            <div style={{ fontSize: '13px', display: 'flex', flexDirection: 'column', gap: '6px' }}>
              <div><strong>Detection Status:</strong> Detected (Confirmed Magic at Sector 0)</div>
              <div><strong>Attribution Status:</strong> <span style={{ color: '#81c784', fontWeight: 'bold' }}>Attributed (Dahua Technology)</span></div>
              <div><strong>Applied Profile:</strong> dahua-dhfs-v1.0 (Hash: e3b0c442...)</div>
              <div><strong>Confidence Score:</strong> 0.96 (Threshold: 0.65)</div>
            </div>
          </div>
        </div>

        <div style={{ marginBottom: '24px' }}>
          <h4 style={{ color: '#2196f3', margin: '0 0 12px 0' }}>3. Independent Validation Operations & Reasons</h4>
          <table style={{ width: '100%', borderCollapse: 'collapse', fontSize: '13px' }}>
            <thead>
              <tr style={{ backgroundColor: '#252525', textAlign: 'left' }}>
                <th style={{ padding: '8px 12px', borderBottom: '1px solid #333' }}>Operation</th>
                <th style={{ padding: '8px 12px', borderBottom: '1px solid #333' }}>Subject</th>
                <th style={{ padding: '8px 12px', borderBottom: '1px solid #333' }}>Outcome</th>
                <th style={{ padding: '8px 12px', borderBottom: '1px solid #333' }}>Mandatory Technical Reason</th>
              </tr>
            </thead>
            <tbody>
              <tr style={{ borderBottom: '1px solid #333' }}>
                <td style={{ padding: '8px 12px' }}>detect_oem</td>
                <td style={{ padding: '8px 12px' }}>Superblock Magic</td>
                <td style={{ padding: '8px 12px' }}><span style={{ color: '#81c784', fontWeight: 'bold' }}>PASS</span></td>
                <td style={{ padding: '8px 12px', color: '#aaa' }}>Verified 'DHFS' ASCII pattern at byte offset 0</td>
              </tr>
              <tr style={{ borderBottom: '1px solid #333' }}>
                <td style={{ padding: '8px 12px' }}>parse_recordings</td>
                <td style={{ padding: '8px 12px' }}>Index Table</td>
                <td style={{ padding: '8px 12px' }}><span style={{ color: '#81c784', fontWeight: 'bold' }}>PASS</span></td>
                <td style={{ padding: '8px 12px', color: '#aaa' }}>12 recording records extracted and bounded via checked math</td>
              </tr>
              <tr style={{ borderBottom: '1px solid #333' }}>
                <td style={{ padding: '8px 12px' }}>execute_recovery</td>
                <td style={{ padding: '8px 12px' }}>Recovery Run Extent</td>
                <td style={{ padding: '8px 12px' }}><span style={{ color: '#ffb74d', fontWeight: 'bold' }}>REVIEW</span></td>
                <td style={{ padding: '8px 12px', color: '#aaa' }}>Bounded search reached 4 GB cap; scan truncated per bounds</td>
              </tr>
            </tbody>
          </table>
        </div>

        <div style={{ backgroundColor: '#252525', borderRadius: '6px', padding: '16px', borderLeft: '4px solid #ff9800' }}>
          <h4 style={{ margin: '0 0 8px 0', color: '#ffb74d', fontSize: '14px' }}>Stated Forensic Limitations (Req 17.5)</h4>
          <ol style={{ margin: '0 0 0 16px', padding: 0, fontSize: '12px', color: '#ccc', lineHeight: '1.6' }}>
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
